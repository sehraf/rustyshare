#[allow(deprecated)]
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::{Duration, SystemTime},
};

use async_trait::async_trait;
use log::{debug, info, trace, warn};
use retroshare_compat::{
    basics::PeerId,
    serde::{from_retroshare_wire, to_retroshare_wire},
    services::chat::{
        ChatLobbyConnectChallengeItem, ChatLobbyEventItem, ChatLobbyFlags, ChatLobbyId,
        ChatLobbyInviteItem, ChatLobbyListItem, ChatLobbyMsgItem, VisibleChatLobbyInfo,
    },
};
use tokio::sync::mpsc::UnboundedSender;
use tokio::sync::RwLock;

use crate::{
    handle_packet,
    model::{intercom::Intercom, DataCore},
    parser::{headers::ServiceHeader, Packet},
    services::{HandlePacketResult, Service},
    utils::simple_stats::StatsCollection,
};

use super::ServiceType;

const CHAT_SUB_TYPE_CHAT_AVATAR: u8 = 0x03;
const CHAT_SUB_TYPE_CHAT_STATUS: u8 = 0x04;
const CHAT_SUB_TYPE_PRIVATECHATMSG_CONFIG: u8 = 0x05;
#[deprecated]
const CHAT_SUB_TYPE_CHAT_LOBBY_MSG_DEPRECATED: u8 = 0x06; // don't use ! Deprecated
#[deprecated]
const CHAT_SUB_TYPE_CHAT_LOBBY_INVITE_DEPREC: u8 = 0x07; // don't use ! Deprecated
const CHAT_SUB_TYPE_CHAT_LOBBY_ACCEPT: u8 = 0x08;
const CHAT_SUB_TYPE_CHAT_LOBBY_CHALLENGE: u8 = 0x09;
const CHAT_SUB_TYPE_CHAT_LOBBY_UNSUBSCRIBE: u8 = 0x0A;
#[deprecated]
const CHAT_SUB_TYPE_CHAT_LOBBY_EVENT_DEPREC: u8 = 0x0B; // don't use ! Deprecated
const CHAT_SUB_TYPE_CHAT_LOBBY_MSG: u8 = 0x0C; // will be deprecated when only signed messages are accepted (02/2015)
const CHAT_SUB_TYPE_CHAT_LOBBY_LIST_REQUEST: u8 = 0x0D;
#[deprecated]
#[allow(non_upper_case_globals)]
const CHAT_SUB_TYPE_CHAT_LOBBY_LIST_deprecated: u8 = 0x0E; // to be removed
#[deprecated]
#[allow(non_upper_case_globals)]
const CHAT_SUB_TYPE_CHAT_LOBBY_INVITE_deprecated: u8 = 0x0F; // to be removed
const CHAT_SUB_TYPE_CHAT_LOBBY_EVENT: u8 = 0x10;
#[deprecated]
#[allow(non_upper_case_globals)]
const CHAT_SUB_TYPE_CHAT_LOBBY_LIST_deprecated2: u8 = 0x11; // to be removed (deprecated since 02 Dec. 2012)
#[deprecated]
#[allow(non_upper_case_globals)]
const CHAT_SUB_TYPE_CHAT_LOBBY_LIST_deprecated3: u8 = 0x12;
const CHAT_SUB_TYPE_DISTANT_INVITE_CONFIG: u8 = 0x13;
const CHAT_SUB_TYPE_CHAT_LOBBY_CONFIG: u8 = 0x15;
const CHAT_SUB_TYPE_DISTANT_CHAT_DH_PUBLIC_KEY: u8 = 0x16;
const CHAT_SUB_TYPE_CHAT_LOBBY_SIGNED_MSG: u8 = 0x17;
const CHAT_SUB_TYPE_CHAT_LOBBY_SIGNED_EVENT: u8 = 0x18;
const CHAT_SUB_TYPE_CHAT_LOBBY_LIST: u8 = 0x19;

#[deprecated]
const CHAT_SUB_TYPE_CHAT_LOBBY_INVITE_DEPRECATED: u8 = 0x1A; // to be removed (deprecated since May 2017)
const CHAT_SUB_TYPE_CHAT_LOBBY_INVITE: u8 = 0x1B;
const CHAT_SUB_TYPE_OUTGOING_MAP: u8 = 0x1C;
const CHAT_SUB_TYPE_SUBSCRIBED_CHAT_LOBBY_CONFIG: u8 = 0x1D;

const LOBBY_REQUEST_INTERVAL: Duration = Duration::from_secs(120);

// ChatLobbyId lobby_id ;						// unique id of the lobby
// std::string lobby_name ;					// name to use for this lobby
// std::string lobby_topic ;					// topic to use for this lobby
// std::set<RsPeerId> participating_friends ;	// list of direct friend who participate.

// uint32_t total_number_of_peers ;			// total number of particpating peers. Might not be
// rstime_t last_report_time ; 					// last time the lobby was reported.
// ChatLobbyFlags lobby_flags ;				// see RS_CHAT_LOBBY_PRIVACY_LEVEL_PUBLIC / RS_CHAT_LOBBY_PRIVACY_LEVEL_PRIVATE
#[derive(Debug, Clone)]
struct VisibleChatLobbyRecord {
    lobby_id: ChatLobbyId,
    lobby_name: String,
    lobby_topic: String,
    participating_friends: HashSet<Arc<PeerId>>,

    total_number_of_peers: u32,
    last_report_time: SystemTime,
    lobby_flags: ChatLobbyFlags,
}

impl From<VisibleChatLobbyInfo> for VisibleChatLobbyRecord {
    fn from(x: VisibleChatLobbyInfo) -> Self {
        Self {
            lobby_id: x.id,
            lobby_name: x.name.into(),
            lobby_topic: x.topic.into(),
            participating_friends: HashSet::new(),
            total_number_of_peers: x.count,
            last_report_time: std::time::SystemTime::now(),
            lobby_flags: x.flags,
        }
    }
}

impl From<VisibleChatLobbyRecord> for ChatLobbyInviteItem {
    fn from(lobby: VisibleChatLobbyRecord) -> Self {
        ChatLobbyInviteItem {
            lobby_flags: lobby.lobby_flags,
            lobby_id: lobby.lobby_id,
            lobby_name: lobby.lobby_name.to_owned().into(),
            lobby_topic: lobby.lobby_topic.to_owned().into(),
        }
    }
}

pub struct Chat {
    core_tx: UnboundedSender<Intercom>,
    last_request: SystemTime,

    known_lobbies: RwLock<HashMap<ChatLobbyId, VisibleChatLobbyRecord>>,
}

impl Chat {
    pub async fn new(_dc: &Arc<DataCore>, core_tx: UnboundedSender<Intercom>) -> Chat {
        Chat {
            core_tx,
            // send fist request after 5 seconds
            last_request: std::time::SystemTime::now()
                .checked_sub(
                    LOBBY_REQUEST_INTERVAL
                        .checked_sub(Duration::from_secs(5))
                        .unwrap(),
                )
                .unwrap(),

            known_lobbies: RwLock::new(HashMap::new()),
        }
    }

    async fn handle_incoming(
        &self,
        header: &ServiceHeader,
        mut packet: Packet,
    ) -> HandlePacketResult {
        trace!("[Chat] {header:?}");

        #[allow(non_upper_case_globals)]
        match header.sub_type {
            CHAT_SUB_TYPE_CHAT_AVATAR => debug!("AVATAR"),
            CHAT_SUB_TYPE_CHAT_STATUS => debug!("STATUS"),
            CHAT_SUB_TYPE_CHAT_LOBBY_ACCEPT
            | CHAT_SUB_TYPE_CHAT_LOBBY_CONFIG
            | CHAT_SUB_TYPE_CHAT_LOBBY_EVENT
            | CHAT_SUB_TYPE_CHAT_LOBBY_INVITE
            | CHAT_SUB_TYPE_CHAT_LOBBY_UNSUBSCRIBE => debug!("LOBBY"),
            CHAT_SUB_TYPE_CHAT_LOBBY_MSG => debug!("MSG"),

            CHAT_SUB_TYPE_DISTANT_CHAT_DH_PUBLIC_KEY | CHAT_SUB_TYPE_DISTANT_INVITE_CONFIG => {
                debug!("DISTANT")
            }
            CHAT_SUB_TYPE_OUTGOING_MAP => debug!("OUTGOING MAP"),
            CHAT_SUB_TYPE_PRIVATECHATMSG_CONFIG => debug!("PRIVATE MSG"),
            CHAT_SUB_TYPE_SUBSCRIBED_CHAT_LOBBY_CONFIG => debug!("SUBSCRIBED CHAT"),

            #[allow(deprecated)]
            CHAT_SUB_TYPE_CHAT_LOBBY_EVENT_DEPREC
            | CHAT_SUB_TYPE_CHAT_LOBBY_INVITE_DEPREC
            | CHAT_SUB_TYPE_CHAT_LOBBY_INVITE_DEPRECATED
            | CHAT_SUB_TYPE_CHAT_LOBBY_INVITE_deprecated
            | CHAT_SUB_TYPE_CHAT_LOBBY_LIST_deprecated
            | CHAT_SUB_TYPE_CHAT_LOBBY_LIST_deprecated2
            | CHAT_SUB_TYPE_CHAT_LOBBY_LIST_deprecated3
            | CHAT_SUB_TYPE_CHAT_LOBBY_MSG_DEPRECATED => debug!("DEPRECATED"),

            // ---
            CHAT_SUB_TYPE_CHAT_LOBBY_CHALLENGE => {
                let challenge: ChatLobbyConnectChallengeItem =
                    from_retroshare_wire(&mut packet.payload).expect("failed to deserialize");
                trace!("[Chat] lobby challenge not supported: {challenge:?}");
            }
            CHAT_SUB_TYPE_CHAT_LOBBY_LIST_REQUEST => {
                trace!("[Chat] requested lobbies");
                assert!(packet.payload.is_empty());

                let list = ChatLobbyListItem { lobbies: vec![] };

                // TODO add lobbies

                let payload = to_retroshare_wire(&list).unwrap();
                let header =
                    ServiceHeader::new(ServiceType::Chat, CHAT_SUB_TYPE_CHAT_LOBBY_LIST, &payload)
                        .into();
                return handle_packet!(Packet::new(header, payload, packet.peer_id.to_owned()));
            }
            CHAT_SUB_TYPE_CHAT_LOBBY_LIST => {
                let list: ChatLobbyListItem =
                    from_retroshare_wire(&mut packet.payload).expect("failed to deserialize");

                info!("[Chat] received lobbies:");
                for lobby in list.lobbies {
                    info!(" - {lobby:?}");

                    let mut lock = self.known_lobbies.write().await;
                    let entry = lock.entry(lobby.id).or_insert(lobby.to_owned().into());
                    entry.last_report_time = std::time::SystemTime::now();
                    entry
                        .participating_friends
                        .insert(packet.peer_id.to_owned());
                    entry.total_number_of_peers =
                        std::cmp::max(entry.total_number_of_peers, lobby.count);
                }

                // check for joinable lobbies
                // TODO
                for (_id, lobby) in self.known_lobbies.read().await.iter() {
                    info!("[Chat] joining lobby {}", lobby.lobby_name);

                    debug!("flags: {:#08b}", lobby.lobby_flags);

                    // send invite(s)
                    let invite: ChatLobbyInviteItem = lobby.to_owned().into();
                    let payload = to_retroshare_wire(&invite).expect("failed to serialize");
                    let header = ServiceHeader::new(
                        ServiceType::Chat,
                        CHAT_SUB_TYPE_CHAT_LOBBY_INVITE,
                        &payload,
                    );
                    let packet = Packet::new_without_location(header.into(), payload);

                    for peer in &lobby.participating_friends {
                        let mut p = packet.to_owned();
                        p.peer_id = peer.to_owned();
                        self.core_tx
                            .send(Intercom::Send(p))
                            .expect("failed to send");
                    }
                }
            }
            CHAT_SUB_TYPE_CHAT_LOBBY_SIGNED_EVENT => {
                trace!("[Chat] signed event");
                let event: ChatLobbyEventItem =
                    from_retroshare_wire(&mut packet.payload).expect("failed to deserialize");
                trace!("{event:?}");
                if let Some(lobby) = self
                    .known_lobbies
                    .read()
                    .await
                    .get(&event.bounce_obj.publobby_id)
                {
                    info!(
                        "[Chat] event {:?} in {}",
                        event.event_type, lobby.lobby_name
                    );
                }
            }
            CHAT_SUB_TYPE_CHAT_LOBBY_SIGNED_MSG => {
                trace!("[Chat] signed msg");
                let msg: ChatLobbyMsgItem =
                    from_retroshare_wire(&mut packet.payload).expect("failed to deserialize");
                if let Some(lobby) = self
                    .known_lobbies
                    .read()
                    .await
                    .get(&msg.bounce_obj.publobby_id)
                {
                    info!("received message in {}:", lobby.lobby_name);
                    info!(" -> [{}] {}", msg.bounce_obj.nick, msg.msg_obj.message);
                }
            }

            sub_type => {
                warn!("[Chat] recevied unknown sub typ {sub_type}");
            }
        }

        handle_packet!()
    }

    fn request_lobbies(&self) -> Vec<Packet> {
        let payload = vec![];
        let header = ServiceHeader::new(
            ServiceType::Chat,
            CHAT_SUB_TYPE_CHAT_LOBBY_LIST_REQUEST,
            &payload,
        )
        .into();
        let packet = Packet::new_without_location(header, payload);

        vec![packet]
    }
}

#[async_trait]
impl Service for Chat {
    fn get_id(&self) -> ServiceType {
        ServiceType::Chat
    }

    async fn handle_packet(&self, packet: Packet) -> HandlePacketResult {
        debug!("handle_packet");

        self.handle_incoming(&packet.header.into(), packet).await
    }

    fn tick(&mut self, _stats: &mut StatsCollection) -> Option<Vec<Packet>> {
        if self.last_request.elapsed().unwrap() > LOBBY_REQUEST_INTERVAL {
            let mut packets = vec![];

            trace!("requesting lobbies");
            self.last_request = SystemTime::now();
            packets.extend(self.request_lobbies());

            return Some(packets);
        }
        None
    }

    fn get_service_info(&self) -> (String, u16, u16, u16, u16) {
        (String::from("chat"), 1, 0, 1, 0)
    }
}
