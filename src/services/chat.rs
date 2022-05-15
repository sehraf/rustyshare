#[allow(deprecated)]
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use log::{debug, info, trace, warn};
use retroshare_compat::{
    serde::{from_retroshare_wire, to_retroshare_wire},
    services::chat::{ChatLobbyListItem, read_rs_chat_lobby_list_item},
};

use crate::{
    handle_packet,
    model::DataCore,
    parser::{headers::ServiceHeader, Packet},
    services::{HandlePacketResult, Service},
    utils::simple_stats::StatsCollection,
};

const CHAT_SERVICE: u16 = 0x0012;

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

const LOBBY_REQUEST_INTERVAL: Duration = Duration::from_secs(15);
pub struct Chat {
    last_request: SystemTime,
}

impl Chat {
    pub async fn new(_dc: &Arc<DataCore>) -> Chat {
        // let (tx, rx) = unbounded_channel();
        // dc.events_subscribe(tx).await;
        Chat {
            last_request: std::time::SystemTime::now(),
        }
    }

    pub fn handle_incoming(
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

            CHAT_SUB_TYPE_CHAT_LOBBY_SIGNED_EVENT | CHAT_SUB_TYPE_CHAT_LOBBY_SIGNED_MSG => {
                debug!("SIGNED")
            }
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
                trace!("[Chat] lobby challenge not supported");
            }
            CHAT_SUB_TYPE_CHAT_LOBBY_LIST_REQUEST => {
                assert!(packet.payload.is_empty());

                let list = ChatLobbyListItem { lobbies: vec![] };

                // TODO add lobbies

                let payload = to_retroshare_wire(&list).unwrap();
                let header =
                    ServiceHeader::new(CHAT_SERVICE, CHAT_SUB_TYPE_CHAT_LOBBY_LIST, &payload)
                        .into();
                return handle_packet!(Packet::new(header, payload, packet.peer_id.to_owned()));
            }
            CHAT_SUB_TYPE_CHAT_LOBBY_LIST => {
                // F*CK TLV
                // let list: ChatLobbyListItem =
                //     from_retroshare_wire(&mut packet.payload).expect("failed to deserialize");
                let list = read_rs_chat_lobby_list_item(&mut packet.payload);

                if log::log_enabled!(log::Level::Info) {
                    info!("[Chat] received lobbies:");
                    for lobby in list.lobbies {
                        info!(" - {lobby:?}");
                    }
                }
            }

            sub_type => {
                warn!("[Chat] recevied unknown sub typ {sub_type}");
            }
        }

        handle_packet!()
    }
}

#[async_trait]
impl Service for Chat {
    fn get_id(&self) -> u16 {
        CHAT_SERVICE
    }

    async fn handle_packet(&self, packet: Packet) -> HandlePacketResult {
        debug!("handle_packet");

        self.handle_incoming(&packet.header.into(), packet)
    }

    fn tick(&mut self, _stats: &mut StatsCollection) -> Option<Vec<Packet>> {
        if self.last_request.elapsed().unwrap() > LOBBY_REQUEST_INTERVAL {
            trace!("requesting lobbies");
            self.last_request = SystemTime::now();

            let payload = vec![];
            let header = ServiceHeader::new(
                CHAT_SERVICE,
                CHAT_SUB_TYPE_CHAT_LOBBY_LIST_REQUEST,
                &payload,
            )
            .into();
            warn!("{header:?}");
            let packet = Packet::new_without_location(header, payload);

            return Some(vec![packet]);
        }
        None
    }

    fn get_service_info(&self) -> (String, u16, u16, u16, u16) {
        (String::from("chat"), 1, 0, 1, 0)
    }
}
