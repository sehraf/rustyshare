#[allow(deprecated)]
use std::{
    collections::hash_map::Entry,
    sync::Arc,
    time::{Duration, SystemTime},
};

use async_trait::async_trait;
use log::{debug, info, trace, warn};
use nanorand::Rng;
use retroshare_compat::{
    basics::GxsId,
    events::EventType,
    serde::{from_retroshare_wire, to_retroshare_wire, Toggleable},
    services::chat::{
        ChatIdType, ChatLobbyBouncingObject, ChatLobbyConnectChallengeItem, ChatLobbyEvent,
        ChatLobbyEventItem, ChatLobbyFlags, ChatLobbyId, ChatLobbyInviteItem, ChatLobbyListItem,
        ChatLobbyMsgItem, ChatMsgItem,
    },
    tlv::tlv_keys::{KeyId, TlvKeyFlags, TlvKeySignature, TlvKeySignatureInner},
};
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};

use crate::{
    gxs::gxsid::{generate_signature, verify_signature},
    handle_packet,
    low_level_parsing::{
        headers::{Header, ServiceHeader},
        Packet,
    },
    model::{
        intercom::Intercom,
        services::chat::{ChatCmd, Lobby},
        DataCore,
    },
    services::{HandlePacketResult, Service},
    utils::{simple_stats::StatsCollection, Timer, Timers},
};

use ::retroshare_compat::services::ServiceType;

const CHAT_SUB_TYPE_CHAT_DEFAULT: u8 = 0x01;
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

const LOBBY_REQUEST_INTERVAL: (&str, Duration, Duration) = (
    "requesting lobbies",
    Duration::from_secs(120),
    Duration::from_secs(5),
);
const LOBBY_MAINTENANCE_INTERVAL: (&str, Duration) =
    ("maintaining lobbies", Duration::from_secs(30));
const LOBBY_KEEP_ALIVE_INTERVAL: (&str, Duration) = ("keep alive", Duration::from_secs(120));

pub const CHAT_MAX_KEEP_MSG_RECORD: Duration = Duration::from_secs(1200); // 20 minutes
const CONNECTION_CHALLENGE_MAX_MSG_AGE: Duration = Duration::from_secs(30); // maximum age of a message to be used in a connection challenge

macro_rules! verify_item {
    ($self:expr, $item:expr, $packet:expr) => {
        let key_id = $item.bounce_obj.signature.key_id.to_owned();

        let header: ServiceHeader = $packet.header.to_owned().into();
        let mut item_to_verify = $item.to_owned();
        item_to_verify.bounce_obj.signature.turn_off();
        let payload = to_retroshare_wire(&item_to_verify);
        let header: Header = ServiceHeader::new(header.service, header.sub_type, &payload).into();
        let data_signed = Packet::new_without_location(header, payload).to_bytes();

        if !$self
            .verify_message(&key_id, &data_signed, &$item.bounce_obj.signature.sign_data)
            .await
        {
            debug!("[Chat] {} verification failed!", stringify!($item));
            debug!(" -> {:?}", $item);
            return handle_packet!();
        } else {
            trace!("verified {} successful", stringify!($item));
        }
    };
}

macro_rules! sign_item {
    ($self:expr, $item:expr, $header:expr) => {{
        let key_id = $item.bounce_obj.signature.key_id.to_owned();

        let header: ServiceHeader = $header;
        let mut item_to_sign = $item.to_owned();
        item_to_sign.bounce_obj.signature.turn_off();
        let payload = to_retroshare_wire(&item_to_sign);
        let header: Header = ServiceHeader::new(header.service, header.sub_type, &payload).into();
        let data_to_sign = Packet::new_without_location(header, payload).to_bytes();

        match $self.sign_message(&key_id, &data_to_sign).await {
            Some(signature) => {
                trace!("signed {} successful", stringify!($item));
                $item.bounce_obj.signature.sign_data = signature.into();
                true
            }
            None => {
                debug!("[Chat] {} signing failed!", stringify!($item));
                debug!(" -> {:?}", $item);
                // TODO error handling
                false
            }
        }
    }};
}

// ChatLobbyId lobby_id ;						// unique id of the lobby
// std::string lobby_name ;					// name to use for this lobby
// std::string lobby_topic ;					// topic to use for this lobby
// std::set<RsPeerId> participating_friends ;	// list of direct friend who participate.

// uint32_t total_number_of_peers ;			// total number of participating peers. Might not be
// rstime_t last_report_time ; 					// last time the lobby was reported.
// ChatLobbyFlags lobby_flags ;				// see RS_CHAT_LOBBY_PRIVACY_LEVEL_PUBLIC / RS_CHAT_LOBBY_PRIVACY_LEVEL_PRIVATE

pub struct Chat {
    core: Arc<DataCore>,
    core_tx: UnboundedSender<Intercom>,

    cmd_rx: UnboundedReceiver<ChatCmd>,

    auto_join: Vec<ChatLobbyId>,

    // TODO this id is used for auto joining
    own_gxs_id: Arc<GxsId>,
}

/*
TODOs:
- banning
*/

impl Chat {
    pub async fn new(
        dc: &Arc<DataCore>,
        core_tx: UnboundedSender<Intercom>,
        timers: &mut Timers,
    ) -> Chat {
        let data = dc.get_service_data().chat();

        timers.insert(
            LOBBY_REQUEST_INTERVAL.0.into(),
            Timer::new_soon(LOBBY_REQUEST_INTERVAL.1, LOBBY_REQUEST_INTERVAL.2),
        );
        timers.insert(
            LOBBY_MAINTENANCE_INTERVAL.0.into(),
            Timer::new(LOBBY_MAINTENANCE_INTERVAL.1),
        );
        timers.insert(
            LOBBY_KEEP_ALIVE_INTERVAL.0.into(),
            Timer::new(LOBBY_KEEP_ALIVE_INTERVAL.1),
        );

        let (tx, rx) = unbounded_channel();
        *data.cmd.write().await = Some(tx);

        // TODO FIXME
        // let own_gxs_id = dc.get_identities_summaries().await.iter().find(|&entry| entry.)
        let own_gxs_id = Arc::new("c59df722f56f2f886ac301acc5572e03".into());

        Chat {
            core: dc.clone(),
            core_tx,

            cmd_rx: rx,

            // TODO FIXME
            // { id: 4347301314802127616, name: StringTagged("test") }
            // { id: 7555643923972858789, name: StringTagged("Retroshare Devel (signed)") }
            // { id: 8705058284245932812, name: StringTagged("][German][Deutsch][") }
            auto_join: [
                8705058284245932812,
                7555643923972858789,
                4347301314802127616,
            ]
            .into(),
            own_gxs_id,
        }
    }

    async fn handle_incoming(
        &self,
        header: &ServiceHeader,
        mut packet: Packet,
    ) -> HandlePacketResult {
        trace!("[Chat] {header:?}");

        // just a read on a RwLock
        let data = self.core.get_service_data().chat();

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
            CHAT_SUB_TYPE_CHAT_DEFAULT => {
                trace!("[Chat] ChatMsgItem");

                let msg: ChatMsgItem = from_retroshare_wire(&mut packet.payload);
                trace!("CHAT_SUB_TYPE_CHAT_DEFAULT {msg:?}");

                if msg.chat_flags.contains(ChatLobbyFlags::PRIVATE) {
                    info!(
                        "received (direct) chat message from {}: {}",
                        packet.peer_id(),
                        msg.message
                    );
                }
                // self.core_tx
                //     .send(Intercom::Event(EventType::ChatMessage { msg: msg.into() }))
                //     .expect("failed to send to core");
            }
            CHAT_SUB_TYPE_CHAT_LOBBY_CHALLENGE => {
                trace!("[Chat] lobby challenge");
                let challenge: ChatLobbyConnectChallengeItem =
                    from_retroshare_wire(&mut packet.payload);
                trace!("{challenge:?}");

                let now = SystemTime::now();
                let mut lock = data.lobbies.write().await;
                for (lobby_id, lobby) in &mut *lock {
                    if !lobby.joined {
                        continue;
                    }

                    for (msg_id, ts) in &lobby.msg_cache {
                        if ts.checked_add(CONNECTION_CHALLENGE_MAX_MSG_AGE).unwrap() < now {
                            continue;
                        }

                        if challenge.challenge_code
                            == self.calculate_lobby_challenge(lobby_id, msg_id)
                        {
                            debug!("found a fitting lobby challenge for {}", lobby.lobby_name);
                            // found a match!
                            *lobby
                                .participating_friends
                                .entry(packet.peer_id.to_owned())
                                .or_insert(SystemTime::now()) = SystemTime::now();

                            let packet = self.build_lobby_invite(lobby);
                            return handle_packet!(packet);
                        }
                    }
                }
            }
            CHAT_SUB_TYPE_CHAT_LOBBY_LIST_REQUEST => {
                trace!("[Chat] requested lobbies");
                assert!(packet.payload.is_empty());

                let lobbies = data
                    .lobbies
                    .read()
                    .await
                    .iter()
                    .map(|(_id, lobby)| lobby.into())
                    .collect();
                let list = ChatLobbyListItem { lobbies };

                let payload = to_retroshare_wire(&list);
                let header =
                    ServiceHeader::new(self.get_id(), CHAT_SUB_TYPE_CHAT_LOBBY_LIST, &payload)
                        .into();
                return handle_packet!(Packet::new(header, payload, packet.peer_id.to_owned()));
            }
            CHAT_SUB_TYPE_CHAT_LOBBY_LIST => {
                let list: ChatLobbyListItem = from_retroshare_wire(&mut packet.payload);

                let mut lock = data.lobbies.write().await;

                info!("[Chat] received lobbies:");
                for lobby in list.lobbies {
                    info!(" - {lobby:?}");

                    let entry = lock.entry(lobby.id).or_insert(lobby.to_owned().into());
                    entry.last_activity = std::time::SystemTime::now();
                    entry.update_participant(packet.peer_id.to_owned());
                    entry.update_max_peers(lobby.count);
                }

                // check for joinable lobbies
                // TODO
                for auto_join in &self.auto_join {
                    if let Some(lobby) = lock.get_mut(auto_join) {
                        if lobby.joined {
                            continue;
                        }
                        // this also triggers a keep alive
                        self.join_lobby(lobby, self.own_gxs_id.to_owned()).await;
                    }
                }
            }
            CHAT_SUB_TYPE_CHAT_LOBBY_SIGNED_EVENT => {
                trace!("[Chat] signed event");
                trace!("{}", hex::encode(&packet.payload));

                let event: ChatLobbyEventItem = from_retroshare_wire(&mut packet.payload);
                trace!("{event:?}");

                return self.handle_chat_event(event, packet).await;
            }
            CHAT_SUB_TYPE_CHAT_LOBBY_SIGNED_MSG => {
                trace!("[Chat] signed msg");

                let msg: ChatLobbyMsgItem = from_retroshare_wire(&mut packet.payload.to_owned());
                trace!("{msg:?}");

                return self.handle_chat_msg(msg, packet).await;
            }

            sub_type => {
                warn!("[Chat] received unknown sub typ {sub_type}");
            }
        }

        handle_packet!()
    }

    async fn handle_chat_event(
        &self,
        event: ChatLobbyEventItem,
        packet: Packet,
    ) -> HandlePacketResult {
        let data = self.core.get_service_data().chat();

        // filter
        if !self.filter_event(&event).await {
            return handle_packet!();
        }
        // verify
        verify_item!(self, event, packet);

        let mut lock = data.lobbies.write().await;
        if let Some(lobby) = lock.get_mut(&event.bounce_obj.publobby_id) {
            // this quite noisy
            debug!(
                "[Chat] event {:?} in {}",
                event.event_type, lobby.lobby_name
            );

            // bounce!
            for (participant, _) in &lobby.participating_friends {
                // skip origin
                if participant == &packet.peer_id {
                    continue;
                }

                let mut packet = packet.to_owned();
                packet.peer_id = participant.to_owned();
                self.core_tx
                    .send(Intercom::Send(packet))
                    .expect("failed to send");
            }

            let key_id = &event.bounce_obj.signature.key_id;

            use ChatLobbyEvent::*;
            match event.event_type {
                KeepAlive => {
                    *lobby
                        .participants
                        .entry(Arc::new(key_id.to_owned().into()))
                        .or_insert(SystemTime::now()) = SystemTime::now();
                }
                PeerChangeNickname => (),
                PeerJoined => {
                    let check = lobby
                        .participants
                        .insert(Arc::new(key_id.to_owned().into()), SystemTime::now());
                    if check.is_some() {
                        warn!(
                            "added peer {} to lobby {} but they are already part of it",
                            key_id.to_string(),
                            lobby.lobby_name
                        )
                    }
                    // FIXME?
                    // trigger a keep alive packets so as to inform the new participant of our presence in the chatroom
                    // it->second.last_keep_alive_packet_time = 0 ;
                }
                PeerLeft => {
                    _ = lobby
                        .participants
                        .remove(&Arc::new(key_id.to_owned().into()))
                }
                PeerStatus => (),
            }

            // TODO fire event to the rest of the code
            // self.core.webui_send(Event)
        }

        handle_packet!()
    }

    async fn handle_chat_msg(&self, msg: ChatLobbyMsgItem, packet: Packet) -> HandlePacketResult {
        let data = self.core.get_service_data().chat();

        // filter
        if !self.filter_message(&msg).await {
            return handle_packet!();
        }
        // verify
        verify_item!(self, msg, packet);

        let lock = data.lobbies.read().await;
        if let Some(lobby) = lock.get(&msg.bounce_obj.publobby_id) {
            info!("received message in {}:", lobby.lobby_name);
            info!(" -> [{}] {}", msg.bounce_obj.nick, msg.msg_obj.message);

            // bounce!
            for (participant, _) in &lobby.participating_friends {
                // skip origin
                if participant == &packet.peer_id {
                    continue;
                }

                let mut packet = packet.to_owned();
                packet.peer_id = participant.to_owned();
                self.core_tx
                    .send(Intercom::Send(packet))
                    .expect("failed to send");
            }
        }

        // fire event
        self.core_tx
            .send(Intercom::Event(EventType::ChatMessage { msg: msg.into() }))
            .expect("failed to send to core");

        handle_packet!()
    }

    fn request_lobbies(&self) -> Vec<Packet> {
        let payload = vec![];
        let header = ServiceHeader::new(
            self.get_id(),
            CHAT_SUB_TYPE_CHAT_LOBBY_LIST_REQUEST,
            &payload,
        )
        .into();
        let packet = Packet::new_without_location(header, payload);

        vec![packet]
    }

    async fn build_bouncing_obj(
        &self,
        lobby_id: ChatLobbyId,
        key_id: &KeyId,
    ) -> ChatLobbyBouncingObject {
        let msg_id = nanorand::WyRand::new().generate();
        let details = {
            // let meta = self
            //     .core
            //     .get_service_data()
            //     .gxs_id()
            //     .get_identities_summaries()
            //     .await;
            // meta.iter()
            //     .find(|entry| entry.group_id.to_string() == key_id.to_string())
            //     .unwrap()
            //     .to_owned()
            self.core
                .get_service_data()
                .gxs_id()
                .database
                .lock()
                .await
                .get_grp_meta(&vec![key_id.to_string().into()])
                .into_iter()
                .nth(0)
                .unwrap()
        };

        ChatLobbyBouncingObject {
            publobby_id: lobby_id,
            msg_id,
            nick: details.group_name.to_owned().into(),
            signature: Toggleable::new(TlvKeySignature::new(TlvKeySignatureInner::new(
                key_id.to_owned(),
            ))),
        }
    }

    async fn send_lobby_event(
        &self,
        lobby: &Lobby,
        event: ChatLobbyEvent,
        string1: Option<String>,
    ) -> Vec<Packet> {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;
        let key_id: KeyId = lobby.gxs_id.unwrap().into();

        let bounce_obj = self.build_bouncing_obj(lobby.lobby_id, &key_id).await;
        let mut event = ChatLobbyEventItem {
            event_type: event,
            send_time: now,
            string1: string1.unwrap_or_default().into(),

            bounce_obj,
        };

        let header = ServiceHeader::new(
            self.get_id(),
            CHAT_SUB_TYPE_CHAT_LOBBY_SIGNED_EVENT,
            &vec![],
        );
        if !sign_item!(self, event, header) {
            return vec![];
        }

        let payload = to_retroshare_wire(&event);
        let header = ServiceHeader::new(
            self.get_id(),
            CHAT_SUB_TYPE_CHAT_LOBBY_SIGNED_EVENT,
            &payload,
        );
        let packet = Packet::new_without_location(header.into(), payload);

        lobby
            .participating_friends
            .iter()
            .map(|(peer, _)| {
                let mut p = packet.to_owned();
                p.peer_id = peer.to_owned();
                p
            })
            .collect()
    }

    async fn keep_alive(&self, lobby: Option<&Lobby>) -> Vec<Packet> {
        let data = self.core.get_service_data().chat();
        let lock = data.lobbies.read().await;

        let lobbies: Vec<_> = {
            lock.iter()
                .filter(|(_id, l)| {
                    if let Some(lobby) = lobby {
                        l.lobby_id == lobby.lobby_id
                    } else {
                        l.joined
                    }
                })
                .collect()
        };

        let mut packets = vec![];
        for (_, lobby) in lobbies {
            // let header =
            packets.extend(
                self.send_lobby_event(lobby, ChatLobbyEvent::KeepAlive, None)
                    .await,
            );
        }
        packets
    }

    fn build_lobby_invite(&self, lobby: &Lobby) -> Packet {
        let invite: ChatLobbyInviteItem = lobby.into();
        let payload = to_retroshare_wire(&invite);
        let header = ServiceHeader::new(self.get_id(), CHAT_SUB_TYPE_CHAT_LOBBY_INVITE, &payload);
        Packet::new_without_location(header.into(), payload)
    }

    async fn join_lobby(&self, lobby: &mut Lobby, gxs_id: Arc<GxsId>) {
        info!("joining lobby {}", lobby.lobby_name);

        lobby.joined = true;
        lobby.gxs_id = Some(*gxs_id);
        *lobby
            .participants
            .entry(gxs_id)
            .or_insert(SystemTime::now()) = SystemTime::now();

        let packet = self.build_lobby_invite(lobby);

        for (peer, _) in &lobby.participating_friends {
            let mut p = packet.to_owned();
            p.peer_id = peer.to_owned();
            self.core_tx
                .send(Intercom::Send(p))
                .expect("failed to send");
        }

        // send join event
        for packet in self
            .send_lobby_event(lobby, ChatLobbyEvent::PeerJoined, None)
            .await
        {
            self.core_tx
                .send(Intercom::Send(packet))
                .expect("failed to send");
        }
    }

    async fn leave_lobby(&self, lobby: &mut Lobby) {
        info!("leaving lobby {}", lobby.lobby_name);

        lobby.joined = false;
        if let Some(gxs_id) = lobby.gxs_id.take() {
            // not sure how this can happen though ..
            lobby.participants.remove(&gxs_id);
        }

        // send leave event
        for packet in self
            .send_lobby_event(lobby, ChatLobbyEvent::PeerLeft, None)
            .await
        {
            self.core_tx
                .send(Intercom::Send(packet))
                .expect("failed to send");
        }
    }

    async fn send_message_lobby(&self, lobby: &Lobby, msg: &str) {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;
        let key_id: KeyId = lobby.gxs_id.unwrap().into();

        let bounce_obj = self.build_bouncing_obj(lobby.lobby_id, &key_id).await;
        let msg_obj = ChatMsgItem {
            chat_flags: ChatLobbyFlags::LOBBY | ChatLobbyFlags::PRIVATE,
            send_time: now,
            message: msg.into(),
            recv_time: now,
        };
        let mut msg = ChatLobbyMsgItem {
            msg_obj,
            parent_msg_id: 0,
            bounce_obj,
        };

        let header =
            ServiceHeader::new(self.get_id(), CHAT_SUB_TYPE_CHAT_LOBBY_SIGNED_MSG, &vec![]);
        if !sign_item!(self, msg, header) {
            return;
        }

        let payload = to_retroshare_wire(&msg);
        let header =
            ServiceHeader::new(self.get_id(), CHAT_SUB_TYPE_CHAT_LOBBY_SIGNED_MSG, &payload);
        let packet = Packet::new_without_location(header.into(), payload);

        for (peer, _) in &lobby.participating_friends {
            let mut p = packet.to_owned();
            p.peer_id = peer.to_owned();
            self.core_tx
                .send(Intercom::Send(p))
                .expect("failed to send");
        }
    }

    async fn handle_cmds(&mut self) {
        let data = self.core.get_service_data().chat();

        while let Ok(msg) = self.cmd_rx.try_recv() {
            match msg {
                ChatCmd::JoinLobby(lobby, gxs_id) => {
                    info!("Joining lobby {lobby:?}");

                    let gxs_id = Arc::new(gxs_id);

                    let mut lock = data.lobbies.write().await;
                    if let Some(lobby) = lock.get_mut(&lobby) {
                        self.join_lobby(lobby, gxs_id).await;
                    }
                }
                ChatCmd::LeaveLobby(lobby) => {
                    info!("leaving lobby {lobby:?}");

                    let mut lock = data.lobbies.write().await;
                    if let Some(lobby) = lock.get_mut(&lobby) {
                        self.leave_lobby(lobby).await;
                    }
                }
                ChatCmd::SendMessage(lobby_id, msg) => {
                    info!("SendMessage: msg {msg} to {lobby_id:?}");

                    match lobby_id.ty {
                        ChatIdType::TypeLobby => {
                            // get lobby but don't hold the lock, tbd if this is useful
                            let lobby = if let Some(lobby) =
                                data.lobbies.read().await.get(&lobby_id.lobby_id.into())
                            {
                                lobby.to_owned()
                            } else {
                                return;
                            };

                            self.send_message_lobby(&lobby, &msg).await;
                        }
                        _ => warn!("chat type {:?} is not supported", lobby_id.ty),
                    }
                }
            }
        }
    }

    fn filter_time(&self, send_time: u32) -> bool {
        let send_time = send_time as i128;
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i128;

        debug!("now: {now}, send_time: {send_time}");

        // simply copy RS for now
        if now + 100 > send_time + CHAT_MAX_KEEP_MSG_RECORD.as_secs() as i128 {
            warn!(
                "Received severely outdated lobby event item ({} seconds in the past)! Dropping it!",
                now - send_time
            );
            return false;
        }
        if now + 600 < send_time {
            warn!(
                "Received event item from the future ({} seconds in the future)! Dropping it!",
                now - send_time
            );
            return false;
        }

        true
    }

    async fn filter_bouncing_obj(&self, bounce_obj: &ChatLobbyBouncingObject) -> bool {
        let data = self.core.get_service_data().chat();
        let mut lock = data.lobbies.write().await;

        match lock.entry(bounce_obj.publobby_id) {
            Entry::Occupied(mut entry) => {
                // now check cache
                match entry.get_mut().msg_cache.entry(bounce_obj.msg_id) {
                    Entry::Occupied(mut entry) => {
                        *entry.get_mut() = SystemTime::now();
                        false
                    }
                    Entry::Vacant(entry) => {
                        _ = entry.insert(SystemTime::now());
                        true
                    }
                }
            }
            Entry::Vacant(_entry) => {
                // no corresponding lobby found, dropping
                warn!(
                    "received chat message for unknown lobby {}, dropping",
                    bounce_obj.publobby_id
                );

                // trigger lobby request
                for p in self.request_lobbies() {
                    self.core_tx
                        .send(Intercom::Send(p))
                        .expect("failed to send to core");
                }
                false
            }
        }
    }

    async fn filter_event(&self, event: &ChatLobbyEventItem) -> bool {
        if !self.filter_time(event.send_time) {
            return false;
        }

        // TODO reputation

        // check cache
        self.filter_bouncing_obj(&event.bounce_obj).await
    }

    async fn filter_message(&self, msg: &ChatLobbyMsgItem) -> bool {
        if !self.filter_time(msg.msg_obj.send_time) {
            return false;
        }
        // TODO reputation

        // check cache
        self.filter_bouncing_obj(&msg.bounce_obj).await
    }

    async fn generate_lobby_challenge(&self, lobby: &Lobby) -> Option<u64> {
        let lobby_id = lobby.lobby_id;
        let msg_id = {
            let limit = SystemTime::now()
                .checked_sub(CONNECTION_CHALLENGE_MAX_MSG_AGE)
                .unwrap();
            lobby
                .msg_cache
                .iter()
                .find(|(_, &ts)| ts > limit)
                .map(|(msg_id, _)| msg_id)
        }?;

        Some(self.calculate_lobby_challenge(&lobby_id, msg_id))
    }

    fn calculate_lobby_challenge(&self, lobby_id: &ChatLobbyId, msg_id: &u64) -> u64 {
        let peer_id = self.core.get_own_location().get_location_id();

        let mut state = 0u64;

        for b in peer_id.to_vec() {
            // state += msg_id;
            // state ^= state >> 35;
            // state += state << 6;
            // state ^= b as u64 * lobby_id;
            // state += state << 26;
            // state ^= state >> 13;
            state = state.wrapping_add(*msg_id);
            state ^= state >> 35;
            state = state.wrapping_add(state << 6);
            state ^= (b as u64).wrapping_mul(*lobby_id);
            state = state.wrapping_add(state << 26);
            state ^= state >> 13;
        }
        state
    }

    async fn verify_message(&self, key_id: &KeyId, data_signed: &[u8], signature: &[u8]) -> bool {
        let key_id = key_id.to_owned().into();

        // get keys
        let key = match self
            .core
            .get_service_data()
            .gxs_id()
            .get_pub_keys_by_id(&key_id)
            .await
        {
            Some(key) => key,
            None => {
                // this can be common (and thus quite noisy)
                info!("failed to find key for {key_id}");
                return false;
            }
        };

        // assert!((key.key_flags & 0x40) > 0);
        assert!(key.key_flags.contains(TlvKeyFlags::DISTRIBUTE_ADMIN));

        match verify_signature(&key, data_signed, signature) {
            Ok(true) => true,
            Ok(false) => false,
            Err(err) => {
                warn!("failed to verify: {err:#}");
                false
            }
        }
    }

    async fn sign_message(&self, key_id: &KeyId, data_to_sign: &[u8]) -> Option<Vec<u8>> {
        let key_id = key_id.to_owned();

        // get keys
        let key = match self
            .core
            .get_service_data()
            .gxs_id()
            .get_priv_keys_by_id(&key_id)
            .await
        {
            Some(key) => key,
            None => {
                // we miss out own key?!
                warn!("failed to find key for {key_id}");
                return None;
            }
        };

        // assert!((key.key_flags & 0x02) > 0);
        assert!(key.key_flags.contains(TlvKeyFlags::TYPE_FULL));

        let res = match generate_signature(&key, data_to_sign) {
            Ok(signature) => Some(signature),
            Err(err) => {
                warn!("failed to sign: {err:#}");
                None
            }
        };

        if let Some(signature) = &res {
            if !self
                .verify_message(&key_id.into(), data_to_sign, &signature)
                .await
            {
                log::error!("signed message does not pass validation!");
            }
        }

        res
    }
}

#[async_trait]
impl Service for Chat {
    fn get_id(&self) -> ServiceType {
        ServiceType::Chat
    }

    async fn handle_packet(&self, packet: Packet) -> HandlePacketResult {
        trace!("handle_packet");

        self.handle_incoming(&packet.header.into(), packet).await
    }

    async fn tick(
        &mut self,
        _stats: &mut StatsCollection,
        timers: &mut Timers,
    ) -> Option<Vec<Packet>> {
        self.handle_cmds().await;

        let mut packets = vec![];
        if timers
            .get_mut(&LOBBY_MAINTENANCE_INTERVAL.0.to_string())
            .unwrap()
            .expired()
        {
            trace!("maintaining lobbies");

            let mut lock = self.core.get_service_data().chat().lobbies.write().await;

            // trigger cleanup
            lock.iter_mut()
                .for_each(|(_, lobby)| lobby.maintain_lobby());

            // gen challenges
            for (_id, lobby) in &mut *lock {
                if let Some(challenge_code) = self.generate_lobby_challenge(lobby).await {
                    let item = ChatLobbyConnectChallengeItem { challenge_code };
                    let payload = to_retroshare_wire(&item);
                    let header = ServiceHeader::new(
                        self.get_id(),
                        CHAT_SUB_TYPE_CHAT_LOBBY_CHALLENGE,
                        &payload,
                    );
                    let packet = Packet::new_without_location(header.into(), payload);
                    packets.push(packet);
                }
            }
        }

        if timers
            .get_mut(&LOBBY_REQUEST_INTERVAL.0.to_string())
            .unwrap()
            .expired()
        {
            trace!("requesting lobbies");

            packets.extend(self.request_lobbies());
        }

        if timers
            .get_mut(&LOBBY_KEEP_ALIVE_INTERVAL.0.to_string())
            .unwrap()
            .expired()
        {
            trace!("keep alive");

            packets.extend(self.keep_alive(None).await);
        }

        if packets.is_empty() {
            None
        } else {
            Some(packets)
        }
    }

    fn get_service_info(&self) -> (String, u16, u16, u16, u16) {
        (String::from("chat"), 1, 0, 1, 0)
    }
}

#[cfg(test)]
mod test_chat {
    use retroshare_compat::{
        basics::PeerId,
        services::chat::{ChatLobbyId, ChatLobbyMsgId},
    };

    fn calculate_lobby_challenge(lobby_id: &ChatLobbyId, msg_id: &u64, peer_id: &PeerId) -> u64 {
        let mut state = 0u64;

        for b in peer_id.to_vec() {
            state = state.wrapping_add(*msg_id);
            state ^= state >> 35;
            state = state.wrapping_add(state << 6);
            state ^= (b as u64).wrapping_mul(*lobby_id);
            state = state.wrapping_add(state << 26);
            state ^= state >> 13;
        }
        state
    }

    #[test]
    fn test_lobby_challenge() {
        let sets: Vec<(PeerId, ChatLobbyId, ChatLobbyMsgId, u64)> = vec![
            (
                "65d33bc7bee18b713364b0301dbed896".into(),
                4347301314802127616,
                10160975498182007285,
                6940256940177840641,
            ),
            (
                "65d33bc7bee18b713364b0301dbed896".into(),
                4347301314802127616,
                10775870470068791562,
                14991788443493439727,
            ),
            (
                "65d33bc7bee18b713364b0301dbed896".into(),
                4347301314802127616,
                11792202543108611761,
                3035154411918242558,
            ),
            (
                "65d33bc7bee18b713364b0301dbed896".into(),
                4347301314802127616,
                10160975498182007285,
                6940256940177840641,
            ),
            (
                "65d33bc7bee18b713364b0301dbed896".into(),
                4347301314802127616,
                10775870470068791562,
                14991788443493439727,
            ),
            (
                "65d33bc7bee18b713364b0301dbed896".into(),
                4347301314802127616,
                11792202543108611761,
                3035154411918242558,
            ),
            (
                "65d33bc7bee18b713364b0301dbed896".into(),
                4347301314802127616,
                10160975498182007285,
                6940256940177840641,
            ),
            (
                "65d33bc7bee18b713364b0301dbed896".into(),
                4347301314802127616,
                10775870470068791562,
                14991788443493439727,
            ),
            (
                "65d33bc7bee18b713364b0301dbed896".into(),
                4347301314802127616,
                11792202543108611761,
                3035154411918242558,
            ),
            (
                "65d33bc7bee18b713364b0301dbed896".into(),
                4347301314802127616,
                10160975498182007285,
                6940256940177840641,
            ),
            (
                "65d33bc7bee18b713364b0301dbed896".into(),
                4347301314802127616,
                10775870470068791562,
                14991788443493439727,
            ),
            (
                "65d33bc7bee18b713364b0301dbed896".into(),
                4347301314802127616,
                11792202543108611761,
                3035154411918242558,
            ),
            (
                "65d33bc7bee18b713364b0301dbed896".into(),
                4347301314802127616,
                10160975498182007285,
                6940256940177840641,
            ),
            (
                "65d33bc7bee18b713364b0301dbed896".into(),
                4347301314802127616,
                10775870470068791562,
                14991788443493439727,
            ),
            (
                "65d33bc7bee18b713364b0301dbed896".into(),
                4347301314802127616,
                11792202543108611761,
                3035154411918242558,
            ),
            // the following are from Xeres
            (
                "01dc22f128d9495541f780a254b89630".into(),
                10949563242187165295,
                140257447151802099,
                1540395435043678632,
            ),
            (
                "01dc22f128d9495541f780a254b89630".into(),
                10949563242187165295,
                3128845210392038968,
                9133905927926710723,
            ),
            (
                "01dc22f128d9495541f780a254b89630".into(),
                10949563242187165295,
                15552989625937603562,
                2213486716447545487,
            ),
            (
                "01dc22f128d9495541f780a254b89630".into(),
                10949563242187165295,
                140257447151802099,
                1540395435043678632,
            ),
            (
                "01dc22f128d9495541f780a254b89630".into(),
                10949563242187165295,
                3128845210392038968,
                9133905927926710723,
            ),
            (
                "01dc22f128d9495541f780a254b89630".into(),
                10949563242187165295,
                15552989625937603562,
                2213486716447545487,
            ),
            (
                "01dc22f128d9495541f780a254b89630".into(),
                10949563242187165295,
                140257447151802099,
                1540395435043678632,
            ),
        ];

        for (peer_id, lobby_id, msg_id, result) in sets {
            assert_eq!(
                calculate_lobby_challenge(&lobby_id, &msg_id, &peer_id),
                result
            );
        }
    }
}
