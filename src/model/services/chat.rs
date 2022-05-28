use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, SystemTime},
};

use retroshare_compat::{
    basics::{GxsId, PeerId},
    services::chat::{
        ChatId, ChatLobbyFlags, ChatLobbyId, ChatLobbyInviteItem, ChatLobbyMsgId,
        VisibleChatLobbyInfo,
    },
    webui::chat::{ChatLobbyInfo, ChatLobbyInfoGxsIds, VisibleChatLobbyRecord},
};
use tokio::sync::{mpsc::UnboundedSender, RwLock};

use crate::services::chat::CHAT_MAX_KEEP_MSG_RECORD;

#[derive(Debug)]
pub struct ChatStore {
    pub lobbies: RwLock<HashMap<ChatLobbyId, Lobby>>,
    pub cmd: RwLock<Option<UnboundedSender<ChatCmd>>>,
}

impl ChatStore {
    pub fn new() -> Self {
        Self {
            lobbies: RwLock::new(HashMap::new()),
            cmd: RwLock::new(None),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Lobby {
    pub lobby_id: ChatLobbyId,
    pub lobby_name: String,
    pub lobby_topic: String,
    pub lobby_flags: ChatLobbyFlags,

    /// tracks our own friends/peers
    pub participating_friends: HashMap<Arc<PeerId>, SystemTime>,
    /// tracks lobby participants
    pub participants: HashMap<Arc<GxsId>, SystemTime>,

    pub total_number_of_peers: u32,
    /// maps to both `last_report_time` and `last_activity`
    pub last_activity: SystemTime,

    pub joined: bool,
    pub gxs_id: Option<GxsId>,

    pub msg_cache: HashMap<ChatLobbyMsgId, SystemTime>,
}

impl Lobby {
    pub fn update_participant(&mut self, peer: Arc<PeerId>) {
        *self
            .participating_friends
            .entry(peer)
            .or_insert(SystemTime::now()) = SystemTime::now();
    }

    pub fn maintain_lobby(&mut self) {
        // TODO pick a sane value
        const CLEAR_TIME: Duration = Duration::from_secs(180);

        self.participating_friends
            .retain(|_, time| SystemTime::now().duration_since(*time).unwrap() < CLEAR_TIME);

        let now = SystemTime::now();
        self.msg_cache
            .retain(|_id, ts| ts.checked_add(CHAT_MAX_KEEP_MSG_RECORD).unwrap() < now);
    }

    pub fn update_max_peers(&mut self, count: u32) {
        self.total_number_of_peers = std::cmp::max(self.total_number_of_peers, count);
    }
}

impl From<VisibleChatLobbyInfo> for Lobby {
    fn from(x: VisibleChatLobbyInfo) -> Self {
        Self {
            lobby_id: x.id,
            lobby_name: x.name.into(),
            lobby_topic: x.topic.into(),
            lobby_flags: x.flags,

            participating_friends: HashMap::new(),
            participants: HashMap::new(),
            total_number_of_peers: x.count,
            last_activity: std::time::SystemTime::now(),

            joined: false,
            gxs_id: None,

            msg_cache: HashMap::new(),
        }
    }
}

impl From<&Lobby> for ChatLobbyInviteItem {
    fn from(lobby: &Lobby) -> Self {
        Self {
            lobby_flags: lobby.lobby_flags,
            lobby_id: lobby.lobby_id,
            lobby_name: lobby.lobby_name.to_owned().into(),
            lobby_topic: lobby.lobby_topic.to_owned().into(),
        }
    }
}

impl From<&Lobby> for VisibleChatLobbyRecord {
    fn from(lobby: &Lobby) -> Self {
        Self {
            lobby_id: lobby.lobby_id.into(),
            lobby_name: lobby.lobby_name.to_owned(),
            lobby_topic: lobby.lobby_topic.to_owned(),

            participating_friends: lobby
                .participating_friends
                .iter()
                .map(|(peer, _)| *peer.to_owned())
                .map(|peer| peer.into())
                .collect(),

            total_number_of_peers: lobby.total_number_of_peers,
            last_report_time: lobby
                .last_activity
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .into(),
            lobby_flags: lobby.lobby_flags,
        }
    }
}

impl From<&Lobby> for ChatLobbyInfo {
    fn from(lobby: &Lobby) -> Self {
        Self {
            lobby_id: lobby.lobby_id.into(),
            lobby_name: lobby.lobby_name.to_owned(),
            lobby_topic: lobby.lobby_topic.to_owned(),
            participating_friends: lobby
                .participating_friends
                .iter()
                .map(|(peer, _)| *peer.to_owned())
                .map(|peer| peer.into())
                .collect(),
            gxs_id: lobby.gxs_id.unwrap_or(GxsId::default()).into(),

            lobby_flags: lobby.lobby_flags,
            gxs_ids: lobby
                .participants
                .iter()
                .map(|(peer, time)| {
                    (
                        *peer.to_owned(),
                        time.duration_since(SystemTime::UNIX_EPOCH).unwrap().into(),
                    )
                })
                .map(|(peer, time)| ChatLobbyInfoGxsIds {
                    key: peer.into(),
                    value: time,
                })
                .collect(),
            last_activity: lobby
                .last_activity
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .into(),
        }
    }
}

impl From<&Lobby> for VisibleChatLobbyInfo {
    fn from(l: &Lobby) -> Self {
        Self {
            id: l.lobby_id,
            name: l.lobby_name.to_owned().into(),
            topic: l.lobby_topic.to_owned().into(),
            count: l.total_number_of_peers,
            flags: l.lobby_flags,
        }
    }
}

#[allow(dead_code)]
pub enum ChatCmd {
    SendMessage(ChatId, String),
    JoinLobby(ChatLobbyId, GxsId),
    LeaveLobby(ChatLobbyId),
}
