use std::time::SystemTime;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use serde_repr::{Deserialize_repr, Serialize_repr};

use crate::{
    basics::{GxsIdHex, PeerIdHex, SslId},
    services::chat::{ChatId, ChatLobbyMsgItem},
};

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub enum EventType {
    None,
    BroadcastDiscovery,
    GossipDiscovery,
    AuthsslConnectionAutentication,
    PeerConnection,
    GxsChanges,
    /// Emitted when a peer state changes, @see RsPeers #
    PeerStateChanged {
        #[serde(with = "hex")]
        ssl_id: SslId,
    },
    MailStatus,
    GxsCircles,
    GxsChannels,
    GxsForums,
    GxsPosted,
    GxsIdentity,
    // #[deprecated]
    SharedDirectories,
    FileTransfer,
    ChatMessage {
        #[serde(rename(serialize = "mChatMessage", deserialize = "mChatMessage"))]
        msg: ChatMessage,
    },
    Network,
    MailTag,
    /** Emitted to update library clients about file hashing being completed */
    FileHashingCompleted,
    TorManager,
}

impl Default for EventType {
    fn default() -> Self {
        EventType::None
    }
}

impl EventType {
    pub fn get_type(&self) -> u32 {
        use EventType::*;

        match self {
            None => 0,
            BroadcastDiscovery => 1,
            GossipDiscovery => 2,
            AuthsslConnectionAutentication => 3,
            PeerConnection => 4,
            GxsChanges => 5,
            PeerStateChanged { .. } => 6,
            MailStatus => 7,
            GxsCircles => 8,
            GxsChannels => 9,
            GxsForums => 10,
            GxsPosted => 11,
            GxsIdentity => 12,
            #[allow(deprecated)]
            SharedDirectories => unreachable!("usage of deprecated item"),
            FileTransfer => 14,
            ChatMessage { .. } => 15,
            Network => 16,
            MailTag => 17,
            FileHashingCompleted => 20,
            TorManager => 21,
        }
    }
}

impl From<EventType> for u32 {
    fn from(event: EventType) -> Self {
        event.get_type()
    }
}

impl From<u32> for EventType {
    fn from(x: u32) -> Self {
        match x {
            0 => EventType::None,
            1 => EventType::BroadcastDiscovery,
            2 => EventType::GossipDiscovery,
            3 => EventType::AuthsslConnectionAutentication,
            4 => EventType::PeerConnection,
            5 => EventType::GxsChanges,
            6 => EventType::PeerStateChanged {
                // TODO
                ssl_id: SslId::default(),
            },
            7 => EventType::MailStatus,
            8 => EventType::GxsCircles,
            9 => EventType::GxsChannels,
            10 => EventType::GxsForums,
            11 => EventType::GxsPosted,
            12 => EventType::GxsIdentity,
            13 => unreachable!("usage of deprecated item"),
            14 => EventType::FileTransfer,
            15 => EventType::ChatMessage {
                msg: ChatMessage::default(),
            },
            16 => EventType::Network,
            17 => EventType::MailTag,
            20 => EventType::FileHashingCompleted,
            21 => EventType::TorManager,
            m @ _ => unreachable!("invalid value {m}"),
        }
    }
}

/// Since RS merges all different events into one "event" struct, we have to do some manual merging.
/// Also we can simply build the xint64 stuff
impl From<EventType> for Value {
    fn from(event: EventType) -> Self {
        let ty: u32 = event.get_type();
        let ts = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("time went backwards!")
            .as_secs();

        // build base structure
        let mut val = json!({
            "event": {
                "mType": ty,
                "mTime": {
                    "xint64": ts,
                    "xstr64": ts.to_string(),
                },
            }
        });

        // build event dependent data
        let data = {
            // j = {"peerStateChanged":{"ssl_id":"..."}}
            let j = serde_json::to_value(event).unwrap();
            // key = "peerStateChanged"
            let key = j.as_object().unwrap().keys().next().unwrap();
            // extract actual event data
            j[key].to_owned()
        };

        // merge actual event data into json object
        val["event"]
            .as_object_mut()
            .unwrap()
            .extend(data.as_object().unwrap().to_owned());

        val
    }
}

// struct ChatMessage : RsSerializable
// {
//     ChatId chat_id; // id of chat endpoint
//     RsPeerId broadcast_peer_id; // only used for broadcast chat: source peer id
//     RsGxsId lobby_peer_gxs_id; // only used for lobbys: nickname of message author
//     std::string peer_alternate_nickname; // only used when key is unknown.

//     unsigned int chatflags;
//     uint32_t sendTime;
//     uint32_t recvTime;
//     std::string msg;
//     bool incoming;
//     bool online; // for outgoing messages: was this message send?
// };

// BUG
// RS said `long int` and uses i16 constants ...
#[repr(i32)]
#[derive(Debug, Serialize_repr, Deserialize_repr, Clone)]

pub enum ChatFlags {
    None = 0,
    Public = 0x0001,
    Private = 0x0002,
    AvatarAvailable = 0x0004,
}
impl Default for ChatFlags {
    fn default() -> Self {
        Self::None
    }
}

// used by RsEvent
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct ChatMessage {
    pub chat_id: ChatId,                 // id of chat endpoint
    pub broadcast_peer_id: PeerIdHex,    // only used for broadcast chat: source peer id
    pub lobby_peer_gxs_id: GxsIdHex,     // only used for lobbys: nickname of message author
    pub peer_alternate_nickname: String, // only used when key is unknown.

    pub chatflags: ChatFlags,
    #[serde(rename(serialize = "sendTime", deserialize = "sendTime"))]
    pub send_time: u32,
    #[serde(rename(serialize = "recvTime", deserialize = "recvTime"))]
    pub recv_time: u32,
    pub msg: String,
    pub incoming: bool,
    pub online: bool, // for outgoing messages: was this message send?
}

impl From<ChatLobbyMsgItem> for ChatMessage {
    fn from(item: ChatLobbyMsgItem) -> Self {
        Self {
            chat_id: item.bounce_obj.publobby_id.into(),
            // broadcast_peer_id: item.,
            lobby_peer_gxs_id: item.bounce_obj.signature.key_id.to_string().into(),
            // peer_alternate_nickname: item.,
            // chatflags: item.msg_obj,
            send_time: item.msg_obj.send_time,
            recv_time: item.msg_obj.recv_time,
            msg: item.msg_obj.message.into(),
            // incoming: item.,
            // online: item.,
            ..Default::default()
        }
    }
}
