use std::time::SystemTime;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::basics::SslId;

#[derive(Debug, Serialize, Deserialize)]
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
    ChatMessage,
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
            ChatMessage => 15,
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
        use EventType::*;

        match x {
            0 => None,
            1 => BroadcastDiscovery,
            2 => GossipDiscovery,
            3 => AuthsslConnectionAutentication,
            4 => PeerConnection,
            5 => GxsChanges,
            6 => PeerStateChanged {
                // TODO
                ssl_id: SslId::default(),
            },
            7 => MailStatus,
            8 => GxsCircles,
            9 => GxsChannels,
            10 => GxsForums,
            11 => GxsPosted,
            12 => GxsIdentity,
            13 => unreachable!("usage of deprecated item"),
            14 => FileTransfer,
            15 => ChatMessage,
            16 => Network,
            17 => MailTag,
            20 => FileHashingCompleted,
            21 => TorManager,
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
