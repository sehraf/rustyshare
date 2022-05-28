use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::{
    basics::{GxsIdHex, SslIdHex},
    gen_type_wrapped,
    services::chat::{ChatLobbyFlags, ChatLobbyId},
};

use super::XInt64;

gen_type_wrapped!(ChatLobbyIdWrapped, id, ChatLobbyId);

// FIXME
pub type GxsImage = Vec<u8>;

// struct VisibleChatLobbyRecord : RsSerializable
// 	ChatLobbyId lobby_id ;						// unique id of the lobby
// 	std::string lobby_name ;					// name to use for this lobby
// 	std::string lobby_topic ;					// topic to use for this lobby
// 	std::set<RsPeerId> participating_friends ;	// list of direct friend who participate.

// 	uint32_t total_number_of_peers ;			// total number of particpating peers. Might not be
// 	rstime_t last_report_time ; 					// last time the lobby was reported.
// 	ChatLobbyFlags lobby_flags ;				// see RS_CHAT_LOBBY_PRIVACY_LEVEL_PUBLIC / RS_CHAT_LOBBY_PRIVACY_LEVEL_PRIVATE
// 	}

// 	~VisibleChatLobbyRecord() override;
// };

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct VisibleChatLobbyRecord {
    pub lobby_id: XInt64<u64>,                    // unique id of the lobby
    pub lobby_name: String,                       // name to use for this lobby
    pub lobby_topic: String,                      // topic to use for this lobby
    pub participating_friends: HashSet<SslIdHex>, // list of direct friend who participate.

    pub total_number_of_peers: u32, // total number of particpating peers. Might not be
    pub last_report_time: XInt64<i64>, // last time the lobby was reported.
    pub lobby_flags: ChatLobbyFlags, // see RS_CHAT_LOBBY_PRIVACY_LEVEL_PUBLIC / RS_CHAT_LOBBY_PRIVACY_LEVEL_PRIVATE
}

// class ChatLobbyInfo : RsSerializable
// {
// public:
// 	virtual ~ChatLobbyInfo() = default;

// 	ChatLobbyId lobby_id ;						// unique id of the lobby
// 	std::string lobby_name ;					// name to use for this lobby
// 	std::string lobby_topic ;					// topic to use for this lobby
// 	std::set<RsPeerId> participating_friends ;	// list of direct friend who participate. Used to broadcast sent messages.
// 	RsGxsId gxs_id ;							// ID to sign messages

// 	ChatLobbyFlags lobby_flags ;				// see RS_CHAT_LOBBY_PRIVACY_LEVEL_PUBLIC / RS_CHAT_LOBBY_PRIVACY_LEVEL_PRIVATE
// 	std::map<RsGxsId, rstime_t> gxs_ids ;			// list of non direct friend who participate. Used to display only.
// 	rstime_t last_activity ;						// last recorded activity. Useful for removing dead lobbies.

//     virtual void clear() { gxs_ids.clear(); lobby_id = 0; lobby_name.clear(); lobby_topic.clear(); participating_friends.clear(); }

// 	// RsSerializable interface
// public:
// 	void serial_process(RsGenericSerializer::SerializeJob j, RsGenericSerializer::SerializeContext &ctx) {
// 		RS_SERIAL_PROCESS(lobby_id);
// 		RS_SERIAL_PROCESS(lobby_name);
// 		RS_SERIAL_PROCESS(lobby_topic);
// 		RS_SERIAL_PROCESS(participating_friends);
// 		RS_SERIAL_PROCESS(gxs_id);

// 		RS_SERIAL_PROCESS(lobby_flags);
// 		RS_SERIAL_PROCESS(gxs_ids);
// 		RS_SERIAL_PROCESS(last_activity);
// 	}
// };

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct ChatLobbyInfo {
    pub lobby_id: XInt64<u64>,                    // unique id of the lobby
    pub lobby_name: String,                       // name to use for this lobby
    pub lobby_topic: String,                      // topic to use for this lobby
    pub participating_friends: HashSet<SslIdHex>, // list of direct friend who participate. Used to broadcast sent messages.
    pub gxs_id: GxsIdHex,                         // ID to sign messages

    pub lobby_flags: ChatLobbyFlags, // see RS_CHAT_LOBBY_PRIVACY_LEVEL_PUBLIC / RS_CHAT_LOBBY_PRIVACY_LEVEL_PRIVATE
    pub gxs_ids: Vec<ChatLobbyInfoGxsIds>, // list of non direct friend who participate. Used to display only.
    pub last_activity: XInt64<i64>, // last recorded activity. Useful for removing dead lobbies.
}

// TODO emulate RS's HashMap to json behavior
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct ChatLobbyInfoGxsIds {
    pub key: GxsIdHex,
    pub value: XInt64<i64>,
}
