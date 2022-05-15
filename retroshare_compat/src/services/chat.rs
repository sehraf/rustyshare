use ::serde::{Deserialize, Serialize};
use log::warn;

use crate::{read_u32, serde::from_retroshare_wire, tlv::read_string_typed};

pub type ChatLobbyId = u64;
pub type ChatLobbyMsgId = u64;
pub type ChatLobbyNickName = String;

// // Flags for chat lobbies
// //
// typedef t_RsFlags32<FLAGS_TAG_SERVICE_CHAT > ChatLobbyFlags ;

// class RsChatMsgItem: public RsChatItem
// {
// public:
//     RsChatMsgItem() :RsChatItem(RS_PKT_SUBTYPE_DEFAULT) {}
//     RsChatMsgItem(uint8_t subtype) :RsChatItem(subtype) {}

//     //RsChatMsgItem() {}

//     virtual ~RsChatMsgItem() {}

//     // derived from RsItem

// 	void serial_process(RsGenericSerializer::SerializeJob j,RsGenericSerializer::SerializeContext& ctx);
//     virtual void clear() {}

//     uint32_t chatFlags;
//     uint32_t sendTime;
//     std::string message;

//     /* not serialised */
//     uint32_t recvTime;
// };

#[derive(Debug, Serialize, Deserialize)]
pub struct ChatMsg {
    chat_flags: u32,
    #[serde(rename(serialize = "ser_name"))]
    send_time: u32,
    message: String,
    #[serde(skip)]
    recv_time: u32,
}

// class RsChatLobbyBouncingObject
// {
// public:
//     ChatLobbyId lobby_id ;
//     ChatLobbyMsgId msg_id ;
//     ChatLobbyNickName nick ;	// Nickname of sender

//     RsTlvKeySignature signature ;
// protected:
//     // The functions below handle the serialisation of data that is specific to the bouncing object level.
//     // They are called by serial_size() and serialise() from children, but should not overload the serial_size() and
//     // serialise() methods, otherwise the wrong method will be called when serialising from this top level class.

// 	virtual void serial_process(RsGenericSerializer::SerializeJob j,RsGenericSerializer::SerializeContext& ctx);

//     virtual uint32_t PacketId() const= 0;
// };

#[derive(Debug, Serialize, Deserialize)]
pub struct ChatLobbyBouncingObject {
    lobby_id: ChatLobbyId,
    msg_id: ChatLobbyMsgId,
    nick: ChatLobbyNickName,
}

// class RsChatLobbyMsgItem: public RsChatMsgItem, public RsChatLobbyBouncingObject
// {
// public:
//     RsChatLobbyMsgItem() :RsChatMsgItem(RS_PKT_SUBTYPE_CHAT_LOBBY_SIGNED_MSG) {}

//     virtual ~RsChatLobbyMsgItem() {}
//     virtual RsChatLobbyBouncingObject *duplicate() const { return new RsChatLobbyMsgItem(*this) ; }

// 	virtual void serial_process(RsGenericSerializer::SerializeJob j,RsGenericSerializer::SerializeContext& ctx);

//     ChatLobbyMsgId parent_msg_id ;				// Used for threaded chat.

// protected:
//     virtual uint32_t PacketId() const { return RsChatMsgItem::PacketId() ; }
// };

#[derive(Debug, Serialize, Deserialize)]
pub struct ChatLobbyMsgItem {
    #[serde(flatten)]
    pub bounce_obj: ChatLobbyBouncingObject,
    #[serde(flatten)]
    pub msg_obj: ChatMsg,

    pub parent_msg_id: ChatLobbyMsgId,
}

// class RsChatLobbyEventItem: public RsChatItem, public RsChatLobbyBouncingObject
// {
// public:
// 	RsChatLobbyEventItem() :RsChatItem(RS_PKT_SUBTYPE_CHAT_LOBBY_SIGNED_EVENT) {}

// 	virtual ~RsChatLobbyEventItem() {}
// 	virtual RsChatLobbyBouncingObject *duplicate() const { return new RsChatLobbyEventItem(*this) ; }
// 	//
// 	virtual void serial_process(RsGenericSerializer::SerializeJob j,RsGenericSerializer::SerializeContext& ctx);

// 	// members.
// 	//
// 	uint8_t event_type ;		// used for defining the type of event.
// 	std::string string1;		// used for any string
// 	uint32_t sendTime;		// used to check for old looping messages

// protected:
// 	virtual uint32_t PacketId() const { return RsChatItem::PacketId() ; }
// };

#[derive(Debug, Serialize, Deserialize)]
pub struct ChatLobbyEventItem {
    #[serde(flatten)]
    pub bounce_obj: ChatLobbyBouncingObject,

    pub event_type: u8,
    pub string1: String,
    pub send_time: u32,
}

// struct VisibleChatLobbyInfo
// {
//     ChatLobbyId id ;
//     std::string name ;
//     std::string topic ;
//     uint32_t    count ;
//     ChatLobbyFlags flags ;
// };
#[derive(Debug, Serialize, Deserialize)]
pub struct VisibleChatLobbyInfo {
    pub id: ChatLobbyId,
    pub name: String,
    pub topic: String,
    pub count: u32,
    // pub flags: CharLobbyFlags, // FIXME
    pub flags: u32,
}

// class RsChatLobbyListItem: public RsChatItem
// {
// 	public:
// 		RsChatLobbyListItem() : RsChatItem(RS_PKT_SUBTYPE_CHAT_LOBBY_LIST) {}
// 		virtual ~RsChatLobbyListItem() {}

// 		void serial_process(RsGenericSerializer::SerializeJob j,RsGenericSerializer::SerializeContext& ctx);

//         std::vector<VisibleChatLobbyInfo> lobbies ;
// };

#[derive(Debug, Serialize, Deserialize)]
pub struct ChatLobbyListItem {
    pub lobbies: Vec<VisibleChatLobbyInfo>,
}

pub fn read_rs_chat_lobby_list_item(payload: &mut Vec<u8>) -> ChatLobbyListItem {
    let num_entries = read_u32(payload);

    warn!("{payload:?}");

    let mut lobbies = vec![];
    for _ in 0..num_entries {
        let id: ChatLobbyId = from_retroshare_wire(payload).expect("failed to deserialize");
        let name: String = read_string_typed(payload, 0x0051);
        let topic: String = read_string_typed(payload, 0x0051);
        let count: u32 = from_retroshare_wire(payload).expect("failed to deserialize");
        let flags: u32 = from_retroshare_wire(payload).expect("failed to deserialize");

        lobbies.push(VisibleChatLobbyInfo {
            id,
            name,
            topic,
            count,
            flags,
        });
    }

    ChatLobbyListItem { lobbies }
}

// class RsChatLobbyUnsubscribeItem: public RsChatItem
// {
// 	public:
// 		RsChatLobbyUnsubscribeItem() :RsChatItem(RS_PKT_SUBTYPE_CHAT_LOBBY_UNSUBSCRIBE) {}

// 		virtual ~RsChatLobbyUnsubscribeItem() {}

// 		void serial_process(RsGenericSerializer::SerializeJob j,RsGenericSerializer::SerializeContext& ctx);

// 		uint64_t lobby_id ;
// };

#[derive(Debug, Serialize, Deserialize)]
pub struct ChatLobbyUnsubscribeItem {
    pub lobby_id: u64,
}

// class RsChatLobbyConnectChallengeItem: public RsChatItem
// {
// 	public:
// 		RsChatLobbyConnectChallengeItem() :RsChatItem(RS_PKT_SUBTYPE_CHAT_LOBBY_CHALLENGE) {}

// 		virtual ~RsChatLobbyConnectChallengeItem() {}

// 		void serial_process(RsGenericSerializer::SerializeJob j,RsGenericSerializer::SerializeContext& ctx);

// 		uint64_t challenge_code ;
// };

#[derive(Debug, Serialize, Deserialize)]
pub struct ChatLobbyConnectChallengeItem {
    pub challenge_code: u64,
}
