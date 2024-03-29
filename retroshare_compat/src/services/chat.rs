use ::serde::{Deserialize, Serialize};
use bitflags::bitflags;
use bitflags_serde_shim::impl_serde_for_bitflags;
use serde_repr::{Deserialize_repr, Serialize_repr};

use crate::{
    basics::{DistantChatPeerId, DistantChatPeerIdHex, PeerId, PeerIdHex},
    serde::Toggleable,
    tlv::{tags::*, tlv_keys::TlvKeySignature, tlv_string::StringTagged},
    webui::XInt64,
};

pub type ChatLobbyId = u64;
pub type ChatLobbyMsgId = u64;
pub type ChatLobbyNickName = StringTagged<TLV_TYPE_STR_NAME>;

// pub type ChatLobbyFlags = u32; // FIXME

bitflags! {
    pub struct ChatLobbyFlags: u32 {
        const PRIVATE                    = 0x0001;
        const REQUESTS_AVATAR            = 0x0002;
        const CONTAINS_AVATAR            = 0x0004;
        const AVATAR_AVAILABLE           = 0x0008;
        const CUSTOM_STATE               = 0x0010;  // used for transmitting peer status string
        const PUBLIC                     = 0x0020;
        const REQUEST_CUSTOM_STATE       = 0x0040;
        const CUSTOM_STATE_AVAILABLE     = 0x0080;
        const PARTIAL_MESSAGE            = 0x0100;
        const LOBBY                      = 0x0200;
        const CLOSING_DISTANT_CONNECTION = 0x0400;
        const ACK_DISTANT_CONNECTION     = 0x0800;
        const KEEP_ALIVE                 = 0x1000;
        const CONNECTION_REFUSED         = 0x2000;
    }
}

impl_serde_for_bitflags!(ChatLobbyFlags);

// const ChatLobbyFlags RS_CHAT_LOBBY_FLAGS_AUTO_SUBSCRIBE( 0x00000001 ) ;
// const ChatLobbyFlags RS_CHAT_LOBBY_FLAGS_deprecated    ( 0x00000002 ) ;
// const ChatLobbyFlags RS_CHAT_LOBBY_FLAGS_PUBLIC        ( 0x00000004 ) ;
// const ChatLobbyFlags RS_CHAT_LOBBY_FLAGS_CHALLENGE     ( 0x00000008 ) ;
// const ChatLobbyFlags RS_CHAT_LOBBY_FLAGS_PGP_SIGNED    ( 0x00000010 ) ; // requires the signing ID to be PGP-linked. Avoids anonymous crap.

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

#[derive(Debug, Serialize, Deserialize, Clone)]
#[allow(unused)]
#[serde(rename_all = "camelCase")]
pub struct ChatMsgItem {
    pub chat_flags: ChatLobbyFlags,
    pub send_time: u32,
    pub message: StringTagged<TLV_TYPE_STR_MSG>,
    #[serde(skip)]
    pub recv_time: u32,
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

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ChatLobbyBouncingObject {
    pub public_lobby_id: ChatLobbyId,
    pub msg_id: ChatLobbyMsgId,
    pub nick: ChatLobbyNickName,
    pub signature: Toggleable<TlvKeySignature>,
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

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ChatLobbyMsgItem {
    pub msg_obj: ChatMsgItem,
    pub parent_msg_id: ChatLobbyMsgId,

    pub bounce_obj: ChatLobbyBouncingObject,
}

// #define RS_CHAT_LOBBY_EVENT_PEER_LEFT   				0x01
// #define RS_CHAT_LOBBY_EVENT_PEER_STATUS 				0x02
// #define RS_CHAT_LOBBY_EVENT_PEER_JOINED 				0x03
// #define RS_CHAT_LOBBY_EVENT_PEER_CHANGE_NICKNAME 	0x04
// #define RS_CHAT_LOBBY_EVENT_KEEP_ALIVE          	0x05
#[repr(u8)]
#[derive(Debug, Serialize_repr, Deserialize_repr, Clone)]
pub enum ChatLobbyEvent {
    PeerLeft = 1,
    PeerStatus,
    PeerJoined,
    PeerChangeNickname,
    KeepAlive,
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

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ChatLobbyEventItem {
    pub event_type: ChatLobbyEvent,
    pub string1: StringTagged<TLV_TYPE_STR_NAME>,
    #[serde(rename(serialize = "sendTime", deserialize = "sendTime"))]
    pub send_time: u32,

    pub bounce_obj: ChatLobbyBouncingObject,
}

// struct VisibleChatLobbyInfo
// {
//     ChatLobbyId id ;
//     std::string name ;
//     std::string topic ;
//     uint32_t    count ;
//     ChatLobbyFlags flags ;
// };
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct VisibleChatLobbyInfo {
    #[serde(rename(serialize = "info.id", deserialize = "info.id"))]
    pub id: ChatLobbyId,
    #[serde(rename(serialize = "info.name", deserialize = "info.name"))]
    pub name: StringTagged<TLV_TYPE_STR_NAME>,
    #[serde(rename(serialize = "info.topic", deserialize = "info.topic"))]
    pub topic: StringTagged<TLV_TYPE_STR_NAME>,
    #[serde(rename(serialize = "info.count", deserialize = "info.count"))]
    pub count: u32,
    #[serde(rename(serialize = "info.flags", deserialize = "info.flags"))]
    pub flags: ChatLobbyFlags,
}

// class RsChatLobbyListItem: public RsChatItem
// {
// 	public:
// 		RsChatLobbyListItem() : RsChatItem(RS_PKT_SUBTYPE_CHAT_LOBBY_LIST) {}
// 		virtual ~RsChatLobbyListItem() {}

// 		void serial_process(RsGenericSerializer::SerializeJob j,RsGenericSerializer::SerializeContext& ctx);

//         std::vector<VisibleChatLobbyInfo> lobbies ;
// };

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ChatLobbyListItem {
    pub lobbies: Vec<VisibleChatLobbyInfo>,
}

// class RsChatLobbyUnsubscribeItem: public RsChatItem
// {
// 	public:
// 		RsChatLobbyUnsubscribeItem() :RsChatItem(RS_PKT_SUBTYPE_CHAT_LOBBY_UNSUBSCRIBE) {}

// 		virtual ~RsChatLobbyUnsubscribeItem() {}

// 		void serial_process(RsGenericSerializer::SerializeJob j,RsGenericSerializer::SerializeContext& ctx);

// 		uint64_t lobby_id ;
// };

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ChatLobbyUnsubscribeItem {
    pub lobby_id: ChatLobbyId,
}

// class RsChatLobbyConnectChallengeItem: public RsChatItem
// {
// 	public:
// 		RsChatLobbyConnectChallengeItem() :RsChatItem(RS_PKT_SUBTYPE_CHAT_LOBBY_CHALLENGE) {}

// 		virtual ~RsChatLobbyConnectChallengeItem() {}

// 		void serial_process(RsGenericSerializer::SerializeJob j,RsGenericSerializer::SerializeContext& ctx);

// 		uint64_t challenge_code ;
// };

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ChatLobbyConnectChallengeItem {
    pub challenge_code: ChatLobbyId,
}

// class RsChatLobbyInviteItem: public RsChatItem
// {
// 	public:
// 		RsChatLobbyInviteItem() :RsChatItem(RS_PKT_SUBTYPE_CHAT_LOBBY_INVITE) {}
// 		virtual ~RsChatLobbyInviteItem() {}

// 		void serial_process(RsGenericSerializer::SerializeJob j,RsGenericSerializer::SerializeContext& ctx);

// 		ChatLobbyId lobby_id ;
// 		std::string lobby_name ;
// 		std::string lobby_topic ;
// 		ChatLobbyFlags lobby_flags ;
// };
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ChatLobbyInviteItem {
    pub lobby_id: ChatLobbyId,
    pub lobby_name: StringTagged<TLV_TYPE_STR_NAME>,
    pub lobby_topic: StringTagged<TLV_TYPE_STR_NAME>,
    pub lobby_flags: ChatLobbyFlags,
}

// // This class contains activity info for the sending peer: active, idle, typing, etc.
// //
// class RsChatStatusItem: public RsChatItem
// {
// 	public:
// 		RsChatStatusItem() :RsChatItem(RS_PKT_SUBTYPE_CHAT_STATUS) {}

// 		virtual ~RsChatStatusItem() {}

// 		void serial_process(RsGenericSerializer::SerializeJob j,RsGenericSerializer::SerializeContext& ctx);

// 		uint32_t flags ;
// 		std::string status_string;
// };

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ChatStatusItem {
    pub flags: u32,
    pub status_string: StringTagged<TLV_TYPE_STR_MSG>,
}

// // This class contains avatar images in Qt format.
// //
// class RsChatAvatarItem: public RsChatItem
// {
// public:
// 	RsChatAvatarItem():
// 	    RsChatItem(RS_PKT_SUBTYPE_CHAT_AVATAR),
// 	    image_size(0), image_data(nullptr)
// 	{ setPriorityLevel(QOS_PRIORITY_RS_CHAT_AVATAR_ITEM); }

// 	~RsChatAvatarItem() override { free(image_data); }

// 	void serial_process(
// 	        RsGenericSerializer::SerializeJob j,
// 	        RsGenericSerializer::SerializeContext& ctx) override;

// 	uint32_t image_size; /// size of data in bytes
// 	unsigned char* image_data ; /// image data
// };

// FIXME: add support for RawMemoryWrapper
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ChatAvatarItem {
    pub uint32_t: u32,
    pub image_data: Vec<u8>,
}

// struct PrivateOugoingMapItem : RsChatItem
// {
// 	PrivateOugoingMapItem() : RsChatItem(RS_PKT_SUBTYPE_OUTGOING_MAP) {}

// 	void serial_process( RsGenericSerializer::SerializeJob j,
// 	                     RsGenericSerializer::SerializeContext& ctx );

// 	std::map<uint64_t, RsChatMsgItem> store;
// };

// #[derive(Debug, Serialize, Deserialize, Clone)]
// pub struct PrivateOugoingMapItem {
//     pub challenge_code: u64,
// }

// class ChatId : RsSerializable
// {
//     // for the very specific case of transfering a status string
//     // from the chatservice to the gui,
//     // this defines from which peer the status string came from
//     RsPeerId broadcast_status_peer_id;
// private:
// 	enum Type : uint8_t
// 	{	TYPE_NOT_SET,
// 		TYPE_PRIVATE,            // private chat with directly connected friend, peer_id is valid
// 		TYPE_PRIVATE_DISTANT,    // private chat with distant peer, gxs_id is valid
// 		TYPE_LOBBY,              // chat lobby id, lobby_id is valid
// 		TYPE_BROADCAST           // message to/from all connected peers
// 	};

//     Type type;
//     RsPeerId peer_id;
//     DistantChatPeerId distant_chat_id;
//     ChatLobbyId lobby_id;

// 	// RsSerializable interface
// public:
// 	void serial_process(RsGenericSerializer::SerializeJob j, RsGenericSerializer::SerializeContext &ctx) {
// 		RS_SERIAL_PROCESS(broadcast_status_peer_id);
// 		RS_SERIAL_PROCESS(type);
// 		RS_SERIAL_PROCESS(peer_id);
// 		RS_SERIAL_PROCESS(distant_chat_id);
// 		RS_SERIAL_PROCESS(lobby_id);
// 	}
// };

#[repr(u8)]
#[derive(Debug, Serialize_repr, Deserialize_repr, Clone)]
pub enum ChatIdType {
    TypeNotSet = 0,
    TypePrivate,        // private chat with directly connected friend, peer_id is valid
    TypePrivateDistant, // private chat with distant peer, gxs_id is valid
    TypeLobby,          // chat lobby id, lobby_id is valid
    TypeBroadcast,      // message to/from all connected peers
}

impl Default for ChatIdType {
    fn default() -> Self {
        Self::TypeNotSet
    }
}

// This is an older version that feels more like C++ instead of Rust
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct ChatId {
    #[serde(default)]
    pub broadcast_status_peer_id: PeerIdHex,
    #[serde(rename(serialize = "type", deserialize = "type"))]
    pub ty: ChatIdType,
    #[serde(default)]
    pub peer_id: PeerIdHex,
    #[serde(default)]
    pub distant_chat_id: DistantChatPeerIdHex,
    #[serde(default)]
    pub lobby_id: XInt64<u64>,
}

impl From<ChatLobbyId> for ChatId {
    fn from(lobby_id: ChatLobbyId) -> Self {
        Self {
            ty: ChatIdType::TypeLobby,
            lobby_id: lobby_id.into(),
            ..Default::default()
        }
    }
}

impl From<PeerId> for ChatId {
    fn from(peer_id: PeerId) -> Self {
        Self {
            ty: ChatIdType::TypePrivate,
            peer_id: peer_id.into(),
            ..Default::default()
        }
    }
}

impl From<DistantChatPeerId> for ChatId {
    fn from(distant_chat_id: DistantChatPeerId) -> Self {
        Self {
            ty: ChatIdType::TypePrivateDistant,
            distant_chat_id: distant_chat_id.into(),
            ..Default::default()
        }
    }
}

// This is a more Rust like version, which sadly doesn't work since the type is encoded as a number

// #[derive(Debug, Serialize, Deserialize, Clone)]
// #[serde(tag = "type")]
// pub enum ChatId {
//     TypePrivate {
//         peer_id: PeerIdHex,
//     }, // private chat with directly connected friend, peer_id is valid
//     TypePrivateDistant {
//         distant_chat_id: DistantChatPeerIdHex,
//     }, // private chat with distant peer, gxs_id is valid
//     TypeLobby {
//         lobby_id: XInt64<u64>,
//     }, // chat lobby id, lobby_id is valid
//     TypeBroadcast, // message to/from all connected peers
// }

// impl From<ChatLobbyId> for ChatId {
//     fn from(lobby_id: ChatLobbyId) -> Self {
//         Self::TypeLobby {
//             lobby_id: lobby_id.into(),
//         }
//     }
// }

// impl From<PeerId> for ChatId {
//     fn from(peer_id: PeerId) -> Self {
//         Self::TypePrivate {
//             peer_id: peer_id.into(),
//         }
//     }
// }

// impl From<DistantChatPeerId> for ChatId {
//     fn from(distant_chat_id: DistantChatPeerId) -> Self {
//         Self::TypePrivateDistant {
//             distant_chat_id: distant_chat_id.into(),
//         }
//     }
// }

// impl Default for ChatId {
//     fn default() -> Self {
//         ChatId::TypeBroadcast
//     }
// }
