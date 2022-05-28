use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};

use crate::{
    basics::{GxsGroupId, GxsId},
    tlv::{tags::*, tlv_string::StringTagged, TlvBinaryData},
};

use self::db::{DbConnection, GxsGrpMetaData, GxsMsgMetaData};

pub mod db;
pub mod sqlite;

#[derive(Debug, PartialEq, Eq)]
pub enum GxsType {
    Forum,
    Id,
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct GxsDatabase {
    ty: GxsType,
    db: DbConnection,
}

impl GxsDatabase {
    pub fn new(ty: GxsType, db: DbConnection) -> Self {
        GxsDatabase { ty, db }
    }

    pub fn get_meta(&self) -> Vec<GxsGrpMetaData> {
        self.db.get_grp_meta().unwrap()
    }

    pub fn get_msg(&self) -> Vec<GxsMsgMetaData> {
        self.db.get_grp_msg().unwrap()
    }

    pub fn get_type(&self) -> &GxsType {
        &self.ty
    }
}

// /*!
//  * Base class for Network exchange service
//  * Main purpose is for rtti based routing used in the
//  * serialisation and deserialisation of NXS packets
//  *
//  * Service type is set by plugin service
//  */
// class RsNxsItem : public RsItem
// {
// public:
// 	RsNxsItem(uint16_t servtype, uint8_t subtype):
// 	    RsItem(RS_PKT_VERSION_SERVICE, servtype, subtype), transactionNumber(0)
// 	{ setPriorityLevel(QOS_PRIORITY_RS_GXS_NET); }

// 	virtual ~RsNxsItem() = default;

// 	uint32_t transactionNumber; // set to zero if this is not a transaction item
// };
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct NxsItem {
    #[serde(rename(serialize = "transactionNumber", deserialize = "transactionNumber"))]
    pub transaction_number: u32,
}

// /*!
//  * Use to request grp list from peer
//  * Server may advise client peer to use sync file
//  * while serving his request. This results
//  */
// class RsNxsSyncGrpReqItem : public RsNxsItem
// {
// public:

// 	static const uint8_t FLAG_USE_SYNC_HASH;
// 	static const uint8_t FLAG_ONLY_CURRENT; // only send most current version of grps / ignores sync hash

// 	explicit RsNxsSyncGrpReqItem(uint16_t servtype) : RsNxsItem(servtype, RS_PKT_SUBTYPE_NXS_SYNC_GRP_REQ_ITEM) { clear();}
// 	virtual void clear() override;

// 	virtual void serial_process(RsGenericSerializer::SerializeJob j,RsGenericSerializer::SerializeContext& ctx) override;
// RsTypeSerializer::serial_process<uint32_t>(j,ctx,transactionNumber,"transactionNumber") ;
// RsTypeSerializer::serial_process<uint8_t> (j,ctx,flag             ,"flag") ;
// RsTypeSerializer::serial_process<uint32_t>(j,ctx,createdSince     ,"createdSince") ;
// RsTypeSerializer::serial_process          (j,ctx,TLV_TYPE_STR_HASH_SHA1,syncHash,"syncHash") ;
// RsTypeSerializer::serial_process<uint32_t>(j,ctx,updateTS         ,"updateTS") ;

// 	uint8_t flag; // advises whether to use sync hash
// 	uint32_t createdSince; // how far back to sync data
// 	uint32_t updateTS; // time of last group update
// 	std::string syncHash; // use to determine if changes that have occured since last hash
// };
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct NxsSyncGrpReqItem {
    pub base: NxsItem,

    pub flag: u8, // advises whether to use sync hash
    #[serde(rename(serialize = "createdSince", deserialize = "createdSince"))]
    pub created_since: u32, // how far back to sync data
    #[serde(rename(serialize = "syncHash", deserialize = "syncHash"))]
    pub sync_hash: StringTagged<TLV_TYPE_STR_HASH_SHA1>, // use to determine if changes that have occured since last hash
    #[serde(rename(serialize = "updateTS", deserialize = "updateTS"))]
    pub update_ts: u32, // time of last group update
}

#[repr(u8)]
#[derive(Debug, Serialize_repr, Deserialize_repr, Clone)]
pub enum NxsSyncGrpItemFlags {
    Request = 0x001,
    Response = 0x002,
    // USE_SYNC_HASH= 0x001, // !?
}

// /*!
//  * Use to send to peer list of grps
//  * held by server peer
//  */
// class RsNxsSyncGrpItem: public RsNxsItem
// {

// public:

//     static const uint8_t FLAG_REQUEST;
//     static const uint8_t FLAG_RESPONSE;
//     static const uint8_t FLAG_USE_SYNC_HASH;

//     explicit RsNxsSyncGrpItem(uint16_t servtype) : RsNxsItem(servtype, RS_PKT_SUBTYPE_NXS_SYNC_GRP_ITEM) { clear();}
//     virtual ~RsNxsSyncGrpItem() {}

//     virtual void clear() override;

// 	virtual void serial_process(RsGenericSerializer::SerializeJob j,RsGenericSerializer::SerializeContext& ctx) override;

//     uint8_t flag; // request or response
//     uint32_t publishTs; // to compare to Ts of receiving peer's grp of same id

//     /// grpId of grp held by sending peer
//     RsGxsGroupId grpId;
//     RsGxsId authorId;

// };
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct NxsSyncGrpItem {
    pub base: NxsItem,

    pub flag: NxsSyncGrpItemFlags, // request or response
    #[serde(rename(serialize = "publishTs", deserialize = "publishTs"))]
    pub publish_ts: u32, // to compare to Ts of receiving peer's grp of same id
    #[serde(rename(serialize = "grpId", deserialize = "grpId"))]
    pub grp_id: GxsGroupId,
    #[serde(rename(serialize = "authorId", deserialize = "authorId"))]
    pub author_id: GxsId,
}

impl From<GxsGrpMetaData> for NxsSyncGrpItem {
    fn from(meta: GxsGrpMetaData) -> Self {
        Self {
            base: NxsItem {
                transaction_number: 0,
            },
            flag: NxsSyncGrpItemFlags::Response,
            publish_ts: meta.publish_ts as u32, // BUG rs uses rstime = i64 mostly but not always ...
            grp_id: meta.group_id,
            author_id: meta.author_id,
        }
    }
}

// /*!
//  * Contains serialised group items
//  * Each item corresponds to a group which needs to be
//  * deserialised
//  */
// class RsNxsGrp : public RsNxsItem
// {

// public:

// 	explicit RsNxsGrp(uint16_t servtype)
// 	    : RsNxsItem(servtype, RS_PKT_SUBTYPE_NXS_GRP_ITEM)
// 	    , pos(0), count(0), meta(servtype), grp(servtype), metaData(NULL)
// 	{ clear(); }
// 	virtual ~RsNxsGrp() { delete metaData; }

// 	RsNxsGrp* clone() const;

// 	virtual void clear() override;

// 	virtual void serial_process( RsGenericSerializer::SerializeJob j,
// 	                             RsGenericSerializer::SerializeContext& ctx ) override;

// 	uint8_t pos; /// used for splitting up grp
// 	uint8_t count; /// number of split up messages
// 	RsGxsGroupId grpId; /// group Id, needed to complete version Id (ncvi)
// 	static int refcount;

// 	/*!
// 	 * This should contains all data
// 	 * which is not specific to the Gxs service data
// 	 */
// 	// This is the binary data for the group meta that is sent to friends. It *should not* contain any private
// 	// key parts. This is ensured in RsGenExchange

// 	RsTlvBinaryData meta;

// 	RsTlvBinaryData grp; /// actual group data

// 	// Deserialised metaData, this is not serialised by the serialize() method. So it may contain private key parts in some cases.
// 	RsGxsGrpMetaData* metaData;
// };
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct NxsGrp<const T: u16> {
    base: NxsItem,
    pos: u8,
    /// used for splitting up grp
    count: u8,
    /// number of split up messages
    #[serde(rename(serialize = "grpId", deserialize = "grpId"))]
    grp_id: GxsGroupId,
    /// group Id, needed to complete version Id (ncvi)
    grp: TlvBinaryData<T>,
    /// actual group data
    meta: TlvBinaryData<T>,
    // Deserialised metaData, this is not serialised by the serialize() method. So it may contain private key parts in some cases.
    // RsGxsGrpMetaData* metaData;
}

// FIXME? can these be mixed? (aka is it really a bitflag?)
// BUG? RS mixes these with the transaction type (type + state in u16)
// For now split them! (Let's see how this works out)
#[repr(u8)]
#[derive(Debug, Serialize_repr, Deserialize_repr, Clone)]
pub enum NxsTransacItemFlags {
    None = 0x0,
    FlagBeginP1 = 0x01,
    FlagBeginP2 = 0x02,
    FlagEndSuccess = 0x04,
    FlagCancel = 0x08,
    FlagEndFailNum = 0x10,
    FlagEndFailTimeout = 0x20,
    FlagEndFailFull = 0x40,
}
#[repr(u8)]
#[derive(Debug, Serialize_repr, Deserialize_repr, Clone)]
pub enum NxsTransacItemType {
    None = 0x0,
    TypeGrpListResp = 0x01,
    TypeMsgListResp = 0x02,
    TypeGrpListReq = 0x04,
    TypeMsgListReq = 0x08,
    TypeGrps = 0x10,
    TypeMsgs = 0x20,
    TypeEncryptedData = 0x40,
}
// /*!
//  * This RsNxsItem is for use in enabling transactions
//  * in order to guaranttee a collection of item have been
//  * received
//  */
// class RsNxsTransacItem: public RsNxsItem {

//     public:

//         static const uint16_t FLAG_STATE_MASK = 0xff;
//         static const uint16_t FLAG_TYPE_MASK = 0xff00;

//         /** transaction state **/
//         static const uint16_t FLAG_BEGIN_P1;
//         static const uint16_t FLAG_BEGIN_P2;
//         static const uint16_t FLAG_END_SUCCESS;
//         static const uint16_t FLAG_CANCEL;
//         static const uint16_t FLAG_END_FAIL_NUM;
//         static const uint16_t FLAG_END_FAIL_TIMEOUT;
//         static const uint16_t FLAG_END_FAIL_FULL;

//         /** transaction type **/
//         static const uint16_t FLAG_TYPE_GRP_LIST_RESP;
//         static const uint16_t FLAG_TYPE_MSG_LIST_RESP;
//         static const uint16_t FLAG_TYPE_GRP_LIST_REQ;
//         static const uint16_t FLAG_TYPE_MSG_LIST_REQ;
//         static const uint16_t FLAG_TYPE_GRPS;
//         static const uint16_t FLAG_TYPE_MSGS;
//         static const uint16_t FLAG_TYPE_ENCRYPTED_DATA;

//         explicit RsNxsTransacItem(uint16_t servtype) : RsNxsItem(servtype, RS_PKT_SUBTYPE_NXS_TRANSAC_ITEM) { clear(); }
//         virtual ~RsNxsTransacItem() {}

//         virtual void clear() override;

//         virtual void serial_process(RsGenericSerializer::SerializeJob j,RsGenericSerializer::SerializeContext& ctx) override;

//         uint16_t transactFlag;
//         uint32_t nItems;
//         uint32_t updateTS;

//         // not serialised
//         uint32_t timestamp;
//     };
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct NxsTransacItem {
    pub base: NxsItem,

    #[serde(rename(serialize = "transactFlag", deserialize = "transactFlag"))]
    pub transact_type: NxsTransacItemType, // This is one field in RS
    pub transact_flag: NxsTransacItemFlags, // This is one field in RS
    // pub test: u16,
    #[serde(rename(serialize = "nItems", deserialize = "nItems"))]
    pub items: u32,
    #[serde(rename(serialize = "updateTS", deserialize = "updateTS"))]
    pub update_ts: u32,

    #[serde(skip)]
    pub timestamp: u32,
}

#[cfg(test)]
mod test_nxs_transac {
    use crate::serde::to_retroshare_wire;

    use super::{NxsItem, NxsTransacItem, NxsTransacItemFlags, NxsTransacItemType};

    #[test]
    fn test_type_state_split() {
        let item = NxsTransacItem {
            base: NxsItem {
                transaction_number: 0x42,
            },
            items: 1,
            timestamp: 2,
            transact_type: NxsTransacItemType::TypeMsgListReq,
            transact_flag: NxsTransacItemFlags::FlagEndSuccess,
            // test: 0x08 << 8 | 0x04,
            update_ts: 0x10,
        };

        let ser = to_retroshare_wire(&item);

        let expected = hex::decode("0000004208040000000100000010").unwrap();

        assert_eq!(ser, expected);
    }
}
