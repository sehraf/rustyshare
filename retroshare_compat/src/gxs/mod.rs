use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};

use crate::{
    basics::{GxsGroupId, GxsId, PeerId},
    tlv::{tags::*, tlv_string::StringTagged, TlvBinaryData},
};

use self::sqlite::{
    database::GxsDatabase,
    types::{GxsGroup, GxsGrpDataSql, GxsGrpMetaSql, GxsMsgMetaSql},
};

pub mod service_string;
pub mod sqlite;

#[derive(Debug, PartialEq, Eq)]
pub enum GxsType {
    Forum,
    Id,
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct GxsDatabaseBackend {
    ty: GxsType,
    db: GxsDatabase,
}

impl GxsDatabaseBackend {
    pub fn new(ty: GxsType, db: GxsDatabase) -> Self {
        GxsDatabaseBackend { ty, db }
    }

    pub fn get_grp_meta(&self, group_ids: &Vec<GxsGroupId>) -> Vec<GxsGroup> {
        let mut res = vec![];

        if group_ids.is_empty() {
            for group_id in self.db.get_group_ids().unwrap() {
                res.extend(self.db.get_grp_meta(&group_id).unwrap());
            }
        } else {
            for group_id in group_ids {
                res.extend(self.db.get_grp_meta(group_id).unwrap());
            }
        }

        res
    }

    pub fn get_grp_data(&self, group_ids: &Vec<GxsGroupId>) -> Vec<GxsGrpDataSql> {
        let mut res = vec![];

        let get = |group_id: &GxsGroupId| -> Vec<GxsGrpDataSql> {
            match self.db.get_grp_meta(group_id).unwrap() {
                None => vec![],
                Some(mut group_meta) => {
                    self.db.get_grp_data(&mut group_meta).unwrap();
                    vec![group_meta.get_blobs()]
                }
            }
        };

        if group_ids.is_empty() {
            for group_id in self.db.get_group_ids().unwrap() {
                res.extend(get(&group_id));
            }
        } else {
            for group_id in group_ids {
                res.extend(get(group_id));
            }
        }

        res
    }

    pub fn store_group(&self, group: &GxsGroup) {
        self.db.insert_group(group).unwrap()
    }

    pub fn get_msg(&self) -> Vec<GxsMsgMetaSql> {
        self.db.get_msg_meta_all().unwrap()
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
#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub struct NxsItem {
    #[serde(rename(serialize = "transactionNumber", deserialize = "transactionNumber"))]
    pub transaction_id: u32,

    /// Used to store the communication partner. RS uses the base class RsItem to do so.
    #[serde(skip)]
    pub peer_id: PeerId,
}

// /*!
//  * Use to request grp list from peer
//  * Server may advise client peer to use sync file
//  * while serving his request. This results
//  */
// class RsNxsSyncGrpReqItem : public RsNxsItem
// {
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
#[derive(Debug, Serialize_repr, Deserialize_repr, Clone, PartialEq)]
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
    #[serde(rename(serialize = "grpId", deserialize = "grpId"))]
    pub grp_id: GxsGroupId,
    #[serde(rename(serialize = "publishTs", deserialize = "publishTs"))]
    pub publish_ts: u32, // to compare to Ts of receiving peer's grp of same id // BUG this is not i64 = rstime_t
    #[serde(rename(serialize = "authorId", deserialize = "authorId"))]
    pub author_id: GxsId,
}

// obsolete
// impl From<GxsGrpMetaSql> for NxsSyncGrpItem {
//     fn from(meta: GxsGrpMetaSql) -> Self {
//         Self {
//             base: NxsItem { transaction_id: 0 },
//             flag: NxsSyncGrpItemFlags::Response,
//             publish_ts: meta.publish_ts as u32, // BUG rs uses rstime_t = i64 mostly but not always ...
//             grp_id: meta.group_id,
//             author_id: meta.author_id,
//         }
//     }
// }

// /*!
//  * Contains serialised group items
//  * Each item corresponds to a group which needs to be
//  * deserialised
//  */
// class RsNxsGrp : public RsNxsItem
// {
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
    pub base: NxsItem,

    pub pos: u8, // used for splitting up grp
    #[serde(skip)]
    pub count: u8, // number of split up messages
    #[serde(rename(serialize = "grpId", deserialize = "grpId"))]
    pub grp_id: GxsGroupId, // group Id, needed to complete version Id (ncvi)
    pub grp: TlvBinaryData<T>, // actual group data
    pub meta: TlvBinaryData<T>,

    // TODO
    // Deserialized metaData, this is not serialized by the serialize() method. So it may contain private key parts in some cases.
    #[serde(skip)]
    #[serde(rename(serialize = "metaData", deserialize = "metaData"))]
    pub meta_data: Option<GxsGrpMetaSql>,
}

// FIXME? can these be mixed? (aka is it really a bitflag?)
// BUG? RS mixes these with the transaction type (type + state in one single u16)
// For now split them! (Let's see how this works out .. seems to workout good! )

/// Values representing the purpose of a transaction packet `NxsTransactionItem`. Only one should be set (the phrase "flag" may not be confused with a bit flag).
///
/// Note:
/// RetroShare uses these together with the transaction type `NxsTransactionItemType` combined in one 16-bit wide value.
/// Since both fit nicely into two 8-bit values, they are splitted here and treated as two "stand-alone" types.
/// Therefore, bit operations (e.g. to check the transaction type) can be avoided.
///
#[repr(u8)]
#[derive(Debug, Serialize_repr, Deserialize_repr, Clone, PartialEq)]
pub enum NxsTransactionItemFlags {
    None = 0x0,
    FlagBegin = 0x01,    // FlagBeginP1
    FlagBeginAck = 0x02, // FlagBeginP2
    FlagEndSuccess = 0x04,

    UnusedFlagCancel = 0x08,
    UnusedFlagEndFailNum = 0x10,
    UnusedFlagEndFailTimeout = 0x20,
    UnusedFlagEndFailFull = 0x40,
}

/// Values representing the type or purpose of a transaction.
///
/// Note:
/// RetroShare uses these together with the transaction flags `NxsTransactionItemFlags` combined in one 16-bit wide value.
///
#[repr(u8)]
#[derive(Debug, Serialize_repr, Deserialize_repr, Clone)]
pub enum NxsTransactionItemType {
    None = 0x0,
    GroupListResponse = 0x01,
    MessageListResponse = 0x02,
    GroupListRequest = 0x04,
    MessageListRequest = 0x08,
    Groups = 0x10,
    Messages = 0x20,
    EncryptedData = 0x40,
}
// /*!
//  * This RsNxsItem is for use in enabling transactions
//  * in order to guaranttee a collection of item have been
//  * received
//  */
// class RsNxsTransacItem: public RsNxsItem {
//         uint16_t transactFlag;
//         uint32_t nItems;
//         uint32_t updateTS;
//         // not serialised
//         uint32_t timestamp;
//     };
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct NxsTransactionItem {
    pub base: NxsItem,

    #[serde(rename(serialize = "transactFlag", deserialize = "transactFlag"))]
    pub transact_type: NxsTransactionItemType, // This is one field in RS
    pub transact_flag: NxsTransactionItemFlags, // This is one field in RS
    #[serde(rename(serialize = "nItems", deserialize = "nItems"))]
    pub items: u32,
    #[serde(rename(serialize = "updateTS", deserialize = "updateTS"))]
    pub update_ts: u32,

    #[serde(skip)]
    pub timestamp: u32,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct GxsReputation {
    #[serde(rename(serialize = "OverallScore", deserialize = "OverallScore"))]
    overall_score: i32,
    #[serde(rename(serialize = "IdScore", deserialize = "IdScore"))]
    id_score: i32, // PGP, Known, etc.
    #[serde(rename(serialize = "OwnOpinion", deserialize = "OwnOpinion"))]
    own_opinion: i32,
    #[serde(rename(serialize = "PeerOpinion", deserialize = "PeerOpinion"))]
    peer_opinion: i32,
}

#[cfg(test)]
mod test_nxs_transaction {
    use crate::serde::to_retroshare_wire;

    use super::{NxsItem, NxsTransactionItem, NxsTransactionItemFlags, NxsTransactionItemType};

    #[test]
    fn test_type_state_split() {
        let item = NxsTransactionItem {
            base: NxsItem {
                transaction_id: 0x42,
                ..Default::default()
            },
            items: 1,
            timestamp: 2,
            transact_type: NxsTransactionItemType::MessageListRequest,
            transact_flag: NxsTransactionItemFlags::FlagEndSuccess,
            // test: 0x08 << 8 | 0x04,
            update_ts: 0x10,
        };

        let ser = to_retroshare_wire(&item);

        let expected = hex::decode("0000004208040000000100000010").unwrap();

        assert_eq!(ser, expected);
    }
}
