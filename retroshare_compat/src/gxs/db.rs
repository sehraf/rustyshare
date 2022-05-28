use std::path::PathBuf;

use log::{debug, warn};
use rusqlite::{Connection, Result};
use serde::{Deserialize, Serialize};

use crate::{
    basics::{
        FileHash, GxsCircleId, GxsCircleIdHex, GxsGroupId, GxsGroupIdHex, GxsId, GxsIdHex,
        GxsMessageId, PeerId, PeerIdHex,
    },
    gen_db_type,
    gxs::sqlite::FromSql,
    tlv::tlv_keys::{TlvKeySignatureSet, TlvSecurityKeySet},
    webui::XInt64,
};

#[derive(Debug)]
pub struct DbConnection {
    db: Connection,
}

impl DbConnection {
    pub fn new(path: PathBuf, passwd: &str) -> Result<Self> {
        let db = Connection::open(path)?;
        db.pragma_update(None, "key", passwd)?;

        Ok(DbConnection { db })
    }

    pub fn get_grp_meta(&self) -> Result<Vec<GxsGrpMetaData>> {
        let stm =
            String::from("SELECT ") + &GxsGrpMetaData::get_columns().join(",") + " FROM GROUPS";
        debug!(
            "querering {stm} on {:?}",
            self.db.path().unwrap().file_name()
        );
        let mut stm = self.db.prepare(&stm)?;
        let entries = stm
            .query_map([], |row| GxsGrpMetaData::from_row(row))?
            .filter_map(|e| match e {
                Ok(e) => Some(e),
                Err(e) => {
                    warn!("{e:?}");
                    None
                }
            })
            .collect();
        Ok(entries)
    }

    pub fn get_grp_msg(&self) -> Result<Vec<GxsMsgMetaData>> {
        let stm =
            String::from("SELECT ") + &GxsMsgMetaData::get_columns().join(",") + " FROM MESSAGES";
        debug!(
            "querering {stm} on {:?}",
            self.db.path().unwrap().file_name()
        );
        let mut stm = self.db.prepare(&stm)?;
        let entries = stm
            .query_map([], |row| GxsMsgMetaData::from_row(row))?
            .filter_map(|e| match e {
                Ok(e) => Some(e),
                Err(e) => {
                    warn!("{e:?}");
                    None
                }
            })
            .collect();
        Ok(entries)
    }
}

// RsGroupMetaData
// struct RsGroupMetaData : RsSerializable
// {
// 	   // (csoler) The correct default value to be used in mCircleType is GXS_CIRCLE_TYPE_PUBLIC, which is defined in rsgxscircles.h,
//     // but because of a loop in the includes, I cannot include it here. So I replaced with its current value 0x0001.

// 	RsGroupMetaData() : mGroupFlags(0), mSignFlags(0), mPublishTs(0),
// 	    mCircleType(0x0001), mAuthenFlags(0), mSubscribeFlags(0), mPop(0),
// 	    mVisibleMsgCount(0), mLastPost(0), mGroupStatus(0) {}

// 	virtual ~RsGroupMetaData() = default;

//     void operator =(const RsGxsGrpMetaData& rGxsMeta);
//     RsGroupMetaData(const RsGxsGrpMetaData& rGxsMeta) { operator=(rGxsMeta); }

//     RsGxsGroupId mGroupId;
//     std::string mGroupName;
// 	   uint32_t    mGroupFlags;  // Combination of FLAG_PRIVACY_PRIVATE | FLAG_PRIVACY_RESTRICTED | FLAG_PRIVACY_PUBLIC: diffusion
//     uint32_t    mSignFlags;   // Combination of RSGXS_GROUP_SIGN_PUBLISH_MASK & RSGXS_GROUP_SIGN_AUTHOR_MASK, i.e. what signatures are required for parent and child msgs

//     rstime_t      mPublishTs; // Mandatory.
//     RsGxsId    mAuthorId;   // Author of the group. Left to "000....0" if anonymous

//     // for circles
//     RsGxsCircleId mCircleId;	// Id of the circle to which the group is restricted
//     uint32_t mCircleType;		// combination of CIRCLE_TYPE_{ PUBLIC,EXTERNAL,YOUR_FRIENDS_ONLY,LOCAL,EXT_SELF,YOUR_EYES_ONLY }

//     // other stuff.
//     uint32_t mAuthenFlags;		// Actually not used yet.
//     RsGxsGroupId mParentGrpId;

//     // BELOW HERE IS LOCAL DATA, THAT IS NOT FROM MSG.

//     uint32_t    mSubscribeFlags;

//     uint32_t    mPop; 			   // Popularity = number of friend subscribers
//     uint32_t    mVisibleMsgCount;  // Max messages reported by friends
//     rstime_t    mLastPost; 		   // Timestamp for last message. Not used yet.
//     rstime_t    mLastSeen; 		   // Last time the group was advertised by friends.

//     uint32_t    mGroupStatus;

// 	   /// Service Specific Free-Form local (non-synced) extra storage.
// 	   std::string mServiceString;
//     RsPeerId mOriginator;
//     RsGxsCircleId mInternalCircle;
// };
#[allow(unused)]
#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub struct GroupMetaData {
    #[serde(rename(serialize = "mGroupId", deserialize = "mGroupId"))]
    pub group_id: GxsGroupIdHex,
    #[serde(rename(serialize = "mGroupName", deserialize = "mGroupName"))]
    pub group_name: String,
    #[serde(rename(serialize = "mGroupFlags", deserialize = "mGroupFlags"))]
    pub group_flags: u32,
    #[serde(rename(serialize = "mSignFlags", deserialize = "mSignFlags"))]
    pub sign_flags: u32,
    #[serde(rename(serialize = "mPublishTs", deserialize = "mPublishTs"))]
    pub publish_ts: XInt64<i64>, // BUG rs uses u32 here but it is a timestamp
    #[serde(rename(serialize = "mAuthorId", deserialize = "mAuthorId"))]
    pub author_id: GxsIdHex,
    #[serde(rename(serialize = "mCircleId", deserialize = "mCircleId"))]
    pub circle_id: GxsCircleIdHex,
    #[serde(rename(serialize = "mCircleType", deserialize = "mCircleType"))]
    pub circle_type: u32,
    #[serde(rename(serialize = "mAuthenFlags", deserialize = "mAuthenFlags"))]
    pub authen_flags: u32,
    #[serde(rename(serialize = "mParentGrpId", deserialize = "mParentGrpId"))]
    pub parent_grp_id: GxsGroupIdHex,
    #[serde(rename(serialize = "mSubscribeFlags", deserialize = "mSubscribeFlags"))]
    pub subscribe_flags: u32,
    #[serde(rename(serialize = "mPop", deserialize = "mPop"))]
    pub pop: u32,
    #[serde(rename(serialize = "mVisibleMsgCount", deserialize = "mVisibleMsgCount"))]
    pub visible_msg_count: u32,
    #[serde(rename(serialize = "mLastPost", deserialize = "mLastPost"))]
    pub last_post: XInt64<i64>,
    #[serde(skip)]
    #[serde(rename(serialize = "mLastSeen", deserialize = "mLastSeen"))]
    pub last_seen: i64,
    #[serde(rename(serialize = "mGroupStatus", deserialize = "mGroupStatus"))]
    pub group_status: u32,
    #[serde(rename(serialize = "mServiceString", deserialize = "mServiceString"))]
    pub service_string: String,
    #[serde(rename(serialize = "mOriginator", deserialize = "mOriginator"))]
    pub originator: PeerIdHex,
    #[serde(rename(serialize = "mInternalCircle", deserialize = "mInternalCircle"))]
    pub internal_circle: GxsCircleIdHex,
}

// class RsGxsGrpMetaData
// {
// public:
//     static const int MAX_ALLOWED_STRING_SIZE = 50 ;

//     RsGxsGrpMetaData();
//     bool deserialise(void *data, uint32_t &pktsize);
//     bool serialise(void* data, uint32_t &pktsize, uint32_t api_version);
//     uint32_t serial_size(uint32_t api_version) const;
//     uint32_t serial_size() const { return serial_size(RS_GXS_GRP_META_DATA_CURRENT_API_VERSION); }
//     void clear();
//     void operator =(const RsGroupMetaData& rMeta);

//     //Sort data in same order than serialiser and deserializer
//     RsGxsGroupId mGroupId;
//     RsGxsGroupId mOrigGrpId;
//     RsGxsGroupId mParentGrpId;
//     std::string mGroupName;
//     uint32_t    mGroupFlags;	// GXS_SERV::FLAG_PRIVACY_RESTRICTED | GXS_SERV::FLAG_PRIVACY_PRIVATE | GXS_SERV::FLAG_PRIVACY_PUBLIC
//     uint32_t    mPublishTs;
//     uint32_t mCircleType;
//     uint32_t mAuthenFlags;
//     RsGxsId mAuthorId;
//     std::string mServiceString;
//     RsGxsCircleId mCircleId;
//     RsTlvKeySignatureSet signSet;
//     RsTlvSecurityKeySet keys;

//     uint32_t    mSignFlags;

//     // BELOW HERE IS LOCAL DATA, THAT IS NOT FROM MSG.

//     uint32_t    mSubscribeFlags;

//     uint32_t    mPop; 			// Number of friends who subscribed
//     uint32_t    mVisibleMsgCount; 	// Max number of messages reported by a single friend (used for unsubscribed groups)
//     uint32_t    mLastPost; 		// Time stamp of last post (not yet filled)
//     uint32_t    mReputationCutOff;
//     uint32_t    mGrpSize;

//     uint32_t    mGroupStatus;
//     uint32_t    mRecvTS;
//     RsPeerId    mOriginator;
//     RsGxsCircleId mInternalCircle;
//     RsFileHash mHash;
// };

gen_db_type!(
    GxsGrpMetaData,
    [group_id: GxsGroupId, "grpId"],
    [orig_grp_id: GxsGroupId, "origGrpId"],
    [parent_grp_id: GxsGroupId, "parentGrpId"],
    [group_name: String, "grpName"],
    [group_flags: u32, "flags"],
    [publish_ts: i64, "timeStamp"], // BUG rs uses u32 here but it is a timestamp
    [circle_type: u32, "circleType"],
    [authen_flags: u32, "authenFlags"],
    [author_id: GxsId, "identity"],
    [service_string: String, "serv_str"],
    [circle_id: GxsCircleId, "circleId"],
    [sign_set: TlvKeySignatureSet, "signSet"],
    [keys: TlvSecurityKeySet, "keySet"],
    [sign_flags: u32, "signFlags"],
    [subscribe_flags: u32, "subscribeFlag"],
    [pop: u32, "popularity"],
    [visible_msg_count: u32, "msgCount"],
    [last_post: i64, "lastPost"],
    [reputation_cut_off: u32, "rep_cutoff"],
    [grp_size: u32, ""],
    [group_status: u32, "grpStatus"],
    [recv_ts: i64, "recv_time_stamp"], // BUG rs uses u32 here but it is a timestamp
    [originator: PeerId, "originator"],
    [internal_circle: GxsCircleId, "internalCircle"],
    [hash: FileHash, "hash"],
);

impl From<GxsGrpMetaData> for GroupMetaData {
    fn from(x: GxsGrpMetaData) -> Self {
        GroupMetaData {
            group_id: x.group_id.into(),
            group_name: x.group_name,
            group_flags: x.group_flags,
            sign_flags: x.sign_flags,
            publish_ts: x.publish_ts.into(),
            author_id: x.author_id.into(),
            circle_id: x.circle_id.into(),
            circle_type: x.circle_type,
            authen_flags: x.authen_flags,
            parent_grp_id: x.parent_grp_id.into(),
            subscribe_flags: x.subscribe_flags,
            pop: x.pop,
            visible_msg_count: x.visible_msg_count,
            last_post: x.last_post.into(),
            last_seen: 0,
            group_status: x.group_status,
            service_string: x.service_string,
            originator: x.originator.into(),
            internal_circle: x.internal_circle.into(),
            ..Default::default()
        }
    }
}

// class RsGxsMsgMetaData
// {
// public:

//     explicit RsGxsMsgMetaData();
//     ~RsGxsMsgMetaData();
//     bool deserialise(void *data, uint32_t *size);
//     bool serialise(void* data, uint32_t *size);
//     uint32_t serial_size() const;
//     void clear();
//     void operator =(const RsMsgMetaData& rMeta);

//     //Sort data in same order than serialiser and deserializer
//     RsGxsGroupId mGroupId;
//     RsGxsMessageId mMsgId;
//     RsGxsMessageId mThreadId;
//     RsGxsMessageId mParentId;
//     RsGxsMessageId mOrigMsgId;
//     RsGxsId mAuthorId;

//     RsTlvKeySignatureSet signSet;
//     std::string mMsgName;
//     rstime_t      mPublishTs;
//     uint32_t    mMsgFlags; // used by some services (e.g. by forums to store message moderation flags)

//     // BELOW HERE IS LOCAL DATA, THAT IS NOT FROM MSG.
//     // normally READ / UNREAD flags. LOCAL Data.

//     std::string mServiceString;
//     uint32_t    mMsgStatus;
//     uint32_t    mMsgSize;
//     rstime_t      mChildTs;
//     uint32_t recvTS;
//     RsFileHash mHash;
//     bool validated;
// };

gen_db_type!(
    GxsMsgMetaData,
    [msg_id: GxsMessageId, "msgId"],
    [group_id: GxsGroupId, "grpId"],
    [thread_id: GxsMessageId, "threadId"],
    [parent_id: GxsMessageId, "parentId"],
    [orig_msg_id: GxsMessageId, "origMsgId"],
    [author_id: GxsId, "identity"],
    [sign_set: TlvKeySignatureSet, "signSet"],
    [msg_name: String, "msgName"],
    [publish_ts: i64, "timeStamp"],
    [msg_flags: u32, "flags"],
    [service_string: String, "serv_str"],
    [msg_status: u32, "msgStatus"],
    [msg_size: u64, ""],
    [child_ts: i64, "childTs"],
    [recv_ts: i64, "recv_time_stamp"],
    [hash: FileHash, "hash"],
    [validated: bool, ""],
);

gen_db_type!(
    GxsDatabaseRelease,
    [id: u32, "id"],
    [release: u32, "release"],
);
