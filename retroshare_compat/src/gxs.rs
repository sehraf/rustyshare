use ::serde::{Deserialize, Serialize};
use rusqlite::Result;

use crate::tlv::tlv_keys::{TlvKeySignatureSet, TlvSecurityKeySet};
#[allow(unused_imports)]
use crate::{
    basics::{FileHash, GxsCircleId, GxsGroupId, GxsId, GxsMessageId, PeerId},
    gen_db_type,
    sqlite::FromSql,
};

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
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct GroupMetaData {
    #[serde(rename(serialize = "mGroupId", deserialize = "mGroupId"))]
    group_id: GxsGroupId,
    #[serde(rename(serialize = "mGroupName", deserialize = "mGroupName"))]
    group_name: String,
    #[serde(rename(serialize = "mGroupFlags", deserialize = "mGroupFlags"))]
    group_flags: u32,
    #[serde(rename(serialize = "mSignFlags", deserialize = "mSignFlags"))]
    sign_flags: u32,
    #[serde(rename(serialize = "mPublishTs", deserialize = "mPublishTs"))]
    publish_ts: i64,
    #[serde(rename(serialize = "mAuthorId", deserialize = "mAuthorId"))]
    author_id: GxsId,
    #[serde(rename(serialize = "mCircleId", deserialize = "mCircleId"))]
    circle_id: GxsCircleId,
    #[serde(rename(serialize = "mCircleType", deserialize = "mCircleType"))]
    circle_type: u32,
    #[serde(rename(serialize = "mAuthenFlags", deserialize = "mAuthenFlags"))]
    authen_flags: u32,
    #[serde(rename(serialize = "mParentGrpId", deserialize = "mParentGrpId"))]
    parent_grp_id: GxsGroupId,
    #[serde(rename(serialize = "mSubscribeFlags", deserialize = "mSubscribeFlags"))]
    subscribe_flags: u32,
    #[serde(rename(serialize = "mPop", deserialize = "mPop"))]
    pop: u32,
    #[serde(rename(serialize = "mVisibleMsgCount", deserialize = "mVisibleMsgCount"))]
    visible_msg_count: u32,
    #[serde(rename(serialize = "mLastPost", deserialize = "mLastPost"))]
    last_post: i64,
    #[serde(rename(serialize = "mLastSeen", deserialize = "mLastSeen"))]
    last_seen: i64,
    #[serde(rename(serialize = "mGroupStatus", deserialize = "mGroupStatus"))]
    group_status: u32,
    #[serde(rename(serialize = "mServiceString", deserialize = "mServiceString"))]
    service_string: String,
    #[serde(rename(serialize = "mOriginator", deserialize = "mOriginator"))]
    originator: PeerId,
    #[serde(rename(serialize = "mInternalCircle", deserialize = "mInternalCircle"))]
    internal_circle: GxsCircleId,
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
// #[derive(Debug, Default, Serialize, Deserialize)]
// pub struct GxsGrpMetaData {
//     #[serde(rename(serialize = "mGroupId", deserialize = "mGroupId"))]
//     group_id: GxsGroupId,
//     orig_grp_id: GxsGroupId,
//     parent_grp_id: GxsGroupId,
//     group_name: String,
//     group_flags: u32,
//     publish_ts: i64,
//     circle_type: u32,
//     authen_flags: u32,
//     author_id: GxsId,
//     service_string: String,
//     circle_id: GxsCircleId,
//     // TODO add type
//     // signSet: TlvKeySignatureSet,
//     // keys: TlvSecurityKeySet,
//     sign_flags: u32,
//     subscribe_flags: u32,
//     pop: u32,
//     visible_msg_count: u32,
//     last_post: i64,
//     reputation_cut_off: u32,
//     grp_size: u32,
//     group_status: u32,
//     recv_ts: u32,
//     originator: PeerId,
//     internal_circle: GxsCircleId,
//     hash: FileHash,
// }

// impl FromSql for GxsGrpMetaData {
//     // fn get_columns() -> &'static str {
//     //     "grpId, timeStamp, grpName, lastPost, popularity, msgCount, subscribeFlag, grpStatus, identity, origGrpId, serv_str, flags, authenFlags, signFlags, circleId, circleType, internalCircle, originator, hash, recv_time_stamp, parentGrpOd, rep_cutoff"
//     // }
//     fn from_row(row: &rusqlite::Row) -> Result<Self> {
//         Ok(GxsGrpMetaData {
//             group_id: row.get(0)?,
//             publish_ts: row.get(1)?,
//             group_name: row.get(2)?,
//             last_post: row.get(3)?,
//             pop: row.get(4)?,
//             visible_msg_count: row.get(5)?,
//             subscribe_flags: row.get(6)?,
//             group_status: row.get(7)?,
//             author_id: row.get(8)?,
//             orig_grp_id: row.get(9)?,
//             service_string: row.get(10)?,
//             group_flags: row.get(11)?,
//             authen_flags: row.get(12)?,
//             sign_flags: row.get(13)?,
//             circle_id: row.get(14)?,
//             circle_type: row.get(15)?,
//             internal_circle: row.get(16)?,
//             originator: row.get(17)?,
//             hash: row.get(18)?,
//             recv_ts: row.get(19)?,
//             parent_grp_id: row.get(20)?,
//             reputation_cut_off: row.get(21)?,
//             ..Default::default()
//         })
//     }
//     fn get_columns() -> Vec<String> {
//         let a: String = "grpId, timeStamp, grpName, lastPost, popularity, msgCount, subscribeFlag, grpStatus, identity, origGrpId, serv_str, flags, authenFlags, signFlags, circleId, circleType, internalCircle, originator, hash, recv_time_stamp, parentGrpId, rep_cutoff".into();
//         a.split(",").map(|s| s.trim().to_owned()).collect()
//     }
// }

gen_db_type!(
    GxsGrpMetaData,
    [group_id: GxsGroupId, "grpId"],
    [orig_grp_id: GxsGroupId, "origGrpId"],
    [parent_grp_id: GxsGroupId, "parentGrpId"],
    [group_name: String, "grpName"],
    [group_flags: u32, "flags"],
    [publish_ts: i64, "timeStamp"],
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
    [recv_ts: i64, "recv_time_stamp"],
    [originator: PeerId, "originator"],
    [internal_circle: GxsCircleId, "internalCircle"],
    [hash: FileHash, "hash"],
);

impl From<GxsGrpMetaData> for GroupMetaData {
    fn from(x: GxsGrpMetaData) -> Self {
        GroupMetaData {
            group_id: x.group_id,
            group_name: x.group_name,
            group_flags: x.group_flags,
            sign_flags: x.sign_flags,
            publish_ts: x.publish_ts,
            author_id: x.author_id,
            circle_id: x.circle_id,
            circle_type: x.circle_type,
            authen_flags: x.authen_flags,
            parent_grp_id: x.parent_grp_id,
            subscribe_flags: x.subscribe_flags,
            pop: x.pop,
            visible_msg_count: x.visible_msg_count,
            last_post: x.last_post,
            last_seen: 0,
            group_status: x.group_status,
            service_string: x.service_string,
            originator: x.originator,
            internal_circle: x.internal_circle,
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
