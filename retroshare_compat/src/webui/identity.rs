use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::{
    basics::{GxsCircleIdHex, GxsGroupIdHex, GxsIdHex, PeerIdHex, PgpIdHex},
    gxs::sqlite::types::{
        AuthenFlags, GroupFlags, GroupStatus, GxsCircleType, GxsGroup, GxsGrpMetaSql, SignFlags,
        SubscribeFlags,
    },
};

use super::{chat::GxsImage, XInt64};

// FIXME
pub type IdentityUsage = ();
// FIXME
pub type ReputationInfo = ();

// struct RsIdentityDetails : RsSerializable
// {
//     RsIdentityDetails() : mFlags(0), mLastUsageTS(0) {}

//     RsGxsId mId;

//     std::string mNickname;

// 	uint32_t mFlags;

// 	RsPgpId mPgpId;

// 	/// @deprecated Recogn details.
// 	RS_DEPRECATED std::list<RsRecognTag> mRecognTags;

// 	/** Cyril: Reputation details. At some point we might want to merge
// 	 * information between the two into a single global score. Since the old
// 	 * reputation system is not finished yet, I leave this in place. We should
// 	 * decide what to do with it.
// 	 */
// 	RsReputationInfo mReputation;

// 	RsGxsImage mAvatar;

// 	rstime_t mPublishTS;
// 	rstime_t mLastUsageTS;

// 	std::map<RsIdentityUsage,rstime_t> mUseCases;

// 	/// @see RsSerializable
// 	virtual void serial_process(
// 	        RsGenericSerializer::SerializeJob j,
// 	        RsGenericSerializer::SerializeContext& ctx ) override
// 	{
// 		RS_SERIAL_PROCESS(mId);
// 		RS_SERIAL_PROCESS(mNickname);
// 		RS_SERIAL_PROCESS(mFlags);
// 		RS_SERIAL_PROCESS(mPgpId);
// 		RS_SERIAL_PROCESS(mReputation);
// 		RS_SERIAL_PROCESS(mAvatar);
// 		RS_SERIAL_PROCESS(mPublishTS);
// 		RS_SERIAL_PROCESS(mLastUsageTS);
// 		RS_SERIAL_PROCESS(mUseCases);
// 	}
// 	~RsIdentityDetails() override;
// };

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct IdentityDetails {
    #[serde(rename(serialize = "mId", deserialize = "mId"))]
    pub id: GxsIdHex,
    #[serde(rename(serialize = "mNickname", deserialize = "mNickname"))]
    pub nickname: String,
    #[serde(rename(serialize = "mFlags", deserialize = "mFlags"))]
    pub flags: GroupFlags,
    #[serde(rename(serialize = "mPgpId", deserialize = "mPgpId"))]
    pub pgp_id: PgpIdHex,
    #[serde(rename(serialize = "mReputation", deserialize = "mReputation"))]
    pub reputation: ReputationInfo,
    #[serde(rename(serialize = "mAvatar", deserialize = "mAvatar"))]
    pub avatar: GxsImage,
    #[serde(rename(serialize = "mPublishTS", deserialize = "mPublishTS"))]
    pub publish_ts: XInt64<i64>,
    #[serde(rename(serialize = "mLastUsageTS", deserialize = "mLastUsageTS"))]
    pub last_usage_ts: XInt64<i64>,
    #[serde(rename(serialize = "mUseCases", deserialize = "mUseCases"))]
    pub use_cases: HashMap<IdentityUsage, XInt64<i64>>,
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
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct GxsGroupMeta {
    #[serde(rename(serialize = "mGroupId", deserialize = "mGroupId"))]
    pub group_id: GxsGroupIdHex,
    #[serde(rename(serialize = "mGroupName", deserialize = "mGroupName"))]
    pub group_name: String,
    #[serde(rename(serialize = "mGroupFlags", deserialize = "mGroupFlags"))]
    pub group_flags: GroupFlags,
    #[serde(rename(serialize = "mSignFlags", deserialize = "mSignFlags"))]
    pub sign_flags: SignFlags,
    #[serde(rename(serialize = "mPublishTs", deserialize = "mPublishTs"))]
    pub publish_ts: XInt64<i64>, // BUG rs uses u32 here but it is a timestamp
    #[serde(rename(serialize = "mAuthorId", deserialize = "mAuthorId"))]
    pub author_id: GxsIdHex,
    #[serde(rename(serialize = "mCircleId", deserialize = "mCircleId"))]
    pub circle_id: GxsCircleIdHex,
    #[serde(rename(serialize = "mCircleType", deserialize = "mCircleType"))]
    pub circle_type: GxsCircleType,
    #[serde(rename(serialize = "mAuthenFlags", deserialize = "mAuthenFlags"))]
    pub authen_flags: AuthenFlags,
    #[serde(rename(serialize = "mParentGrpId", deserialize = "mParentGrpId"))]
    pub parent_grp_id: GxsGroupIdHex,
    #[serde(rename(serialize = "mSubscribeFlags", deserialize = "mSubscribeFlags"))]
    pub subscribe_flags: SubscribeFlags,
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
    pub group_status: GroupStatus,
    #[serde(rename(serialize = "mServiceString", deserialize = "mServiceString"))]
    pub service_string: String,
    #[serde(rename(serialize = "mOriginator", deserialize = "mOriginator"))]
    pub originator: PeerIdHex,
    #[serde(rename(serialize = "mInternalCircle", deserialize = "mInternalCircle"))]
    pub internal_circle: GxsCircleIdHex,
}

impl From<GxsGrpMetaSql> for GxsGroupMeta {
    fn from(x: GxsGrpMetaSql) -> Self {
        GxsGroupMeta {
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
            // ..Default::default()
        }
    }
}

impl From<GxsGroup> for GxsGroupMeta {
    fn from(g: GxsGroup) -> Self {
        GxsGroupMeta {
            group_id: g.group_id.into(),
            group_name: g.group_name,
            group_flags: g.group_flags,
            sign_flags: g.sign_flags,
            publish_ts: g.publish_ts.into(),
            author_id: g.author_id.into(),
            circle_id: g.circle_id.into(),
            circle_type: g.circle_type,
            authen_flags: g.authen_flags,
            parent_grp_id: g.parent_grp_id.into(),
            subscribe_flags: g.subscribe_flags,
            pop: g.pop,
            visible_msg_count: g.visible_msg_count,
            last_post: g.last_post.into(),
            last_seen: g.last_post.into(),
            group_status: g.group_status,
            service_string: g.service_string,
            originator: g.originator.into(),
            internal_circle: g.internal_circle.into(),
        }
    }
}
