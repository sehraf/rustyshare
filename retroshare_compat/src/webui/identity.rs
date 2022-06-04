use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::{
    basics::{GxsIdHex, PgpIdHex},
    gxs::sqlite::database::GroupFlags,
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
