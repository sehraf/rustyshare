use bitflags::bitflags;
use bitflags_serde_shim::impl_serde_for_bitflags;
use rusqlite::{types::FromSql, ToSql};
use serde::Deserialize;
use serde_repr::{Deserialize_repr, Serialize_repr};

use crate::{
    basics::{FileHash, GxsCircleId, GxsGroupId, GxsId, GxsMessageId, PeerId},
    gen_db_type,
    gxs::{NxsGrp, NxsItem, NxsSyncGrpItem, NxsSyncGrpItemFlags},
    impl_sql_for_bitflags, read_u32,
    serde::{from_retroshare_wire, from_retroshare_wire_result},
    tlv::{
        tlv_keys::{TlvKeySignatureSet, TlvSecurityKeySet},
        tlv_string::StringTagged,
    },
};

use super::database::{
    KEY_CHILD_TS, KEY_DATABASE_RELEASE, KEY_DATABASE_RELEASE_ID, KEY_GRP_AUTHEN_FLAGS,
    KEY_GRP_CIRCLE_ID, KEY_GRP_CIRCLE_TYPE, KEY_GRP_ID, KEY_GRP_INTERNAL_CIRCLE, KEY_GRP_LAST_POST,
    KEY_GRP_NAME, KEY_GRP_ORIGINATOR, KEY_GRP_POP, KEY_GRP_REP_CUTOFF, KEY_GRP_SIGN_FLAGS,
    KEY_GRP_STATUS, KEY_GRP_SUBCR_FLAG, KEY_KEY_SET, KEY_MSG_COUNT, KEY_MSG_ID, KEY_MSG_NAME,
    KEY_MSG_PARENT_ID, KEY_MSG_STATUS, KEY_MSG_THREAD_ID, KEY_NXS_DATA, KEY_NXS_DATA_LEN,
    KEY_NXS_FLAGS, KEY_NXS_HASH, KEY_NXS_IDENTITY, KEY_NXS_META, KEY_NXS_SERV_STRING,
    KEY_ORIG_GRP_ID, KEY_ORIG_MSG_ID, KEY_PARENT_GRP_ID, KEY_RECV_TS, KEY_SIGN_SET, KEY_TIME_STAMP,
};

// BUG? why is this an u32 when an u16 definition is used (and tags usually are u16)
const GXS_GRP_META_DATA_VERSION_ID_0002: u32 = 0xaf01;

type Blob = Vec<u8>;

// uint32_t    mGroupFlags;  // Combination of FLAG_PRIVACY_PRIVATE | FLAG_PRIVACY_RESTRICTED | FLAG_PRIVACY_PUBLIC: diffusion
bitflags! {
    #[derive(Default)]
    pub struct GroupFlags: u32 {
        // const PRIVACY_MASK       = 0x0000000f;
        const PRIVACY_PRIVATE    = 0x00000001; // pub key encrypted. No-one can read unless he has the key to decrypt the publish key.
        const PRIVACY_RESTRICTED = 0x00000002; // publish private key needed to publish. Typical usage: channels.
        const PRIVACY_PUBLIC     = 0x00000004; // anyone can publish, publish key pair not needed. Typical usage: forums.
        const REALID             = 0x00000100;
    }
}
impl_serde_for_bitflags!(GroupFlags);
impl_sql_for_bitflags!(GroupFlags);

// uint32_t    mSignFlags;   // Combination of RSGXS_GROUP_SIGN_PUBLISH_MASK & RSGXS_GROUP_SIGN_AUTHOR_MASK, i.e. what signatures are required for parent and child msgs
bitflags! {
    #[derive(Default)]
    pub struct SignFlags: u32 {
        // const GROUP_SIGN_PUBLISH_MASK              = 0x000000ff;
        const GROUP_SIGN_PUBLISH_ENCRYPTED         = 0x00000001;
        const GROUP_SIGN_PUBLISH_ALLSIGNED         = 0x00000002; // unused
        const GROUP_SIGN_PUBLISH_THREADHEAD        = 0x00000004;
        const GROUP_SIGN_PUBLISH_NONEREQ           = 0x00000008;
        // const AUTHOR_AUTHENTICATION_MASK           = 0x0000ff00;
        // const AUTHOR_AUTHENTICATION_NONE           = 0x00000000;
        const AUTHOR_AUTHENTICATION_GPG            = 0x00000100; // Anti-spam feature. Allows to ask higher reputation to anonymous IDs
        const AUTHOR_AUTHENTICATION_REQUIRED       = 0x00000200;
        const AUTHOR_AUTHENTICATION_IFNOPUBSIGN    = 0x00000400; // ???
        const AUTHOR_AUTHENTICATION_TRACK_MESSAGES = 0x00000800; // not used anymore
        const AUTHOR_AUTHENTICATION_GPG_KNOWN      = 0x00001000; // Anti-spam feature. Allows to ask higher reputation to unknown IDs and anonymous IDs
    }
}
impl_serde_for_bitflags!(SignFlags);
impl_sql_for_bitflags!(SignFlags);

bitflags! {
    // BUG RetroShare defines these as u8
    #[derive(Default)]
    pub struct AuthenFlags: u32 {
        const ROOT_PUBLISH_SIGN  = 0x00000001; // means: new threads need to be signed by the publish signature of the group. Typical use: posts in channels.
        const CHILD_PUBLISH_SIGN = 0x00000002; // means: all messages need to be signed by the publish signature of the group. Typical use: channels were comments are restricted to the publisher.
        const ROOT_AUTHOR_SIGN   = 0x00000004; // means: new threads need to be signed by the author of the message. Typical use: forums, since posts are signed.
        const CHILD_AUTHOR_SIGN  = 0x00000008; // means: all messages need to be signed by the author of the message. Typical use: forums since response to posts are signed, and signed comments in channels.
    }
}
impl_serde_for_bitflags!(AuthenFlags);
impl_sql_for_bitflags!(AuthenFlags);

bitflags! {
    #[derive(Default)]
    pub struct SubscribeFlags: u32 {
        const ADMIN          = 0x00000001; // means: you have the admin key for this group
        const PUBLISH        = 0x00000002; // means: you have the publish key for this group. Typical use: publish key in channels are shared with specific friends.
        const SUBSCRIBED     = 0x00000004; // means: you are subscribed to a group, which makes you a source for this group to your friend nodes.
        const NOT_SUBSCRIBED = 0x00000008;
    }
}
impl_serde_for_bitflags!(SubscribeFlags);
impl_sql_for_bitflags!(SubscribeFlags);

#[repr(u32)] // BUG?  RetroShare: "32 bit overkill, just for retrocompat"
#[derive(Debug, Serialize_repr, Deserialize_repr, Clone, PartialEq)]
pub enum GxsCircleType {
    /// Used to detect uninitialized values.
    Unknown = 0,
    /// Public distribution
    Public = 1,
    /// Restricted to an external circle, based on GxsIds
    External = 2,
    /// Restricted to a group of friend nodes, the administrator of the circle behave as a hub for them. Based on PGP nodes ids.
    NodesGroup = 3,
    /// not distributed at all
    Local = 4,
    /// Self-restricted. Used only at creation time of self-restricted circles when the circle id isn't known yet. Once the circle id is known the type is set to EXTERNAL, and the external circle id is set to the id of the circle itself. Based on GxsIds.
    ExtSelf = 5,
    /// distributed to nodes signed by your own PGP key only.
    YourEyesOnly = 6,
}

impl Default for GxsCircleType {
    fn default() -> Self {
        Self::Unknown
    }
}

impl FromSql for GxsCircleType {
    fn column_result(value: rusqlite::types::ValueRef<'_>) -> rusqlite::types::FromSqlResult<Self> {
        let value = value.as_i64()? as u32;
        let x = match value {
            1 => GxsCircleType::Public,
            2 => GxsCircleType::External,
            3 => GxsCircleType::NodesGroup,
            4 => GxsCircleType::Local,
            5 => GxsCircleType::ExtSelf,
            6 => GxsCircleType::YourEyesOnly,
            0 | _ => GxsCircleType::Unknown,
        };
        Ok(x)
    }
}

impl ToSql for GxsCircleType {
    fn to_sql(&self) -> rusqlite::Result<rusqlite::types::ToSqlOutput<'_>> {
        Ok((self.to_owned() as u32).into())
    }
}

// /** START GXS Msg status flags **/
// /*!
//  * Two lower bytes are reserved for Generic STATUS Flags listed here.
//  * Services are free to use the two upper bytes. (16 flags).
//  *
//  * NOTE: RsGxsCommentService uses 0x000f0000.
//  */
// static const uint32_t GXS_MSG_STATUS_GEN_MASK    = 0x0000ffff;
// static const uint32_t GXS_MSG_STATUS_UNPROCESSED = 0x00000001;	// Flags to store the read/process status of group messages.
// static const uint32_t GXS_MSG_STATUS_GUI_UNREAD  = 0x00000002;	// The actual meaning may depend on the type of service.
// static const uint32_t GXS_MSG_STATUS_GUI_NEW     = 0x00000004;	//
// static const uint32_t GXS_MSG_STATUS_KEEP_FOREVER = 0x00000008; // Do not delete message even if older then group maximum storage time
// static const uint32_t GXS_MSG_STATUS_DELETE      = 0x00000020;	//

// /** END GXS Msg status flags **/
// /** START GXS Grp status flags **/
// static const uint32_t GXS_GRP_STATUS_UNPROCESSED = 0x000000100;
// static const uint32_t GXS_GRP_STATUS_UNREAD      = 0x000000200;

// /** END GXS Grp status flags **/
bitflags! {
    #[derive(Default)]
    pub struct GroupStatus: u32 {
        // const GXS_MSG_STATUS_GEN_MASK    = 0x0000ffff;
        const MSG_UNPROCESSED      = 0x00000001;	// Flags to store the read/process status of group messages.
        const MSG_GUI_UNREAD       = 0x00000002;	// The actual meaning may depend on the type of service.
        const MSG_GUI_NEW          = 0x00000004;	//
        const MSG_KEEP_FOREVER     = 0x00000008; // Do not delete message even if older then group maximum storage time
        const MSG_DELETE           = 0x00000020;	//
        const GRP_UNPROCESSED      = 0x00000100;
        const GRP_UNREAD           = 0x00000200;
        // const CMT_GXSCOMMENT_MASK  = 0x000f0000;
        // const CMT_VOTE_MASK        = 0x00030000;
        const CMT_VOTE_UP          = 0x00010000;
        const CMT_VOTE_DOWN        = 0x00020000;
    }
}
impl_serde_for_bitflags!(GroupStatus);
impl_sql_for_bitflags!(GroupStatus);

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
    GxsGrpMetaSql,
    [group_id: GxsGroupId, KEY_GRP_ID],                // "grpId"
    [authen_flags: AuthenFlags, KEY_GRP_AUTHEN_FLAGS], // "authenFlags"
    [author_id: GxsId, KEY_NXS_IDENTITY],              // "identity"
    [circle_id: GxsCircleId, KEY_GRP_CIRCLE_ID],       // "circleId"
    [circle_type: GxsCircleType, KEY_GRP_CIRCLE_TYPE], // "circleType"
    [group_flags: GroupFlags, KEY_NXS_FLAGS],          // "flags"
    [group_name: String, KEY_GRP_NAME],                // "grpName"
    [group_status: GroupStatus, KEY_GRP_STATUS],       // "grpStatus"
    [hash: FileHash, KEY_NXS_HASH],                    // "hash"
    [internal_circle: GxsCircleId, KEY_GRP_INTERNAL_CIRCLE], // "internalCircle"
    [keys: TlvSecurityKeySet, KEY_KEY_SET],            // "keySet"
    [last_post: i64, KEY_GRP_LAST_POST],               // "lastPost"
    [originator: PeerId, KEY_GRP_ORIGINATOR],          // "originator"
    [orig_grp_id: GxsGroupId, KEY_ORIG_GRP_ID],        // "origGrpId"
    [parent_grp_id: GxsGroupId, KEY_PARENT_GRP_ID],    // "parentGrpId"
    [pop: u32, KEY_GRP_POP],                           // "popularity"
    [publish_ts: i64, KEY_TIME_STAMP],                 // "timeStamp"
    [recv_ts: i64, KEY_RECV_TS],                       // "recv_time_stamp"
    [reputation_cut_off: u32, KEY_GRP_REP_CUTOFF],     // "rep_cutoff"
    [service_string: String, KEY_NXS_SERV_STRING],     // "serv_str"
    [sign_set: TlvKeySignatureSet, KEY_SIGN_SET],      // "signSet"
    [sign_flags: SignFlags, KEY_GRP_SIGN_FLAGS],       // "signFlags"
    [subscribe_flags: SubscribeFlags, KEY_GRP_SUBCR_FLAG], // "subscribeFlag"
    [visible_msg_count: u32, KEY_MSG_COUNT],           // "msgCount"
);

impl GxsGrpMetaSql {
    pub fn from_nxs(data: &mut Vec<u8>) -> Self {
        #[derive(Debug, Deserialize)]
        struct Dummy {
            group_id: GxsGroupId,
            orig_grp_id: GxsGroupId,
            parent_grp_id: GxsGroupId,
            group_name: StringTagged<0>,
            group_flags: GroupFlags,
            publish_ts: u32, // BUG?
            circle_type: GxsCircleType,
            authen_flags: AuthenFlags,
            author_id: GxsId,
            service_string: StringTagged<0>,
            circle_id: GxsCircleId,
            sign_set: TlvKeySignatureSet,
            keys: TlvSecurityKeySet,
        }

        let tag = read_u32(data);
        let _len = read_u32(data);
        let d: Dummy = from_retroshare_wire(data);
        // let d: Dummy = from_retroshare_wire_result(data).map_err(|err| {
        //     // TODO
        //     rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Null, Box::new(err))
        // })?;

        let sign_flags = if tag == GXS_GRP_META_DATA_VERSION_ID_0002 {
            match from_retroshare_wire_result(data) {
                Ok(sf) => sf,
                Err(_) => SignFlags::empty(),
            }
        } else {
            SignFlags::empty()
        };

        Self {
            group_id: d.group_id,
            orig_grp_id: d.orig_grp_id,
            parent_grp_id: d.parent_grp_id,
            group_name: d.group_name.into(),
            group_flags: d.group_flags,
            publish_ts: d.publish_ts as i64,
            circle_type: d.circle_type,
            authen_flags: d.authen_flags,
            author_id: d.author_id,
            service_string: d.service_string.into(),
            circle_id: d.circle_id,
            sign_set: d.sign_set,
            keys: d.keys,
            sign_flags,
            ..Default::default()
        }
    }
}

gen_db_type!(
    GxsGrpDataSql,
    [group_id: GxsGroupId, KEY_GRP_ID],      // "grpId"
    [nxs_data: Blob, KEY_NXS_DATA],          // "nxsData"
    [nxs_data_len: usize, KEY_NXS_DATA_LEN], // "nxsDataLen"
    [meta_data: Blob, KEY_NXS_META],         // "meta" // GxsGrpMetaData = GxsGrpMetaSql
);

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
    GxsMsgMetaSql,
    [msg_id: GxsMessageId, KEY_MSG_ID],            // "msgId"
    [child_ts: i64, KEY_CHILD_TS],                 // "childTs"
    [group_id: GxsGroupId, KEY_GRP_ID],            // "grpId"
    [hash: FileHash, KEY_NXS_HASH],                // "hash"
    [msg_flags: u32, KEY_NXS_FLAGS],               // "flags" // These are service specific
    [msg_name: String, KEY_MSG_NAME],              // "msgName"
    [msg_size: u64, KEY_NXS_DATA_LEN],             // "nxsDataLen"
    [msg_status: u32, KEY_MSG_STATUS],             // "msgStatus"
    [nxs_identity: GxsId, KEY_NXS_IDENTITY],       // "identity"
    [orig_msg_id: GxsMessageId, KEY_ORIG_MSG_ID],  // "origMsgId"
    [parent_id: GxsMessageId, KEY_MSG_PARENT_ID],  // "parentId"
    [publish_ts: i64, KEY_TIME_STAMP],             // "timeStamp"
    [recv_ts: i64, KEY_RECV_TS],                   // "recv_time_stamp"
    [service_string: String, KEY_NXS_SERV_STRING], // "serv_str"
    [sign_set: TlvKeySignatureSet, KEY_SIGN_SET],  // "signSet"
    [thread_id: GxsMessageId, KEY_MSG_THREAD_ID],  // "threadId"
    [validated: bool, ""],
);

gen_db_type!(
    GxsMsgDataSql,
    [meta_data: Blob, KEY_NXS_META],    // "meta"
    [group_id: GxsGroupId, KEY_GRP_ID], // "grpId"
    [nxs_data: Blob, KEY_NXS_DATA],     // "nxsData"
);

gen_db_type!(
    GxsDatabaseRelease,
    [id: u32, KEY_DATABASE_RELEASE_ID],
    [release: u32, KEY_DATABASE_RELEASE],
);

#[derive(Debug)]
pub struct GxsGroupBlob {
    group_data: Option<Blob>,
    group_len: usize,
    meta_data: Option<Blob>,
}
#[derive(Debug)]
pub struct GxsGroup {
    pub group_id: GxsGroupId,

    pub authen_flags: AuthenFlags,
    pub author_id: GxsId,

    pub circle_id: GxsCircleId,
    pub circle_type: GxsCircleType,

    pub group_flags: GroupFlags,
    pub group_name: String,
    pub group_status: GroupStatus,

    pub hash: FileHash,
    pub internal_circle: GxsCircleId,

    pub keys: TlvSecurityKeySet,
    pub last_post: i64,

    pub originator: PeerId,
    pub orig_grp_id: GxsGroupId,
    pub parent_grp_id: GxsGroupId,

    pub pop: u32,
    pub publish_ts: i64,
    pub recv_ts: i64,
    pub reputation_cut_off: u32,

    pub service_string: String,

    pub sign_set: TlvKeySignatureSet,
    pub sign_flags: SignFlags,

    pub subscribe_flags: SubscribeFlags,
    pub visible_msg_count: u32,

    blobs: GxsGroupBlob,
}

impl GxsGroup {
    pub fn set_blobs(&mut self, blobs: GxsGrpDataSql) {
        assert_eq!(self.group_id, blobs.group_id);
        assert_eq!(blobs.nxs_data.len(), blobs.nxs_data_len);

        self.blobs.meta_data = Some(blobs.meta_data);
        self.blobs.group_data = Some(blobs.nxs_data);
        self.blobs.group_len = blobs.nxs_data_len;
    }

    pub fn get_blobs(&self) -> GxsGrpDataSql {
        // if you call this on a instance without blobs, simply crash!
        GxsGrpDataSql {
            group_id: self.group_id,
            nxs_data_len: self.blobs.group_len,
            nxs_data: self.blobs.group_data.to_owned().unwrap(),
            meta_data: self.blobs.meta_data.to_owned().unwrap(),
        }
    }

    pub fn to_dyn_sql_row(&self) -> Vec<&dyn rusqlite::ToSql> {
        vec![
            &self.group_id,
            &self.authen_flags,
            &self.author_id,
            &self.circle_id,
            &self.circle_type,
            &self.group_flags,
            &self.group_name,
            &self.group_status,
            &self.hash,
            &self.internal_circle,
            &self.keys,
            &self.last_post,
            &self.originator,
            &self.orig_grp_id,
            &self.parent_grp_id,
            &self.pop,
            &self.publish_ts,
            &self.recv_ts,
            &self.reputation_cut_off,
            &self.service_string,
            &self.sign_set,
            &self.sign_flags,
            &self.subscribe_flags,
            &self.visible_msg_count,
        ]
    }
}

impl From<GxsGrpMetaSql> for GxsGroup {
    fn from(sql: GxsGrpMetaSql) -> Self {
        Self {
            group_id: sql.group_id,
            authen_flags: sql.authen_flags,
            author_id: sql.author_id,
            circle_id: sql.circle_id,
            circle_type: sql.circle_type,
            group_flags: sql.group_flags,
            group_name: sql.group_name,
            group_status: sql.group_status,
            hash: sql.hash,
            internal_circle: sql.internal_circle,
            keys: sql.keys,
            last_post: sql.last_post,
            originator: sql.originator,
            orig_grp_id: sql.orig_grp_id,
            parent_grp_id: sql.parent_grp_id,
            pop: sql.pop,
            publish_ts: sql.publish_ts,
            recv_ts: sql.recv_ts,
            reputation_cut_off: sql.reputation_cut_off,
            service_string: sql.service_string,
            sign_set: sql.sign_set,
            sign_flags: sql.sign_flags,
            subscribe_flags: sql.subscribe_flags,
            visible_msg_count: sql.visible_msg_count,
            blobs: GxsGroupBlob {
                group_data: None,
                group_len: 0,
                meta_data: None,
            },
        }
    }
}

impl From<GxsGroup> for GxsGrpMetaSql {
    fn from(grp: GxsGroup) -> Self {
        GxsGrpMetaSql {
            group_id: grp.group_id,
            authen_flags: grp.authen_flags,
            author_id: grp.author_id,
            circle_id: grp.circle_id,
            circle_type: grp.circle_type,
            group_flags: grp.group_flags,
            group_name: grp.group_name,
            group_status: grp.group_status,
            hash: grp.hash,
            internal_circle: grp.internal_circle,
            keys: grp.keys,
            last_post: grp.last_post,
            originator: grp.originator,
            orig_grp_id: grp.orig_grp_id,
            parent_grp_id: grp.parent_grp_id,
            pop: grp.pop,
            publish_ts: grp.publish_ts,
            recv_ts: grp.recv_ts,
            reputation_cut_off: grp.reputation_cut_off,
            service_string: grp.service_string,
            sign_set: grp.sign_set,
            sign_flags: grp.sign_flags,
            subscribe_flags: grp.subscribe_flags,
            visible_msg_count: grp.visible_msg_count,
        }
    }
}

impl From<GxsGroup> for NxsSyncGrpItem {
    fn from(group: GxsGroup) -> Self {
        NxsSyncGrpItem {
            base: NxsItem::default(),
            flag: NxsSyncGrpItemFlags::Response,
            grp_id: group.group_id,
            publish_ts: group.publish_ts as u32, // BUG RS is not using rstime_t here ...
            author_id: group.author_id,
        }
    }
}

impl<const TYPE: u16> From<NxsGrp<TYPE>> for GxsGroup {
    fn from(nxs_item: NxsGrp<TYPE>) -> Self {
        let meta = GxsGrpMetaSql::from_nxs(&mut nxs_item.meta.to_owned());
        let data = GxsGrpDataSql {
            group_id: nxs_item.grp_id,
            meta_data: (*nxs_item.meta).to_owned(),
            nxs_data: (*nxs_item.grp).to_owned(),
            nxs_data_len: nxs_item.grp.len(),
        };
        let mut group: GxsGroup = meta.into();
        group.set_blobs(data);
        group
    }
}

impl<const TYPE: u16> From<GxsGroup> for NxsGrp<TYPE> {
    fn from(mut group: GxsGroup) -> Self {
        Self {
            base: NxsItem::default(),
            pos: 0,
            count: 0,
            grp_id: group.group_id,
            grp: group.blobs.group_data.take().unwrap().into(),
            meta: group.blobs.meta_data.take().unwrap().into(),
            meta_data: None,
        }
    }
}
