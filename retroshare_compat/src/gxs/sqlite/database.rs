use std::path::PathBuf;

use bitflags::bitflags;
use bitflags_serde_shim::impl_serde_for_bitflags;
use log::{debug, trace, warn};
use rusqlite::{params, types::FromSql, Connection, Result, ToSql};
use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};

use crate::{
    basics::{
        FileHash, GxsCircleId, GxsCircleIdHex, GxsGroupId, GxsGroupIdHex, GxsId, GxsIdHex,
        GxsMessageId, PeerId, PeerIdHex,
    },
    gen_db_type,
    gxs::sqlite::FromSqlRs,
    impl_sql_for_bitflags, read_u32,
    serde::from_retroshare_wire,
    tlv::{
        tlv_keys::{TlvKeySignatureSet, TlvSecurityKeySet},
        tlv_string::StringTagged,
    },
    webui::XInt64,
};

const TABLE_RELEASE: &str = "DATABASE_RELEASE";
const TABLE_GROUPS: &str = "GROUPS";
const TABLE_MESSAGES: &str = "MESSAGES";

// generic
const KEY_NXS_DATA: &str = "nxsData";
const KEY_NXS_DATA_LEN: &str = "nxsDataLen";
const KEY_NXS_IDENTITY: &str = "identity";
const KEY_GRP_ID: &str = "grpId";
const KEY_ORIG_GRP_ID: &str = "origGrpId";
const KEY_PARENT_GRP_ID: &str = "parentGrpId";
const KEY_SIGN_SET: &str = "signSet";
const KEY_TIME_STAMP: &str = "timeStamp";
const KEY_NXS_FLAGS: &str = "flags";
const KEY_NXS_META: &str = "meta";
const KEY_NXS_SERV_STRING: &str = "serv_str";
const KEY_NXS_HASH: &str = "hash";
const KEY_RECV_TS: &str = "recv_time_stamp";

// These are legacy fields, that are not used anymore.
// Here for the sake of documentation.
#[allow(dead_code)]
const KEY_NXS_FILE_OLD: &str = "nxsFile";
#[allow(dead_code)]
const KEY_NXS_FILE_OFFSET_OLD: &str = "fileOffset";
#[allow(dead_code)]
const KEY_NXS_FILE_LEN_OLD: &str = "nxsFileLen";

// grp table columns
const KEY_KEY_SET: &str = "keySet";
const KEY_GRP_NAME: &str = "grpName";
const KEY_GRP_SIGN_FLAGS: &str = "signFlags";
const KEY_GRP_CIRCLE_ID: &str = "circleId";
const KEY_GRP_CIRCLE_TYPE: &str = "circleType";
const KEY_GRP_INTERNAL_CIRCLE: &str = "internalCircle";
const KEY_GRP_ORIGINATOR: &str = "originator";
const KEY_GRP_AUTHEN_FLAGS: &str = "authenFlags";

// grp local
const KEY_GRP_SUBCR_FLAG: &str = "subscribeFlag";
const KEY_GRP_POP: &str = "popularity";
const KEY_MSG_COUNT: &str = "msgCount";
const KEY_GRP_STATUS: &str = "grpStatus";
const KEY_GRP_LAST_POST: &str = "lastPost";
const KEY_GRP_REP_CUTOFF: &str = "rep_cutoff";

// msg table columns
const KEY_MSG_ID: &str = "msgId";
const KEY_ORIG_MSG_ID: &str = "origMsgId";
const KEY_MSG_PARENT_ID: &str = "parentId";
const KEY_MSG_THREAD_ID: &str = "threadId";
const KEY_MSG_NAME: &str = "msgName";

// msg local
const KEY_MSG_STATUS: &str = "msgStatus";
const KEY_CHILD_TS: &str = "childTs";

// database release columns
const KEY_DATABASE_RELEASE_ID: &str = "id";
const KEY_DATABASE_RELEASE: &str = "release";

const RELEASE_ID_VALUE: u32 = 1;
const RELEASE_VERSION: u32 = 1;

// BUG? why is this an u32 when an u16 definition is used (and tags usually are u16)
const GXS_GRP_META_DATA_VERSION_ID_0002: u32 = 0xaf01;

type Blob = Vec<u8>;

#[derive(Debug)]
pub struct GxsDatabase {
    db: Connection,
}

impl GxsDatabase {
    pub fn new_file(path: PathBuf, passwd: &str) -> Result<Self> {
        let db = Connection::open(path)?;
        if !passwd.is_empty() {
            db.pragma_update(None, "key", passwd)?;
        }

        let db = GxsDatabase { db };
        db.verify_version()?;

        Ok(db)
    }

    pub fn new_mem(passwd: &str) -> Result<Self> {
        let db = Connection::open_in_memory()?;
        if !passwd.is_empty() {
            db.pragma_update(None, "key", passwd)?;
        }

        let db = GxsDatabase { db };
        db.create_tables()?;

        Ok(db)
    }

    fn create_tables(&self) -> Result<()> {
        let create_table = |name: &str, columns: &Vec<(&str, &str)>| -> Result<usize> {
            let stm = String::from("CREATE TABLE ")
                + name
                + "("
                + &columns
                    .iter()
                    .map(|(field, ty)| field.to_string() + " " + ty)
                    .collect::<Vec<_>>()
                    .join(",")
                + ");";
            debug!("creating tables: {stm}");

            self.db.execute(&stm, [])
        };

        // release table
        let columns = vec![
            (KEY_DATABASE_RELEASE_ID, "INT PRIMARY KEY"),
            (KEY_DATABASE_RELEASE, "INT"),
        ];
        create_table(TABLE_RELEASE, &columns)?;

        // messages table
        let columns = vec![
            (KEY_MSG_ID, "TEXT PRIMARY KEY"),
            (KEY_GRP_ID, "TEXT"),
            (KEY_NXS_FLAGS, "INT"),
            (KEY_ORIG_MSG_ID, "TEXT"),
            (KEY_TIME_STAMP, "INT"),
            (KEY_NXS_IDENTITY, "TEXT"),
            (KEY_SIGN_SET, "BLOB"),
            (KEY_NXS_DATA, "BLOB"),
            (KEY_NXS_DATA_LEN, "INT"),
            (KEY_MSG_STATUS, "INT"),
            (KEY_CHILD_TS, "INT"),
            (KEY_NXS_META, "BLOB"),
            (KEY_MSG_THREAD_ID, "TEXT"),
            (KEY_MSG_PARENT_ID, "TEXT"),
            (KEY_MSG_NAME, "TEXT"),
            (KEY_NXS_SERV_STRING, "TEXT"),
            (KEY_NXS_HASH, "TEXT"),
            (KEY_RECV_TS, "INT"),
        ];
        create_table(TABLE_MESSAGES, &columns)?;

        // groups table
        let columns = vec![
            (KEY_GRP_ID, "TEXT PRIMARY KEY"),
            (KEY_TIME_STAMP, "INT"),
            (KEY_NXS_DATA, "BLOB"),
            (KEY_NXS_DATA_LEN, "INT"),
            (KEY_KEY_SET, "BLOB"),
            (KEY_NXS_META, "BLOB"),
            (KEY_GRP_NAME, "TEXT"),
            (KEY_GRP_LAST_POST, "INT"),
            (KEY_GRP_POP, "INT"),
            (KEY_MSG_COUNT, "INT"),
            (KEY_GRP_SUBCR_FLAG, "INT"),
            (KEY_GRP_STATUS, "INT"),
            (KEY_NXS_IDENTITY, "TEXT"),
            (KEY_ORIG_GRP_ID, "TEXT"),
            (KEY_NXS_SERV_STRING, "TEXT"),
            (KEY_NXS_FLAGS, "INT"),
            (KEY_GRP_AUTHEN_FLAGS, "INT"),
            (KEY_GRP_SIGN_FLAGS, "INT"),
            (KEY_GRP_CIRCLE_ID, "TEXT"),
            (KEY_GRP_CIRCLE_TYPE, "INT"),
            (KEY_GRP_INTERNAL_CIRCLE, "TEXT"),
            (KEY_GRP_ORIGINATOR, "TEXT"),
            (KEY_NXS_HASH, "TEXT"),
            (KEY_RECV_TS, "INT"),
            (KEY_PARENT_GRP_ID, "TEXT"),
            (KEY_GRP_REP_CUTOFF, "INT"),
            (KEY_SIGN_SET, "BLOB"),
        ];
        create_table(TABLE_GROUPS, &columns)?;

        // mDb->execSQL("CREATE TRIGGER " + GRP_LAST_POST_UPDATE_TRIGGER +
        //    " INSERT ON " + MSG_TABLE_NAME +
        //    std::string(" BEGIN ") +
        //    " UPDATE " + GRP_TABLE_NAME + " SET " + KEY_GRP_LAST_POST + "= new."
        //    + KEY_RECV_TS + " WHERE " + KEY_GRP_ID + "=new." + KEY_GRP_ID + ";"
        //    + std::string("END;"));
        let stm = String::from("CREATE TRIGGER LAST_POST_UPDATE INSERT ON ")
            + TABLE_MESSAGES
            + " BEGIN UPDATE "
            + TABLE_GROUPS
            + " SET "
            + KEY_GRP_LAST_POST
            + "= new."
            + KEY_RECV_TS
            + " WHERE "
            + KEY_GRP_ID
            + "=new."
            + KEY_GRP_ID
            + "; END;";
        debug!("creating trigger: {stm}");
        self.db.execute(&stm, [])?;

        // mDb->execSQL("CREATE INDEX " + MSG_INDEX_GRPID + " ON " + MSG_TABLE_NAME + "(" + KEY_GRP_ID +  ");");
        let stm = String::from("CREATE INDEX INDEX_MESSAGES_GRPID ON ")
            + TABLE_MESSAGES
            + "("
            + KEY_GRP_ID
            + ");";
        debug!("creating index: {stm}");
        self.db.execute(&stm, [])?;

        // Insert release, no need to upgrade
        let stm = String::from("INSERT INTO ")
            + TABLE_RELEASE
            + "("
            + KEY_DATABASE_RELEASE_ID
            + ", "
            + KEY_DATABASE_RELEASE
            + ")"
            + "VALUES (?1, ?2);";
        debug!("inserting release: {stm}");
        self.db.execute(&stm, [RELEASE_ID_VALUE, RELEASE_VERSION])?;

        Ok(())
    }

    fn verify_version(&self) -> Result<()> {
        let stm = String::from("SELECT ")
            + KEY_DATABASE_RELEASE_ID
            + ", "
            + KEY_DATABASE_RELEASE
            + " FROM "
            + TABLE_RELEASE
            + " WHERE "
            + TABLE_RELEASE
            + "."
            + KEY_DATABASE_RELEASE_ID
            + "=?;";
        debug!("verify query {stm}");

        let res = self
            .db
            .prepare(&stm)?
            .query_map([&RELEASE_ID_VALUE.to_string()], |row| {
                GxsDatabaseRelease::from_row(row)
            })?
            .next()
            .ok_or_else(|| panic!("unsupported database version (or no version found)"))
            .unwrap();
        if let Ok(release_info) = res {
            debug!("{release_info:?}");
            assert_eq!(release_info.id, 1); // sql will probably not be broken

            if release_info.release != RELEASE_VERSION {
                panic!(
                    "unsupported database version {}, only {RELEASE_VERSION} is supported",
                    release_info.release
                );
            }
        } else {
            panic!("unsupported database version: no version found");
        }

        Ok(())
    }

    // old code

    pub fn get_grp_meta_all(&self) -> Result<Vec<GxsGrpMetaSql>> {
        let stm = String::from("SELECT ")
            + &GxsGrpMetaSql::get_columns().join(",")
            + " FROM "
            + TABLE_GROUPS;
        debug!(
            "querying {stm} on {:?}",
            self.db.path().unwrap().file_name()
        );
        let mut stm = self.db.prepare(&stm)?;
        let entries = stm
            .query_map([], |row| GxsGrpMetaSql::from_row(row))?
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

    pub fn get_msg_meta_all(&self) -> Result<Vec<GxsMsgMetaSql>> {
        let stm = String::from("SELECT ")
            + &GxsMsgMetaSql::get_columns().join(",")
            + " FROM "
            + TABLE_MESSAGES;
        debug!(
            "querying {stm} on {:?}",
            self.db.path().unwrap().file_name()
        );
        let mut stm = self.db.prepare(&stm)?;
        let entries = stm
            .query_map([], |row| GxsMsgMetaSql::from_row(row))?
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

    // new code

    // msg vs group
    // meta vs data

    fn query_by_group_id<T>(&self, table: &str, group_id: &GxsGroupId) -> Result<Vec<T>>
    where
        T: FromSqlRs,
    {
        // TODO is it always useful to match based on group id?
        // Messages have more than one entry per group id

        let stm = String::from("SELECT ")
            + &T::get_columns().join(",")
            + " FROM "
            + table
            + " WHERE "
            + table
            + ".grpId=(?);";
        debug!("querying {stm}");

        let mut entries = vec![];

        let mut stm = self.db.prepare_cached(&stm)?;
        let res = stm
            .query_map(params!(group_id.to_string()), |row| T::from_row(row))?
            .find_map(|e| match e {
                Ok(e) => Some(e),
                Err(e) => {
                    warn!("{e:?}");
                    None
                }
            });
        if let Some(entry) = res {
            entries.push(entry);
        } else {
            trace!("no entry found for {group_id}");
        }

        Ok(entries)
    }

    pub fn get_grp_ids(&self) -> Result<Vec<GxsGroupId>> {
        let stm = String::from("SELECT grpId FROM ") + TABLE_GROUPS;
        debug!(
            "querying {stm} on {:?}",
            self.db.path().unwrap().file_name()
        );
        let mut stm = self.db.prepare(&stm)?;
        let entries = stm
            .query_map([], |row| row.get(0))?
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

    pub fn get_grp_meta(&self, group_id: &GxsGroupId) -> Result<Vec<GxsGrpMetaSql>> {
        // let stm = String::from("SELECT ")
        //     + &GxsGrpMetaSql::get_columns().join(",")
        //     + " FROM "
        //     + TABLE_GROUPS
        //     + " WHERE "
        //     + TABLE_GROUPS
        //     + ".grpId=(?);";
        // debug!(
        //     "querying {stm} on {:?}",
        //     self.db.path().unwrap().file_name()
        // );

        // let mut entries = vec![];

        // for group_id in group_ids {
        //     let mut stm = self.db.prepare(&stm)?;
        //     let res = stm
        //         .query_map(params!(group_id.to_string()), |row| {
        //             GxsGrpMetaSql::from_row(row)
        //         })?
        //         .find_map(|e| match e {
        //             Ok(e) => Some(e),
        //             Err(e) => {
        //                 warn!("{e:?}");
        //                 None
        //             }
        //         });
        //     if let Some(entry) = res {
        //         entries.push(entry);
        //     } else {
        //         trace!("no entry found for {group_id}");
        //     }
        // }

        // Ok(entries)

        self.query_by_group_id(TABLE_GROUPS, group_id)
    }

    pub fn get_grp_data(&self, group_id: &GxsGroupId) -> Result<Vec<GxsGrpDataSql>> {
        // let stm = String::from("SELECT ")
        //     + &GxsGrpDataSql::get_columns().join(",")
        //     + " FROM "
        //     + TABLE_GROUPS
        //     + " WHERE "
        //     + TABLE_GROUPS
        //     + ".grpId=(?);";
        // debug!(
        //     "querying {stm} on {:?}",
        //     self.db.path().unwrap().file_name()
        // );

        // let mut entries = vec![];

        // for group_id in group_ids {
        //     let mut stm = self.db.prepare(&stm)?;
        //     let res = stm
        //         .query_map(params!(group_id.to_string()), |row| {
        //             GxsGrpDataSql::from_row(row)
        //         })?
        //         .find_map(|e| match e {
        //             Ok(e) => Some(e),
        //             Err(e) => {
        //                 warn!("{e:?}");
        //                 None
        //             }
        //         });
        //     if let Some(entry) = res {
        //         entries.push(entry);
        //     } else {
        //         trace!("no entry found for {group_id}");
        //     }
        // }

        // Ok(entries)

        self.query_by_group_id(TABLE_GROUPS, group_id)
    }

    pub fn get_msg_meta(&self, group_id: &GxsGroupId) -> Result<Vec<GxsMsgMetaSql>> {
        // let stm = String::from("SELECT ")
        //     + &GxsMsgMetaSql::get_columns().join(",")
        //     + " FROM "
        //     + TABLE_MESSAGES
        //     + " WHERE "
        //     + TABLE_MESSAGES
        //     + ".grpId=(?);";
        // debug!(
        //     "querying {stm} on {:?}",
        //     self.db.path().unwrap().file_name()
        // );

        // let mut entries = vec![];

        // for group_id in group_ids {
        //     let mut stm = self.db.prepare(&stm)?;
        //     let res = stm
        //         .query_map(params!(group_id.to_string()), |row| {
        //             GxsMsgMetaSql::from_row(row)
        //         })?
        //         .find_map(|e| match e {
        //             Ok(e) => Some(e),
        //             Err(e) => {
        //                 warn!("{e:?}");
        //                 None
        //             }
        //         });
        //     if let Some(entry) = res {
        //         entries.push(entry);
        //     } else {
        //         trace!("no entry found for {group_id}");
        //     }
        // }

        // Ok(entries)

        self.query_by_group_id(TABLE_MESSAGES, group_id)
    }

    pub fn get_msg_data(&self, group_id: &GxsGroupId) -> Result<Vec<GxsMsgDataSql>> {
        // let stm = String::from("SELECT ")
        //     + &GxsMsgDataSql::get_columns().join(",")
        //     + " FROM "
        //     + TABLE_MESSAGES
        //     + " WHERE "
        //     + TABLE_MESSAGES
        //     + ".grpId=(?);";
        // debug!(
        //     "querying {stm} on {:?}",
        //     self.db.path().unwrap().file_name()
        // );

        // let mut entries = vec![];

        // for group_id in group_ids {
        //     let mut stm = self.db.prepare(&stm)?;
        //     let res = stm
        //         .query_map(params!(group_id.to_string()), |row| {
        //             GxsMsgDataSql::from_row(row)
        //         })?
        //         .find_map(|e| match e {
        //             Ok(e) => Some(e),
        //             Err(e) => {
        //                 warn!("{e:?}");
        //                 None
        //             }
        //         });
        //     if let Some(entry) = res {
        //         entries.push(entry);
        //     } else {
        //         trace!("no entry found for {group_id}");
        //     }
        // }

        // Ok(entries)
        self.query_by_group_id(TABLE_MESSAGES, group_id)
    }

    pub fn insert_group(
        &self,
        group_meta: &GxsGrpMetaSql,
        groups_data: &GxsGrpDataSql,
    ) -> Result<()> {
        // store meta
        let fields = &GxsGrpMetaSql::get_columns();
        let stm = String::from("INSERT INTO ")
            + TABLE_GROUPS
            + " ("
            + &fields.join(",")
            + ") "
            + "VALUES ("
            + &{
                // is there an easier way?!
                let mut numbers = vec![];
                for i in 1..=fields.len() {
                    let entry = String::from("?") + &i.to_string();
                    numbers.push(entry);
                }
                numbers
            }
            .join(",")
            + ");";
        debug!("inserting (meta) {stm}");
        self.db.execute(&stm, group_meta.to_row().as_slice())?;

        // store data
        assert_eq!(
            GxsGrpDataSql::get_columns(),
            vec![KEY_GRP_ID, KEY_NXS_DATA, KEY_NXS_META]
        );
        let stm = String::from("UPDATE ")
            + TABLE_GROUPS
            + " SET "
            + KEY_NXS_DATA
            + "=(?2),"
            + KEY_NXS_META
            + "=(?3)"
            + " WHERE "
            + TABLE_GROUPS
            + "."
            + KEY_GRP_ID
            + "=(?1)";
        debug!("inserting (data) {stm}");
        self.db.execute(&stm, groups_data.to_row().as_slice())?;

        Ok(())
    }

    // pub fn insert_message(
    //     &self,
    //     group: &GxsMsgMetaSql,
    //     meta_blob: &Blob,
    //     nxs_blob: &Blob,
    // ) -> Result<()> {
    //     // TODO
    //     // MUST use msgId!!
    //     unimplemented!()
    // }
}

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
        const AUTHOR_AUTHENTICATION_NONE           = 0x00000000;
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
    fn to_sql(&self) -> Result<rusqlite::types::ToSqlOutput<'_>> {
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
        const CMT_VOTE_MASK        = 0x00030000;
        const CMT_VOTE_UP          = 0x00010000;
        const CMT_VOTE_DOWN        = 0x00020000;
    }
}
impl_serde_for_bitflags!(GroupStatus);
impl_sql_for_bitflags!(GroupStatus);

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
    [orig_grp_id: GxsGroupId, KEY_ORIG_GRP_ID],        // "origGrpId"
    [parent_grp_id: GxsGroupId, KEY_PARENT_GRP_ID],    // "parentGrpId"
    [group_name: String, KEY_GRP_NAME],                // "grpName"
    [group_flags: GroupFlags, KEY_NXS_FLAGS],          // "flags"
    [publish_ts: i64, KEY_TIME_STAMP],                 // "timeStamp"
    [circle_type: GxsCircleType, KEY_GRP_CIRCLE_TYPE], // "circleType"
    [authen_flags: AuthenFlags, KEY_GRP_AUTHEN_FLAGS], // "authenFlags"
    [author_id: GxsId, KEY_NXS_IDENTITY],              // "identity"
    [service_string: String, KEY_NXS_SERV_STRING],     // "serv_str"
    [circle_id: GxsCircleId, KEY_GRP_CIRCLE_ID],       // "circleId"
    [sign_set: TlvKeySignatureSet, KEY_SIGN_SET],      // "signSet"
    [keys: TlvSecurityKeySet, KEY_KEY_SET],            // "keySet"
    [sign_flags: SignFlags, KEY_SIGN_SET],             // "signFlags"
    [subscribe_flags: SubscribeFlags, KEY_GRP_SUBCR_FLAG], // "subscribeFlag"
    [pop: u32, KEY_GRP_POP],                           // "popularity"
    [visible_msg_count: u32, KEY_MSG_COUNT],           // "msgCount"
    [last_post: i64, KEY_GRP_LAST_POST],               // "lastPost"
    [reputation_cut_off: u32, KEY_GRP_REP_CUTOFF],     // "rep_cutoff"
    [grp_size: u32, ""],                               // -
    [group_status: GroupStatus, KEY_GRP_STATUS],       // "grpStatus"
    [recv_ts: i64, KEY_RECV_TS],                       // "recv_time_stamp"
    [originator: PeerId, KEY_GRP_ORIGINATOR],          // "originator"
    [internal_circle: GxsCircleId, KEY_GRP_INTERNAL_CIRCLE], // "internalCircle"
    [hash: FileHash, KEY_NXS_HASH],                    // "hash"
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

        let sign_flags = if tag == GXS_GRP_META_DATA_VERSION_ID_0002 {
            from_retroshare_wire(data)
        } else {
            SignFlags::from_bits(0).unwrap()
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
    [group_id: GxsGroupId, KEY_GRP_ID], // "grpId"
    [nxs_data: Blob, KEY_NXS_DATA],     // "nxsData"
    [meta_data: Blob, KEY_NXS_META],    // "meta" // GxsGrpMetaData = GxsGrpMetaSql
);

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
    [group_id: GxsGroupId, KEY_GRP_ID],            // "grpId"
    [publish_ts: i64, KEY_TIME_STAMP],             // "timeStamp"
    [nxs_flags: u32, KEY_NXS_FLAGS],               // "flags"
    [sign_set: TlvKeySignatureSet, KEY_SIGN_SET],  // "signSet"
    [nxs_identity: GxsId, KEY_NXS_IDENTITY],       // "identity"
    [nxs_hash: FileHash, KEY_NXS_HASH],            // "hash"
    [msg_id: GxsMessageId, KEY_MSG_ID],            // "msgId"
    [orig_msg_id: GxsMessageId, KEY_ORIG_MSG_ID],  // "origMsgId"
    [msg_status: u32, KEY_MSG_STATUS],             // "msgStatus"
    [child_ts: i64, KEY_CHILD_TS],                 // "childTs"
    [parent_id: GxsMessageId, KEY_MSG_PARENT_ID],  // "parentId"
    [thread_id: GxsMessageId, KEY_MSG_THREAD_ID],  // "threadId"
    [msg_name: String, KEY_MSG_NAME],              // "msgName"
    [service_string: String, KEY_NXS_SERV_STRING], // "serv_str"
    [recv_ts: i64, KEY_RECV_TS],                   // "recv_time_stamp"

                                                   // ?!
                                                   // [nxs_data_len: i64, KEY_NXS_DATA_LEN],         // "nxsDataLen"
                                                   // [msg_size: u64, ""],
                                                   // [validated: bool, ""],
);

gen_db_type!(
    GxsMsgDataSql,
    [group_id: GxsGroupId, "grpId"],
    [nxs_data: Blob, "nxsData"],
    [meta_data: Blob, "meta"],
    [msg_id: GxsGroupId, "msgId"],
);

gen_db_type!(
    GxsDatabaseRelease,
    [id: u32, KEY_DATABASE_RELEASE_ID],
    [release: u32, KEY_DATABASE_RELEASE],
);
