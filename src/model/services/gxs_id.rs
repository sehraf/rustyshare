use std::collections::HashMap;

use retroshare_compat::{
    basics::GxsId,
    gxs::{db::GroupMetaData, GxsDatabase},
    tlv::tlv_keys::{TlvPrivateRSAKey, TlvPublicRSAKey},
};
use tokio::sync::Mutex;

#[derive(Debug)]
pub struct GxsIdStore {
    pub database: Mutex<GxsDatabase>,
    pub gxs_ids: HashMap<GxsId, (Option<TlvPublicRSAKey>, Option<TlvPrivateRSAKey>)>,
}

impl GxsIdStore {
    pub fn new(database: GxsDatabase) -> Self {
        let gxs_ids = database
            .get_meta()
            .into_iter()
            .map(|entry| {
                let id: GxsId = entry.group_id.into();
                let key = entry.keys;
                (id, (key.public_keys, key.private_keys))
            })
            .map(|(id, (pub_keys, priv_keys))| {
                let pub_keys: Vec<_> = pub_keys
                    .into_iter()
                    .filter(|key| (key.key_flags & 0x0040) > 0)
                    .collect();
                let priv_keys: Vec<_> = priv_keys
                    .into_iter()
                    .filter(|key| (key.key_flags & 0x0040) > 0)
                    .collect();

                assert!(pub_keys.len() <= 1);
                assert!(priv_keys.len() <= 1);

                // dbg!(pub_keys.len() == 1 && priv_keys.len() == 1);

                let pub_keys = if pub_keys.is_empty() {
                    None
                } else {
                    Some(pub_keys.first().unwrap().to_owned())
                };
                let priv_keys = if priv_keys.is_empty() {
                    None
                } else {
                    Some(priv_keys.first().unwrap().to_owned())
                };

                (id, (pub_keys, priv_keys))
            })
            .collect();

        Self {
            database: Mutex::new(database),
            gxs_ids,
        }
    }

    pub async fn get_identities_summaries(&self) -> Vec<GroupMetaData> {
        self.database
            .lock()
            .await
            .get_meta()
            .into_iter()
            .map(|x| x.into())
            .collect()
    }

    // pub fn get_keys_by_key_id(&self, key_id: &GxsId) -> Option<&TlvSecurityKeySet> {
    //     self.gxs_ids
    //         .iter()
    //         .find(|(_id, entry)| {
    //             entry
    //                 .public_keys
    //                 .iter()
    //                 .find(|key| &key.key_id == key_id)
    //                 .is_some()
    //                 || entry
    //                     .private_keys
    //                     .iter()
    //                     .find(|key| &key.key_id == key_id)
    //                     .is_some()
    //         })
    //         .map(|(_, key)| key)
    // }

    pub fn get_pub_keys_by_id(&self, key_id: &GxsId) -> Option<&TlvPublicRSAKey> {
        self.gxs_ids
            .iter()
            .find_map(|(id, key)| if id == key_id { key.0.as_ref() } else { None })
    }

    pub fn get_priv_keys_by_id(&self, key_id: &GxsId) -> Option<&TlvPrivateRSAKey> {
        self.gxs_ids
            .iter()
            .find_map(|(id, key)| if id == key_id { key.1.as_ref() } else { None })
    }
}
