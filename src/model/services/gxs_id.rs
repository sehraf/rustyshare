use std::collections::HashMap;

use log::{info, warn};
use retroshare_compat::{
    basics::{GxsGroupId, GxsId},
    gxs::{
        sqlite::{
            database::GxsDatabase,
            types::{GxsGroup, GxsGrpDataSql, GxsGrpMetaSql},
        },
        GxsDatabaseBackend, NxsGrp, NxsItem,
    },
    serde::from_retroshare_wire,
    tlv::tlv_keys::{TlvKeyFlags, TlvPrivateRSAKey, TlvPublicRSAKey},
};
use tokio::sync::{Mutex, RwLock};

use crate::gxs::transaction::TransactionId;

/*
####################################
# WARNING
####################################

Currently mixing services, databases and nxs, this is a large refactoring TODO
*/

#[derive(Debug)]
pub struct GxsIdStore {
    pub database: Mutex<GxsDatabaseBackend>,
    pub gxs_ids: RwLock<HashMap<GxsId, (Option<TlvPublicRSAKey>, Option<TlvPrivateRSAKey>)>>,

    mem_cache: Mutex<GxsDatabaseBackend>,

    // FIXME
    pub request_groups: Mutex<Vec<GxsGroupId>>,
    pub received_groups: Mutex<Vec<GxsGroupId>>,
}

impl GxsIdStore {
    pub fn new(database: GxsDatabaseBackend) -> Self {
        let meta = database.get_grp_meta(&vec![]);

        // old code
        let gxs_ids = meta
            .iter()
            .map(|entry| {
                let id: GxsId = entry.group_id.into();
                let key = entry.keys.to_owned();
                (id, (key.public_keys, key.private_keys))
            })
            .map(|(id, (pub_keys, priv_keys))| {
                let pub_keys: Vec<_> = pub_keys
                    .into_iter()
                    .filter(|key| key.key_flags.contains(TlvKeyFlags::DISTRIBUTE_ADMIN))
                    .collect();
                let priv_keys: Vec<_> = priv_keys
                    .into_iter()
                    .filter(|key| key.key_flags.contains(TlvKeyFlags::DISTRIBUTE_ADMIN))
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

        let mem_cache = GxsDatabaseBackend::new(
            retroshare_compat::gxs::GxsType::Id,
            GxsDatabase::new_mem("").unwrap(),
            // GxsDatabase::new_file("/tmp/foo.db".into(), "").unwrap(),
        );

        // load private keys into mem cache
        for mut entry in meta {
            if entry
                .keys
                .private_keys
                .iter()
                .find(|key| key.key_flags.contains(TlvKeyFlags::TYPE_FULL))
                .is_some()
            {
                // found private key

                // load blobs
                let blobs = database.get_grp_data(&vec![entry.group_id]);
                let blob = blobs.into_iter().nth(0).unwrap();

                entry.set_blobs(blob);

                mem_cache.store_group(&entry);
            }
        }

        Self {
            database: Mutex::new(database),
            gxs_ids: RwLock::new(gxs_ids),

            mem_cache: Mutex::new(mem_cache),

            request_groups: Mutex::new(vec![]),
            received_groups: Mutex::new(vec![]),
        }
    }

    pub async fn get_identities_summaries(&self) -> Vec<GxsGrpMetaSql> {
        self.database
            .lock()
            .await
            .get_grp_meta(&vec![])
            .into_iter()
            .map(|x| x.into())
            .collect()
    }

    pub async fn get_pub_keys_by_id(&self, key_id: &GxsId) -> Option<TlvPublicRSAKey> {
        let key_id = key_id.to_owned().into();

        // if self.mem_cache.lock().await.contains_key(&key_id) {
        //     let keys: Vec<_> = self
        //         .mem_cache
        //         .read()
        //         .await
        //         .get(&key_id)
        //         .unwrap()
        //         .keys
        //         .public_keys
        //         .to_owned()
        //         .into_iter()
        //         .filter(|key| key.key_flags.contains(TlvKeyFlags::DISTRIBUTE_ADMIN))
        //         .collect();

        //     if keys.is_empty() {
        //         // is this possible?
        //         warn!("pub: found key id but no corresponding key");
        //         None
        //     } else {
        //         Some(keys.first().unwrap().to_owned())
        //     }
        // } else {
        //     self.request_groups.lock().await.push(key_id);
        //     None
        // }

        let keys: Vec<_> = self
            .mem_cache
            .lock()
            .await
            .get_grp_meta(&vec![key_id])
            .into_iter()
            .flat_map(|group| group.keys.public_keys)
            .filter(|keys| keys.key_flags.contains(TlvKeyFlags::DISTRIBUTE_ADMIN))
            .collect();

        if keys.is_empty() {
            self.request_groups.lock().await.push(key_id);
            None
        } else {
            Some(keys.first().unwrap().to_owned())
        }
    }

    pub async fn get_priv_keys_by_id(&self, key_id: &GxsId) -> Option<TlvPrivateRSAKey> {
        let key_id = key_id.to_owned().into();

        // if self.mem_cache.read().await.contains_key(&key_id) {
        //     let keys: Vec<_> = self
        //         .mem_cache
        //         .read()
        //         .await
        //         .get(&key_id)
        //         .unwrap()
        //         .keys
        //         .private_keys
        //         .to_owned()
        //         .into_iter()
        //         .filter(|key| key.key_flags.contains(TlvKeyFlags::DISTRIBUTE_ADMIN))
        //         .collect();

        //     if keys.is_empty() {
        //         // is this possible?
        //         warn!("priv: found key id but no corresponding key");
        //         None
        //     } else {
        //         Some(keys.first().unwrap().to_owned())
        //     }
        // } else {
        //     self.request_groups.lock().await.push(key_id);
        //     None
        // }
        let keys: Vec<_> = self
            .mem_cache
            .lock()
            .await
            .get_grp_meta(&vec![key_id])
            .into_iter()
            .flat_map(|group| group.keys.private_keys)
            .filter(|keys| keys.key_flags.contains(TlvKeyFlags::DISTRIBUTE_ADMIN))
            .collect();

        if keys.is_empty() {
            self.request_groups.lock().await.push(key_id);
            None
        } else {
            Some(keys.first().unwrap().to_owned())
        }
    }

    pub async fn get_nxs_groups<const T: u16>(
        &self,
        group_ids: &Vec<GxsGroupId>,
        transaction_id: TransactionId,
    ) -> Vec<(GxsGroupId, NxsGrp<T>)> {
        self.database
            .lock()
            .await
            .get_grp_data(group_ids)
            .into_iter()
            .map(|mut entry| {
                (
                    entry.group_id,
                    NxsGrp {
                        base: NxsItem { transaction_id },

                        count: 0,
                        pos: 0,

                        grp_id: entry.group_id,
                        grp: from_retroshare_wire(&mut entry.nxs_data),
                        meta: from_retroshare_wire(&mut entry.meta_data),

                        meta_data: None,
                    },
                )
            })
            .collect()
    }

    pub async fn receive_grp<const T: u16>(&self, mut group: NxsGrp<T>) {
        // get meta data
        // warn!("{}", hex::encode(&*group.meta));
        let mut meta = GxsGrpMetaSql::from_nxs(&mut group.meta);
        let id = meta.group_id;

        // validate group
        // TODO
        /*
        uint32_t p3IdService::idAuthenPolicy()
        {
            uint32_t policy = 0;
            uint8_t flag = 0;

            // Messages are send reputations. normally not by ID holder - so need signatures.
            flag = GXS_SERV::MSG_AUTHEN_ROOT_AUTHOR_SIGN | GXS_SERV::MSG_AUTHEN_CHILD_AUTHOR_SIGN;
            RsGenExchange::setAuthenPolicyFlag(flag, policy, RsGenExchange::PUBLIC_GRP_BITS);
            RsGenExchange::setAuthenPolicyFlag(flag, policy, RsGenExchange::RESTRICTED_GRP_BITS);
            RsGenExchange::setAuthenPolicyFlag(flag, policy, RsGenExchange::PRIVATE_GRP_BITS);

            // No ID required.
            flag = 0;
            RsGenExchange::setAuthenPolicyFlag(flag, policy, RsGenExchange::GRP_OPTION_BITS);

            return policy;
        }
        */
        const POLICY: u32 = 0x000c0c0c;
        let check_authen_flags = |policy: u32| -> bool { (0x01 & (policy >> 24)) > 0 };
        if meta.author_id != GxsId::default() && check_authen_flags(POLICY) {}

        // compute hash
        // TODO verify code
        {
            let hash =
                openssl::hash::hash(openssl::hash::MessageDigest::sha1(), &group.grp).unwrap();
            meta.hash = hash.as_ref().to_owned().into();
        }

        // TODO?
        group.meta_data = Some(meta.to_owned());

        /*
        void RsGenExchange::processRecvdGroups()

        // This has been moved here (as opposed to inside part for new groups below) because it is used to update the server TS when updates
        // of grp metadata arrive.

        grp->metaData->mRecvTS = time(NULL);

        // now check if group already exists

        if(std::find(existingGrpIds.begin(), existingGrpIds.end(), grp->grpId) == existingGrpIds.end())
        {
            grp->metaData->mOriginator = grp->PeerId();
            grp->metaData->mSubscribeFlags = GXS_SERV::GROUP_SUBSCRIBE_NOT_SUBSCRIBED;

            grps_to_store.push_back(grp);
            grpIds.push_back(grp->grpId);
        }
        else
        {
            GroupUpdate update;
            update.newGrp = grp;
            mGroupUpdates.push_back(update);
        }
        */

        // // add it
        // if self.mem_cache.read().await.contains_key(&id) {
        //     warn!("receive_grp: gxs group {id} already exists");
        // } else {
        //     info!("receive_grp: adding new gxs groups {id}");
        //     self.mem_cache.write().await.insert(id, meta);
        //     self.received_groups.lock().await.push(id);
        // }

        let lock = self.mem_cache.lock().await;
        let grp = lock.get_grp_meta(&vec![id]);
        if grp.is_empty() {
            let data = GxsGrpDataSql {
                group_id: id,
                meta_data: (*group.meta).to_owned(),
                nxs_data_len: group.grp.len(),
                nxs_data: (*group.grp).to_owned(),
            };

            // FIXME reading this code hurts my brain, this needs a rewrite
            let mut group: GxsGroup = meta.into();
            group.set_blobs(data);

            info!("receive_grp: adding new gxs groups {id}");
            lock.store_group(&group);
            self.received_groups.lock().await.push(id);
        } else {
            warn!("receive_grp: gxs group {id} already exists");
        }
    }

    pub async fn add_group(&self, group: &GxsGroup) {
        let id = group.group_id;
        // if self.mem_cache.read().await.contains_key(&id) {
        //     warn!("add_group: gxs group {id} already exists");
        // } else {
        //     info!("add_group: adding new gxs groups {id}");
        //     self.mem_cache.write().await.insert(id, group);
        //     self.received_groups.lock().await.push(id);
        // }
        let lock = self.mem_cache.lock().await;
        let grp = lock.get_grp_meta(&vec![id]);
        if grp.is_empty() {
            info!("add_group: adding new gxs groups {id}");
            // let mut group: GxsGroup = meta.to_owned().into();
            // group.set_blobs(data.to_owned());
            lock.store_group(&group);
            self.received_groups.lock().await.push(id);
        } else {
            warn!("add_group: gxs group {id} already exists");
        }
    }
}
