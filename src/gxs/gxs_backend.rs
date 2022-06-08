use std::{collections::HashMap, task::Waker};

use log::debug;
use retroshare_compat::{
    basics::{GxsGroupId, GxsMessageId},
    gxs::sqlite::{database::GxsDatabase, types::GxsGroup},
};

use super::nxs_transactions::NxsTransactionController;

enum PendingRequestType {
    GxsGroup(GxsGroupId),
    GxsMessage(GxsMessageId),
}

struct PendingRequests {
    waker: Vec<Waker>,
}

pub struct GxsBackend<const TYPE: u16> {
    db: GxsDatabase,
    mem_cache: GxsDatabase,
    nxs: NxsTransactionController<TYPE>,

    pending_requests: HashMap<PendingRequestType, PendingRequests>,
}

impl<const TYPE: u16> GxsBackend<TYPE> {
    pub fn new(db: GxsDatabase, nxs: NxsTransactionController<TYPE>) -> Self {
        // setup mem cache
        let mem_cache = GxsDatabase::new_mem("").unwrap();
        // let mem_cache = GxsDatabase::new_file("/tmp/foo.db".into(), "").unwrap();

        Self {
            db,
            mem_cache,
            nxs,

            pending_requests: HashMap::new(),
        }
    }

    pub async fn get_group(&self, group_id: &GxsGroupId) -> Option<GxsGroup> {
        match self.mem_cache.get_grp_meta(group_id) {
            Ok(result) => return result,
            Err(err) => {
                debug!("failed to get group by id: {err}");
            }
        }

        match self.db.get_grp_meta(group_id) {
            Ok(result) => return result,
            Err(err) => {
                debug!("failed to get group by id: {err}");
                None
            }
        }
    }

    // pub fn
    // get group
    // get messages
    // etc
}
