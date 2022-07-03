use std::{collections::HashMap, sync::Arc, time::SystemTime};

use retroshare_compat::basics::{GxsGroupId, PeerId};
use tokio::sync::RwLock;

/// TODO Need to understand timestamp syncing ...
///
/// RS uses these
///     typedef std::map<RsPeerId,     RsGxsMsgUpdate>        ClientMsgMap;
///     typedef std::map<RsGxsGroupId, RsGxsServerMsgUpdate>  ServerMsgMap;
///     typedef std::map<RsPeerId,     RsGxsGrpUpdate>        ClientGrpMap;
///     typedef std::map<RsGxsGroupId, RsGxsGrpConfig>        GrpConfigMap;
///
/// Note on the types:
/// While i would usually stick to the "proper" `SystemTime`, there is no point, since all that is send or received are `u32`.
/// TODO check on local times...
///
#[derive(Debug)]
pub struct GxsSyncTimeStamps {
    // BUG? RetroShares documentation is (maybe) outdated.
    // For example: mServerMsgUpdateMap has an _additional_ std::map<RsPeerId, RsPeerUpdateTsRecord>

    /// mClientGrpUpdateMap: map< RsPeerId, TimeStamp >
    ///
    /// Time stamp of last modification of group data for that peer (in peer's clock time!)
    /// (Set at server side to be mGrpServerUpdateItem->grpUpdateTS)
    ///
    /// Only updated in processCompletedIncomingTransaction() from Grp list transaction.
    /// Used in checkUpdatesFromPeers() sending in RsNxsSyncGrp once to all peers: peer will send data if
    /// has something new. All time comparisons are in the friends' clock time.
    peers_group_update: RwLock<HashMap<Arc<PeerId>, u32>>,

    /// mClientMsgUpdateMap: map< RsPeerId, map<grpId,TimeStamp > >
    ///
    /// Last msg list modification time sent by that peer Id
    /// Updated in processCompletedIncomingTransaction() from Grp list trans.
    /// Used in checkUpdatesFromPeers() sending in RsNxsSyncGrp once to all peers.
    /// Set at server to be mServerMsgUpdateMap[grpId]->msgUpdateTS
    peers_message_update: RwLock<HashMap<Arc<PeerId>, HashMap<Arc<GxsGroupId>, u32>>>,

    /// mGrpServerUpdate:  TimeStamp
    ///
    /// Last group local modification timestamp over all groups
    local_last_update: RwLock<u32>,

    /// mServerMsgUpdateMap: map< GrpId, TimeStamp >
    ///
    /// Timestamp local modification for each group (i.e. time of most recent msg / metadata update)
    local_group_updates: RwLock<HashMap<Arc<GxsGroupId>, SystemTime>>,
}

#[allow(unused)]
impl GxsSyncTimeStamps {
    pub fn new() -> Self {
        GxsSyncTimeStamps {
            peers_group_update: RwLock::new(HashMap::new()),
            peers_message_update: RwLock::new(HashMap::new()),
            local_last_update: RwLock::new(0),
            local_group_updates: RwLock::new(HashMap::new()),
        }
    }

    pub async fn update_peer_group(&self, peer_id: Arc<PeerId>, peers_time: u32) {
        *self
            .peers_group_update
            .write()
            .await
            .entry(peer_id)
            .or_insert(0) = peers_time;
    }

    pub async fn get_peer_group(&self, peer_id: Arc<PeerId>) -> Option<u32> {
        Some(
            self.peers_group_update
                .read()
                .await
                .get(&peer_id)?
                .to_owned(),
        )
    }

    pub async fn update_peer_message(
        &self,
        peer_id: Arc<PeerId>,
        group_id: Arc<GxsGroupId>,
        peers_time: u32,
    ) {
        *self
            .peers_message_update
            .write()
            .await
            .entry(peer_id)
            .or_insert(HashMap::new())
            .entry(group_id)
            .or_insert(0) = peers_time;
    }

    pub async fn update_local_last(&self, last_group_ts: u32) {
        let mut lock = self.local_last_update.write().await;
        if *lock < last_group_ts {
            *lock = last_group_ts;
        }
    }

    pub async fn check_local_last(&self, peer_ts: u32) -> bool {
        let ts = self.local_last_update.read().await;
        peer_ts < *ts
    }

    pub async fn get_local_last(&self) -> u32 {
        *self.local_last_update.read().await
    }

    pub async fn update_local_group(&self, group_id: Arc<GxsGroupId>) {
        *self
            .local_group_updates
            .write()
            .await
            .entry(group_id)
            .or_insert(SystemTime::UNIX_EPOCH) = SystemTime::now();
    }
}
