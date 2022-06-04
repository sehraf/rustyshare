use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::Duration,
};

use async_trait::async_trait;
use log::{debug, trace};
use retroshare_compat::{basics::GxsGroupId, services::SERVICE_GXS_GXSID};
use tokio::sync::mpsc::UnboundedSender;

use crate::{
    gxs::nxs_transactions::{NxsShared, NxsTransactionController},
    handle_packet,
    low_level_parsing::{headers::ServiceHeader, Packet},
    model::{intercom::Intercom, DataCore},
    services::{HandlePacketResult, Service},
    utils::{simple_stats::StatsCollection, Timer, Timers},
};

use ::retroshare_compat::services::ServiceType;

/*
####################################
# WARNING
####################################

Currently mixing services, databases and nxs, this is a large refactoring TODO
*/

// type NxsGrpGxsId = NxsGrp<SERVICE_GXS_GXSID>;
// type NxsTransactionGxsId = NxsTransaction<SERVICE_GXS_GXSID>;

const CHECK_SYNC: (&str, Duration) = ("sync check", Duration::from_secs(60));
const LOAD_MISSING_IDS: (&str, Duration) = ("missing ids", Duration::from_secs(10));

pub struct GxsId {
    #[allow(unused)]
    core: Arc<DataCore>,
    core_tx: UnboundedSender<Intercom>,

    #[allow(unused)]
    shared: Arc<NxsShared>,
    nxs_service: NxsTransactionController<SERVICE_GXS_GXSID>,
    nxs_timers: Timers,

    pending_requests: HashSet<GxsGroupId>,
}

impl GxsId {
    pub async fn new(
        core: &Arc<DataCore>,
        core_tx: UnboundedSender<Intercom>,
        timers: &mut Timers,
    ) -> Self {
        timers.insert(CHECK_SYNC.0.into(), Timer::new(CHECK_SYNC.1));
        timers.insert(LOAD_MISSING_IDS.0.into(), Timer::new(LOAD_MISSING_IDS.1));

        let shared = Arc::new(NxsShared::new(core.to_owned()));
        let mut nxs_timers = HashMap::new();

        GxsId {
            core: core.to_owned(),
            core_tx,

            shared: shared.to_owned(),
            nxs_service: NxsTransactionController::new(shared, &mut nxs_timers),
            nxs_timers,

            pending_requests: HashSet::new(),
        }
    }

    async fn handle_incoming(&self, header: &ServiceHeader, packet: Packet) -> HandlePacketResult {
        let packets = self.nxs_service.handle_incoming(header, packet).await;
        for packet in packets {
            self.core_tx
                .send(Intercom::Send(packet))
                .expect("failed to send to core");
        }
        handle_packet!()
    }

    async fn check_sync(&self) -> Vec<Packet> {
        let mut packets = vec![];

        let peers = self
            .core
            .get_connected_peers()
            .lock()
            .await
            .0
            .iter()
            .map(|(id, _)| id.to_owned())
            .collect();
        packets.extend(self.nxs_service.check_peer_updates(peers).await);

        packets
    }

    async fn handle_missing_ids(&mut self) -> Vec<Packet> {
        // missing ids?
        if self
            .core
            .get_service_data()
            .gxs_id()
            .request_groups
            .lock()
            .await
            .is_empty()
        {
            return vec![];
        }

        // get ids and remove duplicated ones.
        let ids: HashSet<GxsGroupId> = self
            .core
            .get_service_data()
            .gxs_id()
            .request_groups
            .lock()
            .await
            .drain(..)
            .map(|id| id.to_vec().into())
            .collect();

        // remove already pending requests
        let mut ids = &ids - &self.pending_requests;
        // anything to request?
        if ids.is_empty() {
            return vec![];
        }

        debug!("trying to load ids from database: {ids:?}");

        // first, try loading from DB
        let lock = self.core.get_service_data().gxs_id().database.lock().await;
        let meta = lock.get_grp_meta(&ids.iter().copied().collect());
        // .into_iter()
        // .filter(|group| ids.contains(&group.group_id))
        // .collect();
        // remove found ids
        for group in meta.into_iter() {
            ids.remove(&group.group_id);
            let data = lock
                .get_grp_data(&vec![group.group_id])
                .first()
                .unwrap()
                .to_owned();
            self.core
                .get_service_data()
                .gxs_id()
                .add_group(&group, &data)
                .await;
        }

        // found all?
        if ids.is_empty() {
            return vec![];
        }

        debug!("trying to request ids from network: {ids:?}");

        // request missing ones
        let packets = self
            .nxs_service
            .request_groups(ids.to_owned().into_iter().collect())
            .await;
        self.pending_requests.extend(ids);

        packets
    }
}

#[async_trait]
impl Service for GxsId {
    fn get_id(&self) -> ServiceType {
        ServiceType::GxsId
    }

    async fn handle_packet(&self, packet: Packet) -> HandlePacketResult {
        trace!("handle_packet");

        self.handle_incoming(&packet.header.into(), packet).await
    }

    async fn tick(
        &mut self,
        _stats: &mut StatsCollection,
        timers: &mut Timers,
    ) -> Option<Vec<Packet>> {
        let mut packets = vec![];

        // timers
        if timers.get_mut(&CHECK_SYNC.0.to_string()).unwrap().expired() {
            trace!("checking for syncs");

            packets.extend(self.check_sync().await);
        }
        if timers
            .get_mut(&LOAD_MISSING_IDS.0.to_string())
            .unwrap()
            .expired()
        {
            // check for missing ids
            packets.extend(self.handle_missing_ids().await);
        }

        // check for finished transactions
        self.core
            .get_service_data()
            .gxs_id()
            .received_groups
            .lock()
            .await
            .drain(..)
            .for_each(|group| {
                let _ = self.pending_requests.remove(&group);
            });

        packets.extend(self.nxs_service.tick(&mut self.nxs_timers).await);

        // TODO

        if packets.is_empty() {
            return None;
        }
        Some(packets)
    }

    fn get_service_info(&self) -> (String, u16, u16, u16, u16) {
        (String::from("gxsid"), 1, 0, 1, 0)
    }
}
