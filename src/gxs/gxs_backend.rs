use std::{collections::HashMap, fmt::Debug, sync::Arc, time::Duration};

use log::{debug, trace, warn};
use retroshare_compat::{
    basics::{GxsGroupId, PeerId, SslId},
    gxs::{
        sqlite::{
            database::GxsDatabase,
            types::{GxsCircleType, GxsGroup, GxsGrpMetaSql, SubscribeFlags},
        },
        NxsSyncGrpItem, NxsTransactionItemType,
    },
};
use tokio::{
    select,
    sync::{
        mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender},
        Mutex, RwLock,
    },
    time::{interval, Interval},
};
#[cfg(feature = "tracing")]
use tracing::event;

use crate::{
    gxs::transaction::StoredNxsItem,
    low_level_parsing::Packet,
    model::{
        gxs_timestamps::GxsSyncTimeStamps, intercom::Intercom, services::AppRequest, DataCore,
    },
    utils::timer_stuff::Timers,
};

use super::{nxs::NxsTransactionController, transaction::TransactionId};

// TODO
/// Wrapper for transporting various gxs/nxs items
#[derive(Debug)]
pub enum GxsItemsWrapper {
    GxsGroupIdsAll,
    GxsGroupIds(Vec<GxsGroupId>),
    GxsGroups(Vec<GxsGroup>),
    // GxsMessage(GxsMessageId),
}

// +++++++++++++++++++++++++++++++++++++++++
// +++++++++++++++++++++++++++++++++++++++++
// +++++++++++++++++++++++++++++++++++++++++
#[derive(Debug)]
pub enum GxsTaskData {
    GroupIds(Vec<GxsGroupId>),
    Groups(Vec<GxsGroup>),
}

#[derive(Debug, PartialEq)]
pub enum GxsTaskOrigin {
    Own,
    Peer(Arc<PeerId>, u32),
}

#[derive(Debug, PartialEq)]
pub enum GxsTaskState {
    Created,
    Pending(TransactionId),
    Completed,
    Failed,
}
#[derive(Debug)]
pub struct GxsTask {
    pub origin: GxsTaskOrigin,
    pub state: GxsTaskState,

    pub ty: NxsTransactionItemType,
    pub data: Option<GxsTaskData>,
}

impl GxsTask {
    pub fn is_transaction(&self, id: TransactionId) -> bool {
        match self.state {
            GxsTaskState::Pending(transaction_id) => transaction_id == id,
            GxsTaskState::Completed | GxsTaskState::Failed | GxsTaskState::Created => false,
        }
    }
}

// +++++++++++++++++++++++++++++++++++++++++
// +++++++++++++++++++++++++++++++++++++++++
// +++++++++++++++++++++++++++++++++++++++++

enum GxsRequestChannelInner<IN, OUT> {
    Initialized(
        Option<(
            UnboundedSender<AppRequest<IN, OUT>>,
            UnboundedReceiver<AppRequest<IN, OUT>>,
        )>,
    ),
    Ready(UnboundedSender<AppRequest<IN, OUT>>),
}

pub struct GxsRequestChannel<IN, OUT>(RwLock<GxsRequestChannelInner<IN, OUT>>);

impl<IN, OUT> GxsRequestChannel<IN, OUT> {
    pub fn new() -> Self {
        let (tx, rx): (
            UnboundedSender<AppRequest<IN, OUT>>,
            UnboundedReceiver<AppRequest<IN, OUT>>,
        ) = unbounded_channel();
        GxsRequestChannel(RwLock::new(GxsRequestChannelInner::Initialized(Some((
            tx, rx,
        )))))
    }

    pub fn take_receiver(&self) -> UnboundedReceiver<AppRequest<IN, OUT>> {
        let mut lock = self.0.try_write().unwrap(); // when this is called, there should only be one writer (the caller)
        let (tx, rx) = match *lock {
            GxsRequestChannelInner::Initialized(ref mut inner) => inner.take().unwrap(),
            GxsRequestChannelInner::Ready(_) => panic!("calling take_receiver twice it a bug!"),
        };
        *lock = GxsRequestChannelInner::Ready(tx);

        rx
    }

    pub fn add_request(&self, request: AppRequest<IN, OUT>)
    where
        IN: Debug,
        OUT: Debug,
    {
        match *self.0.try_read().unwrap() {
            // when this is called there should only be readers but not a single writer anymore
            GxsRequestChannelInner::Ready(ref tx) => tx.send(request).unwrap(),
            GxsRequestChannelInner::Initialized(Some(ref inner)) => {
                log::error!("add_request was called before take_receiver!");
                inner.0.send(request).unwrap();
            }
            _ => panic!(),
        }
    }
}

// Object shared between various gxs/nxs components
pub struct GxsShared {
    pub(super) core_tx: UnboundedSender<Intercom>,

    pub(super) own_id: Arc<SslId>,

    pub(super) gxs_timestamps: GxsSyncTimeStamps,

    // queues
    // received_items: Mutex<VecDeque<GxsItemsWrapper>>,
    pub requests: GxsRequestChannel<GxsItemsWrapper, GxsItemsWrapper>,
}

impl GxsShared {
    pub fn new(core_tx: UnboundedSender<Intercom>, own_id: Arc<SslId>) -> Self {
        GxsShared {
            core_tx,
            own_id,
            gxs_timestamps: GxsSyncTimeStamps::new(),

            // received_items: Mutex::new(VecDeque::new()),
            // requests: Mutex::new(Vec::new()),
            requests: GxsRequestChannel::new(),
        }
    }
}

pub struct GxsBackend<const TYPE: u16> {
    core: Arc<DataCore>,

    shared: Arc<GxsShared>,
    requests: UnboundedReceiver<AppRequest<GxsItemsWrapper, GxsItemsWrapper>>,

    database: Mutex<GxsDatabase>,
    mem_cache: Mutex<GxsDatabase>,
    nxs: NxsTransactionController<TYPE>,

    tasks: Mutex<Vec<GxsTask>>,

    missing_groups: Mutex<Vec<(GxsGroupId, Arc<PeerId>)>>,

    timer: Interval,
    timer_sync_server_ts: Interval,
    timer_sync_groups: Interval,
    timer_load_missing: Interval,
}

impl<const TYPE: u16> Debug for GxsBackend<TYPE> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "tasks {:?}, missing: {:?}",
            self.tasks.blocking_lock().len(),
            self.missing_groups.blocking_lock().len()
        )
    }
}

impl<const TYPE: u16> GxsBackend<TYPE> {
    pub fn new(
        core: Arc<DataCore>,
        db: GxsDatabase,
        nxs: NxsTransactionController<TYPE>,
        shared: Arc<GxsShared>,
    ) -> Self {
        // setup mem cache
        let mem_cache = GxsDatabase::new_mem("").unwrap();
        // let mem_cache = GxsDatabase::new_file("/tmp/foo.db".into(), "").unwrap();

        let requests = shared.requests.take_receiver();

        Self {
            core,

            shared,
            requests,

            database: Mutex::new(db),
            mem_cache: Mutex::new(mem_cache),
            nxs,

            tasks: Mutex::new(vec![]),

            missing_groups: Mutex::new(vec![]),

            timer: interval(Duration::from_millis(25)),
            timer_sync_server_ts: interval(Duration::from_secs(120)),
            timer_sync_groups: interval(Duration::from_secs(60)),
            timer_load_missing: interval(Duration::from_secs(3)),
        }
    }

    #[cfg_attr(feature = "tracing", tracing::instrument)]
    pub async fn get_group(&self, group_id: &GxsGroupId, with_data: bool) -> Option<GxsGroup> {
        trace!("getting group {group_id}");
        // FIXME this code is a bit odd since the database is not Send. Therefore we cannot hold any reference across an `await`

        let res = match self.mem_cache.lock().await.get_grp_meta(group_id) {
            Ok(Some(group)) => {
                trace!("found group in mem_cache");
                Some(group)
            }
            Ok(None) => None,
            Err(err) => {
                debug!("failed to get group by id: {err}");
                None
            }
        };

        if let Some(mut group) = res {
            #[cfg(feature = "tracing")]
            event!(tracing::Level::DEBUG, "found in memcache");
            if with_data {
                self.mem_cache
                    .lock()
                    .await
                    .get_grp_data(&mut group)
                    .unwrap();
            }
            return Some(group);
        }
        #[cfg(feature = "tracing")]
        event!(tracing::Level::DEBUG, "nothing in memcache");

        let res = match self.database.lock().await.get_grp_meta(group_id) {
            Ok(result) => result,
            Err(err) => {
                debug!("failed to get group by id: {err}");

                None
            }
        };

        match res {
            None => {
                #[cfg(feature = "tracing")]
                event!(tracing::Level::DEBUG, "nothing in database");

                self.missing_groups
                    .lock()
                    .await
                    .push((group_id.to_owned(), Arc::new(PeerId::default())));
                None
            }
            Some(mut group) => {
                trace!("found group in database");
                #[cfg(feature = "tracing")]
                event!(tracing::Level::DEBUG, "found in database");

                let found = self.database.lock().await.get_grp_data(&mut group).is_ok();

                if found {
                    self.mem_cache.lock().await.insert_group(&group).unwrap();
                }

                Some(group)
            }
        }
    }

    async fn request_groups(&self) {
        // collect ids per peer
        let mut peer_map: HashMap<Arc<PeerId>, Vec<GxsGroupId>> = HashMap::new();

        for (group, peer) in self.missing_groups.lock().await.drain(..) {
            peer_map.entry(peer).or_default().push(group);
        }

        for (peer_id, group_ids) in peer_map {
            let transaction_id = self.nxs.request_groups(&group_ids, peer_id).await;

            let task = GxsTask {
                origin: GxsTaskOrigin::Own,
                state: GxsTaskState::Pending(transaction_id),
                data: None,
                ty: NxsTransactionItemType::Groups,
            };

            self.tasks.lock().await.push(task);
        }
    }

    async fn handle_tasks(&self) {
        let mut lock = self.tasks.lock().await;

        self.nxs.handle_completed_transactions(&mut lock).await;

        for task in lock.iter_mut() {
            // debug!("{task:?}");
            match &task.origin {
                GxsTaskOrigin::Own => {
                    // self initiated tasks
                    match &task.state {
                        GxsTaskState::Completed => match &task.ty {
                            NxsTransactionItemType::Groups => {
                                // we requested groups and received groups

                                // process and add groups
                                let groups =
                                    match task.data.take().expect(
                                        "expected groups but nothing is set, this is a bug!",
                                    ) {
                                        GxsTaskData::Groups(groups) => groups,
                                        data @ _ => panic!("unexpected task data {data:?}"),
                                    };

                                for group in groups {
                                    debug!("adding groups {}", group.group_id);
                                    self.mem_cache.lock().await.insert_group(&group).unwrap();
                                }

                                //     // validate group
                                //     // TODO
                                //     /*
                                //     uint32_t p3IdService::idAuthenPolicy()
                                //     {
                                //         uint32_t policy = 0;
                                //         uint8_t flag = 0;

                                //         // Messages are send reputations. normally not by ID holder - so need signatures.
                                //         flag = GXS_SERV::MSG_AUTHEN_ROOT_AUTHOR_SIGN | GXS_SERV::MSG_AUTHEN_CHILD_AUTHOR_SIGN;
                                //         RsGenExchange::setAuthenPolicyFlag(flag, policy, RsGenExchange::PUBLIC_GRP_BITS);
                                //         RsGenExchange::setAuthenPolicyFlag(flag, policy, RsGenExchange::RESTRICTED_GRP_BITS);
                                //         RsGenExchange::setAuthenPolicyFlag(flag, policy, RsGenExchange::PRIVATE_GRP_BITS);

                                //         // No ID required.
                                //         flag = 0;
                                //         RsGenExchange::setAuthenPolicyFlag(flag, policy, RsGenExchange::GRP_OPTION_BITS);

                                //         return policy;
                                //     }
                                //     */
                                //     const POLICY: u32 = 0x000c0c0c;
                                //     let check_authen_flags = |policy: u32| -> bool { (0x01 & (policy >> 24)) > 0 };
                                //     if meta.author_id != GxsId::default() && check_authen_flags(POLICY) {}

                                //     // compute hash
                                //     // TODO verify code
                                //     {
                                //         let hash =
                                //             openssl::hash::hash(openssl::hash::MessageDigest::sha1(), &group.grp).unwrap();
                                //         meta.hash = hash.as_ref().to_owned().into();
                                //     }

                                //     // TODO?
                                //     group.meta_data = Some(meta.to_owned());
                            }
                            _ => {
                                warn!("unimplemented task {task:?} please fix!");
                            }
                        },
                        GxsTaskState::Created => {
                            unimplemented!()
                        }
                        GxsTaskState::Failed => {
                            // TODO?
                        }
                        GxsTaskState::Pending(_transaction_id) => {}
                    }
                }
                GxsTaskOrigin::Peer(peer_id, ts) => {
                    // peer initiated tasks
                    match &task.state {
                        GxsTaskState::Completed => {
                            match &task.ty {
                                NxsTransactionItemType::GroupListRequest => {
                                    // peer requested ids and we will respond now

                                    // 1. collect group ids
                                    let requested_group_ids = match task.data.take().expect(
                                        "expected group ids but nothing is set, this is a bug!",
                                    ) {
                                        GxsTaskData::GroupIds(ids) => ids,
                                        data @ _ => panic!("unexpected task data {data:?}"),
                                    };

                                    debug!(
                                        "peer {peer_id} requested {} groups",
                                        requested_group_ids.len()
                                    );
                                    trace!("{requested_group_ids:?}");

                                    // 2. fetch groups
                                    let items = {
                                        // this is a workaround until async closures are stable
                                        let mut items = vec![];

                                        for group_id in &requested_group_ids {
                                            let res = self.get_group(&group_id, true).await;
                                            trace!("{group_id} -> {res:?}");
                                            match res {
                                                Some(group) => {
                                                    items.push(StoredNxsItem::NxsGrp(group.into()))
                                                }
                                                None => {}
                                            }
                                        }

                                        items
                                    };
                                    trace!("{items:?}");
                                    let empty = items.is_empty();

                                    // 3. send groups to peer (even empty ones, nxs will take care (and especially update timestamps!))
                                    match self
                                        .nxs
                                        .send_groups_transaction(peer_id.to_owned(), *ts, items)
                                        .await
                                    {
                                        Some(transaction_id) => {
                                            task.state = GxsTaskState::Pending(transaction_id);
                                        }
                                        None => {
                                            if empty {
                                                // This is expected on empty groups
                                                debug!("failed to create transaction for {task:?}, no local groups found");
                                            } else {
                                                warn!("failed to create transaction for {task:?}");
                                            }
                                            debug!("requested group ids: {requested_group_ids:?}");
                                            task.state = GxsTaskState::Failed;
                                        }
                                    }
                                }

                                _ => {
                                    warn!("unimplemented task {task:?} please fix!");
                                }
                            }
                        }
                        GxsTaskState::Created => match &task.ty {
                            // GxsPeerRequest::GroupSync(_item) => {
                            NxsTransactionItemType::GroupListResponse => {
                                // peer requested a group item sync
                                // (and nxs timestamps says that there might be something new)

                                // TODO merge once only one db is used.
                                let mut groups: HashMap<GxsGroupId, GxsGrpMetaSql> = HashMap::new();
                                self.database
                                    .lock()
                                    .await
                                    .get_grp_meta_all()
                                    .unwrap()
                                    .into_iter()
                                    .for_each(|group| {
                                        // let _ = groups.insert(group_id);
                                        if !groups.contains_key(&group.group_id) {
                                            groups.insert(group.group_id, group);
                                        }
                                    });
                                self.mem_cache
                                    .lock()
                                    .await
                                    .get_grp_meta_all()
                                    .unwrap()
                                    .into_iter()
                                    .for_each(|group| {
                                        // let _ = groups.insert(group_id);
                                        if !groups.contains_key(&group.group_id) {
                                            groups.insert(group.group_id, group);
                                        }
                                    });

                                let items: Vec<_> = groups
                                    .into_iter()
                                    .map(|(_, group)| GxsGroup::from(group))
                                    .filter(|group| {
                                        true //  group.publish_ts > item.update_ts as i64 // TODO implement all RS checks from RsGxsNetService::canSendGrpId
                                        && group.subscribe_flags.contains(SubscribeFlags::SUBSCRIBED)
                                       &&
                                            [GxsCircleType::Unknown, GxsCircleType::Public]
                                                .contains(&group.circle_type)
                                    })
                                    .map(|group| NxsSyncGrpItem::from(group))
                                    .collect();

                                match self
                                    .nxs
                                    .send_group_sync_transaction(items, peer_id.to_owned())
                                    .await
                                {
                                    Some(transaction_id) => {
                                        task.state = GxsTaskState::Pending(transaction_id)
                                    }
                                    None => {
                                        warn!("failed to create transaction for {task:?}");
                                    }
                                }
                            }
                            _ => {
                                warn!("unimplemented task {task:?} please fix!");
                            }
                        },
                        GxsTaskState::Failed => {
                            // TODO?
                        }
                        GxsTaskState::Pending(_transaction_id) => {}
                    }
                }
            }
        }

        // now remove finished tasks
        lock.retain(|task| match task.state {
            GxsTaskState::Completed | GxsTaskState::Failed => false,
            GxsTaskState::Pending(_) | GxsTaskState::Created => true,
        });
    }

    async fn sync_server_ts(&self) {
        let mut times: Vec<i64> = self
            .database
            .lock()
            .await
            .get_grp_meta_all()
            .unwrap()
            .into_iter()
            .map(|group| group.recv_ts)
            .collect();
        times.sort_unstable();

        if let Some(last) = times.last() {
            self.shared
                .gxs_timestamps
                .update_local_last(*last as u32)
                .await;
        }
    }

    pub async fn handle_packet(&self, packet: Packet) {
        // let peer_id = packet.peer_id.to_owned();

        let mut new_tasks = self
            .nxs
            .handle_incoming_packet(&packet.header.into(), packet)
            .await;

        // register new tasks
        self.tasks.lock().await.append(&mut new_tasks);
    }

    async fn handle_request(&self, request: AppRequest<GxsItemsWrapper, GxsItemsWrapper>) {
        trace!("handling request {request:?}");

        let resp = match request.ty {
            GxsItemsWrapper::GxsGroupIds(group_ids) => {
                let mut groups = vec![];
                for group_id in group_ids {
                    match self.get_group(&group_id, false).await {
                        Some(group) => groups.push(group),
                        None => {}
                    }
                }
                groups
            }
            GxsItemsWrapper::GxsGroupIdsAll => {
                // get all ids
                // FIXME once only one db is used
                let mut group_ids = self.database.lock().await.get_group_ids().unwrap();
                for group_id in self.mem_cache.lock().await.get_group_ids().unwrap() {
                    if !group_ids.contains(&group_id) {
                        group_ids.push(group_id);
                    }
                }

                let mut groups = vec![];
                for group_id in group_ids {
                    match self.get_group(&group_id, false).await {
                        Some(group) => groups.push(group),
                        None => {}
                    }
                }
                groups
            }
            GxsItemsWrapper::GxsGroups(_) => {
                log::error!("this makes no sense: request = {request:?}");
                vec![]
            }
        };

        request
            .tx
            .send(GxsItemsWrapper::GxsGroups(resp))
            .unwrap_or_else(|ref _result| warn!("request failed to send, probably timed out"));
    }

    pub async fn tick(&self, timers: &mut Timers) {
        self.nxs.tick(timers).await;
        self.handle_tasks().await;
    }

    pub async fn run(&mut self) {
        // all of these must be restartable!
        loop {
            select! {
                request = self.requests.recv() => {
                    if let Some(request) = request {
                        self.handle_request(request).await;
                    }
                }
                _ = self.timer.tick() => {
                    let mut dummy = Timers::new();
                    self.tick(&mut dummy).await;
                }
                _ = self.timer_sync_server_ts.tick() => {
                    trace!("sync_server_ts");
                    self.sync_server_ts().await;
                }
                _ = self.timer_sync_groups.tick() => {
                    trace!("check_peer_updates");
                    let peers = self.core.get_connected_peers().lock().await.0.iter().map(|(peer, _)| peer.to_owned()).collect();
                    self.nxs.check_peer_updates(peers).await;
                }
                _ = self.timer_load_missing.tick() => {
                    trace!("requesting missing");
                    self.request_groups().await;
                }
            }
        }
    }
}
