use std::{
    collections::{hash_map::Entry, HashMap},
    sync::Arc,
    time::SystemTime,
};

use log::{debug, trace, warn, info};
use retroshare_compat::{
    basics::{GxsGroupId, GxsId, PeerId},
    gxs::{
        NxsGrp, NxsItem, NxsSyncGrpItem, NxsSyncGrpItemFlags, NxsSyncGrpReqItem,
        NxsTransactionItem, NxsTransactionItemFlags, NxsTransactionItemType,
    },
    read_u32,
    serde::{from_retroshare_wire, to_retroshare_wire},
};
use serde::Serialize;
use tokio::sync::{ Mutex, RwLock};

use crate::{
    gxs::{
        gxs_backend::{GxsTaskData, GxsTaskOrigin, GxsTaskState},
        transaction::{NxsTransactionState, StoredNxsItem},
    },
    low_level_parsing::{headers::ServiceHeader, Packet},
    model::{ intercom::Intercom},
    utils::timer_stuff::Timers,
};

use super::{
    gxs_backend::{ GxsTask, GxsShared},
    transaction::{NxsTransaction, TransactionId},
};

const SUBTYPE_NXS_SYNC_GRP_REQ_ITEM: u8 = 0x01;
const SUBTYPE_NXS_SYNC_GRP_ITEM: u8 = 0x02;
#[allow(unused)]
const SUBTYPE_NXS_SYNC_GRP_STATS_ITEM: u8 = 0x03;
const SUBTYPE_NXS_GRP_ITEM: u8 = 0x04;
#[allow(unused)]
const SUBTYPE_NXS_ENCRYPTED_DATA_ITEM: u8 = 0x05;
#[allow(unused)]
const SUBTYPE_NXS_SESSION_KEY_ITEM: u8 = 0x06;
#[allow(unused)]
const SUBTYPE_NXS_SYNC_MSG_ITEM: u8 = 0x08;
#[allow(unused)]
const SUBTYPE_NXS_SYNC_MSG_REQ_ITEM: u8 = 0x10;
#[allow(unused)]
const SUBTYPE_NXS_MSG_ITEM: u8 = 0x20;
const SUBTYPE_NXS_TRANSACTION_ITEM: u8 = 0x40;
#[allow(unused)]
const SUBTYPE_NXS_GRP_PUBLISH_KEY_ITEM: u8 = 0x80;
#[allow(unused)]
const SUBTYPE_NXS_SYNC_PULL_REQUEST_ITEM: u8 = 0x90;


pub struct NxsTransactionController<const TYPE: u16> {
    shared: Arc<GxsShared>,

    #[allow(unused)]
    last_sync: SystemTime,
    last_transaction_number: Mutex<u32>,

    // RS stores them like this, TODO improve?
    transactions: RwLock<HashMap<Arc<PeerId>, HashMap<TransactionId, NxsTransaction<TYPE>>>>,
    transactions_completed: RwLock<Vec<(TransactionId, NxsTransaction<TYPE>)>>,
}

impl<const TYPE: u16> NxsTransactionController<TYPE> {
    pub fn new(shared: Arc<GxsShared>) -> Self {
        let now = (SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs() % u32::MAX as u64) as u32;
        Self {
            shared,

            // TODO
            last_sync: SystemTime::now(),
            last_transaction_number: Mutex::new(now),

            transactions: RwLock::new(HashMap::new()),
            transactions_completed: RwLock::new(vec![]),
        }
    }

    fn send_packet<T>(&self, sub_type: u8, item: &T, receiving_peer: Arc<PeerId>)
    where
        T: Serialize,
    {
        let payload = to_retroshare_wire(item);
        let header = ServiceHeader::new(TYPE.into(), sub_type, &payload);
        let packet = Packet::new(header.into(), payload, receiving_peer);

        self.shared
            .core_tx
            .send(Intercom::Send(packet))
            .expect("failed to send to core");
    }

    // This function might create new tasks
    #[cfg_attr(feature = "tracing", tracing::instrument)]
    pub async fn handle_incoming_packet(
        &self,
        header: &ServiceHeader,
        mut packet: Packet,
    ) -> Vec<GxsTask> {
        // does the packet have a transaction id?
        let transaction_id = read_u32(&mut packet.payload[0..4].to_owned());
        if transaction_id != 0 {
            trace!("handle_incoming_transaction {transaction_id}");

            self.handle_incoming_transaction(header, packet).await;
            return vec![];
        }

        // Assumption:
        // Here are only types that can be answered directly
        // (Which mean we will create a tasks)

        match header.sub_type {
            SUBTYPE_NXS_SYNC_GRP_REQ_ITEM => {
                trace!("sync grp req item");

                let item: NxsSyncGrpReqItem = from_retroshare_wire(&mut packet.payload);
                trace!("{item:?}");

                if self
                    .shared
                    .gxs_timestamps
                    .check_local_last(item.update_ts)
                    .await
                {
                    let task = GxsTask {
                        origin: GxsTaskOrigin::Peer(packet.peer_id.to_owned(), item.update_ts),
                        state: GxsTaskState::Created,
                        ty: NxsTransactionItemType::GroupListResponse,
                        data: None,
                    };

                    vec![task]
                } else {
                    vec![]
                }
            }

            // TODO
            // SUBTYPE_NXS_SYNC_GRP_STATS_ITEM => (),
            // SUBTYPE_NXS_ENCRYPTED_DATA_ITEM => (),
            // SUBTYPE_NXS_SESSION_KEY_ITEM => (),
            // SUBTYPE_NXS_SYNC_MSG_ITEM => (),
            // SUBTYPE_NXS_SYNC_MSG_REQ_ITEM => (),
            // SUBTYPE_NXS_MSG_ITEM => (),
            // SUBTYPE_NXS_GRP_PUBLISH_KEY_ITEM => (),
            // SUBTYPE_NXS_SYNC_PULL_REQUEST_ITEM => (),

            sub_type => {
                warn!("received unknown sub typ {sub_type:02X}");
                vec![]
            }
        }
    }

    #[cfg_attr(feature = "tracing", tracing::instrument)]
    async fn handle_incoming_transaction(&self, header: &ServiceHeader, mut packet: Packet) {
        /*
        The following cases are expected:
         - a transaction item is doing transactions stuff
         - any other packet is adding items to an existing transaction
        */

        match header.sub_type {
            SUBTYPE_NXS_SYNC_GRP_ITEM => {
                trace!("sync grp item");

                let item: NxsSyncGrpItem = from_retroshare_wire(&mut packet.payload);
                trace!("{item:?}");

                let transaction_id = item.base.transaction_id;
                let peer = packet.peer_id.to_owned();

                self.add_item_to_transaction(
                    peer,
                    transaction_id,
                    StoredNxsItem::NxsSyncGrpItem(item),
                )
                .await;
            }
            SUBTYPE_NXS_GRP_ITEM => {
                trace!("grp req item");

                let item: NxsGrp<TYPE> = from_retroshare_wire(&mut packet.payload);
                trace!("{:?} {}", item.base, item.grp_id);

                if item.count != 0 || item.pos != 0 {
                    // TODO is this even used by RS?
                    warn!("item with pos or count: {item:?}");
                }

                // add item to transaction
                let transaction_id = item.base.transaction_id;
                let peer = packet.peer_id.to_owned();

                self.add_item_to_transaction(peer, transaction_id, StoredNxsItem::NxsGrp(item))
                    .await;
            }
            SUBTYPE_NXS_TRANSACTION_ITEM => {
                trace!("transaction item");

                let item: NxsTransactionItem = from_retroshare_wire(&mut packet.payload);

                let transaction_id = item.base.transaction_id;
                if log::log_enabled!(log::Level::Trace) {
                    trace!("{item:?}");
                } else {
                    debug!("transaction id: {}", transaction_id);
                }                

                let peer = if [
                    NxsTransactionItemFlags::FlagBeginAck,
                    NxsTransactionItemFlags::FlagEndSuccess,
                ]
                .contains(&item.transact_flag)
                {
                    self.shared.own_id.to_owned()
                } else {
                    packet.peer_id.to_owned()
                };

                let mut lock = self.transactions.write().await;

                // Note: used by RS's checks, existing code should be equivalent
                #[cfg(debug_assertions)]
                let (peer_exists, trans_exists) = match lock.entry(peer.to_owned()) {
                    Entry::Occupied(mut entry) => match entry.get_mut().entry(transaction_id) {
                        Entry::Occupied(_entry) => (true, true),
                        Entry::Vacant(_) => (true, false),
                    },
                    Entry::Vacant(_) => (false, false),
                };

                match item.transact_flag {
                    NxsTransactionItemFlags::FlagBegin => {
                        // remote started transaction

                        debug!("received new transaction {transaction_id}: {:?}", item.transact_type);

                        // Note: RS does a check here, we do it later
                        #[cfg(debug_assertions)]
                        {
                            if trans_exists {
                                warn!("peer {peer} tries to start a transaction ({transaction_id}) but it already exists!");
                            }
                        }

                        // get peer's entry
                        let peer_entry = lock.entry(peer.to_owned());

                        // insert new peer entry if necessary
                        match peer_entry.or_insert(HashMap::new()).entry(transaction_id) {
                            Entry::Occupied(entry) => {
                                warn!("FlagBeginIncoming received (incoming) transaction start ({transaction_id}) from peer {peer} but there is already a transaction: {entry:?}!");
                            }
                            Entry::Vacant(entry) => {
                                entry.insert(NxsTransaction::new_starting(
                                    transaction_id,
                                    peer.to_owned(),
                                    item,
                                ));
                            }
                        }
                    }
                    NxsTransactionItemFlags::FlagBeginAck => {
                        // we started a transaction

                        // Note: RS does a check here, we do it later
                        #[cfg(debug_assertions)]
                        {
                            if !peer_exists || !trans_exists {
                                warn!("peer {peer} tries to acknowledge a transaction ({transaction_id}) but it doesn't exists!");
                            }
                        }

                        // get own entry (already set)
                        let peer_entry = lock.entry(peer);

                        match peer_entry {
                            Entry::Occupied(mut entry) => {
                                match entry.get_mut().entry(transaction_id) {
                                    Entry::Occupied(mut entry) => {
                                        info!("WaitingConfirm -> Sending {transaction_id}");
                                        assert!(
                                            entry.get().state
                                                == NxsTransactionState::WaitingConfirm
                                        );
                                        entry.get_mut().state = NxsTransactionState::Sending;
                                    }
                                    Entry::Vacant(_entry) => {
                                        warn!(
                                            "FlagBeginOutgoing received (outgoing) transaction start but there is matching transaction!"
                                        );
                                    }
                                }
                            }
                            Entry::Vacant(_entry) => {
                                warn!(
                                    "FlagBeginOutgoing received (outgoing) transaction start but there is no peer entry!"
                                );
                            }
                        }
                    }
                    NxsTransactionItemFlags::FlagEndSuccess => {
                        // transaction finished

                        // Note: RS does a check here, we do it later
                        #[cfg(debug_assertions)]
                        {
                            if !peer_exists || !trans_exists {
                                warn!("peer {peer} tries to finish a transaction ({transaction_id}) but it doesn't exists!");
                            }
                        }

                        // get own entry (already set)
                        let peer_entry = lock.entry(peer);

                        match peer_entry {
                            Entry::Occupied(mut entry) => {
                                match entry.get_mut().entry(transaction_id) {
                                    Entry::Occupied(mut entry) => {
                                        info!("WaitingConfirm -> Completed {transaction_id}");
                                        assert!(
                                            entry.get().state
                                                == NxsTransactionState::WaitingConfirm
                                        );
                                        entry.get_mut().state = NxsTransactionState::Completed;
                                        entry.get_mut().mark_finished();

                                    }
                                    Entry::Vacant(_entry) => {
                                        warn!("FlagEndSuccess received (outgoing) transaction end but there is no matching transaction!");
                                    }
                                }
                            }
                            Entry::Vacant(_entry) => {
                                warn!(
                                    "FlagEndSuccess received transaction end but there is no peer entry!"
                                );
                            }
                        }
                    }
                    state @ _ => {
                        // RS doesn't handle any other state here
                        warn!("handle_incoming_transaction: transaction item: unexpected state {state:?}");
                    }
                }
            }
            sub_type => {
                warn!("handle_incoming_transaction: received unknown sub typ {sub_type:02X}");
            }
        }
    }

    #[cfg_attr(feature = "tracing", tracing::instrument)]
    async fn add_item_to_transaction(
        &self,
        peer: Arc<PeerId>,
        transaction_id: TransactionId,
        item: StoredNxsItem<TYPE>,
    ) {
        debug!("received part of transaction {transaction_id}");
        trace!("{item:?}");

        let mut lock = self.transactions.write().await;
        let peer_entry = lock.entry(peer.to_owned());
        // insert new peer entry if necessary
        match peer_entry {
            Entry::Occupied(mut entry) => match entry.get_mut().entry(transaction_id) {
                Entry::Occupied(mut entry) => {
                    entry.get_mut().items.push(item);
                    debug!("-> {}/{}", entry.get().items.len() , entry.get().initial_packet.items);
                }
                Entry::Vacant(_entry) => {
                    warn!("received a grp item for transaction {transaction_id} from peer {peer}, but there is no pending transaction!");
                }
            },
            Entry::Vacant(_entry) => {
                warn!("received a grp item for transaction {transaction_id} from peer {peer}, but peer cannot be found!");
            }
        }
    }

    #[cfg_attr(feature = "tracing", tracing::instrument)]
    async fn handle_active_transactions(&self) {
        let mut to_remove = vec![];

        let own_id = &self.shared.own_id;

        let mut lock = self.transactions.write().await;
        for (peer_id, transactions) in lock.iter_mut() {
            to_remove.clear();

            transactions.iter_mut().for_each(|(id, transaction)| {
                if transaction.timeout() {
                    debug!("transaction {id} timed out!");
                    transaction.state = NxsTransactionState::Failed;
                    // transaction is removed below
                }
            });

            // TODO
            // we probably need some timestamp management here...

            if own_id == peer_id {
                // our transactions
                for (id, transaction) in transactions.iter_mut() {
                    match &transaction.state {
                        NxsTransactionState::Sending => {
                            debug!("sending items for transaction {id}");

                            // send items
                            let mut counter = 1;
                            let max = transaction.items.len();
                            for item in transaction.items.drain(..) {
                                debug!("sending part of transaction {id}");
                                debug!("-> {}/{}", counter , max);
                                counter +=1;


                                trace!("sending: {item:?}");

                                match item {
                                    StoredNxsItem::NxsGrp(item) => {
                                        // (to_retroshare_wire(&item), SUBTYPE_NXS_GRP_ITEM)
                                        self.send_packet(
                                            SUBTYPE_NXS_GRP_ITEM,
                                            &item,
                                            transaction.peer_id.to_owned(),
                                        )
                                        ;
                                    }
                                    StoredNxsItem::NxsSyncGrpItem(item) => {
                                        // (to_retroshare_wire(&item), SUBTYPE_NXS_SYNC_GRP_ITEM)
                                        self.send_packet(
                                            SUBTYPE_NXS_SYNC_GRP_ITEM,
                                            &item,
                                            transaction.peer_id.to_owned(),
                                        )
                                        ;
                                    }
                                }
                            }

                            info!("Sending -> WaitingConfirm {id}");
                            transaction.state = NxsTransactionState::WaitingConfirm;
                        }
                        NxsTransactionState::WaitingConfirm => {
                            // nothing
                            trace!(
                                "WaitingConfirm {id} {:?}",
                                transaction.initial_packet.transact_type
                            );
                        }
                        NxsTransactionState::Completed |
                        NxsTransactionState::Failed => {
                            to_remove.push(*id);
                        }
                        state @ _ => {
                            warn!("unknown transaction state {state:?} for {id} (outgoing), canceling!");
                            transaction.state = NxsTransactionState::Failed;
                            to_remove.push(*id);
                        }
                    }
                }
            } else {
                // remote transactions
                for (id, transaction) in transactions.iter_mut() {
                    match &transaction.state {
                        NxsTransactionState::Starting => {
                            debug!("ready to start transaction {id}");
                            let item = NxsTransactionItem {
                                base: NxsItem {
                                    transaction_id: *id,
                                    peer_id: *peer_id.to_owned(),
                                },
                                items: 0,
                                timestamp: 0,
                                transact_flag: NxsTransactionItemFlags::FlagBeginAck,
                                transact_type: transaction.initial_packet.transact_type.to_owned(),
                                update_ts: 0,
                            };
                            self.send_packet(
                                SUBTYPE_NXS_TRANSACTION_ITEM,
                                &item,
                                peer_id.to_owned(),
                            )
                            ;

                            info!("Starting -> Receiving {id}");
                            transaction.state = NxsTransactionState::Receiving;
                        }
                        NxsTransactionState::Receiving => {
                            if transaction.complete() {
                                debug!("completely received transaction {id}");
                                info!("Receiving -> Completed {id}");
                                transaction.state = NxsTransactionState::Completed;

                                // // TODO brought to you by Xeres
                                // self.core
                                //     .get_gxs_timestamps()
                                //     .update_ts_peer(peer_id.to_owned(), self.get_id())
                                //     .await
                            }
                        }
                        NxsTransactionState::Completed => {
                            // note: seen in log
                            debug!("finished transaction {id}");                            
                            transaction.mark_finished();

                            let item = NxsTransactionItem {
                                base: NxsItem {
                                    transaction_id: *id,
                                    peer_id: *peer_id.to_owned(),
                                },
                                items: 0,
                                timestamp: 0,
                                transact_flag: NxsTransactionItemFlags::FlagEndSuccess,
                                transact_type: NxsTransactionItemType::None,
                                update_ts: 0,
                            };
                            // let payload = to_retroshare_wire(&item);
                            // let header = ServiceHeader::new(
                            //     TYPE.into(),
                            //     SUBTYPE_NXS_TRANSACTION_ITEM,
                            //     &payload,
                            // );
                            // packets.push(Packet::new(header.into(), payload, peer_id.to_owned()));
                            self.send_packet(
                                SUBTYPE_NXS_TRANSACTION_ITEM,
                                &item,
                                peer_id.to_owned(),
                            )
                            ;

                            if self.process_transaction_for_decryption(transaction).await {
                                to_remove.push(*id);
                            } else {
                                debug!("unable to decrypt transaction (yet)");
                            }
                        }
                        NxsTransactionState::Failed => {
                            to_remove.push(*id);
                        }
                        state @ _ => {
                            warn!("unknown transaction state {state:?} for {id} (incoming), canceling!");
                            transaction.state = NxsTransactionState::Failed;
                            to_remove.push(*id);
                        }
                    }
                }
            }
            let mut lock2 = self.transactions_completed.write().await;

            for id in &to_remove {
                // remove transaction
                let transaction = transactions.remove(id).unwrap();
                // insert transaction
                lock2.push((*id, transaction));
            }
        }
    }

    // will add new tasks
    #[cfg_attr(feature = "tracing", tracing::instrument)]
    pub async fn handle_completed_transactions(&self, tasks: &mut Vec<GxsTask>) {
        let own_id = &self.shared.own_id;
        let transactions: Vec<_> = self
            .transactions_completed
            .write()
            .await
            .drain(..)
            .collect();

        for (id, transaction) in transactions {
            let transaction_id = transaction.transaction_id;

            if *own_id == transaction.peer_id {
                // our transactions
                // TODO can this case be hit at the moment?
                // warn!("{transaction:?}");
                match &transaction.state {
                    NxsTransactionState::Failed => {
                        // ¯\_(ツ)_/¯
                        match tasks
                        .iter_mut()
                        .find(|entry| entry.is_transaction(transaction_id))
                        {
                            Some(task) => 
                                task.state = GxsTaskState::Failed
                            ,
                            None => {}
                        };
                    }
                    state @ _ => {
                        log::error!("unexpected transaction state {state:?}, this is likely a code bug! id: {id}, transaction: {transaction:?}");
                    }
                }
            } else {
                // remote transactions
                match &transaction.state {
                    NxsTransactionState::Completed => {
                        debug!(
                            "handling completed transaction {id} with type {:?}",
                            transaction.initial_packet.transact_type
                        );
                        transaction.check_finished();

                        match transaction.initial_packet.transact_type {
                            NxsTransactionItemType::GroupListRequest => {
                                // ts are updated later

                                // write result
                                let mut task = match tasks
                                    .iter_mut()
                                    .find(|entry| entry.is_transaction(transaction_id))
                                {
                                    Some(task) => {
                                        assert!(
                                            task.state == GxsTaskState::Pending(transaction_id)
                                        );
                                        task
                                    }
                                    None => {
                                        let task = GxsTask {
                                            data: None, // will be set below
                                            origin: GxsTaskOrigin::Peer(transaction.peer_id.to_owned(), transaction.initial_packet.timestamp),
                                            state: GxsTaskState::Pending(transaction_id), // will be set below
                                            ty: transaction.initial_packet.transact_type, // GroupListRequest
                                        };
                                        tasks.push(task);
                                        tasks.last_mut().unwrap()
                                    }
                                };

                                // extract requested group IDs
                                let requested_group_ids = transaction                 
                                       .items
                                .into_iter()
                                .map(|item| match item {
                                    StoredNxsItem::NxsSyncGrpItem(item) => {
                                        // validate flags, consistency!
                                        if item.flag != NxsSyncGrpItemFlags::Request {
                                            warn!("NxsTransactionItemType::GroupListRequest: item has wrong flags {:?}, expected 'NxsSyncGrpItemFlags::Request'", item.flag);
                                        }
                                        item.grp_id
                                    }
                                    _ => panic!("transaction contains unexpected item type! {item:?}"),
                                }).collect();
                                task.state = GxsTaskState::Completed;
                                task.data = Some(GxsTaskData::GroupIds(requested_group_ids));
                            }
                            NxsTransactionItemType::Groups => {
                                // update ts for peer
                                let peer = transaction.peer_id.to_owned();
                                let time = transaction.initial_packet.timestamp;
                                self.shared
                                    .gxs_timestamps
                                    .update_peer_group(peer, time)
                                    .await;

                                // write result
                                let mut task = match tasks
                                    .iter_mut()
                                    .find(|entry| entry.is_transaction(transaction_id))
                                {
                                    Some(task) => {
                                        assert!(
                                            task.state == GxsTaskState::Pending(transaction_id)
                                        );
                                        task
                                    }
                                    None => {
                                        let task = GxsTask {
                                            data: None, // will be set below
                                            origin: GxsTaskOrigin::Own,
                                            state: GxsTaskState::Pending(transaction_id), // will be set below
                                            ty: transaction.initial_packet.transact_type, // Groups
                                        };
                                        tasks.push(task);
                                        tasks.last_mut().unwrap()
                                    }
                                };

                                // extract received groups
                                let received_groups = transaction
                                .items
                                .into_iter()
                                .map(|item| match item {
                                    StoredNxsItem::NxsGrp(item) => item.into(),
                                    _ => panic!(
                                        "transaction contains unexpected item type! {item:?}"
                                    ),
                                }).collect();
                                task.state = GxsTaskState::Completed;
                                task.data = Some(GxsTaskData::Groups(received_groups));

                            }
                            ty @ _ => {
                                warn!("{:?} unimplemented", ty)
                            }
                        }
                    }
                    NxsTransactionState::Failed =>{
                        match tasks
                            .iter_mut()
                            .find(|entry| entry.is_transaction(transaction_id))
                        {
                            Some(task) => 
                                task.state = GxsTaskState::Failed
                            ,
                            None => {}
                        };
                    },
                    state @ _ => {
                        log::error!("unexpected transaction state {state:?}, this is likely a code bug! id: {id}, transaction: {transaction:?}");
                    }
                }
            }
        }
    }
    
    pub async fn send_group_sync_transaction(
        &self,
        mut items: Vec<NxsSyncGrpItem>,
        peer_id: Arc<PeerId>,
    ) -> Option<TransactionId> {
        if items.is_empty() {
            return None;
        }

        let transaction_id = self.get_next_transaction_number().await;

        // set transaction id
        items
            .iter_mut()
            .for_each(|item| item.base.transaction_id = transaction_id);

        // create new transaction
        let update_ts = self.shared.gxs_timestamps.get_local_last().await;
        let initial_packet = NxsTransactionItem {
            base: NxsItem {
                transaction_id,
                peer_id: *peer_id,
            },
            transact_type: NxsTransactionItemType::GroupListResponse,
            transact_flag: NxsTransactionItemFlags::FlagBegin,
            items: items.len() as u32,
            update_ts,
            timestamp: 0,
        };

        let items = items
            .into_iter()
            .map(|item| StoredNxsItem::NxsSyncGrpItem(item))
            .collect();
        let transaction_new = NxsTransaction::new_responding(
            transaction_id,
            self.shared.own_id.to_owned(),
            initial_packet.to_owned(),
            items,
        );

        // register transaction
        self.transactions
            .write()
            .await
            .entry(transaction_new.peer_id.to_owned())
            .or_default()
            .insert(transaction_id, transaction_new);

        // send item
        self.send_packet(
            SUBTYPE_NXS_TRANSACTION_ITEM,
            &initial_packet,
            peer_id.to_owned(),
        )
        ;

        Some(transaction_id)
    }

    pub async fn send_groups_transaction(
        &self,
        peer_id: Arc<PeerId>,
        update_ts: u32,
        items: Vec<StoredNxsItem<TYPE>>,
    ) -> Option<TransactionId> {
        if items.is_empty() {
            debug!("no requested groups were locally found");

            // Is this correct?
            // from void RsGxsNetService::locked_genReqGrpTransaction(NxsTransaction* tr)
            self.shared
                .gxs_timestamps
                .update_peer_group(peer_id, update_ts)
                .await;

            return None;
        }

        let transaction_id = self.get_next_transaction_number().await;

        // create new transaction
        let update_ts = self.shared.gxs_timestamps.get_local_last().await;
        let initial_packet = NxsTransactionItem {
            base: NxsItem {
                transaction_id,
                peer_id: *peer_id,
            },
            transact_type: NxsTransactionItemType::Groups,
            transact_flag: NxsTransactionItemFlags::FlagBegin,
            items: items.len() as u32,
            update_ts,
            timestamp: 0,
        };
        let transaction_new = NxsTransaction::new_responding(
            transaction_id,
            self.shared.own_id.to_owned(),
            initial_packet.to_owned(),
            items,
        );

        // register transaction
        self.transactions
            .write()
            .await
            .entry(transaction_new.peer_id.to_owned())
            .or_default()
            .insert(transaction_id, transaction_new);

        // send item
        self.send_packet(
            SUBTYPE_NXS_TRANSACTION_ITEM,
            &initial_packet,
            peer_id.to_owned(),
        )
        ;

        Some(transaction_id)
    }

    async fn process_transaction_for_decryption(&self, transaction: &NxsTransaction<TYPE>) -> bool {
        for entry in &transaction.items {
            match entry {
                // ReceivedNxsItem::NxsSyncGrpItem(item) => ()
                _ => (),
            }
        }

        true
    }

    async fn get_next_transaction_number(&self) -> TransactionId {
        let mut lock = self.last_transaction_number.lock().await;
        *lock += 1;

        *lock
    }

    // this function does return a transaction id, since the received groups must be processed
    #[cfg_attr(feature = "tracing", tracing::instrument)]
    pub async fn request_groups(
        &self,
        group_ids: &Vec<GxsGroupId>,
        peer_id: Arc<PeerId>,
    ) -> TransactionId {
        trace!("requesting groups {group_ids:?}");

        let transaction_id = self.get_next_transaction_number().await;

        let items: Vec<_> = group_ids
            .to_owned()
            .into_iter()
            .map(|group_id| NxsSyncGrpItem {
                base: NxsItem {
                    transaction_id,
                    peer_id: *peer_id.to_owned(),
                },

                flag: NxsSyncGrpItemFlags::Request,
                grp_id: group_id.into(),

                author_id: GxsId::default(),
                publish_ts: u32::default(), // not set when requesting groups
            })
            .map(|group_item| StoredNxsItem::NxsSyncGrpItem(group_item))
            .collect();

        // create new transaction
        let initial_packet = NxsTransactionItem {
            base: NxsItem {
                transaction_id,
                peer_id: *peer_id,
            },
            transact_type: NxsTransactionItemType::GroupListRequest,
            transact_flag: NxsTransactionItemFlags::FlagBegin,
            items: items.len() as u32,
            update_ts: self.shared.gxs_timestamps.get_local_last().await,
            timestamp: 0,
        };
        let transaction_new = NxsTransaction::new_responding(
            transaction_id,
            self.shared.own_id.to_owned(),
            initial_packet.to_owned(),
            items,
        );

        debug!("starting new transaction {transaction_id}: {:?}", transaction_new.initial_packet.transact_type);

        // register transaction
        self.transactions
            .write()
            .await
            .entry(transaction_new.peer_id.to_owned())
            .or_default()
            .insert(transaction_id, transaction_new);

        // send item
        self.send_packet(SUBTYPE_NXS_TRANSACTION_ITEM, &initial_packet, peer_id);

        transaction_id
    }

    pub async fn check_peer_updates(&self, peers: Vec<Arc<PeerId>>) -> Vec<TransactionId> {
        let mut result = vec![];
        for peer_id in peers {
            if let Some(update_ts) = self
                .shared
                .gxs_timestamps
                .get_peer_group(peer_id.to_owned())
                .await
            {
                let transaction_id = self.get_next_transaction_number().await;
                let item = NxsSyncGrpReqItem {
                    base: NxsItem {
                        transaction_id,
                        peer_id: *peer_id.to_owned(),
                    },
                    update_ts,

                    created_since: 0,
                    flag: 0,
                    sync_hash: "".into(),
                };
                self.send_packet(SUBTYPE_NXS_SYNC_GRP_REQ_ITEM, &item, peer_id)
                    ;

                result.push(transaction_id);
            }
        }

        // TODO
        // sync groups messages from peers

        result
    }

    pub async fn tick(&self, _timers: &mut Timers) {
        // handle pending transactions
        self.handle_active_transactions().await;
    }
}
