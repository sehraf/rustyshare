use std::{
    collections::{hash_map::Entry, HashMap},
    sync::Arc,
    time::{Duration, SystemTime},
};

use log::{debug, info, trace, warn};
use retroshare_compat::{
    basics::{GxsGroupId, GxsId, PeerId, SslId},
    gxs::{
        sqlite::types::{GxsCircleType, SubscribeFlags},
        NxsGrp, NxsItem, NxsSyncGrpItem, NxsSyncGrpItemFlags, NxsSyncGrpReqItem,
        NxsTransactionItem, NxsTransactionItemFlags, NxsTransactionItemType,
    },
    read_u32,
    serde::{from_retroshare_wire, to_retroshare_wire},
};
use tokio::sync::{Mutex, RwLock};

use crate::{
    gxs::transaction::{NxsTransactionState, StoredNxsItem},
    low_level_parsing::{headers::ServiceHeader, Packet},
    model::{gxs_timestamps::GxsSyncTimeStamps, DataCore},
    utils::{Timer, Timers},
};

use super::transaction::{NxsTransaction, TransactionId};

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

// Object shared between various gxs/nxs components
pub struct NxsShared {
    // FIXME
    core: Arc<DataCore>,

    own_id: Arc<SslId>,

    gxs_timestamps: GxsSyncTimeStamps,
}

impl NxsShared {
    pub fn new(core: Arc<DataCore>) -> Self {
        let own_id = core.get_own_location().get_location_id();
        NxsShared {
            core,
            own_id,
            gxs_timestamps: GxsSyncTimeStamps::new(),
        }
    }
}

const SYNC_SERVER_TS: (&str, Duration) = ("sync server ts", Duration::from_secs(120));

pub struct NxsTransactionController<const T: u16> {
    shared: Arc<NxsShared>,

    #[allow(unused)]
    last_sync: SystemTime,
    last_transaction_number: Mutex<u32>,

    // RS stores them like this, TODO improve?
    transactions: RwLock<HashMap<Arc<PeerId>, HashMap<TransactionId, NxsTransaction<T>>>>,
    transactions_completed: RwLock<Vec<(TransactionId, NxsTransaction<T>)>>,
}

impl<const T: u16> NxsTransactionController<T> {
    pub fn new(shared: Arc<NxsShared>, timers: &mut Timers) -> Self {
        timers.insert(SYNC_SERVER_TS.0.into(), Timer::new(SYNC_SERVER_TS.1));

        Self {
            shared,

            // TODO
            last_sync: SystemTime::now(),
            last_transaction_number: Mutex::new(0),

            transactions: RwLock::new(HashMap::new()),
            transactions_completed: RwLock::new(vec![]),
        }
    }

    pub async fn handle_incoming(&self, header: &ServiceHeader, mut packet: Packet) -> Vec<Packet> {
        let mut packets = vec![];

        // does the packet have a transaction id?
        let transaction_id = read_u32(&mut packet.payload[0..4].to_owned());
        if transaction_id != 0 {
            self.handle_incoming_transaction(header, packet).await;
            return vec![];
        }

        // Assumption:
        // Here are only types that can be answered directly

        match header.sub_type {
            SUBTYPE_NXS_SYNC_GRP_REQ_ITEM => {
                trace!("sync grp req item");
                let data = self.shared.core.get_service_data().gxs_id();

                let item: NxsSyncGrpReqItem = from_retroshare_wire(&mut packet.payload);
                trace!("{item:?}");

                // anything new?
                if self
                    .shared
                    .gxs_timestamps
                    .check_local_last(item.update_ts)
                    .await
                {
                    let transaction_number = self.get_next_transaction_number().await;
                    let meta: Vec<_> = data
                        .database
                        .lock()
                        .await
                        .get_grp_meta(&vec![])
                        .into_iter()
                        // .filter(|entry| entry.publish_ts > item.update_ts as i64) // TODO
                        .filter(|entry| entry.subscribe_flags.contains(SubscribeFlags::SUBSCRIBED))
                        .filter(|entry| {
                            [GxsCircleType::Unknown, GxsCircleType::Public]
                                .contains(&entry.circle_type)
                        })
                        .collect();
                    for entry in meta {
                        let mut item: NxsSyncGrpItem = entry.into();
                        item.base.transaction_id = transaction_number;

                        let payload = to_retroshare_wire(&item);
                        let header =
                            ServiceHeader::new(T.into(), SUBTYPE_NXS_SYNC_GRP_ITEM, &payload);
                        let packet = Packet::new(header.into(), payload, packet.peer_id.to_owned());
                        packets.push(packet);
                    }
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

            // These should always be handled by `handle_incoming_transaction`
            // SUBTYPE_NXS_SYNC_GRP_ITEM => {
            //     // this should be handled in `handle_incoming_transaction` ... right?

            //     warn!("sync grp item");

            //     let item: NxsSyncGrpItem = from_retroshare_wire(&mut packet.payload);
            //     warn!("{item:?}");
            // }
            // SUBTYPE_NXS_GRP_ITEM => {
            //     // this should be handled in `handle_incoming_transaction` ... right?

            //     warn!("grp req item");

            //     let item: NxsGrp<T> = from_retroshare_wire(&mut packet.payload);
            //     warn!("{:?} {}", item.base, item.grp_id);
            // }
            // SUBTYPE_NXS_TRANSAC_ITEM => {
            //     // this should be handled in `handle_incoming_transaction` ... right?
            //     warn!("transaction item");

            //     let item: NxsTransactionItem = from_retroshare_wire(&mut packet.payload);
            //     warn!("{item:?}");
            // }
            sub_type => {
                warn!("[GxsId] received unknown sub typ {sub_type:02X}");
            }
        }

        packets
    }

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

                let item: NxsGrp<T> = from_retroshare_wire(&mut packet.payload);
                trace!("{:?} {}", item.base, item.grp_id);

                // add item to transaction
                let transaction_id = item.base.transaction_id;
                let peer = packet.peer_id.to_owned();

                self.add_item_to_transaction(peer, transaction_id, StoredNxsItem::NxsGrp(item))
                    .await;
            }
            SUBTYPE_NXS_TRANSACTION_ITEM => {
                trace!("transaction item");

                let item: NxsTransactionItem = from_retroshare_wire(&mut packet.payload);
                trace!("{item:?}");

                let transaction_id = item.base.transaction_id;
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
                                        debug!("WaitingConfirm -> Sending {transaction_id}");
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
                                        debug!("WaitingConfirm -> Completed {transaction_id}");
                                        assert!(
                                            entry.get().state
                                                == NxsTransactionState::WaitingConfirm
                                        );
                                        entry.get_mut().state = NxsTransactionState::Completed;
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

    async fn add_item_to_transaction(
        &self,
        peer: Arc<PeerId>,
        transaction_id: TransactionId,
        item: StoredNxsItem<T>,
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

    async fn handle_active_transactions(&self) -> Vec<Packet> {
        let mut packets = vec![];
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
                            for item in transaction.items.drain(..) {
                                debug!("sending part of {id}");

                                let (payload, sub_type) = {
                                    trace!("sending: {item:?}");
                                    match item {
                                        StoredNxsItem::NxsGrp(item) => {
                                            (to_retroshare_wire(&item), SUBTYPE_NXS_GRP_ITEM)
                                        }
                                        StoredNxsItem::NxsSyncGrpItem(item) => {
                                            (to_retroshare_wire(&item), SUBTYPE_NXS_SYNC_GRP_ITEM)
                                        }
                                    }
                                };
                                let header = ServiceHeader::new(T.into(), sub_type, &payload);
                                let packet = Packet::new(
                                    header.into(),
                                    payload,
                                    transaction.peer.to_owned(),
                                );
                                packets.push(packet);
                            }

                            transaction.state = NxsTransactionState::WaitingConfirm;
                        }
                        NxsTransactionState::WaitingConfirm => {
                            // nothing
                            trace!(
                                "WaitingConfirm {id} {:?}",
                                transaction.initial_packet.transact_type
                            );
                        }
                        NxsTransactionState::Completed => {
                            to_remove.push(*id);
                        }
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
                                },
                                items: 0,
                                timestamp: 0,
                                transact_flag: NxsTransactionItemFlags::FlagBeginAck,
                                transact_type: transaction.initial_packet.transact_type.to_owned(),
                                update_ts: 0,
                            };
                            let payload = to_retroshare_wire(&item);
                            let header = ServiceHeader::new(
                                T.into(),
                                SUBTYPE_NXS_TRANSACTION_ITEM,
                                &payload,
                            );
                            packets.push(Packet::new(header.into(), payload, peer_id.to_owned()));

                            transaction.state = NxsTransactionState::Receiving;
                        }
                        NxsTransactionState::Receiving => {
                            if transaction.complete() {
                                debug!("completely received transaction {id}");
                                transaction.state = NxsTransactionState::Completed;

                                // // TODO brought to you by Xeres
                                // self.core
                                //     .get_gxs_timestamps()
                                //     .update_ts_peer(peer_id.to_owned(), self.get_id())
                                //     .await
                            }
                        }
                        NxsTransactionState::Completed => {
                            debug!("finished transaction {id}");
                            let item = NxsTransactionItem {
                                base: NxsItem {
                                    transaction_id: *id,
                                },
                                items: 0,
                                timestamp: 0,
                                transact_flag: NxsTransactionItemFlags::FlagEndSuccess,
                                transact_type: NxsTransactionItemType::None,
                                update_ts: 0,
                            };
                            let payload = to_retroshare_wire(&item);
                            let header = ServiceHeader::new(
                                T.into(),
                                SUBTYPE_NXS_TRANSACTION_ITEM,
                                &payload,
                            );
                            packets.push(Packet::new(header.into(), payload, peer_id.to_owned()));

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
                lock2.push((*id, transactions.remove(id).unwrap()));
            }
        }

        packets
    }

    async fn handle_completed_transactions(&self) -> Vec<Packet> {
        let mut packets = vec![];

        let own_id = &self.shared.own_id;
        let transactions: Vec<_> = self
            .transactions_completed
            .write()
            .await
            .drain(..)
            .collect();

        for (id, transaction) in transactions {
            if *own_id == transaction.peer {
                // our transactions
                unimplemented!()
            } else {
                // remote transactions
                match &transaction.state {
                    NxsTransactionState::Completed => {
                        debug!(
                            "handling completed transaction {id} with type {:?}",
                            transaction.initial_packet.transact_type
                        );
                        match transaction.initial_packet.transact_type {
                            NxsTransactionItemType::TypeGrpListReq => {
                                // peer requested groups
                                if let Some(packet) =
                                    self.send_groups_transaction(transaction).await
                                {
                                    packets.push(packet);
                                }
                            }
                            NxsTransactionItemType::TypeGrps => {
                                let groups: Vec<_> = transaction
                                    .items
                                    .into_iter()
                                    .map(|item| match item {
                                        StoredNxsItem::NxsGrp(grp) => {
                                            info!("received group {}", grp.grp_id);
                                            grp
                                        }
                                        _ => panic!(
                                            "transaction contains unexpected item type! {item:?}"
                                        ),
                                    })
                                    .collect();
                                for group in groups {
                                    self.shared
                                        .core
                                        .get_service_data()
                                        .gxs_id()
                                        .receive_grp(group)
                                        .await;
                                }

                                // update ts for peer
                                let peer = transaction.peer;
                                let time = transaction.initial_packet.timestamp;
                                self.shared
                                    .gxs_timestamps
                                    .update_peer_group(peer, time)
                                    .await;
                            }
                            ty @ _ => {
                                warn!("{:?} unimplemented", ty)
                            }
                        }
                    }
                    NxsTransactionState::Failed => (),
                    state @ _ => {
                        log::error!("unexpected transaction state {state:?}, this is likely a code bug! id: {id}, transaction: {transaction:?}");
                    }
                }
            }
        }

        packets
    }

    async fn send_groups_transaction(&self, transaction: NxsTransaction<T>) -> Option<Packet> {
        let transaction_id = self.get_next_transaction_number().await;

        let peer_id = transaction.peer.to_owned();

        let requested_group_ids: Vec<_> = transaction
            .items
            .into_iter()
            .map(|item| match item {
                StoredNxsItem::NxsSyncGrpItem(item) => {
                    // validate flags, consistency!
                    if item.flag != NxsSyncGrpItemFlags::Request {
                        warn!("send_groups_transaction: item has wrong flags {:?}, expected 'NxsSyncGrpItemFlags::Request'", item.flag);
                    }
                    item.grp_id
                }
                _ => panic!("transaction contains unexpected item type! {item:?}"),
            })
            .collect();

        debug!("peer {} requested groups", peer_id);
        trace!("{requested_group_ids:?}");

        let items: Vec<_> = self
            .shared
            .core
            .get_service_data()
            .gxs_id()
            .get_nxs_groups::<T>(&requested_group_ids, transaction_id)
            .await
            .into_iter()
            .map(|(_id, grp)| {
                // // XXX
                // {
                //     let tmp = GxsGrpMetaSql::from_nxs(&mut grp.meta.to_owned());

                //     warn!("{}", tmp.group_id);
                //     warn!("{:04x}", tmp.sign_flags);
                //     warn!("{:?}", tmp.keys.public_keys);
                //     for key in tmp.keys.public_keys {
                //         warn!("key_flags: {:04x}", key.key_flags);
                //     }
                // }
                // {
                //     use crate::low_level_parsing::headers::Header;
                //     use retroshare_compat::{foo::GxsIdGroupItem, services::ServiceType};

                //     let mut copy = grp.grp.to_owned();
                //     let mut header: [u8; 8] = [0; 8];
                //     header.copy_from_slice(copy.drain(0..8).as_slice());
                //     let header = Header::try_parse(&header).unwrap();
                //     match header {
                //         Header::Service {
                //             service,
                //             sub_type,
                //             size,
                //         } => {
                //             assert_eq!(service, ServiceType::GxsId);
                //             assert_eq!(sub_type, 0x02);

                //             let item: GxsIdGroupItem = from_retroshare_wire(&mut copy);

                //             warn!("{item:?}");
                //         }
                //         _ => unreachable!(),
                //     }
                // }
                StoredNxsItem::NxsGrp(grp)
            })
            .collect();
        trace!("{items:?}");

        if items.is_empty() {
            debug!("no requested groups were locally found");

            // Is this correct?
            // from void RsGxsNetService::locked_genReqGrpTransaction(NxsTransaction* tr)
            self.shared
                .gxs_timestamps
                .update_peer_group(peer_id, transaction.initial_packet.update_ts)
                .await;

            return None;
        }

        // create new transaction
        let update_ts = self.shared.gxs_timestamps.get_local_last().await;
        let initial_packet = NxsTransactionItem {
            base: NxsItem { transaction_id },
            transact_type: NxsTransactionItemType::TypeGrps,
            transact_flag: NxsTransactionItemFlags::FlagBegin,
            items: items.len() as u32,
            update_ts,
            timestamp: 0,
        };
        let transaction_new = NxsTransaction::new_responding(
            transaction_id,
            peer_id.to_owned(),
            initial_packet.to_owned(),
            items,
        );

        // register transaction
        self.transactions
            .write()
            .await
            .entry(self.shared.own_id.to_owned())
            .or_default()
            .insert(transaction_id, transaction_new);

        // send item
        let payload = to_retroshare_wire(&initial_packet);
        let header = ServiceHeader::new(T.into(), SUBTYPE_NXS_TRANSACTION_ITEM, &payload);
        let packet = Packet::new(header.into(), payload, peer_id.to_owned());

        Some(packet)
    }

    async fn process_transaction_for_decryption(&self, transaction: &NxsTransaction<T>) -> bool {
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

    pub async fn request_groups(&self, grp_ids: Vec<GxsGroupId>) -> Vec<Packet> {
        trace!("requesting groups {grp_ids:?}");

        // ask all online peers
        let peers: Vec<_> = self
            .shared
            .core
            .get_connected_peers()
            .lock()
            .await
            .0
            .keys()
            .map(|peer| peer.to_owned())
            .collect();

        let mut packets = vec![];
        for peer_id in peers {
            let transaction_id = self.get_next_transaction_number().await;

            let items: Vec<_> = grp_ids
                .to_owned()
                .into_iter()
                .map(|grp| NxsSyncGrpItem {
                    base: NxsItem { transaction_id },

                    flag: NxsSyncGrpItemFlags::Request,
                    grp_id: grp.into(),

                    author_id: GxsId::default(),
                    publish_ts: 0,
                })
                .map(|grp| StoredNxsItem::NxsSyncGrpItem(grp))
                .collect();

            // create new transaction
            let initial_packet = NxsTransactionItem {
                base: NxsItem { transaction_id },
                transact_type: NxsTransactionItemType::TypeGrpListReq,
                transact_flag: NxsTransactionItemFlags::FlagBegin,
                items: items.len() as u32,
                update_ts: 0, // FIXME
                timestamp: 0,
            };
            let transaction_new = NxsTransaction::new_responding(
                transaction_id,
                peer_id.to_owned(), // FIXME
                initial_packet.to_owned(),
                items,
            );

            // register transaction
            self.transactions
                .write()
                .await
                .entry(self.shared.own_id.to_owned())
                .or_default()
                .insert(transaction_id, transaction_new);

            // send item
            let payload = to_retroshare_wire(&initial_packet);
            let header = ServiceHeader::new(T.into(), SUBTYPE_NXS_TRANSACTION_ITEM, &payload);
            let packet = Packet::new(header.into(), payload, peer_id.to_owned());

            packets.push(packet);
        }

        packets
    }

    async fn sync_server_ts(&self) {
        let mut times: Vec<i64> = self
            .shared
            .core
            .get_service_data()
            .gxs_id()
            .database
            .lock()
            .await
            .get_grp_meta(&vec![])
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

    pub async fn check_peer_updates(&self, peers: Vec<Arc<PeerId>>) -> Vec<Packet> {
        let mut packets = vec![];

        for peer_id in peers {
            if let Some(update_ts) = self
                .shared
                .gxs_timestamps
                .get_peer_group(peer_id.to_owned())
                .await
            {
                let transaction_id = self.get_next_transaction_number().await;
                let item = NxsSyncGrpReqItem {
                    base: NxsItem { transaction_id },
                    update_ts,

                    created_since: 0,
                    flag: 0,
                    sync_hash: "".into(),
                };
                let payload = to_retroshare_wire(&item);
                let header = ServiceHeader::new(T.into(), SUBTYPE_NXS_SYNC_GRP_REQ_ITEM, &payload);
                let packet = Packet::new(header.into(), payload, peer_id);

                packets.push(packet);
            }
        }

        // TODO
        // sync groups messages from peers

        packets
    }

    pub async fn tick(&self, timers: &mut Timers) -> Vec<Packet> {
        let mut packets = vec![];

        if timers
            .get_mut(&SYNC_SERVER_TS.0.to_string())
            .unwrap()
            .expired()
        {
            self.sync_server_ts().await;
        }

        // handle pending transactions
        packets.extend(self.handle_active_transactions().await);

        // handle completed transactions
        packets.extend(self.handle_completed_transactions().await);

        packets
    }
}
