use std::{
    collections::{hash_map::Entry, HashMap},
    sync::Arc,
    time::{Duration, SystemTime},
};

use async_trait::async_trait;
use log::{debug, trace, warn};
use retroshare_compat::{
    basics::PeerId,
    gxs::{
        NxsGrp, NxsItem, NxsSyncGrpItem, NxsSyncGrpReqItem, NxsTransacItem, NxsTransacItemFlags,
        NxsTransacItemType,
    },
    serde::{from_retroshare_wire, to_retroshare_wire},
};
use tokio::sync::{mpsc::UnboundedSender, Mutex, RwLock};

use crate::{
    gxs::transaction::{NxsTransaction, NxsTransactionState, TransactionId},
    handle_packet,
    low_level_parsing::{headers::ServiceHeader, Packet},
    model::{intercom::Intercom, DataCore},
    services::{HandlePacketResult, Service, SERVICE_GXS_GXSID},
    utils::{simple_stats::StatsCollection, Timers},
};

use super::ServiceType;

const SUBTYPE_NXS_SYNC_GRP_REQ_ITEM: u8 = 0x01;
const SUBTYPE_NXS_SYNC_GRP_ITEM: u8 = 0x02;
const SUBTYPE_NXS_SYNC_GRP_STATS_ITEM: u8 = 0x03;
const SUBTYPE_NXS_GRP_ITEM: u8 = 0x04;
const SUBTYPE_NXS_ENCRYPTED_DATA_ITEM: u8 = 0x05;
const SUBTYPE_NXS_SESSION_KEY_ITEM: u8 = 0x06;
const SUBTYPE_NXS_SYNC_MSG_ITEM: u8 = 0x08;
const SUBTYPE_NXS_SYNC_MSG_REQ_ITEM: u8 = 0x10;
const SUBTYPE_NXS_MSG_ITEM: u8 = 0x20;
const SUBTYPE_NXS_TRANSAC_ITEM: u8 = 0x40;
const SUBTYPE_NXS_GRP_PUBLISH_KEY_ITEM: u8 = 0x80;
const SUBTYPE_NXS_SYNC_PULL_REQUEST_ITEM: u8 = 0x90;

type NxsGrpGxsId = NxsGrp<SERVICE_GXS_GXSID>;

// const HANDLE_TRANSACTIONS: (&str, Duration) = ("handle")

pub struct GxsId {
    core: Arc<DataCore>,
    core_tx: UnboundedSender<Intercom>,

    last_sync: SystemTime,
    last_transaction_nubmer: Mutex<u32>,

    // RS stores them like this, TODO improve?
    transactions: RwLock<HashMap<Arc<PeerId>, HashMap<TransactionId, NxsTransaction>>>,
    transactions_completed: RwLock<Vec<(TransactionId, NxsTransaction)>>,
}

impl GxsId {
    pub async fn new(
        core: &Arc<DataCore>,
        core_tx: UnboundedSender<Intercom>,
        _timers: &mut Timers,
    ) -> Self {
        GxsId {
            core: core.to_owned(),
            core_tx,

            // TODO
            last_sync: SystemTime::now(),
            last_transaction_nubmer: Mutex::new(0),

            transactions: RwLock::new(HashMap::new()),
            transactions_completed: RwLock::new(vec![]),
        }
    }

    async fn handle_incoming(
        &self,
        header: &ServiceHeader,
        mut packet: Packet,
    ) -> HandlePacketResult {
        match header.sub_type {
            SUBTYPE_NXS_SYNC_GRP_REQ_ITEM => {
                trace!("sync grp req item");
                let data = self.core.get_service_data().gxs_id();

                let item: NxsSyncGrpReqItem = from_retroshare_wire(&mut packet.payload);
                trace!("{item:?}");

                if item.update_ts
                    >= self
                        .last_sync
                        .duration_since(SystemTime::UNIX_EPOCH)
                        .unwrap()
                        .as_secs() as u32
                {
                    return handle_packet!();
                }

                let transaction_number = self.get_next_transaction_number().await;
                let meta: Vec<_> = data
                    .database
                    .lock()
                    .await
                    .get_meta()
                    .into_iter()
                    .filter(|entry| (entry.subscribe_flags & 0x04) > 0) // FIXME
                    .filter(|entry| [0, 1].contains(&entry.circle_type)) // FIXME RsGxsNetService::canSendGrpId
                    .collect();
                for entry in meta {
                    let mut item: NxsSyncGrpItem = entry.into();
                    item.base.transaction_number = transaction_number;

                    let payload = to_retroshare_wire(&item);
                    let header =
                        ServiceHeader::new(ServiceType::GxsId, SUBTYPE_NXS_SYNC_GRP_ITEM, &payload);
                    let packet = Packet::new(header.into(), payload, packet.peer_id.to_owned());
                    self.core_tx
                        .send(Intercom::Send(packet))
                        .expect("failed to sent to core");
                }
            }
            SUBTYPE_NXS_SYNC_GRP_ITEM => {
                trace!("sync grp item");

                let item: NxsSyncGrpItem = from_retroshare_wire(&mut packet.payload);
                trace!("{item:?}");
            },
            // SUBTYPE_NXS_SYNC_GRP_STATS_ITEM => (),
            SUBTYPE_NXS_GRP_ITEM => {
                trace!("grp req item");

                let item: NxsGrpGxsId = from_retroshare_wire(&mut packet.payload);
                trace!("{item:?}");
            }
            // SUBTYPE_NXS_ENCRYPTED_DATA_ITEM => (),
            // SUBTYPE_NXS_SESSION_KEY_ITEM => (),
            // SUBTYPE_NXS_SYNC_MSG_ITEM => (),
            // SUBTYPE_NXS_SYNC_MSG_REQ_ITEM => (),
            // SUBTYPE_NXS_MSG_ITEM => (),
            SUBTYPE_NXS_TRANSAC_ITEM => {
                trace!("transac item");

                let item: NxsTransacItem = from_retroshare_wire(&mut packet.payload);
                trace!("{item:?}");

                let transaction_id = item.base.transaction_number;
                let peer = &packet.peer_id;
                match item.transact_flag {
                    NxsTransacItemFlags::FlagBeginP1 => {
                        // remote started transaction

                        let mut lock = self.transactions.write().await;
                        match lock
                            .entry(peer.to_owned())
                            .or_insert(HashMap::new())
                            .entry(transaction_id)
                        {
                            Entry::Occupied(entry) => {
                                warn!("received (incoming) transaction start but there is already an entry: {entry:?}!");
                                return handle_packet!();
                            }
                            Entry::Vacant(entry) => {
                                entry.insert(NxsTransaction::new(
                                    transaction_id,
                                    peer.to_owned(),
                                    item,
                                ));
                            }
                        }
                    }
                    NxsTransacItemFlags::FlagBeginP2 => {
                        // we started a transaction

                        let mut lock = self.transactions.write().await;
                        match lock
                            .entry(peer.to_owned())
                            .or_insert(HashMap::new())
                            .entry(transaction_id)
                        {
                            Entry::Occupied(mut entry) => {
                                assert!(entry.get().state == NxsTransactionState::Starting);
                                entry.get_mut().state = NxsTransactionState::Sending;
                            }
                            Entry::Vacant(_entry) => {
                                warn!(
                                    "received (outgoing) transaction start but there is no entry!"
                                );
                                return handle_packet!();
                            }
                        }
                    }
                    state @ _ => {
                        // RS doesn't handle any other state here
                        warn!("unexpected state {state:?}");
                        return handle_packet!();
                    }
                }
            }
            // SUBTYPE_NXS_GRP_PUBLISH_KEY_ITEM => (),
            // SUBTYPE_NXS_SYNC_PULL_REQUEST_ITEM => (),
            sub_type => {
                warn!("[GxsId] recevied unknown sub typ {sub_type:02X}");
            }
        }

        handle_packet!()
    }

    async fn get_next_transaction_number(&self) -> u32 {
        let mut lock = self.last_transaction_nubmer.lock().await;
        *lock += 1;

        *lock
    }

    async fn handle_tansactions(&mut self) -> Vec<Packet> {
        let mut packets = vec![];

        let mut to_remove = vec![];

        let mut lock = self.transactions.write().await;
        let own_id = &self.core.get_own_location().get_location_id();
        for (peer, transactions) in lock.iter_mut() {
            to_remove.clear();

            transactions.iter_mut().for_each(|(id, transaction)| {
                if transaction.timeout < SystemTime::now() {
                    debug!("trancation {id} timed out!");
                    transaction.state = NxsTransactionState::Failed;
                    to_remove.push(*id);
                }
            });

            if own_id == peer {
                // our transactions
                unimplemented!()
            } else {
                // remote transactions
                for (id, transaction) in transactions.iter_mut() {
                    match &transaction.state {
                        NxsTransactionState::Receiving => {
                            if transaction.initial_packet.items as usize
                                == transaction.received_items.len()
                            {
                                debug!("completly received transaction {id}");
                                transaction.state = NxsTransactionState::Completed;
                            }
                        }
                        NxsTransactionState::Completed => {
                            debug!("finished transaction {id}");
                            let item = NxsTransacItem {
                                base: NxsItem {
                                    transaction_number: *id,
                                },
                                items: 0,
                                timestamp: 0,
                                transact_flag: NxsTransacItemFlags::FlagEndSuccess,
                                transact_type: NxsTransacItemType::None,
                                update_ts: 0,
                            };
                            let payload = to_retroshare_wire(&item);
                            let header = ServiceHeader::new(
                                ServiceType::GxsId,
                                SUBTYPE_NXS_TRANSAC_ITEM,
                                &payload,
                            );
                            packets.push(Packet::new(header.into(), payload, peer.to_owned()));

                            // TODO  if(processTransactionForDecryption(tr))
                        }
                        NxsTransactionState::Starting => {
                            debug!("ready to start transaction {id}");
                            let item = NxsTransacItem {
                                base: NxsItem {
                                    transaction_number: *id,
                                },
                                items: 0,
                                timestamp: 0,
                                transact_flag: NxsTransacItemFlags::FlagBeginP2,
                                transact_type: transaction.initial_packet.transact_type.to_owned(),
                                update_ts: 0,
                            };
                            let payload = to_retroshare_wire(&item);
                            let header = ServiceHeader::new(
                                ServiceType::GxsId,
                                SUBTYPE_NXS_TRANSAC_ITEM,
                                &payload,
                            );
                            packets.push(Packet::new(header.into(), payload, peer.to_owned()));

                            transaction.state = NxsTransactionState::Receiving;
                        }
                        state @ _ => {
                            warn!("unkown transaction state {state:?} for {id}, canceling!");
                            transaction.state = NxsTransactionState::Failed;
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
        _timers: &mut Timers,
    ) -> Option<Vec<Packet>> {
        let packets = self.handle_tansactions().await;

        if packets.is_empty() {
            return None;
        }
        Some(packets)
    }

    fn get_service_info(&self) -> (String, u16, u16, u16, u16) {
        (String::from("gxsid"), 1, 0, 1, 0)
    }
}
