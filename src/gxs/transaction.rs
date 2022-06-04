use std::{
    sync::Arc,
    time::{Duration, SystemTime},
};

use retroshare_compat::{
    basics::SslId,
    gxs::{NxsGrp, NxsSyncGrpItem, NxsTransactionItem},
};

#[allow(unused)]
const SYNC_PERIOD: u32 = 60;
#[allow(unused)]
const MAX_REQLIST_SIZE: u32 = 20; // No more than 20 items per msg request list => creates smaller transactions that are less likely to be cancelled.
const TRANSAC_TIMEOUT: u32 = 2000; // In seconds. Has been increased to avoid epidemic transaction cancelling due to overloaded outqueues.

pub type TransactionId = u32;

#[derive(Debug)]
pub enum StoredNxsItem<const T: u16> {
    NxsSyncGrpItem(NxsSyncGrpItem),
    NxsGrp(NxsGrp<T>),
}

#[derive(Debug, PartialEq)]
pub enum NxsTransactionState {
    Starting,  // when
    Receiving, // begin receiving items for incoming trans
    Sending,   // begin sending items for outgoing trans
    Completed,
    Failed,
    WaitingConfirm,
}

#[derive(Debug)]
pub struct NxsTransaction<const T: u16> {
    pub transaction_id: TransactionId,
    pub peer: Arc<SslId>,

    pub state: NxsTransactionState,
    pub initial_packet: NxsTransactionItem,
    // RS stores the raw packet and serializes it again when required - try to avoid this by storing the already serialized packet instead
    pub items: Vec<StoredNxsItem<T>>,

    pub timeout: SystemTime,
}

impl<const T: u16> NxsTransaction<T> {
    pub fn new_starting(
        transaction_id: TransactionId,
        peer: Arc<SslId>,
        initial_packet: NxsTransactionItem,
    ) -> Self {
        NxsTransaction {
            transaction_id,
            peer,

            state: NxsTransactionState::Starting,
            initial_packet,
            items: vec![],

            timeout: SystemTime::now()
                .checked_add(Duration::from_secs(TRANSAC_TIMEOUT as u64))
                .unwrap(),
        }
    }

    pub fn new_responding(
        transaction_id: TransactionId,
        peer: Arc<SslId>,
        initial_packet: NxsTransactionItem,
        items: Vec<StoredNxsItem<T>>,
    ) -> Self {
        NxsTransaction {
            transaction_id,
            peer,

            state: NxsTransactionState::WaitingConfirm,
            initial_packet,
            items,

            timeout: SystemTime::now()
                .checked_add(Duration::from_secs(TRANSAC_TIMEOUT as u64))
                .unwrap(),
        }
    }

    pub fn timeout(&self) -> bool {
        self.timeout < SystemTime::now()
    }

    pub fn complete(&self) -> bool {
        self.initial_packet.items as usize == self.items.len()
    }
}
