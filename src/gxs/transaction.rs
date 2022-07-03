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
const TRANSACTION_TIMEOUT: u32 = 2000; // 2000; // In seconds. Has been increased to avoid epidemic transaction cancelling due to overloaded outqueues.

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
    pub peer_id: Arc<SslId>,

    pub state: NxsTransactionState,
    pub initial_packet: NxsTransactionItem,
    // RS stores the raw packet and serializes it again when required - try to avoid this by storing the already serialized packet instead
    pub items: Vec<StoredNxsItem<T>>,

    pub timeout: SystemTime,

    finished: bool,
}

impl<const T: u16> NxsTransaction<T> {
    pub fn new_starting(
        transaction_id: TransactionId,
        peer: Arc<SslId>,
        initial_packet: NxsTransactionItem,
    ) -> Self {
        NxsTransaction {
            transaction_id,
            peer_id: peer,

            state: NxsTransactionState::Starting,
            initial_packet,
            items: vec![],

            timeout: SystemTime::now()
                .checked_add(Duration::from_secs(TRANSACTION_TIMEOUT as u64))
                .unwrap(),

            /// This is used for debugging to verify that each transaction runs through everything necessary (and e.g. does not get dropped too early at some point)
            finished: false,
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
            peer_id: peer,

            state: NxsTransactionState::WaitingConfirm,
            initial_packet,
            items,

            timeout: SystemTime::now()
                .checked_add(Duration::from_secs(TRANSACTION_TIMEOUT as u64))
                .unwrap(),

            finished: false,
        }
    }

    pub fn timeout(&self) -> bool {
        self.timeout < SystemTime::now()
    }

    pub fn complete(&self) -> bool {
        self.initial_packet.items as usize == self.items.len()
    }

    pub fn mark_finished(&mut self) {
        if self.finished {
            log::error!("already finished! {}", self.transaction_id);
        }
        self.finished = true;
    }

    pub fn check_finished(&self) {
        if !self.finished {
            log::error!("NOT finished! {}", self.transaction_id);
        }
    }

    // pub fn equivalent(&self, other: &Self) -> bool {
    //     for entry in &self.items {
    //         if !other.items.contains(entry) {
    //             return false;
    //         }
    //     }

    //     true
    // }
}
