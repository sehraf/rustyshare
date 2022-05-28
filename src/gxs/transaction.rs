use std::{
    sync::Arc,
    time::{Duration, SystemTime},
};

use retroshare_compat::{basics::SslId, gxs::NxsTransacItem};

use crate::low_level_parsing::Packet;

const SYNC_PERIOD: u32 = 60;
const MAX_REQLIST_SIZE: u32 = 20; // No more than 20 items per msg request list => creates smaller transactions that are less likely to be cancelled.
const TRANSAC_TIMEOUT: u32 = 2000; // In seconds. Has been increased to avoid epidemic transaction cancelling due to overloaded outqueues.

pub type TransactionId = u32;

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
pub struct NxsTransaction {
    pub transaction_id: TransactionId,
    pub peer: Arc<SslId>,

    pub state: NxsTransactionState,
    pub initial_packet: NxsTransacItem,
    pub received_items: Vec<Packet>,

    pub timeout: SystemTime,
}

impl NxsTransaction {
    pub fn new(
        transaction_id: TransactionId,
        peer: Arc<SslId>,
        initial_packet: NxsTransacItem,
    ) -> Self {
        NxsTransaction {
            transaction_id,
            peer,

            state: NxsTransactionState::Starting,
            initial_packet,
            received_items: vec![],

            timeout: SystemTime::now()
                .checked_add(Duration::from_secs(TRANSAC_TIMEOUT as u64))
                .unwrap(),
        }
    }
}
