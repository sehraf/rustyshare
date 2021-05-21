use retroshare_compat::{basics::*, tlv::TlvIpAddressInfo};
use std::{
    collections::HashSet,
    net::SocketAddr,
    sync::{RwLock, RwLockReadGuard, RwLockWriteGuard, Weak},
    time::{Duration, Instant},
};

use crate::model::{peers::Peer, PeerState};

const PEER_CONNECTION_TRY_DURATION: Duration = Duration::from_secs(60 * 5);

// FIXME use Mutex instead of RwLock
#[allow(dead_code)]
pub struct Location {
    peer: PgpId,

    name: String,
    ssl_id: PeerId,

    ips_local: RwLock<HashSet<TlvIpAddressInfo>>,
    ips_external: RwLock<HashSet<TlvIpAddressInfo>>,

    ip_connected: RwLock<Option<SocketAddr>>,
    last_connection_attempt: RwLock<Instant>,
    person: Weak<Peer>,
}

impl Location {
    pub fn new(
        location: String,
        location_id: PeerId,
        peer_id: PgpId,
        ips: (HashSet<TlvIpAddressInfo>, HashSet<TlvIpAddressInfo>),
        person: Weak<Peer>,
    ) -> Location {
        Location {
            name: location,

            ssl_id: location_id,
            peer: peer_id,

            ips_local: RwLock::new(ips.0),
            ips_external: RwLock::new(ips.1),

            ip_connected: RwLock::new(None),
            last_connection_attempt: RwLock::new(
                Instant::now()
                    .checked_sub(PEER_CONNECTION_TRY_DURATION)
                    .unwrap(),
            ),
            person,
        }
    }

    pub fn get_ips(
        &self,
    ) -> (
        RwLockReadGuard<HashSet<TlvIpAddressInfo>>,
        RwLockReadGuard<HashSet<TlvIpAddressInfo>>,
    ) {
        let local = self.ips_local.read().unwrap();
        let external = self.ips_external.read().unwrap();

        (local, external)
    }

    pub fn get_ips_rw(
        &self,
    ) -> (
        RwLockWriteGuard<HashSet<TlvIpAddressInfo>>,
        RwLockWriteGuard<HashSet<TlvIpAddressInfo>>,
    ) {
        let local = self.ips_local.write().unwrap();
        let external = self.ips_external.write().unwrap();

        (local, external)
    }

    pub fn get_name(&self) -> &String {
        &self.name
    }

    pub fn get_location_id(&self) -> &PeerId {
        &self.ssl_id
    }

    pub fn get_person(&self) -> Weak<Peer> {
        self.person.clone()
    }

    pub fn try_reconnect(&self) -> bool {

        if self.ip_connected.read().expect("failed to get read lock").is_some() {
            return false;
        }

        let result =
            self.last_connection_attempt.read().expect("failed to get read lock").elapsed() > PEER_CONNECTION_TRY_DURATION;

        if result {
            *self.last_connection_attempt.write().expect("failed to get write lock") = Instant::now();
        }

        result
    }

    pub fn set_status(&self, state: &PeerState) {
        match state {
            &PeerState::Connected(loc, addr) => {
                assert_eq!(
                    loc, self.ssl_id,
                    "got an update for a different ssl id! This looks like a serious bug!"
                );
                *self.ip_connected.write().unwrap() = Some(addr);
            }
            &PeerState::NotConnected(loc) => {
                assert_eq!(
                    loc, self.ssl_id,
                    "got an update for a different ssl id! This looks like a serious bug!"
                );
                *self.ip_connected.write().unwrap() = None;
            }
        }
    }

    pub fn is_connected(&self) -> bool {
        self.ip_connected.read().expect("failed to read ip value").is_some()
    }
}
