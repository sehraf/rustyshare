use std::{
    net::SocketAddr,
    sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard},
    time::{Duration, Instant},
};

use retroshare_compat::{basics::*, peers::PeerDetails, tlv::TlvIpAddressInfo};

use crate::model::{person::Peer, intercom::PeerState};

const PEER_CONNECTION_TRY_DURATION: Duration = Duration::from_secs(60 * 5);

// FIXME use Mutex instead of RwLock
#[allow(dead_code)]
pub struct Location {
    peer: Arc<PgpId>,

    name: String,
    ssl_id: Arc<SslId>,

    ips_local: RwLock<Vec<TlvIpAddressInfo>>,
    ips_external: RwLock<Vec<TlvIpAddressInfo>>,

    ip_connected: RwLock<Option<SocketAddr>>,
    last_connection_attempt: RwLock<Instant>,
    person: Arc<Peer>,
}

impl Location {
    pub fn new(
        location: String,
        location_id: Arc<SslId>,
        peer_id: Arc<PgpId>,
        ips: (Vec<TlvIpAddressInfo>, Vec<TlvIpAddressInfo>),
        person: Arc<Peer>,
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
        RwLockReadGuard<Vec<TlvIpAddressInfo>>,
        RwLockReadGuard<Vec<TlvIpAddressInfo>>,
    ) {
        let local = self.ips_local.read().unwrap();
        let external = self.ips_external.read().unwrap();

        (local, external)
    }

    pub fn get_ips_mut(
        &self,
    ) -> (
        RwLockWriteGuard<Vec<TlvIpAddressInfo>>,
        RwLockWriteGuard<Vec<TlvIpAddressInfo>>,
    ) {
        let local = self.ips_local.write().unwrap();
        let external = self.ips_external.write().unwrap();

        (local, external)
    }

    pub fn get_name(&self) -> &String {
        &self.name
    }

    pub fn get_location_id(&self) -> Arc<SslId> {
        self.ssl_id.to_owned()
    }

    pub fn get_person(&self) -> Arc<Peer> {
        self.person.clone()
    }

    pub fn try_reconnect(&self) -> bool {
        if self
            .ip_connected
            .read()
            .expect("failed to get read lock")
            .is_some()
        {
            return false;
        }

        let result = self
            .last_connection_attempt
            .read()
            .expect("failed to get read lock")
            .elapsed()
            > PEER_CONNECTION_TRY_DURATION;

        if result {
            *self
                .last_connection_attempt
                .write()
                .expect("failed to get write lock") = Instant::now();
        }

        result
    }

    pub fn set_status(&self, state: &PeerState) {
        match state {
            PeerState::Connected(loc, addr) => {
                assert_eq!(
                    *loc, self.ssl_id,
                    "got an update for a different ssl id! This looks like a serious bug!"
                );
                *self.ip_connected.write().unwrap() = Some(*addr);
            }
            PeerState::NotConnected(loc) => {
                assert_eq!(
                    *loc, self.ssl_id,
                    "got an update for a different ssl id! This looks like a serious bug!"
                );
                *self.ip_connected.write().unwrap() = None;
            }
        }
    }

    pub fn is_connected(&self) -> bool {
        self.ip_connected
            .read()
            .expect("failed to read ip value")
            .is_some()
    }

    pub fn get_peer_details(&self) -> PeerDetails {
        let peer = self.get_person();

        PeerDetails {
            // is_only_gpg_detail: bool,
            id: *self.ssl_id.to_owned(),

            pgp_id: *self.peer.to_owned(),

            name: peer.get_name().to_owned(),
            // email: self,
            location: self.name.to_owned(),
            // org: String,
            issuer: *self.peer.to_owned(),
            fpr: peer.get_pgp().fingerprint().as_bytes().to_owned().into(),
            // gpg_signers: Vec<PgpId>,
            ..Default::default()
        }
    }
}
