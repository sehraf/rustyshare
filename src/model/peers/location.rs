use std::{
    net::SocketAddr,
    sync::RwLockReadGuard,
    sync::{RwLock, Weak},
};

use crate::{model::peers::Peer, retroshare_compat::*};

#[allow(dead_code)]
pub struct Location {
    peer: PeerId,

    name: String,
    ssl_id: SslId,
    ips: RwLock<Vec<SocketAddr>>,
    person: Weak<Peer>,
}

impl Location {
    pub fn new(
        location: String,
        location_id: SslId,
        peer_id: PeerId,
        ips: Vec<SocketAddr>,
        person: Weak<Peer>,
    ) -> Location {
        Location {
            name: location,
            ssl_id: location_id,
            peer: peer_id,
            ips: RwLock::new(ips),
            person,
        }
    }

    pub fn get_ips(&self) -> RwLockReadGuard<Vec<SocketAddr>> {
        self.ips.read().unwrap()
    }

    pub fn get_name(&self) -> &String {
        &self.name
    }

    pub fn get_location_id(&self) -> &LocationId {
        &self.ssl_id
    }

    pub fn get_person(&self) -> Weak<Peer> {
        self.person.clone()
    }
}
