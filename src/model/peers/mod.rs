// use std::net::SocketAddr;
use std::string::String;
use std::sync::{Weak, RwLock, RwLockReadGuard};

use location::Location;
use sequoia_openpgp as openpgp;
use retroshare_compat::basics::*;

pub mod location;
// use crate::error::RsError;
// use crate::model::{DataCore, PeerCommand};
// use location::Location;

pub struct Peer {
    name: String,
    pgp: openpgp::Cert,

    pgp_id: PgpId,

    locations: RwLock<Vec<Weak<location::Location>>>,
}

impl Peer {
    pub fn new(name: String, cert: openpgp::Cert, pgp_id: PgpId) -> Peer {
        Peer {
            name,
            pgp: cert,
            pgp_id,
            locations: RwLock::new(vec![]),
        }
    }

    pub fn get_name(&self) -> &String {
        &self.name
    }

    pub fn get_pgp_id(&self) -> &PgpId {
        &self.pgp_id
    }

    pub fn get_pgp(&self) -> &openpgp::Cert {
        &self.pgp
    }

    pub fn get_locations(&self) -> RwLockReadGuard<Vec<Weak<location::Location>>> {
        self.locations.read().unwrap()
    }

    pub fn add_location(&self, loc: Weak<Location>) {
        // will block!
        self.locations.write().unwrap().push(loc);
    }
}
