// use std::net::SocketAddr;
use std::string::String;
use std::sync::{RwLock, RwLockReadGuard, Arc};

use retroshare_compat::basics::*;
use sequoia_openpgp as openpgp;

use crate::model::location::Location;

pub struct Peer {
    name: String,
    pgp_cert: openpgp::Cert,
    pgp_id: PgpId,

    locations: RwLock<Vec<Arc<Location>>>,
}

impl Peer {
    pub fn new(name: String, cert: openpgp::Cert, pgp_id: PgpId) -> Peer {
        Peer {
            name,
            pgp_cert: cert,
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
        &self.pgp_cert
    }

    pub fn get_locations(&self) -> RwLockReadGuard<Vec<Arc<Location>>> {
        self.locations.read().unwrap()
    }

    pub fn add_location(&self, loc: Arc<Location>) {
        // will block!
        self.locations.write().unwrap().push(loc);
    }
}
