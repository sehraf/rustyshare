// use std::net::SocketAddr;
use std::string::String;
use std::sync::{Weak, RwLock, RwLockReadGuard};

use location::Location;
use sequoia_openpgp as openpgp;

pub mod location;
// use crate::error::RsError;
// use crate::model::{DataCore, PeerCommand};
use crate::retroshare_compat::*;
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

    // pub fn send(&mut self, cmd: PeerCommand) -> Result<(), RsError> {
    //     match cmd {
    //         // PeerCommand::Thread(_) => {
    //         //     // pass down the command
    //         //     let mut errors: Vec<RsError> = vec![];
    //         //     for loc in &mut self.locations {
    //         //         match loc.send(cmd) {
    //         //             Err(err) => errors.push(err),
    //         //             _ => {}
    //         //         }
    //         //     }
    //         //     if errors.is_empty() {
    //         //         return Ok(());
    //         //     } else {
    //         //         return Err(RsError::Generic);
    //         //     }
    //         // }
    //         PeerCommand::Thread(_) => {},
    //         PeerCommand::Send(_) => {},
    //         _ => {},
    //     }
    //     Err(RsError::Generic)
    // }

    pub fn get_name(&self) -> &String {
        &self.name
    }

    pub fn get_pgp_id(&self) -> &[u8; 8] {
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
