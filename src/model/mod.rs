use std::{
    collections::HashSet,
    net::{SocketAddr, TcpStream},
    sync::{mpsc, Arc},
    // task::Context,
};

// use native_tls::Identity;
// use openssl::{pkey, x509};
// use sequoia_openpgp as openpgp;
use retroshare_compat::{basics::*, service_info::RsServiceInfo, tlv::TlvIpAddressInfo};

pub mod peers;
use peers::{location::Location, Peer};

use crate::{
    parser::Packet,
    retroshare_compat::ssl_key::SslKey,
    services::*,
    transport::{
        connection::PeerConnection, tcp_openssl::ConTcpOpenssl, ConnectionType, RsPeerConnection,
    },
    utils::simple_stats::StatsCollection,
};

#[derive(Debug)]
pub enum PeerCommand {
    Thread(PeerThreadCommand),
    PeerUpdate(PeerUpdate),
    ServiceInfoUpdate(Vec<RsServiceInfo>),
    Send(Packet),
    Receive(Packet),
}

#[derive(Debug)]
#[allow(dead_code)]
pub enum PeerThreadCommand {
    Start,
    Stop,
    TryConnect,
    Incoming(TcpStream),
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub enum PeerUpdate {
    Status(PeerState),
    Address(PeerId, HashSet<TlvIpAddressInfo>, HashSet<TlvIpAddressInfo>),
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub enum PeerState {
    Connected(PeerId, SocketAddr),
    NotConnected(PeerId),
}

pub struct DataCore {
    own_key_pair: SslKey,
    // identity: Identity,
    own_location: PeerId,
    own_location_obj: Arc<Location>, // stored for faster access

    services: Services,

    rx: mpsc::Receiver<PeerCommand>,
    tx: mpsc::Sender<PeerCommand>,

    event_listener: Vec<mpsc::Sender<PeerCommand>>,

    #[allow(dead_code)]
    peers: Vec<Arc<Peer>>,
    locations: Vec<Arc<Location>>,

    // TODO one vec is probably enough
    bootup: Vec<(
        PeerId,
        mpsc::Sender<PeerCommand>,
        std::thread::JoinHandle<()>,
    )>,
    worker: Vec<(
        PeerId,
        mpsc::Sender<PeerCommand>,
        std::thread::JoinHandle<()>,
    )>,

    sick: bool,
}

impl DataCore {
    pub fn new(
        keys: SslKey,
        // identity: Identity,
        friends: (Vec<Arc<Peer>>, Vec<Arc<Location>>),
        peer_id: &PeerId,
    ) -> DataCore {
        let (tx, rx) = mpsc::channel();
        // let keys = Arc::new((pub_key, priv_key));

        // find own locations
        let me = friends
            .1
            .iter()
            .find(|&loc| loc.get_location_id() == peer_id)
            .expect("can't find own location!");

        let mut dc = DataCore {
            own_key_pair: keys,
            // identity,
            own_location: peer_id.clone(),
            own_location_obj: me.clone(),

            services: Services::new(),

            peers: friends.0,
            locations: friends.1,
            rx,
            tx,

            event_listener: vec![],

            bootup: vec![],
            worker: vec![],

            sick: false,
        };

        dc.services = Services::get_core_services(&mut dc);

        dc
    }

    fn connect(&mut self, loc: &Arc<Location>) {
        // this is usefull for debugging but not should be disabled on release builds
        // #[cfg(debug_assertions)]
        if loc.get_location_id() == &self.own_location {
            return;
        }

        // copy everything
        let keys = self.own_key_pair.to_owned();
        // let identity = self.identity.to_owned();
        let outer_tx = self.tx.to_owned();
        let (handler_tx, inner_rx) = mpsc::channel();

        // turn IPs into ConnectionType::Tcp
        let ips = loc.get_ips();
        let mut local: Vec<ConnectionType> = ips
            .0
            .iter()
            .map(|val| ConnectionType::Tcp(val.addr.0))
            .collect();
        let mut external: Vec<ConnectionType> = ips
            .1
            .iter()
            .map(|val| ConnectionType::Tcp(val.addr.0))
            .collect();
        local.append(&mut external);
        let ips = local;

        // let ips: Vec<ConnectionType> =
        //     ips.iter().map(|&val| ConnectionType::Tcp(val)).collect();

        let loc_id = loc.get_location_id().to_owned();
        let loc_key = loc.get_person().upgrade().unwrap().get_pgp().to_owned();

        let handler = std::thread::spawn(move || {
            if let Some(mut con) = ConTcpOpenssl::init(&keys, &loc_key) {
                for ip in ips {
                    if con.connect(ip) {
                        PeerConnection::new(loc_id.to_owned(), con, inner_rx, outer_tx.to_owned())
                            .run();
                        break;
                    } else {
                        continue;
                    }
                }
            }

            // old code
            // for ip in ips {
            //     if let ConnectionType::Tcp(target) = ip {
            //         let builder = crate::transport::tcp_openssl::Builder::new(&keys);
            //         if let Some(stream) = builder.connect(&target, &loc_key) {
            //             // if let Ok(stream) = crate::transport::tcp_native_tls::try_connect(
            //             //     &target,
            //             //     &loc_key,
            //             //     &loc_key.keyid().to_hex(),
            //             //     &identity,
            //             // ) {
            //             let transport = Transport {
            //                 target: ip.to_owned(),
            //                 stream,
            //             };
            //             PeerConnection::new(
            //                 loc_id.to_owned(),
            //                 transport,
            //                 inner_rx,
            //                 outer_tx.to_owned(),
            //             )
            //             .run();
            //             break;
            //         }
            //     }
            // }

            // failed to connect or exited
            // TODO handle connection close (peer went offline) better
            outer_tx
                .send(PeerCommand::PeerUpdate(PeerUpdate::Status(
                    PeerState::NotConnected(loc_id.clone()),
                )))
                .unwrap();
        });

        self.bootup.push((loc_id, handler_tx, handler));
    }

    pub fn tick(&mut self, stats: &mut StatsCollection) -> bool {
        // handle incoming commands
        while let Ok(cmd) = match self.rx.try_recv() {
            Ok(cmd) => Ok(cmd),
            Err(std::sync::mpsc::TryRecvError::Empty) => Err(()),
            Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                panic!("is this not supposed to happen?!")
            }
        } {
            match cmd {
                PeerCommand::PeerUpdate(state) => {
                    match &state {
                        PeerUpdate::Status(state) => {
                            // update peer state
                            let loc = match state {
                                PeerState::Connected(loc, _) => loc,
                                PeerState::NotConnected(loc) => loc,
                            };
                            let entry = self
                                .get_location_by_id(loc)
                                .expect("failed to find location");
                            entry.set_status(&state);

                            match state {
                                // updates
                                PeerState::Connected(loc, _addr) => {
                                    if let Some(pos) =
                                        self.bootup.iter().position(|val| &val.0 == loc)
                                    {
                                        println!("[core] booted up location {}", &loc);
                                        let entry = self.bootup.remove(pos);

                                        // now send service information
                                        let services: Vec<RsServiceInfo> = self
                                            .services
                                            .get_services()
                                            .map(|s| s.into())
                                            .collect();
                                        entry
                                            .1
                                            .send(PeerCommand::ServiceInfoUpdate(services))
                                            .expect("failed to send services to peer worker!");

                                        self.worker.push(entry);
                                    } else {
                                        unimplemented!();
                                    }
                                }
                                PeerState::NotConnected(loc) => {
                                    if let Some(pos) =
                                        self.bootup.iter().position(|val| &val.0 == loc)
                                    {
                                        // println!("[core] failed to connect location {}", &loc); // quite noisy
                                        self.bootup.remove(pos);
                                    } else if let Some(pos) =
                                        self.worker.iter().position(|val| &val.0 == loc)
                                    {
                                        println!("[core] shutting down location {}", &loc);
                                        self.worker.remove(pos);
                                    } else {
                                        println!(
                                            "[core] unable to find {} in both worker lists!",
                                            loc
                                        );
                                        // this is send twice some times, ignore for now.
                                        // unimplemented!();
                                    }
                                }
                            }
                        }
                        PeerUpdate::Address(ssl_id, local, external) => {
                            let peer = self
                                .locations
                                .iter()
                                .find(|&loc| loc.get_location_id() == ssl_id);
                            if peer.is_none() {
                                println!("[core] got an update for an unknown location!");
                                // println!(" - ssl_id: {}", ssl_id);
                                // println!("our known locations:");
                                // self.locations.iter().for_each(|loc| {
                                //     println!(" - {} {}", loc.get_location_id(), loc.get_name())
                                // });
                            } else {
                                let peer = peer.unwrap();
                                let mut ip_addresses = peer.get_ips_rw();

                                for ip in local {
                                    ip_addresses.0.insert(ip.to_owned());
                                    println!(
                                        "[core] updating local ip {} of peer {} {}",
                                        ip,
                                        peer.get_person()
                                            .upgrade()
                                            .expect("location is missing it's identity!")
                                            .get_name(),
                                        peer.get_name()
                                    );
                                }
                                for ip in external {
                                    ip_addresses.0.insert(ip.to_owned());
                                    println!(
                                        "[core] updating external ip {} of peer {} {}",
                                        ip,
                                        peer.get_person()
                                            .upgrade()
                                            .expect("location is missing it's identity!")
                                            .get_name(),
                                        peer.get_name()
                                    );
                                }
                            }
                        }
                    }

                    // handle event listener
                    for sink in &self.event_listener {
                        sink.send(PeerCommand::PeerUpdate(state.clone()))
                            .expect("failed to communicate with service");
                    }
                }

                PeerCommand::Thread(PeerThreadCommand::Incoming(con)) => {
                    let _ = con.peer_addr().unwrap();

                    // let builder = crate::transport::tcp_openssl::Builder::new(&self.own_key_pair);
                    // if let Some(stream) = builder.incoming(con) {
                    //     // if let Ok(stream) =
                    //     // crate::transport::tcp_native_tls::try_accept(con, &self.identity)
                    //     // {
                    //     let outer_tx = self.tx.clone();
                    //     let (handle_tx, inner_rx) = mpsc::channel();
                    //     let loc_id = PeerId::default(); // TODO
                    //                                     // let loc_id =stream.peer_certificate().unwrap().unwrap().

                    //     let handle = std::thread::spawn(move || {
                    //         let transport = Transport {
                    //             target: ConnectionType::Tcp(addr),
                    //             stream,
                    //         };
                    //         PeerConnection::new(loc_id, transport, inner_rx, outer_tx).run();
                    //     });

                    //     self.worker.push((loc_id, handle_tx, handle));
                    // }
                    // if
                    // TODO
                    unimplemented!();
                }
                PeerCommand::Send(packet) => {
                    self.try_send_to_peer(packet);
                }
                PeerCommand::Receive(packet) => {
                    // use crate::error::*;

                    assert!(packet.has_location(), "no location set!");

                    match self.services.handle_packet(packet) {
                        // packet was locally handled and an answer was generated
                        HandlePacketResult::Handled(Some(answer)) => self.try_send_to_peer(answer),
                        // packet was locally handled and no answer was generated
                        HandlePacketResult::Handled(None) => {}
                        // packet was not locally handled as no fitting service was found
                        HandlePacketResult::NotHandled(packet) => {
                            println!(
                                "[core] core received a packet that cannot be handled! {:?}",
                                packet.header
                            );
                        }
                        // something else went wrong
                        HandlePacketResult::Error(why) => {
                            println!("[core] failed to handle packet: {:?}", why)
                        }
                    }
                }
                m => {
                    println!("[core] unhandled command: {:?}", m);
                }
            }
        }

        // handle services
        if let Some(items) = self.services.tick_all(stats) {
            // this can be optimazed probably
            for item in items {
                self.try_send_to_peer(item);
            }
        }

        // handle connection attempts
        let mut candidates: Vec<Arc<Location>> = vec![];
        for loc in &self.locations {
            if loc.try_reconnect() {
                candidates.push(loc.clone());
            }
        }
        for loc in candidates {
            self.connect(&loc);
        }

        // self.worker.len() > 0 || self.bootup.len() > 0
        !self.sick
    }

    pub fn get_tx(&self) -> mpsc::Sender<PeerCommand> {
        self.tx.clone()
    }

    fn try_send_to_peer(&self, packet: Packet) {
        assert!(packet.has_location(), "no location set!");
        let to = packet.peer_id;
        if let Some(worker) = self.worker.iter().find(|&w| w.0 == to) {
            worker
                .1
                .send(PeerCommand::Send(packet))
                // .expect("failed to send to peer worker");
                .unwrap_or_else(|_| {
                    println!("[core] failed to send to peer worker");
                })
        }
    }

    pub fn get_own_location(&self) -> Arc<Location> {
        self.own_location_obj.clone()
    }

    pub fn get_locations(&self) -> &Vec<Arc<Location>> {
        &self.locations
    }

    pub fn get_location_by_id(&self, ssl_id: &PeerId) -> Option<&Arc<Location>> {
        self.get_locations()
            .iter()
            .find(|&loc| loc.get_location_id() == ssl_id)
    }

    pub fn get_own_person(&self) -> Arc<Peer> {
        // used stored location for O(1) lookup of own person
        self.own_location_obj.get_person().upgrade().expect(
            "Something went seriously wrong! Our own Peer information cannot be found anymore!",
        )
    }

    pub fn get_persons(&self) -> &Vec<Arc<Peer>> {
        &self.peers
    }

    pub fn subscribe_for_events(&mut self, receiver: mpsc::Sender<PeerCommand>) {
        self.event_listener.push(receiver);
    }
}
