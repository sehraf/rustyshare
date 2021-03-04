use std::{
    net::{SocketAddr, TcpStream},
    sync::{mpsc, Arc},
};

use openssl::{pkey, x509};
// use sequoia_openpgp as openpgp;

pub mod peers;
use peers::{location::Location, Peer};

use crate::{
    // error,
    parser::{headers::Header, Packet},
    retroshare_compat::{keyring::Keyring, *},
    serial_stuff,
    // services::Services,
    transport::{
        connection::PeerConnection,
        ssl::SslKeyPair,
        // tcp::TcpTransport,
        ConnectionType,
        Transport,
    },
};

#[derive(Debug)]
pub enum PeerCommand {
    Thread(PeerThreadCommand),
    PeerUpdate(PeerStatus),
    Send(Packet),
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
pub enum PeerStatus {
    Online(LocationId),
    Offline(LocationId),
}

pub struct DataCore {
    own_key_pair: SslKeyPair,

    rx: mpsc::Receiver<PeerCommand>,
    tx: mpsc::Sender<PeerCommand>,

    peers: Vec<Arc<Peer>>,
    locations: Vec<Arc<Location>>,

    bootup: Vec<(
        LocationId,
        mpsc::Sender<PeerCommand>,
        std::thread::JoinHandle<()>,
    )>,
    worker: Vec<(
        LocationId,
        mpsc::Sender<PeerCommand>,
        std::thread::JoinHandle<()>,
    )>,
}

impl DataCore {
    pub fn new(pub_key: x509::X509, priv_key: pkey::PKey<openssl::pkey::Private>) -> DataCore {
        let (tx, rx) = mpsc::channel();
        let keys = Arc::new((pub_key, priv_key));

        DataCore {
            own_key_pair: keys,
            peers: vec![],
            locations: vec![],
            rx,
            tx,
            bootup: vec![],
            worker: vec![],
        }
    }

    // this should live somewhere else eventually
    pub fn load_peers(&mut self, data: Vec<u8>, keys: &Keyring, ssl_me: &str) -> Vec<SocketAddr> {
        let mut offset = 0;
        let data_size = data.len();
        let mut persons: Vec<Arc<Peer>> = vec![];
        let mut locations: Vec<Arc<Location>> = vec![];

        // helper for reading a varying amount of bytes
        // let read = |data: &Vec<u8>, offset: &mut usize, len: &usize| -> Vec<u8> {
        //     let d = data[*offset..*offset + len].to_owned();
        //     *offset += len;
        //     d
        // };

        while offset < data_size {
            // get header
            let mut header: [u8; 8] = [0; 8];
            header.copy_from_slice(&data[offset..offset + 8]);
            let (class, typ, sub_type, packet_size) =
                match (Header::Raw { data: header }.try_parse()) {
                    Ok(header) => match header {
                        Header::Class {
                            class,
                            typ,
                            sub_type,
                            size,
                        } => (class, typ, sub_type, size),
                        _ => panic!("This should not happen! Expected a class header!"),
                    },
                    Err(why) => {
                        panic!("failed to read header: {:?}", why);
                    }
                };
            // header read
            offset += 8;

            // used for parsing individual packets
            let mut offset_inner = offset.clone();

            // used for tracking packet end
            offset += packet_size as usize - 8; // header was already removed

            match class {
                // const uint8_t RS_PKT_CLASS_BASE      = 0x01;
                // const uint8_t RS_PKT_CLASS_CONFIG    = 0x02;
                0x02 => match typ {
                    // const uint8_t RS_PKT_TYPE_GENERAL_CONFIG = 0x01;
                    0x01 => {
                        // RsGeneralConfigSerialiser
                        match sub_type {
                            // const uint8_t RS_PKT_SUBTYPE_KEY_VALUE = 0x01;
                            0x01 => {
                                // const uint16_t TLV_TYPE_KEYVALUESET   = 0x1011;
                                let t = serial_stuff::read_u16(&data, &mut offset_inner);
                                assert_eq!(t, 0x1011);

                                // size without 6 byte TLV header
                                let size = serial_stuff::read_u32(&data, &mut offset_inner);
                                assert_eq!(size as usize - 6 + offset_inner, offset);

                                while offset_inner < offset {
                                    // RsTlvKeyValue kv;
                                    //  - this are just a bunch of strings with an header

                                    // header
                                    // const uint16_t TLV_TYPE_KEYVALUE      = 0x1010;
                                    let t = serial_stuff::read_u16(&data, &mut offset_inner); // type
                                    let size = serial_stuff::read_u32(&data, &mut offset_inner); // len
                                    let check = offset_inner;
                                    assert_eq!(t, 0x1010);

                                    // const uint16_t TLV_TYPE_STR_KEY       = 0x0053;
                                    let key = serial_stuff::read_string_typed(
                                        &data,
                                        &mut offset_inner,
                                        &0x0053,
                                    );
                                    // const uint16_t TLV_TYPE_STR_VALUE     = 0x0054;
                                    let value = serial_stuff::read_string_typed(
                                        &data,
                                        &mut offset_inner,
                                        &0x0054,
                                    );
                                    dbg!(key, value);

                                    // this must be the end
                                    assert_eq!(offset_inner, check + size as usize - 6);
                                }
                            }
                            m => println!(
                                "unable to handle RsGeneralConfigSerialiser sub type {:02X}",
                                m
                            ),
                        }
                    }
                    // const uint8_t RS_PKT_TYPE_PEER_CONFIG    = 0x02;
                    0x2 => {
                        // RsPeerConfigSerialiser
                        match sub_type {
                            // const uint8_t RS_PKT_SUBTYPE_PEER_STUN             = 0x02;
                            // const uint8_t RS_PKT_SUBTYPE_PEER_NET              = 0x03;
                            0x3 => {
                                let (pgp_id, location, peer_id, ips) =
                                    serial_stuff::read_peer_net_item(&data, &mut offset_inner);

                                // lookup key
                                if let Some(pgp) = keys.get_key_by_id_bytes(&pgp_id, false) {
                                    let name = {
                                        let mut s2: String = String::new();
                                        for ua in pgp.userids() {
                                            let s3 = String::from_utf8_lossy(ua.value());
                                            s2.push_str(&s3);
                                        }
                                        s2
                                    };

                                    println!(
                                        "adding peer {:?} with location {:?}",
                                        &name, &location
                                    );

                                    let mut peer =
                                        persons.iter_mut().find(|p| p.get_pgp_id() == &pgp_id);

                                    if peer.is_none() {
                                        persons.push(Arc::new(Peer::new(
                                            name,
                                            pgp.clone(),
                                            pgp_id,
                                        )));
                                        peer = persons.last_mut();
                                    }

                                    // this shall not crash
                                    let peer = peer.unwrap();

                                    let loc = Arc::new(Location::new(
                                        location,
                                        peer_id,
                                        peer.get_pgp_id().clone(),
                                        ips,
                                        Arc::downgrade(peer),
                                    ));

                                    peer.add_location(Arc::downgrade(&loc));
                                    locations.push(loc);
                                }
                            }
                            // const uint8_t RS_PKT_SUBTYPE_PEER_GROUP_deprecated = 0x04;
                            // const uint8_t RS_PKT_SUBTYPE_PEER_PERMISSIONS      = 0x05;
                            // const uint8_t RS_PKT_SUBTYPE_PEER_BANDLIMITS       = 0x06;
                            // const uint8_t RS_PKT_SUBTYPE_NODE_GROUP            = 0x07;
                            m => println!(
                                "unable to handle RsPeerConfigSerialiser sub type {:02X}",
                                m
                            ),
                        }
                    }
                    // const uint8_t RS_PKT_TYPE_CACHE_CONFIG   = 0x03;
                    // const uint8_t RS_PKT_TYPE_FILE_CONFIG    = 0x04;
                    // const uint8_t RS_PKT_TYPE_PLUGIN_CONFIG  = 0x05;
                    // const uint8_t RS_PKT_TYPE_HISTORY_CONFIG = 0x06;
                    m => println!("unable to handle type {:02X}", m),
                },
                m => println!("unable to handle class {:02X}", m),
            }
        }
        assert_eq!(offset, data_size);

        // summarize
        println!("loaded the following:");
        for person in &persons {
            println!(" - person '{}'", person.get_name());
            let locs = person.get_locations();
            for loc in locs.iter() {
                let loc = loc.upgrade();
                if let Some(loc) = loc {
                    println!("   - location '{}'", loc.get_name());
                } else {
                    unreachable!("We just allocated the locations, an upgrade should work fine!");
                }
            }
        }

        // move everything to main structure
        self.peers = persons;
        self.locations = locations;

        // return own network address ( this hack is worse than it looks )
        let me = self
            .locations
            .iter()
            .find(|loc| {
                let id = loc.get_location_id();
                let mut id_str = String::new();
                for byte in id {
                    // the x must be lower case
                    id_str.push_str(&format!("{:02x}", byte));
                }
                dbg!(&ssl_me, &id_str);
                id_str == ssl_me
            })
            .expect("can't find own location!");
        me.get_ips().to_owned()
    }

    pub fn connect(&mut self) {
        for loc in self.locations.iter() {
            // copy everything
            let keys = self.own_key_pair.clone();
            let outer_tx = self.tx.clone();
            let (handler_tx, inner_rx) = mpsc::channel();

            // turn IPs into ConnectionType::Tcp
            let ips: Vec<ConnectionType> = loc
                .get_ips()
                .iter()
                .map(|&val| ConnectionType::Tcp(val))
                .collect();

            let loc_id = loc.get_location_id().clone();
            let loc_key = loc.get_person().upgrade().unwrap().get_pgp().clone();

            let handler = std::thread::spawn(move || {
                for ip in ips {
                    if let ConnectionType::Tcp(target) = ip {
                        let builder = crate::transport::tcp_openssl::Builder::new(&keys);
                        if let Some(stream) = builder.connect(&target, &loc_key) {
                            let transport = Transport {
                                target: ip.clone(),
                                stream,
                            };
                            PeerConnection::new(
                                loc_id.clone(),
                                transport,
                                inner_rx,
                                outer_tx.clone(),
                            )
                            .run();
                            break;
                        }
                    }
                }

                // failed to connect
                outer_tx
                    .send(PeerCommand::PeerUpdate(PeerStatus::Offline(loc_id.clone())))
                    .unwrap();
            });

            self.bootup.push((loc_id, handler_tx, handler));
        }
    }

    pub fn tick(&mut self) -> bool {
        match self.rx.try_recv() {
            Err(std::sync::mpsc::TryRecvError::Empty) => {}
            Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                panic!("is this supposed to happen?!")
            }
            Ok(cmd) => match cmd {
                PeerCommand::PeerUpdate(PeerStatus::Online(loc)) => {
                    if let Some(pos) = self.bootup.iter().position(|val| val.0 == loc) {
                        println!("booted up location {:x?}", &loc);
                        let entry = self.bootup.remove(pos);
                        self.worker.push(entry);
                    }
                }
                PeerCommand::PeerUpdate(PeerStatus::Offline(loc)) => {
                    if let Some(pos) = self.bootup.iter().position(|val| val.0 == loc) {
                        // println!("shutting down location {:x?}", &loc);
                        let _ = self.bootup.remove(pos);
                    }
                    if let Some(pos) = self.worker.iter().position(|val| val.0 == loc) {
                        // println!("shutting down location {:x?}", &loc);
                        let _ = self.worker.remove(pos);
                    }
                }
                PeerCommand::Thread(PeerThreadCommand::Incoming(con)) => {
                    let addr = con.peer_addr().unwrap();

                    let builder = crate::transport::tcp_openssl::Builder::new(&self.own_key_pair);
                    if let Some(stream) = builder.incoming(con) {
                        let outer_tx = self.tx.clone();
                        let (handle_tx, inner_rx) = mpsc::channel();
                        let loc_id = [0; 16]; // TODO

                        let handle = std::thread::spawn(move || {
                            let transport = Transport {
                                target: ConnectionType::Tcp(addr),
                                stream,
                            };
                            PeerConnection::new(loc_id, transport, inner_rx, outer_tx).run();
                        });

                        self.worker.push((loc_id, handle_tx, handle));
                    }
                }
                _ => {}
            },
        }

        // self.worker.len() > 0 || self.bootup.len() > 0
        true
    }

    pub fn get_tx(&self) -> mpsc::Sender<PeerCommand> {
        self.tx.clone()
    }
}
