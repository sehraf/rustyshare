use rand::{prelude::ThreadRng, thread_rng, Rng};
use retroshare_compat::{basics::PeerId, serde::from_retroshare_wire, turtle::*};
use std::{
    collections::HashMap,
    sync::{mpsc, Arc, Mutex, RwLock},
    time::{Duration, Instant},
};

use crate::{
    model::{peers::location::Location, DataCore, PeerCommand},
    parser::{headers::ServiceHeader, Packet},
    services::{HandlePacketResult, Service},
    utils::{
        simple_stats::{StatsCollection, StatsPrinter},
        units::pretty_print_bytes,
    },
};

const TURTLE_SERVICE: u16 = 0x0014;
// const TURTLE_SUBTYPE_FILE_CRC                = 0x12 ; // unused
// const TURTLE_SUBTYPE_FILE_CRC_REQUEST        = 0x13 ;

const TURTLE_SUB_TYPE_STRING_SEARCH_REQUEST: u8 = 0x01;
const TURTLE_SUB_TYPE_FT_SEARCH_RESULT: u8 = 0x02;
const TURTLE_SUB_TYPE_OPEN_TUNNEL: u8 = 0x03;
const TURTLE_SUB_TYPE_TUNNEL_OK: u8 = 0x04;
const TURTLE_SUB_TYPE_FILE_REQUEST: u8 = 0x07;
const TURTLE_SUB_TYPE_FILE_DATA: u8 = 0x08;
const TURTLE_SUB_TYPE_REGEXP_SEARCH_REQUEST: u8 = 0x09;
const TURTLE_SUB_TYPE_GENERIC_DATA: u8 = 0x0a;
const TURTLE_SUB_TYPE_GENERIC_SEARCH_REQUEST: u8 = 0x0b;
const TURTLE_SUB_TYPE_GENERIC_SEARCH_RESULT: u8 = 0x0c;
const TURTLE_SUB_TYPE_FILE_MAP: u8 = 0x10;
const TURTLE_SUB_TYPE_FILE_MAP_REQUEST: u8 = 0x11;
const TURTLE_SUB_TYPE_FILE_CRC: u8 = 0x12; // unused
const TURTLE_SUB_TYPE_FILE_CRC_REQUEST: u8 = 0x13; // unused
const TURTLE_SUB_TYPE_CHUNK_CRC: u8 = 0x14;
const TURTLE_SUB_TYPE_CHUNK_CRC_REQUEST: u8 = 0x15;
const TURTLE_SUB_TYPE_GENERIC_FAST_DATA: u8 = 0x16;

/// life time for tunnel requests in the cache.
const TUNNEL_REQUESTS_LIFE_TIME: Duration = Duration::from_secs(600);
/// maximum time during which we process/forward results for known tunnel requests
const TUNNEL_REQUESTS_RESULT_TIME: Duration = Duration::from_secs(20);
/// maximum life time of an unused tunnel.
const MAXIMUM_TUNNEL_IDLE_TIME: Duration = Duration::from_secs(60);

// stats stuff
const ENTRY_A: &str = &"times_forwarded";
const ENTRY_A_FN: StatsPrinter = |data| -> String { format!("{} times", data) };

const ENTRY_B: &str = &"data_forwarded";
const ENTRY_B_FN: StatsPrinter =
    |data| -> String { format!("{}/s", pretty_print_bytes(data as u64)) };

pub struct Turtle {
    core: mpsc::Sender<PeerCommand>,

    rng: RwLock<ThreadRng>,
    locations: Vec<Arc<Location>>,

    tunnel_history: RwLock<HashMap<u32, TunnelRequest>>,
    tunnel_active: RwLock<HashMap<u32, TunnelActive>>,

    counter: u8,

    stats_forwarded_count: Mutex<i32>,
    stats_forwarded_data: Mutex<i32>,
}

// TODO handle peers disconnecting

impl Turtle {
    pub fn new(dc: &mut DataCore) -> Turtle {
        Turtle {
            core: dc.get_tx(),

            rng: RwLock::new(thread_rng()),
            locations: dc.get_locations().clone(),

            tunnel_history: RwLock::new(HashMap::new()),
            tunnel_active: RwLock::new(HashMap::new()),

            counter: 0,

            stats_forwarded_count: Mutex::new(0),
            stats_forwarded_data: Mutex::new(0),
        }
    }

    pub fn handle_incoming(&self, header: &ServiceHeader, packet: Packet) -> HandlePacketResult {
        // exclude handled ones
        if ![
            TURTLE_SUB_TYPE_OPEN_TUNNEL,
            TURTLE_SUB_TYPE_TUNNEL_OK,
            TURTLE_SUB_TYPE_GENERIC_DATA,
        ]
        .contains(&header.sub_type)
        {
            println!("[Turtle] received turtle: {:?}", packet.header);
        }

        match header.sub_type {
            TURTLE_SUB_TYPE_STRING_SEARCH_REQUEST => {}
            TURTLE_SUB_TYPE_FT_SEARCH_RESULT => {}
            TURTLE_SUB_TYPE_OPEN_TUNNEL => {
                return self.handle_open_tunnel(packet);
            }
            TURTLE_SUB_TYPE_TUNNEL_OK => {
                return self.handle_tunnel_ok(packet);
            }
            TURTLE_SUB_TYPE_FILE_REQUEST => {}
            TURTLE_SUB_TYPE_FILE_DATA => {}
            TURTLE_SUB_TYPE_REGEXP_SEARCH_REQUEST => {}
            TURTLE_SUB_TYPE_GENERIC_DATA => {
                return self.handle_generic_data(packet);
            }
            TURTLE_SUB_TYPE_GENERIC_SEARCH_REQUEST => {}
            TURTLE_SUB_TYPE_GENERIC_SEARCH_RESULT => {}
            TURTLE_SUB_TYPE_FILE_MAP => {}
            TURTLE_SUB_TYPE_FILE_MAP_REQUEST => {}
            TURTLE_SUB_TYPE_FILE_CRC | TURTLE_SUB_TYPE_FILE_CRC_REQUEST => {
                // RetroShare has these commented out
                println!("[Turtle] {} should not be used", header.sub_type);
                println!("[Turtle] sent by {}", &packet.peer_id);
                unimplemented!();
            }
            TURTLE_SUB_TYPE_CHUNK_CRC => {}
            TURTLE_SUB_TYPE_CHUNK_CRC_REQUEST => {}
            TURTLE_SUB_TYPE_GENERIC_FAST_DATA => {}
            sub_type => {
                println!("[Turtle] recevied unknown sub typ {}", sub_type);
            }
        }

        HandlePacketResult::Handled(None)
    }

    fn handle_open_tunnel(&self, mut packet: Packet) -> HandlePacketResult {
        // forward based on simple probability
        // RS does a lot of math to be "safe", this has been disscussed often in the past

        // create a copy for simple replay
        let mut packet_copy = packet.clone();
        let item: TurtleOpenTunnelItem =
            from_retroshare_wire(&mut packet.payload).expect("failed to deserialze");

        // println!("[Turtle] received open tunnel request: {}", &item);

        // bounce check!
        if self
            .tunnel_history
            .read()
            .expect("failed to get history, lock poisoned!")
            .contains_key(&item.request_id)
        {
            // println!("dropping bounced tunnel request! {}", item);
            return HandlePacketResult::Handled(None);
        }

        // Here be dragons!
        //
        // Goal: tunnel should usually not exceed 6 hops
        // Idea:
        // - drop probability: x
        // - (1-x)^6 <= (1-0.9) drop probability after 6 hop >= 90%
        // - x ~ 0.33 results in about 9% chance of a tunnel being longer than 6 hops
        //
        // DO NOT CARE ABOUT THE (stupid) HOPS COUNTER
        // I know that RS took some effort to not leak anything but i personally believe that this (and basically everything else) introduces leakage to some extend.
        let forward = self
            .rng
            .write()
            .expect("failed to get rng, lock poisoned!")
            .gen_ratio(66, 100);

        if !forward {
            // println!("[Turtle] dropping tunnel request! {}", item);
            return HandlePacketResult::Handled(None);
        }

        // TODO add own file sharing ability BELOW the forward check

        let entry = TunnelRequest {
            from: packet.peer_id,
            time: Instant::now(),
        };
        self.tunnel_history
            .write()
            .expect("failed to get history, lock poisoned!")
            .insert(item.request_id, entry);

        for loc in &self.locations {
            if loc.is_connected() {
                // skipp the packet's origin
                if loc.get_location_id() == &packet.peer_id {
                    continue;
                }

                packet_copy.peer_id = loc.get_location_id().to_owned();
                self.core
                    .send(PeerCommand::Send(packet_copy.clone()))
                    .expect("failed to communicate with core!");
            }
        }
        // println!("[Turtle] spreading tunnel request! {}", item);

        HandlePacketResult::Handled(None)
    }

    fn handle_tunnel_ok(&self, mut packet: Packet) -> HandlePacketResult {
        // create a copy for simple forward
        let mut packet_copy = packet.clone();
        let item: TurtleTunnelOkItem =
            from_retroshare_wire(&mut packet.payload).expect("failed to deserialze");

        // println!("[Turtle] received tunnel ok: {}", &item);

        // look up id
        let entry = self
            .tunnel_history
            .write()
            .expect("failed to get history, lock poisoned!")
            .remove(&item.request_id);
        if entry.is_none() {
            // println!(
            //     "[Turtle] unable to find pending tunnel request for id {:08x}!",
            //     &item.request_id,
            // );
            return HandlePacketResult::Handled(None);
        }

        // entry still fresh?
        let request = entry.unwrap();
        if request.time.elapsed() > TUNNEL_REQUESTS_RESULT_TIME {
            // println!(
            //     "[Turtle] found pending tunnel request for id {:08x} but it's too old!",
            //     &item.request_id
            // );
            return HandlePacketResult::Handled(None);
        }

        // everything is ok, insert new tunnel
        let entry = TunnelActive {
            from: request.from,
            to: packet.peer_id,
            last_active: Instant::now(),
        };
        let prev = self
            .tunnel_active
            .write()
            .expect("failed to get active tunnels, lock poisoned!")
            .insert(item.tunnel_id, entry);
        if !prev.is_none() {
            println!(
                "[Turtle] DOUBLE TUNNEL TROUBLE (replacing an existing tunnel with ... itself?!? nobody knows)"
            );
        }

        // println!("[Turtle] forwarding {:08x}", &item.tunnel_id);

        // send reponse
        packet_copy.peer_id = request.from;

        HandlePacketResult::Handled(Some(packet_copy))
    }

    fn handle_generic_data(&self, mut packet: Packet) -> HandlePacketResult {
        // create a copy for simple forward
        let mut packet_copy = packet.clone();
        let item: TurtleGenericDataItem =
            from_retroshare_wire(&mut packet.payload).expect("failed to deserialze");

        // println!("received generic data: {}", &item);

        // find tunnel id
        let mut lock = self
            .tunnel_active
            .write()
            .expect("failed to get active tunnels, lock poisoned!");
        let entry = lock.get_mut(&item.tunnel_id);
        if entry.is_none() {
            // println!(
            //     "[Turtle] unable to find active tunnel request for id {:08x}",
            //     &item.tunnel_id
            // );
            return HandlePacketResult::Handled(None);
        }
        let mut entry = entry.unwrap();

        // found it, figure out direction
        if packet.peer_id == entry.from {
            packet_copy.peer_id = entry.to;
        } else if packet.peer_id == entry.to {
            packet_copy.peer_id = entry.from;
        } else {
            println!(
                "[Turtle] generic data item has active tunnel {:08x} but no matching source / destination! Dropping tunnel!",
                &item.tunnel_id
            );
            lock.remove(&item.tunnel_id);
            return HandlePacketResult::Handled(None);
        }
        entry.last_active = Instant::now();

        // println!(
        //     "[Turtle] forwarding data (id: {:08x}, size: {})",
        //     &item.tunnel_id,
        //     utils::units::pretty_print_bytes(packet.header.get_payload_size() as u64)
        // );

        // handle stats
        *self
            .stats_forwarded_count
            .lock()
            .expect("failed to get stats_forwarded_count, lock poisened!") += 1;
        *self
            .stats_forwarded_data
            .lock()
            .expect("failed to get stats_forwarded_data, lock poisened!") +=
            packet.header.get_payload_size() as i32;

        return HandlePacketResult::Handled(Some(packet_copy));
    }
}

impl Service for Turtle {
    fn get_id(&self) -> u16 {
        TURTLE_SERVICE
    }

    fn handle_packet(&self, packet: Packet) -> HandlePacketResult {
        self.handle_incoming(&packet.header.into(), packet)
    }

    fn tick(&mut self, stats: &mut StatsCollection) -> Option<Vec<Packet>> {
        // clean up caches
        const COUNTER_MAX: u8 = 10; // arbitrary
        self.counter += 1;
        if self.counter > COUNTER_MAX {
            self.counter = 0;

            // Do not block! It is not worth blocking the main tick!
            if let Ok(mut history) = self.tunnel_history.try_write() {
                history.retain(|_, e| e.time.elapsed() < TUNNEL_REQUESTS_LIFE_TIME);
            }
            if let Ok(mut active) = self.tunnel_active.try_write() {
                active.retain(|_, e| e.last_active.elapsed() < MAXIMUM_TUNNEL_IDLE_TIME);
            }

            // DEBUG

            // println!("[Turtle] tunnel request history:");
            // let lock = self
            //     .tunnel_history
            //     .read()
            //     .expect("failed to get history, lock poisoned!");
            // for entry in lock.iter() {
            //     print!(" {:08x}", entry.0);
            // }
            // if !lock.is_empty() {
            //     print!("\n");
            // }
            // drop(lock);

            // println!("[Turtle] active tunnels:");
            // let lock = self
            //     .tunnel_active
            //     .read()
            //     .expect("failed to get active tunnels, lock poisoned!");
            // for entry in lock.iter() {
            //     println!(
            //         " - id: {:08x}, entry: {} -> {} (last active: {:2?} secs)",
            //         entry.0,
            //         entry.1.from,
            //         entry.1.to,
            //         entry.1.last_active.elapsed().as_secs()
            //     );
            // }
            // drop(lock);
        }

        // update stats
        let name = self.get_service_info().0; // generic way to always have the right name
        let entry = stats.1.entry(name).or_insert(HashMap::new());
        // times data forwarded
        entry.entry(ENTRY_A.to_owned()).or_insert((ENTRY_A_FN, 0)).1 +=
            *self.stats_forwarded_count.lock().expect("lock poisened!");
        // data amount forwarded
        entry.entry(ENTRY_B.to_owned()).or_insert((ENTRY_B_FN, 0)).1 +=
            *self.stats_forwarded_data.lock().expect("lock poisened!");

        // reset stats
        *self.stats_forwarded_count.lock().expect("lock poisened!") = 0;
        *self.stats_forwarded_data.lock().expect("lock poisened!") = 0;

        None
    }

    fn get_service_info(&self) -> (String, u16, u16, u16, u16) {
        (String::from("turtle"), 1, 0, 1, 0)
    }
}

#[derive(Debug)]
struct TunnelRequest {
    from: PeerId,
    time: Instant,
}

#[derive(Debug)]
struct TunnelActive {
    from: PeerId,
    to: PeerId,
    last_active: Instant,
}
