use async_trait::async_trait;
use log::{info, trace, warn};
use nanorand::{Rng, WyRand};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex, RwLock},
    time::{Duration, Instant},
};
use tokio::{
    select,
    sync::mpsc::{UnboundedReceiver, UnboundedSender},
    task::JoinHandle,
    time::{interval, Interval},
};

use retroshare_compat::{
    basics::SslId,
    serde::from_retroshare_wire,
    services::{service_info::RsServiceInfo, turtle::*},
};

use crate::{
    low_level_parsing::{headers::ServiceHeader, Packet},
    // error,
    model::{intercom::Intercom, location::Location, DataCore},
    send_to_core,
    services::Service,
    utils::{self, simple_stats::StatsPrinter, units::pretty_print_bytes},
};

use ::retroshare_compat::services::ServiceType;

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
#[allow(dead_code)]
const ENTRY_A: &str = &"times_forwarded";
#[allow(dead_code)]
const ENTRY_A_FN: StatsPrinter = |data| -> String { format!("{} times", data) };

#[allow(dead_code)]
const ENTRY_B: &str = &"data_forwarded";
#[allow(dead_code)]
const ENTRY_B_FN: StatsPrinter =
    |data| -> String { format!("{}", pretty_print_bytes(data as u64)) };

pub struct Turtle {
    rx: UnboundedReceiver<Intercom>,

    core_tx: UnboundedSender<Intercom>,

    rng: Arc<RwLock<WyRand>>,
    locations: Vec<Arc<Location>>,

    tunnel_history: RwLock<HashMap<u32, TunnelRequest>>,
    tunnel_active: RwLock<HashMap<u32, TunnelActive>>,

    stats_forwarded_count: Mutex<i32>,
    stats_forwarded_data: Mutex<i32>,

    timer_maintenance: Interval,
}

// TODO handle peers disconnecting

impl Turtle {
    pub async fn new(
        core: &Arc<DataCore>,
        core_tx: UnboundedSender<Intercom>,
        rx: UnboundedReceiver<Intercom>,
    ) -> Turtle {
        Turtle {
            rx,

            core_tx,

            rng: Arc::new(RwLock::new(WyRand::new())),
            locations: core.get_locations().clone(),

            tunnel_history: RwLock::new(HashMap::new()),
            tunnel_active: RwLock::new(HashMap::new()),

            stats_forwarded_count: Mutex::new(0),
            stats_forwarded_data: Mutex::new(0),

            timer_maintenance: interval(Duration::from_secs(5)),
        }
    }

    fn handle_incoming(&self, header: &ServiceHeader, mut packet: Packet) {
        trace!("handle_incoming: {header:?}");
        // // exclude handled ones
        // if ![
        //     TURTLE_SUB_TYPE_OPEN_TUNNEL,
        //     TURTLE_SUB_TYPE_TUNNEL_OK,
        //     TURTLE_SUB_TYPE_GENERIC_DATA,
        // ]
        // .contains(&header.sub_type)
        // {
        //     info!("[Turtle] received turtle: {:?}", packet.header);
        // }

        match header.sub_type {
            TURTLE_SUB_TYPE_STRING_SEARCH_REQUEST => {
                let item: TurtleStringSearchRequestItem = from_retroshare_wire(&mut packet.payload);
                info!("search request: string: {item:?}");
            }
            TURTLE_SUB_TYPE_FT_SEARCH_RESULT => {}
            TURTLE_SUB_TYPE_OPEN_TUNNEL => {
                self.handle_open_tunnel(packet);
            }
            TURTLE_SUB_TYPE_TUNNEL_OK => {
                self.handle_tunnel_ok(packet);
            }
            TURTLE_SUB_TYPE_FILE_REQUEST => {}
            TURTLE_SUB_TYPE_FILE_DATA => {}
            TURTLE_SUB_TYPE_REGEXP_SEARCH_REQUEST => {
                let item: TurtleRegExpSearchRequestItem = from_retroshare_wire(&mut packet.payload);
                info!("search request: regex: {item:?}");
            }
            TURTLE_SUB_TYPE_GENERIC_DATA => {
                self.handle_generic_data(packet);
            }
            TURTLE_SUB_TYPE_GENERIC_SEARCH_REQUEST => {
                let item: TurtleGenericSearchRequestItem =
                    from_retroshare_wire(&mut packet.payload);
                info!("search request: generic: {item:?}");
            }
            TURTLE_SUB_TYPE_GENERIC_SEARCH_RESULT => {}
            TURTLE_SUB_TYPE_FILE_MAP => {}
            TURTLE_SUB_TYPE_FILE_MAP_REQUEST => {}
            TURTLE_SUB_TYPE_FILE_CRC | TURTLE_SUB_TYPE_FILE_CRC_REQUEST => {
                // RetroShare has these commented out
                warn!("{} should not be used", header.sub_type);
                warn!("sent by {}", &packet.peer_id);
                unimplemented!();
            }
            TURTLE_SUB_TYPE_CHUNK_CRC => {}
            TURTLE_SUB_TYPE_CHUNK_CRC_REQUEST => {}
            TURTLE_SUB_TYPE_GENERIC_FAST_DATA => {}
            sub_type => {
                log::error!("received unknown sub typ {sub_type}");
            }
        }
    }

    fn handle_open_tunnel(&self, mut packet: Packet) {
        // forward based on simple probability
        // RS does a lot of math to be "safe", this has been discussed often in the past

        // create a copy for simple replay
        let item: TurtleOpenTunnelItem = from_retroshare_wire(&mut packet.payload.clone());

        trace!("received open tunnel request: {item}");

        // bounce check!
        if self
            .tunnel_history
            .read()
            .expect("failed to get history, lock poisoned!")
            .contains_key(&item.request_id)
        {
            trace!("dropping bounced tunnel request! {}", item);
            return;
        }

        if !self.forward() {
            trace!("dropping tunnel request! {}", item);
            return;
        }

        // TODO add own file sharing ability BELOW the forward check

        let entry = TunnelRequest {
            from: packet.peer_id.clone(),
            time: Instant::now(),
        };
        self.tunnel_history
            .write()
            .expect("failed to get history, lock poisoned!")
            .insert(item.request_id, entry);

        for loc in &self.locations {
            if loc.is_connected() {
                // skip the packet's origin
                if loc.get_location_id() == packet.peer_id {
                    continue;
                }

                packet.peer_id = loc.get_location_id().to_owned();
                // self.core_tx
                //     .send(Intercom::Send(packet.clone()))
                //     .expect("failed to communicate with core!");
                send_to_core!(self, packet.to_owned());
            }
        }
        trace!("spreading tunnel request! {}", item);
    }

    fn handle_tunnel_ok(&self, mut packet: Packet) {
        // create a copy for simple forward
        let item: TurtleTunnelOkItem = from_retroshare_wire(&mut packet.payload.clone());

        trace!("received tunnel ok: {item}");

        // look up id
        let entry = self
            .tunnel_history
            .write()
            .expect("failed to get history, lock poisoned!")
            .remove(&item.request_id);
        if entry.is_none() {
            trace!(
                "unable to find pending tunnel request for id {:08x}!",
                &item.request_id,
            );
            return;
        }

        // entry still fresh?
        let request = entry.unwrap();
        if request.time.elapsed() > TUNNEL_REQUESTS_RESULT_TIME {
            trace!(
                "found pending tunnel request for id {:08x} but it's too old!",
                &item.request_id
            );
            return;
        }

        // everything is ok, insert new tunnel
        let entry = TunnelActive {
            from: request.from.clone(),
            to: packet.peer_id.clone(),
            last_active: Instant::now(),
        };
        let prev = self
            .tunnel_active
            .write()
            .expect("failed to get active tunnels, lock poisoned!")
            .insert(item.tunnel_id, entry);
        if prev.is_some() {
            warn!(
                "DOUBLE TUNNEL TROUBLE (replacing an existing tunnel with ... itself?!? nobody knows!)"
            );
        }

        trace!("forwarding {:08x}", &item.tunnel_id);

        // send response
        packet.peer_id = request.from.clone();

        send_to_core!(self, packet);
    }

    fn handle_generic_data(&self, mut packet: Packet) {
        // create a copy for simple forward
        let item: TurtleGenericDataItem = from_retroshare_wire(&mut packet.payload.clone());

        trace!("received generic data: {item}");

        // find tunnel id
        let mut lock = self
            .tunnel_active
            .write()
            .expect("failed to get active tunnels, lock poisoned!");
        let entry = lock.get_mut(&item.tunnel_id);
        if entry.is_none() {
            trace!(
                "unable to find active tunnel request for id {:08x}",
                &item.tunnel_id
            );
            return;
        }
        let mut entry = entry.unwrap();

        // found it, figure out direction
        if packet.peer_id == entry.from {
            packet.peer_id = entry.to.clone();
        } else if packet.peer_id == entry.to {
            packet.peer_id = entry.from.clone();
        } else {
            info!(
                "generic data item has active tunnel {:08x} but no matching source / destination! Dropping tunnel!",
                &item.tunnel_id
            );
            lock.remove(&item.tunnel_id);
            return;
        }
        entry.last_active = Instant::now();

        trace!(
            "forwarding data (id: {:08x}, size: {})",
            &item.tunnel_id,
            utils::units::pretty_print_bytes(packet.header.get_payload_size() as u64)
        );

        // handle stats
        *self
            .stats_forwarded_count
            .lock()
            .expect("failed to get stats_forwarded_count, lock poisoned!") += 1;
        *self
            .stats_forwarded_data
            .lock()
            .expect("failed to get stats_forwarded_data, lock poisoned!") +=
            packet.header.get_payload_size() as i32;

        send_to_core!(self, packet);
    }

    fn forward(&self) -> bool {
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
        //
        // This does code however not respect any limits (e.g. tunnel requests per seconds, bandwidth, and so on .. TODO)

        self.rng
            .write()
            .expect("failed to get rng, lock poisoned!")
            .generate_range(0..100)
            > 66
    }
}

#[async_trait]
impl Service for Turtle {
    fn get_id(&self) -> ServiceType {
        ServiceType::Turtle
    }

    fn get_service_info(&self) -> RsServiceInfo {
        RsServiceInfo::new(self.get_id().into(), "turtle")
    }

    fn run(mut self) -> JoinHandle<()> {
        tokio::spawn(async move {
            loop {
                select! {
                    msg = self.rx.recv() => {
                        if let Some(msg) = msg {
                            trace!("handling msg {msg:?}");

                            match msg {
                                Intercom::Receive(packet) =>
                                    self.handle_incoming(&packet.header.to_owned().into(), packet),
                                _ => warn!("unexpected message: {msg:?}"),
                            }
                        }
                    }
                    _ = self.timer_maintenance.tick() => {
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
                }
            }
        })
    }
}

#[derive(Debug)]
struct TunnelRequest {
    from: Arc<SslId>,
    time: Instant,
}

#[derive(Debug)]
struct TunnelActive {
    from: Arc<SslId>,
    to: Arc<SslId>,
    last_active: Instant,
}
