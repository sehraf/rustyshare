use log::{debug, info, trace, warn};
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    select,
    sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender},
    task::JoinHandle,
    time::interval,
};

use retroshare_compat::{basics::SslId, gxs::sqlite::database::GxsDatabase};

use crate::{
    gxs::gxs_backend::GxsShared,
    model::{
        intercom::{Intercom, PeerState, PeerThreadCommand, PeerUpdate},
        location::Location,
        person::Peer,
        ConnectedPeerEntries, DataCore,
    },
    retroshare_compat::ssl_key::SslKey,
    services::Services,
    utils::{self, simple_stats::StatsCollection},
};

use self::connected_peer::ConnectionBuilder;

pub mod connected_peer;

pub struct CoreController {
    data_core: Arc<DataCore>,
    services: Services,

    core_tx: UnboundedSender<Intercom>,
    core_rx: UnboundedReceiver<Intercom>,

    pending_connection_attempts: ConnectedPeerEntries<Option<JoinHandle<()>>>,
}

impl CoreController {
    pub async fn new(
        keys: SslKey,
        friends: (Vec<Arc<Peer>>, Vec<Arc<Location>>),
        own_id: Arc<SslId>,
        gxs_id_db: GxsDatabase,
    ) -> (Self, Arc<DataCore>) {
        let (core_tx, core_rx) = unbounded_channel();

        let gxs_shared_id = Arc::new(GxsShared::new(core_tx.clone(), own_id.clone()));

        let data_core = DataCore::new(keys, friends, own_id, gxs_shared_id.to_owned()).await;

        let services =
            Services::get_core_services(&data_core, core_tx.clone(), (gxs_id_db, gxs_shared_id))
                .await;

        if log::log_enabled!(log::Level::Info) {
            info!("Core starting ...");
            info!("registered core services:");
            for s in services.get_services() {
                info!(" - {:04X?}: {:?}", s as u16, s);
            }
        }

        let dc = data_core.clone();
        (
            CoreController {
                data_core,
                services,

                core_rx,
                core_tx,

                pending_connection_attempts: ConnectedPeerEntries::default(),
            },
            dc,
        )
    }

    pub async fn run(&mut self) -> ! {
        let mut timer_slow_5s = interval(Duration::from_secs(5));
        let mut stats: StatsCollection = (Instant::now(), HashMap::new());

        loop {
            select! {
                _ = timer_slow_5s.tick() => {
                    trace!("tick_slow");

                    // Stats
                    if log::log_enabled!(log::Level::Trace) {
                        utils::simple_stats::print(&stats);
                    }
                    stats.0 = Instant::now();
                    stats.1.clear();

                    // reconnects
                    self.check_reconnects().await;

                    // // FIXME
                    // self.data_core.webui_send(
                    //     EventType::PeerStateChanged { ssl_id: "d6fb6c0f53d18303dcc9043111490e40".into() }
                    // ).await;
                }
                msg = self.core_rx.recv() => {
                    trace!("queue");

                    match msg {
                        Some(msg) => self.handle_message(&msg).await,
                        None => {}
                    }
                }

            }
        }
    }

    async fn handle_message(&mut self, msg: &Intercom) {
        trace!("handle_message {msg:?}");

        // own processing (message distribution follows later)
        match msg {
            Intercom::PeerUpdate(state) => {
                match &state {
                    PeerUpdate::Status(state) => {
                        // update peer state
                        let loc = match state {
                            PeerState::Connected(loc, _) => loc,
                            PeerState::NotConnected(loc) => loc,
                        };
                        let entry = self
                            .data_core
                            .get_location_by_id(loc.to_owned())
                            .expect("failed to find location");
                        entry.set_status(&state);

                        match state {
                            // updates
                            PeerState::Connected(loc, _addr) => {
                                if let Some((peer_tx, handle)) =
                                    self.pending_connection_attempts.0.remove(loc)
                                {
                                    info!("booted up location {loc}");

                                    let handle = handle.await.unwrap().expect(
                                        "peer is connected but thread handle doesn't exists?!",
                                    );

                                    self.data_core
                                        .get_connected_peers()
                                        .lock()
                                        .await
                                        .0
                                        .insert(loc.to_owned(), (peer_tx, handle));
                                } else {
                                    log::error!("unable to find booted up {loc} in pending list!");
                                }
                            }
                            PeerState::NotConnected(loc) => {
                                if let Some(_) = self.pending_connection_attempts.0.remove(loc) {
                                    debug!("[core] failed to connect location {loc}");
                                } else if let Some(_) =
                                    // self.data_core.connected_peer_remove(loc.to_owned()).await
                                    self
                                        .data_core
                                        .get_connected_peers()
                                        .lock()
                                        .await
                                        .0
                                        .remove(loc)
                                {
                                    info!("[core] shutting down location {loc}");
                                } else {
                                    log::error!(
                                        "[core] unable to find {loc} in both worker lists!"
                                    );
                                }
                            }
                        }
                    }
                    PeerUpdate::Address(ssl_id, local, external) => {
                        let peer = self
                            .data_core
                            .get_locations()
                            .into_iter()
                            .find(|loc| &loc.get_location_id() == ssl_id);
                        if peer.is_none() {
                            warn!("[core] got an update for an unknown location! {ssl_id}");
                            // info!(" - ssl_id: {}", ssl_id);
                            // println!("our known locations:");
                            // self.locations.iter().for_each(|loc| {
                            //     println!(" - {} {}", loc.get_location_id(), loc.get_name())
                            // });
                        } else {
                            let peer = peer.unwrap();
                            let mut ip_addresses = peer.get_ips_mut();

                            for ip in local {
                                if !ip_addresses.0.contains(ip) {
                                    ip_addresses.0.push(ip.to_owned());
                                    info!(
                                        "[core] updating local ip {ip} of peer {} {}",
                                        peer.get_person().get_name(),
                                        peer.get_name()
                                    );
                                }
                            }
                            for ip in external {
                                if !ip_addresses.1.contains(ip) {
                                    ip_addresses.1.push(ip.to_owned());
                                    info!(
                                        "[core] updating external ip {ip} of peer {} {}",
                                        peer.get_person().get_name(),
                                        peer.get_name()
                                    );
                                }
                            }
                        }
                    }
                }
            }

            Intercom::Thread(PeerThreadCommand::Incoming(con)) => {
                let _ = con.peer_addr().unwrap();

                unimplemented!();
            }

            Intercom::Send(packet) => {
                self.data_core.try_send_to_peer(packet.to_owned()).await;
            }

            Intercom::Receive(packet) => {
                assert!(packet.has_location(), "no location set!");
                trace!("handling packet {packet:?}");

                self.services.handle_packet(packet.to_owned()).await;
                // match self.services.handle_packet(packet.to_owned()).await {
                //     // packet was locally handled and an answer was generated
                //     HandlePacketResult::Handled(Some(answer)) => {
                //         self.data_core.try_send_to_peer(answer).await
                //     }
                //     // packet was locally handled and no answer was generated
                //     HandlePacketResult::Handled(None) => {}
                //     // packet was not locally handled as no fitting service was found
                //     HandlePacketResult::NotHandled(packet) => {
                //         warn!(
                //             "[core] core received a packet that cannot be handled! {:?}",
                //             packet.header
                //         );
                //     }
                //     // something else went wrong
                //     HandlePacketResult::Error(why) => {
                //         warn!("[core] failed to handle packet: {why:?}")
                //     }
                // }
            }

            Intercom::Event(_) => (),

            cmd => {
                warn!("[core] unhandled command: {cmd:?}");
            }
        }

        // forward message
        match msg {
            Intercom::PeerUpdate(state) => {
                // handle event listener
                for subscriber in self.data_core.get_subscribers().await.iter() {
                    debug!("{subscriber:?}, closed: {}", subscriber.is_closed());
                    subscriber
                        .send(Intercom::PeerUpdate(state.clone()))
                        .expect("failed to communicate with service");
                }
            }
            Intercom::Event(event) => {
                // handle webui
                self.data_core.webui_send(event.to_owned()).await;

                // handle event listener
                for subscriber in self.data_core.get_subscribers().await.iter() {
                    subscriber
                        .send(Intercom::Event(event.clone()))
                        .expect("failed to communicate with service");
                }
            }
            _ => (),
        }
    }

    async fn check_reconnects(&mut self) {
        let mut candidates: Vec<_> = self
            .data_core
            .get_locations()
            .into_iter()
            .filter(|loc| loc.try_reconnect())
            .collect();
        let own = self.data_core.get_own_location().get_location_id();
        let connected: Vec<_> = self
            .data_core
            .get_connected_peers()
            .lock()
            .await
            .0
            .iter()
            .map(|(ssl_id, _)| ssl_id.to_owned())
            .collect();

        candidates.retain(|entry| {
            let id = entry.get_location_id();
            id != own && !connected.contains(&id)
        });

        for candidate in candidates {
            // if candidate.get_location_id() == own {
            //     continue;
            // }
            trace!("trying to connect to {}", candidate.get_name());
            let (builder, peer_tx) = ConnectionBuilder::new(&self, candidate.clone());
            let handler = tokio::spawn(builder.connect());
            self.pending_connection_attempts
                .0
                .insert(candidate.get_location_id(), (peer_tx, handler));
        }
    }
}
