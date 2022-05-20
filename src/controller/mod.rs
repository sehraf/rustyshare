use log::{debug, info, trace, warn};
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    select,
    sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender},
    time::interval,
};

use retroshare_compat::{events::EventType, services::service_info::RsServiceInfo};

use crate::{
    model::{
        intercom::{Intercom, PeerState, PeerThreadCommand, PeerUpdate},
        location::Location,
        ConnectedPeerEntries, DataCore,
    },
    retroshare_compat::ssl_key::SslKey,
    services::{HandlePacketResult, Services},
    transport_ng::ConnectionType,
    utils::{self, simple_stats::StatsCollection},
};

use self::connected_peer::ConnectedPeer;

pub mod connected_peer;

pub struct CoreController {
    data_core: Arc<DataCore>,
    services: Services,

    tx_core: UnboundedSender<Intercom>,
    rx_core: UnboundedReceiver<Intercom>,

    pending_connection_attempts: ConnectedPeerEntries,
}

impl CoreController {
    pub async fn new(data_core: Arc<DataCore>) -> Self {
        let (tx_core, rx_core) = unbounded_channel();
        let services = Services::get_core_services(&data_core, tx_core.clone()).await;

        if log::log_enabled!(log::Level::Info) {
            info!("Core starting ...");
            info!("registered core services:");
            for s in services.get_services() {
                info!(" - {:04X?}: {}", s.get_id() as u16, s.get_service_info().0);
            }
        }

        CoreController {
            data_core,
            services,

            rx_core,
            tx_core,

            pending_connection_attempts: ConnectedPeerEntries::default(),
        }
    }

    pub async fn run(&mut self) -> ! {
        let mut timer_services_2500ms = interval(Duration::from_millis(250));
        let mut timer_slow_5s = interval(Duration::from_secs(5));
        let mut stats: StatsCollection = (Instant::now(), HashMap::new());

        loop {
            let queue = self.rx_core.recv();
            let tick = timer_services_2500ms.tick();
            let tick_slow = timer_slow_5s.tick();

            select! {
                _ = tick => {
                    trace!("tick");

                    self.tick(&mut stats).await;
                }
                _ = tick_slow => {
                    trace!("tick_slow");

                    // Stats
                    if log::log_enabled!(log::Level::Trace) {
                        utils::simple_stats::print(&stats);
                    }
                    stats.0 = Instant::now();
                    stats.1.clear();

                    // reconnects
                    self.check_reconnects().await;

                    // FIXME
                    self.data_core.webui_send(
                        EventType::PeerStateChanged { ssl_id: "d6fb6c0f53d18303dcc9043111490e40".into() }
                    ).await;
                }
                msg = queue => {
                    trace!("queue");

                    match msg {
                        Some(msg) => self.handle_message(&msg).await,
                        None => {}
                    }
                }
            }
        }
    }

    async fn tick(&mut self, stats: &mut StatsCollection) {
        // handle services
        if let Some(items) = self.services.tick_all(stats) {
            // this can be optimazed probably
            for item in items {
                self.data_core.try_send_to_peer(item).await;
            }
        }
    }

    async fn handle_message(&mut self, msg: &Intercom) {
        trace!("handle_message {msg:?}");
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
                                if let Some((peer_tx, handler)) =
                                    self.pending_connection_attempts.0.remove(loc)
                                {
                                    info!("[core] booted up location {loc}");
                                    // self.data_core
                                    //     .connected_peer_add(loc.clone(), peer_tx, handler)
                                    //     .await;
                                    self.data_core
                                        .get_connected_peers()
                                        .lock()
                                        .await
                                        .0
                                        .insert(loc.to_owned(), (peer_tx, handler));
                                } else {
                                    log::error!(
                                        "[core] unable to find booted up {loc} in pending list!"
                                    );
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

                // handle event listener
                for subscriber in self.data_core.event_listener.lock().await.iter() {
                    subscriber
                        .send(Intercom::PeerUpdate(state.clone()))
                        .expect("failed to communicate with service");
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

                match self.services.handle_packet(packet.to_owned(), true).await {
                    // packet was locally handled and an answer was generated
                    HandlePacketResult::Handled(Some(answer)) => {
                        self.data_core.try_send_to_peer(answer).await
                    }
                    // packet was locally handled and no answer was generated
                    HandlePacketResult::Handled(None) => {}
                    // packet was not locally handled as no fitting service was found
                    HandlePacketResult::NotHandled(packet) => {
                        warn!(
                            "[core] core received a packet that cannot be handled! {:?}",
                            packet.header
                        );
                    }
                    // something else went wrong
                    HandlePacketResult::Error(why) => {
                        warn!("[core] failed to handle packet: {why:?}")
                    }
                }
            }
            cmd => {
                warn!("[core] unhandled command: {cmd:?}");
            }
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
            let (builder, handler_tx) = ConnectionBuilder::new(&self, candidate.clone());
            let handler = tokio::spawn(builder.connect());
            self.pending_connection_attempts
                .0
                .insert(candidate.get_location_id(), (handler_tx, handler));
        }
    }
}

struct ConnectionBuilder {
    peer_location: Arc<Location>,
    // own_peer_id: Arc<PeerId>,
    own_key_pair: SslKey,
    outer_tx: UnboundedSender<Intercom>,
    inner_rx: UnboundedReceiver<Intercom>,
    global_services: Vec<RsServiceInfo>,
}

impl ConnectionBuilder {
    pub fn new(
        cc: &CoreController,
        peer_location: Arc<Location>,
    ) -> (Self, UnboundedSender<Intercom>) {
        let own_peer_id = cc.data_core.get_own_location().get_location_id();
        let own_key_pair = cc.data_core.get_own_keypair().to_owned();
        let outer_tx = cc.tx_core.clone();
        let (handler_tx, inner_rx) = unbounded_channel();
        let global_services = cc.services.get_service_infos();

        assert_ne!(peer_location.get_location_id(), own_peer_id);

        (
            ConnectionBuilder {
                peer_location,
                // own_peer_id,
                own_key_pair,
                outer_tx,
                inner_rx,
                global_services,
            },
            handler_tx,
        )
    }

    async fn connect(self) {
        // turn IPs into ConnectionType::Tcp
        let ips = {
            let ips = self.peer_location.get_ips();
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
            local
        };

        let _loc_id = self.peer_location.get_location_id().to_owned();
        let loc_key = self.peer_location.get_person().get_pgp().to_owned();

        // try to connect
        if let Ok(con) = crate::transport_ng::Connection::new(
            &self.own_key_pair,
            loc_key,
            self.peer_location.get_name(),
        ) {
            for ip in ips {
                if let Ok(tls_stream) = con.connect(ip).await {
                    ConnectedPeer::run(
                        self.inner_rx,
                        self.outer_tx.to_owned(),
                        tls_stream,
                        self.peer_location.clone(),
                        self.global_services,
                    )
                    .await;
                    break;
                }
            }
        } else {
            warn!("failed to connect to {}", self.peer_location.get_name());
        }

        // failed to connect or disconnected
        self.outer_tx
            .send(Intercom::PeerUpdate(PeerUpdate::Status(
                PeerState::NotConnected(self.peer_location.get_location_id()),
            )))
            .expect("failed to send");
    }
}
