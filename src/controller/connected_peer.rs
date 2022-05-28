use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};

use log::{debug, info, trace, warn};
use retroshare_compat::services::service_info::RsServiceInfo;
use tokio::{
    io::{self, split, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::mpsc::{UnboundedReceiver, UnboundedSender},
    time::interval,
};

use crate::{
    error::RsError,
    low_level_parsing::{
        headers::{Header, HEADER_SIZE},
        parser_network::Parser,
        Packet,
    },
    model::{
        intercom::{Intercom, PeerState, PeerUpdate},
        location::Location,
    },
    services::{service_info, HandlePacketResult, Services},
    utils::simple_stats::StatsCollection,
};

pub struct ConnectedPeer {}

impl ConnectedPeer {
    pub async fn run<T: AsyncRead + AsyncWrite>(
        mut receiv: UnboundedReceiver<Intercom>,
        send: UnboundedSender<Intercom>,
        tls_stream: T,
        location: Arc<Location>,
        mut global_services: Vec<RsServiceInfo>,
    ) {
        let (mut stream_read, mut stream_write) = split(tls_stream);

        let mut services = Services::get_peer_services().await;
        let mut parser = Parser::new(location.get_location_id());

        let mut service_infos = services.get_service_infos();
        service_infos.append(&mut global_services);

        let mut timer = interval(Duration::from_millis(250));

        // boot up
        // send through parser
        let packet = service_info::gen_service_info(&service_infos);
        ConnectedPeer::send_packet(&mut stream_write, &mut parser, packet)
            .await
            .expect("failed to send");

        send.send(Intercom::PeerUpdate(PeerUpdate::Status(
            PeerState::Connected(
                location.get_location_id(),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0),
            ),
        )))
        .expect("failed to send");

        if log::log_enabled!(log::Level::Info) {
            info!("Peer ({}) starting ...", location.get_name());
            info!("registered core services:");
            for s in services.get_services() {
                info!(" - {:04X?}: {}", s.get_id() as u16, s.get_service_info().0);
            }
        }

        // enter main loop
        loop {
            let net_fut = ConnectedPeer::receive_packet(&mut stream_read);
            let queue_fut = receiv.recv();
            let tick = timer.tick();

            tokio::select! {
                res = net_fut => {
                    trace!("net");

                    match res {
                        Ok((header, payload)) => {
                            if let Some(packet) = parser.handle_incoming_packet(header, payload) {
                                trace!("handling packet {packet:?}");

                                // try to handle local service first
                                // when no local service is able to handle the packet, send it to the core
                                match services.handle_packet(packet, false).await {
                                    // packet was locally handled and an answer was generated
                                    HandlePacketResult::Handled(Some(mut answer)) => {
                                        if log::log_enabled!(log::Level::Debug) {
                                            // local services only send packets to the connected peer
                                            if !answer.has_location() {
                                                answer.peer_id = location.get_location_id();
                                            }
                                        }
                                        ConnectedPeer::send_packet(&mut stream_write, &mut parser, answer).await.expect("failed to send");}
                                    // packet was locally handled and no answer was generated
                                    HandlePacketResult::Handled(None) => {}
                                    // packet was not locally handled as no fitting service was found
                                    HandlePacketResult::NotHandled(packet) => {
                                        // send packet to core for central processing
                                        send.send(Intercom::Receive(packet)).expect("failed to send")
                                    }
                                    // something else went wrong
                                    HandlePacketResult::Error(why) => {
                                        warn!("[peer] failed to handle packet: {why:?}")
                                    }
                                }
                            }
                        }
                        Err(err) => {warn!("[peer] failed to read packet: {err:?}");
                            return;
                        }
                    }
                }
                res = queue_fut => {
                    trace!("queue");

                    match res {
                        Some(msg) =>   match msg {
                            Intercom::Send(packet) => ConnectedPeer::send_packet(&mut stream_write, &mut parser, packet).await.expect("failed to send"),
                            msg => panic!("not implemented, received {msg:?}"),
                        },
                        None => {}
                    }

                }
                _ = tick => {
                    trace!("tick");
                    let mut stats_dummy: StatsCollection = (Instant::now(), HashMap::new());

                    // handle service ticks
                    if let Some(items) = services.tick_all(&mut stats_dummy).await {
                        for mut item in items {
                            if log::log_enabled!(log::Level::Debug) {
                                // local services only send packets to the connected peer
                                if !item.has_location() {
                                    item.peer_id = location.get_location_id();
                                }
                            }
                            ConnectedPeer::send_packet(&mut stream_write, &mut parser, item).await.expect("failed to send");
                        }
                    }
                }
            }
        }
    }

    async fn receive_packet<T: AsyncRead + std::marker::Unpin>(
        stream: &mut T,
    ) -> Result<(Header, Vec<u8>), RsError> {
        // read header
        let mut header = [0; HEADER_SIZE]; // type + size
        match stream.read_exact(&mut header).await? {
            0 => {
                warn!("[peer] zero read");
                Err(std::io::Error::from(std::io::ErrorKind::ConnectionReset).into())
            }
            HEADER_SIZE => {
                debug!(">>> got header {HEADER_SIZE} bytes {header:02X?}");

                // parse header
                let header = Header::try_parse(&header)?;

                let payload_size = header.get_payload_size();
                debug!(">>> reading {} bytes payload", payload_size);
                let mut payload = vec![];
                payload.resize(payload_size, 0);

                let len = stream.read_exact(payload.as_mut_slice()).await?;
                assert_eq!(payload_size, len);

                trace!(">>> read: {payload:02X?}");
                Ok((header, payload))
            }
            length => {
                log::error!("unable to read full header, only got {length} bytes: {header:02X?}");
                // fail graceful one day?
                panic!("can't hanlde too short");
            }
        }
    }

    async fn send_packet<T: AsyncWrite + std::marker::Unpin>(
        stream: &mut T,
        parser: &mut Parser,
        packet: Packet,
    ) -> io::Result<()> {
        debug!("<<< send_packet to {}", packet.peer_id);
        debug!("<<< header {:?}", packet.header);
        trace!("<<< payload {:02X?}", packet.payload);

        for packet in parser.handle_outgoign_packet(packet) {
            stream.write_all(&packet).await?;
        }
        stream.flush().await
    }
}
