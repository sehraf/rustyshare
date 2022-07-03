use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
};

use log::{debug, info, trace, warn};
use retroshare_compat::services::service_info::RsServiceInfo;
use tokio::{
    io::{self, split, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender},
    task::JoinHandle,
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
    retroshare_compat::ssl_key::SslKey,
    services::{service_info, Services},
    transport_ng::ConnectionType,
};

use super::CoreController;

pub struct ConnectedPeer {}

impl ConnectedPeer {
    pub async fn run<T: AsyncRead + AsyncWrite>(
        mut rx: UnboundedReceiver<Intercom>,
        peer_tx: UnboundedSender<Intercom>, // requires own tx for services
        core_tx: UnboundedSender<Intercom>,
        tls_stream: T,
        location: Arc<Location>,
        mut global_services: Vec<RsServiceInfo>,
    ) {
        let (mut stream_read, mut stream_write) = split(tls_stream);

        let mut services = Services::get_peer_services(core_tx.to_owned(), peer_tx).await;
        let mut parser = Parser::new(location.get_location_id());

        let mut service_infos = services.get_service_infos();
        service_infos.append(&mut global_services);

        // boot up
        // send through parser
        let packet = service_info::ServiceInfo::gen_service_info(&service_infos);
        ConnectedPeer::send_packet(&mut stream_write, &mut parser, packet)
            .await
            .expect("failed to send");

        core_tx
            .send(Intercom::PeerUpdate(PeerUpdate::Status(
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
                info!(" - {:04X?}: {:?}", s as u16, s);
            }
        }

        // enter main loop
        loop {
            let net_fut = ConnectedPeer::receive_packet(&mut stream_read);
            let queue_fut = rx.recv();

            tokio::select! {
                res = net_fut => {
                    trace!("net");

                    match res {
                        Ok((header, payload)) => {
                            if let Some(packet) = parser.handle_incoming_packet(header, payload) {
                                trace!("handling packet {packet:?}");

                                // if there is no fitting peer service, the packet will be forwarded to the core
                                services.handle_packet(packet).await;
                            }
                        }
                        Err(err) => {

                        warn!("[peer] failed to read packet: {err:?}");
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
                // parse header
                let header = Header::try_parse(&header)?;
                debug!(">>> got header {header:?}");

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

pub(super) struct ConnectionBuilder {
    peer_location: Arc<Location>,
    // own_peer_id: Arc<PeerId>,
    own_key_pair: SslKey,

    core_tx: UnboundedSender<Intercom>,

    peer_rx: UnboundedReceiver<Intercom>,
    peer_tx: UnboundedSender<Intercom>,

    global_services: Vec<RsServiceInfo>,
}

impl ConnectionBuilder {
    pub fn new(
        cc: &CoreController,
        peer_location: Arc<Location>,
    ) -> (Self, UnboundedSender<Intercom>) {
        let own_peer_id = cc.data_core.get_own_location().get_location_id();
        let own_key_pair = cc.data_core.get_own_keypair().to_owned();
        let core_tx = cc.core_tx.clone();
        let (peer_tx, peer_rx) = unbounded_channel();
        let global_services = cc.services.get_service_infos();

        assert_ne!(peer_location.get_location_id(), own_peer_id);

        (
            ConnectionBuilder {
                peer_location,
                // own_peer_id,
                own_key_pair,

                core_tx,

                peer_rx,
                peer_tx: peer_tx.to_owned(),

                global_services,
            },
            peer_tx,
        )
    }

    pub(super) async fn connect(self) -> Option<JoinHandle<()>> {
        trace!("trying to connect to {}", self.peer_location.get_name());
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
                trace!(
                    "trying to connect to {} with ip {:?}",
                    self.peer_location.get_name(),
                    ip
                );

                if let Ok(tls_stream) = con.connect(ip).await {
                    trace!("connected to {}!", self.peer_location.get_name());

                    return Some(tokio::spawn(async move {
                        ConnectedPeer::run(
                            self.peer_rx,
                            self.peer_tx,
                            self.core_tx.to_owned(),
                            tls_stream,
                            self.peer_location.clone(),
                            self.global_services,
                        )
                        .await;

                        // disconnected
                        self.core_tx
                            .send(Intercom::PeerUpdate(PeerUpdate::Status(
                                PeerState::NotConnected(self.peer_location.get_location_id()),
                            )))
                            .expect("failed to send");
                    }));
                }
            }
        } else {
            warn!("failed to connect to {}", self.peer_location.get_name());

            // failed to connect
            self.core_tx
                .send(Intercom::PeerUpdate(PeerUpdate::Status(
                    PeerState::NotConnected(self.peer_location.get_location_id()),
                )))
                .expect("failed to send");
        }
        None
    }
}
