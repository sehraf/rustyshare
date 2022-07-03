use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
};

use async_trait::async_trait;
use log::{debug, info, trace, warn};
use retroshare_compat::{
    basics::SslId,
    serde::{from_retroshare_wire, to_retroshare_wire},
    services::{discovery::*, service_info::RsServiceInfo},
    tlv::{
        tlv_ip_addr::{TlvIpAddrSet, TlvIpAddress},
        tlv_set::TlvPgpIdSet,
    },
};
use tokio::{
    select,
    sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender},
    task::JoinHandle,
};

use crate::{
    low_level_parsing::{headers::ServiceHeader, Packet},
    model::{
        intercom::{Intercom, PeerState, PeerUpdate},
        person::Peer,
        DataCore,
    },
    send_to_core,
    services::Service,
};

use ::retroshare_compat::services::ServiceType;

const DISCOVERY_SUB_TYPE_PGP_LIST: u8 = 0x01;
const DISCOVERY_SUB_TYPE_PGP_CERT: u8 = 0x02;
#[deprecated]
const DISCOVERY_SUB_TYPE_CONTACT: u8 = 0x05;
const DISCOVERY_SUB_TYPE_IDENTITY_LIST: u8 = 0x06;
const DISCOVERY_SUB_TYPE_PGP_CERT_BINARY: u8 = 0x09;

pub struct Discovery {
    rx: UnboundedReceiver<Intercom>,

    own_id: Arc<SslId>,

    core_tx: UnboundedSender<Intercom>,
    events_rx: UnboundedReceiver<Intercom>,

    persons: Vec<Arc<Peer>>,
    info: DiscContactItem,
}

impl Discovery {
    pub async fn new(
        core: &Arc<DataCore>,
        core_tx: UnboundedSender<Intercom>,
        rx: UnboundedReceiver<Intercom>,
    ) -> Discovery {
        let (tx_events, rx_events) = unbounded_channel();
        core.events_subscribe(tx_events).await;

        let mut d = Discovery {
            rx,

            own_id: core.get_own_location().get_location_id().clone(),

            core_tx,
            events_rx: rx_events,

            persons: core.get_persons().clone(),
            info: DiscContactItem::default(),
        };

        d.info.pgp_id = core.get_own_person().get_pgp_id().clone();
        d.info.ssl_id = *d.own_id.to_owned();
        d.info.version = format!(
            "{} {}",
            env!("CARGO_PKG_VERSION"),
            env!("CARGO_PKG_VERSION")
        )
        .into();
        d.info.location = String::from("Pluto").into();

        d.info.net_mode = 4;
        d.info.vs_dht = VsDht::Off as u16;
        d.info.vs_disc = VsDisc::Full as u16;

        let me = core.get_own_location();
        let ips = me.get_ips();

        d.info.local_addr_v4 = TlvIpAddress(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(0)), 1337));
        d.info.ext_addr_v4 = TlvIpAddress(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(0)), 1337));

        d.info.local_addr_list = TlvIpAddrSet::default();
        for local in &*ips.0 {
            d.info.local_addr_list.0.insert(
                retroshare_compat::tlv::tlv_ip_addr::TlvIpAddressInfoInner {
                    addr: local.addr.to_owned(),
                    seen_time: 0,
                    source: 0,
                }
                .into(),
            );
        }
        d.info.ext_addr_list = TlvIpAddrSet::default();
        for local in &*ips.1 {
            d.info.local_addr_list.0.insert(
                retroshare_compat::tlv::tlv_ip_addr::TlvIpAddressInfoInner {
                    addr: local.addr.to_owned(),
                    seen_time: 0,
                    source: 0,
                }
                .into(),
            );
        }

        d
    }

    fn handle_incoming(&self, header: &ServiceHeader, mut packet: Packet) {
        match header.sub_type {
            #[allow(deprecated)]
            DISCOVERY_SUB_TYPE_CONTACT => {
                let item = read_rs_disc_contact_item(&mut packet.payload);
                // println!("received DiscContactItem: {}", item);
                // println!("pgp_id: {}", item.pgp_id);
                // println!("ssl_id: {}", item.ssl_id);

                if item.ssl_id == *self.own_id {
                    // describing us self
                    info!("DiscContactItem: received our info");
                } else {
                    self.handle_peer_contact(&item, packet.peer_id.clone());
                }
            }
            DISCOVERY_SUB_TYPE_IDENTITY_LIST => {
                let item: DiscIdentityListItem = from_retroshare_wire(&mut packet.payload);
                info!("received DiscIdentityListItem: {item}");
            }
            DISCOVERY_SUB_TYPE_PGP_LIST
            | DISCOVERY_SUB_TYPE_PGP_CERT
            | DISCOVERY_SUB_TYPE_PGP_CERT_BINARY => {
                info!("received {header:?}");
            }
            sub_type => {
                warn!("received unknown sub typ {sub_type}");
            }
        }
    }

    fn handle_peer_contact(&self, contact: &DiscContactItem, from: Arc<SslId>) {
        if contact.ssl_id == *from {
            // describing themselves
            if contact.vs_disc != VsDisc::Off as u16 {
                // send own DISCOVERY_SUB_TYPE_PGP_LIST
                let mut item = DiscPgpListItem {
                    mode: GossipDiscoveryPgpListMode::Friends,
                    pgp_id_set: TlvPgpIdSet::default(),
                };

                for p in &self.persons {
                    item.pgp_id_set.0.insert(p.get_pgp_id().to_owned());
                }

                let payload = to_retroshare_wire(&item);
                let header =
                    ServiceHeader::new(self.get_id(), DISCOVERY_SUB_TYPE_PGP_LIST, &payload).into();

                send_to_core!(self, Packet::new(header, payload, from));
            }
        } else {
            // describing someone else
            debug!(
                "DiscContactItem: received common friend peer info {}",
                contact.ssl_id
            );

            let local = contact.local_addr_list.0.to_owned();
            let external = contact.ext_addr_list.0.to_owned();
            self.core_tx
                .send(Intercom::PeerUpdate(PeerUpdate::Address(
                    Arc::new(contact.ssl_id),
                    local,
                    external,
                )))
                .expect("failed to communicate with core");
        }
    }
}

#[async_trait]
impl Service for Discovery {
    fn get_id(&self) -> ServiceType {
        ServiceType::Discovery
    }

    fn get_service_info(&self) -> RsServiceInfo {
        RsServiceInfo::new(self.get_id().into(), "disc")
    }

    fn run(mut self) -> JoinHandle<()> {
        tokio::spawn(async move {
            loop {
                select! {
                    msg = self.rx.recv() => {
                        if let Some(msg) = msg {
                            trace!("handling msg {msg:?}");

                            match msg {
                                Intercom::Receive(packet) => self.handle_incoming(&packet.header.to_owned().into(), packet),
                                _ => warn!("unexpected message: {msg:?}"),
                            }
                        }
                    }
                    event = self.events_rx.recv() => {
                        if let Some(event) = event {
                            match event {
                                Intercom::PeerUpdate(PeerUpdate::Status(PeerState::Connected(loc, _addr))) => {
                                    // write_rs_disc_contact_item(&mut payload, &self.info);
                                    let payload = to_retroshare_wire(&self.info);
                                    let packet = Packet::new(
                                        // FIXME
                                        #[allow(deprecated)]
                                        ServiceHeader::new(self.get_id(), DISCOVERY_SUB_TYPE_CONTACT, &payload)
                                            .into(),
                                        payload,
                                        loc.clone(),
                                    );

                                    info!("sending contact info to {loc}");
                                    send_to_core!(self, packet);
                                }
                                // we don't care for the rest!
                                _ => {}
                            }
                        }
                    }
                }
            }
        })
    }
}
