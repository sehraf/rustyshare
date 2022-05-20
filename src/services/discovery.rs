use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
};

use async_trait::async_trait;
use log::{debug, info, warn};
use retroshare_compat::{
    basics::SslId,
    serde::{from_retroshare_wire, to_retroshare_wire},
    services::discovery::*,
    tlv::{
        tlv_ip_addr::{TlvIpAddrSet, TlvIpAddress},
        tlv_set::TlvPgpIdSet,
    },
};
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};

use crate::{
    handle_packet,
    model::{
        intercom::{Intercom, PeerState, PeerUpdate},
        person::Peer,
        DataCore,
    },
    parser::{headers::ServiceHeader, Packet},
    services::{HandlePacketResult, Service},
    utils::simple_stats::StatsCollection,
};

use super::ServiceType;

const DISCOVERY_SUB_TYPE_PGP_LIST: u8 = 0x01;
const DISCOVERY_SUB_TYPE_PGP_CERT: u8 = 0x02;
const DISCOVERY_SUB_TYPE_CONTACT: u8 = 0x05; // deprecated
const DISCOVERY_SUB_TYPE_IDENTITY_LIST: u8 = 0x06;
const DISCOVERY_SUB_TYPE_PGP_CERT_BINARY: u8 = 0x09;

pub struct Discovery {
    own_id: Arc<SslId>,

    core_tx: UnboundedSender<Intercom>,
    events_rx: UnboundedReceiver<Intercom>,

    persons: Vec<Arc<Peer>>,
    info: DiscContactItem,
}

impl Discovery {
    pub async fn new(dc: &Arc<DataCore>, core_tx: UnboundedSender<Intercom>) -> Discovery {
        let (tx, rx) = unbounded_channel();
        dc.events_subscribe(tx).await;

        let mut d = Discovery {
            own_id: dc.get_own_location().get_location_id().clone(),

            core_tx,
            events_rx: rx,

            persons: dc.get_persons().clone(),
            info: DiscContactItem::default(),
        };

        d.info.pgp_id = dc.get_own_person().get_pgp_id().clone();
        d.info.ssl_id = *d.own_id.to_owned();
        // d.info.version = String::from("RustyShare 0.0.dontask");
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

        let me = dc.get_own_location();
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

    pub async fn handle_incoming(
        &self,
        header: &ServiceHeader,
        mut packet: Packet,
    ) -> HandlePacketResult {
        match header.sub_type {
            DISCOVERY_SUB_TYPE_CONTACT => {
                let item = read_rs_disc_contact_item(&mut packet.payload);
                // println!("received DiscContactItem: {}", item);
                // println!("pgp_id: {}", item.pgp_id);
                // println!("ssl_id: {}", item.ssl_id);

                if item.ssl_id == *self.own_id {
                    // describung us self
                    info!("[Discovery] DiscContactItem: received our info");
                } else {
                    return self
                        .handle_peer_contact(&item, packet.peer_id.clone())
                        .await;
                }
            }
            DISCOVERY_SUB_TYPE_IDENTITY_LIST => {
                let item: DiscIdentityListItem =
                    from_retroshare_wire(&mut packet.payload).expect("failed to deserialize");
                info!("received DiscIdentityListItem: {item}");
            }
            DISCOVERY_SUB_TYPE_PGP_LIST
            | DISCOVERY_SUB_TYPE_PGP_CERT
            | DISCOVERY_SUB_TYPE_PGP_CERT_BINARY => {
                info!("[Discovery] received {header:?}");
            }
            sub_type => {
                warn!("[Discovery] recevied unknown sub typ {sub_type}");
            }
        }
        handle_packet!()
    }

    async fn handle_peer_contact(
        &self,
        contact: &DiscContactItem,
        from: Arc<SslId>,
    ) -> HandlePacketResult {
        if contact.ssl_id == *from {
            // describing theirself
            if contact.vs_disc != VsDisc::Off as u16 {
                // send own DISCOVERY_SUB_TYPE_PGP_LIST
                let mut item = DiscPgpListItem {
                    mode: GossipDiscoveryPgpListMode::Friends,
                    pgp_id_set: TlvPgpIdSet::default(),
                };

                for p in &self.persons {
                    item.pgp_id_set.0.insert(p.get_pgp_id().to_owned());
                }

                let payload = to_retroshare_wire(&item).expect("failed to serializes");
                let header = ServiceHeader::new(
                    ServiceType::Discovery,
                    DISCOVERY_SUB_TYPE_PGP_LIST,
                    &payload,
                )
                .into();
                return handle_packet!(Packet::new(header, payload, from));
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

        HandlePacketResult::Handled(None)
    }
}

#[async_trait]
impl Service for Discovery {
    fn get_id(&self) -> ServiceType {
        ServiceType::Discovery
    }

    async fn handle_packet(&self, packet: Packet) -> HandlePacketResult {
        debug!("handle_packet");

        self.handle_incoming(&packet.header.into(), packet).await
    }

    fn tick(&mut self, _stats: &mut StatsCollection) -> Option<Vec<Packet>> {
        let mut out: Vec<Packet> = vec![];

        while let Ok(cmd) = self.events_rx.try_recv() {
            match cmd {
                Intercom::PeerUpdate(PeerUpdate::Status(PeerState::Connected(loc, _addr))) => {
                    let mut payload = vec![];

                    write_rs_disc_contact_item(&mut payload, &self.info);

                    let packet = Packet::new(
                        ServiceHeader::new(
                            ServiceType::Discovery,
                            DISCOVERY_SUB_TYPE_CONTACT,
                            &payload,
                        )
                        .into(),
                        payload,
                        loc.clone(),
                    );

                    out.push(packet);
                    info!("[Discovery] sending contact info to {loc}");
                }
                // we don't care for the rest!
                _ => {}
            }
        }

        if out.is_empty() {
            return None;
        }
        Some(out)
    }

    fn get_service_info(&self) -> (String, u16, u16, u16, u16) {
        (String::from("disc"), 1, 0, 1, 0)
    }
}
