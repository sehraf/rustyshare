use retroshare_compat::{basics::PeerId, discovery::*, serde::from_retroshare_wire, tlv::*};
use std::{
    collections::HashSet,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{mpsc, Arc},
};

use crate::{
    model::{peers::Peer, DataCore, PeerCommand, PeerState, PeerUpdate},
    parser::{
        headers::{ServiceHeader, HEADER_SIZE},
        Packet,
    },
    services::{HandlePacketResult, Service},
    utils::simple_stats::StatsCollection,
};

const DISCOVERY_SERVICE: u16 = 0x0011;
const DISCOVERY_SUB_TYP_PGP_LIST: u8 = 0x01;
const DISCOVERY_SUB_TYP_PGP_CERT: u8 = 0x02;
const DISCOVERY_SUB_TYP_CONTACT: u8 = 0x05; // deprecated
const DISCOVERY_SUB_TYP_IDENTITY_LIST: u8 = 0x06;
const DISCOVERY_SUB_TYP_PGP_CERT_BINARY: u8 = 0x09;

pub struct Discovery {
    own_id: PeerId,

    data_core: mpsc::Sender<PeerCommand>,
    persons: Vec<Arc<Peer>>,
    info: DiscContactItem,

    events: mpsc::Receiver<PeerCommand>,
}

impl Discovery {
    pub fn new(dc: &mut DataCore) -> Discovery {
        let (tx, rx) = mpsc::channel();
        dc.subscribe_for_events(tx);

        let mut d = Discovery {
            own_id: dc.get_own_location().get_location_id().clone(),

            data_core: dc.get_tx(),
            persons: dc.get_persons().clone(),
            info: DiscContactItem::default(),

            events: rx,
        };

        // received RsDiscContactItem: RsDiscContactItem {
        // pgp_id: PgpId([96, 223, 128, 88, 155, 148, 153, 89]),
        // ssl_id: PeerId([101, 211, 59, 199, 190, 225, 139, 113, 51, 100, 176, 48, 29, 190, 216, 150]),
        // location: "Hugo",
        // version: "0.6.6-8-g67c607cb3",
        // net_mode: 1,
        // vs_disc: 2,
        // vs_dht: 2,
        // last_contact: 1616850081,
        // is_hidden: false,
        // hidden_addr: "", hidden_port: 0,
        // current_connect_address: TlvIpAddress(0.0.0.0:0),
        // local_addr_v4: TlvIpAddress(192.168.42.105:55123),
        // ext_addr_v4: TlvIpAddress(91.43.19.236:55123),
        // local_addr_v6: TlvIpAddress(0.0.0.0:0),
        // ext_addr_v6: TlvIpAddress(0.0.0.0:0),
        // dyndns: "",
        // local_addr_list: TlvIpAddrSet({
        //     TlvIpAddressInfo { addr: TlvIpAddress([d200:320:5eac:187f:ff99:2eb6:11ea:efe]:55123), seen_time: 1616701582, source: 0 },
        //     TlvIpAddressInfo { addr: TlvIpAddress(192.168.42.105:55123), seen_time: 1616849042, source: 0 },
        //     TlvIpAddressInfo { addr: TlvIpAddress([d200:320:b47b:e7f:57af:fe8e:e71c:e1]:55123), seen_time: 1600017243, source: 0 },
        //     TlvIpAddressInfo { addr: TlvIpAddress([d200:320:94f5:257f:ff99:2eb6:11ea:efe]:55123), seen_time: 1616849042, source: 0 },
        //     TlvIpAddressInfo { addr: TlvIpAddress([d200:320:b47b:e7f:ff99:2eb6:11ea:efe]:55123), seen_time: 1600017243, source: 0 },
        //     TlvIpAddressInfo { addr: TlvIpAddress([d200:320:5eac:187f:1e05:f36c:8380:e46e]:55123), seen_time: 1616701582, source: 0 },
        //     TlvIpAddressInfo { addr: TlvIpAddress([d200:320:94f5:257f:159e:43fa:f409:6f8a]:55123), seen_time: 1616849042, source: 0 },
        //     TlvIpAddressInfo { addr: TlvIpAddress([d200:320:679:17f:ff99:2eb6:11ea:efe]:55123), seen_time: 1606244239, source: 0 },
        //     TlvIpAddressInfo { addr: TlvIpAddress([d200:320:e360:3f7f:ff99:2eb6:11ea:efe]:55123), seen_time: 1596289768, source: 0 },
        //     TlvIpAddressInfo { addr: TlvIpAddress([d200:320:679:17f:10d5:7ccf:f44:952d]:55123), seen_time: 1606244239, source: 0 }}),
        // ext_addr_list: TlvIpAddrSet({
        //     TlvIpAddressInfo { addr: TlvIpAddress(217.254.174.205:55123), seen_time: 1613685040, source: 0 },
        //     TlvIpAddressInfo { addr: TlvIpAddress(93.225.68.235:55123), seen_time: 1616849015, source: 0 },
        //     TlvIpAddressInfo { addr: TlvIpAddress(93.225.70.127:55123), seen_time: 1600017243, source: 0 },
        //     TlvIpAddressInfo { addr: TlvIpAddress(93.225.69.66:55123), seen_time: 1589118155, source: 0 },
        //     TlvIpAddressInfo { addr: TlvIpAddress(91.43.22.49:55123), seen_time: 1588071911, source: 0 },
        //     TlvIpAddressInfo { addr: TlvIpAddress(217.254.175.131:55123), seen_time: 1587197128, source: 0 },
        //     TlvIpAddressInfo { addr: TlvIpAddress(91.43.19.236:55123), seen_time: 1616849042, source: 0 },
        //     TlvIpAddressInfo { addr: TlvIpAddress(91.43.19.72:55123), seen_time: 1595096198, source: 0 },
        //     TlvIpAddressInfo { addr: TlvIpAddress(217.254.170.107:55123), seen_time: 1596289768, source: 0 },
        //     TlvIpAddressInfo { addr: TlvIpAddress(217.254.164.41:55123), seen_time: 1594847179, source: 0 }}) }

        d.info.pgp_id = dc.get_own_person().get_pgp_id().clone();
        d.info.ssl_id = d.own_id.clone();
        d.info.version = String::from("RustyShare 0.0.dontask");
        d.info.location = String::from("Win");

        d.info.net_mode = 4;
        d.info.vs_dht = VsDht::Off as u16;
        d.info.vs_disc = VsDisc::Full as u16;

        let me = dc.get_own_location();
        let ips = me.get_ips();

        d.info.local_addr_v4 = TlvIpAddress(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(0)), 1337));
        d.info.ext_addr_v4 = TlvIpAddress(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(0)), 1337));

        d.info.local_addr_list = TlvIpAddrSet(HashSet::new());
        for local in &*ips.0 {
            d.info.local_addr_list.0.insert(TlvIpAddressInfo {
                addr: local.addr.to_owned(),
                seen_time: 0,
                source: 0,
            });
        }
        d.info.ext_addr_list = TlvIpAddrSet(HashSet::new());
        for local in &*ips.1 {
            d.info.local_addr_list.0.insert(TlvIpAddressInfo {
                addr: local.addr.to_owned(),
                seen_time: 0,
                source: 0,
            });
        }

        d
    }

    pub fn handle_incoming(
        &self,
        header: &ServiceHeader,
        mut packet: Packet,
    ) -> HandlePacketResult {
        match header.sub_type {
            DISCOVERY_SUB_TYP_CONTACT => {
                let item = read_rs_disc_contact_item(&mut packet.payload);
                // println!("received DiscContactItem: {}", item);
                // println!("pgp_id: {}", item.pgp_id);
                // println!("ssl_id: {}", item.ssl_id);

                if item.ssl_id == self.own_id {
                    // describung us self
                    println!("[Discovery] DiscContactItem: received our info");
                } else {
                    return self.handle_peer_contect(&item, packet.peer_id);
                }
            }
            DISCOVERY_SUB_TYP_IDENTITY_LIST => {
                let _item: RsDiscIdentityListItem =
                    from_retroshare_wire(&mut packet.payload).expect("failed to deserialize");
                // println!("received DiscIdentityListItem: {}", item);
            }
            DISCOVERY_SUB_TYP_PGP_LIST
            | DISCOVERY_SUB_TYP_PGP_CERT
            | DISCOVERY_SUB_TYP_PGP_CERT_BINARY => {
                println!("[Discovery] received {:?}", header);
            }
            sub_type => {
                println!("[Discovery] recevied unknown sub typ {}", sub_type);
            }
        }
        HandlePacketResult::Handled(None)
    }

    fn handle_peer_contect(&self, contact: &DiscContactItem, from: PeerId) -> HandlePacketResult {
        if contact.ssl_id == from {
            // describing theirself
            if contact.vs_disc != VsDisc::Off as u16 {
                // send own DISCOVERY_SUB_TYP_PGP_LIST
                let mut item = DiscPgpListItem {
                    mode: GossipDiscoveryPgpListMode::Friends,
                    pgp_id_set: TlvPgpIdSet(HashSet::new()),
                };

                for p in &self.persons {
                    item.pgp_id_set.0.insert(p.get_pgp_id().to_owned());
                }

                let payload = write_disc_pgp_list_item(&item);

                let header = ServiceHeader {
                    service: DISCOVERY_SERVICE,
                    size: (payload.len() + HEADER_SIZE) as u32,
                    sub_type: DISCOVERY_SUB_TYP_PGP_LIST,
                }
                .into();

                return HandlePacketResult::Handled(Some(Packet::new(header, payload, from)));
            }
        } else {
            // describing someone else
            // println!(
            //     "DiscContactItem: received common friend peer info {}",
            //     contact.ssl_id
            // );

            let local = contact.local_addr_list.0.to_owned();
            let external = contact.ext_addr_list.0.to_owned();
            self.data_core
                .send(PeerCommand::PeerUpdate(PeerUpdate::Address(
                    contact.ssl_id,
                    local,
                    external,
                )))
                .expect("failed to communicate with core");
        }

        HandlePacketResult::Handled(None)
    }
}

impl Service for Discovery {
    fn get_id(&self) -> u16 {
        DISCOVERY_SERVICE
    }

    fn handle_packet(&self, packet: Packet) -> HandlePacketResult {
        self.handle_incoming(&packet.header.into(), packet)
    }

    fn tick(&mut self, _stats: &mut StatsCollection) -> Option<Vec<Packet>> {
        let mut out: Vec<Packet> = vec![];

        while let Ok(cmd) = self.events.try_recv() {
            match cmd {
                PeerCommand::PeerUpdate(PeerUpdate::Status(PeerState::Connected(loc, _addr))) => {
                    let mut payload = vec![];
                    // self.info.current_connect_address = addr.into();// ?!?!
                    // println!("{}", &self.info);
                    write_rs_disc_contact_item(&mut payload, &self.info);

                    let packet = Packet::new(
                        ServiceHeader::new(DISCOVERY_SERVICE, DISCOVERY_SUB_TYP_CONTACT, &payload)
                            .into(),
                        payload,
                        loc.clone(),
                    );

                    out.push(packet);
                    println!("[Discovery] sending contact info to {}", loc);
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
