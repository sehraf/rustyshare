use std::{
    collections::hash_map::{HashMap, Values},
    fmt::Display,
    sync::Arc,
};

pub mod bwctrl;
pub mod chat;
pub mod discovery;
pub mod heartbeat;
pub mod rtt;
pub mod service_info;
pub mod status;
pub mod turtle;
// mod _template;

use async_trait::async_trait;
use log::{trace, warn};
use retroshare_compat::services::service_info::RsServiceInfo;
use tokio::sync::mpsc::UnboundedSender;

use crate::{
    error::RsError,
    model::{intercom::Intercom, DataCore},
    parser::{headers::Header, Packet},
    utils::simple_stats::StatsCollection,
};

pub enum HandlePacketResult {
    Handled(Option<Packet>),
    NotHandled(Packet),
    Error(RsError),
}

/// Shorthand macros for creating HandlePacketResult
#[macro_export]
macro_rules! handle_packet {
    () => {
        HandlePacketResult::Handled(None)
    };
    ($packet:expr) => {
        HandlePacketResult::Handled(Some($packet))
    };
}

const SERVICE_BWCTRL: u16 = 0x0021;
const SERVICE_CHAT: u16 = 0x0012;
const SERVICE_DISCOVERY: u16 = 0x0011;
const SERVICE_HEARTBEAT: u16 = 0x0016;
const SERVICE_RTT: u16 = 0x1011;
const SERVICE_SERVICE_INFO: u16 = 0x0020;
const SERVICE_STATUS: u16 = 0x0102;
const SERVICE_TURTLE: u16 = 0x0014;

/// Special type only used for signaling
const SLICE_PROBE: u16 = 0xaabb;

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ServiceType {
    Unknown,

    BwCtrl = SERVICE_BWCTRL,
    Chat = SERVICE_CHAT,
    Discovery = SERVICE_DISCOVERY,
    Heartbeat = SERVICE_HEARTBEAT,
    Rtt = SERVICE_RTT,
    ServiceInfo = SERVICE_SERVICE_INFO,
    Status = SERVICE_STATUS,
    Turtle = SERVICE_TURTLE,

    SliceProbe = SLICE_PROBE,
}

impl From<&u16> for ServiceType {
    fn from(t: &u16) -> Self {
        use ServiceType::*;

        match *t {
            SERVICE_BWCTRL => BwCtrl,
            SERVICE_CHAT => Chat,
            SERVICE_DISCOVERY => Discovery,
            SERVICE_HEARTBEAT => Heartbeat,
            SERVICE_RTT => Rtt,
            SERVICE_SERVICE_INFO => ServiceInfo,
            SERVICE_STATUS => Status,
            SERVICE_TURTLE => Turtle,

            SLICE_PROBE => SliceProbe,

            x @ _ => {
                warn!("unkown service {x}");
                Unknown
            }
        }
    }
}

impl From<u16> for ServiceType {
    fn from(t: u16) -> Self {
        (&t).into()
    }
}

impl From<ServiceType> for u16 {
    fn from(s: ServiceType) -> Self {
        use ServiceType::*;

        match s {
            Unknown => panic!("service type 'unkown' cannot be converted"),

            BwCtrl => SERVICE_BWCTRL,
            Chat => SERVICE_CHAT,
            Discovery => SERVICE_DISCOVERY,
            Heartbeat => SERVICE_HEARTBEAT,
            Rtt => SERVICE_RTT,
            ServiceInfo => SERVICE_SERVICE_INFO,
            Status => SERVICE_STATUS,
            Turtle => SERVICE_TURTLE,

            SliceProbe => SLICE_PROBE,
        }
    }
}

impl Display for ServiceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use ServiceType::*;

        match self {
            Unknown => write!(f, "Unknown"),

            BwCtrl => write!(f, "BwCtrl"),
            Chat => write!(f, "Chat"),
            Discovery => write!(f, "Discovery"),
            Heartbeat => write!(f, "Heartbeat"),
            Rtt => write!(f, "Rtt"),
            ServiceInfo => write!(f, "ServiceInfo"),
            Status => write!(f, "Status"),
            Turtle => write!(f, "Turtle"),

            SliceProbe => write!(f, "SliceProbe"),
        }
    }
}

#[async_trait]
pub trait Service {
    fn get_id(&self) -> ServiceType;
    fn get_service_info(&self) -> (String, u16, u16, u16, u16);
    async fn handle_packet(&self, packet: Packet) -> HandlePacketResult;
    fn tick(&mut self, stats: &mut StatsCollection) -> Option<Vec<Packet>>;
}

pub struct Services(HashMap<ServiceType, Box<dyn Service + Sync + Send>>);

impl Services {
    pub fn new() -> Services {
        Services(HashMap::new())
    }

    pub fn get_peer_services() -> Services {
        let mut services = Services::new();

        let rtt = Box::new(rtt::Rtt::new());
        services.add_service(rtt);

        let service_info = Box::new(service_info::ServiceInfo::new());
        services.add_service(service_info);

        let heartbeat = Box::new(heartbeat::Heartbeat::new());
        services.add_service(heartbeat);

        let status = Box::new(status::Status::new());
        services.add_service(status);

        services
    }

    pub async fn get_core_services(
        dc: &Arc<DataCore>,
        core_tx: UnboundedSender<Intercom>,
    ) -> Services {
        let mut services = Services::new();

        let disc = Box::new(discovery::Discovery::new(dc, core_tx.clone()).await);
        services.add_service(disc);

        let turtle = Box::new(turtle::Turtle::new(dc, core_tx.clone()));
        services.add_service(turtle);

        let bwctrl = Box::new(bwctrl::BwCtrl::new(dc).await);
        services.add_service(bwctrl);

        let chat = Box::new(chat::Chat::new(dc, core_tx.clone()).await);
        services.add_service(chat);

        services
    }

    pub fn add_service(&mut self, service: Box<impl Service + Sync + Send + 'static>) {
        self.0.insert(service.get_id(), service);
    }

    pub async fn handle_packet(&self, packet: Packet, warn_unkown: bool) -> HandlePacketResult {
        trace!("handle_packet {packet:?}");

        match &packet.header {
            Header::Service { service, .. } => match self.0.get(&service) {
                Some(service) => return service.handle_packet(packet).await,
                None if warn_unkown => warn!("unable to handle service {service}"),
                None => (),
            },
            header => warn!("unable to handle non service header {header:?}"),
        }

        // return packet to caller
        HandlePacketResult::NotHandled(packet)
    }

    pub fn tick_all(&mut self, stats: &mut StatsCollection) -> Option<Vec<Packet>> {
        trace!("tick_all");

        let mut items: Vec<Packet> = vec![];

        for entry in self.0.iter_mut() {
            if let Some(mut packets) = entry.1.tick(stats) {
                items.append(&mut packets);
            }
        }

        if items.len() > 0 {
            return Some(items);
        } else {
            return None;
        }
    }

    #[allow(unused)]
    pub fn get_services(&self) -> Values<ServiceType, Box<dyn Service + Sync + Send>> {
        self.0.values()
    }

    pub fn get_service_infos(&self) -> Vec<RsServiceInfo> {
        self.0
            .iter()
            .map(|(_id, service)| {
                let info = service.get_service_info();
                let service_number = (0x02 as u32) << 24 | (service.get_id() as u32) << 8;

                RsServiceInfo {
                    m_service_name: info.0,
                    m_service_type: service_number,
                    m_version_major: info.1,
                    m_version_minor: info.2,
                    m_min_version_major: info.3,
                    m_min_version_minor: info.4,
                }
            })
            .collect()
    }
}
