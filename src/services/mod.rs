use std::{
    collections::hash_map::{HashMap, Values},
    sync::Arc,
};

pub mod bwctrl;
pub mod chat;
pub mod discovery;
pub mod gxs_id;
pub mod heartbeat;
pub mod rtt;
pub mod service_info;
pub mod status;
pub mod turtle;

use async_trait::async_trait;
use log::{trace, warn};
use retroshare_compat::services::service_info::RsServiceInfo;
use tokio::sync::mpsc::UnboundedSender;

use crate::{
    error::RsError,
    model::{intercom::Intercom, DataCore},
    low_level_parsing::{headers::Header, Packet},
    utils::{simple_stats::StatsCollection, Timers},
};

pub enum HandlePacketResult {
    // The limit to one answer packet is on purpose. If a Service wants to send multiple packets, they must be queued!
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

// const SERVICE_FILE_INDEX: u16 = 0x0001;
const SERVICE_DISCOVERY: u16 = 0x0011;
const SERVICE_CHAT: u16 = 0x0012;
// const SERVICE_MSG: u16 = 0x0013;
const SERVICE_TURTLE: u16 = 0x0014;
// const SERVICE_TUNNEL: u16 = 0x0015;
const SERVICE_HEARTBEAT: u16 = 0x0016;
// const SERVICE_FILE_TRANSFER: u16 = 0x0017;
// const SERVICE_GROUTER: u16 = 0x0018;
// const SERVICE_FILE_DATABASE: u16 = 0x0019;
const SERVICE_SERVICE_INFO: u16 = 0x0020;
const SERVICE_BWCTRL: u16 = 0x0021;
// const SERVICE_MAIL: u16 = 0x0022;
// const SERVICE_DIRECT_MAIL: u16 = 0x0023;
// const SERVICE_DISTANT_MAIL: u16 = 0x0024;
// const SERVICE_GWEMAIL_MAIL: u16 = 0x0025;
// const SERVICE_SERVICE_CONTROL: u16 = 0x0026;
// const SERVICE_DISTANT_CHAT: u16 = 0x0027;
// const SERVICE_GXS_TUNNEL: u16 = 0x0028;
// const SERVICE_BANLIST: u16 = 0x0101;
const SERVICE_STATUS: u16 = 0x0102;
// const SERVICE_FRIEND_SERVER: u16 = 0x0103;

/// Rs Network Exchange Service
// const SERVICE_TYPE_NXS            = 0x0200;
pub const SERVICE_GXS_GXSID: u16 = 0x0211;
pub const SERVICE_GXS_PHOTO: u16 = 0x0212;
pub const SERVICE_GXS_WIKI: u16 = 0x0213;
pub const SERVICE_GXS_WIRE: u16 = 0x0214;
pub const SERVICE_GXS_FORUMS: u16 = 0x0215;
pub const SERVICE_GXS_POSTED: u16 = 0x0216;
pub const SERVICE_GXS_CHANNELS: u16 = 0x0217;
pub const SERVICE_GXS_GXSCIRCLE: u16 = 0x0218;

const SERVICE_RTT: u16 = 0x1011;

/// Special type only used for signaling
const SLICE_PROBE: u16 = 0xaabb;

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ServiceType {
    Unknown = 0xffff,

    BwCtrl = SERVICE_BWCTRL,
    Chat = SERVICE_CHAT,
    Discovery = SERVICE_DISCOVERY,
    Heartbeat = SERVICE_HEARTBEAT,
    Rtt = SERVICE_RTT,
    ServiceInfo = SERVICE_SERVICE_INFO,
    Status = SERVICE_STATUS,
    Turtle = SERVICE_TURTLE,

    GxsId = SERVICE_GXS_GXSID,
    Photo = SERVICE_GXS_PHOTO,
    Wiki = SERVICE_GXS_WIKI,
    Wire = SERVICE_GXS_WIRE,
    Forums = SERVICE_GXS_FORUMS,
    Posted = SERVICE_GXS_POSTED,
    Channels = SERVICE_GXS_CHANNELS,
    GxsCircle = SERVICE_GXS_GXSCIRCLE,

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

            SERVICE_GXS_GXSID => GxsId,
            SERVICE_GXS_PHOTO => Photo,
            SERVICE_GXS_WIKI => Wiki,
            SERVICE_GXS_WIRE => Wire,
            SERVICE_GXS_FORUMS => Forums,
            SERVICE_GXS_POSTED => Posted,
            SERVICE_GXS_CHANNELS => Channels,
            SERVICE_GXS_GXSCIRCLE => GxsCircle,

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

            GxsId => SERVICE_GXS_GXSID,
            Photo => SERVICE_GXS_PHOTO,
            Wiki => SERVICE_GXS_WIKI,
            Wire => SERVICE_GXS_WIRE,
            Forums => SERVICE_GXS_FORUMS,
            Posted => SERVICE_GXS_POSTED,
            Channels => SERVICE_GXS_CHANNELS,
            GxsCircle => SERVICE_GXS_GXSCIRCLE,

            SliceProbe => SLICE_PROBE,
        }
    }
}

// impl Display for ServiceType {
//     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
//         use ServiceType::*;

//         match self {
//             Unknown => write!(f, "Unknown"),

//             BwCtrl => write!(f, "BwCtrl"),
//             Chat => write!(f, "Chat"),
//             Discovery => write!(f, "Discovery"),
//             Heartbeat => write!(f, "Heartbeat"),
//             Rtt => write!(f, "Rtt"),
//             ServiceInfo => write!(f, "ServiceInfo"),
//             Status => write!(f, "Status"),
//             Turtle => write!(f, "Turtle"),

//             SliceProbe => write!(f, "SliceProbe"),
//         }
//     }
// }

macro_rules! create_service {
    ($services:expr, $ty:ident, $module:ident :: $class:ident) => {
        let _ = ServiceType::$ty; // this makes $ty having the correct color
        let s = Box::new($module::$class::new());
        $services.add_service(s);
    };
    ($services:expr, $ty:ident, $module:ident :: $class:ident | TIMER) => {
        $services
            .timers
            .entry(ServiceType::$ty)
            .or_insert(HashMap::new());
        let s = Box::new($module::$class::new(
            &mut $services.timers.get_mut(&ServiceType::$ty).unwrap(),
        ));
        $services.add_service(s);
    };
    ($services:expr, $ty:ident, $module:ident :: $class:ident | $data_core:expr) => {
        let _ = ServiceType::$ty; // this makes $ty having the correct color
        let s = Box::new($module::$class::new($data_core).await);
        $services.add_service(s);
    };
    ($services:expr, $ty:ident, $module:ident :: $class:ident | $data_core:expr , TIMER) => {
        $services
            .timers
            .entry(ServiceType::$ty)
            .or_insert(HashMap::new());
        let s = Box::new($module::$class::new(
            $data_core,
            &mut $services.timers.get_mut(&ServiceType::$ty).unwrap(),
        ));
        $services.add_service(s);
    };
    ($services:expr, $ty:ident, $module:ident :: $class:ident | $data_core:expr , $core_tx:expr) => {
        let _ = ServiceType::$ty; // this makes $ty having the correct color
        let s = Box::new($module::$class::new($data_core, $core_tx.clone()).await);
        $services.add_service(s);
    };
    ($services:expr, $ty:ident, $module:ident :: $class:ident | $data_core:expr , $core_tx:expr, TIMER) => {
        $services
            .timers
            .entry(ServiceType::$ty)
            .or_insert(HashMap::new());
        let s = Box::new(
            $module::$class::new(
                $data_core,
                $core_tx.clone(),
                &mut $services.timers.get_mut(&ServiceType::$ty).unwrap(),
            )
            .await,
        );
        $services.add_service(s);
    };
}

#[async_trait]
pub trait Service {
    fn get_id(&self) -> ServiceType;
    fn get_service_info(&self) -> (String, u16, u16, u16, u16);
    async fn handle_packet(&self, packet: Packet) -> HandlePacketResult;
    async fn tick(
        &mut self,
        stats: &mut StatsCollection,
        timers: &mut Timers,
    ) -> Option<Vec<Packet>>;
}

pub struct Services {
    services: HashMap<ServiceType, Box<dyn Service + Sync + Send>>,
    timers: HashMap<ServiceType, Timers>,
}

impl Services {
    pub fn new() -> Services {
        Services {
            services: HashMap::new(),
            timers: HashMap::new(),
        }
    }

    pub async fn get_peer_services() -> Services {
        let mut services = Services::new();

        // RTT
        create_service!(services, Rtt, rtt::Rtt | TIMER);

        // ServiceInfo
        create_service!(services, ServiceInfo, service_info::ServiceInfo);

        // Heartbeat
        create_service!(services, Heartbeat, heartbeat::Heartbeat | TIMER);

        // Status
        create_service!(services, Status, status::Status);

        services
    }

    pub async fn get_core_services(
        #[allow(non_snake_case)] CORE: &Arc<DataCore>,
        #[allow(non_snake_case)] TX: UnboundedSender<Intercom>,
    ) -> Services {
        let mut services = Services::new();

        // Discovery
        // let disc = Box::new(discovery::Discovery::new(CORE, TX.clone()).await);
        // services.add_service(disc);
        create_service!(services, Discovery, discovery::Discovery | CORE, TX);

        // Turtle
        // let ty = ServiceType::Turtle;
        // services.timers.entry(ty).or_insert(HashMap::new());
        // let turtle = Box::new(turtle::Turtle::new(
        //     CORE,
        //     TX.clone(),
        //     &mut services.timers.get_mut(&ty).unwrap(),
        // ));
        // services.add_service(turtle);
        create_service!(services, Turtle, turtle::Turtle | CORE, TX, TIMER);

        // BwCtrl
        create_service!(services, BwCtrl, bwctrl::BwCtrl | CORE);

        // Chat
        // TODO add macro?
        // let ty = ServiceType::Chat;
        // services.timers.entry(ty).or_insert(HashMap::new());
        // let chat = Box::new(
        //     chat::Chat::new(CORE, TX.clone(), &mut services.timers.get_mut(&ty).unwrap()).await,
        // );
        // services.add_service(chat);
        create_service!(services, Chat, chat::Chat | CORE, TX, TIMER);

        // GXS

        // Gxs Id
        create_service!(services, GxsId, gxs_id::GxsId | CORE, TX, TIMER);

        services
    }

    pub fn add_service(&mut self, service: Box<impl Service + Sync + Send + 'static>) {
        // ensure that a timer entry is created
        self.timers
            .entry(service.get_id())
            .or_insert(HashMap::new());

        self.services.insert(service.get_id(), service);
    }

    pub async fn handle_packet(&mut self, packet: Packet, warn_unkown: bool) -> HandlePacketResult {
        trace!("handle_packet {packet:?}");

        match &packet.header {
            Header::Service { service, .. } => match self.services.get_mut(&service) {
                Some(service) => return service.handle_packet(packet).await,
                None if warn_unkown => warn!("unable to handle service {service:04X?}"),
                None => (),
            },
            header => warn!("unable to handle non service header {header:X?}"),
        }

        // return packet to caller
        HandlePacketResult::NotHandled(packet)
    }

    pub async fn tick_all(&mut self, stats: &mut StatsCollection) -> Option<Vec<Packet>> {
        trace!("tick_all");

        let mut items: Vec<Packet> = vec![];

        for (ty, service) in self.services.iter_mut() {
            if let Some(mut packets) = service.tick(stats, self.timers.get_mut(ty).unwrap()).await {
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
        self.services.values()
    }

    pub fn get_service_infos(&self) -> Vec<RsServiceInfo> {
        self.services
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
