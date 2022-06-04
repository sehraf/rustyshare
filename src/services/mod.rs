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
use retroshare_compat::{
    basics::{PeerId, RsPacket},
    services::{service_info::RsServiceInfo, ServiceType},
};
use serde::Serialize;
use tokio::sync::mpsc::UnboundedSender;

use crate::{
    error::RsError,
    low_level_parsing::{
        headers::{Header, ServiceHeader},
        Packet,
    },
    model::{intercom::Intercom, DataCore},
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

macro_rules! create_service {
    ($services:expr, $ty:ident, $module:ident :: $class:ident) => {
        let _ = ::retroshare_compat::services::ServiceType::$ty; // this makes $ty having the correct color
        let s = Box::new($module::$class::new());
        $services.add_service(s);
    };
    ($services:expr, $ty:ident, $module:ident :: $class:ident | TIMER) => {
        $services
            .timers
            .entry(::retroshare_compat::services::ServiceType::$ty)
            .or_insert(HashMap::new());
        let s = Box::new($module::$class::new(
            &mut $services.timers.get_mut(&::retroshare_compat::services::ServiceType::$ty).unwrap(),
        ));
        $services.add_service(s);
    };
    ($services:expr, $ty:ident, $module:ident :: $class:ident | $data_core:expr) => {
        let _ = ::retroshare_compat::services::ServiceType::$ty; // this makes $ty having the correct color
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
        let _ = ::retroshare_compat::services::ServiceType::$ty; // this makes $ty having the correct color
        let s = Box::new($module::$class::new($data_core, $core_tx.clone()).await);
        $services.add_service(s);
    };
    ($services:expr, $ty:ident, $module:ident :: $class:ident | $data_core:expr , $core_tx:expr, TIMER) => {
        $services
            .timers
            .entry(::retroshare_compat::services::ServiceType::$ty)
            .or_insert(HashMap::new());
        let s = Box::new(
            $module::$class::new(
                $data_core,
                $core_tx.clone(),
                &mut $services.timers.get_mut(&::retroshare_compat::services::ServiceType::$ty).unwrap(),
            )
            .await,
        );
        $services.add_service(s);
    };
}

// Test for a more streamlined sending system
// See services/status.rs
#[allow(dead_code)]
fn build_packet<T>(item: &T, peer: Arc<PeerId>) -> Packet
where
    T: Serialize + RsPacket,
{
    let service = item.get_service();
    let sub_type = item.get_sub_type();
    let payload = retroshare_compat::serde::to_retroshare_wire(item);
    let header = ServiceHeader::new(service.into(), sub_type, &payload);
    let p = Packet::new(header.into(), payload, peer);
    p
}

#[allow(dead_code)]
fn build_packet_without_location<T>(item: &T) -> Packet
where
    T: Serialize + RsPacket,
{
    let service = item.get_service();
    let sub_type = item.get_sub_type();
    let payload = retroshare_compat::serde::to_retroshare_wire(item);
    let header = ServiceHeader::new(service.into(), sub_type, &payload);
    let p = Packet::new_without_location(header.into(), payload);
    p
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

    pub async fn handle_packet(
        &mut self,
        packet: Packet,
        warn_unknown: bool,
    ) -> HandlePacketResult {
        trace!("handle_packet {packet:?}");

        match &packet.header {
            Header::Service { service, .. } => match self.services.get_mut(&service) {
                Some(service) => return service.handle_packet(packet).await,
                None if warn_unknown => warn!("unable to handle service {service:04X?}"),
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
                #[cfg(debug_assertions)]
                {
                    // consistency check
                    for packet in &packets {
                        let header: ServiceHeader = packet.header.into();
                        if header.service != service.get_id() {
                            log::error!(
                                "Service {:?} generated a packet with a different service type: {:?}",
                                service.get_id(),
                                header.service
                            );
                        }
                    }
                }
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
