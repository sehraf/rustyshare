use std::{collections::hash_map::HashMap, sync::Arc};

pub mod bwctrl;
pub mod chat;
pub mod discovery;
pub mod gxs_id;
pub mod heartbeat;
pub mod rtt;
pub mod service_info;
pub mod status;
pub mod turtle;

use ::retroshare_compat::services::ServiceType;
use async_trait::async_trait;
use log::{trace, warn};
use retroshare_compat::{
    basics::{PeerId, RsPacket},
    gxs::sqlite::database::GxsDatabase,
    services::service_info::RsServiceInfo,
};
use serde::Serialize;
use tokio::{
    sync::mpsc::{unbounded_channel, UnboundedSender},
    task::JoinHandle,
};

use crate::{
    gxs::gxs_backend::GxsShared,
    low_level_parsing::{
        headers::{Header, ServiceHeader},
        Packet,
    },
    model::{intercom::Intercom, DataCore},
};

#[macro_export]
macro_rules! send_to_peer {
    ($self:expr, $packet:expr) => {
        $self
            .peer_tx
            .send(Intercom::Send($packet))
            .expect("failed to send to peer");
    };
}
#[macro_export]
macro_rules! send_to_core {
    ($self:expr, $packet:expr) => {
        $self
            .core_tx
            .send(Intercom::Send($packet))
            .expect("failed to send to peer");
    };
}

macro_rules! create_service {
    // peer services
    (PEER: $services:expr, $core_tx:expr, $peer_tx:expr, $ty:ident, $module:ident :: $class:ident) => {
        let _ = ::retroshare_compat::services::ServiceType::$ty; // this makes $ty having the correct color
        let (tx, rx) = unbounded_channel();
        let s = Box::new($module::$class::new($core_tx.to_owned(), $peer_tx.to_owned(), rx));
        let ty = s.get_id();
        let info = s.get_service_info();
        let handle = s.run();
        $services.add_service(ty, tx, info, handle);
    };

    (CORE: $services:expr, $data_core:expr , $core_tx:expr, $ty:ident, $module:ident :: $class:ident) => {
        let _ = ::retroshare_compat::services::ServiceType::$ty; // this makes $ty having the correct color
        let (tx, rx) = unbounded_channel();
        let s = Box::new($module::$class::new($data_core, $core_tx.clone(), rx).await);
        let ty = s.get_id();
        let info = s.get_service_info();
        let handle = s.run();
        $services.add_service(ty, tx, info, handle);
    }

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
    fn get_service_info(&self) -> RsServiceInfo;
    // async fn handle_packet(&self, packet: Packet) -> HandlePacketResult;
    // async fn tick(
    //     &mut self,
    //     stats: &mut StatsCollection,
    //     timers: &mut Timers,
    // ) -> Option<Vec<Packet>>;
    fn run(self) -> JoinHandle<()>;
}

pub struct Services {
    // services: HashMap<ServiceType, (Box<dyn Service + Sync + Send>, UnboundedSender<Intercom>)>,
    services: HashMap<ServiceType, (UnboundedSender<Intercom>, RsServiceInfo, JoinHandle<()>)>,
    // timers: HashMap<ServiceType, Timers>,
    /// used to distinguish between core services and peer services
    is_core_service: bool,
    /// usd by peer services
    core_tx: UnboundedSender<Intercom>,
}

impl Services {
    pub fn new(is_core_service: bool, core_tx: UnboundedSender<Intercom>) -> Services {
        Services {
            services: HashMap::new(),
            // timers: HashMap::new(),
            is_core_service,
            core_tx,
        }
    }

    pub async fn get_peer_services(
        core_tx: UnboundedSender<Intercom>,
        peer_tx: UnboundedSender<Intercom>,
    ) -> Services {
        let mut services = Services::new(false, core_tx.to_owned());

        // RTT
        create_service!(PEER: services, core_tx, peer_tx, Rtt, rtt::Rtt);

        // ServiceInfo
        create_service!(
            PEER: services,
            core_tx,
            peer_tx,
            ServiceInfo,
            service_info::ServiceInfo
        );

        // Heartbeat
        create_service!(
            PEER: services,
            core_tx,
            peer_tx,
            Heartbeat,
            heartbeat::Heartbeat
        );

        // Status
        create_service!(PEER: services, core_tx, peer_tx, Status, status::Status);

        services
    }

    pub async fn get_core_services(
        dc: &Arc<DataCore>,
        core_tx: UnboundedSender<Intercom>,
        (gxs_id_db, gxs_shared_id): (GxsDatabase, Arc<GxsShared>),
    ) -> Services {
        let mut services = Services::new(true, core_tx.to_owned());

        // Discovery
        create_service!(CORE: services, dc, core_tx, Discovery, discovery::Discovery);

        // Turtle
        create_service!(CORE: services, dc, core_tx, Turtle, turtle::Turtle);

        // BwCtrl
        create_service!(CORE: services, dc, core_tx, BwCtrl, bwctrl::BwCtrl);

        // Chat
        create_service!(CORE: services, dc, core_tx, Chat, chat::Chat);

        // GXS

        // Gxs Id
        // create_service!(services, GxsId, gxs_id::GxsId | CORE, TX, TIMER);
        let (tx, rx) = unbounded_channel();
        let s = Box::new(
            gxs_id::GxsId::new(&dc, core_tx.clone(), rx, (gxs_id_db, gxs_shared_id)).await,
        );
        let ty = s.get_id();
        let info = s.get_service_info();
        let handle = s.run();
        services.add_service(ty, tx, info, handle);

        services
    }

    // pub fn add_service(
    //     &mut self,
    //     service: (
    //         Box<dyn Service + Sync + Send + 'static>,
    //         UnboundedSender<Intercom>,
    //     ),
    // ) {
    //     let id = service.0.get_id();
    //     // ensure that a timer entry is created
    //     self.timers.entry(id).or_insert(HashMap::new());

    //     self.services.insert(id, service);
    // }
    fn add_service(
        &mut self,
        ty: ServiceType,
        tx: UnboundedSender<Intercom>,
        info: RsServiceInfo,
        handle: JoinHandle<()>,
    ) {
        self.services.insert(ty, (tx, info, handle));
    }

    pub async fn handle_packet(&mut self, packet: Packet) {
        trace!("handle_packet {packet:?}");

        match &packet.header {
            Header::Service { service, .. } => match self.services.get_mut(&service) {
                Some((tx, _, _)) => tx
                    .send(Intercom::Receive(packet))
                    .expect("failed to send to service"),

                None => {
                    if self.is_core_service {
                        warn!("core: unable to handle service {service:04X?}");
                    } else {
                        self.core_tx
                            .send(Intercom::Receive(packet))
                            .expect("failed to send to core");
                    }
                }
            },
            header => warn!("unable to handle non service header {header:X?}"),
        }
    }

    pub fn get_services(&self) -> Vec<ServiceType> {
        self.services.keys().map(|ty| ty.to_owned()).collect()
    }

    pub fn get_service_infos(&self) -> Vec<RsServiceInfo> {
        self.services
            .iter()
            .map(|(_id, (_, info, _))| info.to_owned())
            .collect()
    }
}
