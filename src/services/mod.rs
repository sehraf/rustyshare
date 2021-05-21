use std::collections::hash_map::{HashMap, Values};

pub mod bwctrl;
pub mod discovery;
pub mod heartbeat;
pub mod rtt;
pub mod service_info;
pub mod status;
pub mod turtle;
// mod _template;

use crate::{
    error::RsError,
    model::DataCore,
    parser::{headers::Header, Packet},
    utils::simple_stats::StatsCollection,
};

pub enum HandlePacketResult {
    Handled(Option<Packet>),
    NotHandled(Packet),
    Error(RsError),
}

pub trait Service {
    fn get_id(&self) -> u16;
    fn get_service_info(&self) -> (String, u16, u16, u16, u16);
    fn handle_packet(&self, packet: Packet) -> HandlePacketResult; // todo add peer info
    fn tick(&mut self, stats: &mut StatsCollection) -> Option<Vec<Packet>>;
}

pub struct Services {
    services: HashMap<u16, Box<dyn Service>>,
    // value: u16,
}

impl Services {
    pub fn new() -> Services {
        Services {
            services: HashMap::new(),
        }
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

    pub fn get_core_services(dc: &mut DataCore) -> Services {
        let mut services = Services::new();

        let disc = Box::new(discovery::Discovery::new(dc));
        services.add_service(disc);

        let turtle = Box::new(turtle::Turtle::new(dc));
        services.add_service(turtle);

        let bwctrl = Box::new(bwctrl::BwCtrl::new(dc));
        services.add_service(bwctrl);

        services
    }

    pub fn add_service(&mut self, service: Box<impl Service + 'static>) {
        self.services.insert(service.get_id(), service);
    }

    pub fn handle_packet(&self, packet: Packet) -> HandlePacketResult {
        match &packet.header {
            Header::Service { service, .. } => {
                if let Some(server) = self.services.get(&service) {
                    return server.handle_packet(packet);
                }
            }
            header => println!("unable to handle non service header {:?}", header),
        }

        // return packet to caller
        HandlePacketResult::NotHandled(packet)
    }

    pub fn tick_all(&mut self, stats: &mut StatsCollection) -> Option<Vec<Packet>> {
        let mut items: Vec<Packet> = vec![];

        for entry in self.services.iter_mut() {
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

    pub fn get_services(&self) -> Values<u16, Box<dyn Service>> {
        self.services.values()
    }
}
