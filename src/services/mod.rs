use std::collections::hash_map::{HashMap, Values};

pub mod heartbeat;
pub mod rtt;
pub mod service_info;
pub mod status;

use crate::parser::{headers::Header, Packet};

pub trait Service {
    fn get_id(&self) -> u16;
    fn get_service_info(&self) -> (String, u16, u16, u16, u16);
    fn handle_packet(&self, packet: Packet) -> Option<Vec<u8>>; // todo add peer info
    fn tick(&mut self) -> Option<Vec<Vec<u8>>>;
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

    pub fn add_service(&mut self, service: Box<impl Service + 'static>) {
        self.services.insert(service.get_id(), service);
    }

    pub fn handle_packet(&self, packet: Packet) -> Option<Vec<u8>> {
        match packet.header {
            Header::Service { service, .. } => {
                if let Some(server) = self.services.get(&service) {
                    return server.handle_packet(packet);
                }
                println!("unable to handle {:04X}", service);
            }
            rest => println!("unable to handle {:?}", rest),
        }

        None
    }

    pub fn tick_all(&mut self) -> Option<Vec<Vec<u8>>> {
        let mut items: Vec<Vec<u8>> = vec![];

        for entry in self.services.iter_mut() {
            match entry.1.tick() {
                None => {}
                Some(mut data) => {
                    items.append(&mut data);
                }
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
