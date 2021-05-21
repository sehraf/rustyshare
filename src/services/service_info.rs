use retroshare_compat::{
    service_info::{read_rs_service_info, write_rs_service_info, RsServiceInfo},
    tlv::TLV_HEADER_SIZE,
};
use std::collections::HashMap;

use crate::{
    parser::{
        headers::{Header, ServiceHeader, HEADER_SIZE},
        Packet,
    },
    services::{HandlePacketResult, Service},
    utils::simple_stats::StatsCollection,
};

// #[derive(Debug)]
// struct RsServiceInfo {
//     pub service_name: String,
//     pub service_type: u32,
//     pub version_major: u16,
//     pub version_minor: u16,
//     pub min_version_major: u16,
//     pub min_version_minor: u16,
// }

impl From<&Box<dyn Service>> for RsServiceInfo {
    fn from(service: &Box<dyn Service>) -> Self {
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
    }
}

pub const SERVICE_INFO_SERVICE: u16 = 0x0020;
pub const SERVICE_INFO_SUB_TYPE: u8 = 0x01;

pub struct ServiceInfo {}

impl ServiceInfo {
    pub fn new() -> ServiceInfo {
        ServiceInfo {}
    }

    pub fn handle_incoming(
        &self,
        header: &ServiceHeader,
        mut packet: Packet,
    ) -> HandlePacketResult {
        if header.sub_type == SERVICE_INFO_SUB_TYPE {
            let mut services = HashMap::new();

            read_rs_service_info(&mut packet.payload, &mut services);

            for s in services {
                println!("[service_info] num: {:#08X} -> {:?}", s.0, s.1);
            }
        } else {
            panic!("ServiceInfo: sub type: {:02X} is unknown", header.sub_type);
        }
        HandlePacketResult::Handled(None)
    }
}

impl Service for ServiceInfo {
    fn get_id(&self) -> u16 {
        SERVICE_INFO_SERVICE
    }

    fn handle_packet(&self, packet: Packet) -> HandlePacketResult {
        self.handle_incoming(&packet.header.into(), packet)
    }

    fn tick(&mut self, _stats: &mut StatsCollection) -> Option<Vec<Packet>> {
        // if !self.sent {
        //     use crate::serial_stuff::gen_service_info;
        //     self.sent = true;
        //     gen_service_info(self.services.get_services());
        // }
        None
    }

    fn get_service_info(&self) -> (String, u16, u16, u16, u16) {
        (String::from("service_info"), 1, 0, 1, 0)
    }
}

pub fn gen_service_info(services: &Vec<RsServiceInfo>) -> Packet {
    let inner_data = write_rs_service_info(services);

    // build packet header
    let size_complete = inner_data.len();
    let header = Header::Service {
        service: SERVICE_INFO_SERVICE,
        sub_type: SERVICE_INFO_SUB_TYPE,
        size: (HEADER_SIZE + size_complete + TLV_HEADER_SIZE) as u32, // include 8 byte header size
    };

    let mut payload: Vec<u8> = vec![];
    retroshare_compat::write_u16(&mut payload, 1); // type
    retroshare_compat::write_u32(&mut payload, (size_complete + TLV_HEADER_SIZE) as u32); // len
    payload.extend(inner_data);

    Packet::new_without_location(header, payload)
}
