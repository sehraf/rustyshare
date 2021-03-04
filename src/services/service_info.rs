// use byteorder::{ByteOrder, NetworkEndian};
use std::collections::HashMap;
// use std::fmt;

use crate::parser::{headers::ServiceHeader, Packet};
use crate::serial_stuff;

use crate::services::{self};

#[derive(Debug)]
struct RsServiceInfo {
    pub service_name: String,
    pub service_type: u32,
    pub version_major: u16,
    pub version_minor: u16,
    pub min_version_major: u16,
    pub min_version_minor: u16,
}

// impl fmt::Debug for RsServiceInfo {
//     fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
//         write!(
//             f,
//             "RsServiceInfo {:?} type: {:08X} (-> {:02X} {:04X}) verMax {:04X} verMin {:04X} minVerMax {:04X} minVerMin {:04X}",
//             self.service_name,
//             self.service_type,
//             (self.service_type >> 24) as u8 ,
//             (self.service_type >> 8) as u16,
//             self.version_major,
//             self.version_minor,
//             self.min_version_major,
//             self.min_version_minor
//         )
//     }
// }

pub const SERVICE_INFO_SERVICE: u16 = 0x0020;
pub const SERVICE_INFO_SUB_TYPE: u8 = 0x01;

pub struct ServiceInfo {}

impl ServiceInfo {
    pub fn new() -> ServiceInfo {
        ServiceInfo {}
    }

    pub fn handle_incoming(header: &ServiceHeader, payload: &Vec<u8>) -> Option<Vec<u8>> {
        let mut services = HashMap::new();

        let mut offset = 0;
        if header.sub_type == SERVICE_INFO_SUB_TYPE {
            // RsTlvGenericMapRef<uint32_t, RsServiceInfo> FUN!
            let _ = serial_stuff::read_u16(payload, &mut offset); // type = 1
            let _ = serial_stuff::read_u32(payload, &mut offset); // len

            while offset < payload.len() {
                // RsTlvGenericPairRef moar FUN
                let _ = serial_stuff::read_u16(payload, &mut offset); // type = 1
                let _ = serial_stuff::read_u32(payload, &mut offset); // len

                // RsTlvParamRef we are getting there ...
                // key
                let _ = serial_stuff::read_u16(payload, &mut offset); // type = 1
                let _ = serial_stuff::read_u32(payload, &mut offset); // len
                let servcie_num = serial_stuff::read_u32(payload, &mut offset);
                // value
                let _ = serial_stuff::read_u16(payload, &mut offset); // type = 1
                let _ = serial_stuff::read_u32(payload, &mut offset); // len

                // read struct
                let str_len: usize = serial_stuff::read_u32(payload, &mut offset) as usize;
                let service_name =
                    String::from_utf8(payload[offset..offset + str_len].to_owned()).unwrap();
                offset += str_len;
                let service_type = serial_stuff::read_u32(payload, &mut offset);
                let version_major = serial_stuff::read_u16(payload, &mut offset);
                let version_minor = serial_stuff::read_u16(payload, &mut offset);
                let min_version_major = serial_stuff::read_u16(payload, &mut offset);
                let min_version_minor = serial_stuff::read_u16(payload, &mut offset);

                let info = RsServiceInfo {
                    service_name,
                    service_type,
                    version_major,
                    version_minor,
                    min_version_major,
                    min_version_minor,
                };

                services.insert(servcie_num, info);
            }

            for s in services {
                println!("num: {:08X} -> {:?}", s.0, s.1);
            }
        } else {
            panic!("ServiceInfo: sub type: {:02X} is unknown", header.sub_type);
        }
        None
    }
}

impl services::Service for ServiceInfo {
    fn get_id(&self) -> u16 {
        SERVICE_INFO_SERVICE
    }

    fn handle_packet(&self, packet: Packet) -> Option<Vec<u8>> {
        return ServiceInfo::handle_incoming(&packet.header.into(), &packet.data);
    }

    fn tick(&mut self) -> Option<Vec<Vec<u8>>> {
        None
    }

    fn get_service_info(&self) -> (String, u16, u16, u16, u16) {
        (String::from("service_info"), 1, 0, 1, 0)
    }
}
