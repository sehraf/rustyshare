use async_trait::async_trait;
use log::{debug, info};
use retroshare_compat::{
    serde::{from_retroshare_wire_result, to_retroshare_wire_result},
    services::service_info::{RsServiceInfo, TlvServiceInfoMapRef},
};

use crate::{
    handle_packet,
    low_level_parsing::{headers::ServiceHeader, Packet},
    services::{HandlePacketResult, Service},
    utils::{simple_stats::StatsCollection, Timers},
};

use ::retroshare_compat::services::ServiceType;

impl From<&dyn Service> for RsServiceInfo {
    fn from(service: &dyn Service) -> Self {
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
        match header.sub_type {
            SERVICE_INFO_SUB_TYPE => {
                let services =
                    from_retroshare_wire_result::<TlvServiceInfoMapRef>(&mut packet.payload)
                        .expect("failed to deserialize")
                        .0;

                for s in services {
                    info!("[service_info] num: {:#08X} -> {:?}", s.0 .0, s.1 .0);
                }
            }
            sub_type => log::error!("[service_info] recevied unknown sub typ {sub_type}"),
        }
        handle_packet!()
    }
}

#[async_trait]
impl Service for ServiceInfo {
    fn get_id(&self) -> ServiceType {
        ServiceType::ServiceInfo
    }

    async fn handle_packet(&self, packet: Packet) -> HandlePacketResult {
        debug!("handle_packet");

        self.handle_incoming(&packet.header.into(), packet)
    }

    async fn tick(
        &mut self,
        _stats: &mut StatsCollection,
        _timers: &mut Timers,
    ) -> Option<Vec<Packet>> {
        None
    }

    fn get_service_info(&self) -> (String, u16, u16, u16, u16) {
        (String::from("service_info"), 1, 0, 1, 0)
    }
}

pub fn gen_service_info(services: &Vec<RsServiceInfo>) -> Packet {
    let services: TlvServiceInfoMapRef = services.to_owned().into();
    let payload = to_retroshare_wire_result(&services).expect("failed to serialize");
    let header = ServiceHeader::new(ServiceType::ServiceInfo, SERVICE_INFO_SUB_TYPE, &payload);

    Packet::new_without_location(header.into(), payload)
}
