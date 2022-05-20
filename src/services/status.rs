use async_trait::async_trait;
use log::{debug, info};
use retroshare_compat::{
    serde::{from_retroshare_wire, to_retroshare_wire},
    services::status::{StatusItem, StatusValue},
};
use std::time::SystemTime;

use crate::{
    handle_packet,
    parser::{headers::ServiceHeader, Packet},
    services::{HandlePacketResult, Service},
    utils::simple_stats::StatsCollection,
};

use super::ServiceType;

const STATUS_SUB_SERVICE: u8 = 0x01;

/// Implements a status stub that sends "online" to the other peer and consums any incoming packets
pub struct Status {
    sent: bool,
}

impl Status {
    pub fn new() -> Status {
        Status { sent: false }
    }

    pub fn handle_incoming(
        &self,
        _header: &ServiceHeader,
        mut packet: Packet,
    ) -> HandlePacketResult {
        // assert_eq!(header.service, ServiceType::Status as u16);
        // assert_eq!(header.sub_type, STATUS_SUB_SERVICE);
        // assert_eq!(packet.payload.len(), 8);

        // let _ts = Duration::seconds(read_u32(&mut packet.payload) as i64);
        // let status = StatusValue::from(read_u32(&mut packet.payload));
        let item: StatusItem =
            from_retroshare_wire(&mut packet.payload).expect("failed to deserialize");
        info!("[status] received status {}", item.status);

        handle_packet!()
    }
}

#[async_trait]
impl Service for Status {
    fn get_id(&self) -> ServiceType {
        ServiceType::Status
    }

    async fn handle_packet(&self, packet: Packet) -> HandlePacketResult {
        debug!("handle_packet");

        self.handle_incoming(&packet.header.into(), packet)
    }

    fn tick(&mut self, _stats: &mut StatsCollection) -> Option<Vec<Packet>> {
        if !self.sent {
            self.sent = true;

            // // built packet
            // let mut payload = vec![];
            // let header = STATUS_PACKET;
            // let mut offset: usize = 0;

            // // sendTime
            // let now = SystemTime::now()
            //     .duration_since(std::time::UNIX_EPOCH)
            //     .expect("Time went backwards");
            // serial_stuff::write_u32(&mut payload, &mut offset, now.as_secs() as u32);

            // // status
            // serial_stuff::write_u32(&mut payload, &mut offset, StatusValue::Online.into());

            // assert_eq!(offset, payload.len());
            // assert_eq!(offset, header.get_payload_size());
            let payload = to_retroshare_wire(&StatusItem {
                send_time: SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("Time went backwards")
                    .as_secs() as u32,
                status: StatusValue::Online.into(),
            })
            .expect("failed to serialize");
            let header =
                ServiceHeader::new(ServiceType::Status, STATUS_SUB_SERVICE, &payload);
            let p = Packet::new_without_location(header.into(), payload);
            return Some(vec![p]);
        }
        None
    }

    fn get_service_info(&self) -> (String, u16, u16, u16, u16) {
        (String::from("status"), 1, 0, 1, 0)
    }
}
