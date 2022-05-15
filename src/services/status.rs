use async_trait::async_trait;
use chrono::Duration;
use log::{info, debug};
use retroshare_compat::read_u32;
use std::time::SystemTime;

use crate::{
    parser::{
        headers::{self, Header, ServiceHeader},
        Packet,
    },
    serial_stuff,
    services::{HandlePacketResult, Service},
    utils::simple_stats::StatsCollection, handle_packet,
};

const STATUS_SERVICE: u16 = 0x0102;
const STATUS_SUB_SERVICE: u8 = 0x01;

const STATUS_PACKET: Header = Header::Service {
    service: STATUS_SERVICE,
    sub_type: STATUS_SUB_SERVICE,
    size: headers::HEADER_SIZE as u32 + 4 + 4, // fixed, header + 2 u32
};

// const uint32_t RS_STATUS_OFFLINE  = 0x0000;
// const uint32_t RS_STATUS_AWAY     = 0x0001;
// const uint32_t RS_STATUS_BUSY     = 0x0002;
// const uint32_t RS_STATUS_ONLINE   = 0x0003;
// const uint32_t RS_STATUS_INACTIVE = 0x0004;
enum StatusValue {
    Offline,
    Away,
    Busy,
    Online,
    Inactive,
}

impl From<u32> for StatusValue {
    fn from(val: u32) -> Self {
        match val {
            0x0000 => StatusValue::Offline,
            0x0001 => StatusValue::Away,
            0x0002 => StatusValue::Busy,
            0x0003 => StatusValue::Online,
            0x0004 => StatusValue::Inactive,
            value => panic!("unknown status value {value}"),
        }
    }
}

impl From<StatusValue> for u32 {
    fn from(status: StatusValue) -> Self {
        match status {
            StatusValue::Offline => 0x0000,
            StatusValue::Away => 0x0001,
            StatusValue::Busy => 0x0002,
            StatusValue::Online => 0x0003,
            StatusValue::Inactive => 0x0004,
        }
    }
}

impl ToString for StatusValue {
    fn to_string(&self) -> String {
        match self {
            StatusValue::Offline => String::from("offline"),
            StatusValue::Away => String::from("away"),
            StatusValue::Busy => String::from("busy"),
            StatusValue::Online => String::from("online"),
            StatusValue::Inactive => String::from("inactive"),
        }
    }
}

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
        header: &ServiceHeader,
        mut packet: Packet,
    ) -> HandlePacketResult {
        assert_eq!(header.service, STATUS_SERVICE);
        assert_eq!(header.sub_type, STATUS_SUB_SERVICE);
        assert_eq!(packet.payload.len(), 8);

        let _ts = Duration::seconds(read_u32(&mut packet.payload) as i64);
        let status = StatusValue::from(read_u32(&mut packet.payload));
        info!("[status] received status {}", status.to_string());

        handle_packet!()
    }
}

#[async_trait]
impl Service for Status {
    fn get_id(&self) -> u16 {
        STATUS_SERVICE
    }

    async fn handle_packet(&self, packet: Packet) -> HandlePacketResult {
        debug!("handle_packet");
        
        self.handle_incoming(&packet.header.into(), packet)
    }

    fn tick(&mut self, _stats: &mut StatsCollection) -> Option<Vec<Packet>> {
        if !self.sent {
            self.sent = true;

            // built packet
            let mut payload = vec![];
            let header = STATUS_PACKET;
            let mut offset: usize = 0;

            // sendTime
            let now = SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("Time went backwards");
            serial_stuff::write_u32(&mut payload, &mut offset, now.as_secs() as u32);

            // status
            serial_stuff::write_u32(&mut payload, &mut offset, StatusValue::Online.into());

            assert_eq!(offset, payload.len());
            assert_eq!(offset, header.get_payload_size());

            let p = Packet::new_without_location(header, payload);
            return Some(vec![p]);
        }
        None
    }

    fn get_service_info(&self) -> (String, u16, u16, u16, u16) {
        (String::from("status"), 1, 0, 1, 0)
    }
}
