use std::time::SystemTime;

use crate::{
    parser::{
        headers::{Header, ServiceHeader},
        Packet,
    },
    serial_stuff, services,
};

const STATUS_SERVICE: u16 = 0x0102;
const STATUS_SUB_SERVICE: u8 = 0x01;

const STATUS_PACKET: Header = Header::Service {
    service: STATUS_SERVICE,
    sub_type: STATUS_SUB_SERVICE,
    size: 8 + 4 + 4,
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
            value => panic!("unknown status value {}", value),
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

pub struct Status {
    sent: bool,
}

impl Status {
    pub fn new() -> Status {
        Status { sent: false }
    }

    pub fn handle_incoming(&self, header: &ServiceHeader, payload: &Vec<u8>) -> Option<Vec<u8>> {
        assert_eq!(header.service, STATUS_SERVICE);
        assert_eq!(header.sub_type, STATUS_SUB_SERVICE);
        assert_eq!(payload.len(), 8);

        println!(
            "received status {}",
            StatusValue::from(serial_stuff::read_u32(payload, &mut 4)).to_string()
        );

        None
    }
}

impl services::Service for Status {
    fn get_id(&self) -> u16 {
        STATUS_SERVICE
    }

    fn handle_packet(&self, packet: Packet) -> Option<Vec<u8>> {
        return self.handle_incoming(&packet.header.into(), &packet.data);
    }

    fn tick(&mut self) -> Option<Vec<Vec<u8>>> {
        if !self.sent {
            self.sent = true;

            // built packet
            let mut data = STATUS_PACKET.to_bytes().to_vec();
            let mut offset: usize = 8;

            // sendTime
            let now = SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("Time went backwards");
            serial_stuff::write_u32(&mut data, &mut offset, now.as_secs() as u32);

            // status
            serial_stuff::write_u32(&mut data, &mut offset, StatusValue::Online.into());

            return Some(vec![data]);
        }
        None
    }

    fn get_service_info(&self) -> (String, u16, u16, u16, u16) {
        (String::from("status"), 1, 0, 1, 0)
    }
}
