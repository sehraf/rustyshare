use std::time::{Duration, Instant};

use crate::{
    parser::{
        headers::{Header, ServiceHeader},
        Packet,
    },
    services,
};

const HEARTBEAT_SERVICE: u16 = 0x0016;
const HEARTBEAT_SUB_SERVICE: u8 = 0x01;

const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5);
const HEARTBEAT_PACKET: Header = Header::Service {
    service: HEARTBEAT_SERVICE,
    sub_type: HEARTBEAT_SUB_SERVICE,
    size: 8,
};
pub struct Heartbeat {
    last_send: Instant,
}

impl Heartbeat {
    pub fn new() -> Heartbeat {
        Heartbeat {
            last_send: Instant::now(),
        }
    }

    pub fn handle_incoming(&self, header: &ServiceHeader, payload: &Vec<u8>) -> Option<Vec<u8>> {
        assert_eq!(header.service, HEARTBEAT_SERVICE);
        assert_eq!(header.sub_type, HEARTBEAT_SUB_SERVICE);
        assert_eq!(payload.len(), 0);

        println!("received heart beat");

        None
    }
}

impl services::Service for Heartbeat {
    fn get_id(&self) -> u16 {
        HEARTBEAT_SERVICE
    }

    fn handle_packet(&self, packet: Packet) -> Option<Vec<u8>> {
        return self.handle_incoming(&packet.header.into(), &packet.data);
    }

    fn tick(&mut self) -> Option<Vec<Vec<u8>>> {
        if self.last_send.elapsed() >= HEARTBEAT_INTERVAL {
            self.last_send = Instant::now();
            return Some(vec![HEARTBEAT_PACKET.to_bytes().to_vec()]);
        }
        None
    }

    fn get_service_info(&self) -> (String, u16, u16, u16, u16) {
        (String::from("heartbeat"), 1, 0, 1, 0)
    }
}
