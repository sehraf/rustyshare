use std::time::{Duration, Instant};

use crate::{
    parser::{
        headers::{Header, ServiceHeader},
        Packet,
    },
    services::{HandlePacketResult, Service},
    utils::simple_stats::StatsCollection,
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

    pub fn handle_incoming(&self, header: &ServiceHeader, packet: Packet) -> HandlePacketResult {
        assert_eq!(header.service, HEARTBEAT_SERVICE);
        assert_eq!(header.sub_type, HEARTBEAT_SUB_SERVICE);
        assert_eq!(packet.payload.len(), 0);

        // println!("received heart beat");

        HandlePacketResult::Handled(None)
    }
}

impl Service for Heartbeat {
    fn get_id(&self) -> u16 {
        HEARTBEAT_SERVICE
    }

    fn handle_packet(&self, packet: Packet) -> HandlePacketResult {
        self.handle_incoming(&packet.header.into(), packet)
    }

    fn tick(&mut self, _stats: &mut StatsCollection) -> Option<Vec<Packet>> {
        if self.last_send.elapsed() >= HEARTBEAT_INTERVAL {
            self.last_send = Instant::now();

            let packet = Packet::new_without_location(HEARTBEAT_PACKET, vec![]);
            return Some(vec![packet]);
        }
        None
    }

    fn get_service_info(&self) -> (String, u16, u16, u16, u16) {
        (String::from("heartbeat"), 1, 0, 1, 0)
    }
}
