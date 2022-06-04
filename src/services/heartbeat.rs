use std::time::Duration;

use async_trait::async_trait;
use log::debug;

use crate::{
    handle_packet,
    low_level_parsing::{
        headers::{Header, ServiceHeader},
        Packet,
    },
    services::{HandlePacketResult, Service},
    utils::{simple_stats::StatsCollection, Timer, Timers},
};

use ::retroshare_compat::services::ServiceType;

const HEARTBEAT_SUB_SERVICE: u8 = 0x01;

const HEARTBEAT_INTERVAL: (&str, Duration) = ("heartbeat", Duration::from_secs(5));
const HEARTBEAT_PACKET: Header = Header::Service {
    service: ServiceType::Heartbeat,
    sub_type: HEARTBEAT_SUB_SERVICE,
    size: 8,
};
pub struct Heartbeat();

impl Heartbeat {
    pub fn new(timers: &mut Timers) -> Heartbeat {
        timers.insert(
            HEARTBEAT_INTERVAL.0.into(),
            Timer::new(HEARTBEAT_INTERVAL.1),
        );

        Heartbeat()
    }

    pub fn handle_incoming(&self, header: &ServiceHeader, packet: Packet) -> HandlePacketResult {
        assert_eq!(header.sub_type, HEARTBEAT_SUB_SERVICE);
        assert_eq!(packet.payload.len(), 0);

        debug!("[heartbeat] received heart beat");

        handle_packet!()
    }
}

#[async_trait]
impl Service for Heartbeat {
    fn get_id(&self) -> ServiceType {
        ServiceType::Heartbeat
    }

    async fn handle_packet(&self, packet: Packet) -> HandlePacketResult {
        debug!("handle_packet");

        self.handle_incoming(&packet.header.into(), packet)
    }

    async fn tick(
        &mut self,
        _stats: &mut StatsCollection,
        timers: &mut Timers,
    ) -> Option<Vec<Packet>> {
        // if self.last_send.elapsed() >= HEARTBEAT_INTERVAL {
        //     self.last_send = Instant::now();

        //     let packet = Packet::new_without_location(HEARTBEAT_PACKET, vec![]);
        //     return Some(vec![packet]);
        // }
        if timers
            .get_mut(HEARTBEAT_INTERVAL.0.into())
            .unwrap()
            .expired()
        {
            let packet = Packet::new_without_location(HEARTBEAT_PACKET, vec![]);
            return Some(vec![packet]);
        }
        None
    }

    fn get_service_info(&self) -> (String, u16, u16, u16, u16) {
        (String::from("heartbeat"), 1, 0, 1, 0)
    }
}
