use async_trait::async_trait;
use log::{debug, info};
use retroshare_compat::{
    serde::from_retroshare_wire,
    services::{status::{StatusItem, StatusValue}, ServiceType},
};
use std::time::SystemTime;

use crate::{
    handle_packet,
    low_level_parsing::{headers::ServiceHeader, Packet},
    services::{HandlePacketResult, Service},
    utils::{simple_stats::StatsCollection, Timers},
};

use super::build_packet_without_location;

#[allow(unused)]
const STATUS_SUB_SERVICE: u8 = 0x01;

/// Implements a status stub that sends "online" to the other peer and consume any incoming packets
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
        let item: StatusItem = from_retroshare_wire(&mut packet.payload);
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

    async fn tick(
        &mut self,
        _stats: &mut StatsCollection,
        _timers: &mut Timers,
    ) -> Option<Vec<Packet>> {
        if !self.sent {
            self.sent = true;

            let item = StatusItem {
                send_time: SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("Time went backwards")
                    .as_secs() as u32,
                status: StatusValue::Online.into(),
            };

            // This is a test for a more streamlines "sending packets" system
            // See services/mod.rs
            let p = build_packet_without_location(&item);

            return Some(vec![p]);
        }
        None
    }

    fn get_service_info(&self) -> (String, u16, u16, u16, u16) {
        (String::from("status"), 1, 0, 1, 0)
    }
}
