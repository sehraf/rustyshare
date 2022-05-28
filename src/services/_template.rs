use async_trait::async_trait;

use crate::{
    parser::Packet,
    services::{HandlePacketResult, Service},
    utils::{simple_stats::StatsCollection, Timers},
};

const TEMPLATE_SUB_TYPE_A: u8 = 0x01;

// FIXME
pub struct Template {}

impl Template {
    pub fn new() -> Template {
        Template {}
    }
}

#[async_trait]
impl Service for Template {
    fn get_id(&self) -> ServiceType {
        // FIXME
        ServiceType::TEMPLATE_SERVICE
    }

    async fn handle_packet(&self, _packet: Packet) -> HandlePacketResult {
        HandlePacketResult::Handled(None)
    }

    async fn tick(&mut self, _stats: &mut StatsCollection, _timers: &mut Timers) -> Option<Vec<Packet>> {
        None
    }

    fn get_service_info(&self) -> (String, u16, u16, u16, u16) {
        // FIXME
        (String::from("template"), 1, 0, 1, 0)
    }
}
