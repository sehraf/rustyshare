use async_trait::async_trait;

use crate::{
    parser::Packet,
    services::{HandlePacketResult, Service},
    utils::SimpleStats::StatsCollection,
};

const TEMPLATE_SERVICE: u16 = 0xDEAD;
const TEMPLATE_SUB_TYPE_A: u8 = 0x01;

pub struct Template {}

impl Template {
    pub fn new() -> Template {
        Template {}
    }
}

#[async_trait]
impl Service for Template {
    fn get_id(&self) -> u16 {
        TEMPLATE_SERVICE
    }

    async fn handle_packet(&self, packet: Packet) -> HandlePacketResult {
        HandlePacketResult::Handled(None)
    }

    fn tick(&mut self, _stats: &mut StatsCollection) -> Option<Vec<Packet>> {
        None
    }

    fn get_service_info(&self) -> (String, u16, u16, u16, u16) {
        (String::from("template"), 1, 0, 1, 0)
    }
}
