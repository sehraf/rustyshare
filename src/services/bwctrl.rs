use std::sync::Arc;

use async_trait::async_trait;
use log::{debug, info};
use retroshare_compat::{
    serde::{from_retroshare_wire, to_retroshare_wire},
    services::bwctrl::BwCtrlAllowedItem,
};
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver};

use crate::{
    handle_packet,
    low_level_parsing::{headers::ServiceHeader, Packet},
    model::{
        intercom::{Intercom, PeerState, PeerUpdate},
        DataCore,
    },
    services::{HandlePacketResult, Service},
    utils::{self, simple_stats::StatsCollection, Timers},
};

use ::retroshare_compat::services::ServiceType;

const BWCTRL_SUB_TYPE: u8 = 0x01; // RS_PKT_SUBTYPE_BWCTRL_ALLOWED_ITEM ?!

pub struct BwCtrl {
    events: UnboundedReceiver<Intercom>,
}

impl BwCtrl {
    pub async fn new(dc: &Arc<DataCore>) -> BwCtrl {
        let (tx, rx) = unbounded_channel();
        dc.events_subscribe(tx).await;
        BwCtrl { events: rx }
    }

    pub fn handle_incoming(
        &self,
        header: &ServiceHeader,
        mut packet: Packet,
    ) -> HandlePacketResult {
        assert_eq!(header.sub_type, BWCTRL_SUB_TYPE);

        let item: BwCtrlAllowedItem = from_retroshare_wire(&mut packet.payload);

        debug!(
            "[BwCtrl] received bandwidth limit of {}/s from {}",
            utils::units::pretty_print_bytes(item.0 as u64),
            &packet.peer_id
        );

        // TODO actually care about bw limits

        handle_packet!()
    }
}

#[async_trait]
impl Service for BwCtrl {
    fn get_id(&self) -> ServiceType {
        ServiceType::BwCtrl
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
        let mut out: Vec<Packet> = vec![];

        while let Ok(cmd) = self.events.try_recv() {
            match cmd {
                Intercom::PeerUpdate(PeerUpdate::Status(PeerState::Connected(loc, _addr))) => {
                    let item = BwCtrlAllowedItem { 0: 1_000_000 }; // bytes/sec
                    let payload = to_retroshare_wire(&item);

                    let packet = Packet::new(
                        ServiceHeader::new(self.get_id(), BWCTRL_SUB_TYPE, &payload).into(),
                        payload,
                        loc.clone(),
                    );

                    out.push(packet);
                    info!("[BwCtrl] sending bw limit info to {loc}");
                }
                // we don't care for the rest!
                _ => {}
            }
        }

        if out.is_empty() {
            return None;
        }
        Some(out)
    }

    fn get_service_info(&self) -> (String, u16, u16, u16, u16) {
        (String::from("bandwidth_ctrl"), 1, 0, 1, 0)
    }
}
