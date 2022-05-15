use std::sync::Arc;

use async_trait::async_trait;
use log::{debug, info};
use retroshare_compat::{read_u16, read_u32, write_u16, write_u32};
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver};

use crate::{
    handle_packet,
    model::{
        intercom::{Intercom, PeerState, PeerUpdate},
        DataCore,
    },
    parser::{headers::ServiceHeader, Packet},
    services::{HandlePacketResult, Service},
    utils::{self, simple_stats::StatsCollection},
};

const BWCTRL_SERVICE: u16 = 0x0021;
const BWCTRL_SUB_TYPE: u8 = 0x01; // RS_PKT_SUBTYPE_BWCTRL_ALLOWED_ITEM ?!

const BWCTRL_ITEM_TAG: u16 = 0x0035;

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
        assert_eq!(header.service, BWCTRL_SERVICE);
        assert_eq!(header.sub_type, BWCTRL_SUB_TYPE);
        assert_eq!(packet.payload.len(), 10);

        // read tag
        assert_eq!(BWCTRL_ITEM_TAG, read_u16(&mut packet.payload));
        // read len
        assert_eq!(10, read_u32(&mut packet.payload));
        // read bw limit
        let bw_limit = read_u32(&mut packet.payload); // status time

        debug!(
            "[BwCtrl] received bandwidth limit of {}/s from {}",
            utils::units::pretty_print_bytes(bw_limit as u64),
            &packet.peer_id
        );

        // TODO actually care about bw limits

        handle_packet!()
    }
}

#[async_trait]
impl Service for BwCtrl {
    fn get_id(&self) -> u16 {
        BWCTRL_SERVICE
    }

    async fn handle_packet(&self, packet: Packet) -> HandlePacketResult {
        debug!("handle_packet");

        self.handle_incoming(&packet.header.into(), packet)
    }

    fn tick(&mut self, _stats: &mut StatsCollection) -> Option<Vec<Packet>> {
        let mut out: Vec<Packet> = vec![];

        while let Ok(cmd) = self.events.try_recv() {
            match cmd {
                Intercom::PeerUpdate(PeerUpdate::Status(PeerState::Connected(loc, _addr))) => {
                    let mut payload = vec![];
                    // write tag
                    write_u16(&mut payload, BWCTRL_ITEM_TAG);
                    // write len
                    write_u32(&mut payload, 10);
                    // write bw limit
                    write_u32(&mut payload, 1_000_000); // bytes/sec

                    let packet = Packet::new(
                        ServiceHeader::new(BWCTRL_SERVICE, BWCTRL_SUB_TYPE, &payload).into(),
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
