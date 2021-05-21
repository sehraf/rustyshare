use retroshare_compat::{read_u16, read_u32, write_u16, write_u32};
use std::sync::mpsc;

use crate::{
    model::{DataCore, PeerCommand, PeerState, PeerUpdate},
    parser::{headers::ServiceHeader, Packet},
    services::{HandlePacketResult, Service},
    utils::simple_stats::StatsCollection,
};

const BWCTRL_SERVICE: u16 = 0x0021;
const BWCTRL_SUB_TYP: u8 = 0x01; // RS_PKT_SUBTYPE_BWCTRL_ALLOWED_ITEM ?!

const BWCTRL_ITEM_TAG: u16 = 0x0035;

pub struct BwCtrl {
    events: mpsc::Receiver<PeerCommand>,
}

impl BwCtrl {
    pub fn new(dc: &mut DataCore) -> BwCtrl {
        let (tx, rx) = mpsc::channel();
        dc.subscribe_for_events(tx);
        BwCtrl { events: rx }
    }

    pub fn handle_incoming(
        &self,
        header: &ServiceHeader,
        mut packet: Packet,
    ) -> HandlePacketResult {
        assert_eq!(header.service, BWCTRL_SERVICE);
        assert_eq!(header.sub_type, BWCTRL_SUB_TYP);
        assert_eq!(packet.payload.len(), 10);

        // read tag
        assert_eq!(BWCTRL_ITEM_TAG, read_u16(&mut packet.payload));
        // read len
        assert_eq!(10, read_u32(&mut packet.payload));
        // read bw limit
        let _bw_limit = read_u32(&mut packet.payload); // status time

        // println!(
        //     "[BwCtrl] received bandwidth limit of {}/s from {}",
        //     utils::units::pretty_print_bytes(bw_limit as u64),
        //     &packet.peer_id
        // );

        // TODO actually care about bw limits

        HandlePacketResult::Handled(None)
    }
}

impl Service for BwCtrl {
    fn get_id(&self) -> u16 {
        BWCTRL_SERVICE
    }

    fn handle_packet(&self, packet: Packet) -> HandlePacketResult {
        self.handle_incoming(&packet.header.into(), packet)
    }

    fn tick(&mut self, _stats: &mut StatsCollection) -> Option<Vec<Packet>> {
        let mut out: Vec<Packet> = vec![];

        while let Ok(cmd) = self.events.try_recv() {
            match cmd {
                PeerCommand::PeerUpdate(PeerUpdate::Status(PeerState::Connected(loc, _addr))) => {
                    let mut payload = vec![];
                    // write tag
                    write_u16(&mut payload, BWCTRL_ITEM_TAG);
                    // write len
                    write_u32(&mut payload, 10);
                    // write bw limit
                    write_u32(&mut payload, 1_000_000); // bytes/sec

                    let packet = Packet::new(
                        ServiceHeader::new(BWCTRL_SERVICE, BWCTRL_SUB_TYP, &payload).into(),
                        payload,
                        loc.clone(),
                    );

                    out.push(packet);
                    // println!("[BwCtrl] sending bw limit info to {}", loc);
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
