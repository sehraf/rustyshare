use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use log::{debug, info, trace, warn};
use retroshare_compat::{
    serde::{from_retroshare_wire, to_retroshare_wire},
    services::{bwctrl::BwCtrlAllowedItem, service_info::RsServiceInfo},
};
use tokio::{
    select,
    sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender},
    task::JoinHandle,
    time::{interval, Interval},
};

use crate::{
    low_level_parsing::{headers::ServiceHeader, Packet},
    model::{
        intercom::{Intercom, PeerState, PeerUpdate},
        DataCore,
    },
    services::Service,
    utils::units,
};

use ::retroshare_compat::services::ServiceType;

const BWCTRL_SUB_TYPE: u8 = 0x01; // RS_PKT_SUBTYPE_BWCTRL_ALLOWED_ITEM ?!

pub struct BwCtrl {
    rx: UnboundedReceiver<Intercom>,

    core: Arc<DataCore>,
    core_tx: UnboundedSender<Intercom>,
    events: UnboundedReceiver<Intercom>,

    timer: Interval,
}

impl BwCtrl {
    pub async fn new(
        core: &Arc<DataCore>,
        core_tx: UnboundedSender<Intercom>,
        rx: UnboundedReceiver<Intercom>,
    ) -> BwCtrl {
        let (tx_events, rx_events) = unbounded_channel();
        core.events_subscribe(tx_events).await;

        BwCtrl {
            rx,

            core: core.to_owned(),
            core_tx,
            events: rx_events,

            timer: interval(Duration::from_secs(5)),
        }
    }

    fn handle_incoming(&self, header: &ServiceHeader, mut packet: Packet) {
        assert_eq!(header.sub_type, BWCTRL_SUB_TYPE);

        let item: BwCtrlAllowedItem = from_retroshare_wire(&mut packet.payload);

        debug!(
            "received bandwidth limit of {}/s from {}",
            units::pretty_print_bytes(item.0 as u64),
            &packet.peer_id
        );

        // TODO actually care about bw limits

        // self.core_tx
        //     .send(Intercom::Send(packet))
        //     .expect("failed to send to core");
    }
}

#[async_trait]
impl Service for BwCtrl {
    fn get_id(&self) -> ServiceType {
        ServiceType::BwCtrl
    }

    fn get_service_info(&self) -> RsServiceInfo {
        RsServiceInfo::new(self.get_id().into(), "bandwidth_ctrl")
    }

    fn run(mut self) -> JoinHandle<()> {
        tokio::spawn(async move {
            loop {
                select! {
                    msg = self.rx.recv() => {
                        if let Some(msg) = msg {
                            trace!("handling msg {msg:?}");

                            match msg {
                                Intercom::Receive(packet) =>
                                    self.handle_incoming(&packet.header.to_owned().into(), packet),
                                _ => warn!("unexpected message: {msg:?}"),
                            }
                        }
                    }
                    event = self.events.recv() => {
                        trace!("handling event: {event:?}");
                        if let Some(event) = event {
                            match event {
                                Intercom::PeerUpdate(PeerUpdate::Status(PeerState::Connected(loc, _addr))) => {
                                    let item = BwCtrlAllowedItem { 0: 1_000_000 }; // bytes/sec
                                    let payload = to_retroshare_wire(&item);

                                    let packet = Packet::new(
                                        ServiceHeader::new(self.get_id(), BWCTRL_SUB_TYPE, &payload).into(),
                                        payload,
                                        loc.clone(),
                                    );
                                    self.core_tx.send(Intercom::Send(packet)).expect("failed to send to core");

                                    info!("sending bw limit info to {loc}");
                                }
                                // we don't care for the rest!
                                _ => {}
                            }
                        }
                    }
                    _ = self.timer.tick() => {
                        for (peer_id, _) in self.core.get_connected_peers().lock().await.0.iter() {
                            let item = BwCtrlAllowedItem { 0: 1_000_000 }; // bytes/sec
                            let payload = to_retroshare_wire(&item);

                            let packet = Packet::new(
                                ServiceHeader::new(self.get_id(), BWCTRL_SUB_TYPE, &payload).into(),
                                payload,
                                peer_id.clone(),
                            );
                            self.core_tx.send(Intercom::Send(packet)).expect("failed to send to core");
                        }
                    }
                }
            }
        })
    }
}
