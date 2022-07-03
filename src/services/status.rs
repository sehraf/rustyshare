use async_trait::async_trait;
use log::{info, trace, warn};
use retroshare_compat::{
    serde::from_retroshare_wire,
    services::{
        status::{StatusItem, StatusValue},
        ServiceType, service_info::RsServiceInfo,
    },
};
use std::time::SystemTime;
use tokio::{
    select,
    sync::mpsc::{UnboundedReceiver, UnboundedSender}, task::JoinHandle,
};

use crate::{
    low_level_parsing::{headers::ServiceHeader, Packet},
    model::intercom::Intercom,
    send_to_peer,
    services::Service,
};

use super::build_packet_without_location;

const STATUS_SUB_SERVICE: u8 = 0x01;

/// Implements a status stub that sends "online" to the other peer and consume any incoming packets
pub struct Status {
    peer_tx: UnboundedSender<Intercom>,
    rx: UnboundedReceiver<Intercom>,
}

impl Status {
    pub fn new(
        _core_tx: UnboundedSender<Intercom>,
        peer_tx: UnboundedSender<Intercom>,
        rx: UnboundedReceiver<Intercom>,
    ) -> Status {
        Status { peer_tx, rx }
    }

    fn handle_incoming(&self, header: &ServiceHeader, mut packet: Packet) {
        assert_eq!(header.sub_type, STATUS_SUB_SERVICE);
        let item: StatusItem = from_retroshare_wire(&mut packet.payload);
        info!("received status {}", item.status);
    }
}

#[async_trait]
impl Service for Status {
    fn get_id(&self) -> ServiceType {
        ServiceType::Status
    }

    fn get_service_info(&self) -> RsServiceInfo {
        RsServiceInfo::new(self.get_id().into(), "status")
    }

    fn run(mut self) -> JoinHandle<()> {
        let item = StatusItem {
            send_time: SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("Time went backwards")
                .as_secs() as u32,
            status: StatusValue::Online.into(),
        };

        // This is a test for a more streamlines "sending packets" system
        // See services/mod.rs
        let item = build_packet_without_location(&item);

        send_to_peer!(self, item);

        tokio::spawn(async move {
            loop {
                select! {
                    msg = self.rx.recv() => {
                        if let Some(msg) = msg {
                            trace!("handling msg {msg:?}");
                            match msg {
                                Intercom::Receive(packet) => self.handle_incoming(&packet.header.to_owned().into(), packet),
                                _ => warn!("unexpected message: {msg:?}"),
                            }
                        }
                    }
                }
            }
        })
    }
}
