use std::time::Duration;

use async_trait::async_trait;
use log::{debug, trace, warn};
use retroshare_compat::services::service_info::RsServiceInfo;
use tokio::{
    select,
    sync::mpsc::{UnboundedReceiver, UnboundedSender},
    task::JoinHandle,
    time::interval,
};

use crate::{
    low_level_parsing::{
        headers::{Header, ServiceHeader},
        Packet,
    },
    model::intercom::Intercom,
    send_to_peer,
    services::Service,
};

use ::retroshare_compat::services::ServiceType;

const HEARTBEAT_SUB_SERVICE: u8 = 0x01;

#[allow(dead_code)]
const HEARTBEAT_INTERVAL: (&str, Duration) = ("heartbeat", Duration::from_secs(5));
const HEARTBEAT_PACKET: Header = Header::Service {
    service: ServiceType::Heartbeat,
    sub_type: HEARTBEAT_SUB_SERVICE,
    size: 8,
};
pub struct Heartbeat {
    peer_tx: UnboundedSender<Intercom>,
    rx: UnboundedReceiver<Intercom>,
}

impl Heartbeat {
    pub fn new(
        _core_tx: UnboundedSender<Intercom>,
        peer_tx: UnboundedSender<Intercom>,
        rx: UnboundedReceiver<Intercom>,
    ) -> Heartbeat {
        Heartbeat { peer_tx, rx }
    }

    fn handle_incoming(&self, header: &ServiceHeader, packet: Packet) {
        assert_eq!(header.sub_type, HEARTBEAT_SUB_SERVICE);
        assert_eq!(packet.payload.len(), 0);

        debug!("received heart beat");
    }

    async fn tick(&mut self) {
        let packet = Packet::new_without_location(HEARTBEAT_PACKET, vec![]);
        // self.peer_tx.send(Intercom::Send(packet)).expect("failed to send to peer");
        send_to_peer!(self, packet);
    }
}

#[async_trait]
impl Service for Heartbeat {
    fn get_id(&self) -> ServiceType {
        ServiceType::Heartbeat
    }

    fn get_service_info(&self) -> RsServiceInfo {
        RsServiceInfo::new(self.get_id().into(), "heartbeat")
    }

    fn run(mut self) -> JoinHandle<()> {
        tokio::spawn(async move {
            let mut tick_timer = interval(Duration::from_secs(5));

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
                    _ = tick_timer.tick() => {
                        self.tick().await;
                    }
                }
            }
        })
    }
}
