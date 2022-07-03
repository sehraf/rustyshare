use async_trait::async_trait;
use log::{info, trace, warn};
use retroshare_compat::{
    serde::{from_retroshare_wire, to_retroshare_wire},
    services::service_info::{RsServiceInfo, TlvServiceInfoMapRef},
};
use tokio::{
    select,
    sync::mpsc::{UnboundedReceiver, UnboundedSender},
    task::JoinHandle,
};

use crate::{
    low_level_parsing::{headers::ServiceHeader, Packet},
    model::intercom::Intercom,
    services::Service,
};

use ::retroshare_compat::services::ServiceType;

pub const SERVICE_INFO_SUB_TYPE: u8 = 0x01;

pub struct ServiceInfo {
    #[allow(dead_code)]
    peer_tx: UnboundedSender<Intercom>,

    rx: UnboundedReceiver<Intercom>,
}

impl ServiceInfo {
    pub fn new(
        _core_tx: UnboundedSender<Intercom>,
        peer_tx: UnboundedSender<Intercom>,
        rx: UnboundedReceiver<Intercom>,
    ) -> ServiceInfo {
        ServiceInfo { peer_tx, rx }
    }

    fn handle_incoming(&self, header: &ServiceHeader, mut packet: Packet) {
        match header.sub_type {
            SERVICE_INFO_SUB_TYPE => {
                let services = from_retroshare_wire::<TlvServiceInfoMapRef>(&mut packet.payload).0;

                for s in services {
                    info!("num: {:#08X} -> {:?}", s.0 .0, s.1 .0);
                }
            }
            sub_type => log::error!("received unknown sub typ {sub_type}"),
        }
    }

    pub fn gen_service_info(services: &Vec<RsServiceInfo>) -> Packet {
        let services: TlvServiceInfoMapRef = services.to_owned().into();
        let payload = to_retroshare_wire(&services);
        let header = ServiceHeader::new(ServiceType::ServiceInfo, SERVICE_INFO_SUB_TYPE, &payload);

        Packet::new_without_location(header.into(), payload)
    }
}

#[async_trait]
impl Service for ServiceInfo {
    fn get_id(&self) -> ServiceType {
        ServiceType::ServiceInfo
    }

    fn get_service_info(&self) -> RsServiceInfo {
        RsServiceInfo::new(self.get_id().into(), "service_info")
    }
    fn run(mut self) -> JoinHandle<()> {
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
