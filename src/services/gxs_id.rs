use std::sync::Arc;

use async_trait::async_trait;
use log::{trace, warn};
use retroshare_compat::{
    gxs::sqlite::database::GxsDatabase,
    services::{service_info::RsServiceInfo, SERVICE_GXS_GXSID},
};
use tokio::{
    select,
    sync::mpsc::{UnboundedReceiver, UnboundedSender},
    task::JoinHandle,
};

use crate::{
    gxs::{gxs_backend::{GxsBackend, GxsShared}, nxs::NxsTransactionController},
    low_level_parsing::Packet,
    model::{intercom::Intercom, DataCore},
    services::Service,
};

use ::retroshare_compat::services::ServiceType;

pub struct GxsId {
    rx: UnboundedReceiver<Intercom>,
    backend: GxsBackend<SERVICE_GXS_GXSID>,
}

impl GxsId {
    pub async fn new(
        core: &Arc<DataCore>,
        _core_tx: UnboundedSender<Intercom>,
        rx: UnboundedReceiver<Intercom>,

        (db, shared): (GxsDatabase, Arc<GxsShared>),
    ) -> Self {
        let nxs = NxsTransactionController::new(shared.to_owned());
        let backend = GxsBackend::new(core.to_owned(), db, nxs, shared.to_owned());

        GxsId { rx, backend }
    }

    async fn handle_incoming(&self, packet: Packet) {
        self.backend.handle_packet(packet).await;
    }
}

#[async_trait]
impl Service for GxsId {
    fn get_id(&self) -> ServiceType {
        ServiceType::GxsId
    }

    fn get_service_info(&self) -> RsServiceInfo {
        RsServiceInfo::new(self.get_id().into(), "gxsid")
    }

    fn run(mut self) -> JoinHandle<()> {
        tokio::spawn(async move {
            loop {
                select! {
                    msg = self.rx.recv() => {
                        if let Some(msg) = msg {
                            trace!("handling msg {msg:?}");

                            match msg {
                                Intercom::Receive(packet) => {
                                    self.handle_incoming(packet).await;
                                }
                                _ => warn!("unexpected message: {msg:?}"),
                            }
                        }
                    }
                    _ = self.backend.run() => {
                        log::error!("gxs backend stopped");
                        panic!();
                    }
                }
            }
        })
    }
}
