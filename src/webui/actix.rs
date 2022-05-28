use actix_files::Files;
use actix_web::{
    middleware, post,
    web::{self, Bytes},
    App, HttpResponse, HttpServer, Result,
};
use futures::Stream;
#[allow(unused_imports)]
use log::info;
use std::sync::Arc;
use tokio::sync::mpsc::UnboundedReceiver;

use crate::model::DataCore;

use super::{identity, msgs, peers};

// rsEvents/registerEventsHandler
struct SSEClient<T>(UnboundedReceiver<T>);
impl<T> Stream for SSEClient<T>
where
    T: ToString,
{
    type Item = Result<Bytes, std::io::Error>;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        self.0.poll_recv(cx).map(|some| {
            some.map(|m| {
                // FIXME: this should probably be moved to some "compat" place
                let s = String::from("data: ") + &m.to_string() + "\n\n";
                Ok(s.into())
            })
        })
    }
}
#[post("/registerEventsHandler")]
pub async fn rs_events_register_events_handler(state: web::Data<Arc<DataCore>>) -> HttpResponse {
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    state.webui_add_client(tx).await;

    let rx = SSEClient(rx);
    HttpResponse::Ok()
        .content_type("text/event-stream")
        .streaming(rx)
}

// #[post("/test")]
// pub async fn test() -> Result<impl Responder> {
//     Ok(web::Json(FormatRadix { format_radix: true }))
// }

pub async fn run_actix(data_core: Arc<DataCore>) {
    match HttpServer::new(move || {
        let data_core = data_core.clone();

        App::new()
            // enable logger
            .wrap(middleware::Logger::default())
            // shared state
            .app_data(web::Data::new(data_core))
            // json config
            .app_data(web::JsonConfig::default().limit(4096))
            // rsPeers
            .service(peers::get_entry_points())
            // rsMsgs
            .service(msgs::get_entry_points())
            // rsEvents
            .service(web::scope("/rsEvents").service(rs_events_register_events_handler))
            // rsIdentity
            .service(identity::get_entry_points())
            // // debug
            // .service(test)
            // files server
            .service(
                Files::new("/", concat!(env!("CARGO_MANIFEST_DIR"), "/webui/"))
                    .index_file("index.html"),
            )
    })
    .bind(("127.0.0.1", 9095))
    {
        Ok(s) => s.run().await.unwrap_or_else(|err| {
            log::error!("failed to start actix: {err}");
        }),
        Err(err) => log::error!("failed to bind actix: {err}"),
    }
}
