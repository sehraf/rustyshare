use actix_files::Files;
use actix_web::{
    post,
    web::{self, Bytes},
    App, HttpResponse, HttpServer, Responder, Result,
};
use futures::Stream;
#[allow(unused_imports)]
use log::info;
use retroshare_compat::{
    basics::{SslIdHex, SslIdWrapped},
    gxs::GroupMetaData,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::mpsc::UnboundedReceiver;

use crate::model::DataCore;

#[derive(Serialize)]

struct RetVal<T> {
    retval: T,
}

// rsPeers/getRetroshareInvite
#[post("/GetRetroshareInvite")]
pub async fn rs_peers_get_rs_invite(_state: web::Data<Arc<DataCore>>) -> Result<impl Responder> {
    Ok(web::Json(RetVal {
        retval: "123456789_THIS_IS_A_DUMMY",
    }))
}

// rsPeers/GetShortInvite
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FormatRadix {
    #[allow(dead_code)]
    format_radix: bool,
}
#[derive(Serialize)]
pub struct RsShortInvite {
    retval: bool,
    invite: String,
}
#[post("/GetShortInvite")]
pub async fn rs_peers_get_short_invite(
    _state: web::Data<Arc<DataCore>>,
    _format_radix: web::Json<FormatRadix>,
) -> Result<impl Responder> {
    Ok(web::Json(RsShortInvite {
        retval: true,
        invite: String::from("https://me.retroshare.cc?rsInvite=123456789_THIS_IS_A_DUMMY"),
    }))
}

// rsPeers/getFriendList
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FriendList {
    retval: bool,
    ssl_ids: Vec<SslIdHex>,
}
#[post("/getFriendList")]
pub async fn rs_peers_get_friend_list(state: web::Data<Arc<DataCore>>) -> Result<impl Responder> {
    let ssl_ids = state
        .get_locations()
        .into_iter()
        .map(|loc| *loc.get_location_id())
        .map(|id| id.into())
        .collect();

    Ok(web::Json(FriendList {
        retval: true,
        ssl_ids,
    }))
}

// rsPeers/getPeerDetails
#[derive(Serialize)]
pub struct PeerDetails {
    retval: bool,
    det: ::retroshare_compat::peers::PeerDetails,
}
#[post("/getPeerDetails")]
pub async fn rs_peers_get_peer_details(
    state: web::Data<Arc<DataCore>>,
    ssl_id: web::Json<SslIdWrapped>,
) -> Result<impl Responder> {
    Ok(web::Json(PeerDetails {
        retval: true,
        det: state
            .get_location_by_id(Arc::new(*ssl_id.0))
            .unwrap()
            .get_peer_details(),
    }))
}

// rsPeers/isOnline
#[derive(Serialize)]
pub struct IsOnline {
    retval: bool,
}
#[post("/isOnline")]
pub async fn rs_peers_is_online(
    state: web::Data<Arc<DataCore>>,
    ssl_id: web::Json<SslIdWrapped>,
) -> Result<impl Responder> {
    let online = state.is_online(Arc::new(*ssl_id.0)).await;
    Ok(web::Json(RetVal { retval: online }))
}

// rsIdentity/getIdentitiesSummaries
#[derive(Serialize)]
pub struct IdentitiesSummaries {
    retval: bool,
    id: Vec<GroupMetaData>,
}
#[post("/getIdentitiesSummaries")]
pub async fn rs_identity_get_identities_summaries(
    state: web::Data<Arc<DataCore>>,
) -> Result<impl Responder> {
    Ok(web::Json(IdentitiesSummaries {
        retval: true,
        id: state.get_identities_summaries().await,
    }))
}

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
                let s: String = ["data: ".into(), m.to_string(), "\n\n".into()].concat();
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

#[post("/test")]
pub async fn test() -> Result<impl Responder> {
    Ok(web::Json(FormatRadix { format_radix: true }))
}

pub async fn run_actix(data_core: Arc<DataCore>) {
    HttpServer::new(move || {
        let data_core = data_core.clone();

        App::new()
            // shared state
            .app_data(web::Data::new(data_core))
            // json config
            .app_data(web::JsonConfig::default().limit(4096))
            // rsPeers
            .service(
                web::scope("/rsPeers")
                    .service(rs_peers_get_peer_details)
                    .service(rs_peers_is_online)
                    .service(rs_peers_get_friend_list)
                    .service(rs_peers_get_rs_invite)
                    .service(rs_peers_get_short_invite),
            )
            // rsEvents
            .service(web::scope("/rsEvents").service(rs_events_register_events_handler))
            // rsIdentity
            .service(web::scope("/rsIdentity").service(rs_identity_get_identities_summaries))
            // debug
            .service(test)
            // files server
            .service(
                Files::new("/", concat!(env!("CARGO_MANIFEST_DIR"), "/webui/"))
                    .index_file("index.html"),
            )
    })
    .bind(("127.0.0.1", 9095))
    .expect("failed to bind")
    .run()
    .await
    .expect("failed to run actix");
}
