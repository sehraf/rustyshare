use std::sync::Arc;

use actix_web::{
    post,
    web::{self},
    Responder, Result,
};
use retroshare_compat::basics::{SslIdHex, SslIdWrapped};
use serde::{Deserialize, Serialize};

use crate::{model::DataCore, webui::RetVal};

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

pub fn get_entry_points() -> actix_web::Scope {
    web::scope("/rsPeers")
        .service(rs_peers_get_peer_details)
        .service(rs_peers_is_online)
        .service(rs_peers_get_friend_list)
        .service(rs_peers_get_rs_invite)
        .service(rs_peers_get_short_invite)
}
