use std::{sync::Arc, thread};

// use rocket::fairing::{Fairing, Info, Kind};
// use rocket::http::{ContentType, Method, Status};
// use rocket::response::content::Json;
// use rocket::{Data, Request, Response};
use rocket::routes;
use rocket_contrib::serve::StaticFiles;

use crate::model::DataCore;

#[allow(dead_code)]
mod rs_peers {
    use std::sync::Arc;

    use log::warn;

    use retroshare_compat::basics::{SslIdWrapped, SslIdHex};
    use rocket::{post, State};
    use rocket_contrib::json::{Json, JsonValue};
    use serde::Serialize;

    use super::RocketData;

    // #[derive(Deserialize)]
    // #[serde(rename_all = "camelCase")]
    // pub struct SslIdIn {
    //     // #[serde(with = "hex::serde")]
    //     ssl_id: SslId,
    // }

    // catch all
    #[post("/<function>")]
    pub fn rs_peers(function: String) -> JsonValue {
        warn!("called rsPeers/{}, NOT IMPLEMENTED", function);
        rocket_contrib::json!({"retval": false})
    }

    // rsPeers/GetRetroshareInvite
    #[post("/GetRetroshareInvite")]
    pub fn rs_peers_get_rs_invite(_state: State<RocketData>) -> JsonValue {
        rocket_contrib::json!({"retval": "123456789_THIS_IS_A_DUMMY"})
    }

    // rsPeers/getFriendList
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    pub struct FriendList {
        retval: bool,
        ssl_ids: Vec<SslIdHex>,
    }
    #[post("/getFriendList")]
    pub fn get_friend_list(state: State<RocketData>) -> Json<FriendList> {
        let ssl_ids = state
            .data_core
            .get_locations()
            .into_iter()
            .map(|loc| *loc.get_location_id())
            .map(|id| id.into())
            .collect();
        Json(FriendList {
            retval: true,
            ssl_ids,
        })
    }

    // rsPeers/getPeerDetails
    #[derive(Serialize)]
    pub struct PeerDetails {
        retval: bool,
        det: ::retroshare_compat::peers::PeerDetails,
    }
    #[post("/getPeerDetails", data = "<ssl_id>")]
    pub fn get_peer_details(
        state: State<RocketData>,
        ssl_id: Json<SslIdWrapped>,
    ) -> Json<PeerDetails> {
        Json(PeerDetails {
            retval: true,
            det: state
                .data_core
                .get_location_by_id(Arc::new(*ssl_id.0))
                .unwrap()
                .get_peer_details(),
        })
    }

    // rsPeers/isOnline
    #[derive(Serialize)]
    pub struct IsOnline {
        retval: bool,
    }
    #[post("/isOnline", data = "<ssl_id>")]
    pub fn is_online(state: State<RocketData>, ssl_id: Json<SslIdWrapped>) -> Json<IsOnline> {
        let online = state.data_core.is_online(Arc::new(*ssl_id.0));
        Json(IsOnline { retval: online })
    }
}

pub struct RocketData {
    data_core: Arc<DataCore>,
}

#[allow(dead_code)]
pub fn start_rocket(data_core: Arc<DataCore>) {
    let config = RocketData { data_core };

    let _web_ui = thread::spawn(|| {
        rocket::ignite()
            .mount(
                "/",
                StaticFiles::from(concat!(env!("CARGO_MANIFEST_DIR"), "/webui/")),
            )
            .mount(
                "/rsPeers",
                routes![
                    rs_peers::rs_peers,
                    rs_peers::rs_peers_get_rs_invite,
                    rs_peers::get_friend_list,
                    rs_peers::get_peer_details,
                    rs_peers::is_online,
                ],
            )
            .manage(config)
            .launch()
    });
}
