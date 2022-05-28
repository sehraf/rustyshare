use std::{collections::HashMap, sync::Arc};

use actix_web::{
    post,
    web::{self},
    Responder, Result,
};
use retroshare_compat::{
    basics::{GxsId, GxsIdHex, PgpIdHex},
    gxs::db::GroupMetaData,
    webui::identity::IdentityDetails,
};
use serde::Serialize;

use crate::{gen_webui_param_type, gen_webui_return_type, model::DataCore};

// rsIdentity/getIdentitiesSummaries
#[derive(Serialize)]
pub struct IdentitiesSummaries {
    retval: bool,
    ids: Vec<GroupMetaData>,
}
#[post("/getIdentitiesSummaries")]
pub async fn rs_identity_get_identities_summaries(
    state: web::Data<Arc<DataCore>>,
) -> Result<impl Responder> {
    Ok(web::Json(IdentitiesSummaries {
        retval: true,
        ids: state
            .get_service_data()
            .gxs_id()
            .get_identities_summaries()
            .await,
    }))
}

// rsIdentity/getOwnSignedIds
// /**
//  * @brief Get own signed ids
//  * @jsonapi{development}
//  * @param[out] ids storage for the ids
//  * @return false on error, true otherwise
//  */
//  virtual bool getOwnSignedIds(std::vector<RsGxsId>& ids) = 0;
gen_webui_return_type!(GetOwnSignedIds, ids, Vec<GxsIdHex>);
#[post("/getOwnSignedIds")]
pub async fn rs_identity_get_own_signed_ids(
    state: web::Data<Arc<DataCore>>,
) -> Result<impl Responder> {
    let ids = state
        .get_service_data()
        .gxs_id()
        .get_identities_summaries()
        .await
        .iter()
        .filter_map(|entry| {
            // FLAG_AUTHOR_AUTHENTICATION_GPG   0x00000100
            // GROUP_SUBSCRIBE_ADMIN            0x01
            if (entry.group_flags & 0x100) > 0 && (entry.subscribe_flags & 0x1) > 0 {
                Some(entry.group_id.to_owned())
            } else {
                None
            }
        })
        .map(|id| Into::<GxsId>::into(id.to_vec()).into())
        .collect();

    Ok(web::Json(GetOwnSignedIds { retval: true, ids }))
}

// rsIdentity/getOwnPseudonimousIds
// /**
//  * @brief Get own pseudonimous (unsigned) ids
//  * @jsonapi{development}
//  * @param[out] ids storage for the ids
//  * @return false on error, true otherwise
//  */
//  virtual bool getOwnPseudonimousIds(std::vector<RsGxsId>& ids) = 0;
#[post("/getOwnPseudonimousIds")]
pub async fn rs_identity_get_own_pseudonimous_ids(
    state: web::Data<Arc<DataCore>>,
) -> Result<impl Responder> {
    let ids = state
        .get_service_data()
        .gxs_id()
        .get_identities_summaries()
        .await
        .iter()
        .filter_map(|entry| {
            // FLAG_AUTHOR_AUTHENTICATION_GPG   0x00000100
            // GROUP_SUBSCRIBE_ADMIN            0x01
            if (entry.group_flags & 0x100) == 0 && (entry.subscribe_flags & 0x1) > 0 {
                Some(entry.group_id.to_owned())
            } else {
                None
            }
        })
        .map(|id| Into::<GxsId>::into(id.to_vec()).into())
        .collect();

    Ok(web::Json(GetOwnSignedIds { retval: true, ids }))
}

// rsIdentity/getIdDetails
// /**
//  * @brief Get identity details, from the cache
//  * @jsonapi{development}
//  * @param[in] id Id of the identity
//  * @param[out] details Storage for the identity details
//  * @return false on error, true otherwise
//  */
//  virtual bool getIdDetails(const RsGxsId& id, RsIdentityDetails& details) = 0;
gen_webui_param_type!(GetIdDetailsIn, id: GxsIdHex);
gen_webui_return_type!(GetIdDetails, details, IdentityDetails);
#[post("/getIdDetails")]
pub async fn rs_identity_get_id_details(
    state: web::Data<Arc<DataCore>>,
    id: web::Json<GetIdDetailsIn>,
) -> Result<impl Responder> {
    let meta = state
        .get_service_data()
        .gxs_id()
        .get_identities_summaries()
        .await;
    let details = meta
        .iter()
        .find(|entry| entry.group_id.to_vec() == id.id.to_vec())
        .unwrap()
        .to_owned();
    let details = IdentityDetails {
        id: Into::<GxsId>::into(details.group_id.to_vec()).into(),
        nickname: details.group_name.to_owned(),
        flags: details.group_flags,
        pgp_id: PgpIdHex::default(),
        reputation: (),
        avatar: vec![],
        publish_ts: details.publish_ts.into(),
        last_usage_ts: details.last_seen.into(), // FIXME
        use_cases: HashMap::new(),
    };

    Ok(web::Json(GetIdDetails {
        retval: true,
        details,
    }))
}

pub fn get_entry_points() -> actix_web::Scope {
    web::scope("/rsIdentity")
        .service(rs_identity_get_identities_summaries)
        .service(rs_identity_get_own_signed_ids)
        .service(rs_identity_get_own_pseudonimous_ids)
        .service(rs_identity_get_id_details)
}
