//! The V1 API things!

use axum::extract::{Path, Query, State};
use axum::headers::{CacheControl, HeaderMapExt};
use axum::middleware::from_fn;
use axum::response::{IntoResponse, Response};

use axum::routing::{delete, get, post, put};
use axum::{Extension, Json, Router};
use axum_macros::debug_handler;
use compact_jwt::Jws;
use http::{HeaderMap, HeaderValue, StatusCode};
use hyper::Body;
use kanidm_proto::v1::{
    AccountUnixExtend, ApiTokenGenerate, AuthIssueSession, AuthRequest, AuthResponse,
    AuthState as ProtoAuthState, CUIntentToken, CURequest, CUSessionToken, CreateRequest,
    DeleteRequest, Entry as ProtoEntry, GroupUnixExtend, ModifyRequest, SearchRequest,
    SingleStringRequest,
};

use kanidmd_lib::idm::event::AuthResult;
use kanidmd_lib::idm::AuthState;
use kanidmd_lib::prelude::*;
use kanidmd_lib::value::PartialValue;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::https::extractors::TrustedClientIp;
use crate::https::to_axum_response;

use super::middleware::caching::dont_cache_me;
use super::middleware::KOpId;
use super::v1_scim::*;
use super::ServerState;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub(crate) struct SessionId {
    pub sessionid: Uuid,
}

#[debug_handler]
pub async fn create(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Json(msg): Json<CreateRequest>,
) -> Response<Body> {
    // parse the req to a CreateRequest
    // let msg: CreateRequest = req.body_json().await?;

    let res = state
        .qe_w_ref
        .handle_create(kopid.uat, msg, kopid.eventid)
        .await;
    to_axum_response(res)
}

pub async fn v1_modify(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Json(msg): Json<ModifyRequest>,
) -> Response<Body> {
    let res = state
        .qe_w_ref
        .handle_modify(kopid.uat, msg, kopid.eventid)
        .await;
    to_axum_response(res)
}

pub async fn v1_delete(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Json(msg): Json<DeleteRequest>,
) -> Response<Body> {
    let res = state
        .qe_w_ref
        .handle_delete(kopid.uat, msg, kopid.eventid)
        .await;
    to_axum_response(res)
}

pub async fn search(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Json(msg): Json<SearchRequest>,
) -> Response<Body> {
    let res = state
        .qe_r_ref
        .handle_search(kopid.uat, msg, kopid.eventid)
        .await;
    to_axum_response(res)
}

#[debug_handler]
pub async fn whoami(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
) -> Response<Body> {
    // New event, feed current auth data from the token to it.
    let res = state.qe_r_ref.handle_whoami(kopid.uat, kopid.eventid).await;
    to_axum_response(res)
}

pub async fn whoami_uat(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
) -> impl IntoResponse {
    let res = state
        .qe_r_ref
        .handle_whoami_uat(kopid.uat, kopid.eventid)
        .await;
    to_axum_response(res)
}

pub async fn logout(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
) -> impl IntoResponse {
    let res = state.qe_w_ref.handle_logout(kopid.uat, kopid.eventid).await;

    to_axum_response(res)
}

// // =============== REST generics ========================

#[instrument(level = "trace", skip(state, kopid))]
pub async fn json_rest_event_get(
    state: ServerState,
    attrs: Option<Vec<String>>,
    filter: Filter<FilterInvalid>,
    kopid: KOpId,
) -> impl IntoResponse {
    let res = state
        .qe_r_ref
        .handle_internalsearch(kopid.uat, filter, attrs, kopid.eventid)
        .await;

    to_axum_response(res)
}

pub async fn json_rest_event_get_id(
    state: ServerState,
    id: String,
    filter: Filter<FilterInvalid>,
    attrs: Option<Vec<String>>,
    kopid: KOpId,
) -> impl IntoResponse {
    let filter = Filter::join_parts_and(filter, filter_all!(f_id(id.as_str())));

    let res = state
        .qe_r_ref
        .handle_internalsearch(kopid.uat, filter, attrs, kopid.eventid)
        .await
        .map(|mut r| r.pop());
    to_axum_response(res)
}

pub async fn json_rest_event_delete_id(
    state: ServerState,
    id: String,
    filter: Filter<FilterInvalid>,
    kopid: KOpId,
) -> impl IntoResponse {
    let filter = Filter::join_parts_and(filter, filter_all!(f_id(id.as_str())));
    let res = state
        .qe_w_ref
        .handle_internaldelete(kopid.uat, filter, kopid.eventid)
        .await;
    to_axum_response(res)
}

pub async fn json_rest_event_get_attr(
    state: ServerState,
    id: &str,
    attr: String,
    filter: Filter<FilterInvalid>,
    kopid: KOpId,
) -> impl IntoResponse {
    let filter = Filter::join_parts_and(filter, filter_all!(f_id(id)));
    let attrs = Some(vec![attr.clone()]);
    let res: Result<Option<_>, _> = state
        .qe_r_ref
        .handle_internalsearch(kopid.uat, filter, attrs, kopid.eventid)
        .await
        .map(|mut event_result| event_result.pop().and_then(|mut e| e.attrs.remove(&attr)));
    to_axum_response(res)
}

pub async fn json_rest_event_get_id_attr(
    state: ServerState,
    id: String,
    attr: String,
    filter: Filter<FilterInvalid>,
    kopid: KOpId,
) -> impl IntoResponse {
    json_rest_event_get_attr(state, id.as_str(), attr, filter, kopid).await
}

pub async fn json_rest_event_post(
    state: ServerState,
    classes: Vec<String>,
    obj: ProtoEntry,
    kopid: KOpId,
) -> impl IntoResponse {
    debug_assert!(!classes.is_empty());

    let mut obj = obj;
    obj.attrs.insert("class".to_string(), classes);
    let msg = CreateRequest {
        entries: vec![obj.to_owned()],
    };

    let res = state
        .qe_w_ref
        .handle_create(kopid.uat, msg, kopid.eventid)
        .await;
    to_axum_response(res)
}

pub async fn json_rest_event_post_id_attr(
    state: ServerState,
    id: String,
    attr: String,
    filter: Filter<FilterInvalid>,
    values: Vec<String>,
    kopid: KOpId,
) -> impl IntoResponse {
    let res = state
        .qe_w_ref
        .handle_appendattribute(kopid.uat, id, attr, values, filter, kopid.eventid)
        .await;
    to_axum_response(res)
}

pub async fn json_rest_event_put_attr(
    state: ServerState,
    id: String,
    attr: String,
    filter: Filter<FilterInvalid>,
    values: Vec<String>,
    kopid: KOpId,
) -> impl IntoResponse {
    let res = state
        .qe_w_ref
        .handle_setattribute(kopid.uat, id, attr, values, filter, kopid.eventid)
        .await;
    to_axum_response(res)
}

pub async fn json_rest_event_post_attr(
    state: ServerState,
    id: String,
    attr: String,
    filter: Filter<FilterInvalid>,
    values: Vec<String>,
    kopid: KOpId,
) -> impl IntoResponse {
    let uuid_or_name = id;
    let res = state
        .qe_w_ref
        .handle_appendattribute(kopid.uat, uuid_or_name, attr, values, filter, kopid.eventid)
        .await;
    to_axum_response(res)
}

pub async fn json_rest_event_put_id_attr(
    state: ServerState,
    id: String,
    attr: String,
    filter: Filter<FilterInvalid>,
    values: Vec<String>,
    kopid: KOpId,
) -> impl IntoResponse {
    json_rest_event_put_attr(state, id, attr, filter, values, kopid).await
}

pub async fn json_rest_event_delete_id_attr(
    state: ServerState,
    id: String,
    attr: String,
    filter: Filter<FilterInvalid>,
    values: Option<Vec<String>>,
    kopid: KOpId,
) -> impl IntoResponse {
    json_rest_event_delete_attr(state, id, attr, filter, values, kopid).await
}

pub async fn json_rest_event_delete_attr(
    state: ServerState,
    uuid_or_name: String,
    attr: String,
    filter: Filter<FilterInvalid>,
    values: Option<Vec<String>>,
    kopid: KOpId,
) -> impl IntoResponse {
    let values = match values {
        Some(val) => val,
        None => vec![],
    };

    if values.is_empty() {
        let res = state
            .qe_w_ref
            .handle_purgeattribute(kopid.uat, uuid_or_name, attr, filter, kopid.eventid)
            .await;
        to_axum_response(res)
    } else {
        let res = state
            .qe_w_ref
            .handle_removeattributevalues(
                kopid.uat,
                uuid_or_name,
                attr,
                values,
                filter,
                kopid.eventid,
            )
            .await;
        to_axum_response(res)
    }
}

// // Okay, so a put normally needs
// //  * filter of what we are working on (id + class)
// //  * a Map<String, Vec<String>> that we turn into a modlist.
// //
// // OR
// //  * filter of what we are working on (id + class)
// //  * a Vec<String> that we are changing
// //  * the attr name  (as a param to this in path)
// //
// // json_rest_event_put_id(path, req, state

pub async fn schema_get(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
) -> impl IntoResponse {
    // NOTE: This is filter_all, because from_internal_message will still do the alterations
    // needed to make it safe. This is needed because there may be aci's that block access
    // to the recycle/ts types in the filter, and we need the aci to only eval on this
    // part of the filter!
    let filter = filter_all!(f_or!([
        f_eq("class", PartialValue::new_class("attributetype")),
        f_eq("class", PartialValue::new_class("classtype"))
    ]));
    json_rest_event_get(state, None, filter, kopid).await
}

pub async fn schema_attributetype_get(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
) -> impl IntoResponse {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("attributetype")));
    json_rest_event_get(state, None, filter, kopid).await
}

pub async fn schema_attributetype_get_id(
    State(state): State<ServerState>,
    Path(id): Path<String>,
    Extension(kopid): Extension<KOpId>,
) -> impl IntoResponse {
    // These can't use get_id because the attribute name and class name aren't ... well name.
    let filter = filter_all!(f_and!([
        f_eq("class", PartialValue::new_class("attributetype")),
        f_eq("attributename", PartialValue::new_iutf8(id.as_str()))
    ]));

    let res = state
        .qe_r_ref
        .handle_internalsearch(kopid.uat, filter, None, kopid.eventid)
        .await
        .map(|mut r| r.pop());
    to_axum_response(res)
}

pub async fn schema_classtype_get(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
) -> impl IntoResponse {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("classtype")));
    json_rest_event_get(state, None, filter, kopid).await
}

pub async fn schema_classtype_get_id(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    // These can't use get_id because they attribute name and class name aren't ... well name.
    let filter = filter_all!(f_and!([
        f_eq("class", PartialValue::new_class("classtype")),
        f_eq("classname", PartialValue::new_iutf8(id.as_str()))
    ]));
    let res = state
        .qe_r_ref
        .handle_internalsearch(kopid.uat, filter, None, kopid.eventid)
        .await
        .map(|mut r| r.pop());
    to_axum_response(res)
}

// // == person ==
pub async fn person_get(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
) -> impl IntoResponse {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("person")));
    json_rest_event_get(state, None, filter, kopid).await
}

// expects the following fields in the attrs field of the req: [name, displayname]
#[debug_handler]
pub async fn person_post(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Json(obj): Json<ProtoEntry>,
) -> impl IntoResponse {
    let classes = vec![
        "person".to_string(),
        "account".to_string(),
        "object".to_string(),
    ];
    json_rest_event_post(state, classes, obj, kopid).await
}

pub async fn person_id_get(
    State(state): State<ServerState>,
    Path(id): Path<String>,
    Extension(kopid): Extension<KOpId>,
) -> impl IntoResponse {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("person")));
    json_rest_event_get_id(state, id, filter, None, kopid).await
}

pub async fn person_account_id_delete(
    State(state): State<ServerState>,
    Path(id): Path<String>,
    Extension(kopid): Extension<KOpId>,
) -> impl IntoResponse {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("person")));
    json_rest_event_delete_id(state, id, filter, kopid).await
}

// // == account ==

pub async fn service_account_get(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
) -> impl IntoResponse {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("service_account")));
    json_rest_event_get(state, None, filter, kopid).await
}

pub async fn service_account_post(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Json(obj): Json<ProtoEntry>,
) -> impl IntoResponse {
    let classes = vec![
        "service_account".to_string(),
        "account".to_string(),
        "object".to_string(),
    ];
    json_rest_event_post(state, classes, obj, kopid).await
}

pub async fn service_account_id_get(
    State(state): State<ServerState>,
    Path(id): Path<String>,
    Extension(kopid): Extension<KOpId>,
) -> impl IntoResponse {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("service_account")));
    json_rest_event_get_id(state, id, filter, None, kopid).await
}

pub async fn service_account_id_delete(
    State(state): State<ServerState>,
    Path(id): Path<String>,
    Extension(kopid): Extension<KOpId>,
) -> impl IntoResponse {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("service_account")));
    json_rest_event_delete_id(state, id, filter, kopid).await
}

pub async fn service_account_credential_generate(
    State(state): State<ServerState>,
    Path(id): Path<String>,
    Extension(kopid): Extension<KOpId>,
) -> impl IntoResponse {
    let res = state
        .qe_w_ref
        .handle_service_account_credential_generate(kopid.uat, id, kopid.eventid)
        .await;
    to_axum_response(res)
}

// // Due to how the migrations work in 6 -> 7, we can accidentally
// // mark "accounts" as service accounts when they are persons. This
// // allows migrating them to the person type due to it's similarities.
// //
// // In the future this will be REMOVED!
pub async fn service_account_into_person(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let res = state
        .qe_w_ref
        .handle_service_account_into_person(kopid.uat, id, kopid.eventid)
        .await;
    to_axum_response(res)
}

// // Api Token
pub async fn service_account_api_token_get(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let res = state
        .qe_r_ref
        .handle_service_account_api_token_get(kopid.uat, id, kopid.eventid)
        .await;
    to_axum_response(res)
}

pub async fn service_account_api_token_post(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Path(id): Path<String>,
    Json(obj): Json<ApiTokenGenerate>, // TODO work out if this limits the fields?
) -> impl IntoResponse {
    let res = state
        .qe_w_ref
        .handle_service_account_api_token_generate(
            kopid.uat,
            id,
            obj.label,
            obj.expiry,
            obj.read_write,
            kopid.eventid,
        )
        .await;
    to_axum_response(res)
}

pub async fn service_account_api_token_delete(
    State(state): State<ServerState>,
    Path((id, token_id)): Path<(String, Uuid)>,
    Extension(kopid): Extension<KOpId>,
) -> impl IntoResponse {
    let res = state
        .qe_w_ref
        .handle_service_account_api_token_destroy(kopid.uat, id, token_id, kopid.eventid)
        .await;
    to_axum_response(res)
}

// // Account stuff
// TODO: shouldn't this be service_account?
pub async fn account_id_get_attr(
    State(state): State<ServerState>,
    Path((id, attr)): Path<(String, String)>,
    Extension(kopid): Extension<KOpId>,
) -> impl IntoResponse {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("account")));
    json_rest_event_get_attr(state, id.as_str(), attr, filter, kopid).await
}

pub async fn account_id_post_attr(
    State(state): State<ServerState>,
    Path((id, attr)): Path<(String, String)>,
    Extension(kopid): Extension<KOpId>,
    Json(values): Json<Vec<String>>,
) -> impl IntoResponse {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("account")));
    json_rest_event_post_id_attr(state, id, attr, filter, values, kopid).await
}

pub async fn account_id_delete_attr(
    State(state): State<ServerState>,
    Path((id, attr)): Path<(String, String)>,
    Extension(kopid): Extension<KOpId>,
) -> impl IntoResponse {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("account")));
    json_rest_event_delete_id_attr(state, id, attr, filter, None, kopid).await
}

pub async fn account_id_put_attr(
    State(state): State<ServerState>,
    Path((id, attr)): Path<(String, String)>,
    Extension(kopid): Extension<KOpId>,
    Json(values): Json<Vec<String>>,
) -> impl IntoResponse {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("account")));
    json_rest_event_put_attr(state, id, attr, filter, values, kopid).await
}

pub async fn account_id_patch(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Path(id): Path<String>,
    Json(obj): Json<ProtoEntry>,
) -> impl IntoResponse {
    // Update a value / attrs

    let filter = filter_all!(f_eq("class", PartialValue::new_class("account")));
    let filter = Filter::join_parts_and(filter, filter_all!(f_id(id.as_str())));
    let res = state
        .qe_w_ref
        .handle_internalpatch(kopid.uat, filter, obj, kopid.eventid)
        .await;
    to_axum_response(res)
}

pub async fn account_get_id_credential_update(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let res = state
        .qe_w_ref
        .handle_idmcredentialupdate(kopid.uat, id, kopid.eventid)
        .await;
    to_axum_response(res)
}

#[instrument(level = "trace", skip(state, kopid))]
pub async fn account_get_id_credential_update_intent_ttl(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Path(id): Path<String>,
    Query(ttl): Query<u64>,
) -> impl IntoResponse {
    let res = state
        .qe_w_ref
        .handle_idmcredentialupdateintent(
            kopid.uat,
            id,
            Some(Duration::from_secs(ttl)),
            kopid.eventid,
        )
        .await;
    to_axum_response(res)
}

#[instrument(level = "trace", skip(state, kopid))]
pub async fn account_get_id_credential_update_intent(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let res = state
        .qe_w_ref
        .handle_idmcredentialupdateintent(kopid.uat, id, None, kopid.eventid)
        .await;
    // panic!("res: {:?}", res);
    to_axum_response(res)
}

pub async fn account_get_id_user_auth_token(
    State(state): State<ServerState>,
    Path(id): Path<String>,
    Extension(kopid): Extension<KOpId>,
) -> impl IntoResponse {
    let res = state
        .qe_r_ref
        .handle_account_user_auth_token_get(kopid.uat, id, kopid.eventid)
        .await;
    to_axum_response(res)
}

pub async fn account_user_auth_token_delete(
    State(state): State<ServerState>,
    Path((id, token_id)): Path<(String, Uuid)>,
    Extension(kopid): Extension<KOpId>,
) -> impl IntoResponse {
    let res = state
        .qe_w_ref
        .handle_account_user_auth_token_destroy(kopid.uat, id, token_id, kopid.eventid)
        .await;
    to_axum_response(res)
}

pub async fn credential_update_exchange_intent(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Json(intent_token): Json<CUIntentToken>,
) -> impl IntoResponse {
    let res = state
        .qe_w_ref
        .handle_idmcredentialexchangeintent(intent_token, kopid.eventid)
        .await;
    to_axum_response(res)
}

pub async fn credential_update_status(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Json(session_token): Json<CUSessionToken>,
) -> impl IntoResponse {
    let res = state
        .qe_r_ref
        .handle_idmcredentialupdatestatus(session_token, kopid.eventid)
        .await;
    to_axum_response(res)
}

// #[derive(Deserialize, Debug, Clone)]
// struct CUBody {
//     pub session_token: CUSessionToken,
//     pub scr: CURequest,
// }
#[instrument(level = "debug", skip(state, kopid))]
pub async fn credential_update_update(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Json(cubody): Json<Vec<serde_json::Value>>,
) -> impl IntoResponse {
    let scr: CURequest = match serde_json::from_value(cubody[0].clone()) {
        Ok(val) => val,
        Err(err) => {
            error!("Failed to deserialize CURequest: {:?}", err);
            #[allow(clippy::unwrap_used)]
            return Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::empty())
                .unwrap();
        }
    };
    let session_token = match serde_json::from_value(cubody[1].clone()) {
        Ok(val) => val,
        Err(err) => {
            error!("Failed to deserialize session token: {:?}", err);
            #[allow(clippy::unwrap_used)]
            return Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::empty())
                .unwrap();
        }
    };
    debug!("session_token: {:?}", session_token);
    debug!("scr: {:?}", scr);
    let res = state
        .qe_r_ref
        .handle_idmcredentialupdate(session_token, scr, kopid.eventid)
        .await;
    to_axum_response(res)
}

pub async fn credential_update_commit(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Json(session_token): Json<CUSessionToken>,
) -> impl IntoResponse {
    let res = state
        .qe_w_ref
        .handle_idmcredentialupdatecommit(session_token, kopid.eventid)
        .await;
    to_axum_response(res)
}

pub async fn credential_update_cancel(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Json(session_token): Json<CUSessionToken>,
) -> impl IntoResponse {
    let res = state
        .qe_w_ref
        .handle_idmcredentialupdatecancel(session_token, kopid.eventid)
        .await;
    to_axum_response(res)
}

pub async fn account_get_id_credential_status(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let res = state
        .qe_r_ref
        .handle_idmcredentialstatus(kopid.uat, id, kopid.eventid)
        .await;
    to_axum_response(res)
}

// // Return a vec of str
pub async fn account_get_id_ssh_pubkeys(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let res = state
        .qe_r_ref
        .handle_internalsshkeyread(kopid.uat, id, kopid.eventid)
        .await;
    to_axum_response(res)
}

pub async fn account_post_id_ssh_pubkey(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Path(id): Path<String>,
    Json((tag, key)): Json<(String, String)>,
) -> impl IntoResponse {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("account")));
    // Add a msg here
    let res = state
        .qe_w_ref
        .handle_sshkeycreate(kopid.uat, id, tag, key, filter, kopid.eventid)
        .await;
    to_axum_response(res)
}

pub async fn account_get_id_ssh_pubkey_tag(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Path((id, tag)): Path<(String, String)>,
) -> impl IntoResponse {
    let res = state
        .qe_r_ref
        .handle_internalsshkeytagread(kopid.uat, id, tag, kopid.eventid)
        .await;
    to_axum_response(res)
}

pub async fn account_delete_id_ssh_pubkey_tag(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Path((id, tag)): Path<(String, String)>,
) -> impl IntoResponse {
    let attr = "ssh_publickey".to_string();
    let values = vec![tag];
    let filter = filter_all!(f_eq("class", PartialValue::new_class("account")));
    let res = state
        .qe_w_ref
        .handle_removeattributevalues(kopid.uat, id, attr, values, filter, kopid.eventid)
        .await;
    to_axum_response(res)
}

// // Get and return a single str
pub async fn account_get_id_radius(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let res = state
        .qe_r_ref
        .handle_internalradiusread(kopid.uat, id, kopid.eventid)
        .await;
    to_axum_response(res)
}

pub async fn account_post_id_radius_regenerate(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    // Need to to send the regen msg
    let res = state
        .qe_w_ref
        .handle_regenerateradius(kopid.uat, id, kopid.eventid)
        .await;
    to_axum_response(res)
}

pub async fn account_delete_id_radius(
    State(state): State<ServerState>,
    Path(id): Path<String>,
    Extension(kopid): Extension<KOpId>,
) -> impl IntoResponse {
    let attr = "radius_secret".to_string();
    let filter = filter_all!(f_eq("class", PartialValue::new_class("account")));
    json_rest_event_delete_id_attr(state, id, attr, filter, None, kopid).await
}

pub async fn account_get_id_radius_token(
    State(state): State<ServerState>,
    Path(id): Path<String>,
    Extension(kopid): Extension<KOpId>,
) -> impl IntoResponse {
    let res = state
        .qe_r_ref
        .handle_internalradiustokenread(kopid.uat, id, kopid.eventid)
        .await;
    let mut res = to_axum_response(res);
    debug!("Response: {:?}", res);
    let cache_header = CacheControl::new()
        .with_max_age(Duration::from_secs(300))
        .with_private();
    res.headers_mut().typed_insert(cache_header);
    res
}

pub async fn account_post_id_unix(
    State(state): State<ServerState>,
    Path(id): Path<String>,
    Extension(kopid): Extension<KOpId>,
    Json(obj): Json<AccountUnixExtend>,
) -> impl IntoResponse {
    let res = state
        .qe_w_ref
        .handle_idmaccountunixextend(kopid.uat, id, obj, kopid.eventid)
        .await;
    to_axum_response(res)
}

pub async fn account_get_id_unix_token(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let res = state
        .qe_r_ref
        .handle_internalunixusertokenread(kopid.uat, id, kopid.eventid)
        .await;
    to_axum_response(res)
}

pub async fn account_post_id_unix_auth(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Path(id): Path<String>,
    Json(obj): Json<SingleStringRequest>,
) -> impl IntoResponse {
    let res = state
        .qe_r_ref
        .handle_idmaccountunixauth(kopid.uat, id, obj.value, kopid.eventid)
        .await;
    to_axum_response(res)
}

pub async fn account_put_id_unix_credential(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Path(id): Path<String>,
    Json(obj): Json<SingleStringRequest>,
) -> impl IntoResponse {
    let res = state
        .qe_w_ref
        .handle_idmaccountunixsetcred(kopid.uat, id, obj.value, kopid.eventid)
        .await;
    to_axum_response(res)
}

pub async fn account_delete_id_unix_credential(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("posixaccount")));
    let res = state
        .qe_w_ref
        .handle_purgeattribute(
            kopid.uat,
            id,
            "unix_password".to_string(),
            filter,
            kopid.eventid,
        )
        .await;
    to_axum_response(res)
}

pub async fn group_get(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
) -> impl IntoResponse {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("group")));
    json_rest_event_get(state, None, filter, kopid).await
}

pub async fn group_post(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Json(obj): Json<ProtoEntry>,
) -> impl IntoResponse {
    let classes = vec!["group".to_string(), "object".to_string()];
    json_rest_event_post(state, classes, obj, kopid).await
}

pub async fn group_id_get(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("group")));
    json_rest_event_get_id(state, id, filter, None, kopid).await
}

pub async fn group_id_get_attr(
    State(state): State<ServerState>,
    Path((id, attr)): Path<(String, String)>,
    Extension(kopid): Extension<KOpId>,
) -> impl IntoResponse {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("group")));
    json_rest_event_get_id_attr(state, id, attr, filter, kopid).await
}

pub async fn group_id_post_attr(
    Path((id, attr)): Path<(String, String)>,
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Json(values): Json<Vec<String>>,
) -> impl IntoResponse {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("group")));
    json_rest_event_post_id_attr(state, id, attr, filter, values, kopid).await
}

pub async fn group_id_delete_attr(
    Path((id, attr)): Path<(String, String)>,
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    values: Option<Json<Vec<String>>>,
) -> impl IntoResponse {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("group")));
    let values = values.map(|v| v.0);
    json_rest_event_delete_id_attr(state, id, attr, filter, values, kopid).await
}

pub async fn group_id_put_attr(
    Path((id, attr)): Path<(String, String)>,
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Json(values): Json<Vec<String>>,
) -> impl IntoResponse {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("group")));
    json_rest_event_put_id_attr(state, id, attr, filter, values, kopid).await
}
pub async fn group_id_delete(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("group")));
    json_rest_event_delete_id(state, id, filter, kopid).await
}

pub async fn group_post_id_unix(
    State(state): State<ServerState>,
    Path(id): Path<String>,
    Extension(kopid): Extension<KOpId>,
    Json(obj): Json<GroupUnixExtend>,
) -> impl IntoResponse {
    let res = state
        .qe_w_ref
        .handle_idmgroupunixextend(kopid.uat, id, obj, kopid.eventid)
        .await;
    to_axum_response(res)
}

pub async fn group_get_id_unix_token(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let res = state
        .qe_r_ref
        .handle_internalunixgrouptokenread(kopid.uat, id, kopid.eventid)
        .await;
    to_axum_response(res)
}

pub async fn domain_get(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
) -> impl IntoResponse {
    let filter = filter_all!(f_eq("uuid", PartialValue::Uuid(UUID_DOMAIN_INFO)));
    json_rest_event_get(state, None, filter, kopid).await
}

pub async fn domain_get_attr(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Path(attr): Path<String>,
) -> impl IntoResponse {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("domain_info")));
    json_rest_event_get_attr(state, STR_UUID_DOMAIN_INFO, attr, filter, kopid).await
}

pub async fn domain_put_attr(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Path(attr): Path<String>,
    Json(values): Json<Vec<String>>,
) -> impl IntoResponse {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("domain_info")));
    json_rest_event_put_attr(
        state,
        STR_UUID_DOMAIN_INFO.to_string(),
        attr,
        filter,
        values,
        kopid,
    )
    .await
}

pub async fn domain_delete_attr(
    State(state): State<ServerState>,
    Path(attr): Path<String>,
    Extension(kopid): Extension<KOpId>,
    Json(values): Json<Option<Vec<String>>>,
) -> impl IntoResponse {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("domain_info")));
    json_rest_event_delete_attr(
        state,
        STR_UUID_DOMAIN_INFO.to_string(),
        attr,
        filter,
        values,
        kopid,
    )
    .await
}

pub async fn system_get(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
) -> impl IntoResponse {
    let filter = filter_all!(f_eq("uuid", PartialValue::Uuid(UUID_SYSTEM_CONFIG)));
    json_rest_event_get(state, None, filter, kopid).await
}

pub async fn system_get_attr(
    State(state): State<ServerState>,
    Path(attr): Path<String>,
    Extension(kopid): Extension<KOpId>,
) -> impl IntoResponse {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("system_config")));
    json_rest_event_get_attr(state, STR_UUID_SYSTEM_CONFIG, attr, filter, kopid).await
}

pub async fn system_post_attr(
    State(state): State<ServerState>,
    Path(attr): Path<String>,
    Extension(kopid): Extension<KOpId>,
    Json(values): Json<Vec<String>>,
) -> impl IntoResponse {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("system_config")));
    json_rest_event_post_attr(
        state,
        STR_UUID_SYSTEM_CONFIG.to_string(),
        attr,
        filter,
        values,
        kopid,
    )
    .await
}

pub async fn system_delete_attr(
    State(state): State<ServerState>,
    Path(attr): Path<String>,
    Extension(kopid): Extension<KOpId>,
    Json(values): Json<Option<Vec<String>>>,
) -> impl IntoResponse {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("system_config")));
    json_rest_event_delete_attr(
        state,
        STR_UUID_SYSTEM_CONFIG.to_string(),
        attr,
        filter,
        values,
        kopid,
    )
    .await
}

pub async fn recycle_bin_get(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
) -> impl IntoResponse {
    let filter = filter_all!(f_pres("class"));
    let attrs = None;
    let res = state
        .qe_r_ref
        .handle_internalsearchrecycled(kopid.uat, filter, attrs, kopid.eventid)
        .await;
    to_axum_response(res)
}

pub async fn recycle_bin_id_get(
    State(state): State<ServerState>,

    Path(id): Path<String>,
    Extension(kopid): Extension<KOpId>,
) -> impl IntoResponse {
    let filter = filter_all!(f_id(id.as_str()));
    let attrs = None;

    let res = state
        .qe_r_ref
        .handle_internalsearchrecycled(kopid.uat, filter, attrs, kopid.eventid)
        .await
        .map(|mut r| r.pop());
    to_axum_response(res)
}

pub async fn recycle_bin_revive_id_post(
    State(state): State<ServerState>,
    Path(id): Path<String>,
    Extension(kopid): Extension<KOpId>,
) -> impl IntoResponse {
    let filter = filter_all!(f_id(id.as_str()));
    let res = state
        .qe_w_ref
        .handle_reviverecycled(kopid.uat, filter, kopid.eventid)
        .await;
    to_axum_response(res)
}

pub async fn applinks_get(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
) -> impl IntoResponse {
    let res = state
        .qe_r_ref
        .handle_list_applinks(kopid.uat, kopid.eventid)
        .await;
    to_axum_response(res)
}

// TODO: routemap things
// pub async fn do_routemap(State(state): State<RouteMap>) -> impl IntoResponse {
//     Json(state.do_map())
// }

pub async fn reauth(
    State(state): State<ServerState>,
    TrustedClientIp(ip_addr): TrustedClientIp,
    Extension(kopid): Extension<KOpId>,
    Json(obj): Json<AuthIssueSession>,
) -> impl IntoResponse {
    // This may change in the future ...
    let inter = state
        .qe_r_ref
        .handle_reauth(kopid.uat, obj, kopid.eventid, ip_addr)
        .await;
    debug!("REAuth result: {:?}", inter);
    auth_session_state_management(state, inter)
}

pub async fn auth(
    State(state): State<ServerState>,
    TrustedClientIp(ip_addr): TrustedClientIp,
    headers: HeaderMap,
    Extension(kopid): Extension<KOpId>,
    Json(obj): Json<AuthRequest>,
) -> impl IntoResponse {
    // First, deal with some state management.
    // Do anything here first that's needed like getting the session details
    // out of the req cookie.

    let maybe_sessionid = state.get_current_auth_session_id(&headers);
    debug!("Session ID: {:?}", maybe_sessionid);
    // We probably need to know if we allocate the cookie, that this is a
    // new session, and in that case, anything *except* authrequest init is
    // invalid.
    let inter = state // This may change in the future ...
        .qe_r_ref
        .handle_auth(maybe_sessionid, obj, kopid.eventid, ip_addr)
        .await;
    debug!("Auth result: {:?}", inter);
    auth_session_state_management(state, inter)
}

#[instrument(skip(state))]
fn auth_session_state_management(
    state: ServerState,
    inter: Result<AuthResult, OperationError>,
) -> impl IntoResponse {
    let mut auth_session_id_tok = None;

    let res: Result<AuthResponse, _> = match inter {
        Ok(AuthResult {
            state: auth_state,
            sessionid,
        }) => {
            // Do some response/state management.
            match auth_state {
                AuthState::Choose(allowed) => {
                    debug!("🧩 -> AuthState::Choose"); // TODO: this should be ... less work
                                                       // Ensure the auth-session-id is set
                    let kref = &state.jws_signer;
                    let jws = Jws::new(SessionId { sessionid });
                    // Get the header token ready.
                    jws.sign(kref)
                        .map(|jwss| {
                            auth_session_id_tok = Some(jwss.to_string());
                        })
                        .map_err(|e| {
                            error!(?e);
                            OperationError::InvalidSessionState
                        })
                        .map(|_| ProtoAuthState::Choose(allowed))
                }
                AuthState::Continue(allowed) => {
                    debug!("🧩 -> AuthState::Continue");
                    let kref = &state.jws_signer;
                    // Get the header token ready.
                    let jws = Jws::new(SessionId { sessionid });
                    jws.sign(kref)
                        .map(|jwss| {
                            auth_session_id_tok = Some(jwss.to_string());
                        })
                        .map_err(|e| {
                            error!(?e);
                            OperationError::InvalidSessionState
                        })
                        .map(|_| ProtoAuthState::Continue(allowed))
                }
                AuthState::Success(token, issue) => {
                    debug!("🧩 -> AuthState::Success");

                    match issue {
                        AuthIssueSession::Token => Ok(ProtoAuthState::Success(token)),
                    }
                }
                AuthState::Denied(reason) => {
                    debug!("🧩 -> AuthState::Denied");
                    Ok(ProtoAuthState::Denied(reason))
                }
            }
            .map(|state| AuthResponse { sessionid, state })
        }
        Err(e) => Err(e),
    };

    let mut res = to_axum_response(res);

    // if the sessionid was injected into our cookie, set it in the header too.
    match auth_session_id_tok {
        Some(tok) => {
            #[allow(clippy::unwrap_used)]
            res.headers_mut().insert(
                "X-KANIDM-AUTH-SESSION-ID",
                HeaderValue::from_str(&tok).unwrap(),
            );
            res
        }
        None => res,
    }
}

pub async fn auth_valid(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
) -> impl IntoResponse {
    let res = state
        .qe_r_ref
        .handle_auth_valid(kopid.uat, kopid.eventid)
        .await;
    to_axum_response(res)
}

#[instrument(skip(state))]
pub fn router(state: ServerState) -> Router<ServerState> {
    Router::new()
        .route("/v1/oauth2", get(super::oauth2::oauth2_get))
        .route("/v1/oauth2/_basic", post(super::oauth2::oauth2_basic_post))
        .route(
            "/v1/oauth2/_public",
            post(super::oauth2::oauth2_public_post),
        )
        .route(
            "/v1/oauth2/:rs_name",
            get(super::oauth2::oauth2_id_get)
                .patch(super::oauth2::oauth2_id_patch)
                .delete(super::oauth2::oauth2_id_delete),
        )
        .route(
            "/v1/oauth2/:rs_name/_basic_secret",
            get(super::oauth2::oauth2_id_get_basic_secret),
        )
        .route(
            "/v1/oauth2/:rs_name/_scopemap/:group",
            post(super::oauth2::oauth2_id_scopemap_post)
                .delete(super::oauth2::oauth2_id_scopemap_delete),
        )
        .route(
            "/v1/oauth2/:rs_name/_sup_scopemap/:group",
            post(super::oauth2::oauth2_id_sup_scopemap_post)
                .delete(super::oauth2::oauth2_id_sup_scopemap_delete),
        )
        .route("/v1/raw/create", post(create))
        .route("/v1/raw/modify", post(v1_modify))
        .route("/v1/raw/delete", post(v1_delete))
        .route("/v1/raw/search", post(search))
        .route("/v1/schema", get(schema_get))
        .route(
            "/v1/schema/attributetype",
            get(schema_attributetype_get), // post(|| async { "TODO" })
        )
        .route(
            "/v1/schema/attributetype/:id",
            get(schema_attributetype_get_id),
        )
        // .route("/schema/attributetype/:id", put(|| async { "TODO" }).patch(|| async { "TODO" }))
        .route(
            "/v1/schema/classtype",
            get(schema_classtype_get), // .post(|| async { "TODO" })
        )
        .route(
            "/v1/schema/classtype/:id",
            get(schema_classtype_get_id)
                .put(|| async { "TODO" })
                .patch(|| async { "TODO" }),
        )
        .route("/v1/self", get(whoami))
        .route("/v1/self/_uat", get(whoami_uat))
        .route("/v1/self/_attr/:attr", get(|| async { "TODO" }))
        .route("/v1/self/_credential", get(|| async { "TODO" }))
        .route("/v1/self/_credential/:cid/_lock", get(|| async { "TODO" }))
        .route(
            "/v1/self/_radius",
            get(|| async { "TODO" })
                .delete(|| async { "TODO" })
                .post(|| async { "TODO" }),
        )
        .route("/v1/self/_radius/_config", post(|| async { "TODO" }))
        .route("/v1/self/_radius/_config/:token", get(|| async { "TODO" }))
        .route(
            "/v1/self/_radius/_config/:token/apple",
            get(|| async { "TODO" }),
        )
        // Applinks are the list of apps this account can access.
        .route("/v1/self/_applinks", get(applinks_get))
        // Person routes
        .route("/v1/person", get(person_get))
        .route("/v1/person", post(person_post))
        .route(
            "/v1/person/:id",
            get(person_id_get)
                .patch(account_id_patch)
                .delete(person_account_id_delete),
        )
        .route(
            "/v1/person/:id/_attr/:attr",
            get(account_id_get_attr)
                .put(account_id_put_attr)
                .post(account_id_post_attr)
                .delete(account_id_delete_attr),
        )
        .route("/v1/person/:id/_lock", get(|| async { "TODO" }))
        .route("/v1/person/:id/_credential", get(|| async { "TODO" }))
        .route(
            "/v1/person/:id/_credential/_status",
            get(account_get_id_credential_status),
        )
        .route(
            "/v1/person/:id/_credential/:cid/_lock",
            get(|| async { "TODO" }),
        )
        .route(
            "/v1/person/:id/_credential/_update",
            get(account_get_id_credential_update),
        )
        .route(
            "/v1/person/:id/_credential/_update_intent/:ttl",
            get(account_get_id_credential_update_intent_ttl),
        )
        .route(
            "/v1/person/:id/_credential/_update_intent",
            get(account_get_id_credential_update_intent),
        )
        .route(
            "/v1/person/:id/_ssh_pubkeys",
            get(account_get_id_ssh_pubkeys).post(account_post_id_ssh_pubkey),
        )
        .route(
            "/v1/person/:id/_ssh_pubkeys/:tag",
            get(account_get_id_ssh_pubkey_tag).delete(account_delete_id_ssh_pubkey_tag),
        )
        .route(
            "/v1/person/:id/_radius",
            get(account_get_id_radius)
                .post(account_post_id_radius_regenerate)
                .delete(account_delete_id_radius),
        )
        .route(
            "/v1/person/:id/_radius/_token",
            get(account_get_id_radius_token),
        ) // TODO: make this cacheable
        .route("/v1/person/:id/_unix", post(account_post_id_unix))
        .route(
            "/v1/person/:id/_unix/_credential",
            put(account_put_id_unix_credential).delete(account_delete_id_unix_credential),
        )
        // Service accounts
        .route(
            "/v1/service_account",
            get(service_account_get).post(service_account_post),
        )
        .route(
            "/v1/service_account/",
            get(service_account_get).post(service_account_post),
        )
        .route(
            "/v1/service_account/:id",
            get(service_account_id_get).delete(service_account_id_delete),
        )
        .route(
            "/v1/service_account/:id/_attr/:attr",
            get(account_id_get_attr)
                .put(account_id_put_attr)
                .post(account_id_post_attr)
                .delete(account_id_delete_attr),
        )
        .route("/v1/service_account/:id/_lock", get(|| async { "TODO" }))
        .route(
            "/v1/service_account/:id/_into_person",
            post(service_account_into_person),
        )
        .route(
            "/v1/service_account/:id/_api_token",
            post(service_account_api_token_post).get(service_account_api_token_get),
        )
        .route(
            "/v1/service_account/:id/_api_token/:token_id",
            delete(service_account_api_token_delete),
        )
        .route(
            "/v1/service_account/:id/_credential",
            get(|| async { "TODO" }),
        )
        .route(
            "/v1/service_account/:id/_credential/_generate",
            get(service_account_credential_generate),
        )
        .route(
            "/v1/service_account/:id/_credential/_status",
            get(account_get_id_credential_status),
        )
        .route(
            "/v1/service_account/:id/_credential/:cid/_lock",
            get(|| async { "TODO" }),
        )
        .route(
            "/v1/service_account/:id/_ssh_pubkeys",
            get(account_get_id_ssh_pubkeys).post(account_post_id_ssh_pubkey),
        )
        .route(
            "/v1/service_account/:id/_ssh_pubkeys/:tag",
            get(account_get_id_ssh_pubkey_tag).delete(account_delete_id_ssh_pubkey_tag),
        )
        .route("/v1/service_account/:id/_unix", post(account_post_id_unix))
        .route(
            "/v1/account/:id/_unix/_auth",
            post(account_post_id_unix_auth),
        )
        .route(
            "/v1/account/:id/_unix/_token",
            post(account_get_id_unix_token).get(account_get_id_unix_token), // TODO: make this cacheable
        )
        .route(
            "/v1/account/:id/_radius/_token",
            post(account_get_id_radius_token).get(account_get_id_radius_token), // TODO: make this cacheable
        )
        .route(
            "/v1/account/:id/_ssh_pubkeys",
            get(account_get_id_ssh_pubkeys),
        )
        .route(
            "/v1/account/:id/_ssh_pubkeys/:tag",
            get(account_get_id_ssh_pubkey_tag),
        )
        .route(
            "/v1/account/:id/_user_auth_token",
            get(account_get_id_user_auth_token),
        )
        .route(
            "/v1/account/:id/_user_auth_token/:token_id",
            delete(account_user_auth_token_delete),
        )
        .route(
            "/v1/credential/_exchange_intent",
            post(credential_update_exchange_intent),
        )
        .route("/v1/credential/_status", post(credential_update_status))
        .route("/v1/credential/_update", post(credential_update_update))
        .route("/v1/credential/_commit", post(credential_update_commit))
        .route("/v1/credential/_cancel", post(credential_update_cancel))
        // domain-things
        .route("/v1/domain", get(domain_get))
        .route(
            "/v1/domain/_attr/:attr",
            get(domain_get_attr)
                .put(domain_put_attr)
                .delete(domain_delete_attr),
        )
        .route("/v1/group/:id/_unix/_token", get(group_get_id_unix_token))
        .route("/v1/group/:id/_unix", post(group_post_id_unix))
        .route("/v1/group", get(group_get).post(group_post))
        .route("/v1/group/:id", get(group_id_get).delete(group_id_delete))
        .route(
            "/v1/group/:id/_attr/:attr",
            delete(group_id_delete_attr)
                .get(group_id_get_attr)
                .put(group_id_put_attr)
                .post(group_id_post_attr),
        )
        .with_state(state.clone())
        .route("/v1/system", get(system_get))
        .route(
            "/v1/system/_attr/:attr",
            get(system_get_attr)
                .post(system_post_attr)
                .delete(system_delete_attr),
        )
        .route("/v1/recycle_bin", get(recycle_bin_get))
        .route("/v1/recycle_bin/:id", get(recycle_bin_id_get))
        .route(
            "/v1/recycle_bin/:id/_revive",
            post(recycle_bin_revive_id_post),
        )
        .route("/v1/access_profile", get(|| async { "TODO" }))
        .route("/v1/access_profile/:id", get(|| async { "TODO" }))
        .route(
            "/v1/access_profile/:id/_attr/:attr",
            get(|| async { "TODO" }),
        )
        .route("/v1/auth", post(auth))
        .route("/v1/auth/valid", get(auth_valid))
        .route("/v1/logout", get(logout))
        .route("/v1/reauth", post(reauth))
        .route(
            "/v1/sync_account",
            get(sync_account_get).post(sync_account_post),
        )
        .route(
            "/v1/sync_account/",
            get(sync_account_get).post(sync_account_post),
        )
        .route(
            "/v1/sync_account/:id",
            get(sync_account_id_get).patch(sync_account_id_patch),
        )
        .route(
            "/v1/sync_account/:id/_attr/:attr",
            get(sync_account_id_get_attr).put(sync_account_id_put_attr),
        )
        .route(
            "/v1/sync_account/:id/_finalise",
            get(sync_account_id_get_finalise),
        )
        .route(
            "/v1/sync_account/:id/_terminate",
            get(sync_account_id_get_terminate),
        )
        .route(
            "/v1/sync_account/:id/_sync_token",
            post(sync_account_token_post).delete(sync_account_token_delete),
        )
        .with_state(state)
        .layer(from_fn(dont_cache_me))
}
