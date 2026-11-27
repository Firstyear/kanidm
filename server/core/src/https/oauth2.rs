use std::collections::{BTreeMap, BTreeSet};

use super::{errors::WebError, middleware::KOpId, ServerState};
use crate::https::extractors::{AuthorisationHeaders, VerifiedClientInformation};
use axum::{
    body::Body,
    extract::{Path, Query, State},
    http::{
        header::{
            ACCESS_CONTROL_ALLOW_HEADERS, ACCESS_CONTROL_ALLOW_ORIGIN, CONTENT_TYPE, LOCATION,
            WWW_AUTHENTICATE,
        },
        HeaderValue, StatusCode,
    },
    middleware::from_fn,
    response::{IntoResponse, Response},
    routing::{get, post},
    Extension, Form, Json, Router,
};
use axum_macros::debug_handler;
use kanidm_proto::{
    constants::{
        uri::{OAUTH2_AUTHORISE, OAUTH2_AUTHORISE_PERMIT, OAUTH2_AUTHORISE_REJECT},
        APPLICATION_JSON,
    },
    oauth2::AuthorisationResponse,
};
use kanidmd_lib::{
    idm::oauth2::{
        AccessTokenIntrospectRequest, AccessTokenRequest, AuthorisationRequest,
        AuthorisationRequestContext, AuthoriseResponse, ErrorResponse, Oauth2Error,
        TokenRevokeRequest,
    },
    prelude::{f_eq, *},
    value::PartialValue,
};
use serde::{Deserialize, Serialize};
use serde_with::{formats::CommaSeparator, serde_as, StringWithSeparator};

#[cfg(feature = "dev-oauth2-device-flow")]
use kanidm_proto::oauth2::DeviceAuthorizationResponse;

#[cfg(feature = "dev-oauth2-device-flow")]
use uri::OAUTH2_AUTHORISE_DEVICE;
use uri::{OAUTH2_TOKEN_ENDPOINT, OAUTH2_TOKEN_INTROSPECT_ENDPOINT, OAUTH2_TOKEN_REVOKE_ENDPOINT};

// == Oauth2 Configuration Endpoints ==

/// Get a filter matching a given OAuth2 Resource Server
pub(crate) fn oauth2_id(rs_name: &str) -> Filter<FilterInvalid> {
    filter_all!(f_and!([
        f_eq(Attribute::Class, EntryClass::OAuth2ResourceServer.into()),
        f_eq(Attribute::Name, PartialValue::new_iname(rs_name))
    ]))
}

#[utoipa::path(
    get,
    path = "/ui/images/oauth2/{rs_name}",
    operation_id = "oauth2_image_get",
    responses(
        (status = 200, description = "Ok", body=&[u8]),
        (status = 401, description = "Authorization required"),
        (status = 403, description = "Not Authorized"),
    ),
    security(("token_jwt" = [])),
    tag = "ui",
)]
/// This returns the image for the OAuth2 Resource Server if the user has permissions
///
pub(crate) async fn oauth2_image_get(
    State(state): State<ServerState>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Path(rs_name): Path<String>,
) -> Response {
    let rs_filter = oauth2_id(&rs_name);
    let res = state
        .qe_r_ref
        .handle_oauth2_rs_image_get_image(client_auth_info, rs_filter)
        .await;

    match res {
        Ok(Some(image)) => (
            StatusCode::OK,
            [(CONTENT_TYPE, image.filetype.as_content_type_str())],
            image.contents,
        )
            .into_response(),
        Ok(None) => {
            warn!(?rs_name, "No image set for OAuth2 client");
            (StatusCode::NOT_FOUND, "").into_response()
        }
        Err(err) => WebError::from(err).into_response(),
    }
}

// == OAUTH2 PROTOCOL FLOW HANDLERS ==
//
// oauth2 (partial)
// https://tools.ietf.org/html/rfc6749
// oauth2 pkce
// https://tools.ietf.org/html/rfc7636
//
// TODO
// oauth2 token introspection
// https://tools.ietf.org/html/rfc7662
// oauth2 bearer token
// https://tools.ietf.org/html/rfc6750
//
// From https://datatracker.ietf.org/doc/html/rfc6749#section-4.1
//
//       +----------+
//       | Resource |
//       |   Owner  |
//       |          |
//       +----------+
//            ^
//            |
//           (B)
//       +----|-----+          Client Identifier      +---------------+
//       |         -+----(A)-- & Redirection URI ---->|               |
//       |  User-   |                                 | Authorization |
//       |  Agent  -+----(B)-- User authenticates --->|     Server    |
//       |          |                                 |               |
//       |         -+----(C)-- Authorization Code ---<|               |
//       +-|----|---+                                 +---------------+
//         |    |                                         ^      v
//        (A)  (C)                                        |      |
//         |    |                                         |      |
//         ^    v                                         |      |
//       +---------+                                      |      |
//       |         |>---(D)-- Authorization Code ---------'      |
//       |  Client |          & Redirection URI                  |
//       |         |                                             |
//       |         |<---(E)----- Access Token -------------------'
//       +---------+       (w/ Optional Refresh Token)
//
//     Note: The lines illustrating steps (A), (B), and (C) are broken into
//     two parts as they pass through the user-agent.
//
//  In this diagram, kanidm is the authorisation server. Each step is handled by:
//
//  * Client Identifier  A)  oauth2_authorise_get
//  * User authenticates B)  normal kanidm auth flow
//  * Authorization Code C)  oauth2_authorise_permit_get
//                           oauth2_authorise_reject_get
//  * Authorization Code / Access Token
//                     D/E)  oauth2_token_post
//
//  These functions appear stateless, but the state is managed through encrypted
//  tokens transmitted in the responses of this flow. This is because in a HA setup
//  we can not guarantee that the User-Agent or the Resource Server (client) will
//  access the same Kanidm instance, and we can not rely on replication in these
//  cases. As a result, we must have our state in localised tokens so that any
//  valid Kanidm instance in the topology can handle these request.
//

#[instrument(level = "debug", skip(state, kopid))]
pub async fn oauth2_authorise_post(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    AuthorisationHeaders(client_auth_info): AuthorisationHeaders,
    Json(auth_req): Json<AuthorisationRequest>,
) -> impl IntoResponse {
    let mut res = oauth2_authorise(state, auth_req, kopid, client_auth_info)
        .await
        .into_response();
    if res.status() == StatusCode::FOUND {
        // in post, we need the redirect not to be issued, so we mask 302 to 200
        *res.status_mut() = StatusCode::OK;
    }
    res
}

#[instrument(level = "debug", skip(state, kopid))]
pub async fn oauth2_authorise_get(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    AuthorisationHeaders(client_auth_info): AuthorisationHeaders,
    Query(auth_req): Query<AuthorisationRequest>,
) -> impl IntoResponse {
    // Start the oauth2 authorisation flow to present to the user.
    oauth2_authorise(state, auth_req, kopid, client_auth_info).await
}

async fn oauth2_authorise(
    state: ServerState,
    auth_req: AuthorisationRequest,
    kopid: KOpId,
    client_auth_info: ClientAuthInfo,
) -> impl IntoResponse {
    let auth_req_ctx = AuthorisationRequestContext::default();

    let res: Result<AuthoriseResponse, Oauth2Error> = state
        .qe_r_ref
        .handle_oauth2_authorise(client_auth_info, auth_req, auth_req_ctx, kopid.eventid)
        .await;

    match res {
        Ok(AuthoriseResponse::ConsentRequested {
            client_name,
            scopes,
            pii_scopes,
            consent_token,
        }) => {
            // Render a redirect to the consent page for the user to interact with
            // to authorise this session-id
            // This is json so later we can expand it with better detail.
            #[allow(clippy::unwrap_used)]
            let body = serde_json::to_string(&AuthorisationResponse::ConsentRequested {
                client_name,
                scopes,
                pii_scopes,
                consent_token,
            })
            .unwrap();
            #[allow(clippy::unwrap_used)]
            Response::builder()
                .status(StatusCode::OK)
                .body(body.into())
                .unwrap()
        }
        Ok(AuthoriseResponse::Permitted(success)) => {
            // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics#section-4.11
            // We could consider changing this to 303?
            #[allow(clippy::unwrap_used)]
            let body =
                Body::from(serde_json::to_string(&AuthorisationResponse::Permitted).unwrap());
            let redirect_uri = success.build_redirect_uri();

            #[allow(clippy::unwrap_used)]
            Response::builder()
                .status(StatusCode::FOUND)
                .header(
                    LOCATION,
                    HeaderValue::from_str(redirect_uri.as_str()).unwrap(),
                )
                // I think the client server needs this
                .header(
                    ACCESS_CONTROL_ALLOW_ORIGIN,
                    HeaderValue::from_str(&redirect_uri.origin().ascii_serialization()).unwrap(),
                )
                .body(body)
                .unwrap()
        }

        Ok(AuthoriseResponse::Reject(rejection)) => {
            #[allow(clippy::unwrap_used)]
            let body = Body::default();
            let redirect_uri = rejection.build_redirect_uri();

            #[allow(clippy::unwrap_used)]
            Response::builder()
                .status(StatusCode::FOUND)
                .header(
                    LOCATION,
                    HeaderValue::from_str(redirect_uri.as_str()).unwrap(),
                )
                // I think the client server needs this
                .header(
                    ACCESS_CONTROL_ALLOW_ORIGIN,
                    HeaderValue::from_str(&redirect_uri.origin().ascii_serialization()).unwrap(),
                )
                .body(body)
                .unwrap()
        }

        Ok(AuthoriseResponse::ReauthenticationRequired { .. })
        | Ok(AuthoriseResponse::AuthenticationRequired { .. })
        | Err(Oauth2Error::AuthenticationRequired) =>
        {
            #[allow(clippy::unwrap_used)]
            Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .header(WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"))
                .header(ACCESS_CONTROL_ALLOW_ORIGIN, "*")
                .body(Body::empty())
                .unwrap()
        }
        Err(Oauth2Error::AccessDenied) => {
            // If scopes are not available for this account.
            #[allow(clippy::expect_used)]
            Response::builder()
                .status(StatusCode::FORBIDDEN)
                .header(ACCESS_CONTROL_ALLOW_ORIGIN, "*")
                .body(Body::empty())
                .expect("Failed to generate a forbidden response")
        }
        /*
        RFC - If the request fails due to a missing, invalid, or mismatching
              redirection URI, or if the client identifier is missing or invalid,
              the authorization server SHOULD inform the resource owner of the
              error and MUST NOT automatically redirect the user-agent to the
              invalid redirection URI.
        */
        // To further this, it appears that a malicious client configuration can set a phishing
        // site as the redirect URL, and then use that to trigger certain types of attacks. Instead
        // we do NOT redirect in an error condition, and just render the error ourselves.
        Err(e) => {
            admin_error!(
                "Unable to authorise - Error ID: {:?} error: {}",
                kopid.eventid,
                &e.to_string()
            );
            #[allow(clippy::expect_used)]
            Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .header(ACCESS_CONTROL_ALLOW_ORIGIN, "*")
                .body(Body::empty())
                .expect("Failed to generate a bad request response")
        }
    }
}

pub async fn oauth2_authorise_permit_post(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    AuthorisationHeaders(client_auth_info): AuthorisationHeaders,
    Json(consent_req): Json<String>,
) -> impl IntoResponse {
    let mut res = oauth2_authorise_permit(state, consent_req, kopid, client_auth_info)
        .await
        .into_response();
    if res.status() == StatusCode::FOUND {
        // in post, we need the redirect not to be issued, so we mask 302 to 200
        *res.status_mut() = StatusCode::OK;
    }
    res
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ConsentRequestData {
    token: String,
}

pub async fn oauth2_authorise_permit_get(
    State(state): State<ServerState>,
    Query(token): Query<ConsentRequestData>,
    Extension(kopid): Extension<KOpId>,
    AuthorisationHeaders(client_auth_info): AuthorisationHeaders,
) -> impl IntoResponse {
    // When this is called, this indicates consent to proceed from the user.
    oauth2_authorise_permit(state, token.token, kopid, client_auth_info).await
}

async fn oauth2_authorise_permit(
    state: ServerState,
    consent_req: String,
    kopid: KOpId,
    client_auth_info: ClientAuthInfo,
) -> impl IntoResponse {
    let res = state
        .qe_w_ref
        .handle_oauth2_authorise_permit(client_auth_info, consent_req, kopid.eventid)
        .await;

    match res {
        Ok(success) => {
            // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics#section-4.11
            // We could consider changing this to 303?
            let redirect_uri = success.build_redirect_uri();

            #[allow(clippy::expect_used)]
            Response::builder()
                .status(StatusCode::FOUND)
                .header(LOCATION, redirect_uri.as_str())
                .header(
                    ACCESS_CONTROL_ALLOW_ORIGIN,
                    redirect_uri.origin().ascii_serialization(),
                )
                .body(Body::empty())
                .expect("Failed to generate response")
        }
        Err(err) => {
            match err {
                OperationError::NotAuthenticated => {
                    WebError::from(err).response_with_access_control_origin_header()
                }
                _ => {
                    // If an error happens in our consent flow, I think
                    // that we should NOT redirect to the calling application
                    // and we need to handle that locally somehow.
                    // This needs to be better!
                    //
                    // Turns out this instinct was correct:
                    //  https://www.proofpoint.com/us/blog/cloud-security/microsoft-and-github-oauth-implementation-vulnerabilities-lead-redirection
                    // Possible to use this with a malicious client configuration to phish / spam.
                    #[allow(clippy::expect_used)]
                    Response::builder()
                        .status(StatusCode::INTERNAL_SERVER_ERROR)
                        .header(ACCESS_CONTROL_ALLOW_ORIGIN, "*")
                        .body(Body::empty())
                        .expect("Failed to generate error response")
                }
            }
        }
    }
}

// When this is called, this indicates the user has REJECTED the intent to proceed.
pub async fn oauth2_authorise_reject_post(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    AuthorisationHeaders(client_auth_info): AuthorisationHeaders,
    Form(consent_req): Form<ConsentRequestData>,
) -> Response<Body> {
    oauth2_authorise_reject(state, consent_req.token, kopid, client_auth_info).await
}

pub async fn oauth2_authorise_reject_get(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    AuthorisationHeaders(client_auth_info): AuthorisationHeaders,
    Query(consent_req): Query<ConsentRequestData>,
) -> Response<Body> {
    oauth2_authorise_reject(state, consent_req.token, kopid, client_auth_info).await
}

// // https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1
// // If the user willingly rejects the authorisation, we must redirect
// // with an error.
async fn oauth2_authorise_reject(
    state: ServerState,
    consent_req: String,
    kopid: KOpId,
    client_auth_info: ClientAuthInfo,
) -> Response<Body> {
    // Need to go back to the redir_uri
    // For this, we'll need to lookup where to go.

    let res = state
        .qe_r_ref
        .handle_oauth2_authorise_reject(client_auth_info, consent_req, kopid.eventid)
        .await;

    match res {
        Ok(reject) => {
            let redirect_uri = reject.build_redirect_uri();

            #[allow(clippy::unwrap_used)]
            Response::builder()
                .header(LOCATION, redirect_uri.as_str())
                .header(
                    ACCESS_CONTROL_ALLOW_ORIGIN,
                    redirect_uri.origin().ascii_serialization(),
                )
                .body(Body::empty())
                .unwrap()
            // I think the client server needs this
        }
        Err(err) => {
            match err {
                OperationError::NotAuthenticated => {
                    WebError::from(err).response_with_access_control_origin_header()
                }
                _ => {
                    // If an error happens in our reject flow, I think
                    // that we should NOT redirect to the calling application
                    // and we need to handle that locally somehow.
                    // This needs to be better!
                    #[allow(clippy::expect_used)]
                    Response::builder()
                        .status(StatusCode::INTERNAL_SERVER_ERROR)
                        .header(ACCESS_CONTROL_ALLOW_ORIGIN, "*")
                        .body(Body::empty())
                        .expect("Failed to generate an error response")
                }
            }
        }
    }
}

#[axum_macros::debug_handler]
#[instrument(skip(state, kopid, client_auth_info), level = "DEBUG")]
pub async fn oauth2_token_post(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    AuthorisationHeaders(client_auth_info): AuthorisationHeaders,
    Form(tok_req): Form<AccessTokenRequest>,
) -> impl IntoResponse {
    // This is called directly by the resource server, where we then issue
    // the token to the caller.

    // Do we change the method/path we take here based on the type of requested
    // grant? Should we cease the delayed/async session update here and just opt
    // for a wr txn?
    match state
        .qe_w_ref
        .handle_oauth2_token_exchange(client_auth_info, tok_req, kopid.eventid)
        .await
    {
        Ok(tok_res) => (
            StatusCode::OK,
            [(ACCESS_CONTROL_ALLOW_ORIGIN, "*")],
            Json(tok_res),
        )
            .into_response(),
        Err(e) => WebError::OAuth2(e).into_response(),
    }
}

// For future openid integration
pub async fn oauth2_openid_discovery_get(
    State(state): State<ServerState>,
    Path(client_id): Path<String>,
    Extension(kopid): Extension<KOpId>,
) -> impl IntoResponse {
    let res = state
        .qe_r_ref
        .handle_oauth2_openid_discovery(client_id, kopid.eventid)
        .await;

    match res {
        Ok(dsc) => (
            StatusCode::OK,
            [(ACCESS_CONTROL_ALLOW_ORIGIN, "*")],
            Json(dsc),
        )
            .into_response(),
        Err(e) => {
            error!(err = ?e, "Unable to access discovery info");
            WebError::from(e).response_with_access_control_origin_header()
        }
    }
}

#[derive(Deserialize)]
pub struct Oauth2OpenIdWebfingerQuery {
    resource: String,
}

pub async fn oauth2_openid_webfinger_get(
    State(state): State<ServerState>,
    Path(client_id): Path<String>,
    Query(query): Query<Oauth2OpenIdWebfingerQuery>,
    Extension(kopid): Extension<KOpId>,
) -> impl IntoResponse {
    let Oauth2OpenIdWebfingerQuery { resource } = query;

    let cleaned_resource = resource.strip_prefix("acct:").unwrap_or(&resource);

    let res = state
        .qe_r_ref
        .handle_oauth2_webfinger_discovery(&client_id, cleaned_resource, kopid.eventid)
        .await;

    match res {
        Ok(mut dsc) => (
            StatusCode::OK,
            [
                (ACCESS_CONTROL_ALLOW_ORIGIN, "*"),
                (CONTENT_TYPE, "application/jrd+json"),
            ],
            Json({
                dsc.subject = resource;
                dsc
            }),
        )
            .into_response(),
        Err(e) => {
            error!(err = ?e, "Unable to access discovery info");
            WebError::from(e).response_with_access_control_origin_header()
        }
    }
}

pub async fn oauth2_rfc8414_metadata_get(
    State(state): State<ServerState>,
    Path(client_id): Path<String>,
    Extension(kopid): Extension<KOpId>,
) -> impl IntoResponse {
    let res = state
        .qe_r_ref
        .handle_oauth2_rfc8414_metadata(client_id, kopid.eventid)
        .await;

    match res {
        Ok(dsc) => (
            StatusCode::OK,
            [(ACCESS_CONTROL_ALLOW_ORIGIN, "*")],
            Json(dsc),
        )
            .into_response(),
        Err(e) => {
            error!(err = ?e, "Unable to access discovery info");
            WebError::from(e).response_with_access_control_origin_header()
        }
    }
}

#[debug_handler]
pub async fn oauth2_openid_userinfo_get(
    State(state): State<ServerState>,
    Path(client_id): Path<String>,
    Extension(kopid): Extension<KOpId>,
    AuthorisationHeaders(client_auth_info): AuthorisationHeaders,
) -> Response {
    // The token we want to inspect is in the authorisation header.
    let res = state
        .qe_r_ref
        .handle_oauth2_openid_userinfo(client_id, &client_auth_info, kopid.eventid)
        .await;

    match res {
        Ok(uir) => (
            StatusCode::OK,
            [(ACCESS_CONTROL_ALLOW_ORIGIN, "*")],
            Json(uir),
        )
            .into_response(),
        Err(e) => WebError::OAuth2(e).into_response(),
    }
}

pub async fn oauth2_openid_publickey_get(
    State(state): State<ServerState>,
    Path(client_id): Path<String>,
    Extension(kopid): Extension<KOpId>,
) -> Response {
    let res = state
        .qe_r_ref
        .handle_oauth2_openid_publickey(client_id, kopid.eventid)
        .await
        .map(Json::from)
        .map_err(WebError::from);

    match res {
        Ok(jsn) => (StatusCode::OK, [(ACCESS_CONTROL_ALLOW_ORIGIN, "*")], jsn).into_response(),
        Err(web_err) => web_err.response_with_access_control_origin_header(),
    }
}

/// This is called directly by the resource server, where we then issue
/// information about this token to the caller.
pub async fn oauth2_token_introspect_post(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Form(intr_req): Form<AccessTokenIntrospectRequest>,
) -> impl IntoResponse {
    request_trace!("Introspect Request - {:?}", intr_req);
    let res = state
        .qe_r_ref
        .handle_oauth2_token_introspect(intr_req, kopid.eventid)
        .await;

    match res {
        Ok(atr) => {
            let body = match serde_json::to_string(&atr) {
                Ok(val) => val,
                Err(e) => {
                    admin_warn!("Failed to serialize introspect response: original_data=\"{:?}\" serialization_error=\"{:?}\"", atr, e);
                    format!("{atr:?}")
                }
            };
            #[allow(clippy::unwrap_used)]
            Response::builder()
                .header(ACCESS_CONTROL_ALLOW_ORIGIN, "*")
                .header(CONTENT_TYPE, APPLICATION_JSON)
                .body(Body::from(body))
                .unwrap()
        }
        Err(Oauth2Error::AuthenticationRequired) => {
            // This will trigger our ui to auth and retry.
            #[allow(clippy::expect_used)]
            Response::builder()
                .header(ACCESS_CONTROL_ALLOW_ORIGIN, "*")
                .status(StatusCode::UNAUTHORIZED)
                .body(Body::empty())
                .expect("Failed to generate an unauthorized response")
        }
        Err(e) => {
            // https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
            let err = ErrorResponse {
                error: e.to_string(),
                ..Default::default()
            };

            let body = match serde_json::to_string(&err) {
                Ok(val) => val,
                Err(e) => {
                    format!("{e:?}")
                }
            };
            #[allow(clippy::expect_used)]
            Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .header(ACCESS_CONTROL_ALLOW_ORIGIN, "*")
                .body(Body::from(body))
                .expect("Failed to generate an error response")
        }
    }
}

/// This is called directly by the resource server, where we then revoke
/// the token identified by this request.
pub async fn oauth2_token_revoke_post(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    Form(intr_req): Form<TokenRevokeRequest>,
) -> impl IntoResponse {
    request_trace!("Revoke Request - {:?}", intr_req);

    let res = state
        .qe_w_ref
        .handle_oauth2_token_revoke(intr_req, kopid.eventid)
        .await;

    match res {
        Ok(()) => (StatusCode::OK, [(ACCESS_CONTROL_ALLOW_ORIGIN, "*")], "").into_response(),
        Err(Oauth2Error::AuthenticationRequired) => {
            // This will trigger our ui to auth and retry.
            (
                StatusCode::UNAUTHORIZED,
                [(ACCESS_CONTROL_ALLOW_ORIGIN, "*")],
                "",
            )
                .into_response()
        }
        Err(e) => {
            // https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
            let err = ErrorResponse {
                error: e.to_string(),
                ..Default::default()
            };
            (
                StatusCode::BAD_REQUEST,
                [(ACCESS_CONTROL_ALLOW_ORIGIN, "*")],
                serde_json::to_string(&err).unwrap_or("".to_string()),
            )
                .into_response()
        }
    }
}

// Some requests from browsers require preflight so that CORS works.
pub async fn oauth2_preflight_options() -> Response {
    (
        StatusCode::OK,
        [
            (ACCESS_CONTROL_ALLOW_ORIGIN, "*"),
            (ACCESS_CONTROL_ALLOW_HEADERS, "Authorization"),
        ],
        String::new(),
    )
        .into_response()
}

// 1.90 incorrectly thinks this is dead code - it's literally used in the function below.
#[allow(dead_code)]
#[serde_as]
#[derive(Deserialize, Debug, Serialize)]
pub(crate) struct DeviceFlowForm {
    client_id: String,
    #[serde_as(as = "Option<StringWithSeparator::<CommaSeparator, String>>")]
    scope: Option<BTreeSet<String>>,
    #[serde(flatten)]
    extra: BTreeMap<String, String>, // catches any extra nonsense that gets sent through
}

/// Device flow! [RFC8628](https://datatracker.ietf.org/doc/html/rfc8628)
#[cfg(feature = "dev-oauth2-device-flow")]
#[instrument(level = "info", skip(state, kopid, client_auth_info))]
pub(crate) async fn oauth2_authorise_device_post(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    AuthorisationHeaders(client_auth_info): AuthorisationHeaders,
    Form(form): Form<DeviceFlowForm>,
) -> Result<Json<DeviceAuthorizationResponse>, WebError> {
    state
        .qe_w_ref
        .handle_oauth2_device_flow_start(
            client_auth_info,
            &form.client_id,
            &form.scope,
            kopid.eventid,
        )
        .await
        .map(Json::from)
        .map_err(WebError::OAuth2)
}

pub fn route_setup(state: ServerState) -> Router<ServerState> {
    // this has all the openid-related routes
    let openid_router = Router::new()
        // // ⚠️  ⚠️   WARNING  ⚠️  ⚠️
        // // IF YOU CHANGE THESE VALUES YOU MUST UPDATE OIDC DISCOVERY URLS
        .route(
            "/oauth2/openid/{client_id}/.well-known/openid-configuration",
            get(oauth2_openid_discovery_get).options(oauth2_preflight_options),
        )
        .route(
            "/oauth2/openid/{client_id}/.well-known/webfinger",
            get(oauth2_openid_webfinger_get).options(oauth2_preflight_options),
        )
        .route(
            "/.well-known/openid-configuration/oauth2/openid/{client_id}",
            get(oauth2_openid_discovery_get).options(oauth2_preflight_options),
        )
        .route(
            "/.well-known/webfinger/oauth2/openid/{client_id}",
            get(oauth2_openid_webfinger_get).options(oauth2_preflight_options),
        )
        // // ⚠️  ⚠️   WARNING  ⚠️  ⚠️
        // // IF YOU CHANGE THESE VALUES YOU MUST UPDATE OIDC DISCOVERY URLS
        .route(
            "/oauth2/openid/{client_id}/userinfo",
            get(oauth2_openid_userinfo_get)
                .post(oauth2_openid_userinfo_get)
                .options(oauth2_preflight_options),
        )
        // // ⚠️  ⚠️   WARNING  ⚠️  ⚠️
        // // IF YOU CHANGE THESE VALUES YOU MUST UPDATE OIDC DISCOVERY URLS
        .route(
            "/oauth2/openid/{client_id}/public_key.jwk",
            get(oauth2_openid_publickey_get).options(oauth2_preflight_options),
        )
        // // ⚠️  ⚠️   WARNING  ⚠️  ⚠️
        // // IF YOU CHANGE THESE VALUES YOU MUST UPDATE OAUTH2 DISCOVERY URLS
        .route(
            "/oauth2/openid/{client_id}/.well-known/oauth-authorization-server",
            get(oauth2_rfc8414_metadata_get).options(oauth2_preflight_options),
        )
        .route(
            "/.well-known/oauth-authorization-server/oauth2/openid/{client_id}",
            get(oauth2_rfc8414_metadata_get).options(oauth2_preflight_options),
        )
        .with_state(state.clone());

    let mut router = Router::new()
        .route("/oauth2", get(super::v1_oauth2::oauth2_get))
        // ⚠️  ⚠️   WARNING  ⚠️  ⚠️
        // IF YOU CHANGE THESE VALUES YOU MUST UPDATE OIDC DISCOVERY URLS
        .route(
            OAUTH2_AUTHORISE,
            post(oauth2_authorise_post).get(oauth2_authorise_get),
        )
        // ⚠️  ⚠️   WARNING  ⚠️  ⚠️
        // IF YOU CHANGE THESE VALUES YOU MUST UPDATE OIDC DISCOVERY URLS
        .route(
            OAUTH2_AUTHORISE_PERMIT,
            post(oauth2_authorise_permit_post).get(oauth2_authorise_permit_get),
        )
        // ⚠️  ⚠️   WARNING  ⚠️  ⚠️
        // IF YOU CHANGE THESE VALUES YOU MUST UPDATE OIDC DISCOVERY URLS
        .route(
            OAUTH2_AUTHORISE_REJECT,
            post(oauth2_authorise_reject_post).get(oauth2_authorise_reject_get),
        );
    // ⚠️  ⚠️   WARNING  ⚠️  ⚠️
    // IF YOU CHANGE THESE VALUES YOU MUST UPDATE OIDC DISCOVERY URLS
    #[cfg(feature = "dev-oauth2-device-flow")]
    {
        router = router.route(OAUTH2_AUTHORISE_DEVICE, post(oauth2_authorise_device_post))
    }
    // ⚠️  ⚠️   WARNING  ⚠️  ⚠️
    // IF YOU CHANGE THESE VALUES YOU MUST UPDATE OIDC DISCOVERY URLS
    router = router
        .route(
            OAUTH2_TOKEN_ENDPOINT,
            post(oauth2_token_post).options(oauth2_preflight_options),
        )
        // ⚠️  ⚠️   WARNING  ⚠️  ⚠️
        // IF YOU CHANGE THESE VALUES YOU MUST UPDATE OIDC DISCOVERY URLS
        .route(
            OAUTH2_TOKEN_INTROSPECT_ENDPOINT,
            post(oauth2_token_introspect_post),
        )
        .route(OAUTH2_TOKEN_REVOKE_ENDPOINT, post(oauth2_token_revoke_post))
        .merge(openid_router)
        .with_state(state)
        .layer(from_fn(super::middleware::caching::dont_cache_me));

    router
}
