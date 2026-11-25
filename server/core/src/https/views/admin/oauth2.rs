#![allow(clippy::result_large_err)]

use crate::{
    actors::models::OAuth2RS,
    https::{
        extractors::{DomainInfo, VerifiedClientInformation},
        middleware::KOpId,
        views::{errors::HtmxError, navbar::NavbarCtx, Urls},
        ServerState,
    },
};

use askama::Template;
use askama_web::WebTemplate;
use axum::{
    extract::State,
    response::{IntoResponse, Response},
    Extension,
};
use axum_htmx::{HxPushUrl, HxRequest};
use kanidm_proto::{internal::UserAuthToken, scim_v1::server::ScimEffectiveAccess};

#[derive(Template, WebTemplate)]
#[template(path = "admin/admin_oauth2_view_partial.html")]
struct OauthViewPartial {
    resources: Vec<(OAuth2RS, ScimEffectiveAccess)>,
}

#[derive(Template, WebTemplate)]
#[template(path = "admin/admin_panel_template.html")]
struct OAuthView {
    navbar_ctx: NavbarCtx,
    partial: OauthViewPartial,
    title: String,
}

pub async fn view_oauth2_get(
    State(state): State<ServerState>,
    HxRequest(is_htmx): HxRequest,
    Extension(kopid): Extension<KOpId>,
    DomainInfo(domain_info): DomainInfo,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
) -> axum::response::Result<Response> {
    let resources = state
        .qe_r_ref
        .get_oauth2_rs_list(kopid.eventid, client_auth_info.clone())
        .await
        .map_err(|op_err| HtmxError::new(&kopid, op_err, domain_info.clone()))?;

    let oauth2s = OauthViewPartial { resources };

    let uat: &UserAuthToken = client_auth_info
        .pre_validated_uat()
        .map_err(|op_err| HtmxError::new(&kopid, op_err, domain_info.clone()))?;

    let push_url = HxPushUrl("/ui/admin/oauth2".to_string());
    Ok(if is_htmx {
        (push_url, oauth2s).into_response()
    } else {
        (
            push_url,
            OAuthView {
                navbar_ctx: NavbarCtx::new(domain_info, &uat.ui_hints),
                partial: oauth2s,
                title: "OAuth2".to_string(),
            },
        )
            .into_response()
    })
}
