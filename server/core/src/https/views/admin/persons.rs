use crate::https::extractors::{DomainInfo, VerifiedClientInformation};
use crate::https::middleware::KOpId;
use crate::https::views::errors::HtmxError;
use crate::https::views::navbar::NavbarCtx;
use crate::https::views::Urls;
use crate::https::ServerState;
use askama::Template;
use axum::extract::{Path, State};
use axum::http::Uri;
use axum::response::{ErrorResponse, IntoResponse, Response};
use axum::Extension;
use axum_htmx::{HxPushUrl, HxRequest};
use kanidm_proto::attribute::Attribute;
use kanidm_proto::internal::OperationError;
use kanidm_proto::scim_v1::client::ScimFilter;
use kanidm_proto::scim_v1::server::{ScimEffectiveAccess, ScimEntryKanidm, ScimPerson};
use kanidm_proto::scim_v1::ScimEntryGetQuery;
use kanidmd_lib::constants::EntryClass;
use kanidmd_lib::idm::server::DomainInfoRead;
use kanidmd_lib::idm::ClientAuthInfo;
use std::str::FromStr;
use uuid::Uuid;

const PERSON_ATTRIBUTES: [Attribute; 9] = [
    Attribute::Uuid,
    Attribute::Description,
    Attribute::Name,
    Attribute::DisplayName,
    Attribute::Spn,
    Attribute::Mail,
    Attribute::Class,
    Attribute::EntryManagedBy,
    Attribute::DirectMemberOf,
];

#[derive(Template)]
#[template(path = "admin/admin_panel_template.html")]
pub(crate) struct PersonsView {
    navbar_ctx: NavbarCtx,
    partial: PersonsPartialView,
}

#[derive(Template)]
#[template(path = "admin/admin_persons_partial.html")]
struct PersonsPartialView {
    persons: Vec<(ScimPerson, ScimEffectiveAccess)>,
}

#[derive(Template)]
#[template(path = "admin/admin_panel_template.html")]
struct PersonView {
    partial: PersonViewPartial,
    navbar_ctx: NavbarCtx,
}

#[derive(Template)]
#[template(path = "admin/admin_person_view_partial.html")]
struct PersonViewPartial {
    person: ScimPerson,
    scim_effective_access: ScimEffectiveAccess,
}

pub(crate) async fn view_person_view_get(
    State(state): State<ServerState>,
    HxRequest(is_htmx): HxRequest,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Path(uuid): Path<Uuid>,
    DomainInfo(domain_info): DomainInfo,
) -> axum::response::Result<Response> {
    let (person, scim_effective_access) =
        get_person_info(uuid, state, &kopid, client_auth_info, domain_info.clone()).await?;
    let person_partial = PersonViewPartial {
        person,
        scim_effective_access,
    };

    let path_string = format!("/ui/admin/person/{uuid}/view");
    let uri = Uri::from_str(path_string.as_str())
        .map_err(|_| HtmxError::new(&kopid, OperationError::Backend, domain_info.clone()))?;
    let push_url = HxPushUrl(uri);
    Ok(if is_htmx {
        (push_url, person_partial).into_response()
    } else {
        (
            push_url,
            PersonView {
                partial: person_partial,
                navbar_ctx: NavbarCtx { domain_info },
            },
        )
            .into_response()
    })
}

pub(crate) async fn view_persons_get(
    State(state): State<ServerState>,
    HxRequest(is_htmx): HxRequest,
    Extension(kopid): Extension<KOpId>,
    DomainInfo(domain_info): DomainInfo,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
) -> axum::response::Result<Response> {
    let persons = get_persons_info(state, &kopid, client_auth_info, domain_info.clone()).await?;
    let persons_partial = PersonsPartialView { persons };

    let push_url = HxPushUrl(Uri::from_static("/ui/admin/persons"));
    Ok(if is_htmx {
        (push_url, persons_partial).into_response()
    } else {
        (
            push_url,
            PersonsView {
                navbar_ctx: NavbarCtx { domain_info },
                partial: persons_partial,
            },
        )
            .into_response()
    })
}

async fn get_person_info(
    uuid: Uuid,
    state: ServerState,
    kopid: &KOpId,
    client_auth_info: ClientAuthInfo,
    domain_info: DomainInfoRead,
) -> Result<(ScimPerson, ScimEffectiveAccess), ErrorResponse> {
    let scim_entry: ScimEntryKanidm = state
        .qe_r_ref
        .scim_entry_id_get(
            client_auth_info.clone(),
            kopid.eventid,
            uuid.to_string(),
            EntryClass::Person,
            ScimEntryGetQuery {
                attributes: Some(Vec::from(PERSON_ATTRIBUTES)),
                ext_access_check: true,
            },
        )
        .await
        .map_err(|op_err| HtmxError::new(kopid, op_err, domain_info.clone()))?;

    if let Some(personinfo_info) = scimentry_into_personinfo(scim_entry) {
        Ok(personinfo_info)
    } else {
        Err(HtmxError::new(kopid, OperationError::InvalidState, domain_info.clone()).into())
    }
}

async fn get_persons_info(
    state: ServerState,
    kopid: &KOpId,
    client_auth_info: ClientAuthInfo,
    domain_info: DomainInfoRead,
) -> Result<Vec<(ScimPerson, ScimEffectiveAccess)>, ErrorResponse> {
    let filter = ScimFilter::Equal(Attribute::Class.into(), EntryClass::Person.into());

    let base: Vec<ScimEntryKanidm> = state
        .qe_r_ref
        .scim_entry_search(
            client_auth_info.clone(),
            kopid.eventid,
            filter,
            ScimEntryGetQuery {
                attributes: Some(Vec::from(PERSON_ATTRIBUTES)),
                ext_access_check: true,
            },
        )
        .await
        .map_err(|op_err| HtmxError::new(kopid, op_err, domain_info.clone()))?;

    // TODO: inefficient to sort here
    let mut persons: Vec<_> = base
        .into_iter()
        // TODO: Filtering away unsuccessful entries may not be desired.
        .filter_map(scimentry_into_personinfo)
        .collect();

    persons.sort_by_key(|(sp, _)| sp.uuid);
    persons.reverse();

    Ok(persons)
}

fn scimentry_into_personinfo(
    scim_entry: ScimEntryKanidm,
) -> Option<(ScimPerson, ScimEffectiveAccess)> {
    let scim_effective_access = scim_entry.ext_access_check.clone()?; // TODO: This should be an error msg.
    let person = ScimPerson::try_from(scim_entry).ok()?;

    Some((person, scim_effective_access))
}
