//! Models / queries for the HTTP views to access allowing structured data to be returned
//! for operations.

use super::QueryServerReadV1;
use kanidm_proto::scim_v1::{
    server::{ScimEffectiveAccess, ScimEntryKanidm, ScimValueKanidm},
    ScimEntryGetQuery, ScimFilter,
};
use kanidmd_lib::prelude::*;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct OAuth2RS {
    pub uuid: Uuid,
    pub name: String,
    pub display_name: String,
}

impl TryFrom<ScimEntryKanidm> for OAuth2RS {
    type Error = ();

    fn try_from(mut value: ScimEntryKanidm) -> Result<Self, Self::Error> {
        let uuid = value.header.id;
        let name = value
            .attrs
            .remove(&Attribute::Name)
            .and_then(|v| match v {
                ScimValueKanidm::String(value) => Some(value),
                _ => None,
            })
            .ok_or(())?;

        let display_name = value
            .attrs
            .remove(&Attribute::DisplayName)
            .and_then(|v| match v {
                ScimValueKanidm::String(value) => Some(value),
                _ => None,
            })
            .ok_or(())?;

        Ok(OAuth2RS {
            uuid,
            name,
            display_name,
        })
    }
}

impl QueryServerReadV1 {
    pub async fn get_oauth2_rs_list(
        &self,
        eventid: Uuid,
        client_auth_info: ClientAuthInfo,
    ) -> Result<Vec<(OAuth2RS, ScimEffectiveAccess)>, OperationError> {
        let group_attributes: [Attribute; _] =
            [Attribute::Uuid, Attribute::DisplayName, Attribute::Name];

        let filter = ScimFilter::Equal(
            Attribute::Class.into(),
            EntryClass::OAuth2ResourceServer.into(),
        );

        let search_result = self
            .scim_entry_search(
                client_auth_info,
                eventid,
                filter,
                ScimEntryGetQuery {
                    attributes: Some(Vec::from(group_attributes)),
                    ext_access_check: true,
                    sort_by: Some(Attribute::Name),
                    ..Default::default()
                },
            )
            .await?;

        let resource_server: Vec<_> = search_result
            .resources
            .into_iter()
            .filter_map(|entry| {
                let effective_access = entry.ext_access_check.clone()?;
                let rs = OAuth2RS::try_from(entry).ok()?;
                Some((rs, effective_access))
            })
            .collect();

        Ok(resource_server)
    }
}
