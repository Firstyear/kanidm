use crate::{ClientError, KanidmClient};
use kanidm_proto::{
    attribute::Attribute,
    constants::{
        ATTR_DISPLAYNAME, ATTR_KEY_ACTION_REVOKE, ATTR_KEY_ACTION_ROTATE, ATTR_NAME,
        ATTR_OAUTH2_ALLOW_INSECURE_CLIENT_DISABLE_PKCE, ATTR_OAUTH2_ALLOW_LOCALHOST_REDIRECT,
        ATTR_OAUTH2_CONSENT_PROMPT_ENABLE, ATTR_OAUTH2_JWT_LEGACY_CRYPTO_ENABLE,
        ATTR_OAUTH2_PREFER_SHORT_USERNAME, ATTR_OAUTH2_RFC9068_TOKENS, ATTR_OAUTH2_RS_BASIC_SECRET,
        ATTR_OAUTH2_RS_ORIGIN, ATTR_OAUTH2_RS_ORIGIN_LANDING, ATTR_OAUTH2_STRICT_REDIRECT_URI,
    },
    internal::{ImageValue, Oauth2ClaimMapJoin},
    v1::Entry,
};
use reqwest::multipart;
use std::collections::BTreeMap;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use url::Url;

impl KanidmClient {
    // ==== Oauth2 resource server configuration
    #[instrument(level = "debug")]
    pub async fn idm_oauth2_rs_list(&self) -> Result<Vec<Entry>, ClientError> {
        self.perform_get_request("/v1/oauth2").await
    }

    pub async fn idm_oauth2_rs_basic_create(
        &self,
        name: &str,
        displayname: &str,
        origin: &str,
    ) -> Result<(), ClientError> {
        let mut new_oauth2_rs = Entry::default();
        new_oauth2_rs
            .attrs
            .insert(ATTR_NAME.to_string(), vec![name.to_string()]);
        new_oauth2_rs
            .attrs
            .insert(ATTR_DISPLAYNAME.to_string(), vec![displayname.to_string()]);
        new_oauth2_rs.attrs.insert(
            ATTR_OAUTH2_RS_ORIGIN_LANDING.to_string(),
            vec![origin.to_string()],
        );
        new_oauth2_rs.attrs.insert(
            ATTR_OAUTH2_STRICT_REDIRECT_URI.to_string(),
            vec!["true".to_string()],
        );
        self.perform_post_request("/v1/oauth2/_basic", new_oauth2_rs)
            .await
    }

    pub async fn idm_oauth2_rs_public_create(
        &self,
        name: &str,
        displayname: &str,
        origin: &str,
    ) -> Result<(), ClientError> {
        let mut new_oauth2_rs = Entry::default();
        new_oauth2_rs
            .attrs
            .insert(ATTR_NAME.to_string(), vec![name.to_string()]);
        new_oauth2_rs
            .attrs
            .insert(ATTR_DISPLAYNAME.to_string(), vec![displayname.to_string()]);
        new_oauth2_rs.attrs.insert(
            ATTR_OAUTH2_RS_ORIGIN_LANDING.to_string(),
            vec![origin.to_string()],
        );
        new_oauth2_rs.attrs.insert(
            ATTR_OAUTH2_STRICT_REDIRECT_URI.to_string(),
            vec!["true".to_string()],
        );
        self.perform_post_request("/v1/oauth2/_public", new_oauth2_rs)
            .await
    }

    pub async fn idm_oauth2_rs_get(&self, client_name: &str) -> Result<Option<Entry>, ClientError> {
        self.perform_get_request(format!("/v1/oauth2/{client_name}").as_str())
            .await
    }

    pub async fn idm_oauth2_rs_get_basic_secret(
        &self,
        client_name: &str,
    ) -> Result<Option<String>, ClientError> {
        self.perform_get_request(format!("/v1/oauth2/{client_name}/_basic_secret").as_str())
            .await
    }

    pub async fn idm_oauth2_rs_revoke_key(
        &self,
        client_name: &str,
        key_id: &str,
    ) -> Result<(), ClientError> {
        self.perform_post_request(
            &format!("/v1/oauth2/{client_name}/_attr/{ATTR_KEY_ACTION_REVOKE}"),
            vec![key_id.to_string()],
        )
        .await
    }

    pub async fn idm_oauth2_rs_rotate_keys(
        &self,
        client_name: &str,
        rotate_at_time: OffsetDateTime,
    ) -> Result<(), ClientError> {
        let rfc_3339_str = rotate_at_time.format(&Rfc3339).map_err(|_| {
            ClientError::InvalidRequest("Unable to format rfc 3339 datetime".into())
        })?;

        self.perform_post_request(
            &format!("/v1/oauth2/{client_name}/_attr/{ATTR_KEY_ACTION_ROTATE}"),
            vec![rfc_3339_str],
        )
        .await
    }

    pub async fn idm_oauth2_rs_update(
        &self,
        id: &str,
        name: Option<&str>,
        displayname: Option<&str>,
        landing: Option<&str>,
        reset_secret: bool,
    ) -> Result<(), ClientError> {
        let mut update_oauth2_rs = Entry {
            attrs: BTreeMap::new(),
        };

        if let Some(newname) = name {
            update_oauth2_rs
                .attrs
                .insert(ATTR_NAME.to_string(), vec![newname.to_string()]);
        }
        if let Some(newdisplayname) = displayname {
            update_oauth2_rs.attrs.insert(
                ATTR_DISPLAYNAME.to_string(),
                vec![newdisplayname.to_string()],
            );
        }
        if let Some(newlanding) = landing {
            update_oauth2_rs.attrs.insert(
                ATTR_OAUTH2_RS_ORIGIN_LANDING.to_string(),
                vec![newlanding.to_string()],
            );
        }
        if reset_secret {
            update_oauth2_rs
                .attrs
                .insert(ATTR_OAUTH2_RS_BASIC_SECRET.to_string(), Vec::new());
        }
        self.perform_patch_request(format!("/v1/oauth2/{id}").as_str(), update_oauth2_rs)
            .await
    }

    pub async fn idm_oauth2_rs_update_scope_map(
        &self,
        id: &str,
        group: &str,
        scopes: Vec<&str>,
    ) -> Result<(), ClientError> {
        let scopes: Vec<String> = scopes.into_iter().map(str::to_string).collect();
        self.perform_post_request(
            format!("/v1/oauth2/{id}/_scopemap/{group}").as_str(),
            scopes,
        )
        .await
    }

    pub async fn idm_oauth2_rs_delete_scope_map(
        &self,
        id: &str,
        group: &str,
    ) -> Result<(), ClientError> {
        self.perform_delete_request(format!("/v1/oauth2/{id}/_scopemap/{group}").as_str())
            .await
    }

    pub async fn idm_oauth2_rs_update_sup_scope_map(
        &self,
        id: &str,
        group: &str,
        scopes: Vec<&str>,
    ) -> Result<(), ClientError> {
        let scopes: Vec<String> = scopes.into_iter().map(str::to_string).collect();
        self.perform_post_request(
            format!("/v1/oauth2/{id}/_sup_scopemap/{group}").as_str(),
            scopes,
        )
        .await
    }

    pub async fn idm_oauth2_rs_delete_sup_scope_map(
        &self,
        id: &str,
        group: &str,
    ) -> Result<(), ClientError> {
        self.perform_delete_request(format!("/v1/oauth2/{id}/_sup_scopemap/{group}").as_str())
            .await
    }

    pub async fn idm_oauth2_rs_delete(&self, id: &str) -> Result<(), ClientError> {
        self.perform_delete_request(["/v1/oauth2/", id].concat().as_str())
            .await
    }

    /// Want to delete the image associated with a resource server? Here's your thing!
    pub async fn idm_oauth2_rs_delete_image(&self, id: &str) -> Result<(), ClientError> {
        self.perform_delete_request(format!("/v1/oauth2/{id}/_image").as_str())
            .await
    }

    /// Want to add/update the image associated with a resource server? Here's your thing!
    pub async fn idm_oauth2_rs_update_image(
        &self,
        id: &str,
        image: ImageValue,
    ) -> Result<(), ClientError> {
        let file_content_type = image.filetype.as_content_type_str();

        let file_data = match multipart::Part::bytes(image.contents.clone())
            .file_name(image.filename)
            .mime_str(file_content_type)
        {
            Ok(part) => part,
            Err(err) => {
                error!(
                    "Failed to generate multipart body from image data: {:}",
                    err
                );
                return Err(ClientError::SystemError);
            }
        };

        let form = multipart::Form::new().part("image", file_data);

        // send it
        let response = self
            .client
            .post(self.make_url(&format!("/v1/oauth2/{id}/_image")))
            .multipart(form);

        let response = {
            let tguard = self.bearer_token.read().await;
            if let Some(token) = &(*tguard) {
                response.bearer_auth(token)
            } else {
                response
            }
        };
        let response = response
            .send()
            .await
            .map_err(|err| self.handle_response_error(err))?;
        self.expect_version(&response).await;

        let opid = self.get_kopid_from_response(&response);

        self.ok_or_clienterror(&opid, response)
            .await?
            .json()
            .await
            .map_err(|e| ClientError::JsonDecode(e, opid))
    }

    pub async fn idm_oauth2_rs_enable_pkce(&self, id: &str) -> Result<(), ClientError> {
        let mut update_oauth2_rs = Entry {
            attrs: BTreeMap::new(),
        };
        update_oauth2_rs.attrs.insert(
            ATTR_OAUTH2_ALLOW_INSECURE_CLIENT_DISABLE_PKCE.to_string(),
            Vec::new(),
        );
        self.perform_patch_request(format!("/v1/oauth2/{id}").as_str(), update_oauth2_rs)
            .await
    }

    pub async fn idm_oauth2_rs_disable_pkce(&self, id: &str) -> Result<(), ClientError> {
        let mut update_oauth2_rs = Entry {
            attrs: BTreeMap::new(),
        };
        update_oauth2_rs.attrs.insert(
            ATTR_OAUTH2_ALLOW_INSECURE_CLIENT_DISABLE_PKCE.to_string(),
            vec!["true".to_string()],
        );
        self.perform_patch_request(format!("/v1/oauth2/{id}").as_str(), update_oauth2_rs)
            .await
    }

    pub async fn idm_oauth2_rs_enable_legacy_crypto(&self, id: &str) -> Result<(), ClientError> {
        let mut update_oauth2_rs = Entry {
            attrs: BTreeMap::new(),
        };
        update_oauth2_rs.attrs.insert(
            ATTR_OAUTH2_JWT_LEGACY_CRYPTO_ENABLE.to_string(),
            vec!["true".to_string()],
        );
        self.perform_patch_request(format!("/v1/oauth2/{id}").as_str(), update_oauth2_rs)
            .await
    }

    pub async fn idm_oauth2_rs_disable_legacy_crypto(&self, id: &str) -> Result<(), ClientError> {
        let mut update_oauth2_rs = Entry {
            attrs: BTreeMap::new(),
        };
        update_oauth2_rs.attrs.insert(
            ATTR_OAUTH2_JWT_LEGACY_CRYPTO_ENABLE.to_string(),
            vec!["false".to_string()],
        );
        self.perform_patch_request(format!("/v1/oauth2/{id}").as_str(), update_oauth2_rs)
            .await
    }

    pub async fn idm_oauth2_rs_prefer_short_username(&self, id: &str) -> Result<(), ClientError> {
        let mut update_oauth2_rs = Entry {
            attrs: BTreeMap::new(),
        };
        update_oauth2_rs.attrs.insert(
            ATTR_OAUTH2_PREFER_SHORT_USERNAME.to_string(),
            vec!["true".to_string()],
        );
        self.perform_patch_request(format!("/v1/oauth2/{id}").as_str(), update_oauth2_rs)
            .await
    }

    pub async fn idm_oauth2_rs_prefer_spn_username(&self, id: &str) -> Result<(), ClientError> {
        let mut update_oauth2_rs = Entry {
            attrs: BTreeMap::new(),
        };
        update_oauth2_rs.attrs.insert(
            ATTR_OAUTH2_PREFER_SHORT_USERNAME.to_string(),
            vec!["false".to_string()],
        );
        self.perform_patch_request(format!("/v1/oauth2/{id}").as_str(), update_oauth2_rs)
            .await
    }

    pub async fn idm_oauth2_rs_enable_public_localhost_redirect(
        &self,
        id: &str,
    ) -> Result<(), ClientError> {
        let mut update_oauth2_rs = Entry {
            attrs: BTreeMap::new(),
        };
        update_oauth2_rs.attrs.insert(
            ATTR_OAUTH2_ALLOW_LOCALHOST_REDIRECT.to_string(),
            vec!["true".to_string()],
        );
        self.perform_patch_request(format!("/v1/oauth2/{id}").as_str(), update_oauth2_rs)
            .await
    }

    pub async fn idm_oauth2_rs_disable_public_localhost_redirect(
        &self,
        id: &str,
    ) -> Result<(), ClientError> {
        let mut update_oauth2_rs = Entry {
            attrs: BTreeMap::new(),
        };
        update_oauth2_rs.attrs.insert(
            ATTR_OAUTH2_ALLOW_LOCALHOST_REDIRECT.to_string(),
            vec!["false".to_string()],
        );
        self.perform_patch_request(format!("/v1/oauth2/{id}").as_str(), update_oauth2_rs)
            .await
    }

    pub async fn idm_oauth2_rs_enable_strict_redirect_uri(
        &self,
        id: &str,
    ) -> Result<(), ClientError> {
        let mut update_oauth2_rs = Entry {
            attrs: BTreeMap::new(),
        };
        update_oauth2_rs.attrs.insert(
            ATTR_OAUTH2_STRICT_REDIRECT_URI.to_string(),
            vec!["true".to_string()],
        );
        self.perform_patch_request(format!("/v1/oauth2/{id}").as_str(), update_oauth2_rs)
            .await
    }

    pub async fn idm_oauth2_rs_disable_strict_redirect_uri(
        &self,
        id: &str,
    ) -> Result<(), ClientError> {
        let mut update_oauth2_rs = Entry {
            attrs: BTreeMap::new(),
        };
        update_oauth2_rs.attrs.insert(
            ATTR_OAUTH2_STRICT_REDIRECT_URI.to_string(),
            vec!["false".to_string()],
        );
        self.perform_patch_request(format!("/v1/oauth2/{id}").as_str(), update_oauth2_rs)
            .await
    }

    pub async fn idm_oauth2_rs_enable_rfc9068(&self, id: &str) -> Result<(), ClientError> {
        let mut update_oauth2_rs = Entry {
            attrs: BTreeMap::new(),
        };
        update_oauth2_rs.attrs.insert(
            ATTR_OAUTH2_RFC9068_TOKENS.to_string(),
            vec!["true".to_string()],
        );
        self.perform_patch_request(format!("/v1/oauth2/{id}").as_str(), update_oauth2_rs)
            .await
    }

    pub async fn idm_oauth2_rs_disable_rfc9068(&self, id: &str) -> Result<(), ClientError> {
        let mut update_oauth2_rs = Entry {
            attrs: BTreeMap::new(),
        };
        update_oauth2_rs.attrs.insert(
            ATTR_OAUTH2_RFC9068_TOKENS.to_string(),
            vec!["false".to_string()],
        );
        self.perform_patch_request(format!("/v1/oauth2/{id}").as_str(), update_oauth2_rs)
            .await
    }

    pub async fn idm_oauth2_rs_update_claim_map(
        &self,
        id: &str,
        claim_name: &str,
        group_id: &str,
        values: &[String],
    ) -> Result<(), ClientError> {
        let values: Vec<String> = values.to_vec();
        self.perform_post_request(
            format!("/v1/oauth2/{id}/_claimmap/{claim_name}/{group_id}").as_str(),
            values,
        )
        .await
    }

    pub async fn idm_oauth2_rs_update_claim_map_join(
        &self,
        id: &str,
        claim_name: &str,
        join: Oauth2ClaimMapJoin,
    ) -> Result<(), ClientError> {
        self.perform_post_request(
            format!("/v1/oauth2/{id}/_claimmap/{claim_name}").as_str(),
            join,
        )
        .await
    }

    pub async fn idm_oauth2_rs_delete_claim_map(
        &self,
        id: &str,
        claim_name: &str,
        group_id: &str,
    ) -> Result<(), ClientError> {
        self.perform_delete_request(
            format!("/v1/oauth2/{id}/_claimmap/{claim_name}/{group_id}").as_str(),
        )
        .await
    }

    pub async fn idm_oauth2_client_add_origin(
        &self,
        id: &str,
        origin: &Url,
    ) -> Result<(), ClientError> {
        // TODO: should we normalise loopback origins, so when a user specifies `http://localhost/foo` we store it as `http://[::1]/foo`?

        let url_to_add = &[origin.as_str()];
        self.perform_post_request(
            format!("/v1/oauth2/{id}/_attr/{ATTR_OAUTH2_RS_ORIGIN}").as_str(),
            url_to_add,
        )
        .await
    }

    pub async fn idm_oauth2_client_remove_origin(
        &self,
        id: &str,
        origin: &Url,
    ) -> Result<(), ClientError> {
        let url_to_remove = &[origin.as_str()];
        self.perform_delete_request_with_body(
            format!("/v1/oauth2/{id}/_attr/{ATTR_OAUTH2_RS_ORIGIN}").as_str(),
            url_to_remove,
        )
        .await
    }

    pub async fn idm_oauth2_client_device_flow_update(
        &self,
        id: &str,
        value: bool,
    ) -> Result<(), ClientError> {
        match value {
            true => {
                let mut update_oauth2_rs = Entry {
                    attrs: BTreeMap::new(),
                };
                update_oauth2_rs.attrs.insert(
                    Attribute::OAuth2DeviceFlowEnable.into(),
                    vec![value.to_string()],
                );
                self.perform_patch_request(format!("/v1/oauth2/{id}").as_str(), update_oauth2_rs)
                    .await
            }
            false => {
                self.perform_delete_request(&format!(
                    "/v1/oauth2/{}/_attr/{}",
                    id,
                    Attribute::OAuth2DeviceFlowEnable.as_str()
                ))
                .await
            }
        }
    }

    pub async fn idm_oauth2_rs_set_refresh_token_expiry(
        &self,
        id: &str,
        expiry: Option<u32>,
    ) -> Result<(), ClientError> {
        match expiry {
            Some(exp) => {
                let mut update_oauth2_rs = Entry {
                    attrs: BTreeMap::new(),
                };
                update_oauth2_rs.attrs.insert(
                    Attribute::OAuth2RefreshTokenExpiry.into(),
                    vec![exp.to_string()],
                );
                self.perform_patch_request(format!("/v1/oauth2/{id}").as_str(), update_oauth2_rs)
                    .await
            }
            None => {
                self.perform_delete_request(&format!(
                    "/v1/oauth2/{}/_attr/{}",
                    id,
                    Attribute::OAuth2RefreshTokenExpiry.as_str()
                ))
                .await
            }
        }
    }

    pub async fn idm_oauth2_rs_enable_consent_prompt(&self, id: &str) -> Result<(), ClientError> {
        let mut update_oauth2_rs = Entry {
            attrs: BTreeMap::new(),
        };
        update_oauth2_rs.attrs.insert(
            ATTR_OAUTH2_CONSENT_PROMPT_ENABLE.to_string(),
            vec!["true".to_string()],
        );
        self.perform_patch_request(format!("/v1/oauth2/{}", id).as_str(), update_oauth2_rs)
            .await
    }

    pub async fn idm_oauth2_rs_disable_consent_prompt(&self, id: &str) -> Result<(), ClientError> {
        let mut update_oauth2_rs = Entry {
            attrs: BTreeMap::new(),
        };
        update_oauth2_rs.attrs.insert(
            ATTR_OAUTH2_CONSENT_PROMPT_ENABLE.to_string(),
            vec!["false".to_string()],
        );
        self.perform_patch_request(format!("/v1/oauth2/{}", id).as_str(), update_oauth2_rs)
            .await
    }
}
