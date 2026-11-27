use compact_jwt::{JweCompact, Jwk};
use kanidm_proto::{
    backup::BackupCompression,
    internal::{
        ApiToken, AppLink, CURequest, CUSessionToken, CUStatus, CredentialStatus,
        IdentifyUserRequest, IdentifyUserResponse, ImageValue, OperationError, RadiusAuthToken,
        SearchRequest, SearchResponse, UserAuthToken,
    },
    oauth2::OidcWebfingerResponse,
    v1::{
        AuthIssueSession, Entry as ProtoEntry, UatStatus, UnixGroupToken, UnixUserToken,
        WhoamiResponse,
    },
};
use kanidmd_lib::{
    be::BackendTransaction,
    event::{OnlineBackupEvent, SearchEvent, SearchResult, WhoamiResult},
    filter::{Filter, FilterInvalid},
    idm::{
        account::ListUserAuthTokenEvent,
        authentication::{AuthStep, ReauthRequest},
        credupdatesession::CredentialUpdateSessionToken,
        event::{
            AuthEvent, AuthResult, CredentialStatusEvent, RadiusAuthTokenEvent,
            UnixGroupTokenEvent, UnixUserAuthEvent, UnixUserTokenEvent,
        },
        identityverification::{
            IdentifyUserDisplayCodeEvent, IdentifyUserStartEvent, IdentifyUserSubmitCodeEvent,
        },
        ldap::{LdapBoundToken, LdapResponseState},
        oauth2::{
            AccessTokenIntrospectRequest, AccessTokenIntrospectResponse, AuthorisationRequest,
            AuthorisationRequestContext, AuthoriseReject, AuthoriseResponse, JwkKeySet,
            Oauth2Error, Oauth2Rfc8414MetadataResponse, OidcDiscoveryResponse, OidcToken,
        },
        server::{DomainInfoRead, IdmServerTransaction},
        serviceaccount::ListApiTokenEvent,
    },
    prelude::*,
};
use ldap3_proto::simple::*;
use regex::Regex;
use std::{
    convert::TryFrom,
    fs,
    net::IpAddr,
    path::{Path, PathBuf},
    str::FromStr,
};
use tracing::{error, info, instrument, trace};
use uuid::Uuid;

use super::QueryServerReadV1;

// ===========================================================

impl QueryServerReadV1 {
    // The server only receives "Message" structures, which
    // are whole self contained DB operations with all parsing
    // required complete. We still need to do certain validation steps, but
    // at this point our just is just to route to do_<action>

    // ! For uuid, we should deprecate `RequestExtensions::new_eventid` and just manually call
    // ! `Uuid::new_v4().to_hyphenated().to_string()` instead of keeping a `Uuid` around.
    // ! Ideally, this function takes &self, uat, req, and then a `uuid` argument that is a `&str` of the hyphenated uuid.
    // ! Then we just don't skip uuid, and we don't have to do the custom `fields(..)` stuff in this macro call.
    #[instrument(
        level = "info",
        name = "search",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn handle_search(
        &self,
        client_auth_info: ClientAuthInfo,
        req: SearchRequest,
        eventid: Uuid,
    ) -> Result<SearchResponse, OperationError> {
        // Begin a read
        let ct = duration_from_epoch_now();
        let mut idms_prox_read = self.idms.proxy_read().await?;
        let ident = idms_prox_read
            .validate_client_auth_info_to_ident(client_auth_info, ct)
            .map_err(|e| {
                error!(?e, "Invalid identity");
                e
            })?;

        // Make an event from the request
        let search =
            SearchEvent::from_message(ident, &req, &mut idms_prox_read.qs_read).map_err(|e| {
                error!(?e, "Failed to begin search");
                e
            })?;

        trace!(?search, "Begin event");

        let entries = idms_prox_read.qs_read.search_ext(&search)?;

        SearchResult::new(&mut idms_prox_read.qs_read, &entries).map(SearchResult::response)
    }

    #[instrument(
        level = "info",
        name = "auth",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn handle_auth(
        &self,
        sessionid: Option<Uuid>,
        req: AuthStep,
        eventid: Uuid,
        client_auth_info: ClientAuthInfo,
    ) -> Result<AuthResult, OperationError> {
        // This is probably the first function that really implements logic
        // "on top" of the db server concept. In this case we check if
        // the credentials provided is sufficient to say if someone is
        // "authenticated" or not.
        let ct = duration_from_epoch_now();
        let mut idm_auth = self.idms.auth().await?;
        debug!(?sessionid, ?req, "Begin auth event");

        // Destructure it.
        // Convert the AuthRequest to an AuthEvent that the idm server
        // can use.
        let ae = AuthEvent::from_message(sessionid, req).map_err(|e| {
            error!(err = ?e, "Failed to parse AuthEvent");
            e
        })?;

        // Trigger a session clean *before* we take any auth steps.
        // It's important to do this before to ensure that timeouts on
        // the session are enforced.
        idm_auth.expire_auth_sessions(ct).await;

        // Generally things like auth denied are in Ok() msgs
        // so true errors should always trigger a rollback.
        let res = idm_auth
            .auth(&ae, ct, client_auth_info)
            .await
            .and_then(|r| idm_auth.commit().map(|_| r));

        match &res {
            Ok(r) => security_info!("Auth result: {}", r),
            Err(e) => security_error!("Auth result: {:?}", e),
        }

        res
    }

    #[instrument(
        level = "info",
        name = "reauth",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn handle_reauth(
        &self,
        client_auth_info: ClientAuthInfo,
        issue: AuthIssueSession,
        reauth_req: ReauthRequest,
        eventid: Uuid,
    ) -> Result<AuthResult, OperationError> {
        let ct = duration_from_epoch_now();
        let mut idm_auth = self.idms.auth().await?;
        security_info!("Begin reauth event");

        let ident = idm_auth
            .validate_client_auth_info_to_ident(client_auth_info.clone(), ct)
            .map_err(|e| {
                error!(?e, "Invalid identity");
                e
            })?;

        // Trigger a session clean *before* we take any auth steps.
        // It's important to do this before to ensure that timeouts on
        // the session are enforced.
        idm_auth.expire_auth_sessions(ct).await;

        // Generally things like auth denied are in Ok() msgs
        // so true errors should always trigger a rollback.
        let res = idm_auth
            .reauth_init(ident, issue, ct, client_auth_info, reauth_req)
            .await
            .and_then(|r| idm_auth.commit().map(|_| r));

        match &res {
            Ok(r) => security_info!("Reauth result: {}", r),
            Err(e) => security_error!("Reauth result: {:?}", e),
        }

        res
    }

    #[instrument(
        level = "info",
        name = "online_backup",
        skip_all,
        fields(uuid = ?msg.eventid)
    )]
    pub async fn handle_online_backup(
        &self,
        msg: OnlineBackupEvent,
        outpath: &Path,
        versions: usize,
        compression: BackupCompression,
    ) -> Result<(), OperationError> {
        trace!(eventid = ?msg.eventid, "Begin online backup event");

        #[allow(clippy::disallowed_methods)]
        // Allowed as this timestamp is only used for the filename creation.
        let now = time::OffsetDateTime::now_utc();

        #[allow(clippy::unwrap_used)]
        let timestamp = now.format(&Rfc3339).unwrap();
        let dest_file = outpath.join(format!("backup-{timestamp}.json{}", compression.suffix()));

        if dest_file.exists() {
            error!(
                "Online backup file {} already exists, will not overwrite it.",
                dest_file.display()
            );
            return Err(OperationError::InvalidState);
        }

        let output = std::fs::File::create(&dest_file).map_err(|err| {
            error!(?err, "File::create error creating {}", dest_file.display());
            OperationError::FsError
        })?;

        // Scope to limit the read txn.
        {
            let mut idms_prox_read = self.idms.proxy_read().await?;
            idms_prox_read
                .qs_read
                .get_be_txn()
                .backup(output, compression)
                .map(|()| {
                    info!("Online backup created {} successfully", dest_file.display());
                })
                .map_err(|e| {
                    error!(
                        "Online backup failed to create {}: {:?}",
                        dest_file.display(),
                        e
                    );
                    OperationError::InvalidState
                })?;
        }

        // TODO: make the file rotation a separate function

        // pattern to find automatically generated backup files
        let re = Regex::new(r"^backup-\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?Z\.json")
            .map_err(|error| {
                error!(
                    "Failed to parse regexp for online backup files: {:?}",
                    error
                );
                OperationError::InvalidState
            })?;

        // cleanup of maximum backup versions to keep
        let mut backup_file_list: Vec<PathBuf> = Vec::new();
        // get a list of backup files
        match fs::read_dir(outpath) {
            Ok(rd) => {
                for entry in rd {
                    // get PathBuf
                    let pb = entry
                        .map_err(|e| {
                            error!(?e, "Pathbuf access");
                            OperationError::InvalidState
                        })?
                        .path();

                    // skip everything that is not a file
                    if !pb.is_file() {
                        continue;
                    }

                    // get the /some/dir/<file_name> of the file
                    let file_name = pb.file_name().and_then(|f| f.to_str()).ok_or_else(|| {
                        error!("filename is invalid");
                        OperationError::InvalidState
                    })?;
                    // check for a online backup file
                    if re.is_match(file_name) {
                        backup_file_list.push(pb.clone());
                    }
                }
            }
            Err(e) => {
                error!(
                    "Online backup cleanup error read dir {}: {}",
                    outpath.display(),
                    e
                );
                return Err(OperationError::InvalidState);
            }
        }

        // sort it to have items listed old to new
        backup_file_list.sort();

        // Versions: OLD 10.9.8.7.6.5.4.3.2.1 NEW
        //              |----delete----|keep|
        // 10 items, we want to keep the latest 3

        // if we have more files then we want to keep, me do some cleanup
        if backup_file_list.len() > versions {
            let x = backup_file_list.len() - versions;
            info!(
                "Online backup cleanup found {} versions, should keep {}, will remove {}",
                backup_file_list.len(),
                versions,
                x
            );
            backup_file_list.truncate(x);

            // removing files
            for file in backup_file_list {
                debug!("Online backup cleanup: removing {:?}", &file);
                match fs::remove_file(&file) {
                    Ok(_) => {}
                    Err(e) => {
                        error!(
                            "Online backup cleanup failed to remove file {:?}: {:?}",
                            file, e
                        )
                    }
                };
            }
        } else {
            debug!("Online backup cleanup had no files to remove");
        };

        Ok(())
    }

    #[instrument(
        level = "info",
        name = "whoami",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn handle_whoami(
        &self,
        client_auth_info: ClientAuthInfo,
        eventid: Uuid,
    ) -> Result<WhoamiResponse, OperationError> {
        // Begin a read
        let ct = duration_from_epoch_now();
        let mut idms_prox_read = self.idms.proxy_read().await?;
        // Make an event from the whoami request. This will process the event and
        // generate a selfuuid search.
        //
        // This current handles the unauthenticated check, and will
        // trigger the failure, but if we can manage to work out async
        // then move this to core.rs, and don't allow Option<UAT> to get
        // this far.
        let ident = idms_prox_read
            .validate_client_auth_info_to_ident(client_auth_info, ct)
            .map_err(|e| {
                error!(?e, "Invalid identity");
                e
            })?;
        let srch =
            SearchEvent::from_whoami_request(ident, &idms_prox_read.qs_read).map_err(|e| {
                error!(?e, "Failed to begin whoami");
                e
            })?;

        trace!(search = ?srch, "Begin event");

        let mut entries = idms_prox_read.qs_read.search_ext(&srch)?;

        match entries.pop() {
            Some(e) if entries.is_empty() => {
                WhoamiResult::new(&mut idms_prox_read.qs_read, &e).map(WhoamiResult::response)
            }
            Some(_) => Err(OperationError::InvalidState), /* Somehow matched multiple entries... */
            _ => Err(OperationError::NoMatchingEntries),
        }
    }

    pub async fn pre_validate_client_auth_info(
        &self,
        client_auth_info: &mut ClientAuthInfo,
    ) -> Result<(), OperationError> {
        let ct = duration_from_epoch_now();
        let mut idms_prox_read = self.idms.proxy_read().await?;
        idms_prox_read
            .pre_validate_client_auth_info(client_auth_info, ct)
            .map_err(|e| {
                error!(?e, "Invalid identity");
                e
            })
    }

    #[instrument(
        level = "info",
        name = "whoami_uat",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn handle_whoami_uat(
        &self,
        client_auth_info: &ClientAuthInfo,
        eventid: Uuid,
    ) -> Result<UserAuthToken, OperationError> {
        let ct = duration_from_epoch_now();
        let mut idms_prox_read = self.idms.proxy_read().await?;
        // Make an event from the whoami request. This will process the event and
        // generate a selfuuid search.
        //
        // This current handles the unauthenticated check, and will
        // trigger the failure, but if we can manage to work out async
        // then move this to core.rs, and don't allow Option<UAT> to get
        // this far.
        idms_prox_read
            .validate_client_auth_info_to_uat(client_auth_info, ct)
            .map_err(|e| {
                error!(?e, "Invalid identity");
                e
            })
    }

    #[instrument(level = "debug", skip_all)]
    /// pull an image so we can present it to the user
    pub async fn handle_oauth2_rs_image_get_image(
        &self,
        client_auth_info: ClientAuthInfo,
        rs: Filter<FilterInvalid>,
    ) -> Result<Option<ImageValue>, OperationError> {
        let mut idms_prox_read = self.idms.proxy_read().await?;
        let ct = duration_from_epoch_now();

        let ident = idms_prox_read
            .validate_client_auth_info_to_ident(client_auth_info, ct)
            .map_err(|e| {
                error!(err = ?e, "Invalid identity in handle_oauth2_rs_image_get_image");
                e
            })?;
        let attrs = vec![Attribute::Image.to_string()];

        let search = SearchEvent::from_internal_message(
            ident,
            &rs,
            Some(attrs.as_slice()),
            &mut idms_prox_read.qs_read,
        )?;

        let entries = idms_prox_read.qs_read.search(&search)?;
        Ok(entries
            .first()
            .and_then(|entry| entry.get_ava_single_image(Attribute::Image)))
    }

    #[instrument(
        level = "info",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn handle_internalsearch(
        &self,
        client_auth_info: ClientAuthInfo,
        filter: Filter<FilterInvalid>,
        attrs: Option<Vec<String>>,
        eventid: Uuid,
    ) -> Result<Vec<ProtoEntry>, OperationError> {
        let ct = duration_from_epoch_now();
        let mut idms_prox_read = self.idms.proxy_read().await?;
        let ident = idms_prox_read
            .validate_client_auth_info_to_ident(client_auth_info, ct)
            .map_err(|e| {
                error!("Invalid identity: {:?}", e);
                e
            })?;
        // Make an event from the request
        let srch = match SearchEvent::from_internal_message(
            ident,
            &filter,
            attrs.as_deref(),
            &mut idms_prox_read.qs_read,
        ) {
            Ok(s) => s,
            Err(e) => {
                error!("Failed to begin internal api search: {:?}", e);
                return Err(e);
            }
        };

        trace!(?srch, "Begin event");

        match idms_prox_read.qs_read.search_ext(&srch) {
            Ok(entries) => SearchResult::new(&mut idms_prox_read.qs_read, &entries)
                .map(|ok_sr| ok_sr.into_proto_array()),
            Err(e) => Err(e),
        }
    }

    #[instrument(
        level = "info",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn handle_search_refers(
        &self,
        client_auth_info: ClientAuthInfo,
        filter: Filter<FilterInvalid>,
        uuid_or_name: String,
        attrs: Option<Vec<String>>,
        eventid: Uuid,
    ) -> Result<Vec<ProtoEntry>, OperationError> {
        let ct = duration_from_epoch_now();
        let mut idms_prox_read = self.idms.proxy_read().await?;
        let ident = idms_prox_read
            .validate_client_auth_info_to_ident(client_auth_info, ct)
            .map_err(|e| {
                error!("Invalid identity: {:?}", e);
                e
            })?;

        let target_uuid = idms_prox_read
            .qs_read
            .name_to_uuid(uuid_or_name.as_str())
            .inspect_err(|err| {
                error!(?err, "Error resolving id to target");
            })?;

        // Update the filter with the target_uuid
        let filter = Filter::join_parts_and(
            filter,
            filter_all!(f_eq(Attribute::Refers, PartialValue::Refer(target_uuid))),
        );

        // Make an event from the request
        let srch = match SearchEvent::from_internal_message(
            ident,
            &filter,
            attrs.as_deref(),
            &mut idms_prox_read.qs_read,
        ) {
            Ok(s) => s,
            Err(e) => {
                error!("Failed to begin internal api search: {:?}", e);
                return Err(e);
            }
        };

        trace!(?srch, "Begin event");

        match idms_prox_read.qs_read.search_ext(&srch) {
            Ok(entries) => SearchResult::new(&mut idms_prox_read.qs_read, &entries)
                .map(|ok_sr| ok_sr.into_proto_array()),
            Err(e) => Err(e),
        }
    }

    #[instrument(
        level = "info",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn handle_internalsearchrecycled(
        &self,
        client_auth_info: ClientAuthInfo,
        filter: Filter<FilterInvalid>,
        attrs: Option<Vec<String>>,
        eventid: Uuid,
    ) -> Result<Vec<ProtoEntry>, OperationError> {
        let ct = duration_from_epoch_now();
        let mut idms_prox_read = self.idms.proxy_read().await?;

        let ident = idms_prox_read
            .validate_client_auth_info_to_ident(client_auth_info, ct)
            .map_err(|e| {
                error!("Invalid identity: {:?}", e);
                e
            })?;
        // Make an event from the request
        let srch = match SearchEvent::from_internal_recycle_message(
            ident,
            &filter,
            attrs.as_deref(),
            &idms_prox_read.qs_read,
        ) {
            Ok(s) => s,
            Err(e) => {
                error!("Failed to begin recycled search: {:?}", e);
                return Err(e);
            }
        };

        trace!(?srch, "Begin event");

        match idms_prox_read.qs_read.search_ext(&srch) {
            Ok(entries) => SearchResult::new(&mut idms_prox_read.qs_read, &entries)
                .map(|ok_sr| ok_sr.into_proto_array()),
            Err(e) => Err(e),
        }
    }

    #[instrument(
        level = "info",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn handle_internalradiusread(
        &self,
        client_auth_info: ClientAuthInfo,
        uuid_or_name: String,
        eventid: Uuid,
    ) -> Result<Option<String>, OperationError> {
        let ct = duration_from_epoch_now();
        let mut idms_prox_read = self.idms.proxy_read().await?;
        let ident = idms_prox_read
            .validate_client_auth_info_to_ident(client_auth_info, ct)
            .map_err(|e| {
                error!("Invalid identity: {:?}", e);
                e
            })?;

        let target_uuid = idms_prox_read
            .qs_read
            .name_to_uuid(uuid_or_name.as_str())
            .inspect_err(|err| {
                error!(?err, "Error resolving id to target");
            })?;

        // Make an event from the request
        let srch = match SearchEvent::from_target_uuid_request(
            ident,
            target_uuid,
            &idms_prox_read.qs_read,
        ) {
            Ok(s) => s,
            Err(e) => {
                error!("Failed to begin radius read: {:?}", e);
                return Err(e);
            }
        };

        trace!(?srch, "Begin event");

        // We have to use search_ext to guarantee acs was applied.
        match idms_prox_read.qs_read.search_ext(&srch) {
            Ok(mut entries) => {
                let r = entries
                    .pop()
                    // From the entry, turn it into the value
                    .and_then(|entry| {
                        entry
                            .get_ava_single(Attribute::RadiusSecret)
                            .and_then(|v| v.get_secret_str().map(str::to_string))
                    });
                Ok(r)
            }
            Err(e) => Err(e),
        }
    }

    #[instrument(
        level = "info",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn handle_internalradiustokenread(
        &self,
        client_auth_info: ClientAuthInfo,
        uuid_or_name: String,
        eventid: Uuid,
    ) -> Result<RadiusAuthToken, OperationError> {
        let ct = duration_from_epoch_now();
        let mut idms_prox_read = self.idms.proxy_read().await?;

        let ident = idms_prox_read
            .validate_client_auth_info_to_ident(client_auth_info, ct)
            .map_err(|e| {
                error!("Invalid identity: {:?}", e);
                e
            })?;

        let target_uuid = idms_prox_read
            .qs_read
            .name_to_uuid(uuid_or_name.as_str())
            .inspect_err(|err| {
                error!(?err, "Error resolving id to target");
            })?;

        // Make an event from the request
        let rate = match RadiusAuthTokenEvent::from_parts(
            // &idms_prox_read.qs_read,
            ident,
            target_uuid,
        ) {
            Ok(s) => s,
            Err(e) => {
                error!("Failed to begin radius token read: {:?}", e);
                return Err(e);
            }
        };

        trace!(?rate, "Begin event");

        idms_prox_read.get_radiusauthtoken(&rate, ct)
    }

    #[instrument(
        level = "info",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn handle_internalunixusertokenread(
        &self,
        client_auth_info: ClientAuthInfo,
        uuid_or_name: String,
        eventid: Uuid,
    ) -> Result<UnixUserToken, OperationError> {
        let ct = duration_from_epoch_now();
        let mut idms_prox_read = self.idms.proxy_read().await?;

        let ident = idms_prox_read
            .validate_client_auth_info_to_ident(client_auth_info, ct)
            .map_err(|e| {
                error!("Invalid identity: {:?}", e);
                e
            })?;

        let target_uuid = idms_prox_read
            .qs_read
            .name_to_uuid(uuid_or_name.as_str())
            .map_err(|e| {
                // sometimes it comes back as empty which is bad, it's safe to start with `<empty` here
                // because a valid username/uuid can never start with that and we're only logging it
                let uuid_or_name_val = match uuid_or_name.is_empty() {
                    true => "<empty uuid_or_name>",
                    false => &uuid_or_name,
                };
                debug!(
                    err = ?e,
                    "Error resolving {} as gidnumber continuing ...",
                    uuid_or_name_val
                );
                e
            })?;

        // Make an event from the request
        let rate = match UnixUserTokenEvent::from_parts(ident, target_uuid) {
            Ok(s) => s,
            Err(e) => {
                error!("Failed to begin unix token read: {:?}", e);
                return Err(e);
            }
        };

        trace!(?rate, "Begin event");

        idms_prox_read.get_unixusertoken(&rate, ct)
    }

    #[instrument(
        level = "debug",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn handle_internalunixgrouptokenread(
        &self,
        client_auth_info: ClientAuthInfo,
        uuid_or_name: String,
        eventid: Uuid,
    ) -> Result<UnixGroupToken, OperationError> {
        let ct = duration_from_epoch_now();
        let mut idms_prox_read = self.idms.proxy_read().await?;
        let ident = idms_prox_read
            .validate_client_auth_info_to_ident(client_auth_info, ct)
            .map_err(|e| {
                error!("Invalid identity: {:?}", e);
                e
            })?;

        let target_uuid = idms_prox_read
            .qs_read
            .name_to_uuid(uuid_or_name.as_str())
            .map_err(|e| {
                admin_info!(err = ?e, "Error resolving as gidnumber continuing");
                e
            })?;

        // Make an event from the request
        let rate = match UnixGroupTokenEvent::from_parts(
            // &idms_prox_read.qs_read,
            ident,
            target_uuid,
        ) {
            Ok(s) => s,
            Err(e) => {
                error!("Failed to begin unix group token read: {:?}", e);
                return Err(e);
            }
        };

        trace!(?rate, "Begin event");

        idms_prox_read.get_unixgrouptoken(&rate)
    }

    #[instrument(
        level = "debug",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn handle_internalsshkeyread(
        &self,
        client_auth_info: ClientAuthInfo,
        uuid_or_name: String,
        eventid: Uuid,
    ) -> Result<Vec<String>, OperationError> {
        let ct = duration_from_epoch_now();
        let mut idms_prox_read = self.idms.proxy_read().await?;
        let ident = idms_prox_read
            .validate_client_auth_info_to_ident(client_auth_info, ct)
            .map_err(|e| {
                error!("Invalid identity: {:?}", e);
                e
            })?;
        let target_uuid = idms_prox_read
            .qs_read
            .name_to_uuid(uuid_or_name.as_str())
            .inspect_err(|err| {
                error!(?err, "Error resolving id to target");
            })?;

        // Make an event from the request
        let srch = match SearchEvent::from_target_uuid_request(
            ident,
            target_uuid,
            &idms_prox_read.qs_read,
        ) {
            Ok(s) => s,
            Err(e) => {
                error!("Failed to begin ssh key read: {:?}", e);
                return Err(e);
            }
        };

        trace!(?srch, "Begin event");

        match idms_prox_read.qs_read.search_ext(&srch) {
            Ok(mut entries) => {
                let r = entries
                    .pop()
                    // get the first entry
                    .and_then(|e| {
                        // From the entry, turn it into the value
                        e.get_ava_iter_sshpubkeys(Attribute::SshPublicKey)
                            .map(|i| i.collect())
                    })
                    .unwrap_or_else(|| {
                        // No matching entry? Return none.
                        Vec::new()
                    });
                Ok(r)
            }
            Err(e) => Err(e),
        }
    }

    #[instrument(
        level = "info",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn handle_internalsshkeytagread(
        &self,
        client_auth_info: ClientAuthInfo,
        uuid_or_name: String,
        tag: String,
        eventid: Uuid,
    ) -> Result<Option<String>, OperationError> {
        let ct = duration_from_epoch_now();
        let mut idms_prox_read = self.idms.proxy_read().await?;
        let ident = idms_prox_read
            .validate_client_auth_info_to_ident(client_auth_info, ct)
            .map_err(|e| {
                error!("Invalid identity: {:?}", e);
                e
            })?;
        let target_uuid = idms_prox_read
            .qs_read
            .name_to_uuid(uuid_or_name.as_str())
            .inspect_err(|err| {
                admin_info!(?err, "Error resolving id to target");
            })?;

        // Make an event from the request
        let srch = match SearchEvent::from_target_uuid_request(
            ident,
            target_uuid,
            &idms_prox_read.qs_read,
        ) {
            Ok(s) => s,
            Err(e) => {
                error!("Failed to begin sshkey tag read: {:?}", e);
                return Err(e);
            }
        };

        trace!(?srch, "Begin event");

        match idms_prox_read.qs_read.search_ext(&srch) {
            Ok(mut entries) => {
                let r = entries
                    .pop()
                    // get the first entry
                    .map(|e| {
                        // From the entry, turn it into the value
                        e.get_ava_set(Attribute::SshPublicKey).and_then(|vs| {
                            // Get the one tagged value
                            vs.get_ssh_tag(&tag).map(|pk| pk.to_string())
                        })
                    })
                    .unwrap_or_else(|| {
                        // No matching entry? Return none.
                        None
                    });
                Ok(r)
            }
            Err(e) => Err(e),
        }
    }

    #[instrument(
        level = "info",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn handle_service_account_api_token_get(
        &self,
        client_auth_info: ClientAuthInfo,
        uuid_or_name: String,
        eventid: Uuid,
    ) -> Result<Vec<ApiToken>, OperationError> {
        let ct = duration_from_epoch_now();
        let mut idms_prox_read = self.idms.proxy_read().await?;
        let ident = idms_prox_read
            .validate_client_auth_info_to_ident(client_auth_info, ct)
            .map_err(|e| {
                error!("Invalid identity: {:?}", e);
                e
            })?;
        let target = idms_prox_read
            .qs_read
            .name_to_uuid(uuid_or_name.as_str())
            .inspect_err(|err| {
                error!(?err, "Error resolving id to target");
            })?;

        let lte = ListApiTokenEvent { ident, target };

        idms_prox_read.service_account_list_api_token(&lte)
    }

    #[instrument(
        level = "info",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn handle_account_user_auth_token_get(
        &self,
        client_auth_info: ClientAuthInfo,
        uuid_or_name: String,
        eventid: Uuid,
    ) -> Result<Vec<UatStatus>, OperationError> {
        let ct = duration_from_epoch_now();
        let mut idms_prox_read = self.idms.proxy_read().await?;
        let ident = idms_prox_read
            .validate_client_auth_info_to_ident(client_auth_info, ct)
            .map_err(|e| {
                error!("Invalid identity: {:?}", e);
                e
            })?;
        let target = idms_prox_read
            .qs_read
            .name_to_uuid(uuid_or_name.as_str())
            .inspect_err(|err| {
                error!(?err, "Error resolving id to target");
            })?;

        let lte = ListUserAuthTokenEvent { ident, target };

        idms_prox_read.account_list_user_auth_tokens(&lte)
    }

    #[instrument(
        level = "info",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn handle_user_identity_verification(
        &self,
        client_auth_info: ClientAuthInfo,
        eventid: Uuid,
        user_request: IdentifyUserRequest,
        other_id: String,
    ) -> Result<IdentifyUserResponse, OperationError> {
        trace!("{:?}", &user_request);
        let ct = duration_from_epoch_now();
        let mut idms_prox_read = self.idms.proxy_read().await?;
        let ident = idms_prox_read
            .validate_client_auth_info_to_ident(client_auth_info, ct)
            .map_err(|e| {
                error!("Invalid identity: {:?}", e);
                e
            })?;
        let target = idms_prox_read
            .qs_read
            .name_to_uuid(&other_id)
            .map_err(|e| {
                error!("No user found with the provided ID: {:?}", e);
                e
            })?;
        match user_request {
            IdentifyUserRequest::Start => idms_prox_read
                .handle_identify_user_start(&IdentifyUserStartEvent::new(target, ident), ct),
            IdentifyUserRequest::DisplayCode => idms_prox_read.handle_identify_user_display_code(
                &IdentifyUserDisplayCodeEvent::new(target, ident),
                ct,
            ),
            IdentifyUserRequest::SubmitCode { other_totp } => idms_prox_read
                .handle_identify_user_submit_code(
                    &IdentifyUserSubmitCodeEvent::new(target, ident, other_totp),
                    ct,
                ),
        }
    }

    #[instrument(
        level = "info",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn handle_idmaccountunixauth(
        &self,
        client_auth_info: ClientAuthInfo,
        uuid_or_name: String,
        cred: String,
        eventid: Uuid,
    ) -> Result<Option<UnixUserToken>, OperationError> {
        let ct = duration_from_epoch_now();
        let mut idm_auth = self.idms.auth().await?;
        // resolve the id
        let ident = idm_auth
            .validate_client_auth_info_to_ident(client_auth_info, ct)
            .map_err(|e| {
                error!(err = ?e, "Invalid identity");
                e
            })?;

        let target_uuid = idm_auth
            .qs_read
            .name_to_uuid(uuid_or_name.as_str())
            .map_err(|e| {
                admin_info!(err = ?e, "Error resolving as gidnumber continuing");
                e
            })?;
        // Make an event from the request
        let uuae = match UnixUserAuthEvent::from_parts(ident, target_uuid, cred) {
            Ok(s) => s,
            Err(e) => {
                error!(err = ?e, "Failed to begin unix auth");
                return Err(e);
            }
        };

        security_info!(event = ?uuae, "Begin unix auth event");

        let res = idm_auth
            .auth_unix(&uuae, ct)
            .await
            .and_then(|r| idm_auth.commit().map(|_| r));

        security_info!(?res, "Sending result");

        res
    }

    #[instrument(
        level = "info",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn handle_idmcredentialstatus(
        &self,
        client_auth_info: ClientAuthInfo,
        uuid_or_name: String,
        eventid: Uuid,
    ) -> Result<CredentialStatus, OperationError> {
        let ct = duration_from_epoch_now();
        let mut idms_prox_read = self.idms.proxy_read().await?;

        let ident = idms_prox_read
            .validate_client_auth_info_to_ident(client_auth_info, ct)
            .map_err(|e| {
                error!(err = ?e, "Invalid identity");
                e
            })?;
        let target_uuid = idms_prox_read
            .qs_read
            .name_to_uuid(uuid_or_name.as_str())
            .map_err(|e| {
                error!(err = ?e, "Error resolving id to target");
                e
            })?;

        // Make an event from the request
        let cse = match CredentialStatusEvent::from_parts(
            // &idms_prox_read.qs_read,
            ident,
            target_uuid,
        ) {
            Ok(s) => s,
            Err(e) => {
                error!(err = ?e, "Failed to begin credential status read");
                return Err(e);
            }
        };

        trace!(?cse, "Begin event");

        idms_prox_read.get_credentialstatus(&cse)
    }

    #[instrument(
        level = "info",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn handle_idmcredentialupdatestatus(
        &self,
        session_token: CUSessionToken,
        eventid: Uuid,
    ) -> Result<CUStatus, OperationError> {
        let session_token = JweCompact::from_str(&session_token.token)
            .map(|token_enc| CredentialUpdateSessionToken { token_enc })
            .map_err(|err| {
                error!(?err, "malformed token");
                OperationError::InvalidRequestState
            })?;

        // Don't proceed unless the token parses
        let ct = duration_from_epoch_now();
        let idms_cred_update = self.idms.cred_update_transaction().await?;

        idms_cred_update
            .credential_update_status(&session_token, ct)
            .map_err(|e| {
                error!(
                    err = ?e,
                    "Failed to begin credential_update_status",
                );
                e
            })
            .map(|sta| sta.into())
    }

    #[instrument(
        level = "info",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn handle_idmcredentialupdate(
        &self,
        session_token: CUSessionToken,
        scr: CURequest,
        eventid: Uuid,
    ) -> Result<CUStatus, OperationError> {
        let session_token = JweCompact::from_str(&session_token.token)
            .map(|token_enc| CredentialUpdateSessionToken { token_enc })
            .map_err(|err| {
                error!(?err, "Invalid Token - Must be a compact JWE");
                OperationError::InvalidRequestState
            })?;

        let ct = duration_from_epoch_now();
        let idms_cred_update = self.idms.cred_update_transaction().await?;

        debug!(?scr);

        match scr {
            CURequest::PrimaryRemove => idms_cred_update
                .credential_primary_delete(&session_token, ct)
                .inspect_err(|err| {
                    error!(?err, "Failed to begin credential_primary_delete",);
                }),
            CURequest::PasswordQualityCheck(pw) => idms_cred_update
                .credential_check_password_quality(&session_token, ct, &pw)
                .inspect_err(|err| {
                    error!(?err, "Failed to begin credential_check_password_quality",);
                }),
            CURequest::Password(pw) => idms_cred_update
                .credential_primary_set_password(&session_token, ct, &pw)
                .inspect_err(|err| {
                    error!(?err, "Failed to begin credential_primary_set_password",);
                }),
            CURequest::CancelMFAReg => idms_cred_update
                .credential_update_cancel_mfareg(&session_token, ct)
                .inspect_err(|err| {
                    error!(?err, "Failed to begin credential_update_cancel_mfareg",);
                }),
            CURequest::TotpGenerate => idms_cred_update
                .credential_primary_init_totp(&session_token, ct)
                .inspect_err(|err| {
                    error!(?err, "Failed to begin credential_primary_init_totp",);
                }),
            CURequest::TotpVerify(totp_chal, label) => idms_cred_update
                .credential_primary_check_totp(&session_token, ct, totp_chal, &label)
                .inspect_err(|err| {
                    error!(?err, "Failed to begin credential_primary_check_totp",);
                }),
            CURequest::TotpAcceptSha1 => idms_cred_update
                .credential_primary_accept_sha1_totp(&session_token, ct)
                .inspect_err(|err| {
                    error!(?err, "Failed to begin credential_primary_accept_sha1_totp",);
                }),
            CURequest::TotpRemove(label) => idms_cred_update
                .credential_primary_remove_totp(&session_token, ct, &label)
                .inspect_err(|err| {
                    error!(?err, "Failed to begin credential_primary_remove_totp",);
                }),
            CURequest::BackupCodeGenerate => idms_cred_update
                .credential_primary_init_backup_codes(&session_token, ct)
                .inspect_err(|err| {
                    error!(?err, "Failed to begin credential_primary_init_backup_codes",);
                }),
            CURequest::BackupCodeRemove => idms_cred_update
                .credential_primary_remove_backup_codes(&session_token, ct)
                .inspect_err(|err| {
                    error!(
                        ?err,
                        "Failed to begin credential_primary_remove_backup_codes",
                    );
                }),
            CURequest::PasskeyInit => idms_cred_update
                .credential_passkey_init(&session_token, ct)
                .inspect_err(|err| {
                    error!(?err, "Failed to begin credential_passkey_init",);
                }),
            CURequest::PasskeyFinish(label, rpkc) => idms_cred_update
                .credential_passkey_finish(&session_token, ct, label, &rpkc)
                .inspect_err(|err| {
                    error!(?err, "Failed to begin credential_passkey_finish",);
                }),
            CURequest::PasskeyRemove(uuid) => idms_cred_update
                .credential_passkey_remove(&session_token, ct, uuid)
                .inspect_err(|err| {
                    error!(?err, "Failed to begin credential_passkey_remove",);
                }),
            CURequest::AttestedPasskeyInit => idms_cred_update
                .credential_attested_passkey_init(&session_token, ct)
                .inspect_err(|err| {
                    error!(?err, "Failed to begin credential_attested_passkey_init",);
                }),
            CURequest::AttestedPasskeyFinish(label, rpkc) => idms_cred_update
                .credential_attested_passkey_finish(&session_token, ct, label, &rpkc)
                .inspect_err(|err| {
                    error!(?err, "Failed to begin credential_attested_passkey_finish",);
                }),
            CURequest::AttestedPasskeyRemove(uuid) => idms_cred_update
                .credential_attested_passkey_remove(&session_token, ct, uuid)
                .inspect_err(|err| {
                    error!(?err, "Failed to begin credential_attested_passkey_remove",);
                }),
            CURequest::UnixPasswordRemove => idms_cred_update
                .credential_unix_delete(&session_token, ct)
                .inspect_err(|err| {
                    error!(?err, "Failed to begin credential_unix_delete");
                }),
            CURequest::UnixPassword(pw) => idms_cred_update
                .credential_unix_set_password(&session_token, ct, &pw)
                .inspect_err(|err| {
                    error!(?err, "Failed to begin credential_unix_set_password");
                }),
            CURequest::SshPublicKey(label, pubkey) => idms_cred_update
                .credential_sshkey_add(&session_token, ct, label, pubkey)
                .inspect_err(|err| {
                    error!(?err, "Failed to begin credential_sshkey_remove");
                }),
            CURequest::SshPublicKeyRemove(label) => idms_cred_update
                .credential_sshkey_remove(&session_token, ct, &label)
                .inspect_err(|err| {
                    error!(?err, "Failed to begin credential_sshkey_remove");
                }),
        }
        .map(|sta| sta.into())
    }

    #[instrument(
        level = "info",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn handle_oauth2_basic_secret_read(
        &self,
        client_auth_info: ClientAuthInfo,
        filter: Filter<FilterInvalid>,
        eventid: Uuid,
    ) -> Result<Option<String>, OperationError> {
        let ct = duration_from_epoch_now();
        let mut idms_prox_read = self.idms.proxy_read().await?;
        let ident = idms_prox_read
            .validate_client_auth_info_to_ident(client_auth_info, ct)
            .map_err(|e| {
                error!("Invalid identity: {:?}", e);
                e
            })?;

        // Make an event from the request
        let srch = match SearchEvent::from_internal_message(
            ident,
            &filter,
            None,
            &mut idms_prox_read.qs_read,
        ) {
            Ok(s) => s,
            Err(e) => {
                error!("Failed to begin oauth2 basic secret read: {:?}", e);
                return Err(e);
            }
        };

        trace!(?srch, "Begin event");

        // We have to use search_ext to guarantee acs was applied.
        match idms_prox_read.qs_read.search_ext(&srch) {
            Ok(mut entries) => {
                let r = entries
                    .pop()
                    // From the entry, turn it into the value
                    .and_then(|entry| {
                        entry
                            .get_ava_single(Attribute::OAuth2RsBasicSecret)
                            .and_then(|v| v.get_secret_str().map(str::to_string))
                    });
                Ok(r)
            }
            Err(e) => Err(e),
        }
    }

    #[instrument(
        level = "info",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn handle_oauth2_authorise(
        &self,
        client_auth_info: ClientAuthInfo,
        auth_req: AuthorisationRequest,
        auth_req_ctx: AuthorisationRequestContext,
        eventid: Uuid,
    ) -> Result<AuthoriseResponse, Oauth2Error> {
        let ct = duration_from_epoch_now();
        let mut idms_prox_read = self
            .idms
            .proxy_read()
            .await
            .map_err(Oauth2Error::ServerError)?;
        let ident = idms_prox_read
            .validate_client_auth_info_to_ident(client_auth_info, ct)
            .inspect_err(|e| {
                error!("Invalid identity: {:?}", e);
            })
            .ok();

        // Now we can send to the idm server for authorisation checking.
        idms_prox_read.check_oauth2_authorisation(ident.as_ref(), &auth_req, &auth_req_ctx, ct)
    }

    #[instrument(
        level = "info",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn handle_oauth2_authorise_reject(
        &self,
        client_auth_info: ClientAuthInfo,
        consent_req: String,
        eventid: Uuid,
    ) -> Result<AuthoriseReject, OperationError> {
        let ct = duration_from_epoch_now();
        let mut idms_prox_read = self.idms.proxy_read().await?;
        let ident = idms_prox_read
            .validate_client_auth_info_to_ident(client_auth_info, ct)
            .map_err(|e| {
                error!("Invalid identity: {:?}", e);
                e
            })?;

        idms_prox_read.check_oauth2_authorise_reject(&ident, &consent_req, ct)
    }

    #[instrument(
        level = "info",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn handle_oauth2_token_introspect(
        &self,
        intr_req: AccessTokenIntrospectRequest,
        eventid: Uuid,
    ) -> Result<AccessTokenIntrospectResponse, Oauth2Error> {
        let ct = duration_from_epoch_now();
        let mut idms_prox_read = self
            .idms
            .proxy_read()
            .await
            .map_err(Oauth2Error::ServerError)?;
        // Now we can send to the idm server for introspection checking.
        idms_prox_read.check_oauth2_token_introspect(&intr_req, ct)
    }

    #[instrument(
        level = "info",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn handle_oauth2_openid_userinfo(
        &self,
        client_id: String,
        client_auth_info: &ClientAuthInfo,
        eventid: Uuid,
    ) -> Result<OidcToken, Oauth2Error> {
        let ct = duration_from_epoch_now();
        let mut idms_prox_read = self
            .idms
            .proxy_read()
            .await
            .map_err(Oauth2Error::ServerError)?;
        idms_prox_read.oauth2_openid_userinfo(&client_id, client_auth_info, ct)
    }

    #[instrument(
        level = "info",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn handle_oauth2_openid_discovery(
        &self,
        client_id: String,
        eventid: Uuid,
    ) -> Result<OidcDiscoveryResponse, OperationError> {
        let idms_prox_read = self.idms.proxy_read().await?;
        idms_prox_read.oauth2_openid_discovery(&client_id)
    }

    #[instrument(
        level = "info",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn handle_oauth2_webfinger_discovery(
        &self,
        client_id: &str,
        resource_id: &str,
        eventid: Uuid,
    ) -> Result<OidcWebfingerResponse, OperationError> {
        let mut idms_prox_read = self.idms.proxy_read().await?;
        idms_prox_read.oauth2_openid_webfinger(client_id, resource_id)
    }

    #[instrument(
        level = "info",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn handle_oauth2_rfc8414_metadata(
        &self,
        client_id: String,
        eventid: Uuid,
    ) -> Result<Oauth2Rfc8414MetadataResponse, OperationError> {
        let idms_prox_read = self.idms.proxy_read().await?;
        idms_prox_read.oauth2_rfc8414_metadata(&client_id)
    }

    #[instrument(
        level = "info",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn handle_oauth2_openid_publickey(
        &self,
        client_id: String,
        eventid: Uuid,
    ) -> Result<JwkKeySet, OperationError> {
        let idms_prox_read = self.idms.proxy_read().await?;
        idms_prox_read.oauth2_openid_publickey(&client_id)
    }

    #[instrument(
        level = "info",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn handle_list_applinks(
        &self,
        client_auth_info: ClientAuthInfo,
        eventid: Uuid,
    ) -> Result<Vec<AppLink>, OperationError> {
        let ct = duration_from_epoch_now();
        let mut idms_prox_read = self.idms.proxy_read().await?;
        let ident = idms_prox_read
            .validate_client_auth_info_to_ident(client_auth_info, ct)
            .map_err(|e| {
                error!("Invalid identity: {:?}", e);
                e
            })?;

        // Nice and easy!
        idms_prox_read.list_applinks(&ident)
    }

    #[instrument(
        level = "info",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn handle_auth_valid(
        &self,
        client_auth_info: ClientAuthInfo,
        eventid: Uuid,
    ) -> Result<(), OperationError> {
        let ct = duration_from_epoch_now();
        let mut idms_prox_read = self.idms.proxy_read().await?;

        idms_prox_read
            .validate_client_auth_info_to_ident(client_auth_info, ct)
            .map(|_| ())
            .map_err(|e| {
                error!("Invalid identity: {:?}", e);
                e
            })
    }

    #[instrument(
        level = "info",
        skip_all,
        fields(uuid = ?eventid)
    )]
    /// Retrieve a public jwk
    pub async fn handle_public_jwk_get(
        &self,
        key_id: String,
        eventid: Uuid,
    ) -> Result<Jwk, OperationError> {
        let mut idms_prox_read = self.idms.proxy_read().await?;

        idms_prox_read.jws_public_jwk(key_id.as_str())
    }

    #[instrument(
        level = "info",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn handle_ldaprequest(
        &self,
        eventid: Uuid,
        protomsg: LdapMsg,
        uat: Option<LdapBoundToken>,
        ip_addr: IpAddr,
    ) -> Option<LdapResponseState> {
        let res = match ServerOps::try_from(protomsg) {
            Ok(server_op) => self
                .ldap
                .do_op(&self.idms, server_op, uat, ip_addr, eventid)
                .await
                .unwrap_or_else(|e| {
                    error!("do_op failed -> {:?}", e);
                    LdapResponseState::Disconnect(DisconnectionNotice::gen_response(
                        LdapResultCode::Other,
                        format!("Internal Server Error {:?}", eventid).as_str(),
                    ))
                }),
            Err(_) => LdapResponseState::Disconnect(DisconnectionNotice::gen_response(
                LdapResultCode::ProtocolError,
                format!("Invalid Request {:?}", eventid).as_str(),
            )),
        };
        Some(res)
    }

    pub fn domain_info_read(&self) -> DomainInfoRead {
        self.idms.domain_read()
    }
}
