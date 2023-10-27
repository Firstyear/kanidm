use kanidm_proto::v1::SchemaError;
use std::time::Duration;

use crate::prelude::*;

use super::ServerPhase;

impl QueryServer {
    #[instrument(level = "info", name = "system_initialisation", skip_all)]
    pub async fn initialise_helper(&self, ts: Duration) -> Result<(), OperationError> {
        // We need to perform this in a single transaction pass to prevent tainting
        // databases during upgrades.
        let mut write_txn = self.write(ts).await;

        // Check our database version - attempt to do an initial indexing
        // based on the in memory configuration
        //
        // If we ever change the core in memory schema, or the schema that we ship
        // in fixtures, we have to bump these values. This is how we manage the
        // first-run and upgrade reindexings.
        //
        // A major reason here to split to multiple transactions is to allow schema
        // reloading to occur, which causes the idxmeta to update, and allows validation
        // of the schema in the subsequent steps as we proceed.
        write_txn.upgrade_reindex(SYSTEM_INDEX_VERSION)?;

        // Because we init the schema here, and commit, this reloads meaning
        // that the on-disk index meta has been loaded, so our subsequent
        // migrations will be correctly indexed.
        //
        // Remember, that this would normally mean that it's possible for schema
        // to be mis-indexed (IE we index the new schemas here before we read
        // the schema to tell us what's indexed), but because we have the in
        // mem schema that defines how schema is structuded, and this is all
        // marked "system", then we won't have an issue here.
        write_txn
            .initialise_schema_core()
            .and_then(|_| write_txn.reload())?;

        write_txn
            .initialise_schema_idm()
            .and_then(|_| write_txn.reload())?;

        // reindex and set to version + 1, this way when we bump the version
        // we are essetially pushing this version id back up to step write_1
        write_txn
            .upgrade_reindex(SYSTEM_INDEX_VERSION + 1)
            .and_then(|_| write_txn.reload())?;

        // Force the schema to reload - this is so that any changes to index slope
        // analysis that was performed during the reindex are now reflected correctly
        // in the in-memory schema cache.
        //
        // A side effect of these reloads is that other plugins or elements that reload
        // on schema change are now setup.

        write_txn.set_phase(ServerPhase::SchemaReady);
        write_txn.force_schema_reload();
        write_txn.reload()?;

        // Now, based on the system version apply migrations. You may ask "should you not
        // be doing migrations before indexes?". And this is a very good question! The issue
        // is within a migration we must be able to search for content by pres index, and those
        // rely on us being indexed! It *is* safe to index content even if the
        // migration would cause a value type change (ie name changing from iutf8s to iname) because
        // the indexing subsystem is schema/value agnostic - the fact the values still let their keys
        // be extracted, means that the pres indexes will be valid even though the entries are pending
        // migration. We must be sure to NOT use EQ/SUB indexes in the migration code however!
        //
        // If we are "in the process of being setup" this is 0, and the migrations will have no
        // effect as ... there is nothing to migrate! It allows reset of the version to 0 to force
        // db migrations to take place.
        let system_info_version = match write_txn.internal_search_uuid(UUID_SYSTEM_INFO) {
            Ok(e) => Ok(e.get_ava_single_uint32(Attribute::Version).unwrap_or(0)),
            Err(OperationError::NoMatchingEntries) => Ok(0),
            Err(r) => Err(r),
        }?;
        admin_debug!(?system_info_version);

        if system_info_version > 0 {
            if system_info_version <= 9 {
                error!("Your instance of Kanidm is version 1.1.0-alpha.10 or lower, and you are trying to perform a skip upgrade. This will not work.");
                error!("You need to upgrade one version at a time to ensure upgrade migrations are performed in the correct order.");
                return Err(OperationError::InvalidState);
            }

            if system_info_version < 9 {
                write_txn.migrate_8_to_9()?;
            }

            if system_info_version < 10 {
                write_txn.migrate_9_to_10()?;
            }

            if system_info_version < 11 {
                write_txn.migrate_10_to_11()?;
            }

            if system_info_version < 12 {
                write_txn.migrate_11_to_12()?;
            }

            if system_info_version < 13 {
                write_txn.migrate_12_to_13()?;
            }

            if system_info_version < 14 {
                write_txn.migrate_13_to_14()?;
            }

            if system_info_version < 15 {
                write_txn.migrate_14_to_15()?;
            }

            if system_info_version < 16 {
                write_txn.migrate_15_to_16()?;
            }
        }

        // Reload if anything in migrations requires it.
        write_txn.reload()?;
        // Migrations complete. Init idm will now set the version as needed.
        write_txn.initialise_idm()?;

        // Now force everything to reload.
        write_txn.force_all_reload();
        // We are ready to run
        write_txn.set_phase(ServerPhase::Running);

        // Commit all changes, this also triggers the reload.
        write_txn.commit()?;

        // Here is where in the future we will need to apply domain version increments.
        // The actually migrations are done in a transaction though, this just needs to
        // bump the version in it's own transaction.

        admin_debug!("Database version check and migrations success! ☀️  ");
        Ok(())
    }
}

impl<'a> QueryServerWriteTransaction<'a> {
    #[instrument(level = "debug", skip_all)]
    pub fn internal_migrate_or_create_str(&mut self, e_str: &str) -> Result<(), OperationError> {
        let res = Entry::from_proto_entry_str(e_str, self)
            /*
            .and_then(|e: Entry<EntryInvalid, EntryNew>| {
                let schema = self.get_schema();
                e.validate(schema).map_err(OperationError::SchemaViolation)
            })
            */
            .and_then(|e: Entry<EntryInit, EntryNew>| self.internal_migrate_or_create(e));
        trace!(?res);
        debug_assert!(res.is_ok());
        res
    }

    pub fn internal_migrate_or_create(
        &mut self,
        e: Entry<EntryInit, EntryNew>,
    ) -> Result<(), OperationError> {
        // if the thing exists, ensure the set of attributes on
        // Entry A match and are present (but don't delete multivalue, or extended
        // attributes in the situation.
        // If not exist, create from Entry B
        //
        // This will extra classes an attributes alone!
        //
        // NOTE: gen modlist IS schema aware and will handle multivalue
        // correctly!
        trace!("internal_migrate_or_create operating on {:?}", e.get_uuid());

        let Some(filt) = e.filter_from_attrs(&[Attribute::Uuid.into()]) else {
            return Err(OperationError::FilterGeneration);
        };

        trace!("internal_migrate_or_create search {:?}", filt);

        let results = self.internal_search(filt.clone())?;

        if results.is_empty() {
            // It does not exist. Create it.
            self.internal_create(vec![e])
        } else if results.len() == 1 {
            // If the thing is subset, pass
            match e.gen_modlist_assert(&self.schema) {
                Ok(modlist) => {
                    // Apply to &results[0]
                    trace!("Generated modlist -> {:?}", modlist);
                    self.internal_modify(&filt, &modlist)
                }
                Err(e) => Err(OperationError::SchemaViolation(e)),
            }
        } else {
            admin_error!(
                "Invalid Result Set - Expected One Entry for {:?} - {:?}",
                filt,
                results
            );
            Err(OperationError::InvalidDbState)
        }
    }

    /// Migrate 8 to 9
    ///
    /// This migration updates properties of oauth2 relying server properties. First, it changes
    /// the former basic value to a secret utf8string.
    ///
    /// The second change improves the current scope system to remove the implicit scope type.
    #[instrument(level = "debug", skip_all)]
    pub fn migrate_8_to_9(&mut self) -> Result<(), OperationError> {
        admin_warn!("starting 8 to 9 migration.");
        let filt = filter_all!(f_or!([
            f_eq(Attribute::Class, EntryClass::OAuth2ResourceServer.into()),
            f_eq(
                Attribute::Class,
                EntryClass::OAuth2ResourceServerBasic.into()
            ),
        ]));

        let pre_candidates = self.internal_search(filt).map_err(|e| {
            admin_error!(err = ?e, "migrate_8_to_9 internal search failure");
            e
        })?;

        // If there is nothing, we don't need to do anything.
        if pre_candidates.is_empty() {
            admin_info!("migrate_8_to_9 no entries to migrate, complete");
            return Ok(());
        }

        // Change the value type.
        let mut candidates: Vec<Entry<EntryInvalid, EntryCommitted>> = pre_candidates
            .iter()
            .map(|er| {
                er.as_ref()
                    .clone()
                    .invalidate(self.cid.clone(), &self.trim_cid)
            })
            .collect();

        candidates.iter_mut().try_for_each(|er| {
            // Migrate basic secrets if they exist.
            let nvs = er
                .get_ava_set(Attribute::OAuth2RsBasicSecret)
                .and_then(|vs| vs.as_utf8_iter())
                .and_then(|vs_iter| {
                    ValueSetSecret::from_iter(vs_iter.map(|s: &str| s.to_string()))
                });
            if let Some(nvs) = nvs {
                er.set_ava_set(Attribute::OAuth2RsBasicSecret, nvs)
            }

            // Migrate implicit scopes if they exist.
            let nv = if let Some(vs) = er.get_ava_set(Attribute::OAuth2RsImplicitScopes) {
                vs.as_oauthscope_set()
                    .map(|v| Value::OauthScopeMap(UUID_IDM_ALL_PERSONS, v.clone()))
            } else {
                None
            };

            if let Some(nv) = nv {
                er.add_ava(Attribute::OAuth2RsScopeMap, nv)
            }
            er.purge_ava(Attribute::OAuth2RsImplicitScopes);

            Ok(())
        })?;

        // Schema check all.
        let res: Result<Vec<Entry<EntrySealed, EntryCommitted>>, SchemaError> = candidates
            .into_iter()
            .map(|e| e.validate(&self.schema).map(|e| e.seal(&self.schema)))
            .collect();

        let norm_cand: Vec<Entry<_, _>> = match res {
            Ok(v) => v,
            Err(e) => {
                admin_error!("migrate_8_to_9 schema error -> {:?}", e);
                return Err(OperationError::SchemaViolation(e));
            }
        };

        // Write them back.
        self.be_txn
            .modify(&self.cid, &pre_candidates, &norm_cand)
            .map_err(|e| {
                admin_error!("migrate_8_to_9 modification failure -> {:?}", e);
                e
            })
        // Complete
    }

    /// Migrate 9 to 10
    ///
    /// This forces a load and rewrite of all credentials stored on all accounts so that they are
    /// updated to new on-disk formats. This will allow us to purge some older on disk formats in
    /// a future version.
    ///
    /// An extended feature of this is the ability to store multiple TOTP's per entry.
    #[instrument(level = "debug", skip_all)]
    pub fn migrate_9_to_10(&mut self) -> Result<(), OperationError> {
        admin_warn!("starting 9 to 10 migration.");
        let filter = filter!(f_or!([
            f_pres(Attribute::PrimaryCredential),
            f_pres(Attribute::UnixPassword),
        ]));
        // This "does nothing" since everything has object anyway, but it forces the entry to be
        // loaded and rewritten.
        let modlist = ModifyList::new_append(Attribute::Class, EntryClass::Object.to_value());
        self.internal_modify(&filter, &modlist)
        // Complete
    }

    /// Migrate 10 to 11
    ///
    /// This forces a load of all credentials, and then examines if any are "passkey" capable. If they
    /// are, they are migrated to the passkey type, allowing us to deprecate and remove the older
    /// credential behaviour.
    ///
    #[instrument(level = "debug", skip_all)]
    pub fn migrate_10_to_11(&mut self) -> Result<(), OperationError> {
        admin_warn!("starting 9 to 10 migration.");
        let filter = filter!(f_pres(Attribute::PrimaryCredential));

        let pre_candidates = self.internal_search(filter).map_err(|e| {
            admin_error!(err = ?e, "migrate_10_to_11 internal search failure");
            e
        })?;

        // First, filter based on if any credentials present actually are the legacy
        // webauthn type.
        let modset: Vec<_> = pre_candidates
            .into_iter()
            .filter_map(|ent| {
                ent.get_ava_single_credential(Attribute::PrimaryCredential)
                    .and_then(|cred| cred.passkey_ref().ok())
                    .map(|pk_map| {
                        let modlist = pk_map
                            .iter()
                            .map(|(t, k)| {
                                Modify::Present(
                                    "passkeys".into(),
                                    Value::Passkey(Uuid::new_v4(), t.clone(), k.clone()),
                                )
                            })
                            .chain(std::iter::once(m_purge(Attribute::PrimaryCredential)))
                            .collect();
                        (ent.get_uuid(), ModifyList::new_list(modlist))
                    })
            })
            .collect();

        // If there is nothing, we don't need to do anything.
        if modset.is_empty() {
            admin_info!("migrate_10_to_11 no entries to migrate, complete");
            return Ok(());
        }

        // Apply the batch mod.
        self.internal_batch_modify(modset.into_iter())
    }

    /// Migrate 11 to 12
    ///
    /// Rewrite api-tokens from session to a dedicated api token type.
    ///
    #[instrument(level = "debug", skip_all)]
    pub fn migrate_11_to_12(&mut self) -> Result<(), OperationError> {
        admin_warn!("starting 11 to 12 migration.");
        // sync_token_session
        let filter = filter!(f_or!([
            f_pres(Attribute::ApiTokenSession),
            f_pres(Attribute::SyncTokenSession),
        ]));

        let mut mod_candidates = self.internal_search_writeable(&filter).map_err(|e| {
            admin_error!(err = ?e, "migrate_11_to_12 internal search failure");
            e
        })?;

        // If there is nothing, we don't need to do anything.
        if mod_candidates.is_empty() {
            admin_info!("migrate_11_to_12 no entries to migrate, complete");
            return Ok(());
        }

        // First, filter based on if any credentials present actually are the legacy
        // webauthn type.

        for (_, ent) in mod_candidates.iter_mut() {
            if let Some(api_token_session) = ent.pop_ava(Attribute::ApiTokenSession) {
                let api_token_session =
                    api_token_session
                        .migrate_session_to_apitoken()
                        .map_err(|e| {
                            error!(
                                "Failed to convert {} from session -> apitoken",
                                Attribute::ApiTokenSession
                            );
                            e
                        })?;

                ent.set_ava_set(Attribute::ApiTokenSession, api_token_session);
            }

            if let Some(sync_token_session) = ent.pop_ava(Attribute::SyncTokenSession) {
                let sync_token_session =
                    sync_token_session
                        .migrate_session_to_apitoken()
                        .map_err(|e| {
                            error!("Failed to convert sync_token_session from session -> apitoken");
                            e
                        })?;

                ent.set_ava_set(Attribute::SyncTokenSession, sync_token_session);
            }
        }

        // Apply the batch mod.
        self.internal_apply_writable(mod_candidates)
    }

    #[instrument(level = "debug", skip_all)]
    pub fn migrate_12_to_13(&mut self) -> Result<(), OperationError> {
        admin_warn!("starting 12 to 13 migration.");
        let filter = filter!(f_and!([
            f_eq(Attribute::Class, EntryClass::DomainInfo.into()),
            f_eq(Attribute::Uuid, PVUUID_DOMAIN_INFO.clone()),
        ]));
        // Delete the existing cookie key to trigger a regeneration.
        let modlist = ModifyList::new_purge(Attribute::PrivateCookieKey);
        self.internal_modify(&filter, &modlist)
        // Complete
    }

    #[instrument(level = "debug", skip_all)]
    pub fn migrate_13_to_14(&mut self) -> Result<(), OperationError> {
        admin_warn!("starting 13 to 14 migration.");
        let filter = filter!(f_eq(
            Attribute::Class,
            EntryClass::DynGroup.to_partialvalue()
        ));
        // Delete the incorrectly added "member" attr.
        let modlist = ModifyList::new_purge(Attribute::Member);
        self.internal_modify(&filter, &modlist)
        // Complete
    }

    #[instrument(level = "debug", skip_all)]
    pub fn migrate_14_to_15(&mut self) -> Result<(), OperationError> {
        admin_warn!("starting 14 to 15 migration.");
        let filter = filter!(f_eq(Attribute::Class, EntryClass::Person.into()));
        // Delete the non-existing attr for idv private key which triggers
        // it to regen.
        let modlist = ModifyList::new_purge(Attribute::IdVerificationEcKey);
        self.internal_modify(&filter, &modlist)
        // Complete
    }

    #[instrument(level = "debug", skip_all)]
    pub fn migrate_15_to_16(&mut self) -> Result<(), OperationError> {
        admin_warn!("starting 15 to 16 migration.");

        let sysconfig_entry = match self.internal_search_uuid(UUID_SYSTEM_CONFIG) {
            Ok(entry) => entry,
            Err(OperationError::NoMatchingEntries) => return Ok(()),
            Err(e) => return Err(e),
        };

        let mut all_account_modlist = Vec::with_capacity(3);

        all_account_modlist.push(Modify::Present(
            Attribute::Class.into(),
            EntryClass::AccountPolicy.to_value(),
        ));

        if let Some(auth_exp) = sysconfig_entry.get_ava_single_uint32(Attribute::AuthSessionExpiry)
        {
            all_account_modlist.push(Modify::Present(
                Attribute::AuthSessionExpiry.into(),
                Value::Uint32(auth_exp),
            ));
        }

        if let Some(priv_exp) = sysconfig_entry.get_ava_single_uint32(Attribute::PrivilegeExpiry) {
            all_account_modlist.push(Modify::Present(
                Attribute::PrivilegeExpiry.into(),
                Value::Uint32(priv_exp),
            ));
        }

        self.internal_batch_modify(
            [
                (
                    UUID_SYSTEM_CONFIG,
                    ModifyList::new_list(vec![
                        Modify::Purged(Attribute::AuthSessionExpiry.into()),
                        Modify::Purged(Attribute::PrivilegeExpiry.into()),
                    ]),
                ),
                (
                    UUID_IDM_ALL_ACCOUNTS,
                    ModifyList::new_list(all_account_modlist),
                ),
            ]
            .into_iter(),
        )
        // Complete
    }

    #[instrument(level = "debug", skip_all)]
    pub fn initialise_schema_core(&mut self) -> Result<(), OperationError> {
        admin_debug!("initialise_schema_core -> start ...");
        // Load in all the "core" schema, that we already have in "memory".
        let entries = self.schema.to_entries();

        // admin_debug!("Dumping schemas: {:?}", entries);

        // internal_migrate_or_create.
        let r: Result<_, _> = entries.into_iter().try_for_each(|e| {
            trace!(?e, "init schema entry");
            self.internal_migrate_or_create(e)
        });
        if r.is_ok() {
            admin_debug!("initialise_schema_core -> Ok!");
        } else {
            admin_error!(?r, "initialise_schema_core -> Error");
        }
        // why do we have error handling if it's always supposed to be `Ok`?
        debug_assert!(r.is_ok());
        r
    }

    #[instrument(level = "debug", skip_all)]
    pub fn initialise_schema_idm(&mut self) -> Result<(), OperationError> {
        admin_debug!("initialise_schema_idm -> start ...");

        let idm_schema_attrs = [
            SCHEMA_ATTR_SYNC_CREDENTIAL_PORTAL.clone().into(),
            SCHEMA_ATTR_SYNC_YIELD_AUTHORITY.clone().into(),
        ];

        let r: Result<(), _> = idm_schema_attrs
            .into_iter()
            .try_for_each(|entry| self.internal_migrate_or_create(entry));

        if r.is_err() {
            error!(res = ?r, "initialise_schema_idm -> Error");
        }
        debug_assert!(r.is_ok());

        // List of IDM schemas to init.
        let idm_schema: Vec<EntryInitNew> = vec![
            SCHEMA_ATTR_MAIL.clone().into(),
            SCHEMA_ATTR_ACCOUNT_EXPIRE.clone().into(),
            SCHEMA_ATTR_ACCOUNT_VALID_FROM.clone().into(),
            SCHEMA_ATTR_API_TOKEN_SESSION.clone().into(),
            SCHEMA_ATTR_AUTH_SESSION_EXPIRY.clone().into(),
            SCHEMA_ATTR_AUTH_PRIVILEGE_EXPIRY.clone().into(),
            SCHEMA_ATTR_BADLIST_PASSWORD.clone().into(),
            SCHEMA_ATTR_CREDENTIAL_UPDATE_INTENT_TOKEN.clone().into(),
            SCHEMA_ATTR_DEVICEKEYS.clone().into(),
            SCHEMA_ATTR_DISPLAYNAME.clone().into(),
            SCHEMA_ATTR_DOMAIN_DISPLAY_NAME.clone().into(),
            SCHEMA_ATTR_DOMAIN_LDAP_BASEDN.clone().into(),
            SCHEMA_ATTR_DOMAIN_NAME.clone().into(),
            SCHEMA_ATTR_LDAP_ALLOW_UNIX_PW_BIND.clone().into(),
            SCHEMA_ATTR_DOMAIN_SSID.clone().into(),
            SCHEMA_ATTR_DOMAIN_TOKEN_KEY.clone().into(),
            SCHEMA_ATTR_DOMAIN_UUID.clone().into(),
            SCHEMA_ATTR_DYNGROUP_FILTER.clone().into(),
            SCHEMA_ATTR_EC_KEY_PRIVATE.clone().into(),
            SCHEMA_ATTR_ES256_PRIVATE_KEY_DER.clone().into(),
            SCHEMA_ATTR_FERNET_PRIVATE_KEY_STR.clone().into(),
            SCHEMA_ATTR_GIDNUMBER.clone().into(),
            SCHEMA_ATTR_GRANT_UI_HINT.clone().into(),
            SCHEMA_ATTR_JWS_ES256_PRIVATE_KEY.clone().into(),
            SCHEMA_ATTR_LEGALNAME.clone().into(),
            SCHEMA_ATTR_LOGINSHELL.clone().into(),
            SCHEMA_ATTR_NAME_HISTORY.clone().into(),
            SCHEMA_ATTR_NSUNIQUEID.clone().into(),
            SCHEMA_ATTR_OAUTH2_ALLOW_INSECURE_CLIENT_DISABLE_PKCE
                .clone()
                .into(),
            SCHEMA_ATTR_OAUTH2_CONSENT_SCOPE_MAP.clone().into(),
            SCHEMA_ATTR_OAUTH2_JWT_LEGACY_CRYPTO_ENABLE.clone().into(),
            SCHEMA_ATTR_OAUTH2_PREFER_SHORT_USERNAME.clone().into(),
            SCHEMA_ATTR_OAUTH2_RS_BASIC_SECRET.clone().into(),
            SCHEMA_ATTR_OAUTH2_RS_IMPLICIT_SCOPES.clone().into(),
            SCHEMA_ATTR_OAUTH2_RS_NAME.clone().into(),
            SCHEMA_ATTR_OAUTH2_RS_ORIGIN_LANDING.clone().into(),
            SCHEMA_ATTR_OAUTH2_RS_ORIGIN.clone().into(),
            SCHEMA_ATTR_OAUTH2_RS_SCOPE_MAP.clone().into(),
            SCHEMA_ATTR_OAUTH2_RS_SUP_SCOPE_MAP.clone().into(),
            SCHEMA_ATTR_OAUTH2_RS_TOKEN_KEY.clone().into(),
            SCHEMA_ATTR_OAUTH2_SESSION.clone().into(),
            SCHEMA_ATTR_PASSKEYS.clone().into(),
            SCHEMA_ATTR_PRIMARY_CREDENTIAL.clone().into(),
            SCHEMA_ATTR_PRIVATE_COOKIE_KEY.clone().into(),
            SCHEMA_ATTR_RADIUS_SECRET.clone().into(),
            SCHEMA_ATTR_RS256_PRIVATE_KEY_DER.clone().into(),
            SCHEMA_ATTR_SSH_PUBLICKEY.clone().into(),
            SCHEMA_ATTR_SYNC_COOKIE.clone().into(),
            SCHEMA_ATTR_SYNC_TOKEN_SESSION.clone().into(),
            SCHEMA_ATTR_UNIX_PASSWORD.clone().into(),
            SCHEMA_ATTR_USER_AUTH_TOKEN_SESSION.clone().into(),
            SCHEMA_ATTR_DENIED_NAME.clone().into(),
        ];

        let r = idm_schema
            .into_iter()
            // Each item individually logs it's result
            .try_for_each(|entry| self.internal_migrate_or_create(entry));

        if r.is_err() {
            error!(res = ?r, "initialise_schema_idm -> Error");
        }

        debug_assert!(r.is_ok());

        let idm_schema_classes: Vec<EntryInitNew> = vec![
            SCHEMA_CLASS_ACCOUNT.clone().into(),
            SCHEMA_CLASS_ACCOUNT_POLICY.clone().into(),
            SCHEMA_CLASS_DOMAIN_INFO.clone().into(),
            SCHEMA_CLASS_DYNGROUP.clone().into(),
            SCHEMA_CLASS_GROUP.clone().into(),
            SCHEMA_CLASS_OAUTH2_RS.clone().into(),
            SCHEMA_CLASS_ORGPERSON.clone().into(),
            SCHEMA_CLASS_PERSON.clone().into(),
            SCHEMA_CLASS_POSIXACCOUNT.clone().into(),
            SCHEMA_CLASS_POSIXGROUP.clone().into(),
            SCHEMA_CLASS_SERVICE_ACCOUNT.clone().into(),
            SCHEMA_CLASS_SYNC_ACCOUNT.clone().into(),
            SCHEMA_CLASS_SYSTEM_CONFIG.clone().into(),
            SCHEMA_CLASS_OAUTH2_RS_BASIC.clone().into(),
            SCHEMA_CLASS_OAUTH2_RS_PUBLIC.clone().into(),
        ];

        let r: Result<(), _> = idm_schema_classes
            .into_iter()
            .try_for_each(|entry| self.internal_migrate_or_create(entry));

        if r.is_err() {
            error!(res = ?r, "initialise_schema_idm -> Error");
        }
        debug_assert!(r.is_ok());

        debug!("initialise_schema_idm -> Ok!");

        r
    }

    // This function is idempotent
    #[instrument(level = "debug", skip_all)]
    pub fn initialise_idm(&mut self) -> Result<(), OperationError> {
        // First, check the system_info object. This stores some server information
        // and details. It's a pretty const thing. Also check anonymous, important to many
        // concepts.
        let res = self
            .internal_migrate_or_create(E_SYSTEM_INFO_V1.clone())
            .and_then(|_| self.internal_migrate_or_create(E_DOMAIN_INFO_V1.clone()))
            .and_then(|_| self.internal_migrate_or_create(E_SYSTEM_CONFIG_V1.clone()));
        if res.is_err() {
            admin_error!("initialise_idm p1 -> result {:?}", res);
        }
        debug_assert!(res.is_ok());
        res?;

        // The domain info now exists, we should be able to do these migrations as they will
        // cause SPN regenerations to occur

        // Check the admin object exists (migrations).
        // Create the default idm_admin group.
        let admin_entries: Vec<EntryInitNew> = idm_builtin_admin_entries()?;
        let res: Result<(), _> = admin_entries
            .into_iter()
            // Each item individually logs it's result
            .try_for_each(|ent| self.internal_migrate_or_create(ent));
        if res.is_err() {
            admin_error!("initialise_idm p2 -> result {:?}", res);
        }
        debug_assert!(res.is_ok());
        res?;

        let idm_entries = idm_builtin_non_admin_groups();

        let res: Result<(), _> = idm_entries
            .into_iter()
            .try_for_each(|e| self.internal_migrate_or_create(e.clone().try_into()?));
        if res.is_ok() {
            admin_debug!("initialise_idm -> result Ok!");
        } else {
            admin_error!(?res, "initialise_idm p3 -> result");
        }
        debug_assert!(res.is_ok());
        res?;

        let idm_entries: Vec<BuiltinAcp> = vec![
            // Built in access controls.
            IDM_ADMINS_ACP_RECYCLE_SEARCH_V1.clone(),
            IDM_ADMINS_ACP_REVIVE_V1.clone(),
            IDM_ALL_ACP_READ_V1.clone(),
            IDM_SELF_ACP_READ_V1.clone(),
            IDM_SELF_ACP_WRITE_V1.clone(),
            E_IDM_PEOPLE_SELF_ACP_WRITE_MAIL_PRIV_V1.clone(),
            IDM_ACP_PEOPLE_READ_PRIV_V1.clone(),
            IDM_ACP_PEOPLE_WRITE_PRIV_V1.clone(),
            IDM_ACP_PEOPLE_MANAGE_PRIV_V1.clone(),
            IDM_ACP_ACCOUNT_READ_PRIV_V1.clone(),
            IDM_ACP_ACCOUNT_WRITE_PRIV_V1.clone(),
            IDM_ACP_ACCOUNT_MANAGE_PRIV_V1.clone(),
            IDM_ACP_HP_ACCOUNT_READ_PRIV_V1.clone(),
            IDM_ACP_HP_ACCOUNT_WRITE_PRIV_V1.clone(),
            IDM_ACP_HP_ACCOUNT_MANAGE_PRIV_V1.clone(),
            IDM_ACP_GROUP_WRITE_PRIV_V1.clone(),
            IDM_ACP_GROUP_MANAGE_PRIV_V1.clone(),
            IDM_ACP_HP_GROUP_WRITE_PRIV_V1.clone(),
            IDM_ACP_HP_GROUP_MANAGE_PRIV_V1.clone(),
            IDM_ACP_SCHEMA_WRITE_ATTRS_PRIV_V1.clone(),
            IDM_ACP_SCHEMA_WRITE_CLASSES_PRIV_V1.clone(),
            IDM_ACP_ACP_MANAGE_PRIV_V1.clone(),
            IDM_ACP_RADIUS_SERVERS_V1.clone(),
            IDM_ACP_DOMAIN_ADMIN_PRIV_V1.clone(),
            IDM_ACP_SYSTEM_CONFIG_PRIV_V1.clone(),
            IDM_ACP_SYSTEM_CONFIG_SESSION_EXP_PRIV_V1.clone(),
            IDM_ACP_PEOPLE_ACCOUNT_PASSWORD_IMPORT_PRIV_V1.clone(),
            IDM_ACP_PEOPLE_EXTEND_PRIV_V1.clone(),
            IDM_ACP_HP_PEOPLE_READ_PRIV_V1.clone(),
            IDM_ACP_HP_PEOPLE_WRITE_PRIV_V1.clone(),
            IDM_ACP_HP_PEOPLE_EXTEND_PRIV_V1.clone(),
            IDM_ACP_ACCOUNT_UNIX_EXTEND_PRIV_V1.clone(),
            E_IDM_HP_ACP_ACCOUNT_UNIX_EXTEND_PRIV_V1.clone(),
            IDM_ACP_GROUP_UNIX_EXTEND_PRIV_V1.clone(),
            E_IDM_HP_ACP_GROUP_UNIX_EXTEND_PRIV_V1.clone(),
            E_IDM_HP_ACP_OAUTH2_MANAGE_PRIV_V1.clone(),
            IDM_ACP_RADIUS_SECRET_READ_PRIV_V1.clone(),
            IDM_ACP_RADIUS_SECRET_WRITE_PRIV_V1.clone(),
            E_IDM_HP_ACP_SERVICE_ACCOUNT_INTO_PERSON_MIGRATE_V1.clone(),
            E_IDM_HP_ACP_SYNC_ACCOUNT_MANAGE_PRIV_V1.clone(),
            IDM_ACP_ACCOUNT_MAIL_READ_PRIV_V1.clone(),
            IDM_ACCOUNT_SELF_ACP_WRITE_V1.clone(),
            IDM_ACP_GROUP_ACCOUNT_POLICY_MANAGE_PRIV_V1.clone(),
        ];

        let res: Result<(), _> = idm_entries
            .into_iter()
            .try_for_each(|entry| self.internal_migrate_or_create(entry.into()));
        if res.is_ok() {
            admin_debug!("initialise_idm -> result Ok!");
        } else {
            admin_error!(?res, "initialise_idm p3 -> result");
        }
        debug_assert!(res.is_ok());
        res?;

        // Delete entries that no longer need to exist.
        let delete_entries = [UUID_IDM_ACP_OAUTH2_READ_PRIV_V1];

        let res: Result<(), _> = delete_entries
            .into_iter()
            .try_for_each(|entry_uuid| self.internal_delete_uuid_if_exists(entry_uuid));
        if res.is_ok() {
            admin_debug!("initialise_idm -> result Ok!");
        } else {
            admin_error!(?res, "initialise_idm p3 -> result");
        }
        debug_assert!(res.is_ok());
        res?;

        // Some attributes we don't want to stomp if they already exist. So we conditionally
        // modify them.

        self.changed_schema = true;
        self.changed_acp = true;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::prelude::*;

    #[qs_test]
    async fn test_init_idempotent_schema_core(server: &QueryServer) {
        {
            // Setup and abort.
            let mut server_txn = server.write(duration_from_epoch_now()).await;
            assert!(server_txn.initialise_schema_core().is_ok());
        }
        {
            let mut server_txn = server.write(duration_from_epoch_now()).await;
            assert!(server_txn.initialise_schema_core().is_ok());
            assert!(server_txn.initialise_schema_core().is_ok());
            assert!(server_txn.commit().is_ok());
        }
        {
            // Now do it again in a new txn, but abort
            let mut server_txn = server.write(duration_from_epoch_now()).await;
            assert!(server_txn.initialise_schema_core().is_ok());
        }
        {
            // Now do it again in a new txn.
            let mut server_txn = server.write(duration_from_epoch_now()).await;
            assert!(server_txn.initialise_schema_core().is_ok());
            assert!(server_txn.commit().is_ok());
        }
    }

    /*
    #[qs_test_no_init]
    async fn test_qs_upgrade_entry_attrs(server: &QueryServer) {
        let mut server_txn = server.write(duration_from_epoch_now()).await;
        assert!(server_txn.upgrade_reindex(SYSTEM_INDEX_VERSION).is_ok());
        assert!(server_txn.commit().is_ok());

        let mut server_txn = server.write(duration_from_epoch_now()).await;
        server_txn.initialise_schema_core().unwrap();
        server_txn.initialise_schema_idm().unwrap();
        assert!(server_txn.commit().is_ok());

        let mut server_txn = server.write(duration_from_epoch_now()).await;
        assert!(server_txn.upgrade_reindex(SYSTEM_INDEX_VERSION + 1).is_ok());
        assert!(server_txn.commit().is_ok());

        let mut server_txn = server.write(duration_from_epoch_now()).await;
        assert!(server_txn
            .internal_migrate_or_create_str(JSON_SYSTEM_INFO_V1)
            .is_ok());
        assert!(server_txn
            .internal_migrate_or_create_str(JSON_DOMAIN_INFO_V1)
            .is_ok());
        assert!(server_txn
            .internal_migrate_or_create_str(JSON_SYSTEM_CONFIG_V1)
            .is_ok());
        assert!(server_txn.commit().is_ok());

        let mut server_txn = server.write(duration_from_epoch_now()).await;
        // ++ Mod the schema to set name to the old string type
        let me_syn = unsafe {
            ModifyEvent::new_internal_invalid(
                filter!(f_or!([
                    f_eq(Attribute::AttributeName, Attribute::Name.to_partialvalue()),
                    f_eq(Attribute::AttributeName, Attribute::DomainName.into()),
                ])),
                ModifyList::new_purge_and_set(
                    "syntax",
                    Value::new_syntaxs("UTF8STRING_INSENSITIVE").unwrap(),
                ),
            )
        };
        assert!(server_txn.modify(&me_syn).is_ok());
        assert!(server_txn.commit().is_ok());

        let mut server_txn = server.write(duration_from_epoch_now()).await;
        // ++ Mod domain name and name to be the old type.
        let me_dn = unsafe {
            ModifyEvent::new_internal_invalid(
                filter!(f_eq(Attribute::Uuid, PartialValue::Uuid(UUID_DOMAIN_INFO))),
                ModifyList::new_list(vec![
                    Modify::Purged(Attribute::Name.into()),
                    Modify::Purged(Attribute::DomainName.into()),
                    Modify::Present(Attribute::Name.into(), Value::new_iutf8("domain_local")),
                    Modify::Present(
                        Attribute::DomainName.into(),
                        Value::new_iutf8("example.com"),
                    ),
                ]),
            )
        };
        assert!(server_txn.modify(&me_dn).is_ok());

        // Now, both the types are invalid.

        // WARNING! We can't commit here because this triggers domain_reload which will fail
        // due to incorrect syntax of the domain name! Run the migration in the same txn!
        // Trigger a schema reload.
        assert!(server_txn.reload_schema().is_ok());

        // We can't just re-run the migrate here because name takes it's definition from
        // in memory, and we can't re-run the initial memory gen. So we just fix it to match
        // what the migrate "would do".
        let me_syn = unsafe {
            ModifyEvent::new_internal_invalid(
                filter!(f_or!([
                    f_eq(Attribute::AttributeName, Attribute::Name.to_partialvalue()),
                    f_eq(Attribute::AttributeName, Attribute::DomainName.into()),
                ])),
                ModifyList::new_purge_and_set(
                    "syntax",
                    Value::new_syntaxs("UTF8STRING_INAME").unwrap(),
                ),
            )
        };
        assert!(server_txn.modify(&me_syn).is_ok());

        // WARNING! We can't commit here because this triggers domain_reload which will fail
        // due to incorrect syntax of the domain name! Run the migration in the same txn!
        // Trigger a schema reload.
        assert!(server_txn.reload_schema().is_ok());

        // ++ Run the upgrade for X to Y
        assert!(server_txn.migrate_2_to_3().is_ok());

        assert!(server_txn.commit().is_ok());

        // Assert that it migrated and worked as expected.
        let mut server_txn = server.write(duration_from_epoch_now()).await;
        let domain = server_txn
            .internal_search_uuid(UUID_DOMAIN_INFO)
            .expect("failed");
        // ++ assert all names are iname
        assert!(
            domain.get_ava_set(Attribute::Name).expect("no name?").syntax() == SyntaxType::Utf8StringIname
        );
        // ++ assert all domain/domain_name are iname
        assert!(
            domain
                .get_ava_set(Attribute::DomainName.as_ref())
                .expect("no domain_name?")
                .syntax()
                == SyntaxType::Utf8StringIname
        );
        assert!(server_txn.commit().is_ok());
    }
    */
}
