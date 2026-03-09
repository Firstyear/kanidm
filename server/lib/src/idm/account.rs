use super::accountpolicy::ResolvedAccountPolicy;
use super::group::{load_account_policy, load_all_groups_from_account, Group, Unix};
use crate::constants::UUID_ANONYMOUS;
use crate::credential::softlock::CredSoftLockPolicy;
use crate::credential::{apppwd::ApplicationPassword, Credential};
use crate::entry::{Entry, EntryCommitted, EntryReduced, EntrySealed};
use crate::event::SearchEvent;
use crate::idm::application::Application;
use crate::idm::ldap::{LdapBoundToken, LdapSession};
use crate::idm::server::{IdmServerProxyReadTransaction, IdmServerProxyWriteTransaction};
use crate::modify::{ModifyInvalid, ModifyList};
use crate::prelude::*;
use crate::schema::SchemaTransaction;
use crate::value::{IntentTokenState, PartialValue, SessionState, Value};
use kanidm_lib_crypto::CryptoPolicy;
use kanidm_proto::internal::{CredentialStatus, UatPurpose, UiHint, UserAuthToken};
use kanidm_proto::v1::{UatStatus, UatStatusState, UnixGroupToken, UnixUserToken};
use sshkey_attest::proto::PublicKey as SshPublicKey;
use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;
use time::OffsetDateTime;
use uuid::Uuid;
use webauthn_rs::prelude::{
    AttestedPasskey as AttestedPasskeyV4, AuthenticationResult, CredentialID, Passkey as PasskeyV4,
};

#[derive(Debug, Clone)]
pub struct UnixExtensions {
    ucred: Option<Credential>,
    shell: Option<String>,
    gidnumber: u32,
    groups: Vec<Group<Unix>>,
}

impl UnixExtensions {
    pub(crate) fn ucred(&self) -> Option<&Credential> {
        self.ucred.as_ref()
    }
}

#[derive(Default, Debug, Clone)]
pub struct OAuth2AccountCredential {
    pub(crate) provider: Uuid,
    pub(crate) cred_id: Uuid,
    pub(crate) user_id: String,
}

#[derive(Default, Debug, Clone)]
pub struct Account {
    // To make this self-referential, we'll need to likely make Entry Pin<Arc<_>>
    // so that we can make the references work.
    spn: String,
    name: Option<String>,
    pub displayname: String,
    pub uuid: Uuid,
    pub sync_parent_uuid: Option<Uuid>,
    pub groups: Vec<Group<()>>,
    pub primary: Option<Credential>,
    pub passkeys: BTreeMap<Uuid, (String, PasskeyV4)>,
    pub attested_passkeys: BTreeMap<Uuid, (String, AttestedPasskeyV4)>,
    pub valid_from: Option<OffsetDateTime>,
    pub expire: Option<OffsetDateTime>,
    softlock_expire: Option<OffsetDateTime>,
    pub radius_secret: Option<String>,
    pub ui_hints: BTreeSet<UiHint>,
    pub mail_primary: Option<String>,
    pub mail: Vec<String>,
    pub credential_update_intent_tokens: BTreeMap<String, IntentTokenState>,
    pub(crate) unix_extn: Option<UnixExtensions>,
    pub(crate) sshkeys: BTreeMap<String, SshPublicKey>,
    pub apps_pwds: BTreeMap<Uuid, Vec<ApplicationPassword>>,
    pub(crate) oauth2_client_provider: Option<OAuth2AccountCredential>,
    pub updated_at: Option<Cid>,
}

#[cfg(test)]
impl From<crate::migration_data::BuiltinAccount> for crate::idm::account::Account {
    fn from(value: crate::migration_data::BuiltinAccount) -> Self {
        Self {
            name: Some(value.name.to_string()),
            uuid: value.uuid,
            displayname: value.displayname.to_string(),
            spn: format!("{}@example.com", value.name),
            mail_primary: None,
            mail: Vec::with_capacity(0),
            ..Default::default()
        }
    }
}

macro_rules! try_from_entry {
    ($value:expr, $groups:expr, $unix_groups:expr) => {{
        // Check the classes
        if !$value.attribute_equality(Attribute::Class, &EntryClass::Account.to_partialvalue()) {
            return Err(OperationError::MissingClass(ENTRYCLASS_ACCOUNT.into()));
        }

        // Now extract our needed attributes
        let name = $value
            .get_ava_single_iname(Attribute::Name)
            .map(|s| s.to_string());

        let displayname = $value
            .get_ava_single_utf8(Attribute::DisplayName)
            .map(|s| s.to_string())
            .ok_or(OperationError::MissingAttribute(Attribute::DisplayName))?;

        let sync_parent_uuid = $value.get_ava_single_refer(Attribute::SyncParentUuid);

        let primary = $value
            .get_ava_single_credential(Attribute::PrimaryCredential)
            .cloned();

        let passkeys = $value
            .get_ava_passkeys(Attribute::PassKeys)
            .cloned()
            .unwrap_or_default();

        let attested_passkeys = $value
            .get_ava_attestedpasskeys(Attribute::AttestedPasskeys)
            .cloned()
            .unwrap_or_default();

        let spn = $value
            .get_ava_single_proto_string(Attribute::Spn)
            .ok_or(OperationError::MissingAttribute(Attribute::Spn))?;

        let mail_primary = $value
            .get_ava_mail_primary(Attribute::Mail)
            .map(str::to_string);

        let mail = $value
            .get_ava_iter_mail(Attribute::Mail)
            .map(|i| i.map(str::to_string).collect())
            .unwrap_or_default();

        let valid_from = $value.get_ava_single_datetime(Attribute::AccountValidFrom);

        let expire = $value.get_ava_single_datetime(Attribute::AccountExpire);

        let softlock_expire = $value.get_ava_single_datetime(Attribute::AccountSoftlockExpire);

        let radius_secret = $value
            .get_ava_single_secret(Attribute::RadiusSecret)
            .map(str::to_string);

        // Resolved by the caller
        let groups = $groups;

        let uuid = $value.get_uuid().clone();

        let credential_update_intent_tokens = $value
            .get_ava_as_intenttokens(Attribute::CredentialUpdateIntentToken)
            .cloned()
            .unwrap_or_default();

        // Provide hints from groups.
        let mut ui_hints: BTreeSet<_> = groups
            .iter()
            .map(|group: &Group<()>| group.ui_hints().iter())
            .flatten()
            .copied()
            .collect();

        // For now disable cred updates on sync accounts too.
        if $value.attribute_equality(Attribute::Class, &EntryClass::Person.to_partialvalue()) {
            ui_hints.insert(UiHint::CredentialUpdate);
        }

        if $value.attribute_equality(Attribute::Class, &EntryClass::SyncObject.to_partialvalue()) {
            ui_hints.insert(UiHint::SynchronisedAccount);
        }

        let sshkeys = $value
            .get_ava_set(Attribute::SshPublicKey)
            .and_then(|vs| vs.as_sshkey_map())
            .cloned()
            .unwrap_or_default();

        let unix_extn = if $value.attribute_equality(
            Attribute::Class,
            &EntryClass::PosixAccount.to_partialvalue(),
        ) {
            ui_hints.insert(UiHint::PosixAccount);

            let ucred = $value
                .get_ava_single_credential(Attribute::UnixPassword)
                .cloned();

            let shell = $value
                .get_ava_single_iutf8(Attribute::LoginShell)
                .map(|s| s.to_string());

            let gidnumber = $value
                .get_ava_single_uint32(Attribute::GidNumber)
                .ok_or_else(|| OperationError::MissingAttribute(Attribute::GidNumber))?;

            let groups = $unix_groups;

            Some(UnixExtensions {
                ucred,
                shell,
                gidnumber,
                groups,
            })
        } else {
            None
        };

        let apps_pwds = $value
            .get_ava_application_password(Attribute::ApplicationPassword)
            .cloned()
            .unwrap_or_default();

        let maybe_account_provider = $value.get_ava_single_refer(Attribute::OAuth2AccountProvider);

        let maybe_account_unique_user_id =
            $value.get_ava_single_utf8(Attribute::OAuth2AccountUniqueUserId);

        let maybe_account_credential_id =
            $value.get_ava_single_uuid(Attribute::OAuth2AccountCredentialUuid);

        let oauth2_client_provider = match (
            maybe_account_provider,
            maybe_account_unique_user_id,
            maybe_account_credential_id,
        ) {
            (Some(provider), Some(user_id), Some(cred_id)) => Some(OAuth2AccountCredential {
                provider,
                cred_id,
                user_id: user_id.to_string(),
            }),
            _ => None,
        };

        let updated_at: Option<Cid> = $value
            .get_ava_set(Attribute::LastModifiedCid)
            .cloned()
            .and_then(|u| u.to_cid_single());

        Ok(Account {
            uuid,
            name,
            sync_parent_uuid,
            displayname,
            groups,
            primary,
            passkeys,
            attested_passkeys,
            valid_from,
            expire,
            softlock_expire,
            radius_secret,
            spn,
            ui_hints,
            mail_primary,
            mail,
            credential_update_intent_tokens,
            unix_extn,
            sshkeys,
            apps_pwds,
            oauth2_client_provider,
            updated_at,
        })
    }};
}

impl Account {
    pub(crate) fn unix_extn(&self) -> Option<&UnixExtensions> {
        self.unix_extn.as_ref()
    }

    pub(crate) fn primary(&self) -> Option<&Credential> {
        self.primary.as_ref()
    }

    pub(crate) fn sshkeys(&self) -> &BTreeMap<String, SshPublicKey> {
        &self.sshkeys
    }

    pub(crate) fn spn(&self) -> &str {
        self.spn.as_str()
    }

    pub(crate) fn name(&self) -> &str {
        self.name.as_deref().unwrap_or(self.spn.as_str())
    }

    pub(crate) fn display_name(&self) -> &str {
        &self.displayname
    }

    pub(crate) fn mail_primary(&self) -> Option<&str> {
        self.mail_primary.as_deref()
    }

    pub(crate) fn mail(&self) -> &[String] {
        self.mail.as_slice()
    }

    pub(crate) fn softlock_expire(&self) -> Option<OffsetDateTime> {
        self.softlock_expire
    }

    #[instrument(level = "trace", skip_all)]
    pub(crate) fn try_from_entry_ro(
        value: &Entry<EntrySealed, EntryCommitted>,
        qs: &mut QueryServerReadTransaction,
    ) -> Result<Self, OperationError> {
        let (groups, unix_groups) = load_all_groups_from_account(value, qs)?;

        try_from_entry!(value, groups, unix_groups)
    }

    #[instrument(level = "trace", skip_all)]
    pub(crate) fn try_from_entry_with_policy<'a, TXN>(
        value: &Entry<EntrySealed, EntryCommitted>,
        qs: &mut TXN,
    ) -> Result<(Self, ResolvedAccountPolicy), OperationError>
    where
        TXN: QueryServerTransaction<'a>,
    {
        let (groups, unix_groups) = load_all_groups_from_account(value, qs)?;
        let rap = load_account_policy(value, qs)?;

        try_from_entry!(value, groups, unix_groups).map(|acct| (acct, rap))
    }

    #[instrument(level = "trace", skip_all)]
    pub(crate) fn try_from_entry_rw(
        value: &Entry<EntrySealed, EntryCommitted>,
        qs: &mut QueryServerWriteTransaction,
    ) -> Result<Self, OperationError> {
        let (groups, unix_groups) = load_all_groups_from_account(value, qs)?;

        try_from_entry!(value, groups, unix_groups)
    }

    #[instrument(level = "trace", skip_all)]
    pub(crate) fn try_from_entry_reduced(
        value: &Entry<EntryReduced, EntryCommitted>,
        qs: &mut QueryServerReadTransaction,
    ) -> Result<Self, OperationError> {
        let (groups, unix_groups) = load_all_groups_from_account(value, qs)?;
        try_from_entry!(value, groups, unix_groups)
    }

    /// Given the session_id and other metadata, create a user authentication token
    /// that represents a users session. Since this metadata can vary from session
    /// to session, this userauthtoken may contain some data (claims) that may yield
    /// different privileges to the bearer.
    pub(crate) fn to_userauthtoken(
        &self,
        session_id: Uuid,
        scope: SessionScope,
        ct: Duration,
        account_policy: &ResolvedAccountPolicy,
    ) -> Option<UserAuthToken> {
        // We have to remove the nanoseconds because when we transmit this / serialise it we drop
        // the nanoseconds, but if we haven't done a serialise on the server our db cache has the
        // ns value which breaks some checks.
        let ct = ct - Duration::from_nanos(ct.subsec_nanos() as u64);
        let issued_at = OffsetDateTime::UNIX_EPOCH + ct;

        let limit_search_max_results = account_policy.limit_search_max_results();
        let limit_search_max_filter_test = account_policy.limit_search_max_filter_test();

        // Note that currently the auth_session time comes from policy, but the already-privileged
        // session bound is hardcoded. This mostly affects admin/idm_admin breakglass accounts.
        let expiry = OffsetDateTime::UNIX_EPOCH
            + ct
            + Duration::from_secs(account_policy.authsession_expiry() as u64);
        let limited_expiry = OffsetDateTime::UNIX_EPOCH
            + ct
            + Duration::from_secs(DEFAULT_AUTH_SESSION_LIMITED_EXPIRY as u64);

        let (purpose, expiry) = match scope {
            // Issue an invalid/expired session.
            SessionScope::Synchronise => {
                warn!(
                    "Should be impossible to issue sync sessions with a uat. Refusing to proceed."
                );
                return None;
            }
            SessionScope::ReadOnly => (UatPurpose::ReadOnly, expiry),
            SessionScope::ReadWrite => {
                // These sessions are always rw, and so have limited life.
                // Ensure that we take the lower of the two bounds.
                let capped = std::cmp::min(expiry, limited_expiry);

                (
                    UatPurpose::ReadWrite {
                        expiry: Some(capped),
                    },
                    capped,
                )
            }
            SessionScope::PrivilegeCapable => (UatPurpose::ReadWrite { expiry: None }, expiry),
        };

        Some(UserAuthToken {
            session_id,
            expiry: Some(expiry),
            issued_at,
            purpose,
            uuid: self.uuid,
            displayname: self.displayname.clone(),
            spn: self.spn.clone(),
            mail_primary: self.mail_primary.clone(),
            ui_hints: self.ui_hints.clone(),
            // application: None,
            // groups: self.groups.iter().map(|g| g.to_proto()).collect(),
            limit_search_max_results,
            limit_search_max_filter_test,
        })
    }

    /// Given the session_id and other metadata, reissue a user authentication token
    /// that has elevated privileges. In the future we may adapt this to change what
    /// scopes are granted per-reauth.
    pub(crate) fn to_reissue_userauthtoken(
        &self,
        session_id: Uuid,
        session_expiry: Option<OffsetDateTime>,
        scope: SessionScope,
        ct: Duration,
        account_policy: &ResolvedAccountPolicy,
    ) -> Option<UserAuthToken> {
        let issued_at = OffsetDateTime::UNIX_EPOCH + ct;

        let limit_search_max_results = account_policy.limit_search_max_results();
        let limit_search_max_filter_test = account_policy.limit_search_max_filter_test();

        let (purpose, expiry) = match scope {
            SessionScope::Synchronise | SessionScope::ReadOnly | SessionScope::ReadWrite => {
                warn!(
                    "Impossible state, should not be re-issuing for session scope {:?}",
                    scope
                );
                return None;
            }
            SessionScope::PrivilegeCapable =>
            // Return a ReadWrite session with an inner expiry for the privileges
            {
                let expiry = Some(
                    OffsetDateTime::UNIX_EPOCH
                        + ct
                        + Duration::from_secs(account_policy.privilege_expiry().into()),
                );
                (
                    UatPurpose::ReadWrite { expiry },
                    // Needs to come from the actual original session. If we don't do this we have
                    // to re-update the expiry in the DB. We don't want a re-auth to extend a time
                    // bound session.
                    session_expiry,
                )
            }
        };

        Some(UserAuthToken {
            session_id,
            expiry,
            issued_at,
            purpose,
            uuid: self.uuid,
            displayname: self.displayname.clone(),
            spn: self.spn.clone(),
            mail_primary: self.mail_primary.clone(),
            ui_hints: self.ui_hints.clone(),
            // application: None,
            // groups: self.groups.iter().map(|g| g.to_proto()).collect(),
            limit_search_max_results,
            limit_search_max_filter_test,
        })
    }

    /// Given the currently bound client certificate, yield a user auth token that
    /// represents the current session for the account.
    pub(crate) fn client_cert_info_to_userauthtoken(
        &self,
        certificate_id: Uuid,
        session_is_rw: bool,
        ct: Duration,
        account_policy: &ResolvedAccountPolicy,
    ) -> Option<UserAuthToken> {
        let issued_at = OffsetDateTime::UNIX_EPOCH + ct;

        let limit_search_max_results = account_policy.limit_search_max_results();
        let limit_search_max_filter_test = account_policy.limit_search_max_filter_test();

        let purpose = if session_is_rw {
            UatPurpose::ReadWrite { expiry: None }
        } else {
            UatPurpose::ReadOnly
        };

        Some(UserAuthToken {
            session_id: certificate_id,
            expiry: None,
            issued_at,
            purpose,
            uuid: self.uuid,
            displayname: self.displayname.clone(),
            spn: self.spn.clone(),
            mail_primary: self.mail_primary.clone(),
            ui_hints: self.ui_hints.clone(),
            // application: None,
            // groups: self.groups.iter().map(|g| g.to_proto()).collect(),
            limit_search_max_results,
            limit_search_max_filter_test,
        })
    }

    /// Determine if an entry is within it's validity period using it's `valid_from` and
    /// `expire` attributes. `true` indicates the account is within the valid period.
    pub fn check_within_valid_time(
        ct: Duration,
        valid_from: Option<&OffsetDateTime>,
        expire: Option<&OffsetDateTime>,
    ) -> bool {
        let cot = OffsetDateTime::UNIX_EPOCH + ct;
        trace!("Checking within valid time: {:?} {:?}", valid_from, expire);

        let vmin = if let Some(vft) = valid_from {
            // If current time greater than start time window
            vft <= &cot
        } else {
            // We have no time, not expired.
            true
        };
        let vmax = if let Some(ext) = expire {
            // If exp greater than ct then expired.
            &cot <= ext
        } else {
            // If not present, we are not expired
            true
        };
        // Mix the results
        vmin && vmax
    }

    /// Determine if this account is within it's validity period. `true` indicates the
    /// account is within the valid period.
    pub fn is_within_valid_time(&self, ct: Duration) -> bool {
        Self::check_within_valid_time(ct, self.valid_from.as_ref(), self.expire.as_ref())
    }

    /// Get related inputs, such as account name, email, etc. This is used for password
    /// quality checking.
    pub fn related_inputs(&self) -> Vec<&str> {
        let mut inputs = Vec::with_capacity(4 + self.mail.len());
        self.mail.iter().for_each(|m| {
            inputs.push(m.as_str());
        });
        inputs.push(self.spn.as_str());
        if let Some(name) = self.name.as_ref() {
            inputs.push(name)
        }
        inputs.push(self.displayname.as_str());
        if let Some(s) = self.radius_secret.as_deref() {
            inputs.push(s);
        }
        inputs
    }

    pub fn primary_cred_uuid_and_policy(&self) -> Option<(Uuid, CredSoftLockPolicy)> {
        self.primary
            .as_ref()
            .map(|cred| (cred.uuid, cred.softlock_policy()))
            .or_else(|| {
                if self.is_anonymous() {
                    Some((UUID_ANONYMOUS, CredSoftLockPolicy::Unrestricted))
                } else {
                    None
                }
            })
    }

    pub fn is_anonymous(&self) -> bool {
        self.uuid == UUID_ANONYMOUS
    }

    #[cfg(test)]
    pub(crate) fn gen_password_mod(
        &self,
        cleartext: &str,
        crypto_policy: &CryptoPolicy,
        ct: OffsetDateTime,
    ) -> Result<ModifyList<ModifyInvalid>, OperationError> {
        match &self.primary {
            // Change the cred
            Some(primary) => {
                let ncred = primary.set_password(crypto_policy, cleartext, ct)?;
                let vcred = Value::new_credential("primary", ncred);
                Ok(ModifyList::new_purge_and_set(
                    Attribute::PrimaryCredential,
                    vcred,
                ))
            }
            // Make a new credential instead
            None => {
                let ncred = Credential::new_password_only(
                    crypto_policy,
                    cleartext,
                    OffsetDateTime::UNIX_EPOCH,
                )?;
                let vcred = Value::new_credential("primary", ncred);
                Ok(ModifyList::new_purge_and_set(
                    Attribute::PrimaryCredential,
                    vcred,
                ))
            }
        }
    }

    pub(crate) fn gen_password_upgrade_mod(
        &self,
        cleartext: &str,
        crypto_policy: &CryptoPolicy,
    ) -> Result<Option<ModifyList<ModifyInvalid>>, OperationError> {
        match &self.primary {
            // Change the cred
            Some(primary) => {
                if let Some(ncred) = primary.upgrade_password(crypto_policy, cleartext)? {
                    let vcred = Value::new_credential("primary", ncred);
                    Ok(Some(ModifyList::new_purge_and_set(
                        Attribute::PrimaryCredential,
                        vcred,
                    )))
                } else {
                    // No action, not the same pw
                    Ok(None)
                }
            }
            // Nothing to do.
            None => Ok(None),
        }
    }

    pub(crate) fn gen_webauthn_counter_mod(
        &mut self,
        auth_result: &AuthenticationResult,
    ) -> Result<Option<ModifyList<ModifyInvalid>>, OperationError> {
        let mut ml = Vec::with_capacity(2);
        // Where is the credential we need to update?
        let opt_ncred = match self.primary.as_ref() {
            Some(primary) => primary.update_webauthn_properties(auth_result)?,
            None => None,
        };

        if let Some(ncred) = opt_ncred {
            let vcred = Value::new_credential("primary", ncred);
            ml.push(Modify::Purged(Attribute::PrimaryCredential));
            ml.push(Modify::Present(Attribute::PrimaryCredential, vcred));
        }

        // Is it a passkey?
        self.passkeys.iter_mut().for_each(|(u, (t, k))| {
            if let Some(true) = k.update_credential(auth_result) {
                ml.push(Modify::Removed(
                    Attribute::PassKeys,
                    PartialValue::Passkey(*u),
                ));

                ml.push(Modify::Present(
                    Attribute::PassKeys,
                    Value::Passkey(*u, t.clone(), k.clone()),
                ));
            }
        });

        // Is it an attested passkey?
        self.attested_passkeys.iter_mut().for_each(|(u, (t, k))| {
            if let Some(true) = k.update_credential(auth_result) {
                ml.push(Modify::Removed(
                    Attribute::AttestedPasskeys,
                    PartialValue::AttestedPasskey(*u),
                ));

                ml.push(Modify::Present(
                    Attribute::AttestedPasskeys,
                    Value::AttestedPasskey(*u, t.clone(), k.clone()),
                ));
            }
        });

        if ml.is_empty() {
            Ok(None)
        } else {
            Ok(Some(ModifyList::new_list(ml)))
        }
    }

    pub(crate) fn invalidate_backup_code_mod(
        self,
        code_to_remove: &str,
    ) -> Result<ModifyList<ModifyInvalid>, OperationError> {
        match self.primary {
            // Change the cred
            Some(primary) => {
                let r_ncred = primary.invalidate_backup_code(code_to_remove);
                match r_ncred {
                    Ok(ncred) => {
                        let vcred = Value::new_credential("primary", ncred);
                        Ok(ModifyList::new_purge_and_set(
                            Attribute::PrimaryCredential,
                            vcred,
                        ))
                    }
                    Err(e) => Err(e),
                }
            }
            None => {
                // No credential exists, we can't supplementy it.
                Err(OperationError::InvalidState)
            }
        }
    }

    pub(crate) fn regenerate_radius_secret_mod(
        &self,
        cleartext: &str,
    ) -> Result<ModifyList<ModifyInvalid>, OperationError> {
        let vcred = Value::new_secret_str(cleartext);
        Ok(ModifyList::new_purge_and_set(
            Attribute::RadiusSecret,
            vcred,
        ))
    }

    pub(crate) fn to_credentialstatus(&self) -> Result<CredentialStatus, OperationError> {
        // In the future this will need to handle multiple credentials, not just single.

        self.primary
            .as_ref()
            .map(|cred| CredentialStatus {
                creds: vec![cred.into()],
            })
            .ok_or(OperationError::NoMatchingAttributes)
    }

    pub(crate) fn existing_credential_id_list(&self) -> Option<Vec<CredentialID>> {
        // TODO!!!
        // Used in registrations only for disallowing existing credentials.
        None
    }

    pub(crate) fn check_user_auth_token_valid(
        ct: Duration,
        uat: &UserAuthToken,
        entry: &Entry<EntrySealed, EntryCommitted>,
    ) -> bool {
        // Remember, token expiry is checked by validate_and_parse_token_to_token.
        // If we wanted we could check other properties of the uat here?
        // Alternatively, we could always store LESS in the uat because of this?

        let within_valid_window = Account::check_within_valid_time(
            ct,
            entry
                .get_ava_single_datetime(Attribute::AccountValidFrom)
                .as_ref(),
            entry
                .get_ava_single_datetime(Attribute::AccountExpire)
                .as_ref(),
        );

        if !within_valid_window {
            security_info!("Account has expired or is not yet valid, not allowing to proceed");
            return false;
        }

        // Anonymous does NOT record it's sessions, so we simply check the expiry time
        // of the token. This is already done for us as noted above.
        trace!("{}", &uat);

        if uat.uuid == UUID_ANONYMOUS {
            security_debug!("Anonymous sessions do not have session records, session is valid.");
            true
        } else {
            // Get the sessions.
            let session_present = entry
                .get_ava_as_session_map(Attribute::UserAuthTokenSession)
                .and_then(|session_map| session_map.get(&uat.session_id));

            // Important - we don't have to check the expiry time against ct here since it was
            // already checked in token_to_token. Here we just need to check it's consistent
            // to our internal session knowledge.
            if let Some(session) = session_present {
                match (&session.state, &uat.expiry) {
                    (SessionState::ExpiresAt(s_exp), Some(u_exp)) if s_exp == u_exp => {
                        security_info!("A valid limited session value exists for this token");
                        true
                    }
                    (SessionState::NeverExpires, None) => {
                        security_info!("A valid unbound session value exists for this token");
                        true
                    }
                    (SessionState::RevokedAt(_), _) => {
                        // William, if you have added a new type of credential, and end up here, you
                        // need to look at session consistency plugin.
                        security_info!("Session has been revoked");
                        false
                    }
                    _ => {
                        security_info!("Session and uat expiry are not consistent, rejecting.");
                        debug!(ses_st = ?session.state, uat_exp = ?uat.expiry);
                        false
                    }
                }
            } else {
                let grace = uat.issued_at + AUTH_TOKEN_GRACE_WINDOW;
                let current = time::OffsetDateTime::UNIX_EPOCH + ct;
                trace!(%grace, %current);
                if current >= grace {
                    security_info!(
                        "The token grace window has passed, and no session exists. Assuming invalid."
                    );
                    false
                } else {
                    security_info!("The token grace window is in effect. Assuming valid.");
                    true
                }
            }
        }
    }

    pub(crate) fn verify_application_password(
        &self,
        application: &Application,
        cleartext: &str,
    ) -> Result<Option<LdapBoundToken>, OperationError> {
        if let Some(v) = self.apps_pwds.get(&application.uuid) {
            for ap in v.iter() {
                let password_verified = ap.password.verify(cleartext).map_err(|e| {
                    error!(crypto_err = ?e);
                    OperationError::CryptographyError
                })?;

                if password_verified {
                    let session_id = uuid::Uuid::new_v4();
                    security_info!(
                        "Starting session {} for {} {}",
                        session_id,
                        self.spn,
                        self.uuid
                    );

                    return Ok(Some(LdapBoundToken {
                        spn: self.spn.clone(),
                        session_id,
                        effective_session: LdapSession::ApplicationPasswordBind(
                            application.uuid,
                            self.uuid,
                        ),
                    }));
                }
            }
        }
        Ok(None)
    }

    pub(crate) fn to_unixusertoken(&self, ct: Duration) -> Result<UnixUserToken, OperationError> {
        let (gidnumber, shell, sshkeys, groups) = match &self.unix_extn {
            Some(ue) => {
                let sshkeys: Vec<_> = self.sshkeys.values().cloned().collect();
                (ue.gidnumber, ue.shell.clone(), sshkeys, ue.groups.clone())
            }
            None => {
                return Err(OperationError::MissingClass(
                    ENTRYCLASS_POSIX_ACCOUNT.into(),
                ));
            }
        };

        let groups: Vec<UnixGroupToken> = groups.iter().map(|g| g.to_unixgrouptoken()).collect();

        Ok(UnixUserToken {
            name: self.name().into(),
            spn: self.spn.clone(),
            displayname: self.displayname.clone(),
            gidnumber,
            uuid: self.uuid,
            shell: shell.clone(),
            groups,
            sshkeys,
            valid: self.is_within_valid_time(ct),
        })
    }

    pub(crate) fn oauth2_client_provider(&self) -> Option<&OAuth2AccountCredential> {
        self.oauth2_client_provider.as_ref()
    }

    #[cfg(test)]
    pub(crate) fn setup_oauth2_client_provider(
        &mut self,
        client_provider: &crate::idm::oauth2_client::OAuth2ClientProvider,
    ) {
        self.oauth2_client_provider = Some(OAuth2AccountCredential {
            provider: client_provider.uuid,
            cred_id: Uuid::new_v4(),
            user_id: self.spn.clone(),
        });
    }
}

// Need to also add a "to UserAuthToken" ...

// Need tests for conversion and the cred validations

pub struct DestroySessionTokenEvent {
    // Who initiated this?
    pub ident: Identity,
    // Who is it targeting?
    pub target: Uuid,
    // Which token id.
    pub token_id: Uuid,
}

impl DestroySessionTokenEvent {
    #[cfg(test)]
    pub fn new_internal(target: Uuid, token_id: Uuid) -> Self {
        DestroySessionTokenEvent {
            ident: Identity::from_internal(),
            target,
            token_id,
        }
    }
}

impl IdmServerProxyWriteTransaction<'_> {
    pub fn account_destroy_session_token(
        &mut self,
        dte: &DestroySessionTokenEvent,
    ) -> Result<(), OperationError> {
        // Delete the attribute with uuid.
        let modlist = ModifyList::new_list(vec![Modify::Removed(
            Attribute::UserAuthTokenSession,
            PartialValue::Refer(dte.token_id),
        )]);

        self.qs_write
            .impersonate_modify(
                // Filter as executed
                &filter!(f_and!([
                    f_eq(Attribute::Uuid, PartialValue::Uuid(dte.target)),
                    f_eq(
                        Attribute::UserAuthTokenSession,
                        PartialValue::Refer(dte.token_id)
                    )
                ])),
                // Filter as intended (acp)
                &filter_all!(f_and!([
                    f_eq(Attribute::Uuid, PartialValue::Uuid(dte.target)),
                    f_eq(
                        Attribute::UserAuthTokenSession,
                        PartialValue::Refer(dte.token_id)
                    )
                ])),
                &modlist,
                // Provide the event to impersonate. Notice how we project this with readwrite
                // capability? This is because without this we'd force re-auths to end
                // a session and we don't want that! you should always be able to logout!
                &dte.ident.project_with_scope(AccessScope::ReadWrite),
            )
            .map_err(|e| {
                admin_error!("Failed to destroy user auth token {:?}", e);
                e
            })
    }

    pub fn service_account_into_person(
        &mut self,
        ident: &Identity,
        target_uuid: Uuid,
    ) -> Result<(), OperationError> {
        let schema_ref = self.qs_write.get_schema();

        // Get the entry.
        let account_entry = self
            .qs_write
            .internal_search_uuid(target_uuid)
            .map_err(|e| {
                admin_error!("Failed to start service account into person -> {:?}", e);
                e
            })?;

        // Copy the current classes
        let prev_classes: BTreeSet<_> = account_entry
            .get_ava_as_iutf8_iter(Attribute::Class)
            .ok_or_else(|| {
                error!(
                    "Invalid entry, {} attribute is not present or not iutf8",
                    Attribute::Class
                );
                OperationError::MissingAttribute(Attribute::Class)
            })?
            .collect();

        // Remove the service account class.
        // Add the person class.
        let mut new_iutf8es = prev_classes.clone();
        new_iutf8es.remove(EntryClass::ServiceAccount.into());
        new_iutf8es.insert(EntryClass::Person.into());

        // diff the schema attrs, and remove the ones that are service_account only.
        let (_added, removed) = schema_ref
            .query_attrs_difference(&prev_classes, &new_iutf8es)
            .map_err(|se| {
                admin_error!("While querying the schema, it reported that requested classes may not be present indicating a possible corruption");
                OperationError::SchemaViolation(
                    se
                )
            })?;

        // Now construct the modlist which:
        // removes service_account
        let mut modlist = ModifyList::new_remove(
            Attribute::Class,
            EntryClass::ServiceAccount.to_partialvalue(),
        );
        // add person
        modlist.push_mod(Modify::Present(
            Attribute::Class,
            EntryClass::Person.to_value(),
        ));
        // purge the other attrs that are SA only.
        removed
            .into_iter()
            .for_each(|attr| modlist.push_mod(Modify::Purged(attr.into())));
        // purge existing sessions

        // Modify
        self.qs_write
            .impersonate_modify(
                // Filter as executed
                &filter!(f_eq(Attribute::Uuid, PartialValue::Uuid(target_uuid))),
                // Filter as intended (acp)
                &filter_all!(f_eq(Attribute::Uuid, PartialValue::Uuid(target_uuid))),
                &modlist,
                // Provide the entry to impersonate
                ident,
            )
            .map_err(|e| {
                admin_error!("Failed to migrate service account to person - {:?}", e);
                e
            })
    }
}

pub struct ListUserAuthTokenEvent {
    // Who initiated this?
    pub ident: Identity,
    // Who is it targeting?
    pub target: Uuid,
}

impl IdmServerProxyReadTransaction<'_> {
    pub fn account_list_user_auth_tokens(
        &mut self,
        lte: &ListUserAuthTokenEvent,
    ) -> Result<Vec<UatStatus>, OperationError> {
        // Make an event from the request
        let srch = match SearchEvent::from_target_uuid_request(
            lte.ident.clone(),
            lte.target,
            &self.qs_read,
        ) {
            Ok(s) => s,
            Err(e) => {
                admin_error!("Failed to begin account list user auth tokens: {:?}", e);
                return Err(e);
            }
        };

        match self.qs_read.search_ext(&srch) {
            Ok(mut entries) => {
                entries
                    .pop()
                    // get the first entry
                    .and_then(|e| {
                        let account_id = e.get_uuid();
                        // From the entry, turn it into the value
                        e.get_ava_as_session_map(Attribute::UserAuthTokenSession)
                            .map(|smap| {
                                smap.iter()
                                    .map(|(u, s)| {
                                        let state = match s.state {
                                            SessionState::ExpiresAt(odt) => {
                                                UatStatusState::ExpiresAt(odt)
                                            }
                                            SessionState::NeverExpires => {
                                                UatStatusState::NeverExpires
                                            }
                                            SessionState::RevokedAt(_) => UatStatusState::Revoked,
                                        };

                                        s.scope
                                            .try_into()
                                            .map(|purpose| UatStatus {
                                                account_id,
                                                session_id: *u,
                                                state,
                                                issued_at: s.issued_at,
                                                purpose,
                                            })
                                            .inspect_err(|_e| {
                                                admin_error!("Invalid user auth token {}", u);
                                            })
                                    })
                                    .collect::<Result<Vec<_>, _>>()
                            })
                    })
                    .unwrap_or_else(|| {
                        // No matching entry? Return none.
                        Ok(Vec::with_capacity(0))
                    })
            }
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::idm::accountpolicy::ResolvedAccountPolicy;
    use crate::prelude::*;
    use kanidm_proto::internal::UiHint;

    #[idm_test]
    async fn test_idm_account_ui_hints(idms: &IdmServer, _idms_delayed: &mut IdmServerDelayed) {
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = idms.proxy_write(ct).await.unwrap();

        let target_uuid = Uuid::new_v4();

        // Create a user. So far no ui hints.
        // Create a service account
        let e = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Account.to_value()),
            (Attribute::Class, EntryClass::Person.to_value()),
            (Attribute::Name, Value::new_iname("testaccount")),
            (Attribute::Uuid, Value::Uuid(target_uuid)),
            (Attribute::Description, Value::new_utf8s("testaccount")),
            (Attribute::DisplayName, Value::new_utf8s("Test Account"))
        );

        let ce = CreateEvent::new_internal(vec![e]);
        assert!(idms_prox_write.qs_write.create(&ce).is_ok());

        let account = idms_prox_write
            .target_to_account(target_uuid)
            .expect("account must exist");
        let session_id = uuid::Uuid::new_v4();
        let uat = account
            .to_userauthtoken(
                session_id,
                SessionScope::ReadWrite,
                ct,
                &ResolvedAccountPolicy::test_policy(),
            )
            .expect("Unable to create uat");

        // Check the ui hints are as expected.
        assert_eq!(uat.ui_hints.len(), 1);
        assert!(uat.ui_hints.contains(&UiHint::CredentialUpdate));

        // Modify the user to be a posix account, ensure they get the hint.
        let me_posix = ModifyEvent::new_internal_invalid(
            filter!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testaccount")
            )),
            ModifyList::new_list(vec![
                Modify::Present(Attribute::Class, EntryClass::PosixAccount.into()),
                Modify::Present(Attribute::GidNumber, Value::new_uint32(2001)),
            ]),
        );
        assert!(idms_prox_write.qs_write.modify(&me_posix).is_ok());

        // Check the ui hints are as expected.
        let account = idms_prox_write
            .target_to_account(target_uuid)
            .expect("account must exist");
        let session_id = uuid::Uuid::new_v4();
        let uat = account
            .to_userauthtoken(
                session_id,
                SessionScope::ReadWrite,
                ct,
                &ResolvedAccountPolicy::test_policy(),
            )
            .expect("Unable to create uat");

        assert_eq!(uat.ui_hints.len(), 2);
        assert!(uat.ui_hints.contains(&UiHint::PosixAccount));
        assert!(uat.ui_hints.contains(&UiHint::CredentialUpdate));

        // Add a group with a ui hint, and then check they get the hint.
        let e = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Group.to_value()),
            (Attribute::Name, Value::new_iname("test_uihint_group")),
            (Attribute::Member, Value::Refer(target_uuid)),
            (
                Attribute::GrantUiHint,
                Value::UiHint(UiHint::ExperimentalFeatures)
            )
        );

        let ce = CreateEvent::new_internal(vec![e]);
        assert!(idms_prox_write.qs_write.create(&ce).is_ok());

        // Check the ui hints are as expected.
        let account = idms_prox_write
            .target_to_account(target_uuid)
            .expect("account must exist");
        let session_id = uuid::Uuid::new_v4();
        let uat = account
            .to_userauthtoken(
                session_id,
                SessionScope::ReadWrite,
                ct,
                &ResolvedAccountPolicy::test_policy(),
            )
            .expect("Unable to create uat");

        assert_eq!(uat.ui_hints.len(), 3);
        assert!(uat.ui_hints.contains(&UiHint::PosixAccount));
        assert!(uat.ui_hints.contains(&UiHint::ExperimentalFeatures));
        assert!(uat.ui_hints.contains(&UiHint::CredentialUpdate));

        assert!(idms_prox_write.commit().is_ok());
    }
}
