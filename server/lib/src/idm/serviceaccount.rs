use std::collections::BTreeMap;
use std::time::Duration;

use compact_jwt::{jws::JwsBuilder, Jws, JwsCompact};
use kanidm_proto::internal::ApiToken as ProtoApiToken;
use time::OffsetDateTime;

use crate::credential::Credential;
use crate::event::SearchEvent;
use crate::idm::account::Account;
use crate::idm::event::GeneratePasswordEvent;
use crate::idm::server::{IdmServerProxyReadTransaction, IdmServerProxyWriteTransaction};
use crate::prelude::*;
use crate::utils::password_from_random;
use crate::value::ApiToken;

macro_rules! try_from_entry {
    ($value:expr) => {{
        // Check the classes
        if !$value.attribute_equality(Attribute::Class, &EntryClass::ServiceAccount.into()) {
            return Err(OperationError::MissingClass(
                ENTRYCLASS_SERVICE_ACCOUNT.into(),
            ));
        }

        let api_tokens = $value
            .get_ava_as_apitoken_map(Attribute::ApiTokenSession)
            .cloned()
            .unwrap_or_default();

        let valid_from = $value.get_ava_single_datetime(Attribute::AccountValidFrom);

        let expire = $value.get_ava_single_datetime(Attribute::AccountExpire);

        let uuid = $value.get_uuid().clone();

        Ok(ServiceAccount {
            uuid,
            valid_from,
            expire,
            api_tokens,
        })
    }};
}

pub struct ServiceAccount {
    pub uuid: Uuid,

    pub valid_from: Option<OffsetDateTime>,
    pub expire: Option<OffsetDateTime>,

    pub api_tokens: BTreeMap<Uuid, ApiToken>,
}

impl ServiceAccount {
    #[instrument(level = "debug", skip_all)]
    pub(crate) fn try_from_entry_rw(
        value: &Entry<EntrySealed, EntryCommitted>,
        // qs: &mut QueryServerWriteTransaction,
    ) -> Result<Self, OperationError> {
        // let groups = Group::try_from_account_entry_rw(value, qs)?;
        try_from_entry!(value)
    }

    pub(crate) fn check_api_token_valid(
        ct: Duration,
        apit: &ProtoApiToken,
        entry: &Entry<EntrySealed, EntryCommitted>,
    ) -> bool {
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

        // Get the sessions.
        let session_present = entry
            .get_ava_as_apitoken_map(Attribute::ApiTokenSession)
            .map(|session_map| session_map.get(&apit.token_id).is_some())
            .unwrap_or(false);

        if session_present {
            security_info!("A valid session value exists for this token");
            true
        } else {
            let grace = apit.issued_at + AUTH_TOKEN_GRACE_WINDOW;
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

pub struct ListApiTokenEvent {
    // Who initiated this?
    pub ident: Identity,
    // Who is it targeting?
    pub target: Uuid,
}

pub struct GenerateApiTokenEvent {
    // Who initiated this?
    pub ident: Identity,
    // Who is it targeting?
    pub target: Uuid,
    // The label
    pub label: String,
    // When should it expire?
    pub expiry: Option<time::OffsetDateTime>,
    // Is it read_write capable?
    pub read_write: bool,
    // Limits?

    // Should it be compact?
    pub compact: bool,
}

impl GenerateApiTokenEvent {
    #[cfg(test)]
    pub fn new_internal(target: Uuid, label: &str, expiry: Option<Duration>) -> Self {
        GenerateApiTokenEvent {
            ident: Identity::from_internal(),
            target,
            label: label.to_string(),
            expiry: expiry.map(|ct| time::OffsetDateTime::UNIX_EPOCH + ct),
            read_write: false,
            compact: false,
        }
    }
}

pub struct DestroyApiTokenEvent {
    // Who initiated this?
    pub ident: Identity,
    // Who is it targeting?
    pub target: Uuid,
    // Which token id.
    pub token_id: Uuid,
}

impl DestroyApiTokenEvent {
    #[cfg(test)]
    pub fn new_internal(target: Uuid, token_id: Uuid) -> Self {
        DestroyApiTokenEvent {
            ident: Identity::from_internal(),
            target,
            token_id,
        }
    }
}

impl IdmServerProxyWriteTransaction<'_> {
    pub fn service_account_generate_api_token(
        &mut self,
        gte: &GenerateApiTokenEvent,
        ct: Duration,
    ) -> Result<JwsCompact, OperationError> {
        let service_account = self
            .qs_write
            .internal_search_uuid(gte.target)
            .and_then(|account_entry| ServiceAccount::try_from_entry_rw(&account_entry))
            .map_err(|e| {
                admin_error!(?e, "Failed to search service account");
                e
            })?;

        let session_id = Uuid::new_v4();
        let issued_at = time::OffsetDateTime::UNIX_EPOCH + ct;

        // Normalise to UTC in case it was provided as something else.
        let expiry = gte.expiry.map(|odt| odt.to_offset(time::UtcOffset::UTC));

        let scope = if gte.read_write {
            ApiTokenScope::ReadWrite
        } else {
            ApiTokenScope::ReadOnly
        };

        // create a new session
        let session = Value::ApiToken(
            session_id,
            ApiToken {
                label: gte.label.clone(),
                expiry,
                // Need the other inner bits?
                // for the gracewindow.
                issued_at,
                // Who actually created this?
                issued_by: gte.ident.get_event_origin_id(),
                // What is the access scope of this session? This is
                // for auditing purposes.
                scope,
            },
        );

        let token = if gte.compact {
            // We only issue the session uuid now. This makes the token as compact as possible, fitting
            // within 128 characters.
            let payload = session_id.as_bytes().to_vec();
            JwsBuilder::from(payload).build()
        } else {
            let purpose = scope.try_into()?;
            // create the session token (not yet signed)
            let proto_api_token = ProtoApiToken {
                account_id: service_account.uuid,
                token_id: session_id,
                label: gte.label.clone(),
                expiry: gte.expiry,
                issued_at,
                purpose,
            };

            let token = Jws::into_json(&proto_api_token).map_err(|err| {
                error!(?err, "Unable to serialise JWS");
                OperationError::SerdeJsonError
            })?;

            token
        };

        // modify the account to put the session onto it.
        let modlist =
            ModifyList::new_list(vec![Modify::Present(Attribute::ApiTokenSession, session)]);

        self.qs_write
            .impersonate_modify(
                // Filter as executed
                &filter!(f_eq(Attribute::Uuid, PartialValue::Uuid(gte.target))),
                // Filter as intended (acp)
                &filter_all!(f_eq(Attribute::Uuid, PartialValue::Uuid(gte.target))),
                &modlist,
                // Provide the event to impersonate
                &gte.ident,
            )
            .map_err(|err| {
                error!(?err, "Failed to generate api token");
                err
            })?;

        self.qs_write
            .get_domain_key_object_handle()?
            .jws_hs256_sign(&token, ct)
    }

    pub fn service_account_destroy_api_token(
        &mut self,
        dte: &DestroyApiTokenEvent,
    ) -> Result<(), OperationError> {
        // Delete the attribute with uuid.
        let modlist = ModifyList::new_list(vec![Modify::Removed(
            Attribute::ApiTokenSession,
            PartialValue::Refer(dte.token_id),
        )]);

        self.qs_write
            .impersonate_modify(
                // Filter as executed
                &filter!(f_and!([
                    f_eq(Attribute::Uuid, PartialValue::Uuid(dte.target)),
                    f_eq(
                        Attribute::ApiTokenSession,
                        PartialValue::Refer(dte.token_id)
                    )
                ])),
                // Filter as intended (acp)
                &filter_all!(f_and!([
                    f_eq(Attribute::Uuid, PartialValue::Uuid(dte.target)),
                    f_eq(
                        Attribute::ApiTokenSession,
                        PartialValue::Refer(dte.token_id)
                    )
                ])),
                &modlist,
                // Provide the event to impersonate
                &dte.ident,
            )
            .map_err(|e| {
                admin_error!("Failed to destroy api token {:?}", e);
                e
            })
    }

    pub fn generate_service_account_password(
        &mut self,
        gpe: &GeneratePasswordEvent,
    ) -> Result<String, OperationError> {
        // Generate a new random, long pw.
        // Because this is generated, we can bypass policy checks!
        let cleartext = password_from_random();
        let timestamp = self.qs_write.get_curtime_odt();
        let ncred =
            Credential::new_generatedpassword_only(self.crypto_policy(), &cleartext, timestamp)
                .map_err(|e| {
                    admin_error!("Unable to generate password mod {:?}", e);
                    e
                })?;
        let vcred = Value::new_credential("primary", ncred);
        // We need to remove other credentials too.
        let modlist = ModifyList::new_list(vec![
            m_purge(Attribute::PassKeys),
            m_purge(Attribute::PrimaryCredential),
            Modify::Present(Attribute::PrimaryCredential, vcred),
        ]);

        trace!(?modlist, "processing change");
        // given the new credential generate a modify
        // We use impersonate here to get the event from ae
        self.qs_write
            .impersonate_modify(
                // Filter as executed
                &filter_all!(f_and!([
                    f_eq(Attribute::Uuid, PartialValue::Uuid(gpe.target)),
                    f_eq(Attribute::Class, EntryClass::ServiceAccount.into())
                ])),
                // Filter as intended (acp)
                &filter!(f_eq(Attribute::Uuid, PartialValue::Uuid(gpe.target))),
                &modlist,
                // Provide the event to impersonate
                &gpe.ident,
            )
            .map(|_| cleartext)
            .map_err(|e| {
                admin_error!("Failed to generate account password {:?}", e);
                e
            })
    }
}

impl IdmServerProxyReadTransaction<'_> {
    pub fn service_account_list_api_token(
        &mut self,
        lte: &ListApiTokenEvent,
    ) -> Result<Vec<ProtoApiToken>, OperationError> {
        // Make an event from the request
        let srch = match SearchEvent::from_target_uuid_request(
            lte.ident.clone(),
            lte.target,
            &self.qs_read,
        ) {
            Ok(s) => s,
            Err(e) => {
                admin_error!("Failed to begin service account api token list: {:?}", e);
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
                        e.get_ava_as_apitoken_map(Attribute::ApiTokenSession)
                            .map(|smap| {
                                smap.iter()
                                    .map(|(u, s)| {
                                        s.scope
                                            .try_into()
                                            .map(|purpose| ProtoApiToken {
                                                account_id,
                                                token_id: *u,
                                                label: s.label.clone(),
                                                expiry: s.expiry,
                                                issued_at: s.issued_at,
                                                purpose,
                                            })
                                            .inspect_err(|err| {
                                                admin_error!(?err, "Invalid api_token {}", u);
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
    use std::time::Duration;

    use compact_jwt::{dangernoverify::JwsDangerReleaseWithoutVerify, JwsVerifier};
    use kanidm_proto::internal::ApiToken;

    use super::{DestroyApiTokenEvent, GenerateApiTokenEvent};
    use crate::idm::server::IdmServerTransaction;
    use crate::prelude::*;

    const TEST_CURRENT_TIME: u64 = 6000;

    #[idm_test]
    async fn test_idm_service_account_api_token(
        idms: &IdmServer,
        _idms_delayed: &mut IdmServerDelayed,
    ) {
        let ct = Duration::from_secs(TEST_CURRENT_TIME);
        let past_grc = Duration::from_secs(TEST_CURRENT_TIME + 1) + AUTH_TOKEN_GRACE_WINDOW;
        let exp = Duration::from_secs(TEST_CURRENT_TIME + 6000);
        let post_exp = Duration::from_secs(TEST_CURRENT_TIME + 6010);
        let mut idms_prox_write = idms.proxy_write(ct).await.unwrap();

        let testaccount_uuid = Uuid::new_v4();

        let e1 = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Account.to_value()),
            (Attribute::Class, EntryClass::ServiceAccount.to_value()),
            (Attribute::Name, Value::new_iname("test_account_only")),
            (Attribute::Uuid, Value::Uuid(testaccount_uuid)),
            (Attribute::Description, Value::new_utf8s("testaccount")),
            (Attribute::DisplayName, Value::new_utf8s("testaccount"))
        );

        idms_prox_write
            .qs_write
            .internal_create(vec![e1])
            .expect("Failed to create service account");

        let gte = GenerateApiTokenEvent::new_internal(testaccount_uuid, "TestToken", Some(exp));

        let api_token = idms_prox_write
            .service_account_generate_api_token(&gte, ct)
            .expect("failed to generate new api token");

        trace!(?api_token);

        // Deserialise it.
        let jws_verifier = JwsDangerReleaseWithoutVerify::default();

        let apitoken_inner = jws_verifier
            .verify(&api_token)
            .unwrap()
            .from_json::<ApiToken>()
            .unwrap();

        let ident = idms_prox_write
            .validate_client_auth_info_to_ident(api_token.clone().into(), ct)
            .expect("Unable to verify api token.");

        assert_eq!(ident.get_uuid(), Some(testaccount_uuid));

        // Woohoo! Okay lets test the other edge cases.

        // Check the expiry
        assert!(
            idms_prox_write
                .validate_client_auth_info_to_ident(api_token.clone().into(), post_exp)
                .expect_err("Should not succeed")
                == OperationError::SessionExpired
        );

        // Delete session
        let dte =
            DestroyApiTokenEvent::new_internal(apitoken_inner.account_id, apitoken_inner.token_id);
        assert!(idms_prox_write
            .service_account_destroy_api_token(&dte)
            .is_ok());

        // Within gracewindow?
        // This is okay, because we are within the gracewindow.
        let ident = idms_prox_write
            .validate_client_auth_info_to_ident(api_token.clone().into(), ct)
            .expect("Unable to verify api token.");
        assert_eq!(ident.get_uuid(), Some(testaccount_uuid));

        // Past gracewindow?
        assert!(
            idms_prox_write
                .validate_client_auth_info_to_ident(api_token.into(), past_grc)
                .expect_err("Should not succeed")
                == OperationError::SessionExpired
        );

        assert!(idms_prox_write.commit().is_ok());
    }

    #[idm_test]
    async fn test_idm_service_account_compact_api_token(
        idms: &IdmServer,
        _idms_delayed: &mut IdmServerDelayed,
    ) {
        let ct = Duration::from_secs(TEST_CURRENT_TIME);
        let exp = Duration::from_secs(TEST_CURRENT_TIME + 6000);
        let post_exp = Duration::from_secs(TEST_CURRENT_TIME + 6010);
        let mut idms_prox_write = idms.proxy_write(ct).await.unwrap();

        let testaccount_uuid = Uuid::new_v4();

        let e1 = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Account.to_value()),
            (Attribute::Class, EntryClass::ServiceAccount.to_value()),
            (Attribute::Name, Value::new_iname("test_account_only")),
            (Attribute::Uuid, Value::Uuid(testaccount_uuid)),
            (Attribute::Description, Value::new_utf8s("testaccount")),
            (Attribute::DisplayName, Value::new_utf8s("testaccount"))
        );

        idms_prox_write
            .qs_write
            .internal_create(vec![e1])
            .expect("Failed to create service account");

        let mut gte = GenerateApiTokenEvent::new_internal(testaccount_uuid, "TestToken", Some(exp));

        // === request a compact token.
        gte.compact = true;

        let api_token = idms_prox_write
            .service_account_generate_api_token(&gte, ct)
            .expect("failed to generate new api token");

        trace!(?api_token);

        // Deserialise it.
        let jws_verifier = JwsDangerReleaseWithoutVerify::default();

        let apitoken_inner = jws_verifier.verify(&api_token).unwrap();

        let session_id = Uuid::from_slice(apitoken_inner.payload())
            .expect("Unable to decode compact token as session id");

        let ident = idms_prox_write
            .validate_client_auth_info_to_ident(api_token.clone().into(), ct)
            .expect("Unable to verify api token.");

        assert_eq!(ident.get_uuid(), Some(testaccount_uuid));

        // Woohoo! Okay lets test the other edge cases.

        // Check the expiry
        assert!(
            idms_prox_write
                .validate_client_auth_info_to_ident(api_token.clone().into(), post_exp)
                .expect_err("Should not succeed")
                == OperationError::SessionExpired
        );

        // Delete session
        let dte = DestroyApiTokenEvent::new_internal(testaccount_uuid, session_id);
        assert!(idms_prox_write
            .service_account_destroy_api_token(&dte)
            .is_ok());

        // These tokens have no grace windows, don't need to be tested.

        assert!(idms_prox_write.commit().is_ok());
    }
}
