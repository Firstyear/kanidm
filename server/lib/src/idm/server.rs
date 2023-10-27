use std::convert::TryFrom;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use kanidm_lib_crypto::CryptoPolicy;

use compact_jwt::{Jws, JwsSigner, JwsUnverified, JwsValidator};
use concread::bptree::{BptreeMap, BptreeMapReadTxn, BptreeMapWriteTxn};
use concread::cowcell::{CowCellReadTxn, CowCellWriteTxn};
use concread::hashmap::HashMap;
use concread::CowCell;
use fernet::Fernet;
use kanidm_proto::internal::ScimSyncToken;
use kanidm_proto::v1::{
    ApiToken, BackupCodesView, CredentialStatus, PasswordFeedback, RadiusAuthToken, UatPurpose,
    UnixGroupToken, UnixUserToken, UserAuthToken,
};
use rand::prelude::*;
use tokio::sync::mpsc::{
    unbounded_channel as unbounded, UnboundedReceiver as Receiver, UnboundedSender as Sender,
};
use tokio::sync::{Mutex, Semaphore};
use tracing::trace;
use url::Url;
use webauthn_rs::prelude::{Webauthn, WebauthnBuilder};

use super::event::ReadBackupCodeEvent;
use super::ldap::{LdapBoundToken, LdapSession};
use crate::credential::{softlock::CredSoftLock, Credential};
use crate::idm::account::Account;
use crate::idm::audit::AuditEvent;
use crate::idm::authsession::{AuthSession, AuthSessionData};
use crate::idm::credupdatesession::CredentialUpdateSessionMutex;
use crate::idm::delayed::{
    AuthSessionRecord, BackupCodeRemoval, DelayedAction, PasswordUpgrade, UnixPasswordUpgrade,
    WebauthnCounterIncrement,
};
#[cfg(test)]
use crate::idm::event::PasswordChangeEvent;
use crate::idm::event::{AuthEvent, AuthEventStep, AuthResult};
use crate::idm::event::{
    CredentialStatusEvent, LdapAuthEvent, LdapTokenAuthEvent, RadiusAuthTokenEvent,
    RegenerateRadiusSecretEvent, UnixGroupTokenEvent, UnixPasswordChangeEvent, UnixUserAuthEvent,
    UnixUserTokenEvent,
};
use crate::idm::oauth2::{
    Oauth2ResourceServers, Oauth2ResourceServersReadTransaction,
    Oauth2ResourceServersWriteTransaction,
};
use crate::idm::radius::RadiusAccount;
use crate::idm::scim::SyncAccount;
use crate::idm::serviceaccount::ServiceAccount;
use crate::idm::unix::{UnixGroup, UnixUserAccount};
use crate::idm::AuthState;
use crate::prelude::*;
use crate::utils::{password_from_random, readable_password_from_random, uuid_from_duration, Sid};
use crate::value::{Session, SessionState};

pub(crate) type AuthSessionMutex = Arc<Mutex<AuthSession>>;
pub(crate) type CredSoftLockMutex = Arc<Mutex<CredSoftLock>>;

#[derive(Clone)]
pub struct DomainKeys {
    pub(crate) uat_jwt_signer: JwsSigner,
    pub(crate) uat_jwt_validator: JwsValidator,
    pub(crate) token_enc_key: Fernet,
    pub(crate) cookie_key: [u8; 64],
}

pub struct IdmServer {
    // There is a good reason to keep this single thread - it
    // means that limits to sessions can be easily applied and checked to
    // various accounts, and we have a good idea of how to structure the
    // in memory caches related to locking.
    session_ticket: Semaphore,
    sessions: BptreeMap<Uuid, AuthSessionMutex>,
    softlocks: HashMap<Uuid, CredSoftLockMutex>,
    /// A set of in progress credential registrations
    cred_update_sessions: BptreeMap<Uuid, CredentialUpdateSessionMutex>,
    /// Reference to the query server.
    qs: QueryServer,
    /// The configured crypto policy for the IDM server. Later this could be transactional and loaded from the db similar to access. But today it's just to allow dynamic pbkdf2rounds
    crypto_policy: CryptoPolicy,
    async_tx: Sender<DelayedAction>,
    audit_tx: Sender<AuditEvent>,
    /// [Webauthn] verifier/config
    webauthn: Webauthn,
    oauth2rs: Arc<Oauth2ResourceServers>,
    domain_keys: Arc<CowCell<DomainKeys>>,
}

/// Contains methods that require writes, but in the context of writing to the idm in memory structures (maybe the query server too). This is things like authentication.
pub struct IdmServerAuthTransaction<'a> {
    pub(crate) session_ticket: &'a Semaphore,
    pub(crate) sessions: &'a BptreeMap<Uuid, AuthSessionMutex>,
    pub(crate) softlocks: &'a HashMap<Uuid, CredSoftLockMutex>,

    pub qs_read: QueryServerReadTransaction<'a>,
    /// Thread/Server ID
    pub(crate) sid: Sid,
    // For flagging eventual actions.
    pub(crate) async_tx: Sender<DelayedAction>,
    pub(crate) audit_tx: Sender<AuditEvent>,
    pub(crate) webauthn: &'a Webauthn,
    pub(crate) domain_keys: CowCellReadTxn<DomainKeys>,
}

pub struct IdmServerCredUpdateTransaction<'a> {
    pub(crate) qs_read: QueryServerReadTransaction<'a>,
    // sid: Sid,
    pub(crate) webauthn: &'a Webauthn,
    pub(crate) cred_update_sessions: BptreeMapReadTxn<'a, Uuid, CredentialUpdateSessionMutex>,
    pub(crate) domain_keys: CowCellReadTxn<DomainKeys>,
    pub(crate) crypto_policy: &'a CryptoPolicy,
}

/// This contains read-only methods, like getting users, groups and other structured content.
pub struct IdmServerProxyReadTransaction<'a> {
    pub qs_read: QueryServerReadTransaction<'a>,
    pub(crate) domain_keys: CowCellReadTxn<DomainKeys>,
    pub(crate) oauth2rs: Oauth2ResourceServersReadTransaction,
}

pub struct IdmServerProxyWriteTransaction<'a> {
    // This does NOT take any read to the memory content, allowing safe
    // qs operations to occur through this interface.
    pub qs_write: QueryServerWriteTransaction<'a>,
    /// Associate to an event origin ID, which has a TS and a UUID instead
    pub(crate) cred_update_sessions: BptreeMapWriteTxn<'a, Uuid, CredentialUpdateSessionMutex>,
    pub(crate) sid: Sid,
    crypto_policy: &'a CryptoPolicy,
    webauthn: &'a Webauthn,
    pub(crate) domain_keys: CowCellWriteTxn<'a, DomainKeys>,
    pub(crate) oauth2rs: Oauth2ResourceServersWriteTransaction<'a>,
}

pub struct IdmServerDelayed {
    pub(crate) async_rx: Receiver<DelayedAction>,
}

pub struct IdmServerAudit {
    pub(crate) audit_rx: Receiver<AuditEvent>,
}

impl IdmServer {
    pub async fn new(
        qs: QueryServer,
        origin: &str,
    ) -> Result<(IdmServer, IdmServerDelayed, IdmServerAudit), OperationError> {
        // This is calculated back from:
        //  100 password auths / thread -> 0.010 sec per op
        let crypto_policy = CryptoPolicy::time_target(Duration::from_millis(10));
        let (async_tx, async_rx) = unbounded();
        let (audit_tx, audit_rx) = unbounded();

        // Get the domain name, as the relying party id.
        let (rp_id, rp_name, fernet_private_key, es256_private_key, cookie_key, oauth2rs_set) = {
            let mut qs_read = qs.read().await;
            (
                qs_read.get_domain_name().to_string(),
                qs_read.get_domain_display_name().to_string(),
                qs_read.get_domain_fernet_private_key()?,
                qs_read.get_domain_es256_private_key()?,
                qs_read.get_domain_cookie_key()?,
                // Add a read/reload of all oauth2 configurations.
                qs_read.get_oauth2rs_set()?,
            )
        };

        // Check that it gels with our origin.
        let origin_url = Url::parse(origin)
            .map_err(|_e| {
                admin_error!("Unable to parse origin URL - refusing to start. You must correct the value for origin. {:?}", origin);
                OperationError::InvalidState
            })
            .and_then(|url| {
                let valid = url.domain().map(|effective_domain| {
                    // We need to prepend the '.' here to ensure that myexample.com != example.com,
                    // rather than just ends with.
                    effective_domain.ends_with(&format!(".{rp_id}"))
                    || effective_domain == rp_id
                }).unwrap_or(false);

                if valid {
                    Ok(url)
                } else {
                    admin_error!("Effective domain is not a descendent of server domain name (rp_id).");
                    admin_error!("You must change origin or domain name to be consistent. ed: {:?} - rp_id: {:?}", origin, rp_id);
                    admin_error!("To change the origin or domain name see: https://kanidm.github.io/kanidm/server_configuration.html");
                    Err(OperationError::InvalidState)
                }
            })?;

        let webauthn = WebauthnBuilder::new(&rp_id, &origin_url)
            .and_then(|builder| builder.allow_subdomains(true).rp_name(&rp_name).build())
            .map_err(|e| {
                admin_error!("Invalid Webauthn Configuration - {:?}", e);
                OperationError::InvalidState
            })?;

        // Setup our auth token signing key.
        let token_enc_key = Fernet::new(&fernet_private_key).ok_or_else(|| {
            admin_error!("Unable to load Fernet encryption key");
            OperationError::CryptographyError
        })?;

        let uat_jwt_signer = JwsSigner::from_es256_der(&es256_private_key).map_err(|e| {
            admin_error!(err = ?e, "Unable to load ES256 JwsSigner from DER");
            OperationError::CryptographyError
        })?;

        let uat_jwt_validator = uat_jwt_signer.get_validator().map_err(|e| {
            admin_error!(err = ?e, "Unable to load ES256 JwsValidator from JwsSigner");
            OperationError::CryptographyError
        })?;

        let domain_keys = Arc::new(CowCell::new(DomainKeys {
            uat_jwt_signer,
            uat_jwt_validator,
            token_enc_key,
            cookie_key,
        }));

        let oauth2rs =
            Oauth2ResourceServers::try_from((oauth2rs_set, origin_url)).map_err(|e| {
                admin_error!("Failed to load oauth2 resource servers - {:?}", e);
                e
            })?;

        Ok((
            IdmServer {
                session_ticket: Semaphore::new(1),
                sessions: BptreeMap::new(),
                softlocks: HashMap::new(),
                cred_update_sessions: BptreeMap::new(),
                qs,
                crypto_policy,
                async_tx,
                audit_tx,
                webauthn,
                domain_keys,
                oauth2rs: Arc::new(oauth2rs),
            },
            IdmServerDelayed { async_rx },
            IdmServerAudit { audit_rx },
        ))
    }

    pub fn get_cookie_key(&self) -> [u8; 64] {
        self.domain_keys.read().cookie_key
    }

    /// Start an auth txn
    pub async fn auth(&self) -> IdmServerAuthTransaction<'_> {
        let qs_read = self.qs.read().await;

        let mut sid = [0; 4];
        let mut rng = StdRng::from_entropy();
        rng.fill(&mut sid);

        IdmServerAuthTransaction {
            session_ticket: &self.session_ticket,
            sessions: &self.sessions,
            softlocks: &self.softlocks,
            qs_read,
            sid,
            async_tx: self.async_tx.clone(),
            audit_tx: self.audit_tx.clone(),
            webauthn: &self.webauthn,
            domain_keys: self.domain_keys.read(),
        }
    }

    /// Read from the database, in a transaction.
    #[instrument(level = "debug", skip_all)]
    pub async fn proxy_read(&self) -> IdmServerProxyReadTransaction<'_> {
        IdmServerProxyReadTransaction {
            qs_read: self.qs.read().await,
            domain_keys: self.domain_keys.read(),
            oauth2rs: self.oauth2rs.read(),
            // async_tx: self.async_tx.clone(),
        }
    }

    #[instrument(level = "debug", skip_all)]
    pub async fn proxy_write(&self, ts: Duration) -> IdmServerProxyWriteTransaction<'_> {
        let qs_write = self.qs.write(ts).await;

        let mut sid = [0; 4];
        let mut rng = StdRng::from_entropy();
        rng.fill(&mut sid);

        IdmServerProxyWriteTransaction {
            cred_update_sessions: self.cred_update_sessions.write(),
            qs_write,
            sid,
            crypto_policy: &self.crypto_policy,
            webauthn: &self.webauthn,
            domain_keys: self.domain_keys.write(),
            oauth2rs: self.oauth2rs.write(),
        }
    }

    pub async fn cred_update_transaction(&self) -> IdmServerCredUpdateTransaction<'_> {
        IdmServerCredUpdateTransaction {
            qs_read: self.qs.read().await,
            // sid: Sid,
            webauthn: &self.webauthn,
            cred_update_sessions: self.cred_update_sessions.read(),
            domain_keys: self.domain_keys.read(),
            crypto_policy: &self.crypto_policy,
        }
    }

    #[cfg(test)]
    pub(crate) async fn delayed_action(
        &self,
        ct: Duration,
        da: DelayedAction,
    ) -> Result<bool, OperationError> {
        let mut pw = self.proxy_write(ct).await;
        pw.process_delayedaction(da, ct)
            .and_then(|_| pw.commit())
            .map(|()| true)
    }
}

impl IdmServerAudit {
    #[cfg(test)]
    pub(crate) fn check_is_empty_or_panic(&mut self) {
        use tokio::sync::mpsc::error::TryRecvError;

        match self.audit_rx.try_recv() {
            Err(TryRecvError::Empty) => {}
            Err(TryRecvError::Disconnected) => {
                panic!("Task queue disconnected");
            }
            Ok(m) => {
                trace!(?m);
                panic!("Task queue not empty");
            }
        }
    }

    pub fn audit_rx(&mut self) -> &mut Receiver<AuditEvent> {
        &mut self.audit_rx
    }
}

impl IdmServerDelayed {
    #[cfg(test)]
    pub(crate) fn check_is_empty_or_panic(&mut self) {
        use tokio::sync::mpsc::error::TryRecvError;

        match self.async_rx.try_recv() {
            Err(TryRecvError::Empty) => {}
            Err(TryRecvError::Disconnected) => {
                panic!("Task queue disconnected");
            }
            Ok(m) => {
                trace!(?m);
                panic!("Task queue not empty");
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn try_recv(&mut self) -> Result<DelayedAction, OperationError> {
        use core::task::{Context, Poll};
        use futures::task as futures_task;

        let waker = futures_task::noop_waker();
        let mut cx = Context::from_waker(&waker);
        match self.async_rx.poll_recv(&mut cx) {
            Poll::Pending => Err(OperationError::InvalidState),
            Poll::Ready(None) => Err(OperationError::QueueDisconnected),
            Poll::Ready(Some(m)) => Ok(m),
        }
    }

    pub async fn next(&mut self) -> Option<DelayedAction> {
        self.async_rx.recv().await
    }
}

pub enum Token {
    UserAuthToken(UserAuthToken),
    ApiToken(ApiToken, Arc<EntrySealedCommitted>),
}

pub trait IdmServerTransaction<'a> {
    type QsTransactionType: QueryServerTransaction<'a>;

    fn get_qs_txn(&mut self) -> &mut Self::QsTransactionType;

    fn get_uat_validator_txn(&self) -> &JwsValidator;

    /// This is the preferred method to transform and securely verify a token into
    /// an identity that can be used for operations and access enforcement. This
    /// function *is* aware of the various classes of tokens that may exist, and can
    /// appropriately check them.
    ///
    /// The primary method of verification selection is the use of the KID parameter
    /// that we internally sign with. We can use this to select the appropriate token type
    /// and validation method.
    #[instrument(level = "info", skip_all)]
    fn validate_and_parse_token_to_ident(
        &mut self,
        token: Option<&str>,
        ct: Duration,
    ) -> Result<Identity, OperationError> {
        match self.validate_and_parse_token_to_token(token, ct)? {
            Token::UserAuthToken(uat) => self.process_uat_to_identity(&uat, ct),
            Token::ApiToken(apit, entry) => self.process_apit_to_identity(&apit, entry, ct),
        }
    }

    #[instrument(level = "info", skip_all)]
    fn validate_and_parse_token_to_uat(
        &mut self,
        token: Option<&str>,
        ct: Duration,
    ) -> Result<UserAuthToken, OperationError> {
        match self.validate_and_parse_token_to_token(token, ct)? {
            Token::UserAuthToken(uat) => Ok(uat),
            Token::ApiToken(_apit, _entry) => {
                warn!("Unable to process non user auth token");
                Err(OperationError::NotAuthenticated)
            }
        }
    }

    fn validate_and_parse_token_to_token(
        &mut self,
        token: Option<&str>,
        ct: Duration,
    ) -> Result<Token, OperationError> {
        let jwsu = token
            .ok_or_else(|| {
                security_info!("No token provided");
                OperationError::NotAuthenticated
            })
            .and_then(|s| {
                JwsUnverified::from_str(s).map_err(|e| {
                    security_info!(?e, "Unable to decode token");
                    OperationError::NotAuthenticated
                })
            })?;

        // Frow the unverified token we can now get the kid, and use that to locate the correct
        // key to id the token.
        let jws_validator = self.get_uat_validator_txn();
        let kid = jwsu.get_jwk_kid().ok_or_else(|| {
            security_info!("Token does not contain a valid kid");
            OperationError::NotAuthenticated
        })?;

        let jwsv_kid = jws_validator.get_jwk_kid().ok_or_else(|| {
            security_info!("JWS validator does not contain a valid kid");
            OperationError::NotAuthenticated
        })?;

        if kid == jwsv_kid {
            // It's signed by the primary jws, so it's probably a UserAuthToken.
            let uat = jwsu
                .validate(jws_validator)
                .map_err(|e| {
                    security_info!(?e, "Unable to verify token");
                    OperationError::NotAuthenticated
                })
                .map(|t: Jws<UserAuthToken>| t.into_inner())?;

            if let Some(exp) = uat.expiry {
                let ct_odt = time::OffsetDateTime::UNIX_EPOCH + ct;
                if ct_odt >= exp {
                    security_info!(?ct_odt, ?exp, "Session expired");
                    Err(OperationError::SessionExpired)
                } else {
                    trace!(?ct_odt, ?exp, "Session not yet expired");
                    Ok(Token::UserAuthToken(uat))
                }
            } else {
                debug!("Session has no expiry");
                Ok(Token::UserAuthToken(uat))
            }
        } else {
            // It's a per-user key, get their validator.
            let entry = self
                .get_qs_txn()
                .internal_search(filter!(f_eq(
                    Attribute::JwsEs256PrivateKey,
                    PartialValue::new_iutf8(kid)
                )))
                .and_then(|mut vs| match vs.pop() {
                    Some(entry) if vs.is_empty() => Ok(entry),
                    _ => {
                        admin_error!(
                            ?kid,
                            "entries was empty, or matched multiple results for kid"
                        );
                        Err(OperationError::NotAuthenticated)
                    }
                })?;

            let user_signer = entry
                .get_ava_single_jws_key_es256(Attribute::JwsEs256PrivateKey)
                .ok_or_else(|| {
                    admin_error!(
                        ?kid,
                        "A kid was present on entry {} but it does not contain a signing key",
                        entry.get_uuid()
                    );
                    OperationError::NotAuthenticated
                })?;

            let user_validator = user_signer.get_validator().map_err(|e| {
                security_info!(?e, "Unable to access token verifier");
                OperationError::NotAuthenticated
            })?;

            let apit = jwsu
                .validate(&user_validator)
                .map_err(|e| {
                    security_info!(?e, "Unable to verify token");
                    OperationError::NotAuthenticated
                })
                .map(|t: Jws<ApiToken>| t.into_inner())?;

            if let Some(expiry) = apit.expiry {
                if time::OffsetDateTime::UNIX_EPOCH + ct >= expiry {
                    security_info!("Session expired");
                    return Err(OperationError::SessionExpired);
                }
            }

            Ok(Token::ApiToken(apit, entry))
        }
    }

    #[instrument(level = "debug", skip_all)]
    fn validate_and_parse_uat(
        &self,
        token: Option<&str>,
        ct: Duration,
    ) -> Result<UserAuthToken, OperationError> {
        // Given the token string, validate and recreate the UAT
        let jws_validator = self.get_uat_validator_txn();

        let uat: UserAuthToken = token
            .ok_or(OperationError::NotAuthenticated)
            .and_then(|s| {
                JwsUnverified::from_str(s).map_err(|e| {
                    security_info!(?e, "Unable to decode token");
                    OperationError::NotAuthenticated
                })
            })
            .and_then(|jwtu| {
                jwtu.validate(jws_validator)
                    .map_err(|e| {
                        security_info!(?e, "Unable to verify token");
                        OperationError::NotAuthenticated
                    })
                    .map(|t: Jws<UserAuthToken>| t.into_inner())
            })?;

        if let Some(exp) = uat.expiry {
            if time::OffsetDateTime::UNIX_EPOCH + ct >= exp {
                security_info!("Session expired");
                Err(OperationError::SessionExpired)
            } else {
                Ok(uat)
            }
        } else {
            debug!("Session has no expiry");
            Ok(uat)
        }
    }

    fn check_oauth2_account_uuid_valid(
        &mut self,
        uuid: Uuid,
        session_id: Uuid,
        parent_session_id: Uuid,
        iat: i64,
        ct: Duration,
    ) -> Result<Option<Arc<Entry<EntrySealed, EntryCommitted>>>, OperationError> {
        let entry = self.get_qs_txn().internal_search_uuid(uuid).map_err(|e| {
            admin_error!(?e, "check_oauth2_account_uuid_valid failed");
            e
        })?;

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
            return Ok(None);
        }

        // We are past the grace window. Enforce session presence.
        // We enforce both sessions are present in case of inconsistency
        // that may occur with replication.

        let grace_valid = ct < (Duration::from_secs(iat as u64) + GRACE_WINDOW);

        let oauth2_session = entry
            .get_ava_as_oauth2session_map(Attribute::OAuth2Session)
            .and_then(|sessions| sessions.get(&session_id));
        let uat_session = entry
            .get_ava_as_session_map(Attribute::UserAuthTokenSession)
            .and_then(|sessions| sessions.get(&parent_session_id));

        if let Some(oauth2_session) = oauth2_session {
            // We have the oauth2 session, lets check it.
            let oauth2_session_valid = !matches!(oauth2_session.state, SessionState::RevokedAt(_));

            if !oauth2_session_valid {
                security_info!("The oauth2 session associated to this token is revoked.");
                return Ok(None);
            }

            if let Some(uat_session) = uat_session {
                let parent_session_valid = !matches!(uat_session.state, SessionState::RevokedAt(_));
                if parent_session_valid {
                    security_info!("A valid parent and oauth2 session value exists for this token");
                } else {
                    security_info!(
                        "The parent oauth2 session associated to this token is revoked."
                    );
                    return Ok(None);
                }
            } else if grace_valid {
                security_info!(
                    "The token grace window is in effect. Assuming parent session valid."
                );
            } else {
                security_info!("The token grace window has passed and no entry parent sessions exist. Assuming invalid.");
                return Ok(None);
            }
        } else if grace_valid {
            security_info!("The token grace window is in effect. Assuming valid.");
        } else {
            security_info!(
                "The token grace window has passed and no entry sessions exist. Assuming invalid."
            );
            return Ok(None);
        }

        Ok(Some(entry))
    }

    /// For any event/operation to proceed, we need to attach an identity to the
    /// event for security and access processing. When that event is externally
    /// triggered via one of our various api layers, we process some type of
    /// account token into this identity. In the current server this is the
    /// UserAuthToken. For a UserAuthToken to be provided it MUST have been
    /// cryptographically verified meaning it is now a *trusted* source of
    /// data that we previously issued.
    ///
    /// This is the function that is responsible for converting that UAT into
    /// something we can pin access controls and other limits and references to.
    /// This is why it is the location where validity windows are checked and other
    /// relevant session information is injected.
    #[instrument(level = "debug", skip_all)]
    fn process_uat_to_identity(
        &mut self,
        uat: &UserAuthToken,
        ct: Duration,
    ) -> Result<Identity, OperationError> {
        // From a UAT, get the current identity and associated information.
        let entry = self
            .get_qs_txn()
            .internal_search_uuid(uat.uuid)
            .map_err(|e| {
                admin_error!(?e, "from_ro_uat failed");
                e
            })?;

        let valid = Account::check_user_auth_token_valid(ct, uat, &entry);

        if !valid {
            return Err(OperationError::SessionExpired);
        }

        // ✅  Session is valid! Start to setup for it to be used.

        let scope = match uat.purpose {
            UatPurpose::ReadOnly => AccessScope::ReadOnly,
            UatPurpose::ReadWrite { expiry: None } => AccessScope::ReadOnly,
            UatPurpose::ReadWrite {
                expiry: Some(expiry),
            } => {
                let cot = time::OffsetDateTime::UNIX_EPOCH + ct;
                if cot < expiry {
                    AccessScope::ReadWrite
                } else {
                    AccessScope::ReadOnly
                }
            }
        };

        let limits = Limits::default();

        // #64: Now apply claims from the uat into the Entry
        // to allow filtering.
        /*
        entry.insert_claim(match &uat.auth_type {
            AuthType::Anonymous => "authtype_anonymous",
            AuthType::UnixPassword => "authtype_unixpassword",
            AuthType::Password => "authtype_password",
            AuthType::GeneratedPassword => "authtype_generatedpassword",
            AuthType::Webauthn => "authtype_webauthn",
            AuthType::PasswordMfa => "authtype_passwordmfa",
        });

        trace!(claims = ?entry.get_ava_set("claim"), "Applied claims");
        */

        Ok(Identity {
            origin: IdentType::User(IdentUser { entry }),
            session_id: uat.session_id,
            scope,
            limits,
        })
    }

    #[instrument(level = "debug", skip_all)]
    fn process_apit_to_identity(
        &mut self,
        apit: &ApiToken,
        entry: Arc<EntrySealedCommitted>,
        ct: Duration,
    ) -> Result<Identity, OperationError> {
        let valid = ServiceAccount::check_api_token_valid(ct, apit, &entry);

        if !valid {
            // Check_api token logs this.
            return Err(OperationError::SessionExpired);
        }

        let scope = (&apit.purpose).into();

        let limits = Limits::default();
        Ok(Identity {
            origin: IdentType::User(IdentUser { entry }),
            session_id: apit.token_id,
            scope,
            limits,
        })
    }

    #[instrument(level = "debug", skip_all)]
    fn validate_ldap_session(
        &mut self,
        session: &LdapSession,
        ct: Duration,
    ) -> Result<Identity, OperationError> {
        match session {
            LdapSession::UnixBind(uuid) => {
                let anon_entry = self
                    .get_qs_txn()
                    .internal_search_uuid(UUID_ANONYMOUS)
                    .map_err(|e| {
                        admin_error!("Failed to validate ldap session -> {:?}", e);
                        e
                    })?;

                let entry = if *uuid == UUID_ANONYMOUS {
                    anon_entry.clone()
                } else {
                    self.get_qs_txn().internal_search_uuid(*uuid).map_err(|e| {
                        admin_error!("Failed to start auth ldap -> {:?}", e);
                        e
                    })?
                };

                if Account::check_within_valid_time(
                    ct,
                    entry
                        .get_ava_single_datetime(Attribute::AccountValidFrom)
                        .as_ref(),
                    entry
                        .get_ava_single_datetime(Attribute::AccountExpire)
                        .as_ref(),
                ) {
                    // Good to go
                    let limits = Limits::default();
                    let session_id = Uuid::new_v4();

                    Ok(Identity {
                        origin: IdentType::User(IdentUser { entry: anon_entry }),
                        session_id,
                        scope: AccessScope::ReadOnly,
                        limits,
                    })
                } else {
                    // Nope, expired
                    Err(OperationError::SessionExpired)
                }
            }
            LdapSession::UserAuthToken(uat) => self.process_uat_to_identity(uat, ct),
            LdapSession::ApiToken(apit) => {
                let entry = self
                    .get_qs_txn()
                    .internal_search_uuid(apit.account_id)
                    .map_err(|e| {
                        admin_error!("Failed to validate ldap session -> {:?}", e);
                        e
                    })?;

                self.process_apit_to_identity(apit, entry, ct)
            }
        }
    }

    #[instrument(level = "info", skip_all)]
    fn validate_and_parse_sync_token_to_ident(
        &mut self,
        token: Option<&str>,
        ct: Duration,
    ) -> Result<Identity, OperationError> {
        let jwsu = token
            .ok_or_else(|| {
                security_info!("No token provided");
                OperationError::NotAuthenticated
            })
            .and_then(|s| {
                JwsUnverified::from_str(s).map_err(|e| {
                    security_info!(?e, "Unable to decode token");
                    OperationError::NotAuthenticated
                })
            })?;

        let kid = jwsu.get_jwk_kid().ok_or_else(|| {
            security_info!("Token does not contain a valid kid");
            OperationError::NotAuthenticated
        })?;

        let entry = self
            .get_qs_txn()
            .internal_search(filter!(f_eq(
                Attribute::JwsEs256PrivateKey,
                PartialValue::new_iutf8(kid)
            )))
            .and_then(|mut vs| match vs.pop() {
                Some(entry) if vs.is_empty() => Ok(entry),
                _ => {
                    admin_error!(
                        ?kid,
                        "entries was empty, or matched multiple results for kid"
                    );
                    Err(OperationError::NotAuthenticated)
                }
            })?;

        let user_signer = entry
            .get_ava_single_jws_key_es256(Attribute::JwsEs256PrivateKey)
            .ok_or_else(|| {
                admin_error!(
                    ?kid,
                    "A kid was present on entry {} but it does not contain a signing key",
                    entry.get_uuid()
                );
                OperationError::NotAuthenticated
            })?;

        let user_validator = user_signer.get_validator().map_err(|e| {
            security_info!(?e, "Unable to access token verifier");
            OperationError::NotAuthenticated
        })?;

        let sync_token = jwsu
            .validate(&user_validator)
            .map_err(|e| {
                security_info!(?e, "Unable to verify token");
                OperationError::NotAuthenticated
            })
            .map(|t: Jws<ScimSyncToken>| t.into_inner())?;

        let valid = SyncAccount::check_sync_token_valid(ct, &sync_token, &entry);

        if !valid {
            security_info!("Unable to proceed with invalid sync token");
            return Err(OperationError::NotAuthenticated);
        }

        // If scope is not Synchronise, then fail.
        let scope = (&sync_token.purpose).into();

        let limits = Limits::unlimited();
        Ok(Identity {
            origin: IdentType::Synch(entry.get_uuid()),
            session_id: sync_token.token_id,
            scope,
            limits,
        })
    }
}

impl<'a> IdmServerTransaction<'a> for IdmServerAuthTransaction<'a> {
    type QsTransactionType = QueryServerReadTransaction<'a>;

    fn get_qs_txn(&mut self) -> &mut Self::QsTransactionType {
        &mut self.qs_read
    }

    fn get_uat_validator_txn(&self) -> &JwsValidator {
        &self.domain_keys.uat_jwt_validator
    }
}

impl<'a> IdmServerAuthTransaction<'a> {
    #[cfg(test)]
    pub fn is_sessionid_present(&self, sessionid: Uuid) -> bool {
        let session_read = self.sessions.read();
        session_read.contains_key(&sessionid)
    }

    pub fn get_origin(&self) -> &Url {
        #[allow(clippy::unwrap_used)]
        self.webauthn.get_allowed_origins().get(0).unwrap()
    }

    #[instrument(level = "trace", skip(self))]
    pub async fn expire_auth_sessions(&mut self, ct: Duration) {
        // ct is current time - sub the timeout. and then split.
        let expire = ct - Duration::from_secs(AUTH_SESSION_TIMEOUT);
        let split_at = uuid_from_duration(expire, self.sid);
        // Removes older sessions in place.
        let _session_ticket = self.session_ticket.acquire().await;
        let mut session_write = self.sessions.write();
        session_write.split_off_lt(&split_at);
        // expired will now be dropped, and can't be used by future sessions.
        session_write.commit();
    }

    pub async fn auth(
        &mut self,
        ae: &AuthEvent,
        ct: Duration,
        source: Source,
    ) -> Result<AuthResult, OperationError> {
        // Match on the auth event, to see what we need to do.
        match &ae.step {
            AuthEventStep::Init(init) => {
                // lperf_segment!("idm::server::auth<Init>", || {
                // Allocate a session id, based on current time.
                let sessionid = uuid_from_duration(ct, self.sid);

                // Begin the auth procedure!
                // Start a read
                //
                // Actually we may not need this - at the time we issue the auth-init
                // we could generate the uat, the nonce and cache hashes in memory,
                // then this can just be fully without a txn.
                //
                // We do need a txn so that we can process/search and claims
                // or related based on the quality of the provided auth steps
                //
                // We *DO NOT* need a write though, because I think that lock outs
                // and rate limits are *per server* and *in memory* only.
                //
                // Check anything needed? Get the current auth-session-id from request
                // because it associates to the nonce's etc which were all cached.
                let euuid = self.qs_read.name_to_uuid(init.username.as_str())?;

                // Get the first / single entry we expect here ....
                let entry = self.qs_read.internal_search_uuid(euuid)?;

                security_info!(
                    username = %init.username,
                    issue = ?init.issue,
                    privileged = ?init.privileged,
                    uuid = %euuid,
                    "Initiating Authentication Session",
                );

                // Now, convert the Entry to an account - this gives us some stronger
                // typing and functionality so we can assess what auth types can
                // continue, and helps to keep non-needed entry specific data
                // out of the session tree.
                let (account, account_policy) =
                    Account::try_from_entry_with_policy(entry.as_ref(), &mut self.qs_read)?;

                trace!(?account.primary);

                // Intent to take both trees to write.
                let _session_ticket = self.session_ticket.acquire().await;

                // We don't actually check the softlock here. We just initialise
                // it under the write lock we currently have, so that we can validate
                // it once we understand what auth mech we will be using.
                //
                // NOTE: Very careful use of await here to avoid an issue with write.
                let _maybe_slock_ref =
                    account
                        .primary_cred_uuid_and_policy()
                        .map(|(cred_uuid, policy)| {
                            // Acquire the softlock map
                            //
                            // We have no issue calling this with .write here, since we
                            // already hold the session_ticket above.
                            let mut softlock_write = self.softlocks.write();
                            let slock_ref: CredSoftLockMutex =
                                if let Some(slock_ref) = softlock_write.get(&cred_uuid) {
                                    slock_ref.clone()
                                } else {
                                    // Create if not exist, and the cred type supports softlocking.
                                    let slock = Arc::new(Mutex::new(CredSoftLock::new(policy)));
                                    softlock_write.insert(cred_uuid, slock.clone());
                                    slock
                                };
                            softlock_write.commit();
                            slock_ref
                        });

                let asd: AuthSessionData = AuthSessionData {
                    account,
                    account_policy,
                    issue: init.issue,
                    webauthn: self.webauthn,
                    ct,
                    source,
                };

                let (auth_session, state) = AuthSession::new(asd, init.privileged);

                match auth_session {
                    Some(auth_session) => {
                        let mut session_write = self.sessions.write();
                        if session_write.contains_key(&sessionid) {
                            // If we have a session of the same id, return an error (despite how
                            // unlikely this is ...
                            Err(OperationError::InvalidSessionState)
                        } else {
                            session_write.insert(sessionid, Arc::new(Mutex::new(auth_session)));
                            // Debugging: ensure we really inserted ...
                            debug_assert!(session_write.get(&sessionid).is_some());
                            Ok(())
                        }?;
                        session_write.commit();
                    }
                    None => {
                        security_info!("Authentication Session Unable to begin");
                    }
                };

                Ok(AuthResult { sessionid, state })
            } // AuthEventStep::Init
            AuthEventStep::Begin(mech) => {
                let session_read = self.sessions.read();
                // Do we have a session?
                let auth_session_ref = session_read
                    // Why is the session missing?
                    .get(&mech.sessionid)
                    .cloned()
                    .ok_or_else(|| {
                        admin_error!("Invalid Session State (no present session uuid)");
                        OperationError::InvalidSessionState
                    })?;

                let mut auth_session = auth_session_ref.lock().await;

                // Indicate to the session which auth mech we now want to proceed with.
                let auth_result = auth_session.start_session(&mech.mech);

                let is_valid = match auth_session.get_credential_uuid()? {
                    Some(cred_uuid) => {
                        // From the auth_session, determine if the current account
                        // credential that we are using has become softlocked or not.
                        let softlock_read = self.softlocks.read();
                        if let Some(slock_ref) = softlock_read.get(&cred_uuid) {
                            let mut slock = slock_ref.lock().await;
                            // Apply the current time.
                            slock.apply_time_step(ct);
                            // Now check the results
                            slock.is_valid()
                        } else {
                            false
                        }
                    }
                    None => true,
                };

                if is_valid {
                    auth_result
                } else {
                    // Fail the session
                    auth_session.end_session("Account is temporarily locked")
                }
                .map(|aus| AuthResult {
                    sessionid: mech.sessionid,
                    state: aus,
                })
            } // End AuthEventStep::Mech
            AuthEventStep::Cred(creds) => {
                // lperf_segment!("idm::server::auth<Creds>", || {
                // let _session_ticket = self.session_ticket.acquire().await;

                let session_read = self.sessions.read();
                // Do we have a session?
                let auth_session_ref = session_read
                    // Why is the session missing?
                    .get(&creds.sessionid)
                    .cloned()
                    .ok_or_else(|| {
                        admin_error!("Invalid Session State (no present session uuid)");
                        OperationError::InvalidSessionState
                    })?;

                let mut auth_session = auth_session_ref.lock().await;

                let maybe_slock_ref = match auth_session.get_credential_uuid()? {
                    Some(cred_uuid) => {
                        let softlock_read = self.softlocks.read();
                        softlock_read.get(&cred_uuid).cloned()
                    }
                    None => None,
                };

                // From the auth_session, determine if the current account
                // credential that we are using has become softlocked or not.
                let mut maybe_slock = if let Some(s) = maybe_slock_ref.as_ref() {
                    Some(s.lock().await)
                } else {
                    None
                };

                let is_valid = if let Some(ref mut slock) = maybe_slock {
                    // Apply the current time.
                    slock.apply_time_step(ct);
                    // Now check the results
                    slock.is_valid()
                } else {
                    // No slock is present for this cred_uuid
                    true
                };

                if is_valid {
                    // Process the credentials here as required.
                    // Basically throw them at the auth_session and see what
                    // falls out.
                    auth_session
                        .validate_creds(
                            &creds.cred,
                            ct,
                            &self.async_tx,
                            &self.audit_tx,
                            self.webauthn,
                            &self.domain_keys.uat_jwt_signer,
                            self.qs_read.pw_badlist(),
                        )
                        .map(|aus| {
                            // Inspect the result:
                            // if it was a failure, we need to inc the softlock.
                            if let AuthState::Denied(_) = &aus {
                                // Update it.
                                if let Some(ref mut slock) = maybe_slock {
                                    slock.record_failure(ct);
                                }
                            };
                            aus
                        })
                } else {
                    // Fail the session
                    auth_session.end_session("Account is temporarily locked")
                }
                .map(|aus| AuthResult {
                    sessionid: creds.sessionid,
                    state: aus,
                })
            } // End AuthEventStep::Cred
        }
    }

    pub async fn auth_unix(
        &mut self,
        uae: &UnixUserAuthEvent,
        ct: Duration,
    ) -> Result<Option<UnixUserToken>, OperationError> {
        // Get the entry/target we are working on.
        let account = self
            .qs_read
            .internal_search_uuid(uae.target)
            .and_then(|account_entry| {
                UnixUserAccount::try_from_entry_ro(account_entry.as_ref(), &mut self.qs_read)
            })
            .map_err(|e| {
                admin_error!("Failed to start auth unix -> {:?}", e);
                e
            })?;

        if !account.is_within_valid_time(ct) {
            security_info!("Account is not within valid time period");
            return Ok(None);
        }

        let maybe_slock_ref = match account.unix_cred_uuid_and_policy() {
            Some((cred_uuid, policy)) => {
                let softlock_read = self.softlocks.read();
                let slock_ref = match softlock_read.get(&cred_uuid) {
                    Some(slock_ref) => slock_ref.clone(),
                    None => {
                        let _session_ticket = self.session_ticket.acquire().await;
                        let mut softlock_write = self.softlocks.write();
                        let slock = Arc::new(Mutex::new(CredSoftLock::new(policy)));
                        softlock_write.insert(cred_uuid, slock.clone());
                        softlock_write.commit();
                        slock
                    }
                };
                Some(slock_ref)
            }
            None => None,
        };

        let maybe_slock = if let Some(s) = maybe_slock_ref.as_ref() {
            Some(s.lock().await)
        } else {
            None
        };

        let maybe_valid = if let Some(mut slock) = maybe_slock {
            // Apply the current time.
            slock.apply_time_step(ct);
            // Now check the results
            if slock.is_valid() {
                Some(slock)
            } else {
                None
            }
        } else {
            None
        };

        // Validate the unix_pw - this checks the account/cred lock states.
        let res = if let Some(mut slock) = maybe_valid {
            // Account is unlocked, can proceed.
            account
                .verify_unix_credential(uae.cleartext.as_str(), &self.async_tx, ct)
                .map(|res| {
                    if res.is_none() {
                        // Update it.
                        slock.record_failure(ct);
                    };
                    res
                })
        } else {
            // Account is slocked!
            security_info!("Account is softlocked.");
            Ok(None)
        };
        res
    }

    pub async fn token_auth_ldap(
        &mut self,
        lae: &LdapTokenAuthEvent,
        ct: Duration,
    ) -> Result<Option<LdapBoundToken>, OperationError> {
        match self.validate_and_parse_token_to_token(Some(&lae.token), ct)? {
            Token::UserAuthToken(uat) => {
                let spn = uat.spn.clone();
                Ok(Some(LdapBoundToken {
                    session_id: uat.session_id,
                    spn,
                    effective_session: LdapSession::UserAuthToken(uat),
                }))
            }
            Token::ApiToken(apit, entry) => {
                let spn = entry
                    .get_ava_single_proto_string(Attribute::Spn)
                    .ok_or_else(|| {
                        OperationError::InvalidAccountState("Missing attribute: spn".to_string())
                    })?;

                Ok(Some(LdapBoundToken {
                    session_id: apit.token_id,
                    spn,
                    effective_session: LdapSession::ApiToken(apit),
                }))
            }
        }
    }

    pub async fn auth_ldap(
        &mut self,
        lae: &LdapAuthEvent,
        ct: Duration,
    ) -> Result<Option<LdapBoundToken>, OperationError> {
        let account_entry = self.qs_read.internal_search_uuid(lae.target).map_err(|e| {
            admin_error!("Failed to start auth ldap -> {:?}", e);
            e
        })?;

        // if anonymous
        if lae.target == UUID_ANONYMOUS {
            let account = Account::try_from_entry_ro(account_entry.as_ref(), &mut self.qs_read)?;
            // Check if the anon account has been locked.
            if !account.is_within_valid_time(ct) {
                security_info!("Account is not within valid time period");
                return Ok(None);
            }

            let session_id = Uuid::new_v4();
            security_info!(
                "Starting session {} for {} {}",
                session_id,
                account.spn,
                account.uuid
            );

            // Account must be anon, so we can gen the uat.
            Ok(Some(LdapBoundToken {
                session_id,
                spn: account.spn,
                effective_session: LdapSession::UnixBind(UUID_ANONYMOUS),
            }))
        } else {
            if !self.qs_read.d_info.d_ldap_allow_unix_pw_bind {
                security_info!("Bind not allowed through Unix passwords.");
                return Ok(None);
            }
            let account =
                UnixUserAccount::try_from_entry_ro(account_entry.as_ref(), &mut self.qs_read)?;

            if !account.is_within_valid_time(ct) {
                security_info!("Account is not within valid time period");
                return Ok(None);
            }

            let maybe_slock_ref = match account.unix_cred_uuid_and_policy() {
                Some((cred_uuid, policy)) => {
                    let softlock_read = self.softlocks.read();
                    let slock_ref = match softlock_read.get(&cred_uuid) {
                        Some(slock_ref) => slock_ref.clone(),
                        None => {
                            let _session_ticket = self.session_ticket.acquire().await;
                            let mut softlock_write = self.softlocks.write();
                            let slock = Arc::new(Mutex::new(CredSoftLock::new(policy)));
                            softlock_write.insert(cred_uuid, slock.clone());
                            softlock_write.commit();
                            slock
                        }
                    };
                    Ok(slock_ref)
                }
                None => Err(false),
            };

            let maybe_slock = match maybe_slock_ref.as_ref() {
                Ok(s) => Ok(s.lock().await),
                Err(cred_state) => Err(cred_state),
            };

            let maybe_valid = match maybe_slock {
                Ok(mut slock) => {
                    // Apply the current time.
                    slock.apply_time_step(ct);
                    // Now check the results
                    if slock.is_valid() {
                        Ok(slock)
                    } else {
                        Err(true)
                    }
                }
                Err(cred_state) => Err(*cred_state),
            };

            match maybe_valid {
                Ok(mut slock) => {
                    if account
                        .verify_unix_credential(lae.cleartext.as_str(), &self.async_tx, ct)?
                        .is_some()
                    {
                        let session_id = Uuid::new_v4();
                        security_info!(
                            "Starting session {} for {} {}",
                            session_id,
                            account.spn,
                            account.uuid
                        );

                        Ok(Some(LdapBoundToken {
                            spn: account.spn,
                            session_id,
                            effective_session: LdapSession::UnixBind(account.uuid),
                        }))
                    } else {
                        // PW failure, update softlock.
                        slock.record_failure(ct);
                        Ok(None)
                    }
                }
                Err(true) => {
                    security_info!("Account is softlocked.");
                    Ok(None)
                }
                Err(false) => {
                    security_info!("Account does not have a configured posix password.");
                    Ok(None)
                }
            }
        }
    }

    pub fn commit(self) -> Result<(), OperationError> {
        /*
        lperf_trace_segment!("idm::server::IdmServerAuthTransaction::commit", || {
            self.sessions.commit();
            Ok(())
        })*/
        Ok(())
    }
}

impl<'a> IdmServerTransaction<'a> for IdmServerProxyReadTransaction<'a> {
    type QsTransactionType = QueryServerReadTransaction<'a>;

    fn get_qs_txn(&mut self) -> &mut Self::QsTransactionType {
        &mut self.qs_read
    }

    fn get_uat_validator_txn(&self) -> &JwsValidator {
        &self.domain_keys.uat_jwt_validator
    }
}

impl<'a> IdmServerProxyReadTransaction<'a> {
    pub fn get_radiusauthtoken(
        &mut self,
        rate: &RadiusAuthTokenEvent,
        ct: Duration,
    ) -> Result<RadiusAuthToken, OperationError> {
        let account = self
            .qs_read
            .impersonate_search_ext_uuid(rate.target, &rate.ident)
            .and_then(|account_entry| {
                RadiusAccount::try_from_entry_reduced(&account_entry, &mut self.qs_read)
            })
            .map_err(|e| {
                admin_error!("Failed to start radius auth token {:?}", e);
                e
            })?;

        account.to_radiusauthtoken(ct)
    }

    pub fn get_unixusertoken(
        &mut self,
        uute: &UnixUserTokenEvent,
        ct: Duration,
    ) -> Result<UnixUserToken, OperationError> {
        let account = self
            .qs_read
            .impersonate_search_uuid(uute.target, &uute.ident)
            .and_then(|account_entry| {
                UnixUserAccount::try_from_entry_ro(&account_entry, &mut self.qs_read)
            })
            .map_err(|e| {
                admin_error!("Failed to start unix user token -> {:?}", e);
                e
            })?;

        account.to_unixusertoken(ct)
    }

    pub fn get_unixgrouptoken(
        &mut self,
        uute: &UnixGroupTokenEvent,
    ) -> Result<UnixGroupToken, OperationError> {
        let group = self
            .qs_read
            .impersonate_search_ext_uuid(uute.target, &uute.ident)
            .and_then(|e| UnixGroup::try_from_entry_reduced(&e))
            .map_err(|e| {
                admin_error!("Failed to start unix group token {:?}", e);
                e
            })?;
        group.to_unixgrouptoken()
    }

    pub fn get_credentialstatus(
        &mut self,
        cse: &CredentialStatusEvent,
    ) -> Result<CredentialStatus, OperationError> {
        let account = self
            .qs_read
            .impersonate_search_ext_uuid(cse.target, &cse.ident)
            .and_then(|account_entry| {
                Account::try_from_entry_reduced(&account_entry, &mut self.qs_read)
            })
            .map_err(|e| {
                admin_error!("Failed to search account {:?}", e);
                e
            })?;

        account.to_credentialstatus()
    }

    pub fn get_backup_codes(
        &mut self,
        rbce: &ReadBackupCodeEvent,
    ) -> Result<BackupCodesView, OperationError> {
        let account = self
            .qs_read
            .impersonate_search_ext_uuid(rbce.target, &rbce.ident)
            .and_then(|account_entry| {
                Account::try_from_entry_reduced(&account_entry, &mut self.qs_read)
            })
            .map_err(|e| {
                admin_error!("Failed to search account {:?}", e);
                e
            })?;

        account.to_backupcodesview()
    }
}

impl<'a> IdmServerTransaction<'a> for IdmServerProxyWriteTransaction<'a> {
    type QsTransactionType = QueryServerWriteTransaction<'a>;

    fn get_qs_txn(&mut self) -> &mut Self::QsTransactionType {
        &mut self.qs_write
    }

    fn get_uat_validator_txn(&self) -> &JwsValidator {
        &self.domain_keys.uat_jwt_validator
    }
}

impl<'a> IdmServerProxyWriteTransaction<'a> {
    pub(crate) fn crypto_policy(&self) -> &CryptoPolicy {
        self.crypto_policy
    }

    pub fn get_origin(&self) -> &Url {
        #[allow(clippy::unwrap_used)]
        self.webauthn.get_allowed_origins().get(0).unwrap()
    }

    fn check_password_quality(
        &mut self,
        cleartext: &str,
        related_inputs: &[&str],
    ) -> Result<(), OperationError> {
        // password strength and badlisting is always global, rather than per-pw-policy.
        // pw-policy as check on the account is about requirements for mfa for example.
        //

        // is the password at least 10 char?
        if cleartext.len() < PW_MIN_LENGTH {
            return Err(OperationError::PasswordQuality(vec![
                PasswordFeedback::TooShort(PW_MIN_LENGTH),
            ]));
        }

        // does the password pass zxcvbn?

        let entropy = zxcvbn::zxcvbn(cleartext, related_inputs).map_err(|e| {
            admin_error!("zxcvbn check failure (password empty?) {:?}", e);
            OperationError::PasswordQuality(vec![PasswordFeedback::TooShort(PW_MIN_LENGTH)])
        })?;

        // Unix PW's are a single factor, so we enforce good pws
        if entropy.score() < 4 {
            // The password is too week as per:
            // https://docs.rs/zxcvbn/2.0.0/zxcvbn/struct.Entropy.html
            let feedback: zxcvbn::feedback::Feedback = entropy
                .feedback()
                .as_ref()
                .ok_or(OperationError::InvalidState)
                .map(|v| v.clone())
                .map_err(|e| {
                    security_info!("zxcvbn returned no feedback when score < 3");
                    e
                })?;

            security_info!(?feedback, "pw quality feedback");

            // return Err(OperationError::PasswordTooWeak(feedback))
            // return Err(OperationError::PasswordTooWeak);
            return Err(OperationError::PasswordQuality(vec![
                PasswordFeedback::BadListed,
            ]));
        }

        // check a password badlist to eliminate more content
        // we check the password as "lower case" to help eliminate possibilities
        // also, when pw_badlist_cache is read from DB, it is read as Value (iutf8 lowercase)
        if self
            .qs_write
            .pw_badlist()
            .contains(&cleartext.to_lowercase())
        {
            security_info!("Password found in badlist, rejecting");
            Err(OperationError::PasswordQuality(vec![
                PasswordFeedback::BadListed,
            ]))
        } else {
            Ok(())
        }
    }

    pub(crate) fn target_to_account(&mut self, target: Uuid) -> Result<Account, OperationError> {
        // Get the account
        let account = self
            .qs_write
            .internal_search_uuid(target)
            .and_then(|account_entry| {
                Account::try_from_entry_rw(&account_entry, &mut self.qs_write)
            })
            .map_err(|e| {
                admin_error!("Failed to search account {:?}", e);
                e
            })?;
        // Ask if tis all good - this step checks pwpolicy and such

        // Deny the change if the account is anonymous!
        if account.is_anonymous() {
            admin_warn!("Unable to convert anonymous to account during write txn");
            Err(OperationError::SystemProtectedObject)
        } else {
            Ok(account)
        }
    }

    #[cfg(test)]
    pub(crate) fn set_account_password(
        &mut self,
        pce: &PasswordChangeEvent,
    ) -> Result<(), OperationError> {
        let account = self.target_to_account(pce.target)?;

        // Get the modifications we *want* to perform.
        let modlist = account
            .gen_password_mod(pce.cleartext.as_str(), self.crypto_policy)
            .map_err(|e| {
                admin_error!("Failed to generate password mod {:?}", e);
                e
            })?;
        trace!(?modlist, "processing change");

        // Check with the QS if we would be ALLOWED to do this change.

        let me = self
            .qs_write
            .impersonate_modify_gen_event(
                // Filter as executed
                &filter!(f_eq(Attribute::Uuid, PartialValue::Uuid(pce.target))),
                // Filter as intended (acp)
                &filter_all!(f_eq(Attribute::Uuid, PartialValue::Uuid(pce.target))),
                &modlist,
                &pce.ident,
            )
            .map_err(|e| {
                request_error!(error = ?e);
                e
            })?;

        let mp = self
            .qs_write
            .modify_pre_apply(&me)
            .and_then(|opt_mp| opt_mp.ok_or(OperationError::NoMatchingEntries))
            .map_err(|e| {
                request_error!(error = ?e);
                e
            })?;

        // If we got here, then pre-apply succeeded, and that means access control
        // passed. Now we can do the extra checks.

        // Check the password quality.
        // Ask if tis all good - this step checks pwpolicy and such

        self.check_password_quality(pce.cleartext.as_str(), account.related_inputs().as_slice())
            .map_err(|e| {
                request_error!(err = ?e, "check_password_quality");
                e
            })?;

        // And actually really apply it now.
        self.qs_write.modify_apply(mp).map_err(|e| {
            request_error!(error = ?e);
            e
        })?;

        Ok(())
    }

    pub fn set_unix_account_password(
        &mut self,
        pce: &UnixPasswordChangeEvent,
    ) -> Result<(), OperationError> {
        // Get the account
        let account = self
            .qs_write
            .internal_search_uuid(pce.target)
            .and_then(|account_entry| {
                // Assert the account is unix and valid.
                UnixUserAccount::try_from_entry_rw(&account_entry, &mut self.qs_write)
            })
            .map_err(|e| {
                admin_error!("Failed to start set unix account password {:?}", e);
                e
            })?;
        // Ask if tis all good - this step checks pwpolicy and such

        // Deny the change if the account is anonymous!
        if account.is_anonymous() {
            return Err(OperationError::SystemProtectedObject);
        }

        let modlist = account
            .gen_password_mod(pce.cleartext.as_str(), self.crypto_policy)
            .map_err(|e| {
                admin_error!(?e, "Unable to generate password change modlist");
                e
            })?;
        trace!(?modlist, "processing change");

        // Check with the QS if we would be ALLOWED to do this change.

        let me = self
            .qs_write
            .impersonate_modify_gen_event(
                // Filter as executed
                &filter!(f_eq(Attribute::Uuid, PartialValue::Uuid(pce.target))),
                // Filter as intended (acp)
                &filter_all!(f_eq(Attribute::Uuid, PartialValue::Uuid(pce.target))),
                &modlist,
                &pce.ident,
            )
            .map_err(|e| {
                request_error!(error = ?e);
                e
            })?;

        let mp = self
            .qs_write
            .modify_pre_apply(&me)
            .and_then(|opt_mp| opt_mp.ok_or(OperationError::NoMatchingEntries))
            .map_err(|e| {
                request_error!(error = ?e);
                e
            })?;

        // If we got here, then pre-apply succeeded, and that means access control
        // passed. Now we can do the extra checks.

        self.check_password_quality(pce.cleartext.as_str(), account.related_inputs().as_slice())
            .map_err(|e| {
                admin_error!(?e, "Failed to checked password quality");
                e
            })?;

        // And actually really apply it now.
        self.qs_write.modify_apply(mp).map_err(|e| {
            request_error!(error = ?e);
            e
        })?;

        Ok(())
    }

    #[instrument(level = "debug", skip_all)]
    pub fn recover_account(
        &mut self,
        name: &str,
        cleartext: Option<&str>,
    ) -> Result<String, OperationError> {
        // name to uuid
        let target = self.qs_write.name_to_uuid(name).map_err(|e| {
            admin_error!(?e, "name to uuid failed");
            e
        })?;

        let cleartext = cleartext
            .map(|s| s.to_string())
            .unwrap_or_else(password_from_random);

        let ncred = Credential::new_generatedpassword_only(self.crypto_policy, &cleartext)
            .map_err(|e| {
                admin_error!("Unable to generate password mod {:?}", e);
                e
            })?;
        let vcred = Value::new_credential("primary", ncred);
        // We need to remove other credentials too.
        let modlist = ModifyList::new_list(vec![
            m_purge(Attribute::PassKeys),
            m_purge(Attribute::PrimaryCredential),
            Modify::Present(Attribute::PrimaryCredential.into(), vcred),
        ]);

        trace!(?modlist, "processing change");

        self.qs_write
            .internal_modify(
                // Filter as executed
                &filter!(f_eq(Attribute::Uuid, PartialValue::Uuid(target))),
                &modlist,
            )
            .map_err(|e| {
                request_error!(error = ?e);
                e
            })?;

        Ok(cleartext)
    }

    #[instrument(level = "debug", skip_all)]
    pub fn regenerate_radius_secret(
        &mut self,
        rrse: &RegenerateRadiusSecretEvent,
    ) -> Result<String, OperationError> {
        let account = self.target_to_account(rrse.target)?;

        // Difference to the password above, this is intended to be read/copied
        // by a human wiath a keyboard in some cases.
        let cleartext = readable_password_from_random();

        // Create a modlist from the change.
        let modlist = account
            .regenerate_radius_secret_mod(cleartext.as_str())
            .map_err(|e| {
                admin_error!("Unable to generate radius secret mod {:?}", e);
                e
            })?;
        trace!(?modlist, "processing change");

        // Apply it.
        self.qs_write
            .impersonate_modify(
                // Filter as executed
                &filter!(f_eq(Attribute::Uuid, PartialValue::Uuid(rrse.target))),
                // Filter as intended (acp)
                &filter_all!(f_eq(Attribute::Uuid, PartialValue::Uuid(rrse.target))),
                &modlist,
                // Provide the event to impersonate
                &rrse.ident,
            )
            .map_err(|e| {
                request_error!(error = ?e);
                e
            })
            .map(|_| cleartext)
    }

    // -- delayed action processing --
    #[instrument(level = "debug", skip_all)]
    fn process_pwupgrade(&mut self, pwu: &PasswordUpgrade) -> Result<(), OperationError> {
        // get the account
        let account = self.target_to_account(pwu.target_uuid)?;

        info!(session_id = %pwu.target_uuid, "Processing password hash upgrade");

        let maybe_modlist = account
            .gen_password_upgrade_mod(pwu.existing_password.as_str(), self.crypto_policy)
            .map_err(|e| {
                admin_error!("Unable to generate password mod {:?}", e);
                e
            })?;

        if let Some(modlist) = maybe_modlist {
            self.qs_write.internal_modify(
                &filter_all!(f_eq(Attribute::Uuid, PartialValue::Uuid(pwu.target_uuid))),
                &modlist,
            )
        } else {
            // No action needed, it's probably been changed/updated already.
            Ok(())
        }
    }

    #[instrument(level = "debug", skip_all)]
    fn process_unixpwupgrade(&mut self, pwu: &UnixPasswordUpgrade) -> Result<(), OperationError> {
        info!(session_id = %pwu.target_uuid, "Processing unix password hash upgrade");

        let account = self
            .qs_write
            .internal_search_uuid(pwu.target_uuid)
            .and_then(|account_entry| {
                UnixUserAccount::try_from_entry_rw(&account_entry, &mut self.qs_write)
            })
            .map_err(|e| {
                admin_error!("Failed to start unix pw upgrade -> {:?}", e);
                e
            })?;

        let maybe_modlist =
            account.gen_password_upgrade_mod(pwu.existing_password.as_str(), self.crypto_policy)?;

        if let Some(modlist) = maybe_modlist {
            self.qs_write.internal_modify(
                &filter_all!(f_eq(Attribute::Uuid, PartialValue::Uuid(pwu.target_uuid))),
                &modlist,
            )
        } else {
            // No action needed, it's probably been changed/updated already.
            Ok(())
        }
    }

    #[instrument(level = "debug", skip_all)]
    pub(crate) fn process_webauthncounterinc(
        &mut self,
        wci: &WebauthnCounterIncrement,
    ) -> Result<(), OperationError> {
        info!(session_id = %wci.target_uuid, "Processing webauthn counter increment");

        let mut account = self.target_to_account(wci.target_uuid)?;

        // Generate an optional mod and then attempt to apply it.
        let opt_modlist = account
            .gen_webauthn_counter_mod(&wci.auth_result)
            .map_err(|e| {
                admin_error!("Unable to generate webauthn counter mod {:?}", e);
                e
            })?;

        if let Some(modlist) = opt_modlist {
            self.qs_write.internal_modify(
                &filter_all!(f_eq(Attribute::Uuid, PartialValue::Uuid(wci.target_uuid))),
                &modlist,
            )
        } else {
            // No mod needed.
            trace!("No modification required");
            Ok(())
        }
    }

    #[instrument(level = "debug", skip_all)]
    pub(crate) fn process_backupcoderemoval(
        &mut self,
        bcr: &BackupCodeRemoval,
    ) -> Result<(), OperationError> {
        info!(session_id = %bcr.target_uuid, "Processing backup code removal");

        let account = self.target_to_account(bcr.target_uuid)?;
        // Generate an optional mod and then attempt to apply it.
        let modlist = account
            .invalidate_backup_code_mod(&bcr.code_to_remove)
            .map_err(|e| {
                admin_error!("Unable to generate backup code mod {:?}", e);
                e
            })?;

        self.qs_write.internal_modify(
            &filter_all!(f_eq(Attribute::Uuid, PartialValue::Uuid(bcr.target_uuid))),
            &modlist,
        )
    }

    #[instrument(level = "debug", skip_all)]
    pub(crate) fn process_authsessionrecord(
        &mut self,
        asr: &AuthSessionRecord,
    ) -> Result<(), OperationError> {
        // We have to get the entry so we can work out if we need to expire any of it's sessions.
        let state = match asr.expiry {
            Some(e) => SessionState::ExpiresAt(e),
            None => SessionState::NeverExpires,
        };

        let session = Value::Session(
            asr.session_id,
            Session {
                label: asr.label.clone(),
                state,
                // Need the other inner bits?
                // for the gracewindow.
                issued_at: asr.issued_at,
                // Who actually created this?
                issued_by: asr.issued_by.clone(),
                // Which credential was used?
                cred_id: asr.cred_id,
                // What is the access scope of this session? This is
                // for auditing purposes.
                scope: asr.scope,
            },
        );

        info!(session_id = %asr.session_id, "Persisting auth session");

        // modify the account to put the session onto it.
        let modlist = ModifyList::new_append(Attribute::UserAuthTokenSession, session);

        self.qs_write
            .internal_modify(
                &filter!(f_eq(Attribute::Uuid, PartialValue::Uuid(asr.target_uuid))),
                &modlist,
            )
            .map_err(|e| {
                admin_error!("Failed to persist user auth token {:?}", e);
                e
            })
        // Done!
    }

    #[instrument(level = "debug", skip_all)]
    pub fn process_delayedaction(
        &mut self,
        da: DelayedAction,
        _ct: Duration,
    ) -> Result<(), OperationError> {
        match da {
            DelayedAction::PwUpgrade(pwu) => self.process_pwupgrade(&pwu),
            DelayedAction::UnixPwUpgrade(upwu) => self.process_unixpwupgrade(&upwu),
            DelayedAction::WebauthnCounterIncrement(wci) => self.process_webauthncounterinc(&wci),
            DelayedAction::BackupCodeRemoval(bcr) => self.process_backupcoderemoval(&bcr),
            DelayedAction::AuthSessionRecord(asr) => self.process_authsessionrecord(&asr),
        }
    }

    #[instrument(level = "debug", skip_all)]
    pub fn commit(mut self) -> Result<(), OperationError> {
        if self.qs_write.get_changed_ouath2() {
            self.qs_write
                .get_oauth2rs_set()
                .and_then(|oauth2rs_set| self.oauth2rs.reload(oauth2rs_set))?;
        }
        if self.qs_write.get_changed_domain() {
            // reload token_key?
            self.qs_write
                .get_domain_fernet_private_key()
                .and_then(|token_key| {
                    Fernet::new(&token_key).ok_or_else(|| {
                        admin_error!("Failed to generate token_enc_key");
                        OperationError::InvalidState
                    })
                })
                .map(|new_handle| {
                    self.domain_keys.token_enc_key = new_handle;
                })?;
            self.qs_write
                .get_domain_es256_private_key()
                .and_then(|key_der| {
                    JwsSigner::from_es256_der(&key_der).map_err(|e| {
                        admin_error!("Failed to generate uat_jwt_signer - {:?}", e);
                        OperationError::InvalidState
                    })
                })
                .and_then(|signer| {
                    signer
                        .get_validator()
                        .map_err(|e| {
                            admin_error!("Failed to generate uat_jwt_validator - {:?}", e);
                            OperationError::InvalidState
                        })
                        .map(|validator| (signer, validator))
                })
                .map(|(new_signer, new_validator)| {
                    self.domain_keys.uat_jwt_signer = new_signer;
                    self.domain_keys.uat_jwt_validator = new_validator;
                })?;
            self.qs_write
                .get_domain_cookie_key()
                .map(|new_cookie_key| {
                    self.domain_keys.cookie_key = new_cookie_key;
                })?;
            // If the domain name has changed, we need to update rp-id in
            // webauthn rs
            //
            // TODO: I'm not sure actually. because on a domain rename we
            // might need to update origin too. So this gets a bit tricky.
            // we might actually need to *not* reload here, and then let the
            // admin do it inline with their configs too.
        }
        // Commit everything.
        self.oauth2rs.commit();
        self.domain_keys.commit();
        self.cred_update_sessions.commit();
        trace!("cred_update_session.commit");
        self.qs_write.commit()
    }
}

// Need tests of the sessions and the auth ...

#[cfg(test)]
mod tests {
    use std::convert::TryFrom;
    use std::time::Duration;

    use kanidm_proto::v1::{AuthAllowed, AuthIssueSession, AuthMech, OperationError};
    use time::OffsetDateTime;
    use uuid::Uuid;

    use crate::credential::{Credential, Password};
    use crate::idm::account::DestroySessionTokenEvent;
    use crate::idm::audit::AuditEvent;
    use crate::idm::delayed::{AuthSessionRecord, DelayedAction};
    use crate::idm::event::{AuthEvent, AuthResult};
    use crate::idm::event::{
        PasswordChangeEvent, RadiusAuthTokenEvent, RegenerateRadiusSecretEvent,
        UnixGroupTokenEvent, UnixPasswordChangeEvent, UnixUserAuthEvent, UnixUserTokenEvent,
    };
    use crate::idm::server::{IdmServer, IdmServerTransaction, Token};
    use crate::idm::AuthState;
    use crate::modify::{Modify, ModifyList};
    use crate::prelude::*;
    use crate::value::SessionState;
    use kanidm_lib_crypto::CryptoPolicy;

    const TEST_PASSWORD: &str = "ntaoeuntnaoeuhraohuercahu😍";
    const TEST_PASSWORD_INC: &str = "ntaoentu nkrcgaeunhibwmwmqj;k wqjbkx ";
    const TEST_CURRENT_TIME: u64 = 6000;

    #[idm_test]
    async fn test_idm_anonymous_auth(idms: &IdmServer, _idms_delayed: &IdmServerDelayed) {
        // Start and test anonymous auth.
        let mut idms_auth = idms.auth().await;
        // Send the initial auth event for initialising the session
        let anon_init = AuthEvent::anonymous_init();
        // Expect success
        let r1 = idms_auth
            .auth(
                &anon_init,
                Duration::from_secs(TEST_CURRENT_TIME),
                Source::Internal,
            )
            .await;
        /* Some weird lifetime things happen here ... */

        let sid = match r1 {
            Ok(ar) => {
                let AuthResult { sessionid, state } = ar;
                match state {
                    AuthState::Choose(mut conts) => {
                        // Should only be one auth mech
                        assert!(conts.len() == 1);
                        // And it should be anonymous
                        let m = conts.pop().expect("Should not fail");
                        assert!(m == AuthMech::Anonymous);
                    }
                    _ => {
                        error!("A critical error has occurred! We have a non-continue result!");
                        panic!();
                    }
                };
                // Now pass back the sessionid, we are good to continue.
                sessionid
            }
            Err(e) => {
                // Should not occur!
                error!("A critical error has occurred! {:?}", e);
                panic!();
            }
        };

        debug!("sessionid is ==> {:?}", sid);

        idms_auth.commit().expect("Must not fail");

        let mut idms_auth = idms.auth().await;
        let anon_begin = AuthEvent::begin_mech(sid, AuthMech::Anonymous);

        let r2 = idms_auth
            .auth(
                &anon_begin,
                Duration::from_secs(TEST_CURRENT_TIME),
                Source::Internal,
            )
            .await;
        debug!("r2 ==> {:?}", r2);

        match r2 {
            Ok(ar) => {
                let AuthResult {
                    sessionid: _,
                    state,
                } = ar;

                match state {
                    AuthState::Continue(allowed) => {
                        // Check the uat.
                        assert!(allowed.len() == 1);
                        assert!(allowed.first() == Some(&AuthAllowed::Anonymous));
                    }
                    _ => {
                        error!("A critical error has occurred! We have a non-continue result!");
                        panic!();
                    }
                }
            }
            Err(e) => {
                error!("A critical error has occurred! {:?}", e);
                // Should not occur!
                panic!();
            }
        };

        idms_auth.commit().expect("Must not fail");

        let mut idms_auth = idms.auth().await;
        // Now send the anonymous request, given the session id.
        let anon_step = AuthEvent::cred_step_anonymous(sid);

        // Expect success
        let r2 = idms_auth
            .auth(
                &anon_step,
                Duration::from_secs(TEST_CURRENT_TIME),
                Source::Internal,
            )
            .await;
        debug!("r2 ==> {:?}", r2);

        match r2 {
            Ok(ar) => {
                let AuthResult {
                    sessionid: _,
                    state,
                } = ar;

                match state {
                    AuthState::Success(_uat, AuthIssueSession::Token) => {
                        // Check the uat.
                    }
                    _ => {
                        error!("A critical error has occurred! We have a non-succcess result!");
                        panic!();
                    }
                }
            }
            Err(e) => {
                error!("A critical error has occurred! {:?}", e);
                // Should not occur!
                panic!();
            }
        };

        idms_auth.commit().expect("Must not fail");
    }

    // Test sending anonymous but with no session init.
    #[idm_test]
    async fn test_idm_anonymous_auth_invalid_states(
        idms: &IdmServer,
        _idms_delayed: &IdmServerDelayed,
    ) {
        {
            let mut idms_auth = idms.auth().await;
            let sid = Uuid::new_v4();
            let anon_step = AuthEvent::cred_step_anonymous(sid);

            // Expect failure
            let r2 = idms_auth
                .auth(
                    &anon_step,
                    Duration::from_secs(TEST_CURRENT_TIME),
                    Source::Internal,
                )
                .await;
            debug!("r2 ==> {:?}", r2);

            match r2 {
                Ok(_) => {
                    error!("Auth state machine not correctly enforced!");
                    panic!();
                }
                Err(e) => match e {
                    OperationError::InvalidSessionState => {}
                    _ => panic!(),
                },
            };
        }
    }

    async fn init_admin_w_password(idms: &IdmServer, pw: &str) -> Result<Uuid, OperationError> {
        let p = CryptoPolicy::minimum();
        let cred = Credential::new_password_only(&p, pw)?;
        let cred_id = cred.uuid;
        let v_cred = Value::new_credential("primary", cred);
        let mut idms_write = idms.proxy_write(duration_from_epoch_now()).await;

        // now modify and provide a primary credential.
        let me_inv_m = ModifyEvent::new_internal_invalid(
            filter!(f_eq(Attribute::Name, PartialValue::new_iname("admin"))),
            ModifyList::new_list(vec![Modify::Present(
                Attribute::PrimaryCredential.into(),
                v_cred,
            )]),
        );
        // go!
        assert!(idms_write.qs_write.modify(&me_inv_m).is_ok());

        idms_write.commit().map(|()| cred_id)
    }

    async fn init_admin_authsession_sid(idms: &IdmServer, ct: Duration, name: &str) -> Uuid {
        let mut idms_auth = idms.auth().await;
        let admin_init = AuthEvent::named_init(name);

        let r1 = idms_auth.auth(&admin_init, ct, Source::Internal).await;
        let ar = r1.unwrap();
        let AuthResult { sessionid, state } = ar;

        assert!(matches!(state, AuthState::Choose(_)));

        // Now push that we want the Password Mech.
        let admin_begin = AuthEvent::begin_mech(sessionid, AuthMech::Password);

        let r2 = idms_auth.auth(&admin_begin, ct, Source::Internal).await;
        let ar = r2.unwrap();
        let AuthResult { sessionid, state } = ar;

        match state {
            AuthState::Continue(_) => {}
            _ => {
                error!("Sessions was not initialised");
                panic!();
            }
        };

        idms_auth.commit().expect("Must not fail");

        sessionid
    }

    async fn check_admin_password(idms: &IdmServer, pw: &str) -> String {
        let sid =
            init_admin_authsession_sid(idms, Duration::from_secs(TEST_CURRENT_TIME), "admin").await;

        let mut idms_auth = idms.auth().await;
        let anon_step = AuthEvent::cred_step_password(sid, pw);

        // Expect success
        let r2 = idms_auth
            .auth(
                &anon_step,
                Duration::from_secs(TEST_CURRENT_TIME),
                Source::Internal,
            )
            .await;
        debug!("r2 ==> {:?}", r2);

        let token = match r2 {
            Ok(ar) => {
                let AuthResult {
                    sessionid: _,
                    state,
                } = ar;

                match state {
                    AuthState::Success(token, AuthIssueSession::Token) => {
                        // Check the uat.
                        token
                    }
                    _ => {
                        error!("A critical error has occurred! We have a non-succcess result!");
                        panic!();
                    }
                }
            }
            Err(e) => {
                error!("A critical error has occurred! {:?}", e);
                // Should not occur!
                panic!();
            }
        };

        idms_auth.commit().expect("Must not fail");

        token
    }

    #[idm_test]
    async fn test_idm_simple_password_auth(idms: &IdmServer, idms_delayed: &mut IdmServerDelayed) {
        init_admin_w_password(idms, TEST_PASSWORD)
            .await
            .expect("Failed to setup admin account");
        check_admin_password(idms, TEST_PASSWORD).await;

        // Clear our the session record
        let da = idms_delayed.try_recv().expect("invalid");
        assert!(matches!(da, DelayedAction::AuthSessionRecord(_)));
        idms_delayed.check_is_empty_or_panic();
    }

    #[idm_test]
    async fn test_idm_simple_password_spn_auth(
        idms: &IdmServer,
        idms_delayed: &mut IdmServerDelayed,
    ) {
        init_admin_w_password(idms, TEST_PASSWORD)
            .await
            .expect("Failed to setup admin account");

        let sid = init_admin_authsession_sid(
            idms,
            Duration::from_secs(TEST_CURRENT_TIME),
            "admin@example.com",
        )
        .await;

        let mut idms_auth = idms.auth().await;
        let anon_step = AuthEvent::cred_step_password(sid, TEST_PASSWORD);

        // Expect success
        let r2 = idms_auth
            .auth(
                &anon_step,
                Duration::from_secs(TEST_CURRENT_TIME),
                Source::Internal,
            )
            .await;
        debug!("r2 ==> {:?}", r2);

        match r2 {
            Ok(ar) => {
                let AuthResult {
                    sessionid: _,
                    state,
                } = ar;
                match state {
                    AuthState::Success(_uat, AuthIssueSession::Token) => {
                        // Check the uat.
                    }
                    _ => {
                        error!("A critical error has occurred! We have a non-succcess result!");
                        panic!();
                    }
                }
            }
            Err(e) => {
                error!("A critical error has occurred! {:?}", e);
                // Should not occur!
                panic!();
            }
        };

        // Clear our the session record
        let da = idms_delayed.try_recv().expect("invalid");
        assert!(matches!(da, DelayedAction::AuthSessionRecord(_)));
        idms_delayed.check_is_empty_or_panic();

        idms_auth.commit().expect("Must not fail");
    }

    #[idm_test(audit)]
    async fn test_idm_simple_password_invalid(
        idms: &IdmServer,
        _idms_delayed: &IdmServerDelayed,
        idms_audit: &mut IdmServerAudit,
    ) {
        init_admin_w_password(idms, TEST_PASSWORD)
            .await
            .expect("Failed to setup admin account");
        let sid =
            init_admin_authsession_sid(idms, Duration::from_secs(TEST_CURRENT_TIME), "admin").await;
        let mut idms_auth = idms.auth().await;
        let anon_step = AuthEvent::cred_step_password(sid, TEST_PASSWORD_INC);

        // Expect success
        let r2 = idms_auth
            .auth(
                &anon_step,
                Duration::from_secs(TEST_CURRENT_TIME),
                Source::Internal,
            )
            .await;
        debug!("r2 ==> {:?}", r2);

        match r2 {
            Ok(ar) => {
                let AuthResult {
                    sessionid: _,
                    state,
                } = ar;
                match state {
                    AuthState::Denied(_reason) => {
                        // Check the uat.
                    }
                    _ => {
                        error!("A critical error has occurred! We have a non-denied result!");
                        panic!();
                    }
                }
            }
            Err(e) => {
                error!("A critical error has occurred! {:?}", e);
                // Should not occur!
                panic!();
            }
        };

        // There should be a queued audit event
        match idms_audit.audit_rx().try_recv() {
            Ok(AuditEvent::AuthenticationDenied { .. }) => {}
            _ => assert!(false),
        }

        idms_auth.commit().expect("Must not fail");
    }

    #[idm_test]
    async fn test_idm_simple_password_reset(idms: &IdmServer, _idms_delayed: &IdmServerDelayed) {
        let pce = PasswordChangeEvent::new_internal(UUID_ADMIN, TEST_PASSWORD);

        let mut idms_prox_write = idms.proxy_write(duration_from_epoch_now()).await;
        assert!(idms_prox_write.set_account_password(&pce).is_ok());
        assert!(idms_prox_write.set_account_password(&pce).is_ok());
        assert!(idms_prox_write.commit().is_ok());
    }

    #[idm_test]
    async fn test_idm_anonymous_set_password_denied(
        idms: &IdmServer,
        _idms_delayed: &IdmServerDelayed,
    ) {
        let pce = PasswordChangeEvent::new_internal(UUID_ANONYMOUS, TEST_PASSWORD);

        let mut idms_prox_write = idms.proxy_write(duration_from_epoch_now()).await;
        assert!(idms_prox_write.set_account_password(&pce).is_err());
        assert!(idms_prox_write.commit().is_ok());
    }

    #[idm_test]
    async fn test_idm_regenerate_radius_secret(idms: &IdmServer, _idms_delayed: &IdmServerDelayed) {
        let mut idms_prox_write = idms.proxy_write(duration_from_epoch_now()).await;
        let rrse = RegenerateRadiusSecretEvent::new_internal(UUID_ADMIN);

        // Generates a new credential when none exists
        let r1 = idms_prox_write
            .regenerate_radius_secret(&rrse)
            .expect("Failed to reset radius credential 1");
        // Regenerates and overwrites the radius credential
        let r2 = idms_prox_write
            .regenerate_radius_secret(&rrse)
            .expect("Failed to reset radius credential 2");
        assert!(r1 != r2);
    }

    #[idm_test]
    async fn test_idm_radius_secret_rejected_from_account_credential(
        idms: &IdmServer,
        _idms_delayed: &IdmServerDelayed,
    ) {
        let mut idms_prox_write = idms.proxy_write(duration_from_epoch_now()).await;
        let rrse = RegenerateRadiusSecretEvent::new_internal(UUID_ADMIN);

        let r1 = idms_prox_write
            .regenerate_radius_secret(&rrse)
            .expect("Failed to reset radius credential 1");

        // Try and set that as the main account password, should fail.
        let pce = PasswordChangeEvent::new_internal(UUID_ADMIN, r1.as_str());
        let e = idms_prox_write.set_account_password(&pce);
        assert!(e.is_err());

        let pce = UnixPasswordChangeEvent::new_internal(UUID_ADMIN, r1.as_str());
        let e = idms_prox_write.set_unix_account_password(&pce);
        assert!(e.is_err());

        assert!(idms_prox_write.commit().is_ok());
    }

    #[idm_test]
    async fn test_idm_radiusauthtoken(idms: &IdmServer, _idms_delayed: &IdmServerDelayed) {
        let mut idms_prox_write = idms.proxy_write(duration_from_epoch_now()).await;
        let rrse = RegenerateRadiusSecretEvent::new_internal(UUID_ADMIN);
        let r1 = idms_prox_write
            .regenerate_radius_secret(&rrse)
            .expect("Failed to reset radius credential 1");
        idms_prox_write.commit().expect("failed to commit");

        let mut idms_prox_read = idms.proxy_read().await;
        let admin_entry = idms_prox_read
            .qs_read
            .internal_search_uuid(UUID_ADMIN)
            .expect("Can't access admin entry.");

        let rate = RadiusAuthTokenEvent::new_impersonate(admin_entry, UUID_ADMIN);
        let tok_r = idms_prox_read
            .get_radiusauthtoken(&rate, duration_from_epoch_now())
            .expect("Failed to generate radius auth token");

        // view the token?
        assert!(r1 == tok_r.secret);
    }

    #[idm_test]
    async fn test_idm_simple_password_reject_weak(
        idms: &IdmServer,
        _idms_delayed: &IdmServerDelayed,
    ) {
        // len check
        let mut idms_prox_write = idms.proxy_write(duration_from_epoch_now()).await;

        let pce = PasswordChangeEvent::new_internal(UUID_ADMIN, "password");
        let e = idms_prox_write.set_account_password(&pce);
        assert!(e.is_err());

        // zxcvbn check
        let pce = PasswordChangeEvent::new_internal(UUID_ADMIN, "password1234");
        let e = idms_prox_write.set_account_password(&pce);
        assert!(e.is_err());

        // Check the "name" checking works too (I think admin may hit a common pw rule first)
        let pce = PasswordChangeEvent::new_internal(UUID_ADMIN, "admin_nta");
        let e = idms_prox_write.set_account_password(&pce);
        assert!(e.is_err());

        // Check that the demo badlist password is rejected.
        let pce = PasswordChangeEvent::new_internal(
            UUID_ADMIN,
            "demo_badlist_shohfie3aeci2oobur0aru9uushah6EiPi2woh4hohngoighaiRuepieN3ongoo1",
        );
        let e = idms_prox_write.set_account_password(&pce);
        assert!(e.is_err());

        assert!(idms_prox_write.commit().is_ok());
    }

    #[idm_test]
    async fn test_idm_simple_password_reject_badlist(
        idms: &IdmServer,
        _idms_delayed: &IdmServerDelayed,
    ) {
        let mut idms_prox_write = idms.proxy_write(duration_from_epoch_now()).await;

        // Check that the badlist password inserted is rejected.
        let pce = PasswordChangeEvent::new_internal(UUID_ADMIN, "bad@no3IBTyqHu$list");
        let e = idms_prox_write.set_account_password(&pce);
        assert!(e.is_err());

        assert!(idms_prox_write.commit().is_ok());
    }

    #[idm_test]
    async fn test_idm_unixusertoken(idms: &IdmServer, _idms_delayed: &IdmServerDelayed) {
        let mut idms_prox_write = idms.proxy_write(duration_from_epoch_now()).await;
        // Modify admin to have posixaccount
        let me_posix = ModifyEvent::new_internal_invalid(
            filter!(f_eq(Attribute::Name, PartialValue::new_iname("admin"))),
            ModifyList::new_list(vec![
                Modify::Present(Attribute::Class.into(), EntryClass::PosixAccount.into()),
                Modify::Present(Attribute::GidNumber.into(), Value::new_uint32(2001)),
            ]),
        );
        assert!(idms_prox_write.qs_write.modify(&me_posix).is_ok());
        // Add a posix group that has the admin as a member.
        let e: Entry<EntryInit, EntryNew> = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Group.to_value()),
            (Attribute::Class, EntryClass::PosixGroup.to_value()),
            (Attribute::Name, Value::new_iname("testgroup")),
            (
                Attribute::Uuid,
                Value::Uuid(uuid::uuid!("01609135-a1c4-43d5-966b-a28227644445"))
            ),
            (Attribute::Description, Value::new_utf8s("testgroup")),
            (
                Attribute::Member,
                Value::Refer(uuid::uuid!("00000000-0000-0000-0000-000000000000"))
            )
        );

        let ce = CreateEvent::new_internal(vec![e]);

        assert!(idms_prox_write.qs_write.create(&ce).is_ok());

        idms_prox_write.commit().expect("failed to commit");

        let mut idms_prox_read = idms.proxy_read().await;

        // Get the account that will be doing the actual reads.
        let admin_entry = idms_prox_read
            .qs_read
            .internal_search_uuid(UUID_ADMIN)
            .expect("Can't access admin entry.");

        let ugte = UnixGroupTokenEvent::new_impersonate(
            admin_entry.clone(),
            uuid!("01609135-a1c4-43d5-966b-a28227644445"),
        );
        let tok_g = idms_prox_read
            .get_unixgrouptoken(&ugte)
            .expect("Failed to generate unix group token");

        assert!(tok_g.name == "testgroup");
        assert!(tok_g.spn == "testgroup@example.com");

        let uute = UnixUserTokenEvent::new_internal(UUID_ADMIN);
        let tok_r = idms_prox_read
            .get_unixusertoken(&uute, duration_from_epoch_now())
            .expect("Failed to generate unix user token");

        assert!(tok_r.name == "admin");
        assert!(tok_r.spn == "admin@example.com");
        assert!(tok_r.groups.len() == 2);
        assert!(tok_r.groups[0].name == "admin");
        assert!(tok_r.groups[1].name == "testgroup");
        assert!(tok_r.valid);

        // Show we can get the admin as a unix group token too
        let ugte = UnixGroupTokenEvent::new_impersonate(
            admin_entry,
            uuid!("00000000-0000-0000-0000-000000000000"),
        );
        let tok_g = idms_prox_read
            .get_unixgrouptoken(&ugte)
            .expect("Failed to generate unix group token");

        assert!(tok_g.name == "admin");
        assert!(tok_g.spn == "admin@example.com");
    }

    #[idm_test]
    async fn test_idm_simple_unix_password_reset(
        idms: &IdmServer,
        _idms_delayed: &IdmServerDelayed,
    ) {
        let mut idms_prox_write = idms.proxy_write(duration_from_epoch_now()).await;
        // make the admin a valid posix account
        let me_posix = ModifyEvent::new_internal_invalid(
            filter!(f_eq(Attribute::Name, PartialValue::new_iname("admin"))),
            ModifyList::new_list(vec![
                Modify::Present(Attribute::Class.into(), EntryClass::PosixAccount.into()),
                Modify::Present(Attribute::GidNumber.into(), Value::new_uint32(2001)),
            ]),
        );
        assert!(idms_prox_write.qs_write.modify(&me_posix).is_ok());

        let pce = UnixPasswordChangeEvent::new_internal(UUID_ADMIN, TEST_PASSWORD);

        assert!(idms_prox_write.set_unix_account_password(&pce).is_ok());
        assert!(idms_prox_write.commit().is_ok());

        let mut idms_auth = idms.auth().await;
        // Check auth verification of the password

        let uuae_good = UnixUserAuthEvent::new_internal(UUID_ADMIN, TEST_PASSWORD);
        let a1 = idms_auth
            .auth_unix(&uuae_good, Duration::from_secs(TEST_CURRENT_TIME))
            .await;
        match a1 {
            Ok(Some(_tok)) => {}
            _ => assert!(false),
        };
        // Check bad password
        let uuae_bad = UnixUserAuthEvent::new_internal(UUID_ADMIN, TEST_PASSWORD_INC);
        let a2 = idms_auth
            .auth_unix(&uuae_bad, Duration::from_secs(TEST_CURRENT_TIME))
            .await;
        match a2 {
            Ok(None) => {}
            _ => assert!(false),
        };
        assert!(idms_auth.commit().is_ok());

        // Check deleting the password
        let mut idms_prox_write = idms.proxy_write(duration_from_epoch_now()).await;
        let me_purge_up = ModifyEvent::new_internal_invalid(
            filter!(f_eq(Attribute::Name, PartialValue::new_iname("admin"))),
            ModifyList::new_list(vec![Modify::Purged(Attribute::UnixPassword.into())]),
        );
        assert!(idms_prox_write.qs_write.modify(&me_purge_up).is_ok());
        assert!(idms_prox_write.commit().is_ok());

        // And auth should now fail due to the lack of PW material (note that
        // softlocking WON'T kick in because the cred_uuid is gone!)
        let mut idms_auth = idms.auth().await;
        let a3 = idms_auth
            .auth_unix(&uuae_good, Duration::from_secs(TEST_CURRENT_TIME))
            .await;
        match a3 {
            Ok(None) => {}
            _ => assert!(false),
        };
        assert!(idms_auth.commit().is_ok());
    }

    #[idm_test]
    async fn test_idm_simple_password_upgrade(
        idms: &IdmServer,
        idms_delayed: &mut IdmServerDelayed,
    ) {
        // Assert the delayed action queue is empty
        idms_delayed.check_is_empty_or_panic();
        // Setup the admin w_ an imported password.
        {
            let mut idms_prox_write = idms.proxy_write(duration_from_epoch_now()).await;
            // now modify and provide a primary credential.
            let me_inv_m =
                ModifyEvent::new_internal_invalid(
                        filter!(f_eq(Attribute::Name, PartialValue::new_iname("admin"))),
                        ModifyList::new_list(vec![Modify::Present(
                            Attribute::PasswordImport.into(),
                            Value::from("{SSHA512}JwrSUHkI7FTAfHRVR6KoFlSN0E3dmaQWARjZ+/UsShYlENOqDtFVU77HJLLrY2MuSp0jve52+pwtdVl2QUAHukQ0XUf5LDtM")
                        )]),
                    );
            // go!
            assert!(idms_prox_write.qs_write.modify(&me_inv_m).is_ok());
            assert!(idms_prox_write.commit().is_ok());
        }
        // Still empty
        idms_delayed.check_is_empty_or_panic();

        let mut idms_prox_read = idms.proxy_read().await;
        let admin_entry = idms_prox_read
            .qs_read
            .internal_search_uuid(UUID_ADMIN)
            .expect("Can't access admin entry.");
        let cred_before = admin_entry
            .get_ava_single_credential(Attribute::PrimaryCredential)
            .expect("No credential present")
            .clone();
        drop(idms_prox_read);

        // Do an auth, this will trigger the action to send.
        check_admin_password(idms, "password").await;

        // ⚠️  We have to be careful here. Between these two actions, it's possible
        // that on the pw upgrade that the credential uuid changes. This immediately
        // causes the session to be invalidated.

        // We need to check the credential id does not change between these steps to
        // prevent this!

        // process it.
        let da = idms_delayed.try_recv().expect("invalid");
        // The first task is the pw upgrade
        assert!(matches!(da, DelayedAction::PwUpgrade(_)));
        let r = idms.delayed_action(duration_from_epoch_now(), da).await;
        // The second is the auth session record
        let da = idms_delayed.try_recv().expect("invalid");
        assert!(matches!(da, DelayedAction::AuthSessionRecord(_)));
        assert!(Ok(true) == r);

        let mut idms_prox_read = idms.proxy_read().await;
        let admin_entry = idms_prox_read
            .qs_read
            .internal_search_uuid(UUID_ADMIN)
            .expect("Can't access admin entry.");
        let cred_after = admin_entry
            .get_ava_single_credential(Attribute::PrimaryCredential)
            .expect("No credential present")
            .clone();
        drop(idms_prox_read);

        assert_eq!(cred_before.uuid, cred_after.uuid);

        // Check the admin pw still matches
        check_admin_password(idms, "password").await;
        // Clear the next auth session record
        let da = idms_delayed.try_recv().expect("invalid");
        assert!(matches!(da, DelayedAction::AuthSessionRecord(_)));

        // No delayed action was queued.
        idms_delayed.check_is_empty_or_panic();
    }

    #[idm_test]
    async fn test_idm_unix_password_upgrade(idms: &IdmServer, idms_delayed: &mut IdmServerDelayed) {
        // Assert the delayed action queue is empty
        idms_delayed.check_is_empty_or_panic();
        // Setup the admin with an imported unix pw.
        let mut idms_prox_write = idms.proxy_write(duration_from_epoch_now()).await;

        let im_pw = "{SSHA512}JwrSUHkI7FTAfHRVR6KoFlSN0E3dmaQWARjZ+/UsShYlENOqDtFVU77HJLLrY2MuSp0jve52+pwtdVl2QUAHukQ0XUf5LDtM";
        let pw = Password::try_from(im_pw).expect("failed to parse");
        let cred = Credential::new_from_password(pw);
        let v_cred = Value::new_credential("unix", cred);

        let me_posix = ModifyEvent::new_internal_invalid(
            filter!(f_eq(Attribute::Name, PartialValue::new_iname("admin"))),
            ModifyList::new_list(vec![
                Modify::Present(Attribute::Class.into(), EntryClass::PosixAccount.into()),
                Modify::Present(Attribute::GidNumber.into(), Value::new_uint32(2001)),
                Modify::Present(Attribute::UnixPassword.into(), v_cred),
            ]),
        );
        assert!(idms_prox_write.qs_write.modify(&me_posix).is_ok());
        assert!(idms_prox_write.commit().is_ok());
        idms_delayed.check_is_empty_or_panic();
        // Get the auth ready.
        let uuae = UnixUserAuthEvent::new_internal(UUID_ADMIN, "password");
        let mut idms_auth = idms.auth().await;
        let a1 = idms_auth
            .auth_unix(&uuae, Duration::from_secs(TEST_CURRENT_TIME))
            .await;
        match a1 {
            Ok(Some(_tok)) => {}
            _ => assert!(false),
        };
        idms_auth.commit().expect("Must not fail");
        // The upgrade was queued
        // Process it.
        let da = idms_delayed.try_recv().expect("invalid");
        let _r = idms.delayed_action(duration_from_epoch_now(), da).await;
        // Go again
        let mut idms_auth = idms.auth().await;
        let a2 = idms_auth
            .auth_unix(&uuae, Duration::from_secs(TEST_CURRENT_TIME))
            .await;
        match a2 {
            Ok(Some(_tok)) => {}
            _ => assert!(false),
        };
        idms_auth.commit().expect("Must not fail");
        // No delayed action was queued.
        idms_delayed.check_is_empty_or_panic();
    }

    // For testing the timeouts
    // We need times on this scale
    //    not yet valid <-> valid from time <-> current_time <-> expire time <-> expired
    const TEST_NOT_YET_VALID_TIME: u64 = TEST_CURRENT_TIME - 240;
    const TEST_VALID_FROM_TIME: u64 = TEST_CURRENT_TIME - 120;
    const TEST_EXPIRE_TIME: u64 = TEST_CURRENT_TIME + 120;
    const TEST_AFTER_EXPIRY: u64 = TEST_CURRENT_TIME + 240;

    async fn set_admin_valid_time(idms: &IdmServer) {
        let mut idms_write = idms.proxy_write(duration_from_epoch_now()).await;

        let v_valid_from = Value::new_datetime_epoch(Duration::from_secs(TEST_VALID_FROM_TIME));
        let v_expire = Value::new_datetime_epoch(Duration::from_secs(TEST_EXPIRE_TIME));

        // now modify and provide a primary credential.
        let me_inv_m = ModifyEvent::new_internal_invalid(
            filter!(f_eq(Attribute::Name, PartialValue::new_iname("admin"))),
            ModifyList::new_list(vec![
                Modify::Present(Attribute::AccountExpire.into(), v_expire),
                Modify::Present(Attribute::AccountValidFrom.into(), v_valid_from),
            ]),
        );
        // go!
        assert!(idms_write.qs_write.modify(&me_inv_m).is_ok());

        idms_write.commit().expect("Must not fail");
    }

    #[idm_test]
    async fn test_idm_account_valid_from_expire(
        idms: &IdmServer,
        _idms_delayed: &mut IdmServerDelayed,
    ) {
        // Any account that is not yet valrid / expired can't auth.

        init_admin_w_password(idms, TEST_PASSWORD)
            .await
            .expect("Failed to setup admin account");
        // Set the valid bounds high/low
        // TEST_VALID_FROM_TIME/TEST_EXPIRE_TIME
        set_admin_valid_time(idms).await;

        let time_low = Duration::from_secs(TEST_NOT_YET_VALID_TIME);
        let time_high = Duration::from_secs(TEST_AFTER_EXPIRY);

        let mut idms_auth = idms.auth().await;
        let admin_init = AuthEvent::named_init("admin");
        let r1 = idms_auth
            .auth(&admin_init, time_low, Source::Internal)
            .await;

        let ar = r1.unwrap();
        let AuthResult {
            sessionid: _,
            state,
        } = ar;

        match state {
            AuthState::Denied(_) => {}
            _ => {
                panic!();
            }
        };

        idms_auth.commit().expect("Must not fail");

        // And here!
        let mut idms_auth = idms.auth().await;
        let admin_init = AuthEvent::named_init("admin");
        let r1 = idms_auth
            .auth(&admin_init, time_high, Source::Internal)
            .await;

        let ar = r1.unwrap();
        let AuthResult {
            sessionid: _,
            state,
        } = ar;

        match state {
            AuthState::Denied(_) => {}
            _ => {
                panic!();
            }
        };

        idms_auth.commit().expect("Must not fail");
    }

    #[idm_test]
    async fn test_idm_unix_valid_from_expire(
        idms: &IdmServer,
        _idms_delayed: &mut IdmServerDelayed,
    ) {
        // Any account that is expired can't unix auth.
        init_admin_w_password(idms, TEST_PASSWORD)
            .await
            .expect("Failed to setup admin account");
        set_admin_valid_time(idms).await;

        let time_low = Duration::from_secs(TEST_NOT_YET_VALID_TIME);
        let time_high = Duration::from_secs(TEST_AFTER_EXPIRY);

        // make the admin a valid posix account
        let mut idms_prox_write = idms.proxy_write(duration_from_epoch_now()).await;
        let me_posix = ModifyEvent::new_internal_invalid(
            filter!(f_eq(Attribute::Name, PartialValue::new_iname("admin"))),
            ModifyList::new_list(vec![
                Modify::Present(Attribute::Class.into(), EntryClass::PosixAccount.into()),
                Modify::Present(Attribute::GidNumber.into(), Value::new_uint32(2001)),
            ]),
        );
        assert!(idms_prox_write.qs_write.modify(&me_posix).is_ok());

        let pce = UnixPasswordChangeEvent::new_internal(UUID_ADMIN, TEST_PASSWORD);

        assert!(idms_prox_write.set_unix_account_password(&pce).is_ok());
        assert!(idms_prox_write.commit().is_ok());

        // Now check auth when the time is too high or too low.
        let mut idms_auth = idms.auth().await;
        let uuae_good = UnixUserAuthEvent::new_internal(UUID_ADMIN, TEST_PASSWORD);

        let a1 = idms_auth.auth_unix(&uuae_good, time_low).await;
        // Should this actually send an error with the details? Or just silently act as
        // badpw?
        match a1 {
            Ok(None) => {}
            _ => assert!(false),
        };

        let a2 = idms_auth.auth_unix(&uuae_good, time_high).await;
        match a2 {
            Ok(None) => {}
            _ => assert!(false),
        };

        idms_auth.commit().expect("Must not fail");
        // Also check the generated unix tokens are invalid.
        let mut idms_prox_read = idms.proxy_read().await;
        let uute = UnixUserTokenEvent::new_internal(UUID_ADMIN);

        let tok_r = idms_prox_read
            .get_unixusertoken(&uute, time_low)
            .expect("Failed to generate unix user token");

        assert!(tok_r.name == "admin");
        assert!(!tok_r.valid);

        let tok_r = idms_prox_read
            .get_unixusertoken(&uute, time_high)
            .expect("Failed to generate unix user token");

        assert!(tok_r.name == "admin");
        assert!(!tok_r.valid);
    }

    #[idm_test]
    async fn test_idm_radius_valid_from_expire(
        idms: &IdmServer,
        _idms_delayed: &mut IdmServerDelayed,
    ) {
        // Any account not valid/expiry should not return
        // a radius packet.
        init_admin_w_password(idms, TEST_PASSWORD)
            .await
            .expect("Failed to setup admin account");
        set_admin_valid_time(idms).await;

        let time_low = Duration::from_secs(TEST_NOT_YET_VALID_TIME);
        let time_high = Duration::from_secs(TEST_AFTER_EXPIRY);

        let mut idms_prox_write = idms.proxy_write(duration_from_epoch_now()).await;
        let rrse = RegenerateRadiusSecretEvent::new_internal(UUID_ADMIN);
        let _r1 = idms_prox_write
            .regenerate_radius_secret(&rrse)
            .expect("Failed to reset radius credential 1");
        idms_prox_write.commit().expect("failed to commit");

        let mut idms_prox_read = idms.proxy_read().await;
        let admin_entry = idms_prox_read
            .qs_read
            .internal_search_uuid(UUID_ADMIN)
            .expect("Can't access admin entry.");

        let rate = RadiusAuthTokenEvent::new_impersonate(admin_entry, UUID_ADMIN);
        let tok_r = idms_prox_read.get_radiusauthtoken(&rate, time_low);

        if tok_r.is_err() {
            // Ok?
        } else {
            assert!(false);
        }

        let tok_r = idms_prox_read.get_radiusauthtoken(&rate, time_high);

        if tok_r.is_err() {
            // Ok?
        } else {
            assert!(false);
        }
    }

    #[idm_test(audit)]
    async fn test_idm_account_softlocking(
        idms: &IdmServer,
        idms_delayed: &mut IdmServerDelayed,
        idms_audit: &mut IdmServerAudit,
    ) {
        init_admin_w_password(idms, TEST_PASSWORD)
            .await
            .expect("Failed to setup admin account");

        // Auth invalid, no softlock present.
        let sid =
            init_admin_authsession_sid(idms, Duration::from_secs(TEST_CURRENT_TIME), "admin").await;
        let mut idms_auth = idms.auth().await;
        let anon_step = AuthEvent::cred_step_password(sid, TEST_PASSWORD_INC);

        let r2 = idms_auth
            .auth(
                &anon_step,
                Duration::from_secs(TEST_CURRENT_TIME),
                Source::Internal,
            )
            .await;
        debug!("r2 ==> {:?}", r2);

        match r2 {
            Ok(ar) => {
                let AuthResult {
                    sessionid: _,
                    state,
                } = ar;
                match state {
                    AuthState::Denied(reason) => {
                        assert!(reason != "Account is temporarily locked");
                    }
                    _ => {
                        error!("A critical error has occurred! We have a non-denied result!");
                        panic!();
                    }
                }
            }
            Err(e) => {
                error!("A critical error has occurred! {:?}", e);
                panic!();
            }
        };

        // There should be a queued audit event
        match idms_audit.audit_rx().try_recv() {
            Ok(AuditEvent::AuthenticationDenied { .. }) => {}
            _ => assert!(false),
        }

        idms_auth.commit().expect("Must not fail");

        // Auth init, softlock present, count == 1, same time (so before unlock_at)
        // aka Auth valid immediate, (ct < exp), autofail
        // aka Auth invalid immediate, (ct < exp), autofail
        let mut idms_auth = idms.auth().await;
        let admin_init = AuthEvent::named_init("admin");

        let r1 = idms_auth
            .auth(
                &admin_init,
                Duration::from_secs(TEST_CURRENT_TIME),
                Source::Internal,
            )
            .await;
        let ar = r1.unwrap();
        let AuthResult { sessionid, state } = ar;
        assert!(matches!(state, AuthState::Choose(_)));

        // Soft locks only apply once a mechanism is chosen
        let admin_begin = AuthEvent::begin_mech(sessionid, AuthMech::Password);

        let r2 = idms_auth
            .auth(
                &admin_begin,
                Duration::from_secs(TEST_CURRENT_TIME),
                Source::Internal,
            )
            .await;
        let ar = r2.unwrap();
        let AuthResult {
            sessionid: _,
            state,
        } = ar;

        match state {
            AuthState::Denied(reason) => {
                assert!(reason == "Account is temporarily locked");
            }
            _ => {
                error!("Sessions was not denied (softlock)");
                panic!();
            }
        };

        idms_auth.commit().expect("Must not fail");

        // Auth invalid once softlock pass (count == 2, exp_at grows)
        // Tested in the softlock state machine.

        // Auth valid once softlock pass, valid. Count remains.
        let sid =
            init_admin_authsession_sid(idms, Duration::from_secs(TEST_CURRENT_TIME + 2), "admin")
                .await;

        let mut idms_auth = idms.auth().await;
        let anon_step = AuthEvent::cred_step_password(sid, TEST_PASSWORD);

        // Expect success
        let r2 = idms_auth
            .auth(
                &anon_step,
                Duration::from_secs(TEST_CURRENT_TIME + 2),
                Source::Internal,
            )
            .await;
        debug!("r2 ==> {:?}", r2);

        match r2 {
            Ok(ar) => {
                let AuthResult {
                    sessionid: _,
                    state,
                } = ar;
                match state {
                    AuthState::Success(_uat, AuthIssueSession::Token) => {
                        // Check the uat.
                    }
                    _ => {
                        error!("A critical error has occurred! We have a non-succcess result!");
                        panic!();
                    }
                }
            }
            Err(e) => {
                error!("A critical error has occurred! {:?}", e);
                // Should not occur!
                panic!();
            }
        };

        idms_auth.commit().expect("Must not fail");

        // Clear the auth session record
        let da = idms_delayed.try_recv().expect("invalid");
        assert!(matches!(da, DelayedAction::AuthSessionRecord(_)));
        idms_delayed.check_is_empty_or_panic();

        // Auth valid after reset at, count == 0.
        // Tested in the softlock state machine.

        // Auth invalid, softlock present, count == 1
        // Auth invalid after reset at, count == 0 and then to count == 1
        // Tested in the softlock state machine.
    }

    #[idm_test(audit)]
    async fn test_idm_account_softlocking_interleaved(
        idms: &IdmServer,
        _idms_delayed: &mut IdmServerDelayed,
        idms_audit: &mut IdmServerAudit,
    ) {
        init_admin_w_password(idms, TEST_PASSWORD)
            .await
            .expect("Failed to setup admin account");

        // Start an *early* auth session.
        let sid_early =
            init_admin_authsession_sid(idms, Duration::from_secs(TEST_CURRENT_TIME), "admin").await;

        // Start a second auth session
        let sid_later =
            init_admin_authsession_sid(idms, Duration::from_secs(TEST_CURRENT_TIME), "admin").await;
        // Get the detail wrong in sid_later.
        let mut idms_auth = idms.auth().await;
        let anon_step = AuthEvent::cred_step_password(sid_later, TEST_PASSWORD_INC);

        let r2 = idms_auth
            .auth(
                &anon_step,
                Duration::from_secs(TEST_CURRENT_TIME),
                Source::Internal,
            )
            .await;
        debug!("r2 ==> {:?}", r2);

        match r2 {
            Ok(ar) => {
                let AuthResult {
                    sessionid: _,
                    state,
                } = ar;
                match state {
                    AuthState::Denied(reason) => {
                        assert!(reason != "Account is temporarily locked");
                    }
                    _ => {
                        error!("A critical error has occurred! We have a non-denied result!");
                        panic!();
                    }
                }
            }
            Err(e) => {
                error!("A critical error has occurred! {:?}", e);
                panic!();
            }
        };

        match idms_audit.audit_rx().try_recv() {
            Ok(AuditEvent::AuthenticationDenied { .. }) => {}
            _ => assert!(false),
        }

        idms_auth.commit().expect("Must not fail");

        // Now check that sid_early is denied due to softlock.
        let mut idms_auth = idms.auth().await;
        let anon_step = AuthEvent::cred_step_password(sid_early, TEST_PASSWORD);

        // Expect success
        let r2 = idms_auth
            .auth(
                &anon_step,
                Duration::from_secs(TEST_CURRENT_TIME),
                Source::Internal,
            )
            .await;
        debug!("r2 ==> {:?}", r2);
        match r2 {
            Ok(ar) => {
                let AuthResult {
                    sessionid: _,
                    state,
                } = ar;
                match state {
                    AuthState::Denied(reason) => {
                        assert!(reason == "Account is temporarily locked");
                    }
                    _ => {
                        error!("A critical error has occurred! We have a non-denied result!");
                        panic!();
                    }
                }
            }
            Err(e) => {
                error!("A critical error has occurred! {:?}", e);
                panic!();
            }
        };
        idms_auth.commit().expect("Must not fail");
    }

    #[idm_test]
    async fn test_idm_account_unix_softlocking(
        idms: &IdmServer,
        _idms_delayed: &mut IdmServerDelayed,
    ) {
        init_admin_w_password(idms, TEST_PASSWORD)
            .await
            .expect("Failed to setup admin account");
        // make the admin a valid posix account
        let mut idms_prox_write = idms.proxy_write(duration_from_epoch_now()).await;
        let me_posix = ModifyEvent::new_internal_invalid(
            filter!(f_eq(Attribute::Name, PartialValue::new_iname("admin"))),
            ModifyList::new_list(vec![
                Modify::Present(Attribute::Class.into(), EntryClass::PosixAccount.into()),
                Modify::Present(Attribute::GidNumber.into(), Value::new_uint32(2001)),
            ]),
        );
        assert!(idms_prox_write.qs_write.modify(&me_posix).is_ok());

        let pce = UnixPasswordChangeEvent::new_internal(UUID_ADMIN, TEST_PASSWORD);
        assert!(idms_prox_write.set_unix_account_password(&pce).is_ok());
        assert!(idms_prox_write.commit().is_ok());

        let mut idms_auth = idms.auth().await;
        let uuae_good = UnixUserAuthEvent::new_internal(UUID_ADMIN, TEST_PASSWORD);
        let uuae_bad = UnixUserAuthEvent::new_internal(UUID_ADMIN, TEST_PASSWORD_INC);

        let a2 = idms_auth
            .auth_unix(&uuae_bad, Duration::from_secs(TEST_CURRENT_TIME))
            .await;
        match a2 {
            Ok(None) => {}
            _ => assert!(false),
        };

        // Now if we immediately auth again, should fail at same time due to SL
        let a1 = idms_auth
            .auth_unix(&uuae_good, Duration::from_secs(TEST_CURRENT_TIME))
            .await;
        match a1 {
            Ok(None) => {}
            _ => assert!(false),
        };

        // And then later, works because of SL lifting.
        let a1 = idms_auth
            .auth_unix(&uuae_good, Duration::from_secs(TEST_CURRENT_TIME + 2))
            .await;
        match a1 {
            Ok(Some(_tok)) => {}
            _ => assert!(false),
        };

        assert!(idms_auth.commit().is_ok());
    }

    #[idm_test]
    async fn test_idm_jwt_uat_expiry(idms: &IdmServer, idms_delayed: &mut IdmServerDelayed) {
        let ct = Duration::from_secs(TEST_CURRENT_TIME);
        let expiry = ct + Duration::from_secs((DEFAULT_AUTH_SESSION_EXPIRY + 1).into());
        // Do an authenticate
        init_admin_w_password(idms, TEST_PASSWORD)
            .await
            .expect("Failed to setup admin account");
        let token = check_admin_password(idms, TEST_PASSWORD).await;

        // Clear out the queued session record
        let da = idms_delayed.try_recv().expect("invalid");
        assert!(matches!(da, DelayedAction::AuthSessionRecord(_)));
        // Persist it.
        let r = idms.delayed_action(ct, da).await;
        assert!(Ok(true) == r);
        idms_delayed.check_is_empty_or_panic();

        let mut idms_prox_read = idms.proxy_read().await;

        // Check it's valid - This is within the time window so will pass.
        idms_prox_read
            .validate_and_parse_token_to_ident(Some(token.as_str()), ct)
            .expect("Failed to validate");

        // In X time it should be INVALID
        match idms_prox_read.validate_and_parse_token_to_ident(Some(token.as_str()), expiry) {
            Err(OperationError::SessionExpired) => {}
            _ => assert!(false),
        }
    }

    #[idm_test]
    async fn test_idm_expired_auth_session_cleanup(
        idms: &IdmServer,
        _idms_delayed: &mut IdmServerDelayed,
    ) {
        let ct = Duration::from_secs(TEST_CURRENT_TIME);
        let expiry_a = ct + Duration::from_secs((DEFAULT_AUTH_SESSION_EXPIRY + 1).into());
        let expiry_b = ct + Duration::from_secs(((DEFAULT_AUTH_SESSION_EXPIRY + 1) * 2).into());

        let session_a = Uuid::new_v4();
        let session_b = Uuid::new_v4();

        // We need to put the credential on the admin.
        let cred_id = init_admin_w_password(idms, TEST_PASSWORD)
            .await
            .expect("Failed to setup admin account");

        // Assert no sessions present
        let mut idms_prox_read = idms.proxy_read().await;
        let admin = idms_prox_read
            .qs_read
            .internal_search_uuid(UUID_ADMIN)
            .expect("failed");
        let sessions = admin.get_ava_as_session_map(Attribute::UserAuthTokenSession);
        assert!(sessions.is_none());
        drop(idms_prox_read);

        let da = DelayedAction::AuthSessionRecord(AuthSessionRecord {
            target_uuid: UUID_ADMIN,
            session_id: session_a,
            cred_id,
            label: "Test Session A".to_string(),
            expiry: Some(OffsetDateTime::UNIX_EPOCH + expiry_a),
            issued_at: OffsetDateTime::UNIX_EPOCH + ct,
            issued_by: IdentityId::User(UUID_ADMIN),
            scope: SessionScope::ReadOnly,
        });
        // Persist it.
        let r = idms.delayed_action(ct, da).await;
        assert!(Ok(true) == r);

        // Check it was written, and check
        let mut idms_prox_read = idms.proxy_read().await;
        let admin = idms_prox_read
            .qs_read
            .internal_search_uuid(UUID_ADMIN)
            .expect("failed");
        let sessions = admin
            .get_ava_as_session_map(Attribute::UserAuthTokenSession)
            .expect("Sessions must be present!");
        assert!(sessions.len() == 1);
        let session_data_a = sessions.get(&session_a).expect("Session A is missing!");
        assert!(matches!(session_data_a.state, SessionState::ExpiresAt(_)));

        drop(idms_prox_read);

        // When we re-auth, this is what triggers the session revoke via the delayed action.

        let da = DelayedAction::AuthSessionRecord(AuthSessionRecord {
            target_uuid: UUID_ADMIN,
            session_id: session_b,
            cred_id,
            label: "Test Session B".to_string(),
            expiry: Some(OffsetDateTime::UNIX_EPOCH + expiry_b),
            issued_at: OffsetDateTime::UNIX_EPOCH + ct,
            issued_by: IdentityId::User(UUID_ADMIN),
            scope: SessionScope::ReadOnly,
        });
        // Persist it.
        let r = idms.delayed_action(expiry_a, da).await;
        assert!(Ok(true) == r);

        let mut idms_prox_read = idms.proxy_read().await;
        let admin = idms_prox_read
            .qs_read
            .internal_search_uuid(UUID_ADMIN)
            .expect("failed");
        let sessions = admin
            .get_ava_as_session_map(Attribute::UserAuthTokenSession)
            .expect("Sessions must be present!");
        trace!(?sessions);
        assert!(sessions.len() == 2);

        let session_data_a = sessions.get(&session_a).expect("Session A is missing!");
        assert!(matches!(session_data_a.state, SessionState::RevokedAt(_)));

        let session_data_b = sessions.get(&session_b).expect("Session B is missing!");
        assert!(matches!(session_data_b.state, SessionState::ExpiresAt(_)));
        // Now show that sessions trim!
    }

    #[idm_test]
    async fn test_idm_account_session_validation(
        idms: &IdmServer,
        idms_delayed: &mut IdmServerDelayed,
    ) {
        use compact_jwt::{Jws, JwsUnverified};
        use kanidm_proto::v1::UserAuthToken;
        use std::str::FromStr;

        let ct = Duration::from_secs(TEST_CURRENT_TIME);

        let post_grace = ct + GRACE_WINDOW + Duration::from_secs(1);
        let expiry = ct + Duration::from_secs(DEFAULT_AUTH_SESSION_EXPIRY as u64 + 1);

        // Assert that our grace time is less than expiry, so we know the failure is due to
        // this.
        assert!(post_grace < expiry);

        // Do an authenticate
        init_admin_w_password(idms, TEST_PASSWORD)
            .await
            .expect("Failed to setup admin account");
        let token = check_admin_password(idms, TEST_PASSWORD).await;

        // Process the session info.
        let da = idms_delayed.try_recv().expect("invalid");
        assert!(matches!(da, DelayedAction::AuthSessionRecord(_)));
        let r = idms.delayed_action(ct, da).await;
        assert!(Ok(true) == r);

        let uat_unverified = JwsUnverified::from_str(&token).expect("Failed to parse apitoken");
        let uat_inner: Jws<UserAuthToken> = uat_unverified
            .validate_embeded()
            .expect("Embedded jwk not found");
        let uat_inner = uat_inner.into_inner();

        let mut idms_prox_read = idms.proxy_read().await;

        // Check it's valid.
        idms_prox_read
            .validate_and_parse_token_to_ident(Some(token.as_str()), ct)
            .expect("Failed to validate");

        // If the auth session record wasn't processed, this will fail.
        idms_prox_read
            .validate_and_parse_token_to_ident(Some(token.as_str()), post_grace)
            .expect("Failed to validate");

        drop(idms_prox_read);

        // Mark the session as invalid now.
        let mut idms_prox_write = idms.proxy_write(ct).await;
        let dte = DestroySessionTokenEvent::new_internal(uat_inner.uuid, uat_inner.session_id);
        assert!(idms_prox_write.account_destroy_session_token(&dte).is_ok());
        assert!(idms_prox_write.commit().is_ok());

        // Now check again with the session destroyed.
        let mut idms_prox_read = idms.proxy_read().await;

        // Now, within gracewindow, it's NOT valid because the session entry exists and is in
        // the revoked state!
        match idms_prox_read.validate_and_parse_token_to_ident(Some(token.as_str()), post_grace) {
            Err(OperationError::SessionExpired) => {}
            _ => assert!(false),
        }
        drop(idms_prox_read);

        // Force trim the session out so that we can check the grate handling.
        let mut idms_prox_write = idms.proxy_write(ct).await;
        let filt = filter!(f_eq(Attribute::Uuid, PartialValue::Uuid(uat_inner.uuid)));
        let mut work_set = idms_prox_write
            .qs_write
            .internal_search_writeable(&filt)
            .expect("Failed to perform internal search writeable");
        for (_, entry) in work_set.iter_mut() {
            let _ = entry.force_trim_ava(Attribute::UserAuthTokenSession.into());
        }
        assert!(idms_prox_write
            .qs_write
            .internal_apply_writable(work_set)
            .is_ok());

        assert!(idms_prox_write.commit().is_ok());

        let mut idms_prox_read = idms.proxy_read().await;
        idms_prox_read
            .validate_and_parse_token_to_ident(Some(token.as_str()), ct)
            .expect("Failed to validate");

        // post grace, it's not valid.
        match idms_prox_read.validate_and_parse_token_to_ident(Some(token.as_str()), post_grace) {
            Err(OperationError::SessionExpired) => {}
            _ => assert!(false),
        }
    }

    #[idm_test]
    async fn test_idm_account_session_expiry(
        idms: &IdmServer,
        _idms_delayed: &mut IdmServerDelayed,
    ) {
        let ct = Duration::from_secs(TEST_CURRENT_TIME);

        //we first set the expiry to a custom value
        let mut idms_prox_write = idms.proxy_write(ct).await;

        let new_authsession_expiry = 1000;

        let modlist = ModifyList::new_purge_and_set(
            Attribute::AuthSessionExpiry,
            Value::Uint32(new_authsession_expiry),
        );
        idms_prox_write
            .qs_write
            .internal_modify_uuid(UUID_IDM_ALL_ACCOUNTS, &modlist)
            .expect("Unable to change default session exp");

        assert!(idms_prox_write.commit().is_ok());

        // Start anonymous auth.
        let mut idms_auth = idms.auth().await;
        // Send the initial auth event for initialising the session
        let anon_init = AuthEvent::anonymous_init();
        // Expect success
        let r1 = idms_auth.auth(&anon_init, ct, Source::Internal).await;
        /* Some weird lifetime things happen here ... */

        let sid = match r1 {
            Ok(ar) => {
                let AuthResult { sessionid, state } = ar;
                match state {
                    AuthState::Choose(mut conts) => {
                        // Should only be one auth mech
                        assert!(conts.len() == 1);
                        // And it should be anonymous
                        let m = conts.pop().expect("Should not fail");
                        assert!(m == AuthMech::Anonymous);
                    }
                    _ => {
                        error!("A critical error has occurred! We have a non-continue result!");
                        panic!();
                    }
                };
                // Now pass back the sessionid, we are good to continue.
                sessionid
            }
            Err(e) => {
                // Should not occur!
                error!("A critical error has occurred! {:?}", e);
                panic!();
            }
        };

        idms_auth.commit().expect("Must not fail");

        let mut idms_auth = idms.auth().await;
        let anon_begin = AuthEvent::begin_mech(sid, AuthMech::Anonymous);

        let r2 = idms_auth.auth(&anon_begin, ct, Source::Internal).await;

        match r2 {
            Ok(ar) => {
                let AuthResult {
                    sessionid: _,
                    state,
                } = ar;

                match state {
                    AuthState::Continue(allowed) => {
                        // Check the uat.
                        assert!(allowed.len() == 1);
                        assert!(allowed.first() == Some(&AuthAllowed::Anonymous));
                    }
                    _ => {
                        error!("A critical error has occurred! We have a non-continue result!");
                        panic!();
                    }
                }
            }
            Err(e) => {
                error!("A critical error has occurred! {:?}", e);
                // Should not occur!
                panic!();
            }
        };

        idms_auth.commit().expect("Must not fail");

        let mut idms_auth = idms.auth().await;
        // Now send the anonymous request, given the session id.
        let anon_step = AuthEvent::cred_step_anonymous(sid);

        // Expect success
        let r2 = idms_auth.auth(&anon_step, ct, Source::Internal).await;

        let token = match r2 {
            Ok(ar) => {
                let AuthResult {
                    sessionid: _,
                    state,
                } = ar;

                match state {
                    AuthState::Success(uat, AuthIssueSession::Token) => uat,
                    _ => {
                        error!("A critical error has occurred! We have a non-succcess result!");
                        panic!();
                    }
                }
            }
            Err(e) => {
                error!("A critical error has occurred! {:?}", e);
                // Should not occur!
                panic!();
            }
        };

        idms_auth.commit().expect("Must not fail");

        // Token_str to uat
        // we have to do it this way because anonymous doesn't have an ideantity for which we cam get the expiry value
        let Token::UserAuthToken(uat) = idms
            .proxy_read()
            .await
            .validate_and_parse_token_to_token(Some(&token), ct)
            .expect("Must not fail")
        else {
            panic!("Unexpected auth token type for anonymous auth");
        };

        debug!(?uat);

        assert!(
            matches!(uat.expiry, Some(exp) if exp == OffsetDateTime::UNIX_EPOCH + ct + Duration::from_secs(new_authsession_expiry as u64))
        );
    }

    #[idm_test]
    async fn test_idm_uat_claim_insertion(idms: &IdmServer, _idms_delayed: &mut IdmServerDelayed) {
        let ct = Duration::from_secs(TEST_CURRENT_TIME);
        let mut idms_prox_write = idms.proxy_write(ct).await;

        // get an account.
        let account = idms_prox_write
            .target_to_account(UUID_ADMIN)
            .expect("account must exist");

        // Create some fake UATs, then process them and see what claims fall out 🥳
        let session_id = uuid::Uuid::new_v4();

        // For the different auth types, check that we get the correct claims:

        // == anonymous
        let uat = account
            .to_userauthtoken(
                session_id,
                SessionScope::ReadWrite,
                ct,
                DEFAULT_AUTH_SESSION_EXPIRY,
            )
            .expect("Unable to create uat");
        let ident = idms_prox_write
            .process_uat_to_identity(&uat, ct)
            .expect("Unable to process uat");

        assert!(!ident.has_claim("authtype_anonymous"));
        // Does NOT have this
        assert!(!ident.has_claim("authlevel_strong"));
        assert!(!ident.has_claim("authclass_single"));
        assert!(!ident.has_claim("authclass_mfa"));

        // == unixpassword
        let uat = account
            .to_userauthtoken(
                session_id,
                SessionScope::ReadWrite,
                ct,
                DEFAULT_AUTH_SESSION_EXPIRY,
            )
            .expect("Unable to create uat");
        let ident = idms_prox_write
            .process_uat_to_identity(&uat, ct)
            .expect("Unable to process uat");

        assert!(!ident.has_claim("authtype_unixpassword"));
        assert!(!ident.has_claim("authclass_single"));
        // Does NOT have this
        assert!(!ident.has_claim("authlevel_strong"));
        assert!(!ident.has_claim("authclass_mfa"));

        // == password
        let uat = account
            .to_userauthtoken(
                session_id,
                SessionScope::ReadWrite,
                ct,
                DEFAULT_AUTH_SESSION_EXPIRY,
            )
            .expect("Unable to create uat");
        let ident = idms_prox_write
            .process_uat_to_identity(&uat, ct)
            .expect("Unable to process uat");

        assert!(!ident.has_claim("authtype_password"));
        assert!(!ident.has_claim("authclass_single"));
        // Does NOT have this
        assert!(!ident.has_claim("authlevel_strong"));
        assert!(!ident.has_claim("authclass_mfa"));

        // == generatedpassword
        let uat = account
            .to_userauthtoken(
                session_id,
                SessionScope::ReadWrite,
                ct,
                DEFAULT_AUTH_SESSION_EXPIRY,
            )
            .expect("Unable to create uat");
        let ident = idms_prox_write
            .process_uat_to_identity(&uat, ct)
            .expect("Unable to process uat");

        assert!(!ident.has_claim("authtype_generatedpassword"));
        assert!(!ident.has_claim("authclass_single"));
        assert!(!ident.has_claim("authlevel_strong"));
        // Does NOT have this
        assert!(!ident.has_claim("authclass_mfa"));

        // == webauthn
        let uat = account
            .to_userauthtoken(
                session_id,
                SessionScope::ReadWrite,
                ct,
                DEFAULT_AUTH_SESSION_EXPIRY,
            )
            .expect("Unable to create uat");
        let ident = idms_prox_write
            .process_uat_to_identity(&uat, ct)
            .expect("Unable to process uat");

        assert!(!ident.has_claim("authtype_webauthn"));
        assert!(!ident.has_claim("authclass_single"));
        assert!(!ident.has_claim("authlevel_strong"));
        // Does NOT have this
        assert!(!ident.has_claim("authclass_mfa"));

        // == passwordmfa
        let uat = account
            .to_userauthtoken(
                session_id,
                SessionScope::ReadWrite,
                ct,
                DEFAULT_AUTH_SESSION_EXPIRY,
            )
            .expect("Unable to create uat");
        let ident = idms_prox_write
            .process_uat_to_identity(&uat, ct)
            .expect("Unable to process uat");

        assert!(!ident.has_claim("authtype_passwordmfa"));
        assert!(!ident.has_claim("authlevel_strong"));
        assert!(!ident.has_claim("authclass_mfa"));
        // Does NOT have this
        assert!(!ident.has_claim("authclass_single"));
    }

    #[idm_test]
    async fn test_idm_jwt_uat_token_key_reload(
        idms: &IdmServer,
        idms_delayed: &mut IdmServerDelayed,
    ) {
        let ct = Duration::from_secs(TEST_CURRENT_TIME);

        init_admin_w_password(idms, TEST_PASSWORD)
            .await
            .expect("Failed to setup admin account");
        let token = check_admin_password(idms, TEST_PASSWORD).await;

        // Clear the session record
        let da = idms_delayed.try_recv().expect("invalid");
        assert!(matches!(da, DelayedAction::AuthSessionRecord(_)));
        idms_delayed.check_is_empty_or_panic();

        let mut idms_prox_read = idms.proxy_read().await;

        // Check it's valid.
        idms_prox_read
            .validate_and_parse_token_to_ident(Some(token.as_str()), ct)
            .expect("Failed to validate");

        drop(idms_prox_read);

        // Now reset the token_key - we can cheat and push this
        // through the migrate 3 to 4 code.
        //
        // fernet_private_key_str
        // es256_private_key_der
        let mut idms_prox_write = idms.proxy_write(ct).await;
        let me_reset_tokens = ModifyEvent::new_internal_invalid(
            filter!(f_eq(Attribute::Uuid, PartialValue::Uuid(UUID_DOMAIN_INFO))),
            ModifyList::new_list(vec![
                Modify::Purged(Attribute::FernetPrivateKeyStr.into()),
                Modify::Purged(Attribute::Es256PrivateKeyDer.into()),
                Modify::Purged(Attribute::DomainTokenKey.into()),
            ]),
        );
        assert!(idms_prox_write.qs_write.modify(&me_reset_tokens).is_ok());
        assert!(idms_prox_write.commit().is_ok());
        // Check the old token is invalid, due to reload.
        let new_token = check_admin_password(idms, TEST_PASSWORD).await;

        // Clear the session record
        let da = idms_delayed.try_recv().expect("invalid");
        assert!(matches!(da, DelayedAction::AuthSessionRecord(_)));
        idms_delayed.check_is_empty_or_panic();

        let mut idms_prox_read = idms.proxy_read().await;
        assert!(idms_prox_read
            .validate_and_parse_token_to_ident(Some(token.as_str()), ct)
            .is_err());
        // A new token will work due to the matching key.
        idms_prox_read
            .validate_and_parse_token_to_ident(Some(new_token.as_str()), ct)
            .expect("Failed to validate");
    }

    #[idm_test]
    async fn test_idm_service_account_to_person(
        idms: &IdmServer,
        _idms_delayed: &mut IdmServerDelayed,
    ) {
        let ct = Duration::from_secs(TEST_CURRENT_TIME);
        let mut idms_prox_write = idms.proxy_write(ct).await;

        let ident = Identity::from_internal();
        let target_uuid = Uuid::new_v4();

        // Create a service account
        let e = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Account.to_value()),
            (Attribute::Class, EntryClass::ServiceAccount.to_value()),
            (Attribute::Name, Value::new_iname("testaccount")),
            (Attribute::Uuid, Value::Uuid(target_uuid)),
            (Attribute::Description, Value::new_utf8s("testaccount")),
            (Attribute::DisplayName, Value::new_utf8s("Test Account"))
        );

        let ce = CreateEvent::new_internal(vec![e]);
        let cr = idms_prox_write.qs_write.create(&ce);
        assert!(cr.is_ok());

        // Do the migrate.
        assert!(idms_prox_write
            .service_account_into_person(&ident, target_uuid)
            .is_ok());

        // Any checks?
    }
}
