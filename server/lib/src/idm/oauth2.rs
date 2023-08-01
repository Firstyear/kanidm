//! Oauth2 resource server configurations
//!
//! This contains the in memory and loaded set of active oauth2 resource server
//! integrations, which are then able to be used an accessed from the IDM layer
//! for operations involving oauth2 authentication processing.

use std::collections::{BTreeMap, BTreeSet};
use std::convert::TryFrom;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use base64::{engine::general_purpose, Engine as _};

use base64urlsafedata::Base64UrlSafeData;
pub use compact_jwt::{JwkKeySet, OidcToken};
use compact_jwt::{JwsSigner, OidcClaims, OidcSubject};
use concread::cowcell::*;
use fernet::Fernet;
use hashbrown::HashMap;
pub use kanidm_proto::oauth2::{
    AccessTokenIntrospectRequest, AccessTokenIntrospectResponse, AccessTokenRequest,
    AccessTokenResponse, AuthorisationRequest, CodeChallengeMethod, ErrorResponse, GrantTypeReq,
    OidcDiscoveryResponse, TokenRevokeRequest,
};
use kanidm_proto::oauth2::{
    ClaimType, DisplayValue, GrantType, IdTokenSignAlg, ResponseMode, ResponseType, SubjectType,
    TokenEndpointAuthMethod,
};
use kanidm_proto::v1::UserAuthToken;
use openssl::sha;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use tracing::trace;
use url::{Origin, Url};

use crate::idm::account::Account;
use crate::idm::server::{
    IdmServerProxyReadTransaction, IdmServerProxyWriteTransaction, IdmServerTransaction,
};
use crate::prelude::*;
use crate::value::{Oauth2Session, OAUTHSCOPE_RE};

#[derive(Serialize, Deserialize, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Oauth2Error {
    // Non-standard - these are used to guide some control flow.
    AuthenticationRequired,
    InvalidClientId,
    InvalidOrigin,
    // Standard
    InvalidRequest,
    InvalidGrant,
    UnauthorizedClient,
    AccessDenied,
    UnsupportedResponseType,
    InvalidScope,
    ServerError(OperationError),
    TemporarilyUnavailable,
    // from https://datatracker.ietf.org/doc/html/rfc6750
    InvalidToken,
    InsufficientScope,
    // from https://datatracker.ietf.org/doc/html/rfc7009#section-2.2.1
    UnsupportedTokenType,
}

impl std::fmt::Display for Oauth2Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Oauth2Error::AuthenticationRequired => "authentication_required",
            Oauth2Error::InvalidClientId => "invalid_client_id",
            Oauth2Error::InvalidOrigin => "invalid_origin",
            Oauth2Error::InvalidGrant => "invalid_grant",
            Oauth2Error::InvalidRequest => "invalid_request",
            Oauth2Error::UnauthorizedClient => "unauthorized_client",
            Oauth2Error::AccessDenied => "access_denied",
            Oauth2Error::UnsupportedResponseType => "unsupported_response_type",
            Oauth2Error::InvalidScope => "invalid_scope",
            Oauth2Error::ServerError(_) => "server_error",
            Oauth2Error::TemporarilyUnavailable => "temporarily_unavailable",
            Oauth2Error::InvalidToken => "invalid_token",
            Oauth2Error::InsufficientScope => "insufficient_scope",
            Oauth2Error::UnsupportedTokenType => "unsupported_token_type",
        })
    }
}

// == internal state formats that we encrypt and send.

#[derive(Serialize, Deserialize, Debug, PartialEq)]
struct ConsentToken {
    pub client_id: String,
    // Must match the session id of the Uat,
    pub session_id: Uuid,
    // So we can ensure that we really match the same uat to prevent confusions.
    pub ident_id: IdentityId,
    // CSRF
    pub state: String,
    // The S256 code challenge.
    pub code_challenge: Option<Base64UrlSafeData>,
    // Where the RS wants us to go back to.
    pub redirect_uri: Url,
    // The scopes being granted
    pub scopes: BTreeSet<String>,
    // We stash some details here for oidc.
    pub nonce: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
struct TokenExchangeCode {
    // We don't need the client_id here, because it's signed with an RS specific
    // key which gives us the assurance that it's the correct combination.
    pub uat: UserAuthToken,
    // The S256 code challenge.
    pub code_challenge: Option<Base64UrlSafeData>,
    // The original redirect uri
    pub redirect_uri: Url,
    // The scopes being granted
    pub scopes: BTreeSet<String>,
    // We stash some details here for oidc.
    pub nonce: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub(crate) enum Oauth2TokenType {
    Access {
        scopes: BTreeSet<String>,
        parent_session_id: Uuid,
        session_id: Uuid,
        #[serde(with = "time::serde::timestamp")]
        expiry: time::OffsetDateTime,
        uuid: Uuid,
        iat: i64,
        nbf: i64,
        auth_time: Option<i64>,
        // We stash some details here for oidc.
        nonce: Option<String>,
    },
    Refresh {
        scopes: BTreeSet<String>,
        parent_session_id: Uuid,
        session_id: Uuid,
        #[serde(with = "time::serde::timestamp")]
        expiry: time::OffsetDateTime,
        uuid: Uuid,
        //
        iat: i64,
        nbf: i64,
        // We stash some details here for oidc.
        nonce: Option<String>,
    },
}

impl fmt::Display for Oauth2TokenType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Oauth2TokenType::Access { session_id, .. } => {
                write!(f, "access_token ({session_id}) ")
            }
            Oauth2TokenType::Refresh { session_id, .. } => {
                write!(f, "refresh_token ({session_id}) ")
            }
        }
    }
}

#[derive(Debug)]
pub enum AuthoriseResponse {
    ConsentRequested {
        // A pretty-name of the client
        client_name: String,
        // A list of scopes requested / to be issued.
        scopes: BTreeSet<String>,
        // Extra PII that may be requested
        pii_scopes: BTreeSet<String>,
        // The users displayname (?)
        // pub display_name: String,
        // The token we need to be given back to allow this to proceed
        consent_token: String,
    },
    Permitted(AuthorisePermitSuccess),
}

#[derive(Debug)]
pub struct AuthorisePermitSuccess {
    // Where the RS wants us to go back to.
    pub redirect_uri: Url,
    // The CSRF as a string
    pub state: String,
    // The exchange code as a String
    pub code: String,
}

#[derive(Clone)]
enum OauthRSType {
    Basic {
        authz_secret: String,
        enable_pkce: bool,
    },
    // Public clients must have pkce.
    Public,
}

impl std::fmt::Debug for OauthRSType {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let mut ds = f.debug_struct("Oauth2RSType");
        match self {
            OauthRSType::Basic { enable_pkce, .. } => {
                ds.field("type", &"basic").field("pkce", enable_pkce)
            }
            OauthRSType::Public => ds.field("type", &"public"),
        };
        ds.finish()
    }
}

#[derive(Clone)]
pub struct Oauth2RS {
    name: String,
    displayname: String,
    uuid: Uuid,
    origin: Origin,
    origin_https: bool,
    scope_maps: BTreeMap<Uuid, BTreeSet<String>>,
    sup_scope_maps: BTreeMap<Uuid, BTreeSet<String>>,
    // Our internal exchange encryption material for this rs.
    token_fernet: Fernet,
    jws_signer: JwsSigner,
    // jws_validator: JwsValidator,
    // For oidc we also need our issuer url.
    iss: Url,
    // For discovery we need to build and keep a number of values.
    authorization_endpoint: Url,
    token_endpoint: Url,
    userinfo_endpoint: Url,
    jwks_uri: Url,
    scopes_supported: BTreeSet<String>,
    prefer_short_username: bool,
    type_: OauthRSType,
}

impl std::fmt::Debug for Oauth2RS {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("Oauth2RS")
            .field("name", &self.name)
            .field("displayname", &self.displayname)
            .field("uuid", &self.uuid)
            .field("type", &self.type_)
            .field("origin", &self.origin)
            .field("scope_maps", &self.scope_maps)
            .field("sup_scope_maps", &self.sup_scope_maps)
            .finish()
    }
}

#[derive(Clone)]
struct Oauth2RSInner {
    origin: Url,
    fernet: Fernet,
    rs_set: HashMap<String, Oauth2RS>,
}

pub struct Oauth2ResourceServers {
    inner: CowCell<Oauth2RSInner>,
}

pub struct Oauth2ResourceServersReadTransaction {
    inner: CowCellReadTxn<Oauth2RSInner>,
}

pub struct Oauth2ResourceServersWriteTransaction<'a> {
    inner: CowCellWriteTxn<'a, Oauth2RSInner>,
}

impl TryFrom<(Vec<Arc<EntrySealedCommitted>>, Url)> for Oauth2ResourceServers {
    type Error = OperationError;

    fn try_from(value: (Vec<Arc<EntrySealedCommitted>>, Url)) -> Result<Self, Self::Error> {
        let (value, origin) = value;
        let fernet =
            Fernet::new(&Fernet::generate_key()).ok_or(OperationError::CryptographyError)?;
        let oauth2rs = Oauth2ResourceServers {
            inner: CowCell::new(Oauth2RSInner {
                origin,
                fernet,
                rs_set: HashMap::new(),
            }),
        };

        let mut oauth2rs_wr = oauth2rs.write();
        oauth2rs_wr.reload(value)?;
        oauth2rs_wr.commit();
        Ok(oauth2rs)
    }
}

impl Oauth2ResourceServers {
    pub fn read(&self) -> Oauth2ResourceServersReadTransaction {
        Oauth2ResourceServersReadTransaction {
            inner: self.inner.read(),
        }
    }

    pub fn write(&self) -> Oauth2ResourceServersWriteTransaction {
        Oauth2ResourceServersWriteTransaction {
            inner: self.inner.write(),
        }
    }
}

impl<'a> Oauth2ResourceServersWriteTransaction<'a> {
    pub fn reload(&mut self, value: Vec<Arc<EntrySealedCommitted>>) -> Result<(), OperationError> {
        let rs_set: Result<HashMap<_, _>, _> = value
            .into_iter()
            .map(|ent| {
                let uuid = ent.get_uuid();
                admin_info!(?uuid, "Checking oauth2 configuration");
                // From each entry, attempt to make an oauth2 configuration.
                if !ent.attribute_equality("class", &PVCLASS_OAUTH2_RS) {
                    admin_error!("Missing class oauth2_resource_server");
                    // Check we have oauth2_resource_server class
                    return Err(OperationError::InvalidEntryState);
                }

                let type_ = if ent.attribute_equality("class", &PVCLASS_OAUTH2_BASIC) {
                    let authz_secret = ent
                        .get_ava_single_secret("oauth2_rs_basic_secret")
                        .map(str::to_string)
                        .ok_or(OperationError::InvalidValueState)?;

                    let enable_pkce = ent
                        .get_ava_single_bool("oauth2_allow_insecure_client_disable_pkce")
                        .map(|e| !e)
                        .unwrap_or(true);

                    OauthRSType::Basic {
                        authz_secret,
                        enable_pkce,
                    }
                } else if ent.attribute_equality("class", &PVCLASS_OAUTH2_PUBLIC) {
                    OauthRSType::Public
                } else {
                    error!("Missing class determining oauth2 rs type");
                    return Err(OperationError::InvalidEntryState);
                };

                // Now we know we can load the shared attrs.
                let name = ent
                    .get_ava_single_iname("oauth2_rs_name")
                    .map(str::to_string)
                    .ok_or(OperationError::InvalidValueState)?;

                let displayname = ent
                    .get_ava_single_utf8("displayname")
                    .map(str::to_string)
                    .ok_or(OperationError::InvalidValueState)?;

                let (origin, origin_https) = ent
                    .get_ava_single_url("oauth2_rs_origin")
                    .map(|url| (url.origin(), url.scheme() == "https"))
                    .ok_or(OperationError::InvalidValueState)?;

                let landing_valid = ent
                    .get_ava_single_url("oauth2_rs_origin_landing")
                    .map(|url| url.origin() == origin).
                    unwrap_or(true);

                if !landing_valid {
                    warn!("{} has a landing page that is not part of origin. May be invalid.", name);
                }

                let token_fernet = ent
                    .get_ava_single_secret("oauth2_rs_token_key")
                    .ok_or(OperationError::InvalidValueState)
                    .and_then(|key| {
                        Fernet::new(key).ok_or(OperationError::CryptographyError)
                    })?;

                let scope_maps = ent
                    .get_ava_as_oauthscopemaps("oauth2_rs_scope_map")
                    .cloned()
                    .unwrap_or_default();

                let sup_scope_maps = ent
                    .get_ava_as_oauthscopemaps("oauth2_rs_sup_scope_map")
                    .cloned()
                    .unwrap_or_default();

                trace!("oauth2_jwt_legacy_crypto_enable");
                let jws_signer = if ent.get_ava_single_bool("oauth2_jwt_legacy_crypto_enable").unwrap_or(false) {
                    trace!("rs256_private_key_der");
                    ent
                        .get_ava_single_private_binary("rs256_private_key_der")
                        .ok_or(OperationError::InvalidValueState)
                        .and_then(|key_der| {
                            JwsSigner::from_rs256_der(key_der).map_err(|e| {
                                admin_error!(err = ?e, "Unable to load Legacy RS256 JwsSigner from DER");
                                OperationError::CryptographyError
                            })
                        })?
                } else {
                    trace!("es256_private_key_der");
                    ent
                        .get_ava_single_private_binary("es256_private_key_der")
                        .ok_or(OperationError::InvalidValueState)
                        .and_then(|key_der| {
                            JwsSigner::from_es256_der(key_der).map_err(|e| {
                                admin_error!(err = ?e, "Unable to load ES256 JwsSigner from DER");
                                OperationError::CryptographyError
                            })
                        })?
                };

                let prefer_short_username = ent
                    .get_ava_single_bool("oauth2_prefer_short_username")
                    .unwrap_or(false);

                let mut authorization_endpoint = self.inner.origin.clone();
                authorization_endpoint.set_path("/ui/oauth2");

                let mut token_endpoint = self.inner.origin.clone();
                token_endpoint.set_path("/oauth2/token");

                let mut userinfo_endpoint = self.inner.origin.clone();
                userinfo_endpoint.set_path(&format!("/oauth2/openid/{name}/userinfo"));

                let mut jwks_uri = self.inner.origin.clone();
                jwks_uri.set_path(&format!("/oauth2/openid/{name}/public_key.jwk"));

                let mut iss = self.inner.origin.clone();
                iss.set_path(&format!("/oauth2/openid/{name}"));

                let scopes_supported: BTreeSet<String> =
                scope_maps
                    .values()
                    .flat_map(|bts| bts.iter())

                    .chain(
                        sup_scope_maps
                            .values()
                            .flat_map(|bts| bts.iter())
                    )

                    .cloned()
                    .collect();

                let client_id = name.clone();
                let rscfg = Oauth2RS {
                    name,
                    displayname,
                    uuid,
                    origin,
                    origin_https,
                    scope_maps,
                    sup_scope_maps,
                    token_fernet,
                    jws_signer,
                    iss,
                    authorization_endpoint,
                    token_endpoint,
                    userinfo_endpoint,
                    jwks_uri,
                    scopes_supported,
                    prefer_short_username,
                    type_,
                };

                Ok((client_id, rscfg))
            })
            .collect();

        rs_set.map(|mut rs_set| {
            // Delay getting the inner mut (which may clone) until we know we are ok.
            let inner_ref = self.inner.get_mut();
            // Swap them if we are ok
            std::mem::swap(&mut inner_ref.rs_set, &mut rs_set);
        })
    }

    pub fn commit(self) {
        self.inner.commit();
    }
}

impl<'a> IdmServerProxyWriteTransaction<'a> {
    pub fn oauth2_token_revoke(
        &mut self,
        client_authz: &str,
        revoke_req: &TokenRevokeRequest,
        ct: Duration,
    ) -> Result<(), Oauth2Error> {
        let (client_id, secret) = parse_basic_authz(client_authz)?;

        // Get the o2rs for the handle.
        let o2rs = self.oauth2rs.inner.rs_set.get(&client_id).ok_or_else(|| {
            admin_warn!("Invalid oauth2 client_id");
            Oauth2Error::AuthenticationRequired
        })?;

        // check the secret.
        match &o2rs.type_ {
            OauthRSType::Basic { authz_secret, .. } => {
                if authz_secret != &secret {
                    security_info!("Invalid oauth2 client_id secret");
                    return Err(Oauth2Error::AuthenticationRequired);
                }
            }
            // Relies on the token to be valid.
            OauthRSType::Public => {}
        };

        // We are authenticated! Yay! Now we can actually check things ...

        // Can we deserialise the token?
        let token: Oauth2TokenType = o2rs
            .token_fernet
            .decrypt(&revoke_req.token)
            .map_err(|_| {
                admin_error!("Failed to decrypt token introspection request");
                Oauth2Error::InvalidRequest
            })
            .and_then(|data| {
                serde_json::from_slice(&data).map_err(|e| {
                    admin_error!("Failed to deserialise token - {:?}", e);
                    Oauth2Error::InvalidRequest
                })
            })?;

        // From these tokens, what we need is the identifiers that *might* exist,
        // such that we can remove them.
        match token {
            Oauth2TokenType::Access {
                session_id,
                expiry,
                uuid,
                ..
            }
            | Oauth2TokenType::Refresh {
                session_id,
                expiry,
                uuid,
                ..
            } => {
                // Only submit a revocation if the token is not yet expired.
                let odt_ct = OffsetDateTime::UNIX_EPOCH + ct;
                if expiry <= odt_ct {
                    security_info!(?uuid, "access token has expired, returning inactive");
                    return Ok(());
                }

                // Consider replication. We have servers A and B. A issues our oauth2
                // token to the client. The resource server then issues the revoke request
                // to B. In this case A has not yet replicated the session to B, but we
                // still need to ensure the revoke is respected. As a result, we don't
                // actually consult if the session is present on the account, we simply
                // submit the Modify::Remove. This way it's inserted into the entry changelog
                // and when replication converges the session is actually removed.

                let modlist = ModifyList::new_list(vec![Modify::Removed(
                    AttrString::from("oauth2_session"),
                    PartialValue::Refer(session_id),
                )]);

                self.qs_write
                    .internal_modify(&filter!(f_eq("uuid", PartialValue::Uuid(uuid))), &modlist)
                    .map_err(|e| {
                        admin_error!("Failed to modify - revoke oauth2 session {:?}", e);
                        Oauth2Error::ServerError(e)
                    })
            }
        }
    }

    pub fn check_oauth2_token_exchange(
        &mut self,
        client_authz: Option<&str>,
        token_req: &AccessTokenRequest,
        ct: Duration,
    ) -> Result<AccessTokenResponse, Oauth2Error> {
        // Public clients will send the client_id via the ATR, so we need to handle this case.
        let (client_id, secret) = if let Some(client_authz) = client_authz {
            let (client_id, secret) = parse_basic_authz(client_authz)?;
            (client_id, Some(secret))
        } else {
            match (&token_req.client_id, &token_req.client_secret) {
                (Some(a), b) => (a.clone(), b.clone()),
                _ => {
                    // We at least need the client_id, else we can't proceed!
                    security_info!(
                        "Invalid oauth2 authentication - no basic auth or missing client_id in access token request"
                    );
                    return Err(Oauth2Error::AuthenticationRequired);
                }
            }
        };

        // DANGER: Why do we have to do this? During the use of qs for internal search
        // and other operations we need qs to be mut. But when we borrow oauth2rs here we
        // cause multiple borrows to occur on struct members that freaks rust out. This *IS*
        // safe however because no element of the search or write process calls the oauth2rs
        // excepting for this idm layer within a single thread, meaning that stripping the
        // lifetime here is safe since we are the sole accessor.
        let o2rs: &Oauth2RS = unsafe {
            let s = self.oauth2rs.inner.rs_set.get(&client_id).ok_or_else(|| {
                admin_warn!("Invalid oauth2 client_id");
                Oauth2Error::AuthenticationRequired
            })?;
            &*(s as *const _)
        };

        // check the secret.
        match &o2rs.type_ {
            OauthRSType::Basic { authz_secret, .. } => {
                match secret {
                    Some(secret) => {
                        if authz_secret != &secret {
                            security_info!("Invalid oauth2 client_id secret");
                            return Err(Oauth2Error::AuthenticationRequired);
                        }
                    }
                    None => {
                        // We can only get here if we relied on the atr for the client_id and secret
                        security_info!(
                            "Invalid oauth2 authentication - no secret in access token request"
                        );
                        return Err(Oauth2Error::AuthenticationRequired);
                    }
                }
            }
            // Relies on the token to be valid - no further action needed.
            OauthRSType::Public => {}
        };

        // We are authenticated! Yay! Now we can actually check things ...

        // TODO: add refresh token grant type.
        //  If it's a refresh token grant, are the consent permissions the same?

        match &token_req.grant_type {
            GrantTypeReq::AuthorizationCode {
                code,
                redirect_uri,
                code_verifier,
            } => self.check_oauth2_token_exchange_authorization_code(
                o2rs,
                code,
                redirect_uri,
                code_verifier.as_deref(),
                ct,
            ),
            GrantTypeReq::RefreshToken {
                refresh_token,
                scope,
            } => self.check_oauth2_token_refresh(o2rs, refresh_token, scope.as_ref(), ct),
        }
    }

    pub fn check_oauth2_authorise_permit(
        &mut self,
        ident: &Identity,
        uat: &UserAuthToken,
        consent_token: &str,
        ct: Duration,
    ) -> Result<AuthorisePermitSuccess, OperationError> {
        // Decode the consent req with our system fernet key. Use a ttl of 5 minutes.
        let consent_req: ConsentToken = self
            .oauth2rs
            .inner
            .fernet
            .decrypt_at_time(consent_token, Some(300), ct.as_secs())
            .map_err(|_| {
                admin_error!("Failed to decrypt consent request");
                OperationError::CryptographyError
            })
            .and_then(|data| {
                serde_json::from_slice(&data).map_err(|e| {
                    admin_error!(err = ?e, "Failed to deserialise consent request");
                    OperationError::SerdeJsonError
                })
            })?;

        // Validate that the ident_id matches our current ident.
        if consent_req.ident_id != ident.get_event_origin_id() {
            security_info!("consent request ident id does not match the identity of our UAT.");
            return Err(OperationError::InvalidSessionState);
        }

        // Validate that the session id matches our uat.
        if consent_req.session_id != uat.session_id {
            security_info!("consent request session id does not match the session id of our UAT.");
            return Err(OperationError::InvalidSessionState);
        }

        // Get the resource server config based on this client_id.
        let o2rs = self
            .oauth2rs
            .inner
            .rs_set
            .get(&consent_req.client_id)
            .ok_or_else(|| {
                admin_error!("Invalid consent request oauth2 client_id");
                OperationError::InvalidRequestState
            })?;

        // Extract the state, code challenge, redirect_uri
        let xchg_code = TokenExchangeCode {
            uat: uat.clone(),
            code_challenge: consent_req.code_challenge,
            redirect_uri: consent_req.redirect_uri.clone(),
            scopes: consent_req.scopes.clone(),
            nonce: consent_req.nonce,
        };

        // Encrypt the exchange token with the fernet key of the client resource server
        let code_data = serde_json::to_vec(&xchg_code).map_err(|e| {
            admin_error!(err = ?e, "Unable to encode xchg_code data");
            OperationError::SerdeJsonError
        })?;

        let code = o2rs.token_fernet.encrypt_at_time(&code_data, ct.as_secs());

        // Everything is DONE! Now submit that it's all happy and the user consented correctly.
        // this will let them bypass consent steps in the future.
        // Submit that we consented to the delayed action queue

        let modlist = ModifyList::new_list(vec![
            Modify::Removed(
                AttrString::from("oauth2_consent_scope_map"),
                PartialValue::Refer(o2rs.uuid),
            ),
            Modify::Present(
                AttrString::from("oauth2_consent_scope_map"),
                Value::OauthScopeMap(o2rs.uuid, consent_req.scopes.iter().cloned().collect()),
            ),
        ]);

        self.qs_write.internal_modify(
            &filter_all!(f_eq("uuid", PartialValue::Uuid(uat.uuid))),
            &modlist,
        )?;

        Ok(AuthorisePermitSuccess {
            redirect_uri: consent_req.redirect_uri,
            state: consent_req.state,
            code,
        })
    }

    fn check_oauth2_token_exchange_authorization_code(
        &mut self,
        o2rs: &Oauth2RS,
        token_req_code: &str,
        token_req_redirect_uri: &Url,
        token_req_code_verifier: Option<&str>,
        ct: Duration,
    ) -> Result<AccessTokenResponse, Oauth2Error> {
        // Check the token_req is within the valid time, and correctly signed for
        // this client.

        let code_xchg: TokenExchangeCode = o2rs
            .token_fernet
            .decrypt_at_time(token_req_code, Some(60), ct.as_secs())
            .map_err(|_| {
                admin_error!("Failed to decrypt token exchange request");
                Oauth2Error::InvalidRequest
            })
            .and_then(|data| {
                serde_json::from_slice(&data).map_err(|e| {
                    admin_error!("Failed to deserialise token exchange code - {:?}", e);
                    Oauth2Error::InvalidRequest
                })
            })?;

        let require_pkce = match &o2rs.type_ {
            OauthRSType::Basic { enable_pkce, .. } => *enable_pkce,
            OauthRSType::Public => true,
        };

        // If we have a verifier present, we MUST assert that a code challenge is present!
        // It is worth noting here that code_xchg is *server issued* and encrypted, with
        // a short validity period. The client controlled value is in token_req.code_verifier
        if let Some(code_challenge) = code_xchg.code_challenge {
            // Validate the code_verifier
            let code_verifier = token_req_code_verifier
                    .ok_or_else(|| {
                        security_info!("PKCE code verification failed - code challenge is present, but no verifier was provided");
                        Oauth2Error::InvalidRequest
                    })?;
            let mut hasher = sha::Sha256::new();
            hasher.update(code_verifier.as_bytes());
            let code_verifier_hash: Vec<u8> = hasher.finish().to_vec();

            if code_challenge.0 != code_verifier_hash {
                security_info!(
                    "PKCE code verification failed - this may indicate malicious activity"
                );
                return Err(Oauth2Error::InvalidRequest);
            }
        } else if require_pkce {
            security_info!(
                "PKCE code verification failed - no code challenge present in PKCE enforced mode"
            );
            return Err(Oauth2Error::InvalidRequest);
        } else if token_req_code_verifier.is_some() {
            security_info!(
                "PKCE code verification failed - a code verifier is present, but no code challenge in exchange"
            );
            return Err(Oauth2Error::InvalidRequest);
        }

        // Validate the redirect_uri is the same as the original.
        if token_req_redirect_uri != &code_xchg.redirect_uri {
            security_info!("Invalid oauth2 redirect_uri (differs from original request uri)");
            return Err(Oauth2Error::InvalidOrigin);
        }

        // Check that the UAT we are issuing for still is valid.
        let odt_ct = OffsetDateTime::UNIX_EPOCH + ct;
        if let Some(expiry) = code_xchg.uat.expiry {
            if expiry <= odt_ct {
                security_info!(
                    "User Auth Token has expired before we could publish the oauth2 response"
                );
                return Err(Oauth2Error::AccessDenied);
            }
        }

        // ==== We are now GOOD TO GO! ====
        // Grant the access token response.
        let parent_session_id = code_xchg.uat.session_id;
        let session_id = Uuid::new_v4();

        let scopes = code_xchg.scopes;
        let account_uuid = code_xchg.uat.uuid;
        let nonce = code_xchg.nonce;

        self.generate_access_token_response(
            o2rs,
            ct,
            scopes,
            account_uuid,
            parent_session_id,
            session_id,
            nonce,
        )
    }

    fn check_oauth2_token_refresh(
        &mut self,
        o2rs: &Oauth2RS,
        refresh_token: &str,
        req_scopes: Option<&BTreeSet<String>>,
        ct: Duration,
    ) -> Result<AccessTokenResponse, Oauth2Error> {
        // Validate the refresh token decrypts and it's expiry is within the valid window.
        let token: Oauth2TokenType = o2rs
            .token_fernet
            .decrypt(refresh_token)
            .map_err(|_| {
                admin_error!("Failed to decrypt refresh token request");
                Oauth2Error::InvalidRequest
            })
            .and_then(|data| {
                serde_json::from_slice(&data).map_err(|e| {
                    admin_error!("Failed to deserialise token - {:?}", e);
                    Oauth2Error::InvalidRequest
                })
            })?;

        match token {
            Oauth2TokenType::Access { .. } => {
                admin_error!("attempt to refresh with access token");
                Err(Oauth2Error::InvalidToken)
            }
            Oauth2TokenType::Refresh {
                scopes,
                parent_session_id,
                session_id,
                expiry,
                uuid,
                iat,
                nbf: _,
                nonce,
            } => {
                // Get the current time in odt
                let odt_ct = OffsetDateTime::UNIX_EPOCH + ct;
                if expiry <= odt_ct {
                    security_info!(?uuid, "refresh token has expired, ");
                    return Err(Oauth2Error::InvalidToken);
                }

                // Check the session is still valid. This call checks the parent session
                // and the oauth2 session.
                let valid = self
                    .check_oauth2_account_uuid_valid(uuid, session_id, parent_session_id, iat, ct)
                    .map_err(|_| admin_error!("Account is not valid"));

                let Ok(Some(entry)) = valid else {
                    security_info!(
                        ?uuid,
                        "access token has no account not valid, returning inactive"
                    );
                    return Err(Oauth2Error::InvalidToken);
                };

                // Check the not issued before of the session relative to this refresh iat
                let oauth2_session = entry
                    .get_ava_as_oauth2session_map("oauth2_session")
                    .and_then(|map| map.get(&session_id))
                    .ok_or_else(|| {
                        security_info!(
                            ?session_id,
                            "No oauth2 session found, unable to proceed with refresh"
                        );
                        Oauth2Error::InvalidToken
                    })?;

                // If the refresh token was issued previous to the time listed in our oauth2_session
                // this indicates session desync / replay. We must nuke the session at this point.
                //
                // Need to think about how to handle this nicely give transactions.
                if iat < oauth2_session.issued_at.unix_timestamp() {
                    security_info!(
                        ?session_id,
                        "Attempt to reuse a refresh token detected, destroying session"
                    );

                    // Revoke it
                    let modlist = ModifyList::new_list(vec![Modify::Removed(
                        AttrString::from("oauth2_session"),
                        PartialValue::Refer(session_id),
                    )]);

                    self.qs_write
                        .internal_modify(&filter!(f_eq("uuid", PartialValue::Uuid(uuid))), &modlist)
                        .map_err(|e| {
                            admin_error!("Failed to modify - revoke oauth2 session {:?}", e);
                            Oauth2Error::ServerError(e)
                        })?;

                    return Err(Oauth2Error::InvalidGrant);
                }

                // Check the scopes are identical, or None.
                if let Some(req_scopes) = req_scopes {
                    if &scopes != req_scopes {
                        warn!("oauth2 scopes requested, invalid.");
                        return Err(Oauth2Error::InvalidScope);
                    } else {
                        debug!("oauth2 scopes requested, checked as valid.");
                    }
                } else {
                    debug!("No oauth2 scopes requested, this is valid.");
                };

                // ----------
                // good to go

                let account_uuid = uuid;

                self.generate_access_token_response(
                    o2rs,
                    ct,
                    scopes,
                    account_uuid,
                    parent_session_id,
                    session_id,
                    nonce,
                )
            }
        }
    }

    fn generate_access_token_response(
        &mut self,
        o2rs: &Oauth2RS,
        ct: Duration,
        //
        scopes: BTreeSet<String>,
        account_uuid: Uuid,
        parent_session_id: Uuid,
        session_id: Uuid,
        nonce: Option<String>,
    ) -> Result<AccessTokenResponse, Oauth2Error> {
        let odt_ct = OffsetDateTime::UNIX_EPOCH + ct;
        let iat = ct.as_secs() as i64;

        // TODO: Configurable from the oauth2rs configuration?

        // Disclaimer: It may seem odd here that we are ignoring our session when it comes to expiry
        // times. However, this actually is valid because when we take the initial code exchange
        // path we have already validate the expiry of the account/session in that process. For the
        // refresh path, we validate the session expiry and validity before we call this. So these
        // expiries are *purely* for the tokens we issue and are *not related* to the expiries of the
        // the session - these are enforced as above!

        let expiry = odt_ct + Duration::from_secs(OAUTH2_ACCESS_TOKEN_EXPIRY as u64);
        let expires_in = OAUTH2_ACCESS_TOKEN_EXPIRY;
        let refresh_expiry = odt_ct + Duration::from_secs(OAUTH_REFRESH_TOKEN_EXPIRY);

        let scope = if scopes.is_empty() {
            None
        } else {
            Some(str_join(&scopes))
        };

        let id_token = if scopes.contains(&"openid".to_string()) {
            // TODO: Scopes map to claims:
            //
            // * profile - (name, family\_name, given\_name, middle\_name, nickname, preferred\_username, profile, picture, website, gender, birthdate, zoneinfo, locale, and updated\_at)
            // * email - (email, email\_verified)
            // * address - (address)
            // * phone - (phone\_number, phone\_number\_verified)
            //
            // https://openid.net/specs/openid-connect-basic-1_0.html#StandardClaims

            // TODO: Can the user consent to which claims are released? Today as we don't support most
            // of them anyway, no, but in the future, we can stash these to the consent req.

            // TODO: If max_age was requested in the request, we MUST provide auth_time.

            // amr == auth method
            // We removed this from uat, and I think that it's okay here. AMR is a bit useless anyway
            // since there is no standard for what it should look like wrt to cred strength.
            let amr = None;

            let iss = o2rs.iss.clone();

            // Just reflect the access token expiry.
            let exp = expiry.unix_timestamp();

            let entry = match self.qs_write.internal_search_uuid(account_uuid) {
                Ok(entry) => entry,
                Err(err) => return Err(Oauth2Error::ServerError(err)),
            };

            let account = match Account::try_from_entry_rw(&entry, &mut self.qs_write) {
                Ok(account) => account,
                Err(err) => return Err(Oauth2Error::ServerError(err)),
            };

            let s_claims = s_claims_for_account(o2rs, &account, &scopes);
            let extra_claims = extra_claims_for_account(&account, &scopes);

            let oidc = OidcToken {
                iss,
                sub: OidcSubject::U(account_uuid),
                aud: o2rs.name.clone(),
                iat,
                nbf: Some(iat),
                exp,
                auth_time: None,
                nonce: nonce.clone(),
                at_hash: None,
                acr: None,
                amr,
                azp: Some(o2rs.name.clone()),
                jti: None,
                s_claims,
                claims: extra_claims,
            };

            trace!(?oidc);

            Some(
                oidc.sign(&o2rs.jws_signer)
                    .map(|jwt_signed| jwt_signed.to_string())
                    .map_err(|e| {
                        admin_error!(err = ?e, "Unable to encode uat data");
                        Oauth2Error::ServerError(OperationError::InvalidState)
                    })?,
            )
        } else {
            // id_token is not required in non-openid flows.
            None
        };

        // We need to record this into the record? Delayed action?

        let access_token_raw = Oauth2TokenType::Access {
            scopes: scopes.clone(),
            parent_session_id,
            session_id,
            expiry,
            uuid: account_uuid,
            iat,
            nbf: iat,
            auth_time: None,
            nonce: nonce.clone(),
        };

        let access_token_data = serde_json::to_vec(&access_token_raw).map_err(|e| {
            admin_error!(err = ?e, "Unable to encode token data");
            Oauth2Error::ServerError(OperationError::SerdeJsonError)
        })?;

        let access_token = o2rs
            .token_fernet
            .encrypt_at_time(&access_token_data, ct.as_secs());

        let refresh_token_raw = Oauth2TokenType::Refresh {
            scopes,
            parent_session_id,
            session_id,
            expiry: refresh_expiry,
            uuid: account_uuid,
            iat,
            nbf: iat,
            nonce,
        };

        let refresh_token_data = serde_json::to_vec(&refresh_token_raw).map_err(|e| {
            admin_error!(err = ?e, "Unable to encode token data");
            Oauth2Error::ServerError(OperationError::SerdeJsonError)
        })?;

        let refresh_token = o2rs
            .token_fernet
            .encrypt_at_time(&refresh_token_data, ct.as_secs());

        // Write the session to the db even with the refresh path, we need to do
        // this to update the "not issued before" time.
        let session = Value::Oauth2Session(
            session_id,
            Oauth2Session {
                parent: parent_session_id,
                expiry: Some(refresh_expiry),
                issued_at: odt_ct,
                rs_uuid: o2rs.uuid,
            },
        );

        // We need to update (replace) this session id if present.
        let modlist = ModifyList::new_list(vec![
            Modify::Removed("oauth2_session".into(), PartialValue::Refer(session_id)),
            Modify::Present("oauth2_session".into(), session),
        ]);

        self.qs_write
            .internal_modify(
                &filter!(f_eq("uuid", PartialValue::Uuid(account_uuid))),
                &modlist,
            )
            .map_err(|e| {
                admin_error!("Failed to persist oauth2 session record {:?}", e);
                Oauth2Error::ServerError(e)
            })?;

        Ok(AccessTokenResponse {
            access_token,
            token_type: "bearer".to_string(),
            expires_in,
            refresh_token: Some(refresh_token),
            scope,
            id_token,
        })
    }

    #[cfg(test)]
    fn reflect_oauth2_token(
        &mut self,
        client_authz: &str,
        token: &str,
    ) -> Result<Oauth2TokenType, OperationError> {
        let (client_id, secret) = parse_basic_authz(client_authz).map_err(|_| {
            admin_warn!("Invalid client_authz base64");
            OperationError::InvalidSessionState
        })?;

        // Get the o2rs for the handle.
        let o2rs = self.oauth2rs.inner.rs_set.get(&client_id).ok_or_else(|| {
            admin_warn!("Invalid oauth2 client_id");
            OperationError::InvalidSessionState
        })?;

        // check the secret.
        match &o2rs.type_ {
            OauthRSType::Basic { authz_secret, .. } => {
                if authz_secret != &secret {
                    security_info!("Invalid oauth2 client_id secret");
                    return Err(OperationError::InvalidSessionState);
                }
            }
            // Relies on the token to be valid.
            OauthRSType::Public => {}
        };

        o2rs.token_fernet
            .decrypt(token)
            .map_err(|_| {
                admin_error!("Failed to decrypt token introspection request");
                OperationError::CryptographyError
            })
            .and_then(|data| {
                serde_json::from_slice(&data).map_err(|e| {
                    admin_error!("Failed to deserialise token exchange code - {:?}", e);
                    OperationError::SerdeJsonError
                })
            })
    }
}

impl<'a> IdmServerProxyReadTransaction<'a> {
    pub fn check_oauth2_authorisation(
        &self,
        ident: &Identity,
        uat: &UserAuthToken,
        auth_req: &AuthorisationRequest,
        ct: Duration,
    ) -> Result<AuthoriseResponse, Oauth2Error> {
        // due to identity processing we already know that:
        // * the session must be authenticated, and valid
        // * is within it's valid time window.
        trace!(?auth_req);

        if auth_req.response_type != "code" {
            admin_warn!("Invalid oauth2 response_type (should be 'code')");
            return Err(Oauth2Error::UnsupportedResponseType);
        }

        /*
         * 4.1.2.1.  Error Response
         *
         * If the request fails due to a missing, invalid, or mismatching
         * redirection URI, or if the client identifier is missing or invalid,
         * the authorization server SHOULD inform the resource owner of the
         * error and MUST NOT automatically redirect the user-agent to the
         * invalid redirection URI.
         */

        //
        let o2rs = self
            .oauth2rs
            .inner
            .rs_set
            .get(&auth_req.client_id)
            .ok_or_else(|| {
                admin_warn!(
                    "Invalid oauth2 client_id ({}) Have you configured the oauth2 resource server?",
                    &auth_req.client_id
                );
                Oauth2Error::InvalidClientId
            })?;

        // redirect_uri must be part of the client_id origin.
        if auth_req.redirect_uri.origin() != o2rs.origin {
            admin_warn!(
                origin = ?o2rs.origin,
                "Invalid oauth2 redirect_uri (must be related to origin {:?}) - got {:?}",
                o2rs.origin,
                auth_req.redirect_uri.origin()
            );
            return Err(Oauth2Error::InvalidOrigin);
        }

        if o2rs.origin_https && auth_req.redirect_uri.scheme() != "https" {
            admin_warn!(
                origin = ?o2rs.origin,
                "Invalid oauth2 redirect_uri (must be https for secure origin) - got {:?}", auth_req.redirect_uri.scheme()
            );
            return Err(Oauth2Error::InvalidOrigin);
        }

        let require_pkce = match &o2rs.type_ {
            OauthRSType::Basic { enable_pkce, .. } => *enable_pkce,
            OauthRSType::Public => true,
        };

        let code_challenge = if let Some(pkce_request) = &auth_req.pkce_request {
            if !require_pkce {
                security_info!(?o2rs.name, "Insecure rs configuration - pkce is not enforced, but rs is requesting it!");
            }
            // CodeChallengeMethod must be S256
            if pkce_request.code_challenge_method != CodeChallengeMethod::S256 {
                admin_warn!("Invalid oauth2 code_challenge_method (must be 'S256')");
                return Err(Oauth2Error::InvalidRequest);
            }
            Some(pkce_request.code_challenge.clone())
        } else if require_pkce {
            security_error!(?o2rs.name, "No PKCE code challenge was provided with client in enforced PKCE mode.");
            return Err(Oauth2Error::InvalidRequest);
        } else {
            security_info!(?o2rs.name, "Insecure client configuration - pkce is not enforced.");
            None
        };

        // TODO: https://openid.net/specs/openid-connect-basic-1_0.html#RequestParameters
        // Are we going to provide the functions for these? Most of these can be "later".
        // IF CHANGED: Update OidcDiscoveryResponse!!!

        // TODO: https://openid.net/specs/openid-connect-basic-1_0.html#RequestParameters
        // prompt - if set to login, we need to force a re-auth. But we don't want to
        // if the user "only just" logged in, that's annoying. So we need a time window for
        // this, to detect when we should force it to the consent req.

        // TODO: display = popup vs touch vs wap etc.

        // TODO: max_age, pass through with consent req. If 0, force login.
        // Otherwise force a login re the uat timeout.

        // TODO: ui_locales / claims_locales for the ui. Only if we don't have a Uat that
        // would provide this.

        // TODO: id_token_hint - a past token which can be used as a hint.

        // NOTE: login_hint is handled in the UI code, not here.

        // Deny anonymous access to oauth2
        if uat.uuid == UUID_ANONYMOUS {
            admin_error!(
                "Invalid oauth2 request - refusing to allow user that authenticated with anonymous"
            );
            return Err(Oauth2Error::AccessDenied);
        }

        // scopes - you need to have every requested scope or this auth_req is denied.
        let req_scopes: BTreeSet<String> = auth_req
            .scope
            .split_ascii_whitespace()
            .map(str::to_string)
            .collect();
        if req_scopes.is_empty() {
            admin_error!("Invalid oauth2 request - must contain at least one requested scope");
            return Err(Oauth2Error::InvalidRequest);
        }

        // Check the scopes by our scope regex validation rules.
        if !req_scopes.iter().all(|s| OAUTHSCOPE_RE.is_match(s)) {
            admin_error!(
                "Invalid oauth2 request - requested scopes failed to pass validation rules"
            );
            return Err(Oauth2Error::InvalidScope);
        }

        let uat_scopes: BTreeSet<String> = o2rs
            .scope_maps
            .iter()
            .filter_map(|(u, m)| {
                if ident.is_memberof(*u) {
                    Some(m.iter())
                } else {
                    None
                }
            })
            .flatten()
            .cloned()
            .collect();

        // Needs to use s.to_string due to &&str which can't use the str::to_string
        let avail_scopes: Vec<String> = req_scopes
            .intersection(&uat_scopes)
            .map(|s| s.to_string())
            .collect();

        debug!(?o2rs.scope_maps);

        // Due to the intersection above, this is correct because the equal len can only
        // occur if all terms were satisfied - effectively this check is that avail_scopes
        // and req_scopes are identical after intersection with the scopes defined by uat_scopes
        if avail_scopes.len() != req_scopes.len() {
            admin_warn!(
                %ident,
                requested_scopes = ?req_scopes,
                available_scopes = ?uat_scopes,
                "Identity does not have access to the requested scopes"
            );
            return Err(Oauth2Error::AccessDenied);
        }

        drop(avail_scopes);

        // ⚠️  At this point, per scopes we are *authorised*

        // We now access the supplemental scopes that will be granted to this session. It is important
        // we DO NOT do this prior to the requested scope check, just in case we accidentally
        // confuse the two!

        // The set of scopes that are being granted during this auth_request. This is a combination
        // of the scopes that were requested, and the scopes we supplement.

        // MICRO OPTIMISATION = flag if we have openid first, so we can into_iter here rather than
        // cloning.
        let openid_requested = req_scopes.contains("openid");

        let granted_scopes: BTreeSet<String> = o2rs
            .sup_scope_maps
            .iter()
            .filter_map(|(u, m)| {
                if ident.is_memberof(*u) {
                    Some(m.iter())
                } else {
                    None
                }
            })
            .flatten()
            .cloned()
            .chain(req_scopes.into_iter())
            .collect();

        let consent_previously_granted =
            if let Some(consent_scopes) = ident.get_oauth2_consent_scopes(o2rs.uuid) {
                granted_scopes.eq(consent_scopes)
            } else {
                false
            };

        if consent_previously_granted {
            let pretty_scopes: Vec<String> = granted_scopes.iter().map(|s| s.to_owned()).collect();
            admin_info!(
                "User has previously consented, permitting with scopes: {}",
                pretty_scopes.join(",")
            );

            // Setup for the permit success
            let xchg_code = TokenExchangeCode {
                uat: uat.clone(),
                code_challenge,
                redirect_uri: auth_req.redirect_uri.clone(),
                scopes: granted_scopes.into_iter().collect(),
                nonce: auth_req.nonce.clone(),
            };

            // Encrypt the exchange token with the fernet key of the client resource server
            let code_data = serde_json::to_vec(&xchg_code).map_err(|e| {
                admin_error!(err = ?e, "Unable to encode xchg_code data");
                Oauth2Error::ServerError(OperationError::SerdeJsonError)
            })?;

            let code = o2rs.token_fernet.encrypt_at_time(&code_data, ct.as_secs());

            Ok(AuthoriseResponse::Permitted(AuthorisePermitSuccess {
                redirect_uri: auth_req.redirect_uri.clone(),
                state: auth_req.state.clone(),
                code,
            }))
        } else {
            //  Check that the scopes are the same as a previous consent (if any)
            // If oidc, what PII is visible?
            // TODO: Scopes map to claims:
            //
            // * profile - (name, family\_name, given\_name, middle\_name, nickname, preferred\_username, profile, picture, website, gender, birthdate, zoneinfo, locale, and updated\_at)
            // * email - (email, email\_verified)
            // * address - (address)
            // * phone - (phone\_number, phone\_number\_verified)
            //
            // https://openid.net/specs/openid-connect-basic-1_0.html#StandardClaims

            // IMPORTANT DISTINCTION - Here req scopes must contain openid, but the PII can be supplemented
            // be the servers scopes!
            let mut pii_scopes = BTreeSet::default();
            if openid_requested {
                // Only mutate if things were requested under openid
                if granted_scopes.contains("email") {
                    pii_scopes.insert("email".to_string());
                    pii_scopes.insert("email_verified".to_string());
                }
            };

            // Subsequent we then return an encrypted session handle which allows
            // the user to indicate their consent to this authorisation.
            //
            // This session handle is what we use in "permit" to generate the redirect.

            let consent_req = ConsentToken {
                client_id: auth_req.client_id.clone(),
                ident_id: ident.get_event_origin_id(),
                session_id: uat.session_id,
                state: auth_req.state.clone(),
                code_challenge,
                redirect_uri: auth_req.redirect_uri.clone(),
                scopes: granted_scopes.iter().cloned().collect(),
                nonce: auth_req.nonce.clone(),
            };

            let consent_data = serde_json::to_vec(&consent_req).map_err(|e| {
                admin_error!(err = ?e, "Unable to encode consent data");
                Oauth2Error::ServerError(OperationError::SerdeJsonError)
            })?;

            let consent_token = self
                .oauth2rs
                .inner
                .fernet
                .encrypt_at_time(&consent_data, ct.as_secs());

            Ok(AuthoriseResponse::ConsentRequested {
                client_name: o2rs.displayname.clone(),
                scopes: granted_scopes.into_iter().collect(),
                pii_scopes,
                consent_token,
            })
        }
    }

    pub fn check_oauth2_authorise_reject(
        &self,
        ident: &Identity,
        uat: &UserAuthToken,
        consent_token: &str,
        ct: Duration,
    ) -> Result<Url, OperationError> {
        // Decode the consent req with our system fernet key. Use a ttl of 5 minutes.
        let consent_req: ConsentToken = self
            .oauth2rs
            .inner
            .fernet
            .decrypt_at_time(consent_token, Some(300), ct.as_secs())
            .map_err(|_| {
                admin_error!("Failed to decrypt consent request");
                OperationError::CryptographyError
            })
            .and_then(|data| {
                serde_json::from_slice(&data).map_err(|e| {
                    admin_error!(err = ?e, "Failed to deserialise consent request");
                    OperationError::SerdeJsonError
                })
            })?;

        // Validate that the ident_id matches our current ident.
        if consent_req.ident_id != ident.get_event_origin_id() {
            security_info!("consent request ident id does not match the identity of our UAT.");
            return Err(OperationError::InvalidSessionState);
        }

        // Validate that the session id matches our uat.
        if consent_req.session_id != uat.session_id {
            security_info!("consent request sessien id does not match the session id of our UAT.");
            return Err(OperationError::InvalidSessionState);
        }

        // Get the resource server config based on this client_id.
        let _o2rs = self
            .oauth2rs
            .inner
            .rs_set
            .get(&consent_req.client_id)
            .ok_or_else(|| {
                admin_error!("Invalid consent request oauth2 client_id");
                OperationError::InvalidRequestState
            })?;

        // All good, now confirm the rejection to the client application.
        Ok(consent_req.redirect_uri)
    }

    pub fn check_oauth2_token_introspect(
        &mut self,
        client_authz: &str,
        intr_req: &AccessTokenIntrospectRequest,
        ct: Duration,
    ) -> Result<AccessTokenIntrospectResponse, Oauth2Error> {
        let (client_id, secret) = parse_basic_authz(client_authz)?;

        // Get the o2rs for the handle.
        let o2rs = self.oauth2rs.inner.rs_set.get(&client_id).ok_or_else(|| {
            admin_warn!("Invalid oauth2 client_id");
            Oauth2Error::AuthenticationRequired
        })?;

        // check the secret.
        match &o2rs.type_ {
            OauthRSType::Basic { authz_secret, .. } => {
                if authz_secret != &secret {
                    security_info!("Invalid oauth2 client_id secret");
                    return Err(Oauth2Error::AuthenticationRequired);
                }
            }
            // Relies on the token to be valid.
            OauthRSType::Public => {}
        };

        // We are authenticated! Yay! Now we can actually check things ...

        let token: Oauth2TokenType = o2rs
            .token_fernet
            .decrypt(&intr_req.token)
            .map_err(|_| {
                admin_error!("Failed to decrypt token introspection request");
                Oauth2Error::InvalidRequest
            })
            .and_then(|data| {
                serde_json::from_slice(&data).map_err(|e| {
                    admin_error!("Failed to deserialise token - {:?}", e);
                    Oauth2Error::InvalidRequest
                })
            })?;

        match token {
            Oauth2TokenType::Access {
                scopes,
                parent_session_id,
                session_id,
                expiry,
                uuid,
                iat,
                nbf,
                auth_time: _,
                nonce: _,
            } => {
                // Has this token expired?
                let odt_ct = OffsetDateTime::UNIX_EPOCH + ct;
                if expiry <= odt_ct {
                    security_info!(?uuid, "access token has expired, returning inactive");
                    return Ok(AccessTokenIntrospectResponse::inactive());
                }

                // Is the user expired, or the oauth2 session invalid?
                let valid = self
                    .check_oauth2_account_uuid_valid(uuid, session_id, parent_session_id, iat, ct)
                    .map_err(|_| admin_error!("Account is not valid"));

                let Ok(Some(entry)) = valid else {
                    security_info!(
                        ?uuid,
                        "access token has no account not valid, returning inactive"
                    );
                    return Ok(AccessTokenIntrospectResponse::inactive());
                };

                let account = match Account::try_from_entry_no_groups(&entry) {
                    Ok(account) => account,
                    Err(err) => return Err(Oauth2Error::ServerError(err)),
                };

                // ==== good to generate response ====

                let scope = if scopes.is_empty() {
                    None
                } else {
                    Some(str_join(&scopes))
                };

                let exp = expiry.unix_timestamp();

                let token_type = Some("access_token".to_string());
                Ok(AccessTokenIntrospectResponse {
                    active: true,
                    scope,
                    client_id: Some(client_id.clone()),
                    username: Some(account.spn),
                    token_type,
                    iat: Some(iat),
                    exp: Some(exp),
                    nbf: Some(nbf),
                    sub: Some(uuid.to_string()),
                    aud: Some(client_id),
                    iss: None,
                    jti: None,
                })
            }
            Oauth2TokenType::Refresh { .. } => Ok(AccessTokenIntrospectResponse::inactive()),
        }
    }

    pub fn oauth2_openid_userinfo(
        &mut self,
        client_id: &str,
        token_str: &str,
        ct: Duration,
    ) -> Result<OidcToken, Oauth2Error> {
        // DANGER: Why do we have to do this? During the use of qs for internal search
        // and other operations we need qs to be mut. But when we borrow oauth2rs here we
        // cause multiple borrows to occur on struct members that freaks rust out. This *IS*
        // safe however because no element of the search or write process calls the oauth2rs
        // excepting for this idm layer within a single thread, meaning that stripping the
        // lifetime here is safe since we are the sole accessor.
        let o2rs: &Oauth2RS = unsafe {
            let s = self.oauth2rs.inner.rs_set.get(client_id).ok_or_else(|| {
                admin_warn!(
                    "Invalid oauth2 client_id (have you configured the oauth2 resource server?)"
                );
                Oauth2Error::InvalidClientId
            })?;
            &*(s as *const _)
        };

        let token: Oauth2TokenType = o2rs
            .token_fernet
            .decrypt(token_str)
            .map_err(|_| {
                admin_error!("Failed to decrypt token introspection request");
                Oauth2Error::InvalidRequest
            })
            .and_then(|data| {
                serde_json::from_slice(&data).map_err(|e| {
                    admin_error!("Failed to deserialise token exchange code - {:?}", e);
                    Oauth2Error::InvalidRequest
                })
            })?;

        match token {
            Oauth2TokenType::Access {
                scopes,
                parent_session_id,
                session_id,
                expiry,
                uuid,
                iat,
                nbf,
                auth_time: _,
                nonce,
            } => {
                // Has this token expired?
                let odt_ct = OffsetDateTime::UNIX_EPOCH + ct;
                if expiry <= odt_ct {
                    security_info!(?uuid, "access token has expired, returning inactive");
                    return Err(Oauth2Error::InvalidToken);
                }

                // Is the user expired, or the oauth2 session invalid?
                let valid = self
                    .check_oauth2_account_uuid_valid(uuid, session_id, parent_session_id, iat, ct)
                    .map_err(|_| admin_error!("Account is not valid"));

                let Ok(Some(entry)) = valid else {
                    security_info!(
                        ?uuid,
                        "access token has account not valid, returning inactive"
                    );
                    return Err(Oauth2Error::InvalidToken);
                };

                let account = match Account::try_from_entry_ro(&entry, &mut self.qs_read) {
                    Ok(account) => account,
                    Err(err) => return Err(Oauth2Error::ServerError(err)),
                };

                let amr = None;

                let iss = o2rs.iss.clone();

                let s_claims = s_claims_for_account(o2rs, &account, &scopes);
                let extra_claims = extra_claims_for_account(&account, &scopes);
                let exp = expiry.unix_timestamp();

                // ==== good to generate response ====

                Ok(OidcToken {
                    iss,
                    sub: OidcSubject::U(uuid),
                    aud: client_id.to_string(),
                    iat,
                    nbf: Some(nbf),
                    exp,
                    auth_time: None,
                    nonce,
                    at_hash: None,
                    acr: None,
                    amr,
                    azp: Some(client_id.to_string()),
                    jti: None,
                    s_claims,
                    claims: extra_claims,
                })
            }
            // https://openid.net/specs/openid-connect-basic-1_0.html#UserInfoErrorResponse
            Oauth2TokenType::Refresh { .. } => Err(Oauth2Error::InvalidToken),
        }
    }

    pub fn oauth2_openid_discovery(
        &self,
        client_id: &str,
    ) -> Result<OidcDiscoveryResponse, OperationError> {
        let o2rs = self.oauth2rs.inner.rs_set.get(client_id).ok_or_else(|| {
            admin_warn!(
                "Invalid oauth2 client_id (have you configured the oauth2 resource server?)"
            );
            OperationError::NoMatchingEntries
        })?;

        let issuer = o2rs.iss.clone();

        let authorization_endpoint = o2rs.authorization_endpoint.clone();
        let token_endpoint = o2rs.token_endpoint.clone();
        let userinfo_endpoint = Some(o2rs.userinfo_endpoint.clone());
        let jwks_uri = o2rs.jwks_uri.clone();
        let scopes_supported = Some(o2rs.scopes_supported.iter().cloned().collect());
        let response_types_supported = vec![ResponseType::Code];
        let response_modes_supported = vec![ResponseMode::Query];
        let grant_types_supported = vec![GrantType::AuthorisationCode];
        let subject_types_supported = vec![SubjectType::Public];

        let id_token_signing_alg_values_supported = match &o2rs.jws_signer {
            JwsSigner::ES256 { .. } => vec![IdTokenSignAlg::ES256],
            JwsSigner::RS256 { .. } => vec![IdTokenSignAlg::RS256],
            JwsSigner::HS256 { .. } => {
                admin_warn!("Invalid oauth2 configuration - HS256 is not supported!");
                vec![]
            }
        };

        let userinfo_signing_alg_values_supported = None;
        let token_endpoint_auth_methods_supported = vec![
            TokenEndpointAuthMethod::ClientSecretBasic,
            TokenEndpointAuthMethod::ClientSecretPost,
        ];
        let display_values_supported = Some(vec![DisplayValue::Page]);
        let claim_types_supported = vec![ClaimType::Normal];
        // What claims can we offer?
        let claims_supported = None;
        let service_documentation = Some(URL_SERVICE_DOCUMENTATION.clone());

        Ok(OidcDiscoveryResponse {
            issuer,
            authorization_endpoint,
            token_endpoint,
            userinfo_endpoint,
            jwks_uri,
            registration_endpoint: None,
            scopes_supported,
            response_types_supported,
            response_modes_supported,
            grant_types_supported,
            acr_values_supported: None,
            subject_types_supported,
            id_token_signing_alg_values_supported,
            id_token_encryption_alg_values_supported: None,
            id_token_encryption_enc_values_supported: None,
            userinfo_signing_alg_values_supported,
            userinfo_encryption_alg_values_supported: None,
            userinfo_encryption_enc_values_supported: None,
            request_object_signing_alg_values_supported: None,
            request_object_encryption_alg_values_supported: None,
            request_object_encryption_enc_values_supported: None,
            token_endpoint_auth_methods_supported,
            token_endpoint_auth_signing_alg_values_supported: None,
            display_values_supported,
            claim_types_supported,
            claims_supported,
            service_documentation,
            claims_locales_supported: None,
            ui_locales_supported: None,
            claims_parameter_supported: false,
            // I think?
            request_parameter_supported: true,
            request_uri_parameter_supported: false,
            require_request_uri_registration: false,
            op_policy_uri: None,
            op_tos_uri: None,
        })
    }

    pub fn oauth2_openid_publickey(&self, client_id: &str) -> Result<JwkKeySet, OperationError> {
        let o2rs = self.oauth2rs.inner.rs_set.get(client_id).ok_or_else(|| {
            admin_warn!(
                "Invalid oauth2 client_id (have you configured the oauth2 resource server?)"
            );
            OperationError::NoMatchingEntries
        })?;

        o2rs.jws_signer
            .public_key_as_jwk()
            .map_err(|e| {
                admin_error!("Unable to retrieve public key for {} - {:?}", o2rs.name, e);
                OperationError::InvalidState
            })
            .map(|jwk| JwkKeySet { keys: vec![jwk] })
    }
}

// TODO: this can be handled by the auth header parsers in axum
fn parse_basic_authz(client_authz: &str) -> Result<(String, String), Oauth2Error> {
    // Check the client_authz
    let authz = general_purpose::STANDARD
        .decode(client_authz)
        .map_err(|_| {
            admin_error!("Basic authz invalid base64");
            Oauth2Error::AuthenticationRequired
        })
        .and_then(|data| {
            String::from_utf8(data).map_err(|_| {
                admin_error!("Basic authz invalid utf8");
                Oauth2Error::AuthenticationRequired
            })
        })?;

    // Get the first :, it should be our delim.
    //
    let mut split_iter = authz.split(':');

    let client_id = split_iter.next().ok_or_else(|| {
        admin_error!("Basic authz invalid format (corrupt input?)");
        Oauth2Error::AuthenticationRequired
    })?;
    let secret = split_iter.next().ok_or_else(|| {
        admin_error!("Basic authz invalid format (missing ':' separator?)");
        Oauth2Error::AuthenticationRequired
    })?;

    Ok((client_id.to_string(), secret.to_string()))
}

fn s_claims_for_account(
    o2rs: &Oauth2RS,
    account: &Account,
    scopes: &BTreeSet<String>,
) -> OidcClaims {
    let preferred_username = if o2rs.prefer_short_username {
        Some(account.name.clone())
    } else {
        Some(account.spn.clone())
    };

    let (email, email_verified) = if scopes.contains(&"email".to_string()) {
        if let Some(mp) = &account.mail_primary {
            (Some(mp.clone()), Some(true))
        } else {
            (None, None)
        }
    } else {
        (None, None)
    };

    OidcClaims {
        // Map from displayname
        name: Some(account.displayname.clone()),
        scopes: scopes.iter().cloned().collect(),
        preferred_username,
        email,
        email_verified,
        ..Default::default()
    }
}
fn extra_claims_for_account(
    account: &Account,
    scopes: &BTreeSet<String>,
) -> BTreeMap<String, serde_json::Value> {
    let mut extra_claims = BTreeMap::new();
    if scopes.contains(&"groups".to_string()) {
        extra_claims.insert(
            "groups".to_string(),
            account.groups.iter().map(|x| x.to_proto().uuid).collect(),
        );
    }
    extra_claims
}

fn str_join(set: &BTreeSet<String>) -> String {
    let alloc_len = set.iter().fold(0, |acc, s| acc + s.len() + 1);
    let mut buf = String::with_capacity(alloc_len);
    set.iter().for_each(|s| {
        buf.push_str(s);
        buf.push(' ');
    });

    // Remove the excess trailing space.
    let _ = buf.pop();

    buf
}

#[cfg(test)]
mod tests {
    use base64::{engine::general_purpose, Engine as _};
    use std::convert::TryFrom;
    use std::str::FromStr;
    use std::time::Duration;

    use base64urlsafedata::Base64UrlSafeData;
    use compact_jwt::{JwaAlg, Jwk, JwkUse, JwsValidator, OidcSubject, OidcUnverified};
    use kanidm_proto::oauth2::*;
    use kanidm_proto::v1::UserAuthToken;
    use openssl::sha;

    use crate::idm::oauth2::{AuthoriseResponse, Oauth2Error};
    use crate::idm::server::{IdmServer, IdmServerTransaction};
    use crate::prelude::*;

    use crate::credential::Credential;
    use kanidm_lib_crypto::CryptoPolicy;

    use super::Oauth2TokenType;

    const TEST_CURRENT_TIME: u64 = 6000;
    const UAT_EXPIRE: u64 = 5;
    const TOKEN_EXPIRE: u64 = 900;

    macro_rules! create_code_verifier {
        ($key:expr) => {{
            let code_verifier = $key.to_string();
            let mut hasher = sha::Sha256::new();
            hasher.update(code_verifier.as_bytes());
            let code_challenge: Vec<u8> = hasher.finish().iter().copied().collect();
            (Some(code_verifier), code_challenge)
        }};
    }

    macro_rules! good_authorisation_request {
        (
            $idms_prox_read:expr,
            $ident:expr,
            $uat:expr,
            $ct:expr,
            $code_challenge:expr,
            $scope:expr
        ) => {{
            let auth_req = AuthorisationRequest {
                response_type: "code".to_string(),
                client_id: "test_resource_server".to_string(),
                state: "123".to_string(),
                pkce_request: Some(PkceRequest {
                    code_challenge: Base64UrlSafeData($code_challenge),
                    code_challenge_method: CodeChallengeMethod::S256,
                }),
                redirect_uri: Url::parse("https://demo.example.com/oauth2/result").unwrap(),
                scope: $scope,
                nonce: Some("abcdef".to_string()),
                oidc_ext: Default::default(),
                unknown_keys: Default::default(),
            };

            $idms_prox_read
                .check_oauth2_authorisation($ident, $uat, &auth_req, $ct)
                .expect("Oauth2 authorisation failed")
        }};
    }

    // setup an oauth2 instance.
    async fn setup_oauth2_resource_server_basic(
        idms: &IdmServer,
        ct: Duration,
        enable_pkce: bool,
        enable_legacy_crypto: bool,
        prefer_short_username: bool,
    ) -> (String, UserAuthToken, Identity, Uuid) {
        let mut idms_prox_write = idms.proxy_write(ct).await;

        let uuid = Uuid::new_v4();

        let e: Entry<EntryInit, EntryNew> = entry_init!(
            ("class", Value::new_class("object")),
            ("class", Value::new_class("oauth2_resource_server")),
            ("class", Value::new_class("oauth2_resource_server_basic")),
            ("uuid", Value::Uuid(uuid)),
            ("oauth2_rs_name", Value::new_iname("test_resource_server")),
            ("displayname", Value::new_utf8s("test_resource_server")),
            (
                "oauth2_rs_origin",
                Value::new_url_s("https://demo.example.com").unwrap()
            ),
            // System admins
            (
                "oauth2_rs_scope_map",
                Value::new_oauthscopemap(UUID_SYSTEM_ADMINS, btreeset!["groups".to_string()])
                    .expect("invalid oauthscope")
            ),
            (
                "oauth2_rs_scope_map",
                Value::new_oauthscopemap(UUID_IDM_ALL_ACCOUNTS, btreeset!["openid".to_string()])
                    .expect("invalid oauthscope")
            ),
            (
                "oauth2_rs_sup_scope_map",
                Value::new_oauthscopemap(
                    UUID_IDM_ALL_ACCOUNTS,
                    btreeset!["supplement".to_string()]
                )
                .expect("invalid oauthscope")
            ),
            (
                "oauth2_allow_insecure_client_disable_pkce",
                Value::new_bool(!enable_pkce)
            ),
            (
                "oauth2_jwt_legacy_crypto_enable",
                Value::new_bool(enable_legacy_crypto)
            ),
            (
                "oauth2_prefer_short_username",
                Value::new_bool(prefer_short_username)
            )
        );
        let ce = CreateEvent::new_internal(vec![e]);
        assert!(idms_prox_write.qs_write.create(&ce).is_ok());

        let entry = idms_prox_write
            .qs_write
            .internal_search_uuid(uuid)
            .expect("Failed to retrieve oauth2 resource entry ");
        let secret = entry
            .get_ava_single_secret("oauth2_rs_basic_secret")
            .map(str::to_string)
            .expect("No oauth2_rs_basic_secret found");

        // Setup the uat we'll be using - note for these tests they *require*
        // the parent session to be valid and present!

        let session_id = uuid::Uuid::new_v4();

        let account = idms_prox_write
            .target_to_account(UUID_ADMIN)
            .expect("account must exist");
        let uat = account
            .to_userauthtoken(session_id, SessionScope::ReadWrite, ct)
            .expect("Unable to create uat");

        // Need the uat first for expiry.
        let expiry = uat.expiry;

        let p = CryptoPolicy::minimum();
        let cred = Credential::new_password_only(&p, "test_password").unwrap();
        let cred_id = cred.uuid;

        let session = Value::Session(
            session_id,
            crate::value::Session {
                label: "label".to_string(),
                expiry,
                issued_at: time::OffsetDateTime::UNIX_EPOCH + ct,
                issued_by: IdentityId::Internal,
                cred_id,
                scope: SessionScope::ReadWrite,
            },
        );

        // Mod the user
        let modlist = ModifyList::new_list(vec![
            Modify::Present("user_auth_token_session".into(), session),
            Modify::Present(
                "primary_credential".into(),
                Value::Cred("primary".to_string(), cred),
            ),
        ]);

        idms_prox_write
            .qs_write
            .internal_modify(
                &filter!(f_eq("uuid", PartialValue::Uuid(UUID_ADMIN))),
                &modlist,
            )
            .expect("Failed to modify user");

        let ident = idms_prox_write
            .process_uat_to_identity(&uat, ct)
            .expect("Unable to process uat");

        idms_prox_write.commit().expect("failed to commit");

        (secret, uat, ident, uuid)
    }

    async fn setup_oauth2_resource_server_public(
        idms: &IdmServer,
        ct: Duration,
    ) -> (UserAuthToken, Identity, Uuid) {
        let mut idms_prox_write = idms.proxy_write(ct).await;

        let uuid = Uuid::new_v4();

        let e: Entry<EntryInit, EntryNew> = entry_init!(
            ("class", Value::new_class("object")),
            ("class", Value::new_class("oauth2_resource_server")),
            ("class", Value::new_class("oauth2_resource_server_public")),
            ("uuid", Value::Uuid(uuid)),
            ("oauth2_rs_name", Value::new_iname("test_resource_server")),
            ("displayname", Value::new_utf8s("test_resource_server")),
            (
                "oauth2_rs_origin",
                Value::new_url_s("https://demo.example.com").unwrap()
            ),
            // System admins
            (
                "oauth2_rs_scope_map",
                Value::new_oauthscopemap(UUID_SYSTEM_ADMINS, btreeset!["groups".to_string()])
                    .expect("invalid oauthscope")
            ),
            (
                "oauth2_rs_scope_map",
                Value::new_oauthscopemap(UUID_IDM_ALL_ACCOUNTS, btreeset!["openid".to_string()])
                    .expect("invalid oauthscope")
            ),
            (
                "oauth2_rs_sup_scope_map",
                Value::new_oauthscopemap(
                    UUID_IDM_ALL_ACCOUNTS,
                    btreeset!["supplement".to_string()]
                )
                .expect("invalid oauthscope")
            )
        );
        let ce = CreateEvent::new_internal(vec![e]);
        assert!(idms_prox_write.qs_write.create(&ce).is_ok());

        // Setup the uat we'll be using - note for these tests they *require*
        // the parent session to be valid and present!

        let session_id = uuid::Uuid::new_v4();

        let account = idms_prox_write
            .target_to_account(UUID_ADMIN)
            .expect("account must exist");
        let uat = account
            .to_userauthtoken(session_id, SessionScope::ReadWrite, ct)
            .expect("Unable to create uat");

        // Need the uat first for expiry.
        let expiry = uat.expiry;

        let p = CryptoPolicy::minimum();
        let cred = Credential::new_password_only(&p, "test_password").unwrap();
        let cred_id = cred.uuid;

        let session = Value::Session(
            session_id,
            crate::value::Session {
                label: "label".to_string(),
                expiry,
                issued_at: time::OffsetDateTime::UNIX_EPOCH + ct,
                issued_by: IdentityId::Internal,
                cred_id,
                scope: SessionScope::ReadWrite,
            },
        );

        // Mod the user
        let modlist = ModifyList::new_list(vec![
            Modify::Present("user_auth_token_session".into(), session),
            Modify::Present(
                "primary_credential".into(),
                Value::Cred("primary".to_string(), cred),
            ),
        ]);

        idms_prox_write
            .qs_write
            .internal_modify(
                &filter!(f_eq("uuid", PartialValue::Uuid(UUID_ADMIN))),
                &modlist,
            )
            .expect("Failed to modify user");

        let ident = idms_prox_write
            .process_uat_to_identity(&uat, ct)
            .expect("Unable to process uat");

        idms_prox_write.commit().expect("failed to commit");

        (uat, ident, uuid)
    }

    async fn setup_idm_admin(idms: &IdmServer, ct: Duration) -> (UserAuthToken, Identity) {
        let mut idms_prox_write = idms.proxy_write(ct).await;
        let account = idms_prox_write
            .target_to_account(UUID_IDM_ADMIN)
            .expect("account must exist");
        let session_id = uuid::Uuid::new_v4();
        let uat = account
            .to_userauthtoken(session_id, SessionScope::ReadWrite, ct)
            .expect("Unable to create uat");
        let ident = idms_prox_write
            .process_uat_to_identity(&uat, ct)
            .expect("Unable to process uat");

        idms_prox_write.commit().expect("failed to commit");

        (uat, ident)
    }

    #[idm_test]
    async fn test_idm_oauth2_basic_function(
        idms: &IdmServer,
        _idms_delayed: &mut IdmServerDelayed,
    ) {
        let ct = Duration::from_secs(TEST_CURRENT_TIME);
        let (secret, uat, ident, _) =
            setup_oauth2_resource_server_basic(idms, ct, true, false, false).await;

        let idms_prox_read = idms.proxy_read().await;

        // Get an ident/uat for now.

        // == Setup the authorisation request
        let (code_verifier, code_challenge) = create_code_verifier!("Whar Garble");

        let consent_request = good_authorisation_request!(
            idms_prox_read,
            &ident,
            &uat,
            ct,
            code_challenge,
            "openid".to_string()
        );

        // Should be in the consent phase;
        let consent_token =
            if let AuthoriseResponse::ConsentRequested { consent_token, .. } = consent_request {
                consent_token
            } else {
                unreachable!();
            };

        // == Manually submit the consent token to the permit for the permit_success
        drop(idms_prox_read);
        let mut idms_prox_write = idms.proxy_write(ct).await;

        let permit_success = idms_prox_write
            .check_oauth2_authorise_permit(&ident, &uat, &consent_token, ct)
            .expect("Failed to perform oauth2 permit");

        // Check we are reflecting the CSRF properly.
        assert!(permit_success.state == "123");

        // == Submit the token exchange code.

        let token_req = AccessTokenRequest {
            grant_type: GrantTypeReq::AuthorizationCode {
                code: permit_success.code,
                redirect_uri: Url::parse("https://demo.example.com/oauth2/result").unwrap(),
                // From the first step.
                code_verifier,
            },
            client_id: Some("test_resource_server".to_string()),
            client_secret: Some(secret),
        };

        let token_response = idms_prox_write
            .check_oauth2_token_exchange(None, &token_req, ct)
            .expect("Failed to perform oauth2 token exchange");

        // 🎉 We got a token! In the future we can then check introspection from this point.
        assert!(token_response.token_type == "bearer");

        assert!(idms_prox_write.commit().is_ok());
    }

    #[idm_test]
    async fn test_idm_oauth2_public_function(
        idms: &IdmServer,
        _idms_delayed: &mut IdmServerDelayed,
    ) {
        let ct = Duration::from_secs(TEST_CURRENT_TIME);
        let (uat, ident, _) = setup_oauth2_resource_server_public(idms, ct).await;

        let idms_prox_read = idms.proxy_read().await;

        // Get an ident/uat for now.

        // == Setup the authorisation request
        let (code_verifier, code_challenge) = create_code_verifier!("Whar Garble");

        let consent_request = good_authorisation_request!(
            idms_prox_read,
            &ident,
            &uat,
            ct,
            code_challenge,
            "openid".to_string()
        );

        // Should be in the consent phase;
        let consent_token =
            if let AuthoriseResponse::ConsentRequested { consent_token, .. } = consent_request {
                consent_token
            } else {
                unreachable!();
            };

        // == Manually submit the consent token to the permit for the permit_success
        drop(idms_prox_read);
        let mut idms_prox_write = idms.proxy_write(ct).await;

        let permit_success = idms_prox_write
            .check_oauth2_authorise_permit(&ident, &uat, &consent_token, ct)
            .expect("Failed to perform oauth2 permit");

        // Check we are reflecting the CSRF properly.
        assert!(permit_success.state == "123");

        // == Submit the token exchange code.

        let token_req = AccessTokenRequest {
            grant_type: GrantTypeReq::AuthorizationCode {
                code: permit_success.code,
                redirect_uri: Url::parse("https://demo.example.com/oauth2/result").unwrap(),
                // From the first step.
                code_verifier,
            },
            client_id: Some("test_resource_server".to_string()),
            client_secret: None,
        };

        let token_response = idms_prox_write
            .check_oauth2_token_exchange(None, &token_req, ct)
            .expect("Failed to perform oauth2 token exchange");

        // 🎉 We got a token! In the future we can then check introspection from this point.
        assert!(token_response.token_type == "bearer");

        assert!(idms_prox_write.commit().is_ok());
    }

    #[idm_test]
    async fn test_idm_oauth2_invalid_authorisation_requests(
        idms: &IdmServer,
        _idms_delayed: &mut IdmServerDelayed,
    ) {
        // Test invalid oauth2 authorisation states/requests.
        let ct = Duration::from_secs(TEST_CURRENT_TIME);
        let (_secret, uat, ident, _) =
            setup_oauth2_resource_server_basic(idms, ct, true, false, false).await;

        let (anon_uat, anon_ident) = setup_idm_admin(idms, ct).await;
        let (idm_admin_uat, idm_admin_ident) = setup_idm_admin(idms, ct).await;

        // Need a uat from a user not in the group. Probs anonymous.
        let idms_prox_read = idms.proxy_read().await;

        let (_code_verifier, code_challenge) = create_code_verifier!("Whar Garble");

        let pkce_request = Some(PkceRequest {
            code_challenge: Base64UrlSafeData(code_challenge),
            code_challenge_method: CodeChallengeMethod::S256,
        });

        //  * response type != code.
        let auth_req = AuthorisationRequest {
            response_type: "NOTCODE".to_string(),
            client_id: "test_resource_server".to_string(),
            state: "123".to_string(),
            pkce_request: pkce_request.clone(),
            redirect_uri: Url::parse("https://demo.example.com/oauth2/result").unwrap(),
            scope: "openid".to_string(),
            nonce: None,
            oidc_ext: Default::default(),
            unknown_keys: Default::default(),
        };

        assert!(
            idms_prox_read
                .check_oauth2_authorisation(&ident, &uat, &auth_req, ct)
                .unwrap_err()
                == Oauth2Error::UnsupportedResponseType
        );

        // * No pkce in pkce enforced mode.
        let auth_req = AuthorisationRequest {
            response_type: "code".to_string(),
            client_id: "test_resource_server".to_string(),
            state: "123".to_string(),
            pkce_request: None,
            redirect_uri: Url::parse("https://demo.example.com/oauth2/result").unwrap(),
            scope: "openid".to_string(),
            nonce: None,
            oidc_ext: Default::default(),
            unknown_keys: Default::default(),
        };

        assert!(
            idms_prox_read
                .check_oauth2_authorisation(&ident, &uat, &auth_req, ct)
                .unwrap_err()
                == Oauth2Error::InvalidRequest
        );

        //  * invalid rs name
        let auth_req = AuthorisationRequest {
            response_type: "code".to_string(),
            client_id: "NOT A REAL RESOURCE SERVER".to_string(),
            state: "123".to_string(),
            pkce_request: pkce_request.clone(),
            redirect_uri: Url::parse("https://demo.example.com/oauth2/result").unwrap(),
            scope: "openid".to_string(),
            nonce: None,
            oidc_ext: Default::default(),
            unknown_keys: Default::default(),
        };

        assert!(
            idms_prox_read
                .check_oauth2_authorisation(&ident, &uat, &auth_req, ct)
                .unwrap_err()
                == Oauth2Error::InvalidClientId
        );

        //  * mismatched origin in the redirect.
        let auth_req = AuthorisationRequest {
            response_type: "code".to_string(),
            client_id: "test_resource_server".to_string(),
            state: "123".to_string(),
            pkce_request: pkce_request.clone(),
            redirect_uri: Url::parse("https://totes.not.sus.org/oauth2/result").unwrap(),
            scope: "openid".to_string(),
            nonce: None,
            oidc_ext: Default::default(),
            unknown_keys: Default::default(),
        };

        assert!(
            idms_prox_read
                .check_oauth2_authorisation(&ident, &uat, &auth_req, ct)
                .unwrap_err()
                == Oauth2Error::InvalidOrigin
        );

        // Requested scope is not available
        let auth_req = AuthorisationRequest {
            response_type: "code".to_string(),
            client_id: "test_resource_server".to_string(),
            state: "123".to_string(),
            pkce_request: pkce_request.clone(),
            redirect_uri: Url::parse("https://demo.example.com/oauth2/result").unwrap(),
            scope: "invalid_scope read".to_string(),
            nonce: None,
            oidc_ext: Default::default(),
            unknown_keys: Default::default(),
        };

        assert!(
            idms_prox_read
                .check_oauth2_authorisation(&ident, &uat, &auth_req, ct)
                .unwrap_err()
                == Oauth2Error::AccessDenied
        );

        // Not a member of the group.
        let auth_req = AuthorisationRequest {
            response_type: "code".to_string(),
            client_id: "test_resource_server".to_string(),
            state: "123".to_string(),
            pkce_request: pkce_request.clone(),
            redirect_uri: Url::parse("https://demo.example.com/oauth2/result").unwrap(),
            scope: "read openid".to_string(),
            nonce: None,
            oidc_ext: Default::default(),
            unknown_keys: Default::default(),
        };

        assert!(
            idms_prox_read
                .check_oauth2_authorisation(&idm_admin_ident, &idm_admin_uat, &auth_req, ct)
                .unwrap_err()
                == Oauth2Error::AccessDenied
        );

        // Deny Anonymous auth methods
        let auth_req = AuthorisationRequest {
            response_type: "code".to_string(),
            client_id: "test_resource_server".to_string(),
            state: "123".to_string(),
            pkce_request,
            redirect_uri: Url::parse("https://demo.example.com/oauth2/result").unwrap(),
            scope: "read openid".to_string(),
            nonce: None,
            oidc_ext: Default::default(),
            unknown_keys: Default::default(),
        };

        assert!(
            idms_prox_read
                .check_oauth2_authorisation(&anon_ident, &anon_uat, &auth_req, ct)
                .unwrap_err()
                == Oauth2Error::AccessDenied
        );
    }

    #[idm_test]
    async fn test_idm_oauth2_invalid_authorisation_permit_requests(
        idms: &IdmServer,
        _idms_delayed: &mut IdmServerDelayed,
    ) {
        // Test invalid oauth2 authorisation states/requests.
        let ct = Duration::from_secs(TEST_CURRENT_TIME);
        let (_secret, uat, ident, _) =
            setup_oauth2_resource_server_basic(idms, ct, true, false, false).await;

        let (uat2, ident2) = {
            let mut idms_prox_write = idms.proxy_write(ct).await;
            let account = idms_prox_write
                .target_to_account(UUID_IDM_ADMIN)
                .expect("account must exist");
            let session_id = uuid::Uuid::new_v4();
            let uat2 = account
                .to_userauthtoken(session_id, SessionScope::ReadWrite, ct)
                .expect("Unable to create uat");
            let ident2 = idms_prox_write
                .process_uat_to_identity(&uat2, ct)
                .expect("Unable to process uat");
            (uat2, ident2)
        };

        let idms_prox_read = idms.proxy_read().await;

        let (_code_verifier, code_challenge) = create_code_verifier!("Whar Garble");

        let consent_request = good_authorisation_request!(
            idms_prox_read,
            &ident,
            &uat,
            ct,
            code_challenge,
            "openid".to_string()
        );

        let consent_token =
            if let AuthoriseResponse::ConsentRequested { consent_token, .. } = consent_request {
                consent_token
            } else {
                unreachable!();
            };

        drop(idms_prox_read);
        let mut idms_prox_write = idms.proxy_write(ct).await;

        // Invalid permits
        //  * expired token, aka past ttl.
        assert!(
            idms_prox_write
                .check_oauth2_authorise_permit(
                    &ident,
                    &uat,
                    &consent_token,
                    ct + Duration::from_secs(TOKEN_EXPIRE),
                )
                .unwrap_err()
                == OperationError::CryptographyError
        );

        //  * incorrect ident
        // We get another uat, but for a different user, and we'll introduce these
        // inconsistently to cause confusion.

        assert!(
            idms_prox_write
                .check_oauth2_authorise_permit(&ident2, &uat, &consent_token, ct,)
                .unwrap_err()
                == OperationError::InvalidSessionState
        );

        //  * incorrect session id
        assert!(
            idms_prox_write
                .check_oauth2_authorise_permit(&ident, &uat2, &consent_token, ct,)
                .unwrap_err()
                == OperationError::InvalidSessionState
        );

        assert!(idms_prox_write.commit().is_ok());
    }

    #[idm_test]
    async fn test_idm_oauth2_invalid_token_exchange_requests(
        idms: &IdmServer,
        _idms_delayed: &mut IdmServerDelayed,
    ) {
        let ct = Duration::from_secs(TEST_CURRENT_TIME);
        let (secret, mut uat, ident, _) =
            setup_oauth2_resource_server_basic(idms, ct, true, false, false).await;

        // ⚠️  We set the uat expiry time to 5 seconds from TEST_CURRENT_TIME. This
        // allows all our other tests to pass, but it means when we specifically put the
        // clock forward a fraction, the fernet tokens are still valid, but the uat
        // is not.
        // IE
        //   |---------------------|------------------|
        //   TEST_CURRENT_TIME     UAT_EXPIRE         TOKEN_EXPIRE
        //
        // This lets us check a variety of time based cases.
        uat.expiry = Some(
            time::OffsetDateTime::UNIX_EPOCH
                + Duration::from_secs(TEST_CURRENT_TIME + UAT_EXPIRE - 1),
        );

        let idms_prox_read = idms.proxy_read().await;

        // == Setup the authorisation request
        let (code_verifier, code_challenge) = create_code_verifier!("Whar Garble");
        let consent_request = good_authorisation_request!(
            idms_prox_read,
            &ident,
            &uat,
            ct,
            code_challenge,
            "openid".to_string()
        );

        let consent_token =
            if let AuthoriseResponse::ConsentRequested { consent_token, .. } = consent_request {
                consent_token
            } else {
                unreachable!();
            };

        drop(idms_prox_read);
        let mut idms_prox_write = idms.proxy_write(ct).await;

        // == Manually submit the consent token to the permit for the permit_success
        let permit_success = idms_prox_write
            .check_oauth2_authorise_permit(&ident, &uat, &consent_token, ct)
            .expect("Failed to perform oauth2 permit");

        // == Submit the token exchange code.

        // Invalid token exchange
        //  * invalid client_authz (not base64)
        let token_req: AccessTokenRequest = GrantTypeReq::AuthorizationCode {
            code: permit_success.code.clone(),
            redirect_uri: Url::parse("https://demo.example.com/oauth2/result").unwrap(),
            code_verifier: code_verifier.clone(),
        }
        .into();

        assert!(
            idms_prox_write
                .check_oauth2_token_exchange(Some("not base64"), &token_req, ct)
                .unwrap_err()
                == Oauth2Error::AuthenticationRequired
        );

        //  * doesn't have :
        let client_authz =
            Some(general_purpose::STANDARD.encode(format!("test_resource_server {secret}")));
        assert!(
            idms_prox_write
                .check_oauth2_token_exchange(client_authz.as_deref(), &token_req, ct)
                .unwrap_err()
                == Oauth2Error::AuthenticationRequired
        );

        //  * invalid client_id
        let client_authz =
            Some(general_purpose::STANDARD.encode(format!("NOT A REAL SERVER:{secret}")));
        assert!(
            idms_prox_write
                .check_oauth2_token_exchange(client_authz.as_deref(), &token_req, ct)
                .unwrap_err()
                == Oauth2Error::AuthenticationRequired
        );

        //  * valid client_id, but invalid secret
        let client_authz = Some(general_purpose::STANDARD.encode("test_resource_server:12345"));
        assert!(
            idms_prox_write
                .check_oauth2_token_exchange(client_authz.as_deref(), &token_req, ct)
                .unwrap_err()
                == Oauth2Error::AuthenticationRequired
        );

        // ✅ Now the valid client_authz is in place.
        let client_authz =
            Some(general_purpose::STANDARD.encode(format!("test_resource_server:{secret}")));
        //  * expired exchange code (took too long)
        assert!(
            idms_prox_write
                .check_oauth2_token_exchange(
                    client_authz.as_deref(),
                    &token_req,
                    ct + Duration::from_secs(TOKEN_EXPIRE)
                )
                .unwrap_err()
                == Oauth2Error::InvalidRequest
        );

        //  * Uat has expired!
        // NOTE: This is setup EARLY in the test, by manipulation of the UAT expiry.
        assert!(
            idms_prox_write
                .check_oauth2_token_exchange(
                    client_authz.as_deref(),
                    &token_req,
                    ct + Duration::from_secs(UAT_EXPIRE)
                )
                .unwrap_err()
                == Oauth2Error::AccessDenied
        );

        /*
        //  * incorrect grant_type
        // No longer possible due to changes in json api
        let token_req: AccessTokenRequest = GrantTypeReq::AuthorizationCode {
            grant_type: "INCORRECT GRANT TYPE".to_string(),
            code: permit_success.code.clone(),
            redirect_uri: Url::parse("https://demo.example.com/oauth2/result").unwrap(),
            client_id: None,
            client_secret: None,
            code_verifier: code_verifier.clone(),
        };
        assert!(
            idms_prox_read
                .check_oauth2_token_exchange(client_authz.as_deref(), &token_req, ct)
                .unwrap_err()
                == Oauth2Error::InvalidRequest
        );
        */

        //  * Incorrect redirect uri
        let token_req: AccessTokenRequest = GrantTypeReq::AuthorizationCode {
            code: permit_success.code.clone(),
            redirect_uri: Url::parse("https://totes.not.sus.org/oauth2/result").unwrap(),
            code_verifier,
        }
        .into();
        assert!(
            idms_prox_write
                .check_oauth2_token_exchange(client_authz.as_deref(), &token_req, ct)
                .unwrap_err()
                == Oauth2Error::InvalidOrigin
        );

        //  * code verifier incorrect
        let token_req: AccessTokenRequest = GrantTypeReq::AuthorizationCode {
            code: permit_success.code,
            redirect_uri: Url::parse("https://demo.example.com/oauth2/result").unwrap(),
            code_verifier: Some("12345".to_string()),
        }
        .into();
        assert!(
            idms_prox_write
                .check_oauth2_token_exchange(client_authz.as_deref(), &token_req, ct)
                .unwrap_err()
                == Oauth2Error::InvalidRequest
        );

        assert!(idms_prox_write.commit().is_ok());
    }

    #[idm_test]
    async fn test_idm_oauth2_token_introspect(
        idms: &IdmServer,
        _idms_delayed: &mut IdmServerDelayed,
    ) {
        let ct = Duration::from_secs(TEST_CURRENT_TIME);
        let (secret, uat, ident, _) =
            setup_oauth2_resource_server_basic(idms, ct, true, false, false).await;
        let client_authz =
            Some(general_purpose::STANDARD.encode(format!("test_resource_server:{secret}")));

        let idms_prox_read = idms.proxy_read().await;

        // == Setup the authorisation request
        let (code_verifier, code_challenge) = create_code_verifier!("Whar Garble");
        let consent_request = good_authorisation_request!(
            idms_prox_read,
            &ident,
            &uat,
            ct,
            code_challenge,
            "openid".to_string()
        );

        let consent_token =
            if let AuthoriseResponse::ConsentRequested { consent_token, .. } = consent_request {
                consent_token
            } else {
                unreachable!();
            };

        // == Manually submit the consent token to the permit for the permit_success
        drop(idms_prox_read);
        let mut idms_prox_write = idms.proxy_write(ct).await;

        let permit_success = idms_prox_write
            .check_oauth2_authorise_permit(&ident, &uat, &consent_token, ct)
            .expect("Failed to perform oauth2 permit");

        let token_req: AccessTokenRequest = GrantTypeReq::AuthorizationCode {
            code: permit_success.code,
            redirect_uri: Url::parse("https://demo.example.com/oauth2/result").unwrap(),
            code_verifier,
        }
        .into();
        let oauth2_token = idms_prox_write
            .check_oauth2_token_exchange(client_authz.as_deref(), &token_req, ct)
            .expect("Unable to exchange for oauth2 token");

        assert!(idms_prox_write.commit().is_ok());

        // Okay, now we have the token, we can check it works with introspect.
        let mut idms_prox_read = idms.proxy_read().await;

        let intr_request = AccessTokenIntrospectRequest {
            token: oauth2_token.access_token,
            token_type_hint: None,
        };
        let intr_response = idms_prox_read
            .check_oauth2_token_introspect(client_authz.as_deref().unwrap(), &intr_request, ct)
            .expect("Failed to inspect token");

        eprintln!("👉  {intr_response:?}");
        assert!(intr_response.active);
        assert!(intr_response.scope.as_deref() == Some("openid supplement"));
        assert!(intr_response.client_id.as_deref() == Some("test_resource_server"));
        assert!(intr_response.username.as_deref() == Some("admin@example.com"));
        assert!(intr_response.token_type.as_deref() == Some("access_token"));
        assert!(intr_response.iat == Some(ct.as_secs() as i64));
        assert!(intr_response.nbf == Some(ct.as_secs() as i64));

        drop(idms_prox_read);
        // start a write,

        let mut idms_prox_write = idms.proxy_write(ct).await;
        // Expire the account, should cause introspect to return inactive.
        let v_expire = Value::new_datetime_epoch(Duration::from_secs(TEST_CURRENT_TIME - 1));
        let me_inv_m = ModifyEvent::new_internal_invalid(
            filter!(f_eq("name", PartialValue::new_iname("admin"))),
            ModifyList::new_list(vec![Modify::Present(
                AttrString::from("account_expire"),
                v_expire,
            )]),
        );
        // go!
        assert!(idms_prox_write.qs_write.modify(&me_inv_m).is_ok());
        assert!(idms_prox_write.commit().is_ok());

        // start a new read
        // check again.
        let mut idms_prox_read = idms.proxy_read().await;
        let intr_response = idms_prox_read
            .check_oauth2_token_introspect(&client_authz.unwrap(), &intr_request, ct)
            .expect("Failed to inspect token");

        assert!(!intr_response.active);
    }

    #[idm_test]
    async fn test_idm_oauth2_token_revoke(idms: &IdmServer, _idms_delayed: &mut IdmServerDelayed) {
        // First, setup to get a token.
        let ct = Duration::from_secs(TEST_CURRENT_TIME);
        let (secret, uat, ident, _) =
            setup_oauth2_resource_server_basic(idms, ct, true, false, false).await;
        let client_authz =
            Some(general_purpose::STANDARD.encode(format!("test_resource_server:{secret}")));

        let idms_prox_read = idms.proxy_read().await;

        // == Setup the authorisation request
        let (code_verifier, code_challenge) = create_code_verifier!("Whar Garble");
        let consent_request = good_authorisation_request!(
            idms_prox_read,
            &ident,
            &uat,
            ct,
            code_challenge,
            "openid".to_string()
        );

        let consent_token =
            if let AuthoriseResponse::ConsentRequested { consent_token, .. } = consent_request {
                consent_token
            } else {
                unreachable!();
            };

        // == Manually submit the consent token to the permit for the permit_success
        drop(idms_prox_read);
        let mut idms_prox_write = idms.proxy_write(ct).await;

        let permit_success = idms_prox_write
            .check_oauth2_authorise_permit(&ident, &uat, &consent_token, ct)
            .expect("Failed to perform oauth2 permit");

        // Assert that the consent was submitted
        let token_req: AccessTokenRequest = GrantTypeReq::AuthorizationCode {
            code: permit_success.code,
            redirect_uri: Url::parse("https://demo.example.com/oauth2/result").unwrap(),
            code_verifier,
        }
        .into();
        let oauth2_token = idms_prox_write
            .check_oauth2_token_exchange(client_authz.as_deref(), &token_req, ct)
            .expect("Unable to exchange for oauth2 token");

        assert!(idms_prox_write.commit().is_ok());

        // Okay, now we have the token, we can check behaviours with the revoke interface.

        // First, assert it is valid, similar to the introspect api.
        let mut idms_prox_read = idms.proxy_read().await;
        let intr_request = AccessTokenIntrospectRequest {
            token: oauth2_token.access_token.clone(),
            token_type_hint: None,
        };
        let intr_response = idms_prox_read
            .check_oauth2_token_introspect(client_authz.as_deref().unwrap(), &intr_request, ct)
            .expect("Failed to inspect token");
        eprintln!("👉  {intr_response:?}");
        assert!(intr_response.active);
        drop(idms_prox_read);

        // First, the revoke needs basic auth. Provide incorrect auth, and we fail.
        let mut idms_prox_write = idms.proxy_write(ct).await;

        let bad_client_authz = Some(general_purpose::STANDARD.encode("test_resource_server:12345"));
        let revoke_request = TokenRevokeRequest {
            token: oauth2_token.access_token.clone(),
            token_type_hint: None,
        };
        let e = idms_prox_write
            .oauth2_token_revoke(bad_client_authz.as_deref().unwrap(), &revoke_request, ct)
            .unwrap_err();
        assert!(matches!(e, Oauth2Error::AuthenticationRequired));
        assert!(idms_prox_write.commit().is_ok());

        // Now submit a non-existent/invalid token. Does not affect our tokens validity.
        let mut idms_prox_write = idms.proxy_write(ct).await;
        let revoke_request = TokenRevokeRequest {
            token: "this is an invalid token, nothing will happen!".to_string(),
            token_type_hint: None,
        };
        let e = idms_prox_write
            .oauth2_token_revoke(client_authz.as_deref().unwrap(), &revoke_request, ct)
            .unwrap_err();
        assert!(matches!(e, Oauth2Error::InvalidRequest));
        assert!(idms_prox_write.commit().is_ok());

        // Check our token is still valid.
        let mut idms_prox_read = idms.proxy_read().await;
        let intr_response = idms_prox_read
            .check_oauth2_token_introspect(client_authz.as_deref().unwrap(), &intr_request, ct)
            .expect("Failed to inspect token");
        assert!(intr_response.active);
        drop(idms_prox_read);

        // Finally revoke it.
        let mut idms_prox_write = idms.proxy_write(ct).await;
        let revoke_request = TokenRevokeRequest {
            token: oauth2_token.access_token.clone(),
            token_type_hint: None,
        };
        assert!(idms_prox_write
            .oauth2_token_revoke(client_authz.as_deref().unwrap(), &revoke_request, ct,)
            .is_ok());
        assert!(idms_prox_write.commit().is_ok());

        // Check it is still valid - this is because we are still in the GRACE window.
        let mut idms_prox_read = idms.proxy_read().await;
        let intr_response = idms_prox_read
            .check_oauth2_token_introspect(client_authz.as_deref().unwrap(), &intr_request, ct)
            .expect("Failed to inspect token");

        assert!(intr_response.active);
        drop(idms_prox_read);

        // Check after the grace window, it will be invalid.
        let ct = ct + GRACE_WINDOW;

        // Assert it is now invalid.
        let mut idms_prox_read = idms.proxy_read().await;
        let intr_response = idms_prox_read
            .check_oauth2_token_introspect(client_authz.as_deref().unwrap(), &intr_request, ct)
            .expect("Failed to inspect token");

        assert!(!intr_response.active);
        drop(idms_prox_read);

        // A second invalidation of the token "does nothing".
        let mut idms_prox_write = idms.proxy_write(ct).await;
        let revoke_request = TokenRevokeRequest {
            token: oauth2_token.access_token,
            token_type_hint: None,
        };
        assert!(idms_prox_write
            .oauth2_token_revoke(client_authz.as_deref().unwrap(), &revoke_request, ct,)
            .is_ok());
        assert!(idms_prox_write.commit().is_ok());
    }

    #[idm_test]
    async fn test_idm_oauth2_session_cleanup_post_rs_delete(
        idms: &IdmServer,
        _idms_delayed: &mut IdmServerDelayed,
    ) {
        // First, setup to get a token.
        let ct = Duration::from_secs(TEST_CURRENT_TIME);
        let (secret, uat, ident, _) =
            setup_oauth2_resource_server_basic(idms, ct, true, false, false).await;
        let client_authz =
            Some(general_purpose::STANDARD.encode(format!("test_resource_server:{secret}")));

        let idms_prox_read = idms.proxy_read().await;

        // == Setup the authorisation request
        let (code_verifier, code_challenge) = create_code_verifier!("Whar Garble");
        let consent_request = good_authorisation_request!(
            idms_prox_read,
            &ident,
            &uat,
            ct,
            code_challenge,
            "openid".to_string()
        );

        let consent_token =
            if let AuthoriseResponse::ConsentRequested { consent_token, .. } = consent_request {
                consent_token
            } else {
                unreachable!();
            };

        // == Manually submit the consent token to the permit for the permit_success
        drop(idms_prox_read);
        let mut idms_prox_write = idms.proxy_write(ct).await;

        let permit_success = idms_prox_write
            .check_oauth2_authorise_permit(&ident, &uat, &consent_token, ct)
            .expect("Failed to perform oauth2 permit");

        let token_req: AccessTokenRequest = GrantTypeReq::AuthorizationCode {
            code: permit_success.code,
            redirect_uri: Url::parse("https://demo.example.com/oauth2/result").unwrap(),
            code_verifier,
        }
        .into();

        let oauth2_token = idms_prox_write
            .check_oauth2_token_exchange(client_authz.as_deref(), &token_req, ct)
            .expect("Unable to exchange for oauth2 token");

        let reflected_token = idms_prox_write
            .reflect_oauth2_token(client_authz.as_ref().unwrap(), &oauth2_token.access_token)
            .expect("Failed to access internals of the refresh token");

        let session_id = match reflected_token {
            Oauth2TokenType::Refresh { session_id, .. } => session_id,
            Oauth2TokenType::Access { session_id, .. } => session_id,
        };

        assert!(idms_prox_write.commit().is_ok());

        // Process it to ensure the record exists.
        let mut idms_prox_write = idms.proxy_write(ct).await;

        // Check it is now there
        let entry = idms_prox_write
            .qs_write
            .internal_search_uuid(UUID_ADMIN)
            .expect("failed");
        let valid = entry
            .get_ava_as_oauth2session_map("oauth2_session")
            .map(|map| map.get(&session_id).is_some())
            .unwrap_or(false);
        assert!(valid);

        // Delete the resource server.

        let de = DeleteEvent::new_internal_invalid(filter!(f_eq(
            "oauth2_rs_name",
            PartialValue::new_iname("test_resource_server")
        )));

        assert!(idms_prox_write.qs_write.delete(&de).is_ok());

        // Assert the session is gone. This is cleaned up as an artifact of the referential
        // integrity plugin.
        let entry = idms_prox_write
            .qs_write
            .internal_search_uuid(UUID_ADMIN)
            .expect("failed");
        let valid = entry
            .get_ava_as_oauth2session_map("oauth2_session")
            .map(|map| map.get(&session_id).is_some())
            .unwrap_or(false);
        assert!(!valid);

        assert!(idms_prox_write.commit().is_ok());
    }

    #[idm_test]
    async fn test_idm_oauth2_authorisation_reject(
        idms: &IdmServer,
        _idms_delayed: &mut IdmServerDelayed,
    ) {
        let ct = Duration::from_secs(TEST_CURRENT_TIME);
        let (_secret, uat, ident, _) =
            setup_oauth2_resource_server_basic(idms, ct, true, false, false).await;

        let (uat2, ident2) = {
            let mut idms_prox_write = idms.proxy_write(ct).await;
            let account = idms_prox_write
                .target_to_account(UUID_IDM_ADMIN)
                .expect("account must exist");
            let session_id = uuid::Uuid::new_v4();
            let uat2 = account
                .to_userauthtoken(session_id, SessionScope::ReadWrite, ct)
                .expect("Unable to create uat");
            let ident2 = idms_prox_write
                .process_uat_to_identity(&uat2, ct)
                .expect("Unable to process uat");
            (uat2, ident2)
        };

        let idms_prox_read = idms.proxy_read().await;
        let redirect_uri = Url::parse("https://demo.example.com/oauth2/result").unwrap();
        let (_code_verifier, code_challenge) = create_code_verifier!("Whar Garble");

        // Check reject behaviour
        let consent_request = good_authorisation_request!(
            idms_prox_read,
            &ident,
            &uat,
            ct,
            code_challenge,
            "openid".to_string()
        );

        let consent_token =
            if let AuthoriseResponse::ConsentRequested { consent_token, .. } = consent_request {
                consent_token
            } else {
                unreachable!();
            };

        let reject_success = idms_prox_read
            .check_oauth2_authorise_reject(&ident, &uat, &consent_token, ct)
            .expect("Failed to perform oauth2 reject");

        assert!(reject_success == redirect_uri);

        // Too much time past to reject
        let past_ct = Duration::from_secs(TEST_CURRENT_TIME + 301);
        assert!(
            idms_prox_read
                .check_oauth2_authorise_reject(&ident, &uat, &consent_token, past_ct)
                .unwrap_err()
                == OperationError::CryptographyError
        );

        // Invalid consent token
        assert!(
            idms_prox_read
                .check_oauth2_authorise_reject(&ident, &uat, "not a token", ct)
                .unwrap_err()
                == OperationError::CryptographyError
        );

        // Wrong UAT
        assert!(
            idms_prox_read
                .check_oauth2_authorise_reject(&ident, &uat2, &consent_token, ct)
                .unwrap_err()
                == OperationError::InvalidSessionState
        );
        // Wrong ident
        assert!(
            idms_prox_read
                .check_oauth2_authorise_reject(&ident2, &uat, &consent_token, ct)
                .unwrap_err()
                == OperationError::InvalidSessionState
        );
    }

    #[idm_test]
    async fn test_idm_oauth2_openid_discovery(
        idms: &IdmServer,
        _idms_delayed: &mut IdmServerDelayed,
    ) {
        let ct = Duration::from_secs(TEST_CURRENT_TIME);
        let (_secret, _uat, _ident, _) =
            setup_oauth2_resource_server_basic(idms, ct, true, false, false).await;

        let idms_prox_read = idms.proxy_read().await;

        // check the discovery end point works as we expect
        assert!(
            idms_prox_read
                .oauth2_openid_discovery("nosuchclient")
                .unwrap_err()
                == OperationError::NoMatchingEntries
        );

        assert!(
            idms_prox_read
                .oauth2_openid_publickey("nosuchclient")
                .unwrap_err()
                == OperationError::NoMatchingEntries
        );

        let discovery = idms_prox_read
            .oauth2_openid_discovery("test_resource_server")
            .expect("Failed to get discovery");

        let mut jwkset = idms_prox_read
            .oauth2_openid_publickey("test_resource_server")
            .expect("Failed to get public key");

        let jwk = jwkset.keys.pop().expect("no such jwk");

        match jwk {
            Jwk::EC { alg, use_, kid, .. } => {
                match (
                    alg.unwrap(),
                    &discovery.id_token_signing_alg_values_supported[0],
                ) {
                    (JwaAlg::ES256, IdTokenSignAlg::ES256) => {}
                    _ => panic!(),
                };
                assert!(use_.unwrap() == JwkUse::Sig);
                assert!(kid.is_some())
            }
            _ => panic!(),
        };

        assert!(
            discovery.issuer
                == Url::parse("https://idm.example.com/oauth2/openid/test_resource_server")
                    .unwrap()
        );

        assert!(
            discovery.authorization_endpoint
                == Url::parse("https://idm.example.com/ui/oauth2").unwrap()
        );

        assert!(
            discovery.token_endpoint == Url::parse("https://idm.example.com/oauth2/token").unwrap()
        );

        assert!(
            discovery.userinfo_endpoint
                == Some(
                    Url::parse(
                        "https://idm.example.com/oauth2/openid/test_resource_server/userinfo"
                    )
                    .unwrap()
                )
        );

        assert!(
            discovery.jwks_uri
                == Url::parse(
                    "https://idm.example.com/oauth2/openid/test_resource_server/public_key.jwk"
                )
                .unwrap()
        );

        eprintln!("{:?}", discovery.scopes_supported);
        assert!(
            discovery.scopes_supported
                == Some(vec![
                    "groups".to_string(),
                    "openid".to_string(),
                    "supplement".to_string(),
                ])
        );

        assert!(discovery.response_types_supported == vec![ResponseType::Code]);
        assert!(discovery.response_modes_supported == vec![ResponseMode::Query]);
        assert!(discovery.grant_types_supported == vec![GrantType::AuthorisationCode]);
        assert!(discovery.subject_types_supported == vec![SubjectType::Public]);
        assert!(discovery.id_token_signing_alg_values_supported == vec![IdTokenSignAlg::ES256]);
        assert!(discovery.userinfo_signing_alg_values_supported.is_none());
        assert!(
            discovery.token_endpoint_auth_methods_supported
                == vec![
                    TokenEndpointAuthMethod::ClientSecretBasic,
                    TokenEndpointAuthMethod::ClientSecretPost
                ]
        );
        assert!(discovery.display_values_supported == Some(vec![DisplayValue::Page]));
        assert!(discovery.claim_types_supported == vec![ClaimType::Normal]);
        assert!(discovery.claims_supported.is_none());
        assert!(discovery.service_documentation.is_some());

        assert!(discovery.registration_endpoint.is_none());
        assert!(discovery.acr_values_supported.is_none());
        assert!(discovery.id_token_encryption_alg_values_supported.is_none());
        assert!(discovery.id_token_encryption_enc_values_supported.is_none());
        assert!(discovery.userinfo_encryption_alg_values_supported.is_none());
        assert!(discovery.userinfo_encryption_enc_values_supported.is_none());
        assert!(discovery
            .request_object_signing_alg_values_supported
            .is_none());
        assert!(discovery
            .request_object_encryption_alg_values_supported
            .is_none());
        assert!(discovery
            .request_object_encryption_enc_values_supported
            .is_none());
        assert!(discovery
            .token_endpoint_auth_signing_alg_values_supported
            .is_none());
        assert!(discovery.claims_locales_supported.is_none());
        assert!(discovery.ui_locales_supported.is_none());
        assert!(discovery.op_policy_uri.is_none());
        assert!(discovery.op_tos_uri.is_none());
        assert!(!discovery.claims_parameter_supported);
        assert!(!discovery.request_uri_parameter_supported);
        assert!(!discovery.require_request_uri_registration);
        assert!(discovery.request_parameter_supported);
    }

    #[idm_test]
    async fn test_idm_oauth2_openid_extensions(
        idms: &IdmServer,
        _idms_delayed: &mut IdmServerDelayed,
    ) {
        let ct = Duration::from_secs(TEST_CURRENT_TIME);
        let (secret, uat, ident, _) =
            setup_oauth2_resource_server_basic(idms, ct, true, false, false).await;
        let client_authz =
            Some(general_purpose::STANDARD.encode(format!("test_resource_server:{secret}")));

        let idms_prox_read = idms.proxy_read().await;

        let (code_verifier, code_challenge) = create_code_verifier!("Whar Garble");

        let consent_request = good_authorisation_request!(
            idms_prox_read,
            &ident,
            &uat,
            ct,
            code_challenge,
            "openid".to_string()
        );

        let consent_token =
            if let AuthoriseResponse::ConsentRequested { consent_token, .. } = consent_request {
                consent_token
            } else {
                unreachable!();
            };

        // == Manually submit the consent token to the permit for the permit_success
        drop(idms_prox_read);
        let mut idms_prox_write = idms.proxy_write(ct).await;

        let permit_success = idms_prox_write
            .check_oauth2_authorise_permit(&ident, &uat, &consent_token, ct)
            .expect("Failed to perform oauth2 permit");

        // == Submit the token exchange code.
        let token_req: AccessTokenRequest = GrantTypeReq::AuthorizationCode {
            code: permit_success.code,
            redirect_uri: Url::parse("https://demo.example.com/oauth2/result").unwrap(),
            // From the first step.
            code_verifier,
        }
        .into();

        let token_response = idms_prox_write
            .check_oauth2_token_exchange(client_authz.as_deref(), &token_req, ct)
            .expect("Failed to perform oauth2 token exchange");

        // 🎉 We got a token!
        assert!(token_response.token_type == "bearer");

        let id_token = token_response.id_token.expect("No id_token in response!");
        let access_token = token_response.access_token;
        let refresh_token = token_response
            .refresh_token
            .as_ref()
            .expect("no refresh token was issued")
            .clone();

        // Get the read txn for inspecting the tokens
        assert!(idms_prox_write.commit().is_ok());

        let mut idms_prox_read = idms.proxy_read().await;

        let mut jwkset = idms_prox_read
            .oauth2_openid_publickey("test_resource_server")
            .expect("Failed to get public key");

        let public_jwk = jwkset.keys.pop().expect("no such jwk");

        let jws_validator = JwsValidator::try_from(&public_jwk).expect("failed to build validator");

        let oidc_unverified =
            OidcUnverified::from_str(&id_token).expect("Failed to parse id_token");

        let iat = ct.as_secs() as i64;

        let oidc = oidc_unverified
            .validate(&jws_validator, iat)
            .expect("Failed to verify oidc");

        // Are the id_token values what we expect?
        assert!(
            oidc.iss
                == Url::parse("https://idm.example.com/oauth2/openid/test_resource_server")
                    .unwrap()
        );
        assert!(oidc.sub == OidcSubject::U(UUID_ADMIN));
        assert!(oidc.aud == "test_resource_server");
        assert!(oidc.iat == iat);
        assert!(oidc.nbf == Some(iat));
        // Previously this was the auth session but it's now inline with the access token expiry.
        assert!(oidc.exp == iat + (OAUTH2_ACCESS_TOKEN_EXPIRY as i64));
        assert!(oidc.auth_time.is_none());
        // Is nonce correctly passed through?
        assert!(oidc.nonce == Some("abcdef".to_string()));
        assert!(oidc.at_hash.is_none());
        assert!(oidc.acr.is_none());
        assert!(oidc.amr.is_none());
        assert!(oidc.azp == Some("test_resource_server".to_string()));
        assert!(oidc.jti.is_none());
        assert!(oidc.s_claims.name == Some("System Administrator".to_string()));
        assert!(oidc.s_claims.preferred_username == Some("admin@example.com".to_string()));
        assert!(oidc.s_claims.scopes == vec!["openid".to_string(), "supplement".to_string()]);
        assert!(oidc.claims.is_empty());
        // Does our access token work with the userinfo endpoint?
        // Do the id_token details line up to the userinfo?
        let userinfo = idms_prox_read
            .oauth2_openid_userinfo("test_resource_server", &access_token, ct)
            .expect("failed to get userinfo");

        assert!(oidc.iss == userinfo.iss);
        assert!(oidc.sub == userinfo.sub);
        assert!(oidc.aud == userinfo.aud);
        assert!(oidc.iat == userinfo.iat);
        assert!(oidc.nbf == userinfo.nbf);
        assert!(oidc.exp == userinfo.exp);
        assert!(userinfo.auth_time.is_none());
        assert!(userinfo.nonce == Some("abcdef".to_string()));
        assert!(userinfo.at_hash.is_none());
        assert!(userinfo.acr.is_none());
        assert!(oidc.amr == userinfo.amr);
        assert!(oidc.azp == userinfo.azp);
        assert!(userinfo.jti.is_none());
        assert!(oidc.s_claims == userinfo.s_claims);
        assert!(userinfo.claims.is_empty());

        drop(idms_prox_read);

        // Importantly, we need to persist the nonce through access/refresh token operations
        // because some clients like the rust openidconnect library require it always for claim
        // verification.
        let mut idms_prox_write = idms.proxy_write(ct).await;

        let token_req: AccessTokenRequest = GrantTypeReq::RefreshToken {
            refresh_token,
            scope: None,
        }
        .into();

        let token_response = idms_prox_write
            .check_oauth2_token_exchange(client_authz.as_deref(), &token_req, ct)
            .expect("Unable to exchange for oauth2 token");

        let access_token = token_response.access_token;

        assert!(idms_prox_write.commit().is_ok());

        // Okay, refresh done, lets check it.
        let mut idms_prox_read = idms.proxy_read().await;

        let userinfo = idms_prox_read
            .oauth2_openid_userinfo("test_resource_server", &access_token, ct)
            .expect("failed to get userinfo");

        assert!(oidc.iss == userinfo.iss);
        assert!(oidc.sub == userinfo.sub);
        assert!(oidc.aud == userinfo.aud);
        assert!(oidc.iat == userinfo.iat);
        assert!(oidc.nbf == userinfo.nbf);
        assert!(oidc.exp == userinfo.exp);
        assert!(userinfo.auth_time.is_none());
        assert!(userinfo.nonce == Some("abcdef".to_string()));
        assert!(userinfo.at_hash.is_none());
        assert!(userinfo.acr.is_none());
        assert!(oidc.amr == userinfo.amr);
        assert!(oidc.azp == userinfo.azp);
        assert!(userinfo.jti.is_none());
        assert!(oidc.s_claims == userinfo.s_claims);
        assert!(userinfo.claims.is_empty());
    }

    #[idm_test]
    async fn test_idm_oauth2_openid_short_username(
        idms: &IdmServer,
        _idms_delayed: &mut IdmServerDelayed,
    ) {
        // we run the same test as test_idm_oauth2_openid_extensions()
        // but change the preferred_username setting on the RS
        let ct = Duration::from_secs(TEST_CURRENT_TIME);
        let (secret, uat, ident, _) =
            setup_oauth2_resource_server_basic(idms, ct, true, false, true).await;
        let client_authz =
            Some(general_purpose::STANDARD.encode(format!("test_resource_server:{secret}")));

        let idms_prox_read = idms.proxy_read().await;

        let (code_verifier, code_challenge) = create_code_verifier!("Whar Garble");

        let consent_request = good_authorisation_request!(
            idms_prox_read,
            &ident,
            &uat,
            ct,
            code_challenge,
            "openid".to_string()
        );

        let consent_token =
            if let AuthoriseResponse::ConsentRequested { consent_token, .. } = consent_request {
                consent_token
            } else {
                unreachable!();
            };

        // == Manually submit the consent token to the permit for the permit_success
        drop(idms_prox_read);
        let mut idms_prox_write = idms.proxy_write(ct).await;

        let permit_success = idms_prox_write
            .check_oauth2_authorise_permit(&ident, &uat, &consent_token, ct)
            .expect("Failed to perform oauth2 permit");

        // == Submit the token exchange code.
        let token_req: AccessTokenRequest = GrantTypeReq::AuthorizationCode {
            code: permit_success.code,
            redirect_uri: Url::parse("https://demo.example.com/oauth2/result").unwrap(),
            // From the first step.
            code_verifier,
        }
        .into();

        let token_response = idms_prox_write
            .check_oauth2_token_exchange(client_authz.as_deref(), &token_req, ct)
            .expect("Failed to perform oauth2 token exchange");

        let id_token = token_response.id_token.expect("No id_token in response!");
        let access_token = token_response.access_token;

        assert!(idms_prox_write.commit().is_ok());
        let mut idms_prox_read = idms.proxy_read().await;

        let mut jwkset = idms_prox_read
            .oauth2_openid_publickey("test_resource_server")
            .expect("Failed to get public key");
        let public_jwk = jwkset.keys.pop().expect("no such jwk");

        let jws_validator = JwsValidator::try_from(&public_jwk).expect("failed to build validator");

        let oidc_unverified =
            OidcUnverified::from_str(&id_token).expect("Failed to parse id_token");

        let iat = ct.as_secs() as i64;

        let oidc = oidc_unverified
            .validate(&jws_validator, iat)
            .expect("Failed to verify oidc");

        // Do we have the short username in the token claims?
        assert!(oidc.s_claims.preferred_username == Some("admin".to_string()));
        // Do the id_token details line up to the userinfo?
        let userinfo = idms_prox_read
            .oauth2_openid_userinfo("test_resource_server", &access_token, ct)
            .expect("failed to get userinfo");

        assert!(oidc.s_claims == userinfo.s_claims);
    }

    #[idm_test]
    async fn test_idm_oauth2_openid_group_claims(
        idms: &IdmServer,
        _idms_delayed: &mut IdmServerDelayed,
    ) {
        // we run the same test as test_idm_oauth2_openid_extensions()
        // but change the preferred_username setting on the RS
        let ct = Duration::from_secs(TEST_CURRENT_TIME);
        let (secret, uat, ident, _) =
            setup_oauth2_resource_server_basic(idms, ct, true, false, true).await;
        let client_authz =
            Some(general_purpose::STANDARD.encode(format!("test_resource_server:{secret}")));

        let idms_prox_read = idms.proxy_read().await;

        let (code_verifier, code_challenge) = create_code_verifier!("Whar Garble");

        let consent_request = good_authorisation_request!(
            idms_prox_read,
            &ident,
            &uat,
            ct,
            code_challenge,
            "openid groups".to_string()
        );

        let consent_token =
            if let AuthoriseResponse::ConsentRequested { consent_token, .. } = consent_request {
                consent_token
            } else {
                unreachable!();
            };

        // == Manually submit the consent token to the permit for the permit_success
        drop(idms_prox_read);
        let mut idms_prox_write = idms.proxy_write(ct).await;

        let permit_success = idms_prox_write
            .check_oauth2_authorise_permit(&ident, &uat, &consent_token, ct)
            .expect("Failed to perform oauth2 permit");

        // == Submit the token exchange code.
        let token_req: AccessTokenRequest = GrantTypeReq::AuthorizationCode {
            code: permit_success.code,
            redirect_uri: Url::parse("https://demo.example.com/oauth2/result").unwrap(),
            // From the first step.
            code_verifier,
        }
        .into();

        let token_response = idms_prox_write
            .check_oauth2_token_exchange(client_authz.as_deref(), &token_req, ct)
            .expect("Failed to perform oauth2 token exchange");

        let id_token = token_response.id_token.expect("No id_token in response!");
        let access_token = token_response.access_token;

        assert!(idms_prox_write.commit().is_ok());
        let mut idms_prox_read = idms.proxy_read().await;

        let mut jwkset = idms_prox_read
            .oauth2_openid_publickey("test_resource_server")
            .expect("Failed to get public key");
        let public_jwk = jwkset.keys.pop().expect("no such jwk");

        let jws_validator = JwsValidator::try_from(&public_jwk).expect("failed to build validator");

        let oidc_unverified =
            OidcUnverified::from_str(&id_token).expect("Failed to parse id_token");

        let iat = ct.as_secs() as i64;

        let oidc = oidc_unverified
            .validate(&jws_validator, iat)
            .expect("Failed to verify oidc");

        // does our id_token contain the expected groups?
        assert!(oidc.claims.contains_key(&"groups".to_string()));

        assert!(oidc
            .claims
            .get(&"groups".to_string())
            .expect("unable to find key")
            .as_array()
            .unwrap()
            .contains(&serde_json::json!(STR_UUID_IDM_ALL_ACCOUNTS)));

        // Do the id_token details line up to the userinfo?
        let userinfo = idms_prox_read
            .oauth2_openid_userinfo("test_resource_server", &access_token, ct)
            .expect("failed to get userinfo");

        // does the userinfo endpoint provide the same groups?
        assert!(
            oidc.claims.get(&"groups".to_string()) == userinfo.claims.get(&"groups".to_string())
        );
    }

    //  Check insecure pkce behaviour.
    #[idm_test]
    async fn test_idm_oauth2_insecure_pkce(idms: &IdmServer, _idms_delayed: &mut IdmServerDelayed) {
        let ct = Duration::from_secs(TEST_CURRENT_TIME);
        let (_secret, uat, ident, _) =
            setup_oauth2_resource_server_basic(idms, ct, false, false, false).await;

        let idms_prox_read = idms.proxy_read().await;

        // == Setup the authorisation request
        let (_code_verifier, code_challenge) = create_code_verifier!("Whar Garble");

        // Even in disable pkce mode, we will allow pkce
        let _consent_request = good_authorisation_request!(
            idms_prox_read,
            &ident,
            &uat,
            ct,
            code_challenge,
            "openid".to_string()
        );

        // Check we allow none.
        let auth_req = AuthorisationRequest {
            response_type: "code".to_string(),
            client_id: "test_resource_server".to_string(),
            state: "123".to_string(),
            pkce_request: None,
            redirect_uri: Url::parse("https://demo.example.com/oauth2/result").unwrap(),
            scope: "openid".to_string(),
            nonce: Some("abcdef".to_string()),
            oidc_ext: Default::default(),
            unknown_keys: Default::default(),
        };

        idms_prox_read
            .check_oauth2_authorisation(&ident, &uat, &auth_req, ct)
            .expect("Oauth2 authorisation failed");
    }

    #[idm_test]
    async fn test_idm_oauth2_openid_legacy_crypto(
        idms: &IdmServer,
        _idms_delayed: &mut IdmServerDelayed,
    ) {
        let ct = Duration::from_secs(TEST_CURRENT_TIME);
        let (secret, uat, ident, _) =
            setup_oauth2_resource_server_basic(idms, ct, false, true, false).await;
        let idms_prox_read = idms.proxy_read().await;
        // The public key url should offer an rs key
        // discovery should offer RS256
        let discovery = idms_prox_read
            .oauth2_openid_discovery("test_resource_server")
            .expect("Failed to get discovery");

        let mut jwkset = idms_prox_read
            .oauth2_openid_publickey("test_resource_server")
            .expect("Failed to get public key");

        let jwk = jwkset.keys.pop().expect("no such jwk");
        let public_jwk = jwk.clone();

        match jwk {
            Jwk::RSA { alg, use_, kid, .. } => {
                match (
                    alg.unwrap(),
                    &discovery.id_token_signing_alg_values_supported[0],
                ) {
                    (JwaAlg::RS256, IdTokenSignAlg::RS256) => {}
                    _ => panic!(),
                };
                assert!(use_.unwrap() == JwkUse::Sig);
                assert!(kid.is_some());
            }
            _ => panic!(),
        };

        // Check that the id_token is signed with the correct key.
        let (code_verifier, code_challenge) = create_code_verifier!("Whar Garble");

        let consent_request = good_authorisation_request!(
            idms_prox_read,
            &ident,
            &uat,
            ct,
            code_challenge,
            "openid".to_string()
        );

        let consent_token =
            if let AuthoriseResponse::ConsentRequested { consent_token, .. } = consent_request {
                consent_token
            } else {
                unreachable!();
            };

        // == Manually submit the consent token to the permit for the permit_success
        drop(idms_prox_read);
        let mut idms_prox_write = idms.proxy_write(ct).await;

        let permit_success = idms_prox_write
            .check_oauth2_authorise_permit(&ident, &uat, &consent_token, ct)
            .expect("Failed to perform oauth2 permit");

        // == Submit the token exchange code.
        let token_req = AccessTokenRequest {
            grant_type: GrantTypeReq::AuthorizationCode {
                code: permit_success.code,
                redirect_uri: Url::parse("https://demo.example.com/oauth2/result").unwrap(),
                // From the first step.
                code_verifier,
            },
            client_id: Some("test_resource_server".to_string()),
            client_secret: Some(secret),
        };

        let token_response = idms_prox_write
            .check_oauth2_token_exchange(None, &token_req, ct)
            .expect("Failed to perform oauth2 token exchange");

        // 🎉 We got a token!
        assert!(token_response.token_type == "bearer");
        let id_token = token_response.id_token.expect("No id_token in response!");

        let jws_validator = JwsValidator::try_from(&public_jwk).expect("failed to build validator");

        let oidc_unverified =
            OidcUnverified::from_str(&id_token).expect("Failed to parse id_token");

        let iat = ct.as_secs() as i64;

        let oidc = oidc_unverified
            .validate(&jws_validator, iat)
            .expect("Failed to verify oidc");

        assert!(oidc.sub == OidcSubject::U(UUID_ADMIN));

        assert!(idms_prox_write.commit().is_ok());
    }

    #[idm_test]
    async fn test_idm_oauth2_consent_granted_and_changed_workflow(
        idms: &IdmServer,
        _idms_delayed: &mut IdmServerDelayed,
    ) {
        let ct = Duration::from_secs(TEST_CURRENT_TIME);
        let (_secret, uat, ident, _) =
            setup_oauth2_resource_server_basic(idms, ct, true, false, false).await;

        let idms_prox_read = idms.proxy_read().await;

        let (_code_verifier, code_challenge) = create_code_verifier!("Whar Garble");
        let consent_request = good_authorisation_request!(
            idms_prox_read,
            &ident,
            &uat,
            ct,
            code_challenge,
            "openid".to_string()
        );

        // Should be in the consent phase;
        let consent_token =
            if let AuthoriseResponse::ConsentRequested { consent_token, .. } = consent_request {
                consent_token
            } else {
                unreachable!();
            };

        // == Manually submit the consent token to the permit for the permit_success
        drop(idms_prox_read);
        let mut idms_prox_write = idms.proxy_write(ct).await;

        let _permit_success = idms_prox_write
            .check_oauth2_authorise_permit(&ident, &uat, &consent_token, ct)
            .expect("Failed to perform oauth2 permit");

        assert!(idms_prox_write.commit().is_ok());

        // == Now try the authorise again, should be in the permitted state.
        let mut idms_prox_read = idms.proxy_read().await;

        // We need to reload our identity
        let ident = idms_prox_read
            .process_uat_to_identity(&uat, ct)
            .expect("Unable to process uat");

        let (_code_verifier, code_challenge) = create_code_verifier!("Whar Garble");
        let consent_request = good_authorisation_request!(
            idms_prox_read,
            &ident,
            &uat,
            ct,
            code_challenge,
            "openid".to_string()
        );

        // Should be in the consent phase;
        let _permit_success = if let AuthoriseResponse::Permitted(permit_success) = consent_request
        {
            permit_success
        } else {
            unreachable!();
        };

        drop(idms_prox_read);

        // Great! Now change the scopes on the oauth2 instance, this revokes the permit.
        let mut idms_prox_write = idms.proxy_write(ct).await;

        let me_extend_scopes = ModifyEvent::new_internal_invalid(
            filter!(f_eq(
                "oauth2_rs_name",
                PartialValue::new_iname("test_resource_server")
            )),
            ModifyList::new_list(vec![Modify::Present(
                AttrString::from("oauth2_rs_scope_map"),
                Value::new_oauthscopemap(
                    UUID_IDM_ALL_ACCOUNTS,
                    btreeset!["email".to_string(), "openid".to_string()],
                )
                .expect("invalid oauthscope"),
            )]),
        );

        assert!(idms_prox_write.qs_write.modify(&me_extend_scopes).is_ok());
        assert!(idms_prox_write.commit().is_ok());

        // And do the workflow once more to see if we need to consent again.

        let mut idms_prox_read = idms.proxy_read().await;

        // We need to reload our identity
        let ident = idms_prox_read
            .process_uat_to_identity(&uat, ct)
            .expect("Unable to process uat");

        let (_code_verifier, code_challenge) = create_code_verifier!("Whar Garble");

        let auth_req = AuthorisationRequest {
            response_type: "code".to_string(),
            client_id: "test_resource_server".to_string(),
            state: "123".to_string(),
            pkce_request: Some(PkceRequest {
                code_challenge: Base64UrlSafeData(code_challenge),
                code_challenge_method: CodeChallengeMethod::S256,
            }),
            redirect_uri: Url::parse("https://demo.example.com/oauth2/result").unwrap(),
            scope: "openid email".to_string(),
            nonce: Some("abcdef".to_string()),
            oidc_ext: Default::default(),
            unknown_keys: Default::default(),
        };

        let consent_request = idms_prox_read
            .check_oauth2_authorisation(&ident, &uat, &auth_req, ct)
            .expect("Oauth2 authorisation failed");

        // Should be in the consent phase;
        let _consent_token =
            if let AuthoriseResponse::ConsentRequested { consent_token, .. } = consent_request {
                consent_token
            } else {
                unreachable!();
            };

        drop(idms_prox_read);

        // Success! We had to consent again due to the change :)

        // Now change the supplemental scopes on the oauth2 instance, this revokes the permit.
        let mut idms_prox_write = idms.proxy_write(ct).await;

        let me_extend_scopes = ModifyEvent::new_internal_invalid(
            filter!(f_eq(
                "oauth2_rs_name",
                PartialValue::new_iname("test_resource_server")
            )),
            ModifyList::new_list(vec![Modify::Present(
                AttrString::from("oauth2_rs_sup_scope_map"),
                Value::new_oauthscopemap(UUID_IDM_ALL_ACCOUNTS, btreeset!["newscope".to_string()])
                    .expect("invalid oauthscope"),
            )]),
        );

        assert!(idms_prox_write.qs_write.modify(&me_extend_scopes).is_ok());
        assert!(idms_prox_write.commit().is_ok());

        // And do the workflow once more to see if we need to consent again.

        let mut idms_prox_read = idms.proxy_read().await;

        // We need to reload our identity
        let ident = idms_prox_read
            .process_uat_to_identity(&uat, ct)
            .expect("Unable to process uat");

        let (_code_verifier, code_challenge) = create_code_verifier!("Whar Garble");

        let auth_req = AuthorisationRequest {
            response_type: "code".to_string(),
            client_id: "test_resource_server".to_string(),
            state: "123".to_string(),
            pkce_request: Some(PkceRequest {
                code_challenge: Base64UrlSafeData(code_challenge),
                code_challenge_method: CodeChallengeMethod::S256,
            }),
            redirect_uri: Url::parse("https://demo.example.com/oauth2/result").unwrap(),
            // Note the scope isn't requested here!
            scope: "openid email".to_string(),
            nonce: Some("abcdef".to_string()),
            oidc_ext: Default::default(),
            unknown_keys: Default::default(),
        };

        let consent_request = idms_prox_read
            .check_oauth2_authorisation(&ident, &uat, &auth_req, ct)
            .expect("Oauth2 authorisation failed");

        // Should be present in the consent phase however!
        let _consent_token = if let AuthoriseResponse::ConsentRequested {
            consent_token,
            scopes,
            ..
        } = consent_request
        {
            assert!(scopes.contains(&"newscope".to_string()));
            consent_token
        } else {
            unreachable!();
        };
    }

    #[idm_test]
    async fn test_idm_oauth2_consent_granted_refint_cleanup_on_delete(
        idms: &IdmServer,
        _idms_delayed: &mut IdmServerDelayed,
    ) {
        let ct = Duration::from_secs(TEST_CURRENT_TIME);
        let (_secret, uat, ident, o2rs_uuid) =
            setup_oauth2_resource_server_basic(idms, ct, true, false, false).await;

        // Assert there are no consent maps yet.
        assert!(ident.get_oauth2_consent_scopes(o2rs_uuid).is_none());

        let idms_prox_read = idms.proxy_read().await;

        let (_code_verifier, code_challenge) = create_code_verifier!("Whar Garble");
        let consent_request = good_authorisation_request!(
            idms_prox_read,
            &ident,
            &uat,
            ct,
            code_challenge,
            "openid".to_string()
        );

        // Should be in the consent phase;
        let consent_token =
            if let AuthoriseResponse::ConsentRequested { consent_token, .. } = consent_request {
                consent_token
            } else {
                unreachable!();
            };

        // == Manually submit the consent token to the permit for the permit_success
        drop(idms_prox_read);
        let mut idms_prox_write = idms.proxy_write(ct).await;

        let _permit_success = idms_prox_write
            .check_oauth2_authorise_permit(&ident, &uat, &consent_token, ct)
            .expect("Failed to perform oauth2 permit");

        let ident = idms_prox_write
            .process_uat_to_identity(&uat, ct)
            .expect("Unable to process uat");

        // Assert that the ident now has the consents.
        assert!(
            ident.get_oauth2_consent_scopes(o2rs_uuid)
                == Some(&btreeset!["openid".to_string(), "supplement".to_string()])
        );

        // Now trigger the delete of the RS
        let de = DeleteEvent::new_internal_invalid(filter!(f_eq(
            "oauth2_rs_name",
            PartialValue::new_iname("test_resource_server")
        )));

        assert!(idms_prox_write.qs_write.delete(&de).is_ok());
        // Assert the consent maps are gone.
        let ident = idms_prox_write
            .process_uat_to_identity(&uat, ct)
            .expect("Unable to process uat");
        assert!(ident.get_oauth2_consent_scopes(o2rs_uuid).is_none());

        assert!(idms_prox_write.commit().is_ok());
    }

    #[idm_test]
    // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics#section-4.8
    //
    // It was reported we were vulnerable to this attack, but that isn't the case. First
    // this attack relies on stripping the *code_challenge* from the internals of the returned
    // code exchange token. This isn't possible due to our use of encryption of the code exchange
    // token. If that code challenge *could* be removed, then the attacker could use the code exchange
    // with no verifier or an incorrect verifier.
    //
    // Due to the logic in our server, if a code exchange contains a code challenge we always enforce
    // it is correctly used!
    //
    // This left a single odd case where if a client did an authorisation request without a pkce
    // verifier, but then a verifier was submitted during the code exchange, that the server would
    // *ignore* the verifier parameter. In this case, no stripping of the code challenge was done,
    // and the client could have simply also submitted *no* verifier anyway. It could be that
    // an attacker could gain a code exchange with no code challenge and then force a victim to
    // exchange that code exchange with out the verifier, but I'm not sure what damage that would
    // lead to? Regardless, we test for and close off that possible hole in this test.
    //
    async fn test_idm_oauth2_1076_pkce_downgrade(
        idms: &IdmServer,
        _idms_delayed: &mut IdmServerDelayed,
    ) {
        let ct = Duration::from_secs(TEST_CURRENT_TIME);
        // Enable pkce is set to FALSE
        let (secret, uat, ident, _) =
            setup_oauth2_resource_server_basic(idms, ct, false, false, false).await;

        let idms_prox_read = idms.proxy_read().await;

        // Get an ident/uat for now.

        // == Setup the authorisation request
        // We attempt pkce even though the rs is set to not support pkce.
        let (code_verifier, _code_challenge) = create_code_verifier!("Whar Garble");

        // First, the user does not request pkce in their exchange.
        let auth_req = AuthorisationRequest {
            response_type: "code".to_string(),
            client_id: "test_resource_server".to_string(),
            state: "123".to_string(),
            pkce_request: None,
            redirect_uri: Url::parse("https://demo.example.com/oauth2/result").unwrap(),
            scope: "openid".to_string(),
            nonce: None,
            oidc_ext: Default::default(),
            unknown_keys: Default::default(),
        };

        let consent_request = idms_prox_read
            .check_oauth2_authorisation(&ident, &uat, &auth_req, ct)
            .expect("Failed to perform oauth2 authorisation request.");

        // Should be in the consent phase;
        let consent_token =
            if let AuthoriseResponse::ConsentRequested { consent_token, .. } = consent_request {
                consent_token
            } else {
                unreachable!();
            };

        // == Manually submit the consent token to the permit for the permit_success
        drop(idms_prox_read);
        let mut idms_prox_write = idms.proxy_write(ct).await;

        let permit_success = idms_prox_write
            .check_oauth2_authorise_permit(&ident, &uat, &consent_token, ct)
            .expect("Failed to perform oauth2 permit");

        // == Submit the token exchange code.
        // This exchange failed because we submitted a verifier when the code exchange
        // has NO code challenge present.
        let token_req = AccessTokenRequest {
            grant_type: GrantTypeReq::AuthorizationCode {
                code: permit_success.code,
                redirect_uri: Url::parse("https://demo.example.com/oauth2/result").unwrap(),
                // Note the code verifier is set to "something else"
                code_verifier,
            },
            client_id: Some("test_resource_server".to_string()),
            client_secret: Some(secret),
        };

        // Assert the exchange fails.
        assert!(matches!(
            idms_prox_write.check_oauth2_token_exchange(None, &token_req, ct),
            Err(Oauth2Error::InvalidRequest)
        ));

        assert!(idms_prox_write.commit().is_ok());
    }

    #[idm_test]
    // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics#section-2.1
    //
    // If the origin configured is https, do not allow downgrading to http on redirect
    async fn test_idm_oauth2_redir_http_downgrade(
        idms: &IdmServer,
        _idms_delayed: &mut IdmServerDelayed,
    ) {
        let ct = Duration::from_secs(TEST_CURRENT_TIME);
        // Enable pkce is set to FALSE
        let (secret, uat, ident, _) =
            setup_oauth2_resource_server_basic(idms, ct, false, false, false).await;

        let idms_prox_read = idms.proxy_read().await;

        // Get an ident/uat for now.

        // == Setup the authorisation request
        // We attempt pkce even though the rs is set to not support pkce.
        let (code_verifier, code_challenge) = create_code_verifier!("Whar Garble");

        // First, NOTE the lack of https on the redir uri.
        let auth_req = AuthorisationRequest {
            response_type: "code".to_string(),
            client_id: "test_resource_server".to_string(),
            state: "123".to_string(),
            pkce_request: Some(PkceRequest {
                code_challenge: Base64UrlSafeData(code_challenge.clone()),
                code_challenge_method: CodeChallengeMethod::S256,
            }),
            redirect_uri: Url::parse("http://demo.example.com/oauth2/result").unwrap(),
            scope: "openid".to_string(),
            nonce: None,
            oidc_ext: Default::default(),
            unknown_keys: Default::default(),
        };

        assert!(
            idms_prox_read
                .check_oauth2_authorisation(&ident, &uat, &auth_req, ct)
                .unwrap_err()
                == Oauth2Error::InvalidOrigin
        );

        // This does have https
        let consent_request = good_authorisation_request!(
            idms_prox_read,
            &ident,
            &uat,
            ct,
            code_challenge,
            "openid".to_string()
        );

        // Should be in the consent phase;
        let consent_token =
            if let AuthoriseResponse::ConsentRequested { consent_token, .. } = consent_request {
                consent_token
            } else {
                unreachable!();
            };

        // == Manually submit the consent token to the permit for the permit_success
        drop(idms_prox_read);
        let mut idms_prox_write = idms.proxy_write(ct).await;

        let permit_success = idms_prox_write
            .check_oauth2_authorise_permit(&ident, &uat, &consent_token, ct)
            .expect("Failed to perform oauth2 permit");

        // == Submit the token exchange code.
        // NOTE the url is http again
        let token_req = AccessTokenRequest {
            grant_type: GrantTypeReq::AuthorizationCode {
                code: permit_success.code,
                redirect_uri: Url::parse("http://demo.example.com/oauth2/result").unwrap(),
                // Note the code verifier is set to "something else"
                code_verifier,
            },
            client_id: Some("test_resource_server".to_string()),
            client_secret: Some(secret),
        };

        // Assert the exchange fails.
        assert!(matches!(
            idms_prox_write.check_oauth2_token_exchange(None, &token_req, ct),
            Err(Oauth2Error::InvalidOrigin)
        ));

        assert!(idms_prox_write.commit().is_ok());
    }

    async fn setup_refresh_token(
        idms: &IdmServer,
        _idms_delayed: &mut IdmServerDelayed,
        ct: Duration,
    ) -> (AccessTokenResponse, Option<String>) {
        // First, setup to get a token.
        let (secret, uat, ident, _) =
            setup_oauth2_resource_server_basic(idms, ct, true, false, false).await;
        let client_authz =
            Some(general_purpose::STANDARD.encode(format!("test_resource_server:{secret}")));

        let idms_prox_read = idms.proxy_read().await;

        // == Setup the authorisation request
        let (code_verifier, code_challenge) = create_code_verifier!("Whar Garble");
        let consent_request = good_authorisation_request!(
            idms_prox_read,
            &ident,
            &uat,
            ct,
            code_challenge,
            "openid".to_string()
        );

        let consent_token =
            if let AuthoriseResponse::ConsentRequested { consent_token, .. } = consent_request {
                consent_token
            } else {
                unreachable!();
            };

        // == Manually submit the consent token to the permit for the permit_success
        drop(idms_prox_read);
        let mut idms_prox_write = idms.proxy_write(ct).await;

        let permit_success = idms_prox_write
            .check_oauth2_authorise_permit(&ident, &uat, &consent_token, ct)
            .expect("Failed to perform oauth2 permit");

        let token_req: AccessTokenRequest = GrantTypeReq::AuthorizationCode {
            code: permit_success.code,
            redirect_uri: Url::parse("https://demo.example.com/oauth2/result").unwrap(),
            code_verifier,
        }
        .into();
        let access_token_response_1 = idms_prox_write
            .check_oauth2_token_exchange(client_authz.as_deref(), &token_req, ct)
            .expect("Unable to exchange for oauth2 token");

        assert!(idms_prox_write.commit().is_ok());

        trace!(?access_token_response_1);

        (access_token_response_1, client_authz)
    }

    #[idm_test]
    async fn test_idm_oauth2_refresh_token_basic(
        idms: &IdmServer,
        idms_delayed: &mut IdmServerDelayed,
    ) {
        // First, setup to get a token.
        let ct = Duration::from_secs(TEST_CURRENT_TIME);

        let (access_token_response_1, client_authz) =
            setup_refresh_token(idms, idms_delayed, ct).await;

        // ============================================
        // test basic refresh while access still valid.

        let ct = Duration::from_secs(TEST_CURRENT_TIME + 10);
        let mut idms_prox_write = idms.proxy_write(ct).await;

        let refresh_token = access_token_response_1
            .refresh_token
            .as_ref()
            .expect("no refresh token was issued")
            .clone();

        let token_req: AccessTokenRequest = GrantTypeReq::RefreshToken {
            refresh_token,
            scope: None,
        }
        .into();

        let access_token_response_2 = idms_prox_write
            .check_oauth2_token_exchange(client_authz.as_deref(), &token_req, ct)
            .expect("Unable to exchange for oauth2 token");

        assert!(idms_prox_write.commit().is_ok());

        trace!(?access_token_response_2);

        assert!(access_token_response_1.access_token != access_token_response_2.access_token);
        assert!(access_token_response_1.refresh_token != access_token_response_2.refresh_token);
        assert!(access_token_response_1.id_token != access_token_response_2.id_token);

        // ============================================
        // test basic refresh after access exp
        let ct =
            Duration::from_secs(TEST_CURRENT_TIME + 20 + access_token_response_2.expires_in as u64);

        let mut idms_prox_write = idms.proxy_write(ct).await;

        let refresh_token = access_token_response_2
            .refresh_token
            .as_ref()
            .expect("no refresh token was issued")
            .clone();

        // get the refresh token expiry now before we use it.
        let reflected_token = idms_prox_write
            .reflect_oauth2_token(client_authz.as_ref().unwrap(), &refresh_token)
            .expect("Failed to access internals of the refresh token");

        let refresh_exp = match reflected_token {
            Oauth2TokenType::Refresh { expiry, .. } => expiry.unix_timestamp(),
            Oauth2TokenType::Access { .. } => unreachable!(),
        };

        let token_req: AccessTokenRequest = GrantTypeReq::RefreshToken {
            refresh_token,
            scope: None,
        }
        .into();

        let access_token_response_3 = idms_prox_write
            .check_oauth2_token_exchange(client_authz.as_deref(), &token_req, ct)
            .expect("Unable to exchange for oauth2 token");

        assert!(idms_prox_write.commit().is_ok());

        trace!(?access_token_response_3);

        assert!(access_token_response_3.access_token != access_token_response_2.access_token);
        assert!(access_token_response_3.refresh_token != access_token_response_2.refresh_token);
        assert!(access_token_response_3.id_token != access_token_response_2.id_token);

        // refresh after refresh has expired.
        // Refresh tokens have a max time limit - the session time limit still bounds it though, but
        // so does the refresh token limit. We check both, but the refresh time is checked first so
        // we can guarantee this in this test.

        let ct = Duration::from_secs(
            TEST_CURRENT_TIME + refresh_exp as u64 + access_token_response_3.expires_in as u64,
        );

        let mut idms_prox_write = idms.proxy_write(ct).await;

        let refresh_token = access_token_response_3
            .refresh_token
            .as_ref()
            .expect("no refresh token was issued")
            .clone();

        let token_req: AccessTokenRequest = GrantTypeReq::RefreshToken {
            refresh_token,
            scope: None,
        }
        .into();
        let access_token_response_4 = idms_prox_write
            .check_oauth2_token_exchange(client_authz.as_deref(), &token_req, ct)
            .unwrap_err();

        assert!(access_token_response_4 == Oauth2Error::InvalidToken);

        assert!(idms_prox_write.commit().is_ok());
    }

    // refresh when oauth2 parent session exp / missing.
    #[idm_test]
    async fn test_idm_oauth2_refresh_token_oauth2_session_expired(
        idms: &IdmServer,
        idms_delayed: &mut IdmServerDelayed,
    ) {
        // First, setup to get a token.
        let ct = Duration::from_secs(TEST_CURRENT_TIME);

        let (access_token_response_1, client_authz) =
            setup_refresh_token(idms, idms_delayed, ct).await;

        // ============================================
        // Revoke the oauth2 session

        let mut idms_prox_write = idms.proxy_write(ct).await;
        let revoke_request = TokenRevokeRequest {
            token: access_token_response_1.access_token.clone(),
            token_type_hint: None,
        };
        assert!(idms_prox_write
            .oauth2_token_revoke(client_authz.as_deref().unwrap(), &revoke_request, ct,)
            .is_ok());
        assert!(idms_prox_write.commit().is_ok());

        // ============================================
        // then attempt a refresh.
        let mut idms_prox_write = idms.proxy_write(ct).await;

        let refresh_token = access_token_response_1
            .refresh_token
            .as_ref()
            .expect("no refresh token was issued")
            .clone();

        let token_req: AccessTokenRequest = GrantTypeReq::RefreshToken {
            refresh_token,
            scope: None,
        }
        .into();
        let access_token_response_2 = idms_prox_write
            .check_oauth2_token_exchange(client_authz.as_deref(), &token_req, ct)
            // Should be unable to exchange.
            .unwrap_err();

        assert!(access_token_response_2 == Oauth2Error::InvalidToken);

        assert!(idms_prox_write.commit().is_ok());
    }

    // refresh with wrong client id/authz
    #[idm_test]
    async fn test_idm_oauth2_refresh_token_invalid_client_authz(
        idms: &IdmServer,
        idms_delayed: &mut IdmServerDelayed,
    ) {
        // First, setup to get a token.
        let ct = Duration::from_secs(TEST_CURRENT_TIME);

        let (access_token_response_1, mut client_authz) =
            setup_refresh_token(idms, idms_delayed, ct).await;

        if let Some(s) = client_authz.as_mut() {
            s.push_str("invalid")
        }

        // ============================================
        // Refresh with invalid client authz

        let mut idms_prox_write = idms.proxy_write(ct).await;

        let refresh_token = access_token_response_1
            .refresh_token
            .as_ref()
            .expect("no refresh token was issued")
            .clone();

        let token_req: AccessTokenRequest = GrantTypeReq::RefreshToken {
            refresh_token,
            scope: None,
        }
        .into();
        let access_token_response_2 = idms_prox_write
            .check_oauth2_token_exchange(client_authz.as_deref(), &token_req, ct)
            .unwrap_err();

        assert!(access_token_response_2 == Oauth2Error::AuthenticationRequired);

        assert!(idms_prox_write.commit().is_ok());
    }

    // Incorrect scopes re-requested
    #[idm_test]
    async fn test_idm_oauth2_refresh_token_inconsistent_scopes(
        idms: &IdmServer,
        idms_delayed: &mut IdmServerDelayed,
    ) {
        // First, setup to get a token.
        let ct = Duration::from_secs(TEST_CURRENT_TIME);

        let (access_token_response_1, client_authz) =
            setup_refresh_token(idms, idms_delayed, ct).await;

        // ============================================
        // Refresh with different scopes

        let mut idms_prox_write = idms.proxy_write(ct).await;

        let refresh_token = access_token_response_1
            .refresh_token
            .as_ref()
            .expect("no refresh token was issued")
            .clone();

        let token_req: AccessTokenRequest = GrantTypeReq::RefreshToken {
            refresh_token,
            scope: Some(btreeset!["invalid_scope".to_string()]),
        }
        .into();
        let access_token_response_2 = idms_prox_write
            .check_oauth2_token_exchange(client_authz.as_deref(), &token_req, ct)
            .unwrap_err();

        assert!(access_token_response_2 == Oauth2Error::InvalidScope);

        assert!(idms_prox_write.commit().is_ok());
    }

    // Test that re-use of a refresh token is denied + terminates the session.
    //
    // https://www.ietf.org/archive/id/draft-ietf-oauth-security-topics-18.html#refresh_token_protection
    #[idm_test]
    async fn test_idm_oauth2_refresh_token_reuse_invalidates_session(
        idms: &IdmServer,
        idms_delayed: &mut IdmServerDelayed,
    ) {
        // First, setup to get a token.
        let ct = Duration::from_secs(TEST_CURRENT_TIME);

        let (access_token_response_1, client_authz) =
            setup_refresh_token(idms, idms_delayed, ct).await;

        // ============================================
        // Use the refresh token once
        let ct = Duration::from_secs(TEST_CURRENT_TIME + 1);
        let mut idms_prox_write = idms.proxy_write(ct).await;

        let refresh_token = access_token_response_1
            .refresh_token
            .as_ref()
            .expect("no refresh token was issued")
            .clone();

        let token_req: AccessTokenRequest = GrantTypeReq::RefreshToken {
            refresh_token,
            scope: None,
        }
        .into();

        let _access_token_response_2 = idms_prox_write
            .check_oauth2_token_exchange(client_authz.as_deref(), &token_req, ct)
            .expect("Unable to exchange for oauth2 token");

        assert!(idms_prox_write.commit().is_ok());

        // Now use it again. - this will cause an error and the session to be terminated.
        let ct = Duration::from_secs(TEST_CURRENT_TIME + 2);
        let mut idms_prox_write = idms.proxy_write(ct).await;

        let refresh_token = access_token_response_1
            .refresh_token
            .as_ref()
            .expect("no refresh token was issued")
            .clone();

        let token_req: AccessTokenRequest = GrantTypeReq::RefreshToken {
            refresh_token,
            scope: None,
        }
        .into();

        let access_token_response_3 = idms_prox_write
            .check_oauth2_token_exchange(client_authz.as_deref(), &token_req, ct)
            .unwrap_err();

        assert!(access_token_response_3 == Oauth2Error::InvalidGrant);

        let entry = idms_prox_write
            .qs_write
            .internal_search_uuid(UUID_ADMIN)
            .expect("failed");
        let valid = entry
            .get_ava_as_oauth2session_map("oauth2_session")
            .map(|map| {
                trace!(?map);
                map.is_empty()
            })
            // If there is no map, it must be empty
            .unwrap_or(true);
        assert!(valid);

        assert!(idms_prox_write.commit().is_ok());
    }

    // Test session divergence. This means that we have to:
    // access + refresh 1
    // use refresh 1 -> access + refresh 2 // don't commit this txn.
    // use refresh 2 -> access + refresh 3
    //    check the session state.

    #[idm_test]
    async fn test_idm_oauth2_refresh_token_divergence(
        idms: &IdmServer,
        idms_delayed: &mut IdmServerDelayed,
    ) {
        // First, setup to get a token.
        let ct = Duration::from_secs(TEST_CURRENT_TIME);

        let (access_token_response_1, client_authz) =
            setup_refresh_token(idms, idms_delayed, ct).await;

        // ============================================
        // Use the refresh token once
        let ct = Duration::from_secs(TEST_CURRENT_TIME + 1);
        let mut idms_prox_write = idms.proxy_write(ct).await;

        let refresh_token = access_token_response_1
            .refresh_token
            .as_ref()
            .expect("no refresh token was issued")
            .clone();

        let token_req: AccessTokenRequest = GrantTypeReq::RefreshToken {
            refresh_token,
            scope: None,
        }
        .into();

        let access_token_response_2 = idms_prox_write
            .check_oauth2_token_exchange(client_authz.as_deref(), &token_req, ct)
            .expect("Unable to exchange for oauth2 token");

        // DO NOT COMMIT HERE - this is what forces the session issued_at
        // time to stay at the original time!
        drop(idms_prox_write);

        // ============================================
        let ct = Duration::from_secs(TEST_CURRENT_TIME + 2);
        let mut idms_prox_write = idms.proxy_write(ct).await;

        let refresh_token = access_token_response_2
            .refresh_token
            .as_ref()
            .expect("no refresh token was issued")
            .clone();

        let token_req: AccessTokenRequest = GrantTypeReq::RefreshToken {
            refresh_token,
            scope: None,
        }
        .into();

        let _access_token_response_3 = idms_prox_write
            .check_oauth2_token_exchange(client_authz.as_deref(), &token_req, ct)
            .expect("Unable to exchange for oauth2 token");

        assert!(idms_prox_write.commit().is_ok());

        // Success!
    }
    #[test] // I know this looks kinda dumb but at some point someone pointed out that our scope syntax wasn't compliant with rfc6749
            //(https://datatracker.ietf.org/doc/html/rfc6749#section-3.3), so I'm just making sure that we don't break it again.
    fn compliant_serialization_test() {
        let token_req: Result<AccessTokenRequest, serde_json::Error> = serde_json::from_str(
            r#"
            {
                "grant_type": "refresh_token",
                "refresh_token": "some_dumb_refresh_token",
                "scope": "invalid_scope vasd asd"
            }
        "#,
        );
        assert!(token_req.is_ok());
    }
}
