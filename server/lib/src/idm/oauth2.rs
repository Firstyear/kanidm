//! Oauth2 resource server configurations
//!
//! This contains the in memory and loaded set of active OAuth2 resource server
//! integrations, which are then able to be used an accessed from the IDM layer
//! for operations involving OAuth2 authentication processing.

use crate::idm::account::Account;
use crate::idm::server::{
    IdmServerProxyReadTransaction, IdmServerProxyWriteTransaction, IdmServerTransaction, Token,
};
use crate::prelude::*;
use crate::server::keys::{KeyObject, KeyProvidersTransaction, KeyProvidersWriteTransaction};
use crate::utils;
use crate::value::{Oauth2Session, OauthClaimMapJoin, SessionState, OAUTHSCOPE_RE};
use base64::{engine::general_purpose, Engine as _};
pub use compact_jwt::{compact::JwkKeySet, OidcToken};
use compact_jwt::{
    crypto::{JweA128GCMEncipher, JweA128KWEncipher},
    jwe::Jwe,
    jws::JwsBuilder,
    JweCompact, JwsCompact, OidcClaims, OidcSubject,
};
use concread::cowcell::*;
use crypto_glue::{s256::Sha256, traits::Digest};
use hashbrown::HashMap;
use hashbrown::HashSet;
use kanidm_proto::constants::*;
use kanidm_proto::oauth2::IssuedTokenType;
pub use kanidm_proto::oauth2::{
    AccessTokenIntrospectRequest, AccessTokenIntrospectResponse, AccessTokenRequest,
    AccessTokenResponse, AccessTokenType, AuthorisationRequest, ClaimType, ClientAuth,
    ClientPostAuth, CodeChallengeMethod, DeviceAuthorizationResponse, DisplayValue, ErrorResponse,
    GrantType, GrantTypeReq, IdTokenSignAlg, OAuth2RFC9068Token, OAuth2RFC9068TokenExtensions,
    Oauth2Rfc8414MetadataResponse, OidcDiscoveryResponse, OidcWebfingerRel, OidcWebfingerResponse,
    PkceAlg, PkceRequest, ResponseMode, ResponseType, SubjectType, TokenEndpointAuthMethod,
    TokenRevokeRequest, OAUTH2_TOKEN_TYPE_ACCESS_TOKEN,
};
use serde::{Deserialize, Serialize};
use serde_with::{formats, serde_as};
use std::collections::btree_map::Entry as BTreeEntry;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use time::OffsetDateTime;
use tracing::trace;
use uri::{OAUTH2_TOKEN_INTROSPECT_ENDPOINT, OAUTH2_TOKEN_REVOKE_ENDPOINT};
use url::{Host, Origin, Url};
use utoipa::ToSchema;

const TOKEN_EXCHANGE_SUBJECT_TOKEN_TYPE_ACCESS: &str = OAUTH2_TOKEN_TYPE_ACCESS_TOKEN;

#[derive(Serialize, Deserialize, Debug, PartialEq, ToSchema)]
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
    InvalidTarget,
    ServerError(OperationError),
    TemporarilyUnavailable,
    // from https://datatracker.ietf.org/doc/html/rfc6750
    InvalidToken,
    InsufficientScope,
    // from https://datatracker.ietf.org/doc/html/rfc7009#section-2.2.1
    UnsupportedTokenType,
    /// <https://datatracker.ietf.org/doc/html/rfc8628#section-3.5>  A variant of "authorization_pending", the authorization request is
    ///   still pending and polling should continue, but the interval MUST
    ///   be increased by 5 seconds for this and all subsequent requests.
    SlowDown,
    /// The authorization request is still pending as the end user hasn't
    ///   yet completed the user-interaction steps (Section 3.3).  The
    ///   client SHOULD repeat the access token request to the token
    ///   endpoint (a process known as polling).  Before each new request,
    ///   the client MUST wait at least the number of seconds specified by
    ///   the "interval" parameter of the device authorization response (see
    ///   Section 3.2), or 5 seconds if none was provided, and respect any
    ///   increase in the polling interval required by the "slow_down"
    ///   error.
    AuthorizationPending,
    /// The "device_code" has expired, and the device authorization
    ///   session has concluded.  The client MAY commence a new device
    ///   authorization request but SHOULD wait for user interaction before
    ///   restarting to avoid unnecessary polling.
    ExpiredToken,
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
            Oauth2Error::InvalidTarget => "invalid_target",
            Oauth2Error::ServerError(_) => "server_error",
            Oauth2Error::TemporarilyUnavailable => "temporarily_unavailable",
            Oauth2Error::InvalidToken => "invalid_token",
            Oauth2Error::InsufficientScope => "insufficient_scope",
            Oauth2Error::UnsupportedTokenType => "unsupported_token_type",
            Oauth2Error::SlowDown => "slow_down",
            Oauth2Error::AuthorizationPending => "authorization_pending",
            Oauth2Error::ExpiredToken => "expired_token",
        })
    }
}

pub struct PkceS256Secret {
    secret: String,
}

impl Default for PkceS256Secret {
    fn default() -> Self {
        Self {
            secret: utils::password_from_random(),
        }
    }
}

impl From<String> for PkceS256Secret {
    fn from(secret: String) -> Self {
        Self { secret }
    }
}

impl PkceS256Secret {
    pub fn to_request(&self) -> PkceRequest {
        let mut hasher = Sha256::new();
        hasher.update(self.secret.as_bytes());
        let code_challenge = hasher.finalize();

        PkceRequest {
            code_challenge: code_challenge.to_vec(),
            code_challenge_method: CodeChallengeMethod::S256,
        }
    }

    pub(crate) fn verifier(&self) -> &str {
        &self.secret
    }

    pub fn to_verifier(self) -> String {
        self.secret
    }

    pub fn verify<V: AsRef<[u8]>>(&self, challenge: V) -> bool {
        let mut hasher = Sha256::new();
        hasher.update(self.secret.as_bytes());
        let code_challenge = hasher.finalize();

        challenge.as_ref() == code_challenge.as_slice()
    }
}

// == internal state formats that we encrypt and send.
#[derive(Serialize, Deserialize, Debug, PartialEq)]
enum SupportedResponseMode {
    Query,
    Fragment,
}

#[serde_as]
#[derive(Serialize, Deserialize, Debug, PartialEq)]
struct ConsentToken {
    pub client_id: String,
    // Must match the session id of the Uat,
    pub session_id: Uuid,
    pub expiry: u64,

    // So we can ensure that we really match the same uat to prevent confusions.
    pub ident_id: IdentityId,
    // CSRF
    pub state: Option<String>,
    // The S256 code challenge.
    #[serde_as(
        as = "Option<serde_with::base64::Base64<serde_with::base64::UrlSafe, formats::Unpadded>>"
    )]
    pub code_challenge: Option<Vec<u8>>,
    // Where the client wants us to go back to.
    pub redirect_uri: Url,
    // The scopes being granted
    pub scopes: BTreeSet<String>,
    // We stash some details here for oidc.
    pub nonce: Option<String>,
    /// The format the response should be returned to the application in.
    pub response_mode: SupportedResponseMode,
}

#[serde_as]
#[derive(Serialize, Deserialize, Debug)]
struct TokenExchangeCode {
    // We don't need the client_id here, because it's signed with an RS specific
    // key which gives us the assurance that it's the correct combination.
    pub account_uuid: Uuid,
    pub session_id: Uuid,

    pub expiry: u64,

    // The S256 code challenge.
    #[serde_as(
        as = "Option<serde_with::base64::Base64<serde_with::base64::UrlSafe, formats::Unpadded>>"
    )]
    pub code_challenge: Option<Vec<u8>>,
    // The original redirect uri
    pub redirect_uri: Url,
    // The scopes being granted
    pub scopes: BTreeSet<String>,
    // We stash some details here for oidc.
    pub nonce: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub(crate) enum Oauth2TokenType {
    Refresh {
        scopes: BTreeSet<String>,
        parent_session_id: Uuid,
        session_id: Uuid,
        exp: i64,
        uuid: Uuid,
        //
        iat: i64,
        nbf: i64,
        // We stash some details here for oidc.
        nonce: Option<String>,
    },
    ClientAccess {
        scopes: BTreeSet<String>,
        session_id: Uuid,
        uuid: Uuid,
        exp: i64,
        iat: i64,
        nbf: i64,
    },
}

impl fmt::Display for Oauth2TokenType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Oauth2TokenType::Refresh { session_id, .. } => {
                write!(f, "refresh_token ({session_id}) ")
            }
            Oauth2TokenType::ClientAccess { session_id, .. } => {
                write!(f, "client_access_token ({session_id})")
            }
        }
    }
}

#[derive(Debug)]
pub enum AuthoriseResponse {
    AuthenticationRequired {
        // A pretty-name of the client
        client_name: String,
        // A username hint, if any
        login_hint: Option<String>,
    },
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
    // Where the client wants us to go back to.
    pub redirect_uri: Url,
    // The CSRF as a string
    pub state: Option<String>,
    // The exchange code as a String
    pub code: String,
    /// The format the response should be returned to the application in.
    response_mode: SupportedResponseMode,
}

impl AuthorisePermitSuccess {
    /// Builds a redirect URI to go back to the application when permission was
    /// granted.
    pub fn build_redirect_uri(&self) -> Url {
        let mut redirect_uri = self.redirect_uri.clone();

        // Always clear the fragment per RFC
        redirect_uri.set_fragment(None);

        match self.response_mode {
            SupportedResponseMode::Query => {
                redirect_uri
                    .query_pairs_mut()
                    .append_pair("code", &self.code);

                if let Some(state) = self.state.as_ref() {
                    redirect_uri.query_pairs_mut().append_pair("state", state);
                };
            }
            SupportedResponseMode::Fragment => {
                redirect_uri.set_query(None);

                // Per [the RFC](https://www.rfc-editor.org/rfc/rfc6749#section-3.1.2), we can't set query pairs on fragment-containing redirects, only query ones.
                let mut uri_builder = url::form_urlencoded::Serializer::new(String::new());
                uri_builder.append_pair("code", &self.code);
                if let Some(state) = self.state.as_ref() {
                    uri_builder.append_pair("state", state);
                };
                let encoded = uri_builder.finish();

                redirect_uri.set_fragment(Some(&encoded))
            }
        }

        redirect_uri
    }
}

#[derive(Debug)]
pub struct AuthoriseReject {
    // Where the client wants us to go back to.
    pub redirect_uri: Url,
    /// The format the response should be returned to the application in.
    response_mode: SupportedResponseMode,
}

impl AuthoriseReject {
    /// Builds a redirect URI to go back to the application when permission was
    /// rejected.
    pub fn build_redirect_uri(&self) -> Url {
        let mut redirect_uri = self.redirect_uri.clone();

        // Always clear query and fragment, regardless of the response mode
        redirect_uri.set_query(None);
        redirect_uri.set_fragment(None);

        // We can't set query pairs on fragments, only query.
        let encoded = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("error", "access_denied")
            .append_pair("error_description", "authorisation rejected")
            .finish();

        match self.response_mode {
            SupportedResponseMode::Query => redirect_uri.set_query(Some(&encoded)),
            SupportedResponseMode::Fragment => redirect_uri.set_fragment(Some(&encoded)),
        }

        redirect_uri
    }
}

#[derive(Clone)]
enum OauthRSType {
    Basic {
        authz_secret: String,
        enable_pkce: bool,
        enable_consent_prompt: bool,
    },
    // Public clients must have pkce and consent prompt
    Public {
        allow_localhost_redirect: bool,
    },
}

impl OauthRSType {
    /// We only allow localhost redirects if PKCE is enabled/required
    fn allow_localhost_redirect(&self) -> bool {
        match self {
            OauthRSType::Basic { .. } => false,
            OauthRSType::Public {
                allow_localhost_redirect,
            } => *allow_localhost_redirect,
        }
    }

    /// This type COULD have localhost redirection enabled, but does not reflect
    /// the current configuration state.
    fn allow_localhost_redirect_could_be_possible(&self) -> bool {
        match self {
            OauthRSType::Basic { .. } => false,
            OauthRSType::Public { .. } => true,
        }
    }
}

impl std::fmt::Debug for OauthRSType {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let mut ds = f.debug_struct("OauthRSType");
        match self {
            OauthRSType::Basic {
                enable_pkce,
                enable_consent_prompt,
                ..
            } => ds
                .field("type", &"basic")
                .field("pkce", enable_pkce)
                .field("consent_prompt", enable_consent_prompt),
            OauthRSType::Public {
                allow_localhost_redirect,
            } => ds
                .field("type", &"public")
                .field("allow_localhost_redirect", allow_localhost_redirect),
        };
        ds.finish()
    }
}

#[derive(Clone, Debug)]
struct ClaimValue {
    join: OauthClaimMapJoin,
    values: BTreeSet<String>,
}

impl ClaimValue {
    fn merge(&mut self, other: &Self) {
        self.values.extend(other.values.iter().cloned())
    }

    fn to_json_value(&self) -> serde_json::Value {
        let join_str = match self.join {
            OauthClaimMapJoin::JsonArray => {
                let arr: Vec<_> = self
                    .values
                    .iter()
                    .cloned()
                    .map(serde_json::Value::String)
                    .collect();

                // This shortcuts out.
                return serde_json::Value::Array(arr);
            }
            joiner => joiner.to_str(),
        };

        let joined = str_concat!(&self.values, join_str);

        serde_json::Value::String(joined)
    }
}

#[derive(Clone, Copy, Debug)]
enum SignatureAlgo {
    Es256,
    Rs256,
}

#[derive(Clone)]
pub struct Oauth2RS {
    name: String,
    displayname: String,
    uuid: Uuid,

    origins: HashSet<Origin>,
    opaque_origins: HashSet<Url>,
    redirect_uris: HashSet<Url>,
    origin_secure_required: bool,
    strict_redirect_uri: bool,

    claim_map: BTreeMap<Uuid, Vec<(String, ClaimValue)>>,
    scope_maps: BTreeMap<Uuid, BTreeSet<String>>,
    sup_scope_maps: BTreeMap<Uuid, BTreeSet<String>>,
    client_scopes: BTreeSet<String>,
    client_sup_scopes: BTreeSet<String>,
    // Our internal exchange encryption material for this rs.
    sign_alg: SignatureAlgo,
    key_object: Arc<KeyObject>,

    // For oidc we also need our issuer url.
    iss: Url,
    // For discovery we need to build and keep a number of values.
    authorization_endpoint: Url,
    token_endpoint: Url,
    revocation_endpoint: Url,
    introspection_endpoint: Url,
    userinfo_endpoint: Url,
    jwks_uri: Url,
    scopes_supported: BTreeSet<String>,
    prefer_short_username: bool,
    type_: OauthRSType,
    /// Does the RS have a custom image set? If not, we use the default.
    has_custom_image: bool,

    device_authorization_endpoint: Option<Url>,
}

impl Oauth2RS {
    pub fn is_basic(&self) -> bool {
        match self.type_ {
            OauthRSType::Basic { .. } => true,
            OauthRSType::Public { .. } => false,
        }
    }

    pub fn is_pkce(&self) -> bool {
        match self.type_ {
            OauthRSType::Basic { .. } => false,
            OauthRSType::Public { .. } => true,
        }
    }

    /// Does this client require PKCE?
    pub fn require_pkce(&self) -> bool {
        match &self.type_ {
            OauthRSType::Basic { enable_pkce, .. } => *enable_pkce,
            OauthRSType::Public { .. } => true,
        }
    }

    /// Does this RS have device flow enabled?
    pub fn device_flow_enabled(&self) -> bool {
        self.device_authorization_endpoint.is_some()
    }

    /// Does this client have the consent prompt enabled?
    /// As per RFC-6819 5.2.3.2 it can't be disabled on Public clients
    pub fn enable_consent_prompt(&self) -> bool {
        match &self.type_ {
            OauthRSType::Basic {
                enable_consent_prompt,
                ..
            } => *enable_consent_prompt,
            OauthRSType::Public { .. } => true,
        }
    }
}

impl std::fmt::Debug for Oauth2RS {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("Oauth2RS")
            .field("name", &self.name)
            .field("displayname", &self.displayname)
            .field("uuid", &self.uuid)
            .field("type", &self.type_)
            .field("origins", &self.origins)
            .field("opaque_origins", &self.opaque_origins)
            .field("scope_maps", &self.scope_maps)
            .field("sup_scope_maps", &self.sup_scope_maps)
            .field("claim_map", &self.claim_map)
            .field("has_custom_image", &self.has_custom_image)
            .finish()
    }
}

#[derive(Clone)]
struct Oauth2RSInner {
    origin: Url,
    consent_key: JweA128KWEncipher,
    private_rs_set: HashMap<String, Oauth2RS>,
}

impl Oauth2RSInner {
    fn rs_set_get(&self, client_id: &str) -> Option<&Oauth2RS> {
        self.private_rs_set.get(client_id.to_lowercase().as_str())
    }
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

impl Oauth2ResourceServers {
    pub fn new(origin: Url) -> Result<Self, OperationError> {
        let consent_key = JweA128KWEncipher::generate_ephemeral()
            .map_err(|_| OperationError::CryptographyError)?;

        Ok(Oauth2ResourceServers {
            inner: CowCell::new(Oauth2RSInner {
                origin,
                consent_key,
                private_rs_set: HashMap::new(),
            }),
        })
    }

    pub fn read(&self) -> Oauth2ResourceServersReadTransaction {
        Oauth2ResourceServersReadTransaction {
            inner: self.inner.read(),
        }
    }

    pub fn write(&self) -> Oauth2ResourceServersWriteTransaction<'_> {
        Oauth2ResourceServersWriteTransaction {
            inner: self.inner.write(),
        }
    }
}

/// For when you've got the bearer auth and the post auth and you just want the resulting auth attempt
fn get_client_auth(
    client_auth_info: &ClientAuthInfo,
    client_post_auth: &ClientPostAuth,
) -> Result<ClientAuth, Oauth2Error> {
    if let Some(client_authz) = client_auth_info.basic_authz.as_ref() {
        parse_basic_authz(client_authz.as_str())
    } else if let Some(client_id) = &client_post_auth.client_id {
        Ok(ClientAuth {
            client_id: client_id.clone(),
            client_secret: client_post_auth.client_secret.clone(),
        })
    } else {
        admin_warn!("OAuth2 client authentication not provided");
        Err(Oauth2Error::AuthenticationRequired)
    }
}

impl Oauth2ResourceServersWriteTransaction<'_> {
    #[instrument(level = "debug", name = "oauth2::reload", skip_all)]
    pub fn reload(
        &mut self,
        value: Vec<Arc<EntrySealedCommitted>>,
        key_providers: &KeyProvidersWriteTransaction,
        domain_level: DomainVersion,
    ) -> Result<(), OperationError> {
        let rs_set: Result<HashMap<_, _>, _> = value
            .into_iter()
            .map(|ent| {
                let uuid = ent.get_uuid();
                trace!(?uuid, "Checking OAuth2 configuration");
                // From each entry, attempt to make an OAuth2 configuration.
                if !ent
                    .attribute_equality(Attribute::Class, &EntryClass::OAuth2ResourceServer.into())
                {
                    error!("Missing class oauth2_resource_server");
                    // Check we have oauth2_resource_server class
                    return Err(OperationError::InvalidEntryState);
                }

                let Some(key_object) = key_providers.get_key_object_handle(uuid) else {
                    error!("OAuth2 RS is missing its key object!");
                    return Err(OperationError::InvalidEntryState);
                };

                let type_ = if ent.attribute_equality(
                    Attribute::Class,
                    &EntryClass::OAuth2ResourceServerBasic.into(),
                ) {
                    let authz_secret = ent
                        .get_ava_single_secret(Attribute::OAuth2RsBasicSecret)
                        .map(str::to_string)
                        .ok_or(OperationError::InvalidValueState)?;

                    let enable_pkce = ent
                        .get_ava_single_bool(Attribute::OAuth2AllowInsecureClientDisablePkce)
                        .map(|e| !e)
                        .unwrap_or(true);

                    let enable_consent_prompt = ent
                        .get_ava_single_bool(Attribute::OAuth2ConsentPromptEnable)
                        .unwrap_or(true);

                    OauthRSType::Basic {
                        authz_secret,
                        enable_pkce,
                        enable_consent_prompt,
                    }
                } else if ent.attribute_equality(
                    Attribute::Class,
                    &EntryClass::OAuth2ResourceServerPublic.into(),
                ) {
                    let allow_localhost_redirect = ent
                        .get_ava_single_bool(Attribute::OAuth2AllowLocalhostRedirect)
                        .unwrap_or(false);

                    OauthRSType::Public {
                        allow_localhost_redirect,
                    }
                } else {
                    error!("Missing class determining OAuth2 rs type");
                    return Err(OperationError::InvalidEntryState);
                };

                // Now we know we can load the shared attrs.
                let name = ent
                    .get_ava_single_iname(Attribute::Name)
                    .map(str::to_string)
                    .ok_or(OperationError::InvalidValueState)?;

                let displayname = ent
                    .get_ava_single_utf8(Attribute::DisplayName)
                    .map(str::to_string)
                    .ok_or(OperationError::InvalidValueState)?;

                // Setup the landing uri and its implied origin, as well as
                // the supplemental origins.
                let landing_url = ent
                    .get_ava_single_url(Attribute::OAuth2RsOriginLanding)
                    .cloned()
                    .ok_or(OperationError::InvalidValueState)?;

                let maybe_extra_urls = ent
                    .get_ava_set(Attribute::OAuth2RsOrigin)
                    .and_then(|s| s.as_url_set());

                let len_uris = maybe_extra_urls.map(|s| s.len() + 1).unwrap_or(1);

                // If we are DL8, then strict enforcement is always required.
                let strict_redirect_uri = cfg!(test)
                    || domain_level >= DOMAIN_LEVEL_8
                    || ent
                        .get_ava_single_bool(Attribute::OAuth2StrictRedirectUri)
                        .unwrap_or(false);

                // The reason we have to allocate this is that we need to do some processing on these
                // urls to determine if they are opaque or not.
                let mut redirect_uris_v = Vec::with_capacity(len_uris);

                redirect_uris_v.push(landing_url);
                if let Some(extra_origins) = maybe_extra_urls {
                    for x_origin in extra_origins {
                        redirect_uris_v.push(x_origin.clone());
                    }
                }

                // Now redirect_uris has the full set of the landing uri and the other uris
                // that may or may not be an opaque origin. We need to split these up now.

                let mut origins = HashSet::with_capacity(len_uris);
                let mut redirect_uris = HashSet::with_capacity(len_uris);
                let mut opaque_origins = HashSet::with_capacity(len_uris);
                let mut origin_secure_required = false;

                for mut uri in redirect_uris_v.into_iter() {
                    // https://www.rfc-editor.org/rfc/rfc6749#section-3.1.2
                    // Must not include a fragment.
                    uri.set_fragment(None);
                    // Given the presence of a single https url, then all other urls must be https.
                    if uri.scheme() == "https" {
                        origin_secure_required = true;
                        origins.insert(uri.origin());
                        redirect_uris.insert(uri);
                    } else if uri.scheme() == "http" {
                        origins.insert(uri.origin());
                        redirect_uris.insert(uri);
                    } else {
                        opaque_origins.insert(uri);
                    }
                }

                let scope_maps = ent
                    .get_ava_as_oauthscopemaps(Attribute::OAuth2RsScopeMap)
                    .cloned()
                    .unwrap_or_default();

                let sup_scope_maps = ent
                    .get_ava_as_oauthscopemaps(Attribute::OAuth2RsSupScopeMap)
                    .cloned()
                    .unwrap_or_default();

                // From our scope maps we can now determine what scopes would be granted to our
                // client during a client credentials authentication.
                let (client_scopes, client_sup_scopes) =
                    if let Some(client_member_of) = ent.get_ava_refer(Attribute::MemberOf) {
                        let client_scopes = scope_maps
                            .iter()
                            .filter_map(|(u, m)| {
                                if client_member_of.contains(u) {
                                    Some(m.iter())
                                } else {
                                    None
                                }
                            })
                            .flatten()
                            .cloned()
                            .collect::<BTreeSet<_>>();

                        let client_sup_scopes = sup_scope_maps
                            .iter()
                            .filter_map(|(u, m)| {
                                if client_member_of.contains(u) {
                                    Some(m.iter())
                                } else {
                                    None
                                }
                            })
                            .flatten()
                            .cloned()
                            .collect::<BTreeSet<_>>();

                        (client_scopes, client_sup_scopes)
                    } else {
                        (BTreeSet::default(), BTreeSet::default())
                    };

                let e_claim_maps = ent
                    .get_ava_set(Attribute::OAuth2RsClaimMap)
                    .and_then(|vs| vs.as_oauthclaim_map());

                // ⚠️  Claim Maps as they are stored in the DB are optimised
                // for referential integrity and user interaction. However we
                // need to "invert" these for fast lookups during actual
                // operation of the oauth2 client.
                let claim_map = if let Some(e_claim_maps) = e_claim_maps {
                    let mut claim_map = BTreeMap::default();

                    for (claim_name, claim_mapping) in e_claim_maps.iter() {
                        for (group_uuid, claim_values) in claim_mapping.values().iter() {
                            // We always insert/append here because the outer claim_name has
                            // to be unique.
                            match claim_map.entry(*group_uuid) {
                                BTreeEntry::Vacant(e) => {
                                    e.insert(vec![(
                                        claim_name.clone(),
                                        ClaimValue {
                                            join: claim_mapping.join(),
                                            values: claim_values.clone(),
                                        },
                                    )]);
                                }
                                BTreeEntry::Occupied(mut e) => {
                                    e.get_mut().push((
                                        claim_name.clone(),
                                        ClaimValue {
                                            join: claim_mapping.join(),
                                            values: claim_values.clone(),
                                        },
                                    ));
                                }
                            }
                        }
                    }

                    claim_map
                } else {
                    BTreeMap::default()
                };

                let sign_alg = if ent
                    .get_ava_single_bool(Attribute::OAuth2JwtLegacyCryptoEnable)
                    .unwrap_or(false)
                {
                    SignatureAlgo::Rs256
                } else {
                    SignatureAlgo::Es256
                };

                let prefer_short_username = ent
                    .get_ava_single_bool(Attribute::OAuth2PreferShortUsername)
                    .unwrap_or(false);

                let has_custom_image = ent.get_ava_single_image(Attribute::Image).is_some();

                let mut authorization_endpoint = self.inner.origin.clone();
                authorization_endpoint.set_path("/ui/oauth2");

                let mut token_endpoint = self.inner.origin.clone();
                token_endpoint.set_path(uri::OAUTH2_TOKEN_ENDPOINT);

                let mut revocation_endpoint = self.inner.origin.clone();
                revocation_endpoint.set_path(OAUTH2_TOKEN_REVOKE_ENDPOINT);

                let mut introspection_endpoint = self.inner.origin.clone();
                introspection_endpoint.set_path(OAUTH2_TOKEN_INTROSPECT_ENDPOINT);

                let mut userinfo_endpoint = self.inner.origin.clone();
                userinfo_endpoint.set_path(&format!("/oauth2/openid/{name}/userinfo"));

                let mut jwks_uri = self.inner.origin.clone();
                jwks_uri.set_path(&format!("/oauth2/openid/{name}/public_key.jwk"));

                let mut iss = self.inner.origin.clone();
                iss.set_path(&format!("/oauth2/openid/{name}"));

                let scopes_supported: BTreeSet<String> = scope_maps
                    .values()
                    .flat_map(|bts| bts.iter())
                    .chain(sup_scope_maps.values().flat_map(|bts| bts.iter()))
                    .cloned()
                    .collect();

                let device_authorization_endpoint: Option<Url> =
                    match cfg!(feature = "dev-oauth2-device-flow") {
                        true => {
                            match ent
                                .get_ava_single_bool(Attribute::OAuth2DeviceFlowEnable)
                                .unwrap_or(false)
                            {
                                true => {
                                    let mut device_authorization_endpoint =
                                        self.inner.origin.clone();
                                    device_authorization_endpoint
                                        .set_path(uri::OAUTH2_AUTHORISE_DEVICE);
                                    Some(device_authorization_endpoint)
                                }
                                false => None,
                            }
                        }
                        false => None,
                    };

                let client_id = name.clone();
                let rscfg = Oauth2RS {
                    name,
                    displayname,
                    uuid,
                    origins,
                    opaque_origins,
                    redirect_uris,
                    origin_secure_required,
                    strict_redirect_uri,
                    scope_maps,
                    sup_scope_maps,
                    client_scopes,
                    client_sup_scopes,
                    claim_map,
                    sign_alg,
                    key_object,
                    iss,
                    authorization_endpoint,
                    token_endpoint,
                    revocation_endpoint,
                    introspection_endpoint,
                    userinfo_endpoint,
                    jwks_uri,
                    scopes_supported,
                    prefer_short_username,
                    type_,
                    has_custom_image,
                    device_authorization_endpoint,
                };

                Ok((client_id, rscfg))
            })
            .collect();

        rs_set.map(|mut rs_set| {
            // Delay getting the inner mut (which may clone) until we know we are ok.
            let inner_ref = self.inner.get_mut();
            // Swap them if we are ok
            std::mem::swap(&mut inner_ref.private_rs_set, &mut rs_set);
        })
    }

    pub fn commit(self) {
        self.inner.commit();
    }
}

impl IdmServerProxyWriteTransaction<'_> {
    #[instrument(level = "debug", skip_all)]
    pub fn oauth2_token_revoke(
        &mut self,
        client_auth_info: &ClientAuthInfo,
        revoke_req: &TokenRevokeRequest,
        ct: Duration,
    ) -> Result<(), Oauth2Error> {
        let client_auth = get_client_auth(client_auth_info, &revoke_req.client_post_auth)?;

        // Get the o2rs for the handle.
        let o2rs = self
            .oauth2rs
            .inner
            .rs_set_get(client_auth.client_id.as_str())
            .ok_or_else(|| {
                warn!("Invalid OAuth2 client_id");
                Oauth2Error::AuthenticationRequired
            })?;

        // check the secret.
        match &o2rs.type_ {
            OauthRSType::Basic { authz_secret, .. } => {
                if Some(authz_secret) != client_auth.client_secret.as_ref() {
                    info!("Invalid OAuth2 client_id secret, this can happen if your RS is public but you configured a 'basic' type.");
                    return Err(Oauth2Error::AuthenticationRequired);
                }
            }
            // Relies on the token to be valid.
            OauthRSType::Public { .. } => {}
        };

        // We are authenticated! Yay! Now we can actually check things ...

        // Because this is the only path that deals with the tokens that
        // are either signed *or* encrypted, we need to check both options.

        let (session_id, expiry, uuid) = if let Ok(jwsc) = JwsCompact::from_str(&revoke_req.token) {
            let access_token = o2rs
                .key_object
                .jws_verify(&jwsc)
                .map_err(|err| {
                    admin_error!(?err, "Unable to verify access token");
                    Oauth2Error::InvalidRequest
                })
                .and_then(|jws| {
                    jws.from_json().map_err(|err| {
                        admin_error!(?err, "Unable to deserialise access token");
                        Oauth2Error::InvalidRequest
                    })
                })?;

            let OAuth2RFC9068Token::<_> {
                sub: uuid,
                exp,
                extensions: OAuth2RFC9068TokenExtensions { session_id, .. },
                ..
            } = access_token;

            (session_id, exp, uuid)
        } else {
            // Assume it's encrypted.
            let jwe_compact = JweCompact::from_str(&revoke_req.token).map_err(|_| {
                error!("Failed to deserialise a valid JWE");
                Oauth2Error::InvalidRequest
            })?;

            let token: Oauth2TokenType = o2rs
                .key_object
                .jwe_decrypt(&jwe_compact)
                .map_err(|_| {
                    error!("Failed to decrypt token revoke request");
                    Oauth2Error::InvalidRequest
                })
                .and_then(|jwe| {
                    jwe.from_json().map_err(|err| {
                        error!(?err, "Failed to deserialise token");
                        Oauth2Error::InvalidRequest
                    })
                })?;

            match token {
                Oauth2TokenType::ClientAccess {
                    session_id,
                    exp,
                    uuid,
                    ..
                }
                | Oauth2TokenType::Refresh {
                    session_id,
                    exp,
                    uuid,
                    ..
                } => (session_id, exp, uuid),
            }
        };

        // Only submit a revocation if the token is not yet expired.
        if expiry <= ct.as_secs() as i64 {
            security_info!(?uuid, "token has expired, returning inactive");
            return Ok(());
        }

        // Consider replication. We have servers A and B. A issues our oauth2
        // token to the client. The resource server then issues the revoke request
        // to B. In this case A has not yet replicated the session to B, but we
        // still need to ensure the revoke is respected. As a result, we don't
        // actually consult if the session is present on the account, we simply
        // submit the Modify::Remove. This way it's inserted into the entry changelog
        // and when replication converges the session is actually removed.

        let modlist: ModifyList<ModifyInvalid> = ModifyList::new_list(vec![Modify::Removed(
            Attribute::OAuth2Session,
            PartialValue::Refer(session_id),
        )]);

        self.qs_write
            .internal_modify(
                &filter!(f_eq(Attribute::Uuid, PartialValue::Uuid(uuid))),
                &modlist,
            )
            .map_err(|e| {
                admin_error!("Failed to modify - revoke OAuth2 session {:?}", e);
                Oauth2Error::ServerError(e)
            })
    }

    #[instrument(level = "debug", skip_all)]
    pub fn check_oauth2_token_exchange(
        &mut self,
        client_auth_info: &ClientAuthInfo,
        token_req: &AccessTokenRequest,
        ct: Duration,
    ) -> Result<AccessTokenResponse, Oauth2Error> {
        // Public clients will send the client_id via the ATR, so we need to handle this case.
        let client_auth = get_client_auth(client_auth_info, &token_req.client_post_auth)?;

        let o2rs = self.get_client(&client_auth.client_id)?;
        let is_token_exchange = matches!(token_req.grant_type, GrantTypeReq::TokenExchange { .. });

        // check the secret.
        let client_authentication_valid = match (&o2rs.type_, is_token_exchange) {
            (OauthRSType::Basic { .. }, true) => {
                if client_auth.client_secret.is_some() {
                    security_info!(
                        "Client secret is not accepted when exchanging a service account token"
                    );
                    return Err(Oauth2Error::InvalidRequest);
                }
                true
            }
            (OauthRSType::Basic { authz_secret, .. }, false) => {
                match client_auth.client_secret {
                    Some(secret) => {
                        if authz_secret == &secret {
                            true
                        } else {
                            info!("Invalid OAuth2 client_id secret");
                            return Err(Oauth2Error::AuthenticationRequired);
                        }
                    }
                    None => {
                        // We can only get here if we relied on the atr for the client_id and secret
                        info!(
                            "Invalid OAuth2 authentication - no secret in access token request - this can happen if you're expecting a public client and configured a basic one."
                        );
                        return Err(Oauth2Error::AuthenticationRequired);
                    }
                }
            }
            // Relies on the token to be valid - no further action needed.
            (OauthRSType::Public { .. }, _) => false,
        };

        // We are authenticated! Yay! Now we can actually check things ...
        match &token_req.grant_type {
            GrantTypeReq::AuthorizationCode {
                code,
                redirect_uri,
                code_verifier,
            } => self.check_oauth2_token_exchange_authorization_code(
                &o2rs,
                code,
                redirect_uri,
                code_verifier.as_deref(),
                ct,
            ),
            GrantTypeReq::ClientCredentials { scope } => {
                if client_authentication_valid {
                    self.check_oauth2_token_client_credentials(&o2rs, scope.as_ref(), ct)
                } else {
                    security_info!(
                        "Unable to proceed with client credentials grant unless client authentication is provided and valid"
                    );
                    Err(Oauth2Error::AuthenticationRequired)
                }
            }
            GrantTypeReq::RefreshToken {
                refresh_token,
                scope,
            } => self.check_oauth2_token_refresh(&o2rs, refresh_token, scope.as_ref(), ct),
            GrantTypeReq::TokenExchange {
                subject_token,
                subject_token_type,
                requested_token_type,
                audience,
                resource,
                actor_token,
                actor_token_type,
                scope,
            } => {
                if actor_token.is_some() || actor_token_type.is_some() {
                    warn!("actor_token is not supported for token exchange");
                    return Err(Oauth2Error::InvalidRequest);
                }

                self.check_oauth2_token_exchange_service_account(
                    &o2rs,
                    subject_token,
                    subject_token_type,
                    requested_token_type.as_deref(),
                    audience.as_deref(),
                    resource.as_deref(),
                    scope.as_ref(),
                    ct,
                )
            }
            GrantTypeReq::DeviceCode { device_code, scope } => {
                self.check_oauth2_device_code_status(device_code, scope)
            }
        }
    }

    fn get_client(&self, client_id: &str) -> Result<Oauth2RS, Oauth2Error> {
        let s = self
            .oauth2rs
            .inner
            .rs_set_get(client_id)
            .ok_or_else(|| {
                warn!("Invalid OAuth2 client_id {}", client_id);
                Oauth2Error::AuthenticationRequired
            })?
            .clone();
        Ok(s)
    }

    #[instrument(level = "info", skip(self))]
    pub fn handle_oauth2_start_device_flow(
        &mut self,
        _client_auth_info: ClientAuthInfo,
        _client_id: &str,
        _scope: &Option<BTreeSet<String>>,
        _eventid: Uuid,
    ) -> Result<DeviceAuthorizationResponse, Oauth2Error> {
        // let o2rs = self.get_client(client_id)?;

        // info!("Got Client: {:?}", o2rs);

        // // TODO: change this to checking if it's got device flow enabled
        // if !o2rs.require_pkce() {
        //     security_info!("Device flow is only available for PKCE-enabled clients");
        //     return Err(Oauth2Error::InvalidRequest);
        // }

        // info!(
        //     "Starting device flow for client_id={} scopes={} source={:?}",
        //     client_id,
        //     scope
        //         .as_ref()
        //         .map(|s| s.iter().cloned().collect::<Vec<_>>().into_iter().join(","))
        //         .unwrap_or("[]".to_string()),
        //     client_auth_info.source
        // );

        // let mut verification_uri = self.oauth2rs.inner.origin.clone();
        // verification_uri.set_path(uri::OAUTH2_DEVICE_LOGIN);

        // let (user_code_string, _user_code) = gen_user_code();
        // let expiry =
        //     Duration::from_secs(OAUTH2_DEVICE_CODE_EXPIRY_SECONDS) + duration_from_epoch_now();
        // let device_code = gen_device_code()
        //     .inspect_err(|err| error!("Failed to generate a device code! {:?}", err))?;

        Err(Oauth2Error::InvalidGrant)

        // TODO: store user_code / expiry / client_id / device_code in the backend, needs to be checked on the token exchange.
        // Ok(DeviceAuthorizationResponse::new(
        //     verification_uri,
        //     device_code,
        //     user_code_string,
        // ))
    }

    #[instrument(level = "info", skip(self))]
    fn check_oauth2_device_code_status(
        &mut self,
        device_code: &str,
        scope: &Option<BTreeSet<String>>,
    ) -> Result<AccessTokenResponse, Oauth2Error> {
        // TODO: check the device code is valid, do the needful

        error!(
            "haven't done the device grant yet! Got device_code={} scope={:?}",
            device_code, scope
        );
        Err(Oauth2Error::AuthorizationPending)

        // if it's an expired code, then just delete it from the db and return an error.
        // Err(Oauth2Error::ExpiredToken)
    }

    #[instrument(level = "debug", skip_all)]
    pub fn check_oauth2_authorise_permit(
        &mut self,
        ident: &Identity,
        consent_token: &str,
        ct: Duration,
    ) -> Result<AuthorisePermitSuccess, OperationError> {
        let Some(account_uuid) = ident.get_uuid() else {
            error!("consent request ident does not have a valid uuid, unable to proceed");
            return Err(OperationError::InvalidSessionState);
        };

        let consent_token_jwe = JweCompact::from_str(consent_token).map_err(|err| {
            error!(?err, "Consent token is not a valid jwe compact");
            OperationError::InvalidSessionState
        })?;

        let consent_req: ConsentToken = self
            .oauth2rs
            .inner
            .consent_key
            .decipher(&consent_token_jwe)
            .map_err(|err| {
                error!(?err, "Failed to decrypt consent request");
                OperationError::CryptographyError
            })
            .and_then(|jwe| {
                jwe.from_json().map_err(|err| {
                    error!(?err, "Failed to deserialise consent request");
                    OperationError::SerdeJsonError
                })
            })?;

        // Validate that the ident_id matches our current ident.
        if consent_req.ident_id != ident.get_event_origin_id() {
            security_info!("consent request ident id does not match the identity of our UAT.");
            return Err(OperationError::InvalidSessionState);
        }

        // Validate that the session id matches our uat.
        if consent_req.session_id != ident.get_session_id() {
            security_info!("consent request session id does not match the session id of our UAT.");
            return Err(OperationError::InvalidSessionState);
        }

        if consent_req.expiry <= ct.as_secs() {
            // Token is expired
            error!("Failed to decrypt consent request");
            return Err(OperationError::CryptographyError);
        }

        // The exchange must be performed in the next 60 seconds.
        let expiry = ct.as_secs() + 60;

        // Get the resource server config based on this client_id.
        let o2rs = self
            .oauth2rs
            .inner
            .rs_set_get(&consent_req.client_id)
            .ok_or_else(|| {
                admin_error!("Invalid consent request OAuth2 client_id");
                OperationError::InvalidRequestState
            })?;

        // Extract the state, code challenge, redirect_uri
        let xchg_code = TokenExchangeCode {
            account_uuid,
            session_id: ident.get_session_id(),
            expiry,
            code_challenge: consent_req.code_challenge,
            redirect_uri: consent_req.redirect_uri.clone(),
            scopes: consent_req.scopes.clone(),
            nonce: consent_req.nonce,
        };

        // Encrypt the exchange token
        let code_data_jwe = Jwe::into_json(&xchg_code).map_err(|err| {
            error!(?err, "Unable to encode xchg_code data");
            OperationError::SerdeJsonError
        })?;

        let code = o2rs
            .key_object
            .jwe_a128gcm_encrypt(&code_data_jwe, ct)
            .map(|code| code.to_string())
            .map_err(|err| {
                error!(?err, "Unable to encrypt xchg_code");
                OperationError::CryptographyError
            })?;

        // Everything is DONE! Now submit that it's all happy and the user consented correctly.
        // this will let them bypass consent steps in the future.
        // Submit that we consented to the delayed action queue

        let modlist = ModifyList::new_list(vec![
            Modify::Removed(
                Attribute::OAuth2ConsentScopeMap,
                PartialValue::Refer(o2rs.uuid),
            ),
            Modify::Present(
                Attribute::OAuth2ConsentScopeMap,
                Value::OauthScopeMap(o2rs.uuid, consent_req.scopes.iter().cloned().collect()),
            ),
        ]);

        self.qs_write.internal_modify(
            &filter_all!(f_eq(Attribute::Uuid, PartialValue::Uuid(account_uuid))),
            &modlist,
        )?;

        Ok(AuthorisePermitSuccess {
            redirect_uri: consent_req.redirect_uri,
            state: consent_req.state,
            code,
            response_mode: consent_req.response_mode,
        })
    }

    #[instrument(level = "debug", skip_all)]
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
        let jwe_compact = JweCompact::from_str(token_req_code).map_err(|_| {
            error!("Failed to deserialise a valid JWE");
            Oauth2Error::InvalidRequest
        })?;

        let code_xchg: TokenExchangeCode = o2rs
            .key_object
            .jwe_decrypt(&jwe_compact)
            .map_err(|_| {
                admin_error!("Failed to decrypt token exchange request");
                Oauth2Error::InvalidRequest
            })
            .and_then(|jwe| {
                debug!(?jwe);
                jwe.from_json::<TokenExchangeCode>().map_err(|err| {
                    error!(?err, "Failed to deserialise token exchange code");
                    Oauth2Error::InvalidRequest
                })
            })?;

        if code_xchg.expiry <= ct.as_secs() {
            error!("Expired token exchange request");
            return Err(Oauth2Error::InvalidRequest);
        }

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

            let verifier_secret = PkceS256Secret::from(code_verifier.to_string());

            if !verifier_secret.verify(code_challenge) {
                security_info!(
                    "PKCE code verification failed - this may indicate malicious activity"
                );
                return Err(Oauth2Error::InvalidRequest);
            }
        } else if o2rs.require_pkce() {
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
            security_info!("Invalid OAuth2 redirect_uri (differs from original request uri)");
            return Err(Oauth2Error::InvalidOrigin);
        }

        /*
        // Check that the UAT we are issuing for still is valid.
        //
        // Not sure this is actually needed. To create the token exchange code you need to have
        // a valid, non-expired session, so why do we double check this here?
        let odt_ct = OffsetDateTime::UNIX_EPOCH + ct;
        if let Some(expiry) = code_xchg.uat.expiry {
            if expiry <= odt_ct {
                security_info!(
                    "User Auth Token has expired before we could publish the OAuth2 response"
                );
                return Err(Oauth2Error::AccessDenied);
            }
        }
        */

        // ==== We are now GOOD TO GO! ====
        // Grant the access token response.
        let parent_session_id = code_xchg.session_id;
        let session_id = Uuid::new_v4();

        let scopes = code_xchg.scopes;
        let account_uuid = code_xchg.account_uuid;
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

    #[instrument(level = "debug", skip_all)]
    fn check_oauth2_token_refresh(
        &mut self,
        o2rs: &Oauth2RS,
        refresh_token: &str,
        req_scopes: Option<&BTreeSet<String>>,
        ct: Duration,
    ) -> Result<AccessTokenResponse, Oauth2Error> {
        let jwe_compact = JweCompact::from_str(refresh_token).map_err(|_| {
            error!("Failed to deserialise a valid JWE");
            Oauth2Error::InvalidRequest
        })?;

        // Validate the refresh token decrypts and it's expiry is within the valid window.
        let token: Oauth2TokenType = o2rs
            .key_object
            .jwe_decrypt(&jwe_compact)
            .map_err(|_| {
                admin_error!("Failed to decrypt refresh token request");
                Oauth2Error::InvalidRequest
            })
            .and_then(|jwe| {
                jwe.from_json().map_err(|err| {
                    error!(?err, "Failed to deserialise token");
                    Oauth2Error::InvalidRequest
                })
            })?;

        match token {
            // Oauth2TokenType::Access { .. } |
            Oauth2TokenType::ClientAccess { .. } => {
                admin_error!("attempt to refresh with an access token");
                Err(Oauth2Error::InvalidRequest)
            }
            Oauth2TokenType::Refresh {
                scopes,
                parent_session_id,
                session_id,
                exp,
                uuid,
                iat,
                nbf: _,
                nonce,
            } => {
                if exp <= ct.as_secs() as i64 {
                    security_info!(?uuid, "refresh token has expired, ");
                    return Err(Oauth2Error::InvalidGrant);
                }

                // Check the session is still valid. This call checks the parent session
                // and the OAuth2 session.
                let valid = self
                    .check_oauth2_account_uuid_valid(
                        uuid,
                        session_id,
                        Some(parent_session_id),
                        iat,
                        ct,
                    )
                    .map_err(|_| admin_error!("Account is not valid"));

                let Ok(Some(entry)) = valid else {
                    security_info!(
                        ?uuid,
                        "access token has no account not valid, returning inactive"
                    );
                    return Err(Oauth2Error::InvalidGrant);
                };

                // Check the not issued before of the session relative to this refresh iat
                let oauth2_session = entry
                    .get_ava_as_oauth2session_map(Attribute::OAuth2Session)
                    .and_then(|map| map.get(&session_id))
                    .ok_or_else(|| {
                        security_info!(
                            ?session_id,
                            "No OAuth2 session found, unable to proceed with refresh"
                        );
                        Oauth2Error::InvalidGrant
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
                        Attribute::OAuth2Session,
                        PartialValue::Refer(session_id),
                    )]);

                    self.qs_write
                        .internal_modify(
                            &filter!(f_eq(Attribute::Uuid, PartialValue::Uuid(uuid))),
                            &modlist,
                        )
                        .map_err(|e| {
                            admin_error!("Failed to modify - revoke OAuth2 session {:?}", e);
                            Oauth2Error::ServerError(e)
                        })?;

                    return Err(Oauth2Error::InvalidGrant);
                }

                // Check the scopes are equal or subset, OR none.
                let update_scopes = if let Some(req_scopes) = req_scopes {
                    if req_scopes.is_subset(&scopes) {
                        debug!("oauth2 scopes requested, checked as valid.");
                        // We have to return the requested set since it
                        // may be constrained.
                        req_scopes.clone()
                    } else {
                        warn!("oauth2 scopes requested, invalid.");
                        return Err(Oauth2Error::InvalidScope);
                    }
                } else {
                    debug!("No OAuth2 scopes requested, this is valid.");
                    // Return the initial set of scopes.
                    scopes
                };

                // ----------
                // good to go

                let account_uuid = uuid;

                self.generate_access_token_response(
                    o2rs,
                    ct,
                    update_scopes,
                    account_uuid,
                    parent_session_id,
                    session_id,
                    nonce,
                )
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    #[instrument(level = "debug", skip_all)]
    fn check_oauth2_token_exchange_service_account(
        &mut self,
        o2rs: &Oauth2RS,
        subject_token: &str,
        subject_token_type: &str,
        requested_token_type: Option<&str>,
        audience: Option<&str>,
        resource: Option<&str>,
        req_scopes: Option<&BTreeSet<String>>,
        ct: Duration,
    ) -> Result<AccessTokenResponse, Oauth2Error> {
        if let Some(rtt) = requested_token_type {
            if rtt != OAUTH2_TOKEN_TYPE_ACCESS_TOKEN {
                warn!(
                    requested_token_type = rtt,
                    "Unsupported requested_token_type in token exchange"
                );
                return Err(Oauth2Error::InvalidRequest);
            }
        }

        if let Some(aud) = audience {
            if aud != o2rs.name {
                warn!(expected = %o2rs.name, requested = aud, "Token exchange audience mismatch");
                return Err(Oauth2Error::InvalidTarget);
            }
        }

        if let Some(res) = resource {
            let parsed_resource = Url::parse(res).map_err(|_| {
                warn!(
                    requested = res,
                    "Invalid resource parameter in token exchange"
                );
                Oauth2Error::InvalidRequest
            })?;

            if parsed_resource.fragment().is_some() {
                warn!(
                    requested = res,
                    "Resource parameter must not contain a fragment"
                );
                return Err(Oauth2Error::InvalidRequest);
            }

            let origin = parsed_resource.origin();
            let target_allowed =
                o2rs.origins.contains(&origin) || o2rs.opaque_origins.contains(&parsed_resource);
            if !target_allowed {
                admin_warn!(requested = res, "Token exchange resource target mismatch");
                return Err(Oauth2Error::InvalidTarget);
            }
        }

        if subject_token_type != TOKEN_EXCHANGE_SUBJECT_TOKEN_TYPE_ACCESS {
            security_info!(
                ?subject_token_type,
                "Unsupported subject_token_type in token exchange"
            );
            return Err(Oauth2Error::InvalidRequest);
        }

        let jwsc = JwsCompact::from_str(subject_token).map_err(|_| {
            error!("Failed to deserialise subject token for token exchange");
            Oauth2Error::InvalidRequest
        })?;

        let token = self
            .validate_and_parse_token_to_identity_token(&jwsc, ct)
            .map_err(|err| {
                security_info!(?err, "Unable to validate subject token for token exchange");
                Oauth2Error::InvalidRequest
            })?;

        let (apit, entry) = match token {
            Token::ApiToken(apit, entry) => (apit, entry),
            Token::UserAuthToken(_) => {
                security_info!("Token exchange subject_token must be a service account api token");
                return Err(Oauth2Error::InvalidRequest);
            }
        };

        let ident = self
            .process_apit_to_identity(&apit, Source::Internal, entry, ct)
            .map_err(|err| match err {
                OperationError::SessionExpired | OperationError::NotAuthenticated => {
                    security_info!(
                        ?err,
                        "Service account api token rejected during token exchange"
                    );
                    Oauth2Error::InvalidRequest
                }
                err => Oauth2Error::ServerError(err),
            })?;

        let (_req_scopes, granted_scopes) =
            process_requested_scopes_for_identity(o2rs, &ident, req_scopes)?;

        let session_id = Uuid::new_v4();
        let parent_session_id = apit.token_id;
        let account_uuid = apit.account_id;

        self.generate_access_token_response(
            o2rs,
            ct,
            granted_scopes,
            account_uuid,
            parent_session_id,
            session_id,
            None,
        )
    }

    fn check_oauth2_token_client_credentials(
        &mut self,
        o2rs: &Oauth2RS,
        req_scopes: Option<&BTreeSet<String>>,
        ct: Duration,
    ) -> Result<AccessTokenResponse, Oauth2Error> {
        let req_scopes = req_scopes.cloned().unwrap_or_default();

        // Validate all request scopes have valid syntax.
        validate_scopes(&req_scopes)?;

        // Of these scopes, which do we have available?
        let avail_scopes: Vec<String> = req_scopes
            .intersection(&o2rs.client_scopes)
            .map(|s| s.to_string())
            .collect();

        if avail_scopes.len() != req_scopes.len() {
            admin_warn!(
                ident = %o2rs.name,
                requested_scopes = ?req_scopes,
                available_scopes = ?o2rs.client_scopes,
                "Client does not have access to the requested scopes"
            );
            return Err(Oauth2Error::AccessDenied);
        }

        // == ready to build the access token ==

        let granted_scopes = avail_scopes
            .into_iter()
            .chain(o2rs.client_sup_scopes.iter().cloned())
            .collect::<BTreeSet<_>>();

        let odt_ct = OffsetDateTime::UNIX_EPOCH + ct;
        let iat = ct.as_secs() as i64;
        let exp = iat + OAUTH2_ACCESS_TOKEN_EXPIRY as i64;
        let odt_exp = odt_ct + Duration::from_secs(OAUTH2_ACCESS_TOKEN_EXPIRY as u64);
        let expires_in = OAUTH2_ACCESS_TOKEN_EXPIRY;

        let session_id = Uuid::new_v4();

        let scope = granted_scopes.clone();

        let uuid = o2rs.uuid;

        let access_token_raw = Oauth2TokenType::ClientAccess {
            scopes: granted_scopes,
            session_id,
            uuid,
            exp,
            iat,
            nbf: iat,
        };

        let access_token_data = Jwe::into_json(&access_token_raw).map_err(|err| {
            error!(?err, "Unable to encode token data");
            Oauth2Error::ServerError(OperationError::SerdeJsonError)
        })?;

        let access_token = o2rs
            .key_object
            .jwe_a128gcm_encrypt(&access_token_data, ct)
            .map(|jwe| jwe.to_string())
            .map_err(|err| {
                error!(?err, "Unable to encode token data");
                Oauth2Error::ServerError(OperationError::CryptographyError)
            })?;

        // Write the session to the db
        let session = Value::Oauth2Session(
            session_id,
            Oauth2Session {
                parent: None,
                state: SessionState::ExpiresAt(odt_exp),
                issued_at: odt_ct,
                rs_uuid: o2rs.uuid,
            },
        );

        // We need to create this session on the o2rs
        let modlist =
            ModifyList::new_list(vec![Modify::Present(Attribute::OAuth2Session, session)]);

        self.qs_write
            .internal_modify(
                &filter!(f_eq(Attribute::Uuid, PartialValue::Uuid(uuid))),
                &modlist,
            )
            .map_err(|e| {
                admin_error!("Failed to persist OAuth2 session record {:?}", e);
                Oauth2Error::ServerError(e)
            })?;

        Ok(AccessTokenResponse {
            access_token,
            token_type: AccessTokenType::Bearer,
            issued_token_type: Some(IssuedTokenType::AccessToken),
            expires_in,
            refresh_token: None,
            scope,
            id_token: None,
        })
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
        let refresh_expiry = iat + OAUTH_REFRESH_TOKEN_EXPIRY as i64;
        let odt_refresh_expiry = odt_ct + Duration::from_secs(OAUTH_REFRESH_TOKEN_EXPIRY);

        let scope = scopes.clone();

        let iss = o2rs.iss.clone();

        // Just reflect the access token expiry.
        let exp = expiry.unix_timestamp();

        let aud = o2rs.name.clone();

        let client_id = o2rs.name.clone();

        let id_token = if scopes.contains(OAUTH2_SCOPE_OPENID) {
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

            let entry = match self.qs_write.internal_search_uuid(account_uuid) {
                Ok(entry) => entry,
                Err(err) => return Err(Oauth2Error::ServerError(err)),
            };

            let account = match Account::try_from_entry_rw(&entry, &mut self.qs_write) {
                Ok(account) => account,
                Err(err) => return Err(Oauth2Error::ServerError(err)),
            };

            let s_claims = s_claims_for_account(o2rs, &account, &scopes);
            let extra_claims = extra_claims_for_account(&account, &o2rs.claim_map, &scopes);

            let oidc = OidcToken {
                iss: iss.clone(),
                sub: OidcSubject::U(account_uuid),
                aud: aud.clone(),
                iat,
                nbf: Some(iat),
                exp,
                auth_time: None,
                nonce: nonce.clone(),
                at_hash: None,
                acr: None,
                amr,
                azp: Some(o2rs.name.clone()),
                jti: Some(session_id.to_string()),
                s_claims,
                claims: extra_claims,
            };

            trace!(?oidc);
            let oidc = JwsBuilder::into_json(&oidc)
                .map(|builder| builder.build())
                .map_err(|err| {
                    admin_error!(?err, "Unable to encode access token data");
                    Oauth2Error::ServerError(OperationError::InvalidState)
                })?;

            let jwt_signed = match o2rs.sign_alg {
                SignatureAlgo::Es256 => o2rs.key_object.jws_es256_sign(&oidc, ct),
                SignatureAlgo::Rs256 => o2rs.key_object.jws_rs256_sign(&oidc, ct),
            }
            .map_err(|err| {
                error!(?err, "Unable to encode oidc token data");
                Oauth2Error::ServerError(OperationError::InvalidState)
            })?;

            Some(jwt_signed.to_string())
        } else {
            // id_token is not required in non-openid flows.
            None
        };

        // We need to record this into the record? Delayed action?
        let access_token_data = OAuth2RFC9068Token {
            iss: iss.to_string(),
            sub: account_uuid,
            aud,
            exp,
            nbf: iat,
            iat,
            jti: session_id,
            client_id,
            extensions: OAuth2RFC9068TokenExtensions {
                auth_time: None,
                acr: None,
                amr: None,
                scope: scopes.clone(),
                nonce: nonce.clone(),
                session_id,
                parent_session_id: Some(parent_session_id),
            },
        };

        let access_token_data = JwsBuilder::into_json(&access_token_data)
            .map(|builder| builder.set_typ(Some("at+jwt")).build())
            .map_err(|err| {
                error!(?err, "Unable to encode access token data");
                Oauth2Error::ServerError(OperationError::InvalidState)
            })?;

        let access_token = match o2rs.sign_alg {
            SignatureAlgo::Es256 => o2rs.key_object.jws_es256_sign(&access_token_data, ct),
            SignatureAlgo::Rs256 => o2rs.key_object.jws_rs256_sign(&access_token_data, ct),
        }
        .map_err(|e| {
            admin_error!(err = ?e, "Unable to sign access token data");
            Oauth2Error::ServerError(OperationError::InvalidState)
        })?;

        let refresh_token_raw = Oauth2TokenType::Refresh {
            scopes,
            parent_session_id,
            session_id,
            exp: refresh_expiry,
            uuid: account_uuid,
            iat,
            nbf: iat,
            nonce,
        };

        let refresh_token_data = Jwe::into_json(&refresh_token_raw).map_err(|err| {
            error!(?err, "Unable to encode token data");
            Oauth2Error::ServerError(OperationError::SerdeJsonError)
        })?;

        let refresh_token = o2rs
            .key_object
            .jwe_a128gcm_encrypt(&refresh_token_data, ct)
            .map(|jwe| jwe.to_string())
            .map_err(|err| {
                error!(?err, "Unable to encrypt token data");
                Oauth2Error::ServerError(OperationError::CryptographyError)
            })?;

        // Write the session to the db even with the refresh path, we need to do
        // this to update the "not issued before" time.
        let session = Value::Oauth2Session(
            session_id,
            Oauth2Session {
                parent: Some(parent_session_id),
                state: SessionState::ExpiresAt(odt_refresh_expiry),
                issued_at: odt_ct,
                rs_uuid: o2rs.uuid,
            },
        );

        // We need to update (replace) this session id if present.
        let modlist = ModifyList::new_list(vec![
            // NOTE: Oauth2_session has special handling that allows update in place without
            // the remove step needing to be carried out.
            // Modify::Removed("oauth2_session".into(), PartialValue::Refer(session_id)),
            Modify::Present(Attribute::OAuth2Session, session),
        ]);

        self.qs_write
            .internal_modify(
                &filter!(f_eq(Attribute::Uuid, PartialValue::Uuid(account_uuid))),
                &modlist,
            )
            .map_err(|e| {
                admin_error!("Failed to persist OAuth2 session record {:?}", e);
                Oauth2Error::ServerError(e)
            })?;

        Ok(AccessTokenResponse {
            access_token: access_token.to_string(),
            token_type: AccessTokenType::Bearer,
            issued_token_type: Some(IssuedTokenType::AccessToken),
            expires_in,
            refresh_token: Some(refresh_token),
            scope,
            id_token,
        })
    }

    #[cfg(test)]
    fn reflect_oauth2_token(
        &mut self,
        client_auth_info: &ClientAuthInfo,
        token: &str,
    ) -> Result<Oauth2TokenType, OperationError> {
        let Some(client_authz) = client_auth_info.basic_authz.as_ref() else {
            warn!("OAuth2 client_id not provided by basic authz");
            return Err(OperationError::InvalidSessionState);
        };

        let client_auth = parse_basic_authz(client_authz.as_str()).map_err(|_| {
            warn!("Invalid client_authz base64");
            OperationError::InvalidSessionState
        })?;

        // Get the o2rs for the handle.
        let o2rs = self
            .oauth2rs
            .inner
            .rs_set_get(&client_auth.client_id)
            .ok_or_else(|| {
                warn!("Invalid OAuth2 client_id");
                OperationError::InvalidSessionState
            })?;

        // check the secret.
        if let OauthRSType::Basic { authz_secret, .. } = &o2rs.type_ {
            if o2rs.is_basic() && Some(authz_secret) != client_auth.client_secret.as_ref() {
                info!(
                    "Invalid OAuth2 secret for client_id={}",
                    client_auth.client_id
                );
                return Err(OperationError::InvalidSessionState);
            }
        }

        let jwe_compact = JweCompact::from_str(token).map_err(|err| {
            error!(?err, "Failed to deserialise a valid JWE");
            OperationError::InvalidSessionState
        })?;

        o2rs.key_object
            .jwe_decrypt(&jwe_compact)
            .map_err(|err| {
                error!(?err, "Failed to decrypt token reflection request");
                OperationError::CryptographyError
            })
            .and_then(|jwe| {
                jwe.from_json().map_err(|err| {
                    error!(?err, "Failed to deserialise token for reflection");
                    OperationError::SerdeJsonError
                })
            })
    }
}

impl IdmServerProxyReadTransaction<'_> {
    #[instrument(level = "debug", skip_all)]
    pub fn check_oauth2_authorisation(
        &self,
        maybe_ident: Option<&Identity>,
        auth_req: &AuthorisationRequest,
        ct: Duration,
    ) -> Result<AuthoriseResponse, Oauth2Error> {
        // due to identity processing we already know that:
        // * the session must be authenticated, and valid
        // * is within it's valid time window.
        trace!(?auth_req);

        if auth_req.response_type != ResponseType::Code {
            admin_warn!("Unsupported OAuth2 response_type (should be 'code')");
            return Err(Oauth2Error::UnsupportedResponseType);
        }

        let Some(response_mode) = auth_req.get_response_mode() else {
            warn!(
                "Invalid response_mode {:?} for response_type {:?}",
                auth_req.response_mode, auth_req.response_type
            );
            return Err(Oauth2Error::InvalidRequest);
        };

        let response_mode = match response_mode {
            ResponseMode::Query => SupportedResponseMode::Query,
            ResponseMode::Fragment => SupportedResponseMode::Fragment,
            ResponseMode::FormPost => {
                warn!(
                    "Invalid response mode form_post requested - many clients request this incorrectly but proceed with response_mode=query. Remapping to query."
                );
                warn!("This behaviour WILL BE REMOVED in a future release.");
                SupportedResponseMode::Query
            }
            ResponseMode::Invalid => {
                warn!("Invalid response mode requested, unable to proceed");
                return Err(Oauth2Error::InvalidRequest);
            }
        };

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
            .rs_set_get(&auth_req.client_id)
            .ok_or_else(|| {
                warn!(
                    "Invalid OAuth2 client_id ({}) Have you configured the OAuth2 resource server?",
                    &auth_req.client_id
                );
                Oauth2Error::InvalidClientId
            })?;

        // redirect_uri must be part of the client_id origins, unless the client is public and then it MAY
        // be a loopback address exempting it from this check and enforcement and we can carry on safely.

        // == start validate oauth2 redirect conditions.

        let auth_req_uri_is_loopback = check_is_loopback(&auth_req.redirect_uri);
        let type_allows_localhost_redirect = o2rs.type_.allow_localhost_redirect();

        // This allows loopback uri's that are *not* part of the origin/redirect_uri configurations.
        let loopback_uri_matched = auth_req_uri_is_loopback && type_allows_localhost_redirect;

        // The legacy origin match is in use.
        let origin_uri_matched =
            !o2rs.strict_redirect_uri && o2rs.origins.contains(&auth_req.redirect_uri.origin());

        // Strict uri validation is in use, must be an exact match.
        let strict_redirect_uri_matched =
            o2rs.strict_redirect_uri && o2rs.redirect_uris.contains(&auth_req.redirect_uri);

        // Allow opaque origins such as app uris.
        let opaque_origin_matched = o2rs.opaque_origins.contains(&auth_req.redirect_uri);

        // Was the redirect origin secure?
        let redirect_origin_is_secure = opaque_origin_matched
            || auth_req_uri_is_loopback
            || auth_req.redirect_uri.scheme() == "https";

        // We must assert that *AT LEAST* one of the above match conditions holds true to proceed.
        let valid_match_condition_asserted = loopback_uri_matched
            || origin_uri_matched
            || strict_redirect_uri_matched
            || opaque_origin_matched;

        if valid_match_condition_asserted {
            debug!(
                ?loopback_uri_matched,
                ?origin_uri_matched,
                ?strict_redirect_uri_matched,
                ?opaque_origin_matched,
                "valid redirect uri match condition met."
            );
        } else {
            // Display why it failed.

            // This is to catch the specific case that a public client gets a localhost redirect, but
            // the admin hasn't enabled the flag for it. This way we direct them to the correct cause
            // of the issue, rather than telling them to configure localhost as a redirect location.
            let could_allow_localhost_redirect =
                o2rs.type_.allow_localhost_redirect_could_be_possible();

            if auth_req_uri_is_loopback
                && could_allow_localhost_redirect
                && !type_allows_localhost_redirect
            {
                warn!(redirect_uri = %auth_req.redirect_uri, "OAuth2 redirect_uri returns to localhost, but localhost redirection is not allowed. See 'kanidm system oauth2 enable-localhost-redirects'");
            } else {
                // Not localhost - must be missing the redirect uri then, which is why strict/origin/opaque all failed to assert
                if o2rs.strict_redirect_uri {
                    warn!(
                        "Invalid OAuth2 redirect_uri (must be an exact match to a redirect-url) - got {} from client but configured uris do not match (check oauth2_rs_origin entries)",
                        auth_req.redirect_uri.as_str()
                    );
                } else {
                    warn!(
                        "Invalid OAuth2 redirect_uri (must be related to origin) - got {:?} from client but configured uris differ (compare oauth2_rs_origin_landing with oauth2_rs_origin entries)",
                        auth_req.redirect_uri.origin()
                    );
                }
            }

            // All roads lead to error.
            return Err(Oauth2Error::InvalidOrigin);
        }

        // Assert that if secure origins were required, that we are enforcing that.
        if o2rs.origin_secure_required && !redirect_origin_is_secure {
            warn!(
                "Invalid OAuth2 redirect_uri scheme (must be a secure origin) - got {} instead. Secure origins are required when *at least* one redirect_uri is https, then all uri's must also be secure origins.",
                auth_req.redirect_uri
            );
            return Err(Oauth2Error::InvalidOrigin);
        }

        // == end validation of oauth2 redirect conditions.

        let code_challenge = if let Some(pkce_request) = &auth_req.pkce_request {
            if !o2rs.require_pkce() {
                security_info!(?o2rs.name, "Insecure OAuth2 client configuration - PKCE is not enforced, but client is requesting it!");
            }
            // CodeChallengeMethod must be S256
            if pkce_request.code_challenge_method != CodeChallengeMethod::S256 {
                admin_warn!("Invalid OAuth2 code_challenge_method (must be 'S256')");
                return Err(Oauth2Error::InvalidRequest);
            }
            Some(pkce_request.code_challenge.clone())
        } else if o2rs.require_pkce() {
            security_error!(?o2rs.name, "No PKCE code challenge was provided with client in enforced PKCE mode");
            return Err(Oauth2Error::InvalidRequest);
        } else {
            security_info!(?o2rs.name, "Insecure client configuration - PKCE is not enforced");
            None
        };

        // =============================================================================
        // By this point, we have validated the majority of the security related
        // parameters of the request. We can now inspect the identity and decide
        // if we should ask the user to re-authenticate and proceed.

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

        let Some(ident) = maybe_ident else {
            debug!("No identity available, assume authentication required");
            return Ok(AuthoriseResponse::AuthenticationRequired {
                client_name: o2rs.displayname.clone(),
                login_hint: auth_req.oidc_ext.login_hint.clone(),
            });
        };

        let Some(account_uuid) = ident.get_uuid() else {
            error!("Consent request ident does not have a valid UUID, unable to proceed");
            return Err(Oauth2Error::InvalidRequest);
        };

        // Deny anonymous access to oauth2
        if account_uuid == UUID_ANONYMOUS {
            admin_error!(
                "Invalid OAuth2 request - refusing to allow user that authenticated with anonymous"
            );
            return Err(Oauth2Error::AccessDenied);
        }

        // scopes - you need to have every requested scope or this auth_req is denied.
        let (req_scopes, granted_scopes) =
            process_requested_scopes_for_identity(o2rs, ident, Some(&auth_req.scope))?;

        // MICRO OPTIMISATION = flag if we have openid first, so we can into_iter here rather than
        // cloning.
        let openid_requested = req_scopes.contains(OAUTH2_SCOPE_OPENID);

        let consent_previously_granted =
            if let Some(consent_scopes) = ident.get_oauth2_consent_scopes(o2rs.uuid) {
                trace!(?granted_scopes);
                trace!(?consent_scopes);
                granted_scopes.eq(consent_scopes)
            } else {
                false
            };

        let session_id = ident.get_session_id();

        if consent_previously_granted || !o2rs.enable_consent_prompt() {
            if event_enabled!(tracing::Level::DEBUG) {
                let pretty_scopes: Vec<String> =
                    granted_scopes.iter().map(|s| s.to_owned()).collect();
                debug!(
                    pretty_scopes = pretty_scopes.join(","),
                    prompt_enabled = o2rs.enable_consent_prompt(),
                    previously_granted = consent_previously_granted,
                    "Consent flow passed"
                );
            }

            // Xchg token expires in
            let expiry = ct.as_secs() + 60;

            // Setup for the permit success
            let xchg_code = TokenExchangeCode {
                account_uuid,
                session_id,
                expiry,
                code_challenge,
                redirect_uri: auth_req.redirect_uri.clone(),
                scopes: granted_scopes.into_iter().collect(),
                nonce: auth_req.nonce.clone(),
            };

            // Encrypt the exchange token with the key of the client
            let code_data_jwe = Jwe::into_json(&xchg_code).map_err(|err| {
                error!(?err, "Unable to encode xchg_code data");
                Oauth2Error::ServerError(OperationError::SerdeJsonError)
            })?;

            let code = o2rs
                .key_object
                .jwe_a128gcm_encrypt(&code_data_jwe, ct)
                .map(|jwe| jwe.to_string())
                .map_err(|err| {
                    error!(?err, "Unable to encrypt xchg_code data");
                    Oauth2Error::ServerError(OperationError::CryptographyError)
                })?;

            Ok(AuthoriseResponse::Permitted(AuthorisePermitSuccess {
                redirect_uri: auth_req.redirect_uri.clone(),
                state: auth_req.state.clone(),
                code,
                response_mode,
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
                if granted_scopes.contains(OAUTH2_SCOPE_EMAIL) {
                    pii_scopes.insert(OAUTH2_SCOPE_EMAIL.to_string());
                    pii_scopes.insert("email_verified".to_string());
                }
            };

            if granted_scopes.contains(OAUTH2_SCOPE_SSH_PUBLICKEYS) {
                pii_scopes.insert(OAUTH2_SCOPE_SSH_PUBLICKEYS.to_string());
            }

            // Consent token expires in
            let expiry = ct.as_secs() + 300;

            // Subsequent we then return an encrypted session handle which allows
            // the user to indicate their consent to this authorisation.
            //
            // This session handle is what we use in "permit" to generate the redirect.

            let consent_req = ConsentToken {
                client_id: auth_req.client_id.clone(),
                ident_id: ident.get_event_origin_id(),
                expiry,
                session_id,
                state: auth_req.state.clone(),
                code_challenge,
                redirect_uri: auth_req.redirect_uri.clone(),
                scopes: granted_scopes.iter().cloned().collect(),
                nonce: auth_req.nonce.clone(),
                response_mode,
            };

            let consent_jwe = Jwe::into_json(&consent_req).map_err(|err| {
                error!(?err, "Unable to encode consent data");
                Oauth2Error::ServerError(OperationError::SerdeJsonError)
            })?;

            let consent_token = self
                .oauth2rs
                .inner
                .consent_key
                .encipher::<JweA128GCMEncipher>(&consent_jwe)
                .map(|jwe_compact| jwe_compact.to_string())
                .map_err(|err| {
                    error!(?err, "Unable to encrypt jwe");
                    Oauth2Error::ServerError(OperationError::CryptographyError)
                })?;

            Ok(AuthoriseResponse::ConsentRequested {
                client_name: o2rs.displayname.clone(),
                scopes: granted_scopes.into_iter().collect(),
                pii_scopes,
                consent_token,
            })
        }
    }

    #[instrument(level = "debug", skip_all)]
    pub fn check_oauth2_authorise_reject(
        &self,
        ident: &Identity,
        consent_token: &str,
        ct: Duration,
    ) -> Result<AuthoriseReject, OperationError> {
        let jwe_compact = JweCompact::from_str(consent_token).map_err(|_| {
            error!("Failed to deserialise a valid JWE");
            OperationError::CryptographyError
        })?;

        // Decode the consent req with our system fernet key. Use a ttl of 5 minutes.
        let consent_req: ConsentToken = self
            .oauth2rs
            .inner
            .consent_key
            .decipher(&jwe_compact)
            .map_err(|_| {
                admin_error!("Failed to decrypt consent request");
                OperationError::CryptographyError
            })
            .and_then(|jwe| {
                jwe.from_json().map_err(|err| {
                    error!(?err, "Failed to deserialise consent request");
                    OperationError::SerdeJsonError
                })
            })?;

        // Validate that the ident_id matches our current ident.
        if consent_req.ident_id != ident.get_event_origin_id() {
            security_info!("consent request ident id does not match the identity of our UAT.");
            return Err(OperationError::InvalidSessionState);
        }

        // Validate that the session id matches our session
        if consent_req.session_id != ident.get_session_id() {
            security_info!("consent request sessien id does not match the session id of our UAT.");
            return Err(OperationError::InvalidSessionState);
        }

        if consent_req.expiry <= ct.as_secs() {
            // Token is expired
            error!("Failed to decrypt consent request");
            return Err(OperationError::CryptographyError);
        }

        // Get the resource server config based on this client_id.
        let _o2rs = self
            .oauth2rs
            .inner
            .rs_set_get(&consent_req.client_id)
            .ok_or_else(|| {
                admin_error!("Invalid consent request OAuth2 client_id");
                OperationError::InvalidRequestState
            })?;

        // All good, now confirm the rejection to the client application.
        Ok(AuthoriseReject {
            redirect_uri: consent_req.redirect_uri,
            response_mode: consent_req.response_mode,
        })
    }

    #[instrument(level = "debug", skip_all)]
    pub fn check_oauth2_token_introspect(
        &mut self,
        client_auth_info: &ClientAuthInfo,
        intr_req: &AccessTokenIntrospectRequest,
        ct: Duration,
    ) -> Result<AccessTokenIntrospectResponse, Oauth2Error> {
        let client_auth = get_client_auth(client_auth_info, &intr_req.client_post_auth)?;

        // Get the o2rs for the handle.
        let o2rs = self
            .oauth2rs
            .inner
            .rs_set_get(&client_auth.client_id)
            .ok_or_else(|| {
                warn!("Invalid OAuth2 client_id");
                Oauth2Error::AuthenticationRequired
            })?;

        // We don't need to authenticate, since possession of the access token is already enough
        // to prove identity, and we enforce it is cryptographically valid so it can't be bruteforced
        // by a scanning attack.
        let prefer_short_username = o2rs.prefer_short_username;

        if let Ok(jwsc) = JwsCompact::from_str(&intr_req.token) {
            let access_token = o2rs
                .key_object
                .jws_verify(&jwsc)
                .map_err(|err| {
                    error!(?err, "Unable to verify access token");
                    Oauth2Error::InvalidRequest
                })
                .and_then(|jws| {
                    jws.from_json().map_err(|err| {
                        error!(?err, "Unable to deserialise access token");
                        Oauth2Error::InvalidRequest
                    })
                })?;

            let OAuth2RFC9068Token::<_> {
                iss: _,
                sub,
                aud: _,
                exp,
                nbf,
                iat,
                jti,
                client_id: _,
                extensions:
                    OAuth2RFC9068TokenExtensions {
                        auth_time: _,
                        acr: _,
                        amr: _,
                        scope: scopes,
                        nonce: _,
                        session_id,
                        parent_session_id,
                    },
            } = access_token;

            // Has this token expired?
            if exp <= ct.as_secs() as i64 {
                security_info!(?sub, "access token has expired, returning inactive");
                return Ok(AccessTokenIntrospectResponse::inactive(jti));
            }

            // Is the user expired, or the OAuth2 session invalid?
            let valid = self
                .check_oauth2_account_uuid_valid(sub, session_id, parent_session_id, iat, ct)
                .map_err(|_| admin_error!("Account is not valid"));

            let Ok(Some(entry)) = valid else {
                security_info!(
                    ?sub,
                    "access token account is not valid, returning inactive"
                );
                return Ok(AccessTokenIntrospectResponse::inactive(jti));
            };

            let account = match Account::try_from_entry_ro(&entry, &mut self.qs_read) {
                Ok(account) => account,
                Err(err) => return Err(Oauth2Error::ServerError(err)),
            };

            // ==== good to generate response ====

            let scope = scopes.clone();

            let preferred_username = if prefer_short_username {
                Some(account.name().into())
            } else {
                Some(account.spn().into())
            };

            let token_type = Some(AccessTokenType::Bearer);
            Ok(AccessTokenIntrospectResponse {
                active: true,
                scope,
                client_id: Some(client_auth.client_id.clone()),
                username: preferred_username,
                token_type,
                iat: Some(iat),
                exp: Some(exp),
                nbf: Some(nbf),
                sub: Some(sub.to_string()),
                aud: Some(client_auth.client_id),
                iss: None,
                jti,
            })
        } else {
            let jwe_compact = JweCompact::from_str(&intr_req.token).map_err(|_| {
                error!("Failed to deserialise a valid JWE");
                Oauth2Error::InvalidRequest
            })?;

            let token: Oauth2TokenType = o2rs
                .key_object
                .jwe_decrypt(&jwe_compact)
                .map_err(|_| {
                    admin_error!("Failed to decrypt token introspection request");
                    Oauth2Error::InvalidRequest
                })
                .and_then(|jwe| {
                    jwe.from_json().map_err(|err| {
                        error!(?err, "Failed to deserialise token");
                        Oauth2Error::InvalidRequest
                    })
                })?;

            match token {
                Oauth2TokenType::ClientAccess {
                    scopes,
                    session_id,
                    uuid,
                    exp,
                    iat,
                    nbf,
                } => {
                    // Has this token expired?
                    if exp <= ct.as_secs() as i64 {
                        security_info!(?uuid, "access token has expired, returning inactive");
                        return Ok(AccessTokenIntrospectResponse::inactive(session_id));
                    }

                    // We can't do the same validity check for the client as we do with an account
                    let valid = self
                        .check_oauth2_account_uuid_valid(uuid, session_id, None, iat, ct)
                        .map_err(|_| admin_error!("Account is not valid"));

                    let Ok(Some(entry)) = valid else {
                        security_info!(
                            ?uuid,
                            "access token account is not valid, returning inactive"
                        );
                        return Ok(AccessTokenIntrospectResponse::inactive(session_id));
                    };

                    let scope = scopes.clone();

                    let token_type = Some(AccessTokenType::Bearer);

                    let username = if prefer_short_username {
                        entry
                            .get_ava_single_iname(Attribute::Name)
                            .map(|s| s.to_string())
                    } else {
                        entry.get_ava_single_proto_string(Attribute::Spn)
                    };

                    Ok(AccessTokenIntrospectResponse {
                        active: true,
                        scope,
                        client_id: Some(client_auth.client_id.clone()),
                        username,
                        token_type,
                        iat: Some(iat),
                        exp: Some(exp),
                        nbf: Some(nbf),
                        sub: Some(uuid.to_string()),
                        aud: Some(client_auth.client_id),
                        iss: None,
                        jti: session_id,
                    })
                }
                Oauth2TokenType::Refresh { session_id, .. } => {
                    Ok(AccessTokenIntrospectResponse::inactive(session_id))
                }
            }
        }
    }

    #[instrument(level = "debug", skip_all)]
    pub fn oauth2_openid_userinfo(
        &mut self,
        client_id: &str,
        token: &JwsCompact,
        ct: Duration,
    ) -> Result<OidcToken, Oauth2Error> {
        // DANGER: Why do we have to do this? During the use of qs for internal search
        // and other operations we need qs to be mut. But when we borrow oauth2rs here we
        // cause multiple borrows to occur on struct members that freaks rust out. This *IS*
        // safe however because no element of the search or write process calls the oauth2rs
        // excepting for this idm layer within a single thread, meaning that stripping the
        // lifetime here is safe since we are the sole accessor.
        let o2rs: &Oauth2RS = unsafe {
            let s = self.oauth2rs.inner.rs_set_get(client_id).ok_or_else(|| {
                warn!("Invalid OAuth2 client_id (have you configured the OAuth2 resource server?)");
                Oauth2Error::InvalidClientId
            })?;
            &*(s as *const _)
        };

        let access_token = o2rs
            .key_object
            .jws_verify(token)
            .map_err(|err| {
                error!(?err, "Unable to verify access token");
                Oauth2Error::InvalidRequest
            })
            .and_then(|jws| {
                jws.from_json().map_err(|err| {
                    error!(?err, "Unable to deserialise access token");
                    Oauth2Error::InvalidRequest
                })
            })?;

        let OAuth2RFC9068Token::<_> {
            iss: _,
            sub,
            aud: _,
            exp,
            nbf,
            iat,
            jti: _,
            client_id: _,
            extensions:
                OAuth2RFC9068TokenExtensions {
                    auth_time: _,
                    acr: _,
                    amr: _,
                    scope: scopes,
                    nonce,
                    session_id,
                    parent_session_id,
                },
        } = access_token;
        // Has this token expired?
        if exp <= ct.as_secs() as i64 {
            security_info!(?sub, "access token has expired, returning inactive");
            return Err(Oauth2Error::InvalidToken);
        }

        // Is the user expired, or the OAuth2 session invalid?
        let valid = self
            .check_oauth2_account_uuid_valid(sub, session_id, parent_session_id, iat, ct)
            .map_err(|_| admin_error!("Account is not valid"));

        let Ok(Some(entry)) = valid else {
            security_info!(
                ?sub,
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
        let extra_claims = extra_claims_for_account(&account, &o2rs.claim_map, &scopes);

        // ==== good to generate response ====

        Ok(OidcToken {
            iss,
            sub: OidcSubject::U(sub),
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
            jti: Some(session_id.to_string()),
            s_claims,
            claims: extra_claims,
        })
    }

    #[instrument(level = "debug", skip_all)]
    pub fn oauth2_rfc8414_metadata(
        &self,
        client_id: &str,
    ) -> Result<Oauth2Rfc8414MetadataResponse, OperationError> {
        let o2rs = self.oauth2rs.inner.rs_set_get(client_id).ok_or_else(|| {
            warn!("Invalid OAuth2 client_id (have you configured the OAuth2 resource server?)");
            OperationError::NoMatchingEntries
        })?;

        let issuer = o2rs.iss.clone();
        let authorization_endpoint = o2rs.authorization_endpoint.clone();
        let token_endpoint = o2rs.token_endpoint.clone();
        let revocation_endpoint = Some(o2rs.revocation_endpoint.clone());
        let introspection_endpoint = Some(o2rs.introspection_endpoint.clone());
        let jwks_uri = Some(o2rs.jwks_uri.clone());
        let scopes_supported = Some(o2rs.scopes_supported.iter().cloned().collect());
        let response_types_supported = vec![ResponseType::Code];
        let response_modes_supported = vec![ResponseMode::Query, ResponseMode::Fragment];
        let grant_types_supported = vec![GrantType::AuthorisationCode, GrantType::TokenExchange];

        let token_endpoint_auth_methods_supported = vec![
            TokenEndpointAuthMethod::ClientSecretBasic,
            TokenEndpointAuthMethod::ClientSecretPost,
        ];

        let revocation_endpoint_auth_methods_supported = vec![
            TokenEndpointAuthMethod::ClientSecretBasic,
            TokenEndpointAuthMethod::ClientSecretPost,
        ];

        let introspection_endpoint_auth_methods_supported = vec![
            TokenEndpointAuthMethod::ClientSecretBasic,
            TokenEndpointAuthMethod::ClientSecretPost,
        ];

        let service_documentation = Some(URL_SERVICE_DOCUMENTATION.clone());

        let code_challenge_methods_supported = if o2rs.require_pkce() {
            vec![PkceAlg::S256]
        } else {
            Vec::with_capacity(0)
        };

        Ok(Oauth2Rfc8414MetadataResponse {
            issuer,
            authorization_endpoint,
            token_endpoint,
            jwks_uri,
            registration_endpoint: None,
            scopes_supported,
            response_types_supported,
            response_modes_supported,
            grant_types_supported,
            token_endpoint_auth_methods_supported,
            token_endpoint_auth_signing_alg_values_supported: None,
            service_documentation,
            ui_locales_supported: None,
            op_policy_uri: None,
            op_tos_uri: None,
            revocation_endpoint,
            revocation_endpoint_auth_methods_supported,
            introspection_endpoint,
            introspection_endpoint_auth_methods_supported,
            introspection_endpoint_auth_signing_alg_values_supported: None,
            code_challenge_methods_supported,
        })
    }

    #[instrument(level = "debug", skip_all)]
    pub fn oauth2_openid_discovery(
        &self,
        client_id: &str,
    ) -> Result<OidcDiscoveryResponse, OperationError> {
        let o2rs = self.oauth2rs.inner.rs_set_get(client_id).ok_or_else(|| {
            warn!("Invalid OAuth2 client_id (have you configured the OAuth2 resource server?)");
            OperationError::NoMatchingEntries
        })?;

        let issuer = o2rs.iss.clone();

        let authorization_endpoint = o2rs.authorization_endpoint.clone();
        let token_endpoint = o2rs.token_endpoint.clone();
        let userinfo_endpoint = Some(o2rs.userinfo_endpoint.clone());
        let jwks_uri = o2rs.jwks_uri.clone();
        let scopes_supported = Some(o2rs.scopes_supported.iter().cloned().collect());
        let response_types_supported = vec![ResponseType::Code];
        let response_modes_supported = vec![ResponseMode::Query, ResponseMode::Fragment];

        // TODO: add device code if the rs supports it per <https://www.rfc-editor.org/rfc/rfc8628#section-4>
        // `urn:ietf:params:oauth:grant-type:device_code`
        let grant_types_supported = vec![GrantType::AuthorisationCode, GrantType::TokenExchange];

        let subject_types_supported = vec![SubjectType::Public];

        let id_token_signing_alg_values_supported = match &o2rs.sign_alg {
            SignatureAlgo::Es256 => vec![IdTokenSignAlg::ES256],
            SignatureAlgo::Rs256 => vec![IdTokenSignAlg::RS256],
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

        let code_challenge_methods_supported = if o2rs.require_pkce() {
            vec![PkceAlg::S256]
        } else {
            Vec::with_capacity(0)
        };

        // The following are extensions allowed by the oidc specification.

        let revocation_endpoint = Some(o2rs.revocation_endpoint.clone());
        let revocation_endpoint_auth_methods_supported = vec![
            TokenEndpointAuthMethod::ClientSecretBasic,
            TokenEndpointAuthMethod::ClientSecretPost,
        ];

        let introspection_endpoint = Some(o2rs.introspection_endpoint.clone());
        let introspection_endpoint_auth_methods_supported = vec![
            TokenEndpointAuthMethod::ClientSecretBasic,
            TokenEndpointAuthMethod::ClientSecretPost,
        ];

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
            // TODO: once we support RFC9101 this can be true again
            request_parameter_supported: false,
            // TODO: if we support RFC9101 request_uri methods this can be true
            request_uri_parameter_supported: false,
            // TODO: if we support RFC9101 request_uri methods this should be true
            require_request_uri_registration: false,
            op_policy_uri: None,
            op_tos_uri: None,
            code_challenge_methods_supported,
            // Extensions
            revocation_endpoint,
            revocation_endpoint_auth_methods_supported,
            introspection_endpoint,
            introspection_endpoint_auth_methods_supported,
            introspection_endpoint_auth_signing_alg_values_supported: None,
            device_authorization_endpoint: o2rs.device_authorization_endpoint.clone(),
        })
    }

    #[instrument(level = "debug", skip_all)]
    pub fn oauth2_openid_webfinger(
        &mut self,
        client_id: &str,
        resource_id: &str,
    ) -> Result<OidcWebfingerResponse, OperationError> {
        let o2rs = self.oauth2rs.inner.rs_set_get(client_id).ok_or_else(|| {
            warn!("Invalid OAuth2 client_id (have you configured the OAuth2 resource server?)");
            OperationError::NoMatchingEntries
        })?;

        let Some(spn) = PartialValue::new_spn_s(resource_id) else {
            return Err(OperationError::NoMatchingEntries);
        };

        // Ensure that the account exists.
        if !self
            .qs_read
            .internal_exists(&Filter::new(f_eq(Attribute::Spn, spn)))?
        {
            return Err(OperationError::NoMatchingEntries);
        }

        let issuer = o2rs.iss.clone();

        Ok(OidcWebfingerResponse {
            // we set the subject to the resource_id to ensure we always send something valid back
            // but realistically this will be overwritten on at the API layer
            subject: resource_id.to_string(),
            links: vec![OidcWebfingerRel {
                rel: "http://openid.net/specs/connect/1.0/issuer".into(),
                href: issuer.into(),
            }],
        })
    }

    #[instrument(level = "debug", skip_all)]
    pub fn oauth2_openid_publickey(&self, client_id: &str) -> Result<JwkKeySet, OperationError> {
        let o2rs = self.oauth2rs.inner.rs_set_get(client_id).ok_or_else(|| {
            warn!("Invalid OAuth2 client_id (have you configured the OAuth2 resource server?)");
            OperationError::NoMatchingEntries
        })?;

        trace!(sign_alg = ?o2rs.sign_alg);

        match o2rs.sign_alg {
            SignatureAlgo::Es256 => o2rs.key_object.jws_es256_jwks(),
            SignatureAlgo::Rs256 => o2rs.key_object.jws_rs256_jwks(),
        }
        .ok_or_else(|| {
            error!(o2_client = ?o2rs.name, "Unable to retrieve public keys");
            OperationError::InvalidState
        })
    }
}

fn parse_basic_authz(client_authz: &str) -> Result<ClientAuth, Oauth2Error> {
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

    Ok((client_id, Some(secret)).into())
}

fn s_claims_for_account(
    o2rs: &Oauth2RS,
    account: &Account,
    scopes: &BTreeSet<String>,
) -> OidcClaims {
    let preferred_username = if o2rs.prefer_short_username {
        Some(account.name().into())
    } else {
        Some(account.spn().into())
    };

    let (email, email_verified) = if scopes.contains(OAUTH2_SCOPE_EMAIL) {
        if let Some(mp) = &account.mail_primary {
            (Some(mp.clone()), Some(true))
        } else {
            (None, None)
        }
    } else {
        (None, None)
    };

    let updated_at: Option<OffsetDateTime> = if scopes.contains(OAUTH2_SCOPE_PROFILE) {
        account
            .updated_at
            .as_ref()
            .map(OffsetDateTime::from)
            .and_then(|odt| odt.replace_nanosecond(0).ok())
    } else {
        None
    };
    OidcClaims {
        // Map from displayname
        name: Some(account.displayname.clone()),
        scopes: scopes.iter().cloned().collect(),
        preferred_username,
        email,
        email_verified,
        updated_at,
        ..Default::default()
    }
}

fn extra_claims_for_account(
    account: &Account,

    claim_map: &BTreeMap<Uuid, Vec<(String, ClaimValue)>>,

    scopes: &BTreeSet<String>,
) -> BTreeMap<String, serde_json::Value> {
    let mut extra_claims = BTreeMap::new();

    let mut account_claims: BTreeMap<&str, ClaimValue> = BTreeMap::new();

    // for each group
    for group_uuid in account.groups.iter().map(|g| g.uuid()) {
        // Does this group have any custom claims?
        if let Some(claim) = claim_map.get(group_uuid) {
            // If so, iterate over the set of claims and values.
            for (claim_name, claim_value) in claim.iter() {
                // Does this claim name already exist in our in-progress map?
                match account_claims.entry(claim_name.as_str()) {
                    BTreeEntry::Vacant(e) => {
                        e.insert(claim_value.clone());
                    }
                    BTreeEntry::Occupied(mut e) => {
                        let mut_claim_value = e.get_mut();
                        // Merge the extra details into this.
                        mut_claim_value.merge(claim_value);
                    }
                }
            }
        }
    }

    // Now, flatten all these into the final structure.
    for (claim_name, claim_value) in account_claims {
        extra_claims.insert(claim_name.to_string(), claim_value.to_json_value());
    }

    // Now perform our custom claim's from scopes. We do these second so that
    // a user can't stomp our claim names.

    if scopes.contains(OAUTH2_SCOPE_SSH_PUBLICKEYS) {
        extra_claims.insert(
            OAUTH2_SCOPE_SSH_PUBLICKEYS.to_string(),
            account
                .sshkeys()
                .values()
                .map(|pub_key| serde_json::Value::String(pub_key.to_string()))
                .collect(),
        );
    }

    let wants_groups = scopes.contains(OAUTH2_SCOPE_GROUPS);
    // groups implies uuid + spn to match current behaviour.
    let wants_groups_uuid = wants_groups || scopes.contains(OAUTH2_SCOPE_GROUPS_UUID);
    let wants_groups_spn = wants_groups || scopes.contains(OAUTH2_SCOPE_GROUPS_SPN);
    let wants_groups_name = scopes.contains(OAUTH2_SCOPE_GROUPS_NAME);

    if wants_groups_uuid || wants_groups_name || wants_groups_spn {
        extra_claims.insert(
            OAUTH2_SCOPE_GROUPS.to_string(),
            account
                .groups
                .iter()
                .flat_map(|group| {
                    let mut attrs = Vec::with_capacity(3);

                    if wants_groups_uuid {
                        attrs.push(group.uuid().as_hyphenated().to_string())
                    }

                    if wants_groups_spn {
                        attrs.push(group.spn().clone())
                    }

                    if wants_groups_name {
                        if let Some(name) = group.name() {
                            attrs.push(name.into())
                        }
                    }

                    attrs
                })
                .collect(),
        );
    }

    trace!(?extra_claims);

    extra_claims
}

fn process_requested_scopes_for_identity(
    o2rs: &Oauth2RS,
    ident: &Identity,
    req_scopes: Option<&BTreeSet<String>>,
) -> Result<(BTreeSet<String>, BTreeSet<String>), Oauth2Error> {
    let req_scopes = req_scopes.cloned().unwrap_or_default();

    if req_scopes.is_empty() {
        admin_error!("Invalid OAuth2 request - must contain at least one requested scope");
        return Err(Oauth2Error::InvalidRequest);
    }

    validate_scopes(&req_scopes)?;

    let available_scopes: BTreeSet<String> = o2rs
        .scope_maps
        .iter()
        .filter_map(|(u, m)| ident.is_memberof(*u).then_some(m.iter()))
        .flatten()
        .cloned()
        .collect();

    if !req_scopes.is_subset(&available_scopes) {
        admin_warn!(
            %ident,
            requested_scopes = ?req_scopes,
            available_scopes = ?available_scopes,
            "Identity does not have access to the requested scopes"
        );
        return Err(Oauth2Error::AccessDenied);
    }

    let granted_scopes: BTreeSet<String> = o2rs
        .sup_scope_maps
        .iter()
        .filter_map(|(u, m)| ident.is_memberof(*u).then_some(m.iter()))
        .flatten()
        .cloned()
        .chain(req_scopes.iter().cloned())
        .collect();

    Ok((req_scopes, granted_scopes))
}

fn validate_scopes(req_scopes: &BTreeSet<String>) -> Result<(), Oauth2Error> {
    let failed_scopes = req_scopes
        .iter()
        .filter(|&s| !OAUTHSCOPE_RE.is_match(s))
        .cloned()
        .collect::<Vec<String>>();

    if !failed_scopes.is_empty() {
        let requested_scopes_string = req_scopes
            .iter()
            .cloned()
            .collect::<Vec<String>>()
            .join(",");
        admin_error!(
                "Invalid OAuth2 request - requested scopes ({}) but ({}) failed to pass validation rules - all must match the regex {}",
                    requested_scopes_string,
                    failed_scopes.join(","),
                    OAUTHSCOPE_RE.as_str()
            );
        return Err(Oauth2Error::InvalidScope);
    }
    Ok(())
}

/// device code is a random bucket of bytes used in the device flow
#[inline]
#[cfg(any(feature = "dev-oauth2-device-flow", test))]
#[allow(dead_code)]
fn gen_device_code() -> Result<[u8; 16], Oauth2Error> {
    use rand::TryRng;

    let mut rng = rand::rng();
    let mut result = [0u8; 16];
    // doing it here because of feature-shenanigans.
    if let Err(err) = rng.try_fill_bytes(&mut result) {
        error!("Failed to generate device code! {:?}", err);
        return Err(Oauth2Error::ServerError(OperationError::Backend));
    }
    Ok(result)
}

#[inline]
#[cfg(any(feature = "dev-oauth2-device-flow", test))]
#[allow(dead_code)]
/// Returns (xxx-yyy-zzz, digits) where one's the human-facing code, the other is what we store in the DB.
fn gen_user_code() -> (String, u32) {
    use rand::RngExt;
    let mut rng = rand::rng();
    let num: u32 = rng.random_range(0..=999999999);
    let result = format!("{num:09}");
    (
        format!("{}-{}-{}", &result[0..3], &result[3..6], &result[6..9]),
        num,
    )
}

/// Take the supplied user code and check it's a valid u32
#[allow(dead_code)]
fn parse_user_code(val: &str) -> Result<u32, Oauth2Error> {
    let mut val = val.to_string();
    val.retain(|c| c.is_ascii_digit());
    val.parse().map_err(|err| {
        debug!("Failed to parse value={} as u32: {:?}", val, err);
        Oauth2Error::InvalidRequest
    })
}

/// Check if a host is local (loopback or localhost)
fn host_is_local(host: &Host<&str>) -> bool {
    match host {
        Host::Ipv4(ip) => ip.is_loopback(),
        Host::Ipv6(ip) => ip.is_loopback(),
        Host::Domain(domain) => *domain == "localhost",
    }
}

/// Ensure that the redirect URI is a loopback/localhost address
fn check_is_loopback(redirect_uri: &Url) -> bool {
    redirect_uri.host().is_some_and(|host| {
        // Check if the host is a loopback/localhost address.
        host_is_local(&host)
    })
}

#[cfg(test)]
mod tests {
    use super::{Oauth2TokenType, PkceS256Secret, TOKEN_EXCHANGE_SUBJECT_TOKEN_TYPE_ACCESS};
    use crate::credential::Credential;
    use crate::idm::accountpolicy::ResolvedAccountPolicy;
    use crate::idm::oauth2::{host_is_local, AuthoriseResponse, Oauth2Error, OauthRSType};
    use crate::idm::server::{IdmServer, IdmServerTransaction};
    use crate::idm::serviceaccount::GenerateApiTokenEvent;
    use crate::prelude::*;
    use crate::value::{AuthType, OauthClaimMapJoin, SessionState};
    use crate::valueset::{ValueSetOauthScopeMap, ValueSetSshKey};
    use base64::{engine::general_purpose, Engine as _};
    use compact_jwt::{
        compact::JwkUse, crypto::JwsRs256Verifier, dangernoverify::JwsDangerReleaseWithoutVerify,
        JwaAlg, Jwk, JwsCompact, JwsEs256Verifier, JwsVerifier, OidcSubject, OidcToken,
        OidcUnverified,
    };
    use kanidm_lib_crypto::CryptoPolicy;
    use kanidm_proto::constants::*;
    use kanidm_proto::internal::{SshPublicKey, UserAuthToken};
    use kanidm_proto::oauth2::*;
    use std::collections::{BTreeMap, BTreeSet};
    use std::convert::TryFrom;
    use std::str::FromStr;
    use std::time::Duration;
    use time::OffsetDateTime;
    use uri::{OAUTH2_TOKEN_INTROSPECT_ENDPOINT, OAUTH2_TOKEN_REVOKE_ENDPOINT};

    const TEST_CURRENT_TIME: u64 = 6000;
    const UAT_EXPIRE: u64 = 5;
    const TOKEN_EXPIRE: u64 = 900;

    const UUID_TESTGROUP: Uuid = uuid!("a3028223-bf20-47d5-8b65-967b5d2bb3eb");

    macro_rules! good_authorisation_request {
        (
            $idms_prox_read:expr,
            $ident:expr,
            $ct:expr,
            $pkce_request:expr,
            $scope:expr
        ) => {{
            #[allow(clippy::unnecessary_to_owned)]
            let scope: BTreeSet<String> = $scope.split(" ").map(|s| s.to_string()).collect();

            let auth_req = AuthorisationRequest {
                response_type: ResponseType::Code,
                response_mode: None,
                client_id: "test_resource_server".to_string(),
                state: Some("123".to_string()),
                pkce_request: Some($pkce_request),
                redirect_uri: Url::parse("https://demo.example.com/oauth2/result").unwrap(),
                scope,
                nonce: Some("abcdef".to_string()),
                oidc_ext: Default::default(),
                max_age: None,
                unknown_keys: Default::default(),
            };

            $idms_prox_read
                .check_oauth2_authorisation(Some($ident), &auth_req, $ct)
                .expect("OAuth2 authorisation failed")
        }};
    }

    // setup an OAuth2 instance.
    async fn setup_oauth2_resource_server_basic(
        idms: &IdmServer,
        ct: Duration,
        enable_pkce: bool,
        enable_legacy_crypto: bool,
        prefer_short_username: bool,
    ) -> (String, UserAuthToken, Identity, Uuid) {
        let mut idms_prox_write = idms.proxy_write(ct).await.unwrap();

        let rs_uuid = Uuid::new_v4();

        let entry_group: Entry<EntryInit, EntryNew> = entry_init!(
            (Attribute::Class, EntryClass::Group.to_value()),
            (Attribute::Name, Value::new_iname("testgroup")),
            (Attribute::Description, Value::new_utf8s("testgroup")),
            (Attribute::Uuid, Value::Uuid(UUID_TESTGROUP)),
            (Attribute::Member, Value::Refer(UUID_TESTPERSON_1),)
        );

        let entry_rs: Entry<EntryInit, EntryNew> = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Account.to_value()),
            (
                Attribute::Class,
                EntryClass::OAuth2ResourceServer.to_value()
            ),
            (
                Attribute::Class,
                EntryClass::OAuth2ResourceServerBasic.to_value()
            ),
            (Attribute::Uuid, Value::Uuid(rs_uuid)),
            (Attribute::Name, Value::new_iname("test_resource_server")),
            (
                Attribute::DisplayName,
                Value::new_utf8s("test_resource_server")
            ),
            (
                Attribute::OAuth2RsOriginLanding,
                Value::new_url_s("https://demo.example.com").unwrap()
            ),
            // Supplemental origins
            (
                Attribute::OAuth2RsOrigin,
                Value::new_url_s("https://demo.example.com/oauth2/result").unwrap()
            ),
            (
                Attribute::OAuth2RsOrigin,
                Value::new_url_s("https://portal.example.com/?custom=foo").unwrap()
            ),
            (
                Attribute::OAuth2RsOrigin,
                Value::new_url_s("app://cheese").unwrap()
            ),
            // System admins
            (
                Attribute::OAuth2RsScopeMap,
                Value::new_oauthscopemap(
                    UUID_TESTGROUP,
                    btreeset![OAUTH2_SCOPE_GROUPS.to_string()]
                )
                .expect("invalid oauthscope")
            ),
            (
                Attribute::OAuth2RsScopeMap,
                Value::new_oauthscopemap(
                    UUID_IDM_ALL_ACCOUNTS,
                    btreeset![
                        OAUTH2_SCOPE_OPENID.to_string(),
                        OAUTH2_SCOPE_PROFILE.to_string()
                    ]
                )
                .expect("invalid oauthscope")
            ),
            (
                Attribute::OAuth2RsSupScopeMap,
                Value::new_oauthscopemap(
                    UUID_IDM_ALL_ACCOUNTS,
                    btreeset!["supplement".to_string()]
                )
                .expect("invalid oauthscope")
            ),
            (
                Attribute::OAuth2AllowInsecureClientDisablePkce,
                Value::new_bool(!enable_pkce)
            ),
            (
                Attribute::OAuth2JwtLegacyCryptoEnable,
                Value::new_bool(enable_legacy_crypto)
            ),
            (
                Attribute::OAuth2PreferShortUsername,
                Value::new_bool(prefer_short_username)
            )
        );

        let ce = CreateEvent::new_internal(vec![entry_rs, entry_group, E_TESTPERSON_1.clone()]);
        assert!(idms_prox_write.qs_write.create(&ce).is_ok());

        let entry = idms_prox_write
            .qs_write
            .internal_search_uuid(rs_uuid)
            .expect("Failed to retrieve OAuth2 resource entry ");
        let secret = entry
            .get_ava_single_secret(Attribute::OAuth2RsBasicSecret)
            .map(str::to_string)
            .expect("No oauth2_rs_basic_secret found");

        // Setup the uat we'll be using - note for these tests they *require*
        // the parent session to be valid and present!
        let session_id = uuid::Uuid::new_v4();

        let account = idms_prox_write
            .target_to_account(UUID_TESTPERSON_1)
            .expect("account must exist");

        let uat = account
            .to_userauthtoken(
                session_id,
                SessionScope::ReadWrite,
                ct,
                &ResolvedAccountPolicy::test_policy(),
            )
            .expect("Unable to create uat");

        // Need the uat first for expiry.
        let state = uat
            .expiry
            .map(SessionState::ExpiresAt)
            .unwrap_or(SessionState::NeverExpires);

        let p = CryptoPolicy::minimum();
        let cred =
            Credential::new_password_only(&p, "test_password", OffsetDateTime::UNIX_EPOCH).unwrap();
        let cred_id = cred.uuid;

        let session = Value::Session(
            session_id,
            crate::value::Session {
                label: "label".to_string(),
                state,
                issued_at: time::OffsetDateTime::UNIX_EPOCH + ct,
                issued_by: IdentityId::Internal(UUID_SYSTEM),
                cred_id,
                scope: SessionScope::ReadWrite,
                type_: AuthType::Passkey,
                ext_metadata: Default::default(),
            },
        );

        // Mod the user
        let modlist = ModifyList::new_list(vec![
            Modify::Present(Attribute::UserAuthTokenSession, session),
            Modify::Present(
                Attribute::PrimaryCredential,
                Value::Cred("primary".to_string(), cred),
            ),
        ]);

        idms_prox_write
            .qs_write
            .internal_modify(
                &filter!(f_eq(Attribute::Uuid, PartialValue::Uuid(UUID_TESTPERSON_1))),
                &modlist,
            )
            .expect("Failed to modify user");

        let ident = idms_prox_write
            .process_uat_to_identity(&uat, ct, Source::Internal)
            .expect("Unable to process uat");

        idms_prox_write.commit().expect("failed to commit");

        (secret, uat, ident, rs_uuid)
    }

    async fn setup_oauth2_resource_server_public(
        idms: &IdmServer,
        ct: Duration,
    ) -> (UserAuthToken, Identity, Uuid) {
        let mut idms_prox_write = idms.proxy_write(ct).await.unwrap();

        let rs_uuid = Uuid::new_v4();

        let entry_group: Entry<EntryInit, EntryNew> = entry_init!(
            (Attribute::Class, EntryClass::Group.to_value()),
            (Attribute::Name, Value::new_iname("testgroup")),
            (Attribute::Description, Value::new_utf8s("testgroup")),
            (Attribute::Uuid, Value::Uuid(UUID_TESTGROUP)),
            (Attribute::Member, Value::Refer(UUID_TESTPERSON_1),)
        );

        let entry_rs: Entry<EntryInit, EntryNew> = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Account.to_value()),
            (
                Attribute::Class,
                EntryClass::OAuth2ResourceServer.to_value()
            ),
            (
                Attribute::Class,
                EntryClass::OAuth2ResourceServerPublic.to_value()
            ),
            (Attribute::Uuid, Value::Uuid(rs_uuid)),
            (Attribute::Name, Value::new_iname("test_resource_server")),
            (
                Attribute::DisplayName,
                Value::new_utf8s("test_resource_server")
            ),
            (
                Attribute::OAuth2RsOriginLanding,
                Value::new_url_s("https://demo.example.com").unwrap()
            ),
            (
                Attribute::OAuth2RsOrigin,
                Value::new_url_s("https://demo.example.com/oauth2/result").unwrap()
            ),
            // System admins
            (
                Attribute::OAuth2RsScopeMap,
                Value::new_oauthscopemap(
                    UUID_TESTGROUP,
                    btreeset![OAUTH2_SCOPE_GROUPS.to_string()]
                )
                .expect("invalid oauthscope")
            ),
            (
                Attribute::OAuth2RsScopeMap,
                Value::new_oauthscopemap(
                    UUID_IDM_ALL_ACCOUNTS,
                    btreeset![OAUTH2_SCOPE_OPENID.to_string()]
                )
                .expect("invalid oauthscope")
            ),
            (
                Attribute::OAuth2RsSupScopeMap,
                Value::new_oauthscopemap(
                    UUID_IDM_ALL_ACCOUNTS,
                    btreeset!["supplement".to_string()]
                )
                .expect("invalid oauthscope")
            )
        );
        let ce = CreateEvent::new_internal(vec![entry_rs, entry_group, E_TESTPERSON_1.clone()]);
        assert!(idms_prox_write.qs_write.create(&ce).is_ok());

        // Setup the uat we'll be using - note for these tests they *require*
        // the parent session to be valid and present!

        let session_id = uuid::Uuid::new_v4();

        let account = idms_prox_write
            .target_to_account(UUID_TESTPERSON_1)
            .expect("account must exist");
        let uat = account
            .to_userauthtoken(
                session_id,
                SessionScope::ReadWrite,
                ct,
                &ResolvedAccountPolicy::test_policy(),
            )
            .expect("Unable to create uat");

        // Need the uat first for expiry.
        let state = uat
            .expiry
            .map(SessionState::ExpiresAt)
            .unwrap_or(SessionState::NeverExpires);

        let p = CryptoPolicy::minimum();
        let cred =
            Credential::new_password_only(&p, "test_password", OffsetDateTime::UNIX_EPOCH).unwrap();
        let cred_id = cred.uuid;

        let session = Value::Session(
            session_id,
            crate::value::Session {
                label: "label".to_string(),
                state,
                issued_at: time::OffsetDateTime::UNIX_EPOCH + ct,
                issued_by: IdentityId::Internal(UUID_SYSTEM),
                cred_id,
                scope: SessionScope::ReadWrite,
                type_: AuthType::Passkey,
                ext_metadata: Default::default(),
            },
        );

        // Mod the user
        let modlist = ModifyList::new_list(vec![
            Modify::Present(Attribute::UserAuthTokenSession, session),
            Modify::Present(
                Attribute::PrimaryCredential,
                Value::Cred("primary".to_string(), cred),
            ),
        ]);

        idms_prox_write
            .qs_write
            .internal_modify(
                &filter!(f_eq(Attribute::Uuid, PartialValue::Uuid(UUID_TESTPERSON_1))),
                &modlist,
            )
            .expect("Failed to modify user");

        let ident = idms_prox_write
            .process_uat_to_identity(&uat, ct, Source::Internal)
            .expect("Unable to process uat");

        idms_prox_write.commit().expect("failed to commit");

        (uat, ident, rs_uuid)
    }

    /// Perform an oauth2 exchange, assuming that it will succeed.
    async fn perform_oauth2_exchange(
        idms: &IdmServer,
        ident: &Identity,
        ct: Duration,
        client_authz: ClientAuthInfo,
        scopes: String,
    ) -> AccessTokenResponse {
        let idms_prox_read = idms.proxy_read().await.unwrap();

        let pkce_secret = PkceS256Secret::default();

        let consent_request = good_authorisation_request!(
            idms_prox_read,
            ident,
            ct,
            pkce_secret.to_request(),
            scopes
        );

        let AuthoriseResponse::ConsentRequested { consent_token, .. } = consent_request else {
            unreachable!();
        };

        // == Manually submit the consent token to the permit for the permit_success
        drop(idms_prox_read);
        let mut idms_prox_write = idms.proxy_write(ct).await.unwrap();

        let permit_success = idms_prox_write
            .check_oauth2_authorise_permit(ident, &consent_token, ct)
            .expect("Failed to perform OAuth2 permit");

        // == Submit the token exchange code.
        let token_req: AccessTokenRequest = GrantTypeReq::AuthorizationCode {
            code: permit_success.code,
            redirect_uri: Url::parse("https://demo.example.com/oauth2/result").unwrap(),
            code_verifier: Some(pkce_secret.to_verifier()),
        }
        .into();

        let token_response = idms_prox_write
            .check_oauth2_token_exchange(&client_authz, &token_req, ct)
            .expect("Failed to perform OAuth2 token exchange");

        assert!(idms_prox_write.commit().is_ok());

        token_response
    }

    async fn validate_id_token(idms: &IdmServer, ct: Duration, id_token: &str) -> OidcToken {
        let idms_prox_read = idms.proxy_read().await.unwrap();

        let mut jwkset = idms_prox_read
            .oauth2_openid_publickey("test_resource_server")
            .expect("Failed to get public key");
        let public_jwk = jwkset.keys.pop().expect("no such jwk");

        let jws_validator =
            JwsEs256Verifier::try_from(&public_jwk).expect("failed to build validator");

        let oidc_unverified = OidcUnverified::from_str(id_token).expect("Failed to parse id_token");

        let iat = ct.as_secs() as i64;

        jws_validator
            .verify(&oidc_unverified)
            .unwrap()
            .verify_exp(iat)
            .expect("Failed to verify oidc")
    }

    async fn setup_idm_admin(idms: &IdmServer, ct: Duration) -> (UserAuthToken, Identity) {
        let mut idms_prox_write = idms.proxy_write(ct).await.unwrap();
        let account = idms_prox_write
            .target_to_account(UUID_IDM_ADMIN)
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
        let ident = idms_prox_write
            .process_uat_to_identity(&uat, ct, Source::Internal)
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
        let (secret, _uat, ident, _) =
            setup_oauth2_resource_server_basic(idms, ct, true, false, false).await;

        let idms_prox_read = idms.proxy_read().await.unwrap();

        // == Setup the authorisation request
        let pkce_secret = PkceS256Secret::default();

        let consent_request = good_authorisation_request!(
            idms_prox_read,
            &ident,
            ct,
            pkce_secret.to_request(),
            OAUTH2_SCOPE_OPENID.to_string()
        );

        // Should be in the consent phase;
        let AuthoriseResponse::ConsentRequested { consent_token, .. } = consent_request else {
            unreachable!();
        };

        // == Manually submit the consent token to the permit for the permit_success
        drop(idms_prox_read);
        let mut idms_prox_write = idms.proxy_write(ct).await.unwrap();

        let permit_success = idms_prox_write
            .check_oauth2_authorise_permit(&ident, &consent_token, ct)
            .expect("Failed to perform OAuth2 permit");

        // Check we are reflecting the CSRF properly.
        assert_eq!(permit_success.state.as_deref(), Some("123"));

        // == Submit the token exchange code.

        let token_req = AccessTokenRequest {
            grant_type: GrantTypeReq::AuthorizationCode {
                code: permit_success.code,
                redirect_uri: Url::parse("https://demo.example.com/oauth2/result").unwrap(),
                code_verifier: Some(pkce_secret.to_verifier()),
            },
            client_post_auth: ClientPostAuth {
                client_id: Some("test_resource_server".to_string()),
                client_secret: Some(secret),
            },
        };

        let token_response = idms_prox_write
            .check_oauth2_token_exchange(&ClientAuthInfo::none(), &token_req, ct)
            .expect("Failed to perform OAuth2 token exchange");

        // 🎉 We got a token! In the future we can then check introspection from this point.
        assert_eq!(token_response.token_type, AccessTokenType::Bearer);

        assert!(idms_prox_write.commit().is_ok());
    }

    #[idm_test]
    async fn test_idm_oauth2_public_function(
        idms: &IdmServer,
        _idms_delayed: &mut IdmServerDelayed,
    ) {
        let ct = Duration::from_secs(TEST_CURRENT_TIME);
        let (_uat, ident, _) = setup_oauth2_resource_server_public(idms, ct).await;

        let idms_prox_read = idms.proxy_read().await.unwrap();

        // Get an ident/uat for now.

        // == Setup the authorisation request
        let pkce_secret = PkceS256Secret::default();

        let consent_request = good_authorisation_request!(
            idms_prox_read,
            &ident,
            ct,
            pkce_secret.to_request(),
            OAUTH2_SCOPE_OPENID.to_string()
        );

        // Should be in the consent phase;
        let AuthoriseResponse::ConsentRequested { consent_token, .. } = consent_request else {
            unreachable!();
        };

        // == Manually submit the consent token to the permit for the permit_success
        drop(idms_prox_read);
        let mut idms_prox_write = idms.proxy_write(ct).await.unwrap();

        let permit_success = idms_prox_write
            .check_oauth2_authorise_permit(&ident, &consent_token, ct)
            .expect("Failed to perform OAuth2 permit");

        // Check we are reflecting the CSRF properly.
        assert_eq!(permit_success.state.as_deref(), Some("123"));

        // == Submit the token exchange code.

        let token_req = AccessTokenRequest {
            grant_type: GrantTypeReq::AuthorizationCode {
                code: permit_success.code,
                redirect_uri: Url::parse("https://demo.example.com/oauth2/result").unwrap(),
                // From the first step.
                code_verifier: Some(pkce_secret.to_verifier()),
            },

            client_post_auth: ClientPostAuth {
                client_id: Some("Test_Resource_Server".to_string()),
                client_secret: None,
            },
        };

        let token_response = idms_prox_write
            .check_oauth2_token_exchange(&ClientAuthInfo::none(), &token_req, ct)
            .expect("Failed to perform OAuth2 token exchange");

        // 🎉 We got a token! In the future we can then check introspection from this point.
        assert_eq!(token_response.token_type, AccessTokenType::Bearer);

        assert!(idms_prox_write.commit().is_ok());
    }

    #[idm_test]
    async fn test_idm_oauth2_invalid_authorisation_requests(
        idms: &IdmServer,
        _idms_delayed: &mut IdmServerDelayed,
    ) {
        // Test invalid OAuth2 authorisation states/requests.
        let ct = Duration::from_secs(TEST_CURRENT_TIME);
        let (_secret, _uat, ident, _) =
            setup_oauth2_resource_server_basic(idms, ct, true, false, false).await;

        let (_anon_uat, anon_ident) = setup_idm_admin(idms, ct).await;
        let (_idm_admin_uat, idm_admin_ident) = setup_idm_admin(idms, ct).await;

        // Need a uat from a user not in the group. Probs anonymous.
        let idms_prox_read = idms.proxy_read().await.unwrap();

        let pkce_secret = PkceS256Secret::default();

        let pkce_request = pkce_secret.to_request();

        //  * response type != code.
        let auth_req = AuthorisationRequest {
            // We're unlikely to support Implicit Grant
            response_type: ResponseType::Token,
            response_mode: None,
            client_id: "test_resource_server".to_string(),
            state: Some("123".to_string()),
            pkce_request: Some(pkce_request.clone()),
            redirect_uri: Url::parse("https://demo.example.com/oauth2/result").unwrap(),
            scope: btreeset![OAUTH2_SCOPE_OPENID.to_string()],
            nonce: None,
            oidc_ext: Default::default(),
            max_age: None,
            unknown_keys: Default::default(),
        };

        assert!(
            idms_prox_read
                .check_oauth2_authorisation(Some(&ident), &auth_req, ct)
                .unwrap_err()
                == Oauth2Error::UnsupportedResponseType
        );

        // * No pkce in pkce enforced mode.
        let auth_req = AuthorisationRequest {
            response_type: ResponseType::Code,
            response_mode: None,
            client_id: "test_resource_server".to_string(),
            state: Some("123".to_string()),
            pkce_request: None,
            redirect_uri: Url::parse("https://demo.example.com/oauth2/result").unwrap(),
            scope: btreeset![OAUTH2_SCOPE_OPENID.to_string()],
            nonce: None,
            oidc_ext: Default::default(),
            max_age: None,
            unknown_keys: Default::default(),
        };

        assert!(
            idms_prox_read
                .check_oauth2_authorisation(Some(&ident), &auth_req, ct)
                .unwrap_err()
                == Oauth2Error::InvalidRequest
        );

        //  * invalid rs name
        let auth_req = AuthorisationRequest {
            response_type: ResponseType::Code,
            response_mode: None,
            client_id: "NOT A REAL RESOURCE SERVER".to_string(),
            state: Some("123".to_string()),
            pkce_request: Some(pkce_request.clone()),
            redirect_uri: Url::parse("https://demo.example.com/oauth2/result").unwrap(),
            scope: btreeset![OAUTH2_SCOPE_OPENID.to_string()],
            nonce: None,
            oidc_ext: Default::default(),
            max_age: None,
            unknown_keys: Default::default(),
        };

        assert!(
            idms_prox_read
                .check_oauth2_authorisation(Some(&ident), &auth_req, ct)
                .unwrap_err()
                == Oauth2Error::InvalidClientId
        );

        //  * mismatched origin in the redirect.
        let auth_req = AuthorisationRequest {
            response_type: ResponseType::Code,
            response_mode: None,
            client_id: "test_resource_server".to_string(),
            state: Some("123".to_string()),
            pkce_request: Some(pkce_request.clone()),
            redirect_uri: Url::parse("https://totes.not.sus.org/oauth2/result").unwrap(),
            scope: btreeset![OAUTH2_SCOPE_OPENID.to_string()],
            nonce: None,
            oidc_ext: Default::default(),
            max_age: None,
            unknown_keys: Default::default(),
        };

        assert!(
            idms_prox_read
                .check_oauth2_authorisation(Some(&ident), &auth_req, ct)
                .unwrap_err()
                == Oauth2Error::InvalidOrigin
        );

        // * invalid uri in the redirect
        let auth_req = AuthorisationRequest {
            response_type: ResponseType::Code,
            response_mode: None,
            client_id: "test_resource_server".to_string(),
            state: Some("123".to_string()),
            pkce_request: Some(pkce_request.clone()),
            redirect_uri: Url::parse("https://demo.example.com/oauth2/wrong_place").unwrap(),
            scope: btreeset![OAUTH2_SCOPE_OPENID.to_string()],
            nonce: None,
            oidc_ext: Default::default(),
            max_age: None,
            unknown_keys: Default::default(),
        };

        assert!(
            idms_prox_read
                .check_oauth2_authorisation(Some(&ident), &auth_req, ct)
                .unwrap_err()
                == Oauth2Error::InvalidOrigin
        );

        // * invalid uri (doesn't match query params)
        let auth_req = AuthorisationRequest {
            response_type: ResponseType::Code,
            response_mode: None,
            client_id: "test_resource_server".to_string(),
            state: Some("123".to_string()),
            pkce_request: Some(pkce_request.clone()),
            redirect_uri: Url::parse("https://portal.example.com/?custom=foo&too=many").unwrap(),
            scope: btreeset![OAUTH2_SCOPE_OPENID.to_string()],
            nonce: None,
            oidc_ext: Default::default(),
            max_age: None,
            unknown_keys: Default::default(),
        };

        assert!(
            idms_prox_read
                .check_oauth2_authorisation(Some(&ident), &auth_req, ct)
                .unwrap_err()
                == Oauth2Error::InvalidOrigin
        );

        let auth_req = AuthorisationRequest {
            response_type: ResponseType::Code,
            response_mode: None,
            client_id: "test_resource_server".to_string(),
            state: Some("123".to_string()),
            pkce_request: Some(pkce_request.clone()),
            redirect_uri: Url::parse("https://portal.example.com").unwrap(),
            scope: btreeset![OAUTH2_SCOPE_OPENID.to_string()],
            nonce: None,
            oidc_ext: Default::default(),
            max_age: None,
            unknown_keys: Default::default(),
        };

        assert!(
            idms_prox_read
                .check_oauth2_authorisation(Some(&ident), &auth_req, ct)
                .unwrap_err()
                == Oauth2Error::InvalidOrigin
        );

        let auth_req = AuthorisationRequest {
            response_type: ResponseType::Code,
            response_mode: None,
            client_id: "test_resource_server".to_string(),
            state: Some("123".to_string()),
            pkce_request: Some(pkce_request.clone()),
            redirect_uri: Url::parse("https://portal.example.com/?wrong=queryparam").unwrap(),
            scope: btreeset![OAUTH2_SCOPE_OPENID.to_string()],
            nonce: None,
            oidc_ext: Default::default(),
            max_age: None,
            unknown_keys: Default::default(),
        };

        assert!(
            idms_prox_read
                .check_oauth2_authorisation(Some(&ident), &auth_req, ct)
                .unwrap_err()
                == Oauth2Error::InvalidOrigin
        );

        // Not Authenticated
        let auth_req = AuthorisationRequest {
            response_type: ResponseType::Code,
            response_mode: None,
            client_id: "test_resource_server".to_string(),
            state: Some("123".to_string()),
            pkce_request: Some(pkce_request.clone()),
            redirect_uri: Url::parse("https://demo.example.com/oauth2/result").unwrap(),
            scope: btreeset![OAUTH2_SCOPE_OPENID.to_string()],
            nonce: None,
            oidc_ext: Default::default(),
            max_age: None,
            unknown_keys: Default::default(),
        };

        let req = idms_prox_read
            .check_oauth2_authorisation(None, &auth_req, ct)
            .unwrap();

        assert!(matches!(
            req,
            AuthoriseResponse::AuthenticationRequired { .. }
        ));

        // Requested scope is not available
        let auth_req = AuthorisationRequest {
            response_type: ResponseType::Code,
            response_mode: None,
            client_id: "test_resource_server".to_string(),
            state: Some("123".to_string()),
            pkce_request: Some(pkce_request.clone()),
            redirect_uri: Url::parse("https://demo.example.com/oauth2/result").unwrap(),
            scope: btreeset!["invalid_scope".to_string(), "read".to_string()],
            nonce: None,
            oidc_ext: Default::default(),
            max_age: None,
            unknown_keys: Default::default(),
        };

        assert!(
            idms_prox_read
                .check_oauth2_authorisation(Some(&ident), &auth_req, ct)
                .unwrap_err()
                == Oauth2Error::AccessDenied
        );

        // Not a member of the group.
        let auth_req = AuthorisationRequest {
            response_type: ResponseType::Code,
            response_mode: None,
            client_id: "test_resource_server".to_string(),
            state: Some("123".to_string()),
            pkce_request: Some(pkce_request.clone()),
            redirect_uri: Url::parse("https://demo.example.com/oauth2/result").unwrap(),
            scope: btreeset!["openid".to_string(), "read".to_string()],
            nonce: None,
            oidc_ext: Default::default(),
            max_age: None,
            unknown_keys: Default::default(),
        };

        assert!(
            idms_prox_read
                .check_oauth2_authorisation(Some(&idm_admin_ident), &auth_req, ct)
                .unwrap_err()
                == Oauth2Error::AccessDenied
        );

        // Deny Anonymous auth methods
        let auth_req = AuthorisationRequest {
            response_type: ResponseType::Code,
            response_mode: None,
            client_id: "test_resource_server".to_string(),
            state: Some("123".to_string()),
            pkce_request: Some(pkce_request),
            redirect_uri: Url::parse("https://demo.example.com/oauth2/result").unwrap(),
            scope: btreeset!["openid".to_string(), "read".to_string()],
            nonce: None,
            oidc_ext: Default::default(),
            max_age: None,
            unknown_keys: Default::default(),
        };

        assert!(
            idms_prox_read
                .check_oauth2_authorisation(Some(&anon_ident), &auth_req, ct)
                .unwrap_err()
                == Oauth2Error::AccessDenied
        );
    }

    #[idm_test]
    async fn test_idm_oauth2_invalid_authorisation_permit_requests(
        idms: &IdmServer,
        _idms_delayed: &mut IdmServerDelayed,
    ) {
        // Test invalid OAuth2 authorisation states/requests.
        let ct = Duration::from_secs(TEST_CURRENT_TIME);
        let (_secret, uat, ident, _) =
            setup_oauth2_resource_server_basic(idms, ct, true, false, false).await;

        let mut idms_prox_write = idms.proxy_write(ct).await.unwrap();

        let mut uat_wrong_session_id = uat.clone();
        uat_wrong_session_id.session_id = uuid::Uuid::new_v4();
        let ident_wrong_session_id = idms_prox_write
            .process_uat_to_identity(&uat_wrong_session_id, ct, Source::Internal)
            .expect("Unable to process uat");

        let account = idms_prox_write
            .target_to_account(UUID_IDM_ADMIN)
            .expect("account must exist");
        let session_id = uuid::Uuid::new_v4();
        let uat2 = account
            .to_userauthtoken(
                session_id,
                SessionScope::ReadWrite,
                ct,
                &ResolvedAccountPolicy::test_policy(),
            )
            .expect("Unable to create uat");
        let ident2 = idms_prox_write
            .process_uat_to_identity(&uat2, ct, Source::Internal)
            .expect("Unable to process uat");

        assert!(idms_prox_write.commit().is_ok());

        // Now start the test

        let idms_prox_read = idms.proxy_read().await.unwrap();

        let pkce_secret = PkceS256Secret::default();

        let consent_request = good_authorisation_request!(
            idms_prox_read,
            &ident,
            ct,
            pkce_secret.to_request(),
            OAUTH2_SCOPE_OPENID.to_string()
        );

        let AuthoriseResponse::ConsentRequested { consent_token, .. } = consent_request else {
            unreachable!();
        };

        drop(idms_prox_read);
        let mut idms_prox_write = idms.proxy_write(ct).await.unwrap();

        // Invalid permits
        //  * expired token, aka past ttl.
        assert!(
            idms_prox_write
                .check_oauth2_authorise_permit(
                    &ident,
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
                .check_oauth2_authorise_permit(&ident2, &consent_token, ct,)
                .unwrap_err()
                == OperationError::InvalidSessionState
        );

        //  * incorrect session id
        assert!(
            idms_prox_write
                .check_oauth2_authorise_permit(&ident_wrong_session_id, &consent_token, ct,)
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

        let idms_prox_read = idms.proxy_read().await.unwrap();

        // == Setup the authorisation request
        let pkce_secret = PkceS256Secret::default();

        let consent_request = good_authorisation_request!(
            idms_prox_read,
            &ident,
            ct,
            pkce_secret.to_request(),
            OAUTH2_SCOPE_OPENID.to_string()
        );

        let code_verifier = Some(pkce_secret.to_verifier());

        let AuthoriseResponse::ConsentRequested { consent_token, .. } = consent_request else {
            unreachable!();
        };

        drop(idms_prox_read);
        let mut idms_prox_write = idms.proxy_write(ct).await.unwrap();

        // == Manually submit the consent token to the permit for the permit_success
        let permit_success = idms_prox_write
            .check_oauth2_authorise_permit(&ident, &consent_token, ct)
            .expect("Failed to perform OAuth2 permit");

        // == Submit the token exchange code.

        // Invalid token exchange
        //  * invalid client_authz (not base64)
        let token_req: AccessTokenRequest = GrantTypeReq::AuthorizationCode {
            code: permit_success.code.clone(),
            redirect_uri: Url::parse("https://demo.example.com/oauth2/result").unwrap(),
            code_verifier: code_verifier.clone(),
        }
        .into();

        let client_authz = ClientAuthInfo::from("not base64");

        assert!(
            idms_prox_write
                .check_oauth2_token_exchange(&client_authz, &token_req, ct)
                .unwrap_err()
                == Oauth2Error::AuthenticationRequired
        );

        //  * doesn't have ':'
        let client_authz =
            general_purpose::STANDARD.encode(format!("test_resource_server {secret}"));
        let client_authz = ClientAuthInfo::from(client_authz.as_str());

        assert!(
            idms_prox_write
                .check_oauth2_token_exchange(&client_authz, &token_req, ct)
                .unwrap_err()
                == Oauth2Error::AuthenticationRequired
        );

        //  * invalid client_id
        let client_authz = ClientAuthInfo::encode_basic("NOT A REAL SERVER", secret.as_str());

        assert!(
            idms_prox_write
                .check_oauth2_token_exchange(&client_authz, &token_req, ct)
                .unwrap_err()
                == Oauth2Error::AuthenticationRequired
        );

        //  * valid client_id, but invalid secret
        let client_authz = ClientAuthInfo::encode_basic("test_resource_server", "12345");

        assert!(
            idms_prox_write
                .check_oauth2_token_exchange(&client_authz, &token_req, ct)
                .unwrap_err()
                == Oauth2Error::AuthenticationRequired
        );

        // ✅ Now the valid client_authz is in place.
        let client_authz = ClientAuthInfo::encode_basic("test_resource_server", secret.as_str());

        //  * expired exchange code (took too long)
        assert!(
            idms_prox_write
                .check_oauth2_token_exchange(
                    &client_authz,
                    &token_req,
                    ct + Duration::from_secs(TOKEN_EXPIRE)
                )
                .unwrap_err()
                == Oauth2Error::InvalidRequest
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
            code_verifier: code_verifier.clone(),
        }
        .into();
        assert!(
            idms_prox_write
                .check_oauth2_token_exchange(&client_authz, &token_req, ct)
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
                .check_oauth2_token_exchange(&client_authz, &token_req, ct)
                .unwrap_err()
                == Oauth2Error::InvalidRequest
        );

        assert!(idms_prox_write.commit().is_ok());
    }

    #[idm_test]
    async fn test_idm_oauth2_supplemental_origin_redirect(
        idms: &IdmServer,
        _idms_delayed: &mut IdmServerDelayed,
    ) {
        let ct = Duration::from_secs(TEST_CURRENT_TIME);
        let (secret, uat, ident, _) =
            setup_oauth2_resource_server_basic(idms, ct, true, false, false).await;

        let idms_prox_read = idms.proxy_read().await.unwrap();

        // == Setup the authorisation request
        let pkce_secret = PkceS256Secret::default();

        let redirect_uri = Url::parse("https://portal.example.com/?custom=foo").unwrap();

        let auth_req = AuthorisationRequest {
            response_type: ResponseType::Code,
            response_mode: None,
            client_id: "test_resource_server".to_string(),
            state: None,
            pkce_request: Some(pkce_secret.to_request()),
            redirect_uri: redirect_uri.clone(),
            scope: btreeset![OAUTH2_SCOPE_GROUPS.to_string()],
            nonce: Some("abcdef".to_string()),
            oidc_ext: Default::default(),
            max_age: None,
            unknown_keys: Default::default(),
        };

        let consent_request = idms_prox_read
            .check_oauth2_authorisation(Some(&ident), &auth_req, ct)
            .expect("OAuth2 authorisation failed");

        trace!(?consent_request);

        // Should be in the consent phase;
        let AuthoriseResponse::ConsentRequested { consent_token, .. } = consent_request else {
            unreachable!();
        };

        // == Manually submit the consent token to the permit for the permit_success
        drop(idms_prox_read);
        let mut idms_prox_write = idms.proxy_write(ct).await.unwrap();

        let permit_success = idms_prox_write
            .check_oauth2_authorise_permit(&ident, &consent_token, ct)
            .expect("Failed to perform OAuth2 permit");

        // Check we are reflecting the CSRF properly.
        assert_eq!(permit_success.state.as_deref(), None);

        // Assert we followed the redirect uri including the query elements
        // we have in the url.
        let permit_redirect_uri = permit_success.build_redirect_uri();

        assert_eq!(permit_redirect_uri.origin(), redirect_uri.origin());
        assert_eq!(permit_redirect_uri.path(), redirect_uri.path());
        let query = BTreeMap::from_iter(permit_redirect_uri.query_pairs().into_owned());
        // Assert the query pair wasn't changed
        assert_eq!(query.get("custom").map(|s| s.as_str()), Some("foo"));

        // == Submit the token exchange code.
        // ⚠️  This is where we submit a different origin!
        let token_req = AccessTokenRequest {
            grant_type: GrantTypeReq::AuthorizationCode {
                code: permit_success.code,
                redirect_uri,
                code_verifier: Some(pkce_secret.to_verifier()),
            },

            client_post_auth: ClientPostAuth {
                client_id: Some("test_resource_server".to_string()),
                client_secret: Some(secret.clone()),
            },
        };

        let token_response = idms_prox_write
            .check_oauth2_token_exchange(&ClientAuthInfo::none(), &token_req, ct)
            .expect("Failed to perform OAuth2 token exchange");

        // 🎉 We got a token! In the future we can then check introspection from this point.
        assert_eq!(token_response.token_type, AccessTokenType::Bearer);

        assert!(idms_prox_write.commit().is_ok());

        // ============================================================================
        // Now repeat the test with the app url.

        let mut idms_prox_read = idms.proxy_read().await.unwrap();

        // Reload the ident since it pins an entry in memory.
        let ident = idms_prox_read
            .process_uat_to_identity(&uat, ct, Source::Internal)
            .expect("Unable to process uat");

        let pkce_secret = PkceS256Secret::default();

        let auth_req = AuthorisationRequest {
            response_type: ResponseType::Code,
            response_mode: None,
            client_id: "test_resource_server".to_string(),
            state: Some("123".to_string()),
            pkce_request: Some(pkce_secret.to_request()),
            redirect_uri: Url::parse("app://cheese").unwrap(),
            scope: btreeset![OAUTH2_SCOPE_GROUPS.to_string()],
            nonce: Some("abcdef".to_string()),
            oidc_ext: Default::default(),
            max_age: None,
            unknown_keys: Default::default(),
        };

        let consent_request = idms_prox_read
            .check_oauth2_authorisation(Some(&ident), &auth_req, ct)
            .expect("OAuth2 authorisation failed");

        trace!(?consent_request);

        let AuthoriseResponse::Permitted(permit_success) = consent_request else {
            unreachable!();
        };

        // == Manually submit the consent token to the permit for the permit_success
        // Check we are reflecting the CSRF properly.
        assert_eq!(permit_success.state.as_deref(), Some("123"));

        // == Submit the token exchange code.
        // ⚠️  This is where we submit a different origin!
        let token_req = AccessTokenRequest {
            grant_type: GrantTypeReq::AuthorizationCode {
                code: permit_success.code,
                redirect_uri: Url::parse("app://cheese").unwrap(),
                code_verifier: Some(pkce_secret.to_verifier()),
            },

            client_post_auth: ClientPostAuth {
                client_id: Some("test_resource_server".to_string()),
                client_secret: Some(secret),
            },
        };

        drop(idms_prox_read);
        let mut idms_prox_write = idms.proxy_write(ct).await.unwrap();

        let token_response = idms_prox_write
            .check_oauth2_token_exchange(&ClientAuthInfo::none(), &token_req, ct)
            .expect("Failed to perform OAuth2 token exchange");

        // 🎉 We got a token! In the future we can then check introspection from this point.
        assert_eq!(token_response.token_type, AccessTokenType::Bearer);
    }

    #[idm_test]
    async fn test_idm_oauth2_token_introspect(
        idms: &IdmServer,
        _idms_delayed: &mut IdmServerDelayed,
    ) {
        let ct = Duration::from_secs(TEST_CURRENT_TIME);
        let (secret, _uat, ident, _) =
            setup_oauth2_resource_server_basic(idms, ct, true, false, false).await;
        let client_authz = ClientAuthInfo::encode_basic("test_resource_server", secret.as_str());

        let idms_prox_read = idms.proxy_read().await.unwrap();

        // == Setup the authorisation request
        let pkce_secret = PkceS256Secret::default();
        let consent_request = good_authorisation_request!(
            idms_prox_read,
            &ident,
            ct,
            pkce_secret.to_request(),
            OAUTH2_SCOPE_OPENID.to_string()
        );

        let AuthoriseResponse::ConsentRequested { consent_token, .. } = consent_request else {
            unreachable!();
        };

        // == Manually submit the consent token to the permit for the permit_success
        drop(idms_prox_read);
        let mut idms_prox_write = idms.proxy_write(ct).await.unwrap();

        let permit_success = idms_prox_write
            .check_oauth2_authorise_permit(&ident, &consent_token, ct)
            .expect("Failed to perform OAuth2 permit");

        let token_req: AccessTokenRequest = GrantTypeReq::AuthorizationCode {
            code: permit_success.code,
            redirect_uri: Url::parse("https://demo.example.com/oauth2/result").unwrap(),
            code_verifier: Some(pkce_secret.to_verifier()),
        }
        .into();
        let oauth2_token = idms_prox_write
            .check_oauth2_token_exchange(&client_authz, &token_req, ct)
            .expect("Unable to exchange for OAuth2 token");

        assert!(idms_prox_write.commit().is_ok());

        // Okay, now we have the token, we can check it works with introspect.
        let mut idms_prox_read = idms.proxy_read().await.unwrap();

        let intr_request = AccessTokenIntrospectRequest {
            token: oauth2_token.access_token,
            token_type_hint: None,
            client_post_auth: ClientPostAuth::default(),
        };
        let intr_response = idms_prox_read
            .check_oauth2_token_introspect(&client_authz, &intr_request, ct)
            .expect("Failed to inspect token");

        eprintln!("👉  {intr_response:?}");
        assert!(intr_response.active);
        assert_eq!(
            intr_response.scope,
            btreeset!["openid".to_string(), "supplement".to_string()]
        );
        assert_eq!(
            intr_response.client_id.as_deref(),
            Some("test_resource_server")
        );
        assert_eq!(
            intr_response.username.as_deref(),
            Some("testperson1@example.com")
        );
        assert_eq!(intr_response.token_type, Some(AccessTokenType::Bearer));
        assert_eq!(intr_response.iat, Some(ct.as_secs() as i64));
        assert_eq!(intr_response.nbf, Some(ct.as_secs() as i64));

        drop(idms_prox_read);
        // start a write,

        let mut idms_prox_write = idms.proxy_write(ct).await.unwrap();
        // Expire the account, should cause introspect to return inactive.
        let v_expire = Value::new_datetime_epoch(Duration::from_secs(TEST_CURRENT_TIME - 1));
        let me_inv_m = ModifyEvent::new_internal_invalid(
            filter!(f_eq(Attribute::Uuid, PartialValue::Uuid(UUID_TESTPERSON_1))),
            ModifyList::new_list(vec![Modify::Present(Attribute::AccountExpire, v_expire)]),
        );
        // go!
        assert!(idms_prox_write.qs_write.modify(&me_inv_m).is_ok());
        assert!(idms_prox_write.commit().is_ok());

        // start a new read
        // check again.
        let mut idms_prox_read = idms.proxy_read().await.unwrap();
        let intr_response = idms_prox_read
            .check_oauth2_token_introspect(&client_authz, &intr_request, ct)
            .expect("Failed to inspect token");

        assert!(!intr_response.active);
    }

    #[idm_test]
    async fn test_idm_oauth2_token_revoke(idms: &IdmServer, _idms_delayed: &mut IdmServerDelayed) {
        // First, setup to get a token.
        let ct = Duration::from_secs(TEST_CURRENT_TIME);
        let (secret, _uat, ident, _) =
            setup_oauth2_resource_server_basic(idms, ct, true, false, false).await;
        let client_authz = ClientAuthInfo::encode_basic("test_resource_server", secret.as_str());

        let idms_prox_read = idms.proxy_read().await.unwrap();

        // == Setup the authorisation request
        let pkce_secret = PkceS256Secret::default();

        let consent_request = good_authorisation_request!(
            idms_prox_read,
            &ident,
            ct,
            pkce_secret.to_request(),
            OAUTH2_SCOPE_OPENID.to_string()
        );

        let AuthoriseResponse::ConsentRequested { consent_token, .. } = consent_request else {
            unreachable!();
        };

        // == Manually submit the consent token to the permit for the permit_success
        drop(idms_prox_read);
        let mut idms_prox_write = idms.proxy_write(ct).await.unwrap();

        let permit_success = idms_prox_write
            .check_oauth2_authorise_permit(&ident, &consent_token, ct)
            .expect("Failed to perform OAuth2 permit");

        // Assert that the consent was submitted
        let token_req: AccessTokenRequest = GrantTypeReq::AuthorizationCode {
            code: permit_success.code,
            redirect_uri: Url::parse("https://demo.example.com/oauth2/result").unwrap(),
            code_verifier: Some(pkce_secret.to_verifier()),
        }
        .into();
        let oauth2_token = idms_prox_write
            .check_oauth2_token_exchange(&client_authz, &token_req, ct)
            .expect("Unable to exchange for OAuth2 token");

        assert!(idms_prox_write.commit().is_ok());

        // Okay, now we have the token, we can check behaviours with the revoke interface.

        // First, assert it is valid, similar to the introspect api.
        let mut idms_prox_read = idms.proxy_read().await.unwrap();
        let intr_request = AccessTokenIntrospectRequest {
            token: oauth2_token.access_token.clone(),
            token_type_hint: None,
            client_post_auth: ClientPostAuth::default(),
        };
        let intr_response = idms_prox_read
            .check_oauth2_token_introspect(&client_authz, &intr_request, ct)
            .expect("Failed to inspect token");
        eprintln!("👉  {intr_response:?}");
        assert!(intr_response.active);
        drop(idms_prox_read);

        // First, the revoke needs basic auth. Provide incorrect auth, and we fail.
        let mut idms_prox_write = idms.proxy_write(ct).await.unwrap();

        let bad_client_authz = ClientAuthInfo::encode_basic("test_resource_server", "12345");

        let revoke_request = TokenRevokeRequest {
            token: oauth2_token.access_token.clone(),
            token_type_hint: None,
            client_post_auth: ClientPostAuth::default(),
        };
        let e = idms_prox_write
            .oauth2_token_revoke(&bad_client_authz, &revoke_request, ct)
            .unwrap_err();
        assert!(matches!(e, Oauth2Error::AuthenticationRequired));
        assert!(idms_prox_write.commit().is_ok());

        // Now submit a non-existent/invalid token. Does not affect our tokens validity.
        let mut idms_prox_write = idms.proxy_write(ct).await.unwrap();
        let revoke_request = TokenRevokeRequest {
            token: "this is an invalid token, nothing will happen!".to_string(),
            token_type_hint: None,
            client_post_auth: ClientPostAuth::default(),
        };
        let e = idms_prox_write
            .oauth2_token_revoke(&client_authz, &revoke_request, ct)
            .unwrap_err();
        assert!(matches!(e, Oauth2Error::InvalidRequest));
        assert!(idms_prox_write.commit().is_ok());

        // Check our token is still valid.
        let mut idms_prox_read = idms.proxy_read().await.unwrap();
        let intr_response = idms_prox_read
            .check_oauth2_token_introspect(&client_authz, &intr_request, ct)
            .expect("Failed to inspect token");
        assert!(intr_response.active);
        drop(idms_prox_read);

        // Finally revoke it.
        let mut idms_prox_write = idms.proxy_write(ct).await.unwrap();
        let revoke_request = TokenRevokeRequest {
            token: oauth2_token.access_token.clone(),
            token_type_hint: None,
            client_post_auth: ClientPostAuth::default(),
        };
        assert!(idms_prox_write
            .oauth2_token_revoke(&client_authz, &revoke_request, ct,)
            .is_ok());
        assert!(idms_prox_write.commit().is_ok());

        // Assert it is now invalid.
        let mut idms_prox_read = idms.proxy_read().await.unwrap();
        let intr_response = idms_prox_read
            .check_oauth2_token_introspect(&client_authz, &intr_request, ct)
            .expect("Failed to inspect token");

        assert!(!intr_response.active);
        drop(idms_prox_read);

        // Force trim the session and wait for the grace window to pass. The token will be invalidated
        let mut idms_prox_write = idms.proxy_write(ct).await.unwrap();
        let filt = filter!(f_eq(
            Attribute::Uuid,
            PartialValue::Uuid(ident.get_uuid().unwrap())
        ));
        let mut work_set = idms_prox_write
            .qs_write
            .internal_search_writeable(&filt)
            .expect("Failed to perform internal search writeable");
        for (_, entry) in work_set.iter_mut() {
            let _ = entry.force_trim_ava(Attribute::OAuth2Session);
        }
        assert!(idms_prox_write
            .qs_write
            .internal_apply_writable(work_set)
            .is_ok());

        assert!(idms_prox_write.commit().is_ok());

        let mut idms_prox_read = idms.proxy_read().await.unwrap();
        // Grace window in effect.
        let intr_response = idms_prox_read
            .check_oauth2_token_introspect(&client_authz, &intr_request, ct)
            .expect("Failed to inspect token");
        assert!(intr_response.active);

        // Grace window passed, it will now be invalid.
        let ct = ct + AUTH_TOKEN_GRACE_WINDOW;
        let intr_response = idms_prox_read
            .check_oauth2_token_introspect(&client_authz, &intr_request, ct)
            .expect("Failed to inspect token");
        assert!(!intr_response.active);

        drop(idms_prox_read);

        // A second invalidation of the token "does nothing".
        let mut idms_prox_write = idms.proxy_write(ct).await.unwrap();
        let revoke_request = TokenRevokeRequest {
            token: oauth2_token.access_token,
            token_type_hint: None,
            client_post_auth: ClientPostAuth::default(),
        };
        assert!(idms_prox_write
            .oauth2_token_revoke(&client_authz, &revoke_request, ct,)
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
        let (secret, _uat, ident, _) =
            setup_oauth2_resource_server_basic(idms, ct, true, false, false).await;
        let client_authz = ClientAuthInfo::encode_basic("test_resource_server", secret.as_str());

        let idms_prox_read = idms.proxy_read().await.unwrap();

        // == Setup the authorisation request
        let pkce_secret = PkceS256Secret::default();

        let consent_request = good_authorisation_request!(
            idms_prox_read,
            &ident,
            ct,
            pkce_secret.to_request(),
            OAUTH2_SCOPE_OPENID.to_string()
        );

        let AuthoriseResponse::ConsentRequested { consent_token, .. } = consent_request else {
            unreachable!();
        };

        // == Manually submit the consent token to the permit for the permit_success
        drop(idms_prox_read);
        let mut idms_prox_write = idms.proxy_write(ct).await.unwrap();

        let permit_success = idms_prox_write
            .check_oauth2_authorise_permit(&ident, &consent_token, ct)
            .expect("Failed to perform OAuth2 permit");

        let token_req: AccessTokenRequest = GrantTypeReq::AuthorizationCode {
            code: permit_success.code,
            redirect_uri: Url::parse("https://demo.example.com/oauth2/result").unwrap(),
            code_verifier: Some(pkce_secret.to_verifier()),
        }
        .into();

        let oauth2_token = idms_prox_write
            .check_oauth2_token_exchange(&client_authz, &token_req, ct)
            .expect("Unable to exchange for OAuth2 token");

        let access_token =
            JwsCompact::from_str(&oauth2_token.access_token).expect("Invalid Access Token");

        let jws_verifier = JwsDangerReleaseWithoutVerify::default();

        let reflected_token = jws_verifier
            .verify(&access_token)
            .unwrap()
            .from_json::<OAuth2RFC9068Token<OAuth2RFC9068TokenExtensions>>()
            .expect("Failed to access internals of the refresh token");

        let session_id = reflected_token.extensions.session_id;

        assert!(idms_prox_write.commit().is_ok());

        // Process it to ensure the record exists.
        let mut idms_prox_write = idms.proxy_write(ct).await.unwrap();

        // Check it is now there
        let entry = idms_prox_write
            .qs_write
            .internal_search_uuid(UUID_TESTPERSON_1)
            .expect("failed");
        let valid = entry
            .get_ava_as_oauth2session_map(Attribute::OAuth2Session)
            .map(|map| map.get(&session_id).is_some())
            .unwrap_or(false);
        assert!(valid);

        // Delete the resource server.

        let de = DeleteEvent::new_internal_invalid(filter!(f_eq(
            Attribute::Name,
            PartialValue::new_iname("test_resource_server")
        )));

        assert!(idms_prox_write.qs_write.delete(&de).is_ok());

        // Assert the session is revoked. This is cleaned up as an artifact of the referential
        // integrity plugin. Remember, refint doesn't consider revoked sessions once they are
        // revoked.
        let entry = idms_prox_write
            .qs_write
            .internal_search_uuid(UUID_TESTPERSON_1)
            .expect("failed");
        let revoked = entry
            .get_ava_as_oauth2session_map(Attribute::OAuth2Session)
            .and_then(|sessions| sessions.get(&session_id))
            .map(|session| matches!(session.state, SessionState::RevokedAt(_)))
            .unwrap_or(false);
        assert!(revoked);

        assert!(idms_prox_write.commit().is_ok());
    }

    #[idm_test]
    async fn test_idm_oauth2_authorisation_reject(
        idms: &IdmServer,
        _idms_delayed: &mut IdmServerDelayed,
    ) {
        let ct = Duration::from_secs(TEST_CURRENT_TIME);
        let (_secret, _uat, ident, _) =
            setup_oauth2_resource_server_basic(idms, ct, true, false, false).await;

        let ident2 = {
            let mut idms_prox_write = idms.proxy_write(ct).await.unwrap();
            let account = idms_prox_write
                .target_to_account(UUID_IDM_ADMIN)
                .expect("account must exist");
            let session_id = uuid::Uuid::new_v4();
            let uat2 = account
                .to_userauthtoken(
                    session_id,
                    SessionScope::ReadWrite,
                    ct,
                    &ResolvedAccountPolicy::test_policy(),
                )
                .expect("Unable to create uat");

            idms_prox_write
                .process_uat_to_identity(&uat2, ct, Source::Internal)
                .expect("Unable to process uat")
        };

        let idms_prox_read = idms.proxy_read().await.unwrap();
        let redirect_uri = Url::parse("https://demo.example.com/oauth2/result").unwrap();

        let pkce_secret = PkceS256Secret::default();

        // Check reject behaviour
        let consent_request = good_authorisation_request!(
            idms_prox_read,
            &ident,
            ct,
            pkce_secret.to_request(),
            OAUTH2_SCOPE_OPENID.to_string()
        );

        let AuthoriseResponse::ConsentRequested { consent_token, .. } = consent_request else {
            unreachable!();
        };

        let reject_success = idms_prox_read
            .check_oauth2_authorise_reject(&ident, &consent_token, ct)
            .expect("Failed to perform OAuth2 reject");

        assert_eq!(reject_success.redirect_uri, redirect_uri);

        // Too much time past to reject
        let past_ct = Duration::from_secs(TEST_CURRENT_TIME + 301);
        assert!(
            idms_prox_read
                .check_oauth2_authorise_reject(&ident, &consent_token, past_ct)
                .unwrap_err()
                == OperationError::CryptographyError
        );

        // Invalid consent token
        assert_eq!(
            idms_prox_read
                .check_oauth2_authorise_reject(&ident, "not a token", ct)
                .unwrap_err(),
            OperationError::CryptographyError
        );

        // Wrong ident
        assert!(
            idms_prox_read
                .check_oauth2_authorise_reject(&ident2, &consent_token, ct)
                .unwrap_err()
                == OperationError::InvalidSessionState
        );
    }

    #[idm_test]
    async fn test_idm_oauth2_rfc8414_metadata(
        idms: &IdmServer,
        _idms_delayed: &mut IdmServerDelayed,
    ) {
        let ct = Duration::from_secs(TEST_CURRENT_TIME);
        let (_secret, _uat, _ident, _) =
            setup_oauth2_resource_server_basic(idms, ct, true, false, false).await;

        let idms_prox_read = idms.proxy_read().await.unwrap();

        // check the discovery end point works as we expect
        assert!(
            idms_prox_read
                .oauth2_rfc8414_metadata("nosuchclient")
                .unwrap_err()
                == OperationError::NoMatchingEntries
        );

        let discovery = idms_prox_read
            .oauth2_rfc8414_metadata("test_resource_server")
            .expect("Failed to get discovery");

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
            discovery.token_endpoint
                == Url::parse(&format!(
                    "https://idm.example.com{}",
                    uri::OAUTH2_TOKEN_ENDPOINT
                ))
                .unwrap()
        );

        assert!(
            discovery.jwks_uri
                == Some(
                    Url::parse(
                        "https://idm.example.com/oauth2/openid/test_resource_server/public_key.jwk"
                    )
                    .unwrap()
                )
        );

        assert!(discovery.registration_endpoint.is_none());

        assert!(
            discovery.scopes_supported
                == Some(vec![
                    OAUTH2_SCOPE_GROUPS.to_string(),
                    OAUTH2_SCOPE_OPENID.to_string(),
                    OAUTH2_SCOPE_PROFILE.to_string(),
                    "supplement".to_string(),
                ])
        );

        assert_eq!(discovery.response_types_supported, vec![ResponseType::Code]);
        assert_eq!(
            discovery.response_modes_supported,
            vec![ResponseMode::Query, ResponseMode::Fragment]
        );
        assert_eq!(
            discovery.grant_types_supported,
            vec![GrantType::AuthorisationCode, GrantType::TokenExchange]
        );
        assert!(
            discovery.token_endpoint_auth_methods_supported
                == vec![
                    TokenEndpointAuthMethod::ClientSecretBasic,
                    TokenEndpointAuthMethod::ClientSecretPost
                ]
        );
        assert!(discovery.service_documentation.is_some());

        assert!(discovery.ui_locales_supported.is_none());
        assert!(discovery.op_policy_uri.is_none());
        assert!(discovery.op_tos_uri.is_none());

        assert!(
            discovery.revocation_endpoint
                == Some(
                    Url::parse(&format!(
                        "https://idm.example.com{OAUTH2_TOKEN_REVOKE_ENDPOINT}"
                    ))
                    .unwrap()
                )
        );
        assert!(
            discovery.revocation_endpoint_auth_methods_supported
                == vec![
                    TokenEndpointAuthMethod::ClientSecretBasic,
                    TokenEndpointAuthMethod::ClientSecretPost
                ]
        );

        assert!(
            discovery.introspection_endpoint
                == Some(
                    Url::parse(&format!(
                        "https://idm.example.com{}",
                        kanidm_proto::constants::uri::OAUTH2_TOKEN_INTROSPECT_ENDPOINT
                    ))
                    .unwrap()
                )
        );
        assert!(
            discovery.introspection_endpoint_auth_methods_supported
                == vec![
                    TokenEndpointAuthMethod::ClientSecretBasic,
                    TokenEndpointAuthMethod::ClientSecretPost
                ]
        );
        assert!(discovery
            .introspection_endpoint_auth_signing_alg_values_supported
            .is_none());

        assert_eq!(
            discovery.code_challenge_methods_supported,
            vec![PkceAlg::S256]
        )
    }

    #[idm_test]
    async fn test_idm_oauth2_openid_discovery(
        idms: &IdmServer,
        _idms_delayed: &mut IdmServerDelayed,
    ) {
        let ct = Duration::from_secs(TEST_CURRENT_TIME);
        let (_secret, _uat, _ident, _) =
            setup_oauth2_resource_server_basic(idms, ct, true, false, false).await;

        let idms_prox_read = idms.proxy_read().await.unwrap();

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
                assert_eq!(use_.unwrap(), JwkUse::Sig);
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

        assert!(
            discovery.scopes_supported
                == Some(vec![
                    OAUTH2_SCOPE_GROUPS.to_string(),
                    OAUTH2_SCOPE_OPENID.to_string(),
                    OAUTH2_SCOPE_PROFILE.to_string(),
                    "supplement".to_string(),
                ])
        );

        assert_eq!(discovery.response_types_supported, vec![ResponseType::Code]);
        assert_eq!(
            discovery.response_modes_supported,
            vec![ResponseMode::Query, ResponseMode::Fragment]
        );
        assert_eq!(
            discovery.grant_types_supported,
            vec![GrantType::AuthorisationCode, GrantType::TokenExchange]
        );
        assert_eq!(discovery.subject_types_supported, vec![SubjectType::Public]);
        assert_eq!(
            discovery.id_token_signing_alg_values_supported,
            vec![IdTokenSignAlg::ES256]
        );
        assert!(discovery.userinfo_signing_alg_values_supported.is_none());
        assert!(
            discovery.token_endpoint_auth_methods_supported
                == vec![
                    TokenEndpointAuthMethod::ClientSecretBasic,
                    TokenEndpointAuthMethod::ClientSecretPost
                ]
        );
        assert_eq!(
            discovery.display_values_supported,
            Some(vec![DisplayValue::Page])
        );
        assert_eq!(discovery.claim_types_supported, vec![ClaimType::Normal]);
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
        assert!(!discovery.request_parameter_supported);
        assert_eq!(
            discovery.code_challenge_methods_supported,
            vec![PkceAlg::S256]
        );

        // Extensions
        assert!(
            discovery.revocation_endpoint
                == Some(
                    Url::parse(&format!(
                        "https://idm.example.com{OAUTH2_TOKEN_REVOKE_ENDPOINT}"
                    ))
                    .unwrap()
                )
        );
        assert!(
            discovery.revocation_endpoint_auth_methods_supported
                == vec![
                    TokenEndpointAuthMethod::ClientSecretBasic,
                    TokenEndpointAuthMethod::ClientSecretPost
                ]
        );

        assert!(
            discovery.introspection_endpoint
                == Some(
                    Url::parse(&format!(
                        "https://idm.example.com{OAUTH2_TOKEN_INTROSPECT_ENDPOINT}"
                    ))
                    .unwrap()
                )
        );
        assert!(
            discovery.introspection_endpoint_auth_methods_supported
                == vec![
                    TokenEndpointAuthMethod::ClientSecretBasic,
                    TokenEndpointAuthMethod::ClientSecretPost
                ]
        );
        assert!(discovery
            .introspection_endpoint_auth_signing_alg_values_supported
            .is_none());
    }

    #[idm_test]
    async fn test_idm_oauth2_openid_extensions(
        idms: &IdmServer,
        _idms_delayed: &mut IdmServerDelayed,
    ) {
        let ct = Duration::from_secs(TEST_CURRENT_TIME);
        let (secret, _uat, ident, _) =
            setup_oauth2_resource_server_basic(idms, ct, true, false, false).await;
        let client_authz = ClientAuthInfo::encode_basic("test_resource_server", secret.as_str());

        let idms_prox_read = idms.proxy_read().await.unwrap();

        let pkce_secret = PkceS256Secret::default();

        let consent_request = good_authorisation_request!(
            idms_prox_read,
            &ident,
            ct,
            pkce_secret.to_request(),
            format!("{OAUTH2_SCOPE_OPENID} {OAUTH2_SCOPE_PROFILE}")
        );

        let AuthoriseResponse::ConsentRequested { consent_token, .. } = consent_request else {
            unreachable!();
        };

        // == Manually submit the consent token to the permit for the permit_success
        drop(idms_prox_read);
        let mut idms_prox_write = idms.proxy_write(ct).await.unwrap();

        let permit_success = idms_prox_write
            .check_oauth2_authorise_permit(&ident, &consent_token, ct)
            .expect("Failed to perform OAuth2 permit");

        // == Submit the token exchange code.
        let token_req: AccessTokenRequest = GrantTypeReq::AuthorizationCode {
            code: permit_success.code,
            redirect_uri: Url::parse("https://demo.example.com/oauth2/result").unwrap(),
            code_verifier: Some(pkce_secret.to_verifier()),
        }
        .into();

        let token_response = idms_prox_write
            .check_oauth2_token_exchange(&client_authz, &token_req, ct)
            .expect("Failed to perform OAuth2 token exchange");

        // 🎉 We got a token!
        assert_eq!(token_response.token_type, AccessTokenType::Bearer);

        let id_token = token_response.id_token.expect("No id_token in response!");

        let access_token =
            JwsCompact::from_str(&token_response.access_token).expect("Invalid Access Token");

        let refresh_token = token_response
            .refresh_token
            .as_ref()
            .expect("no refresh token was issued")
            .clone();

        // Get the read txn for inspecting the tokens
        assert!(idms_prox_write.commit().is_ok());

        let mut idms_prox_read = idms.proxy_read().await.unwrap();

        let mut jwkset = idms_prox_read
            .oauth2_openid_publickey("test_resource_server")
            .expect("Failed to get public key");

        let public_jwk = jwkset.keys.pop().expect("no such jwk");

        let jws_validator =
            JwsEs256Verifier::try_from(&public_jwk).expect("failed to build validator");

        let oidc_unverified =
            OidcUnverified::from_str(&id_token).expect("Failed to parse id_token");

        let iat = ct.as_secs() as i64;

        let oidc = jws_validator
            .verify(&oidc_unverified)
            .unwrap()
            .verify_exp(iat)
            .expect("Failed to verify oidc");

        // Are the id_token values what we expect?
        assert!(
            oidc.iss
                == Url::parse("https://idm.example.com/oauth2/openid/test_resource_server")
                    .unwrap()
        );
        assert_eq!(oidc.sub, OidcSubject::U(UUID_TESTPERSON_1));
        assert_eq!(oidc.aud, "test_resource_server");
        assert_eq!(oidc.iat, iat);
        assert_eq!(oidc.nbf, Some(iat));
        // Previously this was the auth session but it's now inline with the access token expiry.
        assert_eq!(oidc.exp, iat + (OAUTH2_ACCESS_TOKEN_EXPIRY as i64));
        assert!(oidc.auth_time.is_none());
        // Is nonce correctly passed through?
        assert_eq!(oidc.nonce, Some("abcdef".to_string()));
        assert!(oidc.at_hash.is_none());
        assert!(oidc.acr.is_none());
        assert!(oidc.amr.is_none());
        assert_eq!(oidc.azp, Some("test_resource_server".to_string()));
        assert!(oidc.jti.is_some());
        if let Some(jti) = &oidc.jti {
            assert!(Uuid::from_str(jti).is_ok());
        }
        assert_eq!(oidc.s_claims.name, Some("Test Person 1".to_string()));
        assert_eq!(
            oidc.s_claims.preferred_username,
            Some("testperson1@example.com".to_string())
        );
        assert!(
            oidc.s_claims.scopes
                == vec![
                    OAUTH2_SCOPE_OPENID.to_string(),
                    OAUTH2_SCOPE_PROFILE.to_string(),
                    "supplement".to_string()
                ]
        );
        assert!(oidc.claims.is_empty());
        // Does our access token work with the userinfo endpoint?
        // Do the id_token details line up to the userinfo?
        let userinfo = idms_prox_read
            .oauth2_openid_userinfo("test_resource_server", &access_token, ct)
            .expect("failed to get userinfo");

        assert_eq!(oidc.iss, userinfo.iss);
        assert_eq!(oidc.sub, userinfo.sub);
        assert_eq!(oidc.aud, userinfo.aud);
        assert_eq!(oidc.iat, userinfo.iat);
        assert_eq!(oidc.nbf, userinfo.nbf);
        assert_eq!(oidc.exp, userinfo.exp);
        assert!(userinfo.auth_time.is_none());
        assert_eq!(userinfo.nonce, Some("abcdef".to_string()));
        assert!(userinfo.at_hash.is_none());
        assert!(userinfo.acr.is_none());
        assert_eq!(oidc.amr, userinfo.amr);
        assert_eq!(oidc.azp, userinfo.azp);
        assert!(userinfo.jti.is_some());
        if let Some(jti) = &userinfo.jti {
            assert!(Uuid::from_str(jti).is_ok());
        }
        assert_eq!(oidc.s_claims, userinfo.s_claims);
        assert!(userinfo.claims.is_empty());

        drop(idms_prox_read);

        // Importantly, we need to persist the nonce through access/refresh token operations
        // because some clients like the rust openidconnect library require it always for claim
        // verification.
        let mut idms_prox_write = idms.proxy_write(ct).await.unwrap();

        let token_req: AccessTokenRequest = GrantTypeReq::RefreshToken {
            refresh_token,
            scope: None,
        }
        .into();

        let token_response = idms_prox_write
            .check_oauth2_token_exchange(&client_authz, &token_req, ct)
            .expect("Unable to exchange for OAuth2 token");

        let access_token =
            JwsCompact::from_str(&token_response.access_token).expect("Invalid Access Token");

        assert!(idms_prox_write.commit().is_ok());

        // Okay, refresh done, lets check it.
        let mut idms_prox_read = idms.proxy_read().await.unwrap();

        let userinfo = idms_prox_read
            .oauth2_openid_userinfo("test_resource_server", &access_token, ct)
            .expect("failed to get userinfo");

        assert_eq!(oidc.iss, userinfo.iss);
        assert_eq!(oidc.sub, userinfo.sub);
        assert_eq!(oidc.aud, userinfo.aud);
        assert_eq!(oidc.iat, userinfo.iat);
        assert_eq!(oidc.nbf, userinfo.nbf);
        assert_eq!(oidc.exp, userinfo.exp);
        assert!(userinfo.auth_time.is_none());
        assert_eq!(userinfo.nonce, Some("abcdef".to_string()));
        assert!(userinfo.at_hash.is_none());
        assert!(userinfo.acr.is_none());
        assert_eq!(oidc.amr, userinfo.amr);
        assert_eq!(oidc.azp, userinfo.azp);
        assert!(userinfo.jti.is_some());
        if let Some(jti) = &userinfo.jti {
            assert!(Uuid::from_str(jti).is_ok());
        }
        assert_eq!(oidc.s_claims, userinfo.s_claims);
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
        let (secret, _uat, ident, _) =
            setup_oauth2_resource_server_basic(idms, ct, true, false, true).await;
        let client_authz = ClientAuthInfo::encode_basic("test_resource_server", secret.as_str());

        let idms_prox_read = idms.proxy_read().await.unwrap();

        let pkce_secret = PkceS256Secret::default();

        let consent_request = good_authorisation_request!(
            idms_prox_read,
            &ident,
            ct,
            pkce_secret.to_request(),
            OAUTH2_SCOPE_OPENID.to_string()
        );

        let AuthoriseResponse::ConsentRequested { consent_token, .. } = consent_request else {
            unreachable!();
        };

        // == Manually submit the consent token to the permit for the permit_success
        drop(idms_prox_read);
        let mut idms_prox_write = idms.proxy_write(ct).await.unwrap();

        let permit_success = idms_prox_write
            .check_oauth2_authorise_permit(&ident, &consent_token, ct)
            .expect("Failed to perform OAuth2 permit");

        // == Submit the token exchange code.
        let token_req: AccessTokenRequest = GrantTypeReq::AuthorizationCode {
            code: permit_success.code,
            redirect_uri: Url::parse("https://demo.example.com/oauth2/result").unwrap(),
            code_verifier: Some(pkce_secret.to_verifier()),
        }
        .into();

        let token_response = idms_prox_write
            .check_oauth2_token_exchange(&client_authz, &token_req, ct)
            .expect("Failed to perform OAuth2 token exchange");

        let id_token = token_response.id_token.expect("No id_token in response!");
        let access_token =
            JwsCompact::from_str(&token_response.access_token).expect("Invalid Access Token");

        assert!(idms_prox_write.commit().is_ok());
        let mut idms_prox_read = idms.proxy_read().await.unwrap();

        let mut jwkset = idms_prox_read
            .oauth2_openid_publickey("test_resource_server")
            .expect("Failed to get public key");
        let public_jwk = jwkset.keys.pop().expect("no such jwk");

        let jws_validator =
            JwsEs256Verifier::try_from(&public_jwk).expect("failed to build validator");

        let oidc_unverified =
            OidcUnverified::from_str(&id_token).expect("Failed to parse id_token");

        let iat = ct.as_secs() as i64;

        let oidc = jws_validator
            .verify(&oidc_unverified)
            .unwrap()
            .verify_exp(iat)
            .expect("Failed to verify oidc");

        // Do we have the short username in the token claims?
        assert_eq!(
            oidc.s_claims.preferred_username,
            Some("testperson1".to_string())
        );
        // Do the id_token details line up to the userinfo?
        let userinfo = idms_prox_read
            .oauth2_openid_userinfo("test_resource_server", &access_token, ct)
            .expect("failed to get userinfo");

        assert_eq!(oidc.s_claims, userinfo.s_claims);
    }

    #[idm_test]
    async fn test_idm_oauth2_openid_group_claims(
        idms: &IdmServer,
        _idms_delayed: &mut IdmServerDelayed,
    ) {
        // we run the same test as test_idm_oauth2_openid_extensions()
        // but change the preferred_username setting on the RS
        let ct = Duration::from_secs(TEST_CURRENT_TIME);
        let (secret, _uat, ident, _) =
            setup_oauth2_resource_server_basic(idms, ct, true, false, true).await;

        let client_authz = ClientAuthInfo::encode_basic("test_resource_server", secret.as_str());

        let token_response = perform_oauth2_exchange(
            idms,
            &ident,
            ct,
            client_authz,
            format!("{OAUTH2_SCOPE_OPENID} {OAUTH2_SCOPE_GROUPS}"),
        )
        .await;

        let id_token = token_response.id_token.expect("No id_token in response!");
        let access_token =
            JwsCompact::from_str(&token_response.access_token).expect("Invalid Access Token");

        let oidc = validate_id_token(idms, ct, &id_token).await;

        // does our id_token contain the expected groups?
        assert!(oidc.claims.contains_key("groups"));

        assert!(oidc
            .claims
            .get("groups")
            .expect("unable to find key")
            .as_array()
            .unwrap()
            .contains(&serde_json::json!(STR_UUID_IDM_ALL_ACCOUNTS)));

        let mut idms_prox_read = idms.proxy_read().await.unwrap();

        // Do the id_token details line up to the userinfo?
        let userinfo = idms_prox_read
            .oauth2_openid_userinfo("test_resource_server", &access_token, ct)
            .expect("failed to get userinfo");

        // does the userinfo endpoint provide the same groups?
        assert_eq!(oidc.claims.get("groups"), userinfo.claims.get("groups"));
    }

    #[idm_test]
    async fn test_idm_oauth2_openid_group_extended_claims(
        idms: &IdmServer,
        _idms_delayed: &mut IdmServerDelayed,
    ) {
        // we run the same test as test_idm_oauth2_openid_extensions()
        // but change the preferred_username setting on the RS
        let ct = Duration::from_secs(TEST_CURRENT_TIME);
        let (secret, _uat, ident, oauth2_client_uuid) =
            setup_oauth2_resource_server_basic(idms, ct, true, false, true).await;

        // Modify the oauth2 client to have different scope maps.
        let mut idms_prox_write = idms.proxy_write(ct).await.unwrap();

        let modlist = ModifyList::new_list(vec![
            Modify::Removed(
                Attribute::OAuth2RsScopeMap,
                PartialValue::Refer(UUID_TESTGROUP),
            ),
            Modify::Present(
                Attribute::OAuth2RsScopeMap,
                Value::new_oauthscopemap(
                    UUID_TESTGROUP,
                    btreeset![OAUTH2_SCOPE_GROUPS_NAME.to_string()],
                )
                .expect("invalid oauthscope"),
            ),
        ]);

        idms_prox_write
            .qs_write
            .internal_modify_uuid(oauth2_client_uuid, &modlist)
            .expect("Failed to modify scopes");

        idms_prox_write.commit().expect("failed to commit");

        // Now actually do the test.
        let client_authz = ClientAuthInfo::encode_basic("test_resource_server", secret.as_str());

        let token_response = perform_oauth2_exchange(
            idms,
            &ident,
            ct,
            client_authz,
            format!("{OAUTH2_SCOPE_OPENID} {OAUTH2_SCOPE_GROUPS_NAME}"),
        )
        .await;

        let id_token = token_response.id_token.expect("No id_token in response!");
        let access_token =
            JwsCompact::from_str(&token_response.access_token).expect("Invalid Access Token");

        let oidc = validate_id_token(idms, ct, &id_token).await;

        // does our id_token contain the expected groups?
        assert!(oidc.claims.contains_key("groups"));

        assert!(oidc
            .claims
            .get("groups")
            .expect("unable to find key")
            .as_array()
            .unwrap()
            .contains(&serde_json::json!("testgroup")));

        let mut idms_prox_read = idms.proxy_read().await.unwrap();

        // Do the id_token details line up to the userinfo?
        let userinfo = idms_prox_read
            .oauth2_openid_userinfo("test_resource_server", &access_token, ct)
            .expect("failed to get userinfo");

        // does the userinfo endpoint provide the same groups?
        assert_eq!(oidc.claims.get("groups"), userinfo.claims.get("groups"));
    }

    #[idm_test]
    async fn test_idm_oauth2_openid_ssh_publickey_claim(
        idms: &IdmServer,
        _idms_delayed: &mut IdmServerDelayed,
    ) {
        let ct = Duration::from_secs(TEST_CURRENT_TIME);
        let (secret, _uat, ident, client_uuid) =
            setup_oauth2_resource_server_basic(idms, ct, true, false, true).await;

        // Extra setup for our test - add the correct claim and give an ssh publickey
        // to our testperson
        const ECDSA_SSH_PUBLIC_KEY: &str = "ecdsa-sha2-nistp521 AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAAAIbmlzdHA1MjEAAACFBAGyIY7o3BtOzRiJ9vvjj96bRImwmyy5GvFSIUPlK00HitiAWGhiO1jGZKmK7220Oe4rqU3uAwA00a0758UODs+0OQHLMDRtl81lzPrVSdrYEDldxH9+a86dBZhdm0e15+ODDts2LHUknsJCRRldO4o9R9VrohlF7cbyBlnhJQrR4S+Oag== william@amethyst";
        let ssh_pubkey = SshPublicKey::from_string(ECDSA_SSH_PUBLIC_KEY).unwrap();

        let scope_set = BTreeSet::from([OAUTH2_SCOPE_SSH_PUBLICKEYS.to_string()]);

        let mut idms_prox_write = idms.proxy_write(ct).await.unwrap();

        idms_prox_write
            .qs_write
            .internal_batch_modify(
                [
                    (
                        UUID_TESTPERSON_1,
                        ModifyList::new_set(
                            Attribute::SshPublicKey,
                            ValueSetSshKey::new("label".to_string(), ssh_pubkey),
                        ),
                    ),
                    (
                        client_uuid,
                        ModifyList::new_set(
                            Attribute::OAuth2RsSupScopeMap,
                            ValueSetOauthScopeMap::new(UUID_IDM_ALL_ACCOUNTS, scope_set),
                        ),
                    ),
                ]
                .into_iter(),
            )
            .expect("Failed to modify test entries");

        assert!(idms_prox_write.commit().is_ok());

        let client_authz = ClientAuthInfo::encode_basic("test_resource_server", secret.as_str());

        let idms_prox_read = idms.proxy_read().await.unwrap();

        let pkce_secret = PkceS256Secret::default();

        let consent_request = good_authorisation_request!(
            idms_prox_read,
            &ident,
            ct,
            pkce_secret.to_request(),
            "openid groups".to_string()
        );

        let AuthoriseResponse::ConsentRequested { consent_token, .. } = consent_request else {
            unreachable!();
        };

        // == Manually submit the consent token to the permit for the permit_success
        drop(idms_prox_read);
        let mut idms_prox_write = idms.proxy_write(ct).await.unwrap();

        let permit_success = idms_prox_write
            .check_oauth2_authorise_permit(&ident, &consent_token, ct)
            .expect("Failed to perform OAuth2 permit");

        // == Submit the token exchange code.
        let token_req: AccessTokenRequest = GrantTypeReq::AuthorizationCode {
            code: permit_success.code,
            redirect_uri: Url::parse("https://demo.example.com/oauth2/result").unwrap(),
            code_verifier: Some(pkce_secret.to_verifier()),
        }
        .into();

        let token_response = idms_prox_write
            .check_oauth2_token_exchange(&client_authz, &token_req, ct)
            .expect("Failed to perform OAuth2 token exchange");

        let id_token = token_response.id_token.expect("No id_token in response!");
        let access_token =
            JwsCompact::from_str(&token_response.access_token).expect("Invalid Access Token");

        assert!(idms_prox_write.commit().is_ok());
        let mut idms_prox_read = idms.proxy_read().await.unwrap();

        let mut jwkset = idms_prox_read
            .oauth2_openid_publickey("test_resource_server")
            .expect("Failed to get public key");
        let public_jwk = jwkset.keys.pop().expect("no such jwk");

        let jws_validator =
            JwsEs256Verifier::try_from(&public_jwk).expect("failed to build validator");

        let oidc_unverified =
            OidcUnverified::from_str(&id_token).expect("Failed to parse id_token");

        let iat = ct.as_secs() as i64;

        let oidc = jws_validator
            .verify(&oidc_unverified)
            .unwrap()
            .verify_exp(iat)
            .expect("Failed to verify oidc");

        // does our id_token contain the expected groups?
        assert!(oidc.claims.contains_key(OAUTH2_SCOPE_SSH_PUBLICKEYS));

        assert!(oidc
            .claims
            .get(OAUTH2_SCOPE_SSH_PUBLICKEYS)
            .expect("unable to find key")
            .as_array()
            .unwrap()
            .contains(&serde_json::json!(ECDSA_SSH_PUBLIC_KEY)));

        // Do the id_token details line up to the userinfo?
        let userinfo = idms_prox_read
            .oauth2_openid_userinfo("test_resource_server", &access_token, ct)
            .expect("failed to get userinfo");

        // does the userinfo endpoint provide the same groups?
        assert_eq!(
            oidc.claims.get(OAUTH2_SCOPE_SSH_PUBLICKEYS),
            userinfo.claims.get(OAUTH2_SCOPE_SSH_PUBLICKEYS)
        );
    }

    //  Check insecure pkce behaviour.
    #[idm_test]
    async fn test_idm_oauth2_insecure_pkce(idms: &IdmServer, _idms_delayed: &mut IdmServerDelayed) {
        let ct = Duration::from_secs(TEST_CURRENT_TIME);
        let (_secret, _uat, ident, _) =
            setup_oauth2_resource_server_basic(idms, ct, false, false, false).await;

        let idms_prox_read = idms.proxy_read().await.unwrap();

        // == Setup the authorisation request
        let pkce_secret = PkceS256Secret::default();

        // Even in disable pkce mode, we will allow pkce
        let _consent_request = good_authorisation_request!(
            idms_prox_read,
            &ident,
            ct,
            pkce_secret.to_request(),
            OAUTH2_SCOPE_OPENID.to_string()
        );

        // Check we allow none.
        let auth_req = AuthorisationRequest {
            response_type: ResponseType::Code,
            response_mode: None,
            client_id: "test_resource_server".to_string(),
            state: Some("123".to_string()),
            pkce_request: None,
            redirect_uri: Url::parse("https://demo.example.com/oauth2/result").unwrap(),
            scope: btreeset![OAUTH2_SCOPE_GROUPS.to_string()],
            nonce: Some("abcdef".to_string()),
            oidc_ext: Default::default(),
            max_age: None,
            unknown_keys: Default::default(),
        };

        idms_prox_read
            .check_oauth2_authorisation(Some(&ident), &auth_req, ct)
            .expect("Oauth2 authorisation failed");
    }

    #[idm_test]
    async fn test_idm_oauth2_webfinger(idms: &IdmServer, _idms_delayed: &mut IdmServerDelayed) {
        let ct = Duration::from_secs(TEST_CURRENT_TIME);
        let (_secret, _uat, _ident, _) =
            setup_oauth2_resource_server_basic(idms, ct, true, false, true).await;
        let mut idms_prox_read = idms.proxy_read().await.unwrap();

        let user = "testperson1@example.com";

        let webfinger = idms_prox_read
            .oauth2_openid_webfinger("test_resource_server", user)
            .expect("Failed to get webfinger");

        assert_eq!(webfinger.subject, user);
        assert_eq!(webfinger.links.len(), 1);

        let link = &webfinger.links[0];
        assert_eq!(link.rel, "http://openid.net/specs/connect/1.0/issuer");
        assert_eq!(
            link.href,
            "https://idm.example.com/oauth2/openid/test_resource_server"
        );

        let failed_webfinger = idms_prox_read
            .oauth2_openid_webfinger("test_resource_server", "someone@another.domain");
        assert!(failed_webfinger.is_err());
    }

    #[idm_test]
    async fn test_idm_oauth2_openid_legacy_crypto(
        idms: &IdmServer,
        _idms_delayed: &mut IdmServerDelayed,
    ) {
        let ct = Duration::from_secs(TEST_CURRENT_TIME);
        let (secret, _uat, ident, _) =
            setup_oauth2_resource_server_basic(idms, ct, false, true, false).await;
        let idms_prox_read = idms.proxy_read().await.unwrap();
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
                assert_eq!(use_.unwrap(), JwkUse::Sig);
                assert!(kid.is_some());
            }
            _ => panic!(),
        };

        // Check that the id_token is signed with the correct key.
        let pkce_secret = PkceS256Secret::default();

        let consent_request = good_authorisation_request!(
            idms_prox_read,
            &ident,
            ct,
            pkce_secret.to_request(),
            OAUTH2_SCOPE_OPENID.to_string()
        );

        let AuthoriseResponse::ConsentRequested { consent_token, .. } = consent_request else {
            unreachable!();
        };

        // == Manually submit the consent token to the permit for the permit_success
        drop(idms_prox_read);
        let mut idms_prox_write = idms.proxy_write(ct).await.unwrap();

        let permit_success = idms_prox_write
            .check_oauth2_authorise_permit(&ident, &consent_token, ct)
            .expect("Failed to perform OAuth2 permit");

        // == Submit the token exchange code.
        let token_req = AccessTokenRequest {
            grant_type: GrantTypeReq::AuthorizationCode {
                code: permit_success.code,
                redirect_uri: Url::parse("https://demo.example.com/oauth2/result").unwrap(),
                code_verifier: Some(pkce_secret.to_verifier()),
            },

            client_post_auth: ClientPostAuth {
                client_id: Some("test_resource_server".to_string()),
                client_secret: Some(secret),
            },
        };

        let token_response = idms_prox_write
            .check_oauth2_token_exchange(&ClientAuthInfo::none(), &token_req, ct)
            .expect("Failed to perform OAuth2 token exchange");

        // 🎉 We got a token!
        assert_eq!(token_response.token_type, AccessTokenType::Bearer);
        let id_token = token_response.id_token.expect("No id_token in response!");

        let jws_validator =
            JwsRs256Verifier::try_from(&public_jwk).expect("failed to build validator");

        let oidc_unverified =
            OidcUnverified::from_str(&id_token).expect("Failed to parse id_token");

        let iat = ct.as_secs() as i64;

        let oidc = jws_validator
            .verify(&oidc_unverified)
            .unwrap()
            .verify_exp(iat)
            .expect("Failed to verify oidc");

        assert_eq!(oidc.sub, OidcSubject::U(UUID_TESTPERSON_1));

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

        let idms_prox_read = idms.proxy_read().await.unwrap();

        let pkce_secret = PkceS256Secret::default();

        let consent_request = good_authorisation_request!(
            idms_prox_read,
            &ident,
            ct,
            pkce_secret.to_request(),
            OAUTH2_SCOPE_OPENID.to_string()
        );

        // Should be in the consent phase;
        let AuthoriseResponse::ConsentRequested { consent_token, .. } = consent_request else {
            unreachable!();
        };

        // == Manually submit the consent token to the permit for the permit_success
        drop(idms_prox_read);
        let mut idms_prox_write = idms.proxy_write(ct).await.unwrap();

        let _permit_success = idms_prox_write
            .check_oauth2_authorise_permit(&ident, &consent_token, ct)
            .expect("Failed to perform OAuth2 permit");

        assert!(idms_prox_write.commit().is_ok());

        // == Now try the authorise again, should be in the permitted state.
        let mut idms_prox_read = idms.proxy_read().await.unwrap();

        // We need to reload our identity
        let ident = idms_prox_read
            .process_uat_to_identity(&uat, ct, Source::Internal)
            .expect("Unable to process uat");

        let pkce_secret = PkceS256Secret::default();

        let consent_request = good_authorisation_request!(
            idms_prox_read,
            &ident,
            ct,
            pkce_secret.to_request(),
            OAUTH2_SCOPE_OPENID.to_string()
        );

        // Should be in the consent phase;
        let AuthoriseResponse::Permitted(_permit_success) = consent_request else {
            unreachable!();
        };

        drop(idms_prox_read);

        // Great! Now change the scopes on the OAuth2 instance, this revokes the permit.
        let mut idms_prox_write = idms.proxy_write(ct).await.unwrap();

        let me_extend_scopes = ModifyEvent::new_internal_invalid(
            filter!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("test_resource_server")
            )),
            ModifyList::new_list(vec![Modify::Present(
                Attribute::OAuth2RsScopeMap,
                Value::new_oauthscopemap(
                    UUID_IDM_ALL_ACCOUNTS,
                    btreeset![
                        OAUTH2_SCOPE_EMAIL.to_string(),
                        OAUTH2_SCOPE_PROFILE.to_string(),
                        OAUTH2_SCOPE_OPENID.to_string()
                    ],
                )
                .expect("invalid oauthscope"),
            )]),
        );

        assert!(idms_prox_write.qs_write.modify(&me_extend_scopes).is_ok());
        assert!(idms_prox_write.commit().is_ok());

        // And do the workflow once more to see if we need to consent again.

        let mut idms_prox_read = idms.proxy_read().await.unwrap();

        // We need to reload our identity
        let ident = idms_prox_read
            .process_uat_to_identity(&uat, ct, Source::Internal)
            .expect("Unable to process uat");

        let pkce_secret = PkceS256Secret::default();

        let auth_req = AuthorisationRequest {
            response_type: ResponseType::Code,
            response_mode: None,
            client_id: "test_resource_server".to_string(),
            state: Some("123".to_string()),
            pkce_request: Some(pkce_secret.to_request()),
            redirect_uri: Url::parse("https://demo.example.com/oauth2/result").unwrap(),
            scope: btreeset![
                "openid".to_string(),
                "email".to_string(),
                "profile".to_string()
            ],
            nonce: Some("abcdef".to_string()),
            oidc_ext: Default::default(),
            max_age: None,
            unknown_keys: Default::default(),
        };

        let consent_request = idms_prox_read
            .check_oauth2_authorisation(Some(&ident), &auth_req, ct)
            .expect("Oauth2 authorisation failed");

        // Should be in the consent phase;
        let AuthoriseResponse::ConsentRequested { .. } = consent_request else {
            unreachable!();
        };

        drop(idms_prox_read);

        // Success! We had to consent again due to the change :)

        // Now change the supplemental scopes on the OAuth2 instance, this revokes the permit.
        let mut idms_prox_write = idms.proxy_write(ct).await.unwrap();

        let me_extend_scopes = ModifyEvent::new_internal_invalid(
            filter!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("test_resource_server")
            )),
            ModifyList::new_list(vec![Modify::Present(
                Attribute::OAuth2RsSupScopeMap,
                Value::new_oauthscopemap(UUID_IDM_ALL_ACCOUNTS, btreeset!["newscope".to_string()])
                    .expect("invalid oauthscope"),
            )]),
        );

        assert!(idms_prox_write.qs_write.modify(&me_extend_scopes).is_ok());
        assert!(idms_prox_write.commit().is_ok());

        // And do the workflow once more to see if we need to consent again.

        let mut idms_prox_read = idms.proxy_read().await.unwrap();

        // We need to reload our identity
        let ident = idms_prox_read
            .process_uat_to_identity(&uat, ct, Source::Internal)
            .expect("Unable to process uat");

        let pkce_secret = PkceS256Secret::default();

        let auth_req = AuthorisationRequest {
            response_type: ResponseType::Code,
            response_mode: None,
            client_id: "test_resource_server".to_string(),
            state: Some("123".to_string()),
            pkce_request: Some(pkce_secret.to_request()),
            redirect_uri: Url::parse("https://demo.example.com/oauth2/result").unwrap(),
            // Note the scope isn't requested here!
            scope: btreeset![
                "openid".to_string(),
                "email".to_string(),
                "profile".to_string()
            ],
            nonce: Some("abcdef".to_string()),
            oidc_ext: Default::default(),
            max_age: None,
            unknown_keys: Default::default(),
        };

        let consent_request = idms_prox_read
            .check_oauth2_authorisation(Some(&ident), &auth_req, ct)
            .expect("Oauth2 authorisation failed");

        // Should be present in the consent phase however!
        let _consent_token = if let AuthoriseResponse::ConsentRequested {
            consent_token,
            scopes,
            ..
        } = consent_request
        {
            assert!(scopes.contains("newscope"));
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

        let idms_prox_read = idms.proxy_read().await.unwrap();

        let pkce_secret = PkceS256Secret::default();
        let consent_request = good_authorisation_request!(
            idms_prox_read,
            &ident,
            ct,
            pkce_secret.to_request(),
            OAUTH2_SCOPE_OPENID.to_string()
        );

        // Should be in the consent phase;
        let AuthoriseResponse::ConsentRequested { consent_token, .. } = consent_request else {
            unreachable!();
        };

        // == Manually submit the consent token to the permit for the permit_success
        drop(idms_prox_read);
        let mut idms_prox_write = idms.proxy_write(ct).await.unwrap();

        let _permit_success = idms_prox_write
            .check_oauth2_authorise_permit(&ident, &consent_token, ct)
            .expect("Failed to perform OAuth2 permit");

        let ident = idms_prox_write
            .process_uat_to_identity(&uat, ct, Source::Internal)
            .expect("Unable to process uat");

        // Assert that the ident now has the consents.
        assert!(
            ident.get_oauth2_consent_scopes(o2rs_uuid)
                == Some(&btreeset![
                    OAUTH2_SCOPE_OPENID.to_string(),
                    "supplement".to_string()
                ])
        );

        // Now trigger the delete of the RS
        let de = DeleteEvent::new_internal_invalid(filter!(f_eq(
            Attribute::Name,
            PartialValue::new_iname("test_resource_server")
        )));

        assert!(idms_prox_write.qs_write.delete(&de).is_ok());
        // Assert the consent maps are gone.
        let ident = idms_prox_write
            .process_uat_to_identity(&uat, ct, Source::Internal)
            .expect("Unable to process uat");
        dbg!(&o2rs_uuid);
        dbg!(&ident);
        let consent_scopes = ident.get_oauth2_consent_scopes(o2rs_uuid);
        dbg!(consent_scopes);
        assert!(consent_scopes.is_none());

        assert!(idms_prox_write.commit().is_ok());
    }

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
    #[idm_test]
    async fn test_idm_oauth2_1076_pkce_downgrade(
        idms: &IdmServer,
        _idms_delayed: &mut IdmServerDelayed,
    ) {
        let ct = Duration::from_secs(TEST_CURRENT_TIME);
        // Enable pkce is set to FALSE
        let (secret, _uat, ident, _) =
            setup_oauth2_resource_server_basic(idms, ct, false, false, false).await;

        let idms_prox_read = idms.proxy_read().await.unwrap();

        // Get an ident/uat for now.

        // == Setup the authorisation request
        // We attempt pkce even though the rs is set to not support pkce.
        let pkce_secret = PkceS256Secret::default();

        // First, the user does not request pkce in their exchange.
        let auth_req = AuthorisationRequest {
            response_type: ResponseType::Code,
            response_mode: None,
            client_id: "test_resource_server".to_string(),
            state: Some("123".to_string()),
            pkce_request: None,
            redirect_uri: Url::parse("https://demo.example.com/oauth2/result").unwrap(),
            scope: btreeset![OAUTH2_SCOPE_OPENID.to_string()],
            nonce: None,
            oidc_ext: Default::default(),
            max_age: None,
            unknown_keys: Default::default(),
        };

        let consent_request = idms_prox_read
            .check_oauth2_authorisation(Some(&ident), &auth_req, ct)
            .expect("Failed to perform OAuth2 authorisation request.");

        // Should be in the consent phase;
        let AuthoriseResponse::ConsentRequested { consent_token, .. } = consent_request else {
            unreachable!();
        };

        // == Manually submit the consent token to the permit for the permit_success
        drop(idms_prox_read);
        let mut idms_prox_write = idms.proxy_write(ct).await.unwrap();

        let permit_success = idms_prox_write
            .check_oauth2_authorise_permit(&ident, &consent_token, ct)
            .expect("Failed to perform OAuth2 permit");

        // == Submit the token exchange code.
        // This exchange failed because we submitted a verifier when the code exchange
        // has NO code challenge present.
        let token_req = AccessTokenRequest {
            grant_type: GrantTypeReq::AuthorizationCode {
                code: permit_success.code,
                redirect_uri: Url::parse("https://demo.example.com/oauth2/result").unwrap(),
                code_verifier: Some(pkce_secret.to_verifier()),
            },
            client_post_auth: ClientPostAuth {
                client_id: Some("test_resource_server".to_string()),
                client_secret: Some(secret),
            },
        };

        // Assert the exchange fails.
        assert!(matches!(
            idms_prox_write.check_oauth2_token_exchange(&ClientAuthInfo::none(), &token_req, ct),
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
        let (secret, _uat, ident, _) =
            setup_oauth2_resource_server_basic(idms, ct, false, false, false).await;

        let idms_prox_read = idms.proxy_read().await.unwrap();

        // Get an ident/uat for now.

        // == Setup the authorisation request
        // We attempt pkce even though the rs is set to not support pkce.
        let pkce_secret = PkceS256Secret::default();

        // First, NOTE the lack of https on the redir uri.
        let auth_req = AuthorisationRequest {
            response_type: ResponseType::Code,
            response_mode: None,
            client_id: "test_resource_server".to_string(),
            state: Some("123".to_string()),
            pkce_request: Some(pkce_secret.to_request()),
            redirect_uri: Url::parse("http://demo.example.com/oauth2/result").unwrap(),
            scope: btreeset![OAUTH2_SCOPE_OPENID.to_string()],
            nonce: None,
            oidc_ext: Default::default(),
            max_age: None,
            unknown_keys: Default::default(),
        };

        assert!(
            idms_prox_read
                .check_oauth2_authorisation(Some(&ident), &auth_req, ct)
                .unwrap_err()
                == Oauth2Error::InvalidOrigin
        );

        // This does have https
        let consent_request = good_authorisation_request!(
            idms_prox_read,
            &ident,
            ct,
            pkce_secret.to_request(),
            OAUTH2_SCOPE_OPENID.to_string()
        );

        // Should be in the consent phase;
        let AuthoriseResponse::ConsentRequested { consent_token, .. } = consent_request else {
            unreachable!();
        };

        // == Manually submit the consent token to the permit for the permit_success
        drop(idms_prox_read);
        let mut idms_prox_write = idms.proxy_write(ct).await.unwrap();

        let permit_success = idms_prox_write
            .check_oauth2_authorise_permit(&ident, &consent_token, ct)
            .expect("Failed to perform OAuth2 permit");

        // == Submit the token exchange code.
        // NOTE the url is http again
        let token_req = AccessTokenRequest {
            grant_type: GrantTypeReq::AuthorizationCode {
                code: permit_success.code,
                redirect_uri: Url::parse("http://demo.example.com/oauth2/result").unwrap(),
                code_verifier: Some(pkce_secret.to_verifier()),
            },

            client_post_auth: ClientPostAuth {
                client_id: Some("test_resource_server".to_string()),
                client_secret: Some(secret),
            },
        };

        // Assert the exchange fails.
        assert!(matches!(
            idms_prox_write.check_oauth2_token_exchange(&ClientAuthInfo::none(), &token_req, ct),
            Err(Oauth2Error::InvalidOrigin)
        ));

        assert!(idms_prox_write.commit().is_ok());
    }

    async fn setup_refresh_token(
        idms: &IdmServer,
        _idms_delayed: &mut IdmServerDelayed,
        ct: Duration,
    ) -> (AccessTokenResponse, ClientAuthInfo) {
        // First, setup to get a token.
        let (secret, _uat, ident, _) =
            setup_oauth2_resource_server_basic(idms, ct, true, false, false).await;
        let client_authz = ClientAuthInfo::encode_basic("test_resource_server", secret.as_str());

        let idms_prox_read = idms.proxy_read().await.unwrap();

        // == Setup the authorisation request
        let pkce_secret = PkceS256Secret::default();

        let consent_request = good_authorisation_request!(
            idms_prox_read,
            &ident,
            ct,
            pkce_secret.to_request(),
            OAUTH2_SCOPE_OPENID.to_string()
        );

        let AuthoriseResponse::ConsentRequested { consent_token, .. } = consent_request else {
            unreachable!();
        };

        // == Manually submit the consent token to the permit for the permit_success
        drop(idms_prox_read);
        let mut idms_prox_write = idms.proxy_write(ct).await.unwrap();

        let permit_success = idms_prox_write
            .check_oauth2_authorise_permit(&ident, &consent_token, ct)
            .expect("Failed to perform OAuth2 permit");

        let token_req: AccessTokenRequest = GrantTypeReq::AuthorizationCode {
            code: permit_success.code,
            redirect_uri: Url::parse("https://demo.example.com/oauth2/result").unwrap(),
            code_verifier: Some(pkce_secret.to_verifier()),
        }
        .into();
        let access_token_response_1 = idms_prox_write
            .check_oauth2_token_exchange(&client_authz, &token_req, ct)
            .expect("Unable to exchange for OAuth2 token");

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
        let mut idms_prox_write = idms.proxy_write(ct).await.unwrap();

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
            .check_oauth2_token_exchange(&client_authz, &token_req, ct)
            .expect("Unable to exchange for OAuth2 token");

        assert!(idms_prox_write.commit().is_ok());

        trace!(?access_token_response_2);

        assert!(access_token_response_1.access_token != access_token_response_2.access_token);
        assert!(access_token_response_1.refresh_token != access_token_response_2.refresh_token);
        assert!(access_token_response_1.id_token != access_token_response_2.id_token);

        // ============================================
        // test basic refresh after access exp
        let ct =
            Duration::from_secs(TEST_CURRENT_TIME + 20 + access_token_response_2.expires_in as u64);

        let mut idms_prox_write = idms.proxy_write(ct).await.unwrap();

        let refresh_token = access_token_response_2
            .refresh_token
            .as_ref()
            .expect("no refresh token was issued")
            .clone();

        // get the refresh token expiry now before we use it.
        let reflected_token = idms_prox_write
            .reflect_oauth2_token(&client_authz, &refresh_token)
            .expect("Failed to access internals of the refresh token");

        let refresh_exp = match reflected_token {
            Oauth2TokenType::Refresh { exp, .. } => exp,
            // Oauth2TokenType::Access { .. } |
            Oauth2TokenType::ClientAccess { .. } => unreachable!(),
        };

        let token_req: AccessTokenRequest = GrantTypeReq::RefreshToken {
            refresh_token,
            scope: None,
        }
        .into();

        let access_token_response_3 = idms_prox_write
            .check_oauth2_token_exchange(&client_authz, &token_req, ct)
            .expect("Unable to exchange for OAuth2 token");

        // Get the user entry to check the session life was extended.

        let entry = idms_prox_write
            .qs_write
            .internal_search_uuid(UUID_TESTPERSON_1)
            .expect("failed");
        let session = entry
            .get_ava_as_oauth2session_map(Attribute::OAuth2Session)
            .and_then(|sessions| sessions.first_key_value())
            // If there is no map, then something is wrong.
            .unwrap();

        trace!(?session);
        // The Oauth2 Session must be updated with a newer session time.
        assert_eq!(
            SessionState::ExpiresAt(
                time::OffsetDateTime::UNIX_EPOCH
                    + ct
                    + Duration::from_secs(OAUTH_REFRESH_TOKEN_EXPIRY)
            ),
            session.1.state
        );

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

        let mut idms_prox_write = idms.proxy_write(ct).await.unwrap();

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
            .check_oauth2_token_exchange(&client_authz, &token_req, ct)
            .unwrap_err();

        assert_eq!(access_token_response_4, Oauth2Error::InvalidGrant);

        assert!(idms_prox_write.commit().is_ok());
    }

    // refresh when OAuth2 parent session exp / missing.
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
        // Revoke the OAuth2 session

        let mut idms_prox_write = idms.proxy_write(ct).await.unwrap();
        let revoke_request = TokenRevokeRequest {
            token: access_token_response_1.access_token.clone(),
            token_type_hint: None,
            client_post_auth: ClientPostAuth::default(),
        };
        assert!(idms_prox_write
            .oauth2_token_revoke(&client_authz, &revoke_request, ct,)
            .is_ok());
        assert!(idms_prox_write.commit().is_ok());

        // ============================================
        // then attempt a refresh.
        let mut idms_prox_write = idms.proxy_write(ct).await.unwrap();

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
            .check_oauth2_token_exchange(&client_authz, &token_req, ct)
            // Should be unable to exchange.
            .unwrap_err();

        assert_eq!(access_token_response_2, Oauth2Error::InvalidGrant);

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

        let (access_token_response_1, _client_authz) =
            setup_refresh_token(idms, idms_delayed, ct).await;

        let bad_client_authz = ClientAuthInfo::encode_basic("test_resource_server", "12345");

        // ============================================
        // Refresh with invalid client authz

        let mut idms_prox_write = idms.proxy_write(ct).await.unwrap();

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
            .check_oauth2_token_exchange(&bad_client_authz, &token_req, ct)
            .unwrap_err();

        assert_eq!(access_token_response_2, Oauth2Error::AuthenticationRequired);

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

        let mut idms_prox_write = idms.proxy_write(ct).await.unwrap();

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
            .check_oauth2_token_exchange(&client_authz, &token_req, ct)
            .unwrap_err();

        assert_eq!(access_token_response_2, Oauth2Error::InvalidScope);

        assert!(idms_prox_write.commit().is_ok());
    }

    // Test that reuse of a refresh token is denied + terminates the session.
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
        let mut idms_prox_write = idms.proxy_write(ct).await.unwrap();

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
            .check_oauth2_token_exchange(&client_authz, &token_req, ct)
            .expect("Unable to exchange for OAuth2 token");

        assert!(idms_prox_write.commit().is_ok());

        // Now use it again. - this will cause an error and the session to be terminated.
        let ct = Duration::from_secs(TEST_CURRENT_TIME + 2);
        let mut idms_prox_write = idms.proxy_write(ct).await.unwrap();

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
            .check_oauth2_token_exchange(&client_authz, &token_req, ct)
            .unwrap_err();

        assert_eq!(access_token_response_3, Oauth2Error::InvalidGrant);

        let entry = idms_prox_write
            .qs_write
            .internal_search_uuid(UUID_TESTPERSON_1)
            .expect("failed");
        let valid = entry
            .get_ava_as_oauth2session_map(Attribute::OAuth2Session)
            .and_then(|sessions| sessions.first_key_value())
            .map(|(_, session)| !matches!(session.state, SessionState::RevokedAt(_)))
            // If there is no map, then something is wrong.
            .unwrap();
        // The session should be invalid at this point.
        assert!(!valid);

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
        let mut idms_prox_write = idms.proxy_write(ct).await.unwrap();

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
            .check_oauth2_token_exchange(&client_authz, &token_req, ct)
            .expect("Unable to exchange for OAuth2 token");

        // DO NOT COMMIT HERE - this is what forces the session issued_at
        // time to stay at the original time!
        drop(idms_prox_write);

        // ============================================
        let ct = Duration::from_secs(TEST_CURRENT_TIME + 2);
        let mut idms_prox_write = idms.proxy_write(ct).await.unwrap();

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
            .check_oauth2_token_exchange(&client_authz, &token_req, ct)
            .expect("Unable to exchange for OAuth2 token");

        assert!(idms_prox_write.commit().is_ok());

        // Success!
    }

    #[idm_test]
    async fn test_idm_oauth2_refresh_token_scope_constraints(
        idms: &IdmServer,
        idms_delayed: &mut IdmServerDelayed,
    ) {
        // First, setup to get a token.
        let ct = Duration::from_secs(TEST_CURRENT_TIME);

        let (access_token_response_1, client_authz) =
            setup_refresh_token(idms, idms_delayed, ct).await;

        // https://www.rfc-editor.org/rfc/rfc6749#section-1.5
        // Refresh tokens are issued to the client by the authorization
        // server and are used to obtain a new access token when the
        // current access token becomes invalid or expires, or to obtain
        // additional access tokens with identical or narrower scope
        // (access tokens may have a shorter lifetime and fewer
        // permissions than authorized by the resource owner).

        let ct = Duration::from_secs(TEST_CURRENT_TIME + 10);
        let mut idms_prox_write = idms.proxy_write(ct).await.unwrap();

        let refresh_token = access_token_response_1
            .refresh_token
            .as_ref()
            .expect("no refresh token was issued")
            .clone();

        // Get the initial scopes.
        let jws_verifier = JwsDangerReleaseWithoutVerify::default();

        let access_token_unverified = JwsCompact::from_str(&access_token_response_1.access_token)
            .expect("Invalid Access Token");

        let reflected_token = jws_verifier
            .verify(&access_token_unverified)
            .unwrap()
            .from_json::<OAuth2RFC9068Token<OAuth2RFC9068TokenExtensions>>()
            .expect("Failed to access internals of the refresh token");

        trace!(?reflected_token);
        let initial_scopes = reflected_token.extensions.scope;
        trace!(?initial_scopes);

        // Should be the same scopes as initial.
        let token_req: AccessTokenRequest = GrantTypeReq::RefreshToken {
            refresh_token,
            scope: None,
        }
        .into();

        let access_token_response_2 = idms_prox_write
            .check_oauth2_token_exchange(&client_authz, &token_req, ct)
            .expect("Unable to exchange for OAuth2 token");

        let access_token_unverified = JwsCompact::from_str(&access_token_response_2.access_token)
            .expect("Invalid Access Token");

        let reflected_token = jws_verifier
            .verify(&access_token_unverified)
            .unwrap()
            .from_json::<OAuth2RFC9068Token<OAuth2RFC9068TokenExtensions>>()
            .expect("Failed to access internals of the refresh token");

        assert_eq!(initial_scopes, reflected_token.extensions.scope);

        let refresh_token = access_token_response_2
            .refresh_token
            .as_ref()
            .expect("no refresh token was issued")
            .clone();

        // Now the scopes can be constrained.
        let token_req: AccessTokenRequest = GrantTypeReq::RefreshToken {
            refresh_token,
            scope: Some(["openid".to_string()].into()),
        }
        .into();

        let access_token_response_3 = idms_prox_write
            .check_oauth2_token_exchange(&client_authz, &token_req, ct)
            .expect("Unable to exchange for OAuth2 token");

        let access_token_unverified = JwsCompact::from_str(&access_token_response_3.access_token)
            .expect("Invalid Access Token");

        let reflected_token = jws_verifier
            .verify(&access_token_unverified)
            .unwrap()
            .from_json::<OAuth2RFC9068Token<OAuth2RFC9068TokenExtensions>>()
            .expect("Failed to access internals of the refresh token");

        assert_ne!(initial_scopes, reflected_token.extensions.scope);

        // Keep the constrained scopes.
        let constrained_scopes = reflected_token.extensions.scope;

        let refresh_token = access_token_response_3
            .refresh_token
            .as_ref()
            .expect("no refresh token was issued")
            .clone();

        // No scope request still issues the constrained values.
        let token_req: AccessTokenRequest = GrantTypeReq::RefreshToken {
            refresh_token,
            scope: None,
        }
        .into();

        let access_token_response_4 = idms_prox_write
            .check_oauth2_token_exchange(&client_authz, &token_req, ct)
            .expect("Unable to exchange for OAuth2 token");

        let access_token_unverified = JwsCompact::from_str(&access_token_response_4.access_token)
            .expect("Invalid Access Token");

        let reflected_token = jws_verifier
            .verify(&access_token_unverified)
            .unwrap()
            .from_json::<OAuth2RFC9068Token<OAuth2RFC9068TokenExtensions>>()
            .expect("Failed to access internals of the refresh token");

        assert_ne!(initial_scopes, reflected_token.extensions.scope);
        assert_eq!(constrained_scopes, reflected_token.extensions.scope);

        let refresh_token = access_token_response_4
            .refresh_token
            .as_ref()
            .expect("no refresh token was issued")
            .clone();

        // We can't now extend back to the initial scopes.
        let token_req: AccessTokenRequest = GrantTypeReq::RefreshToken {
            refresh_token,
            scope: Some(initial_scopes),
        }
        .into();

        let access_token_response_5_err = idms_prox_write
            .check_oauth2_token_exchange(&client_authz, &token_req, ct)
            .unwrap_err();

        assert_eq!(access_token_response_5_err, Oauth2Error::InvalidScope);

        assert!(idms_prox_write.commit().is_ok());
    }

    #[test]
    // I know this looks kinda dumb but at some point someone pointed out that our scope syntax wasn't compliant with rfc6749
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

    #[idm_test]
    async fn test_idm_oauth2_custom_claims(idms: &IdmServer, _idms_delayed: &mut IdmServerDelayed) {
        let ct = Duration::from_secs(TEST_CURRENT_TIME);
        let (secret, _uat, ident, oauth2_rs_uuid) =
            setup_oauth2_resource_server_basic(idms, ct, true, false, false).await;

        // Setup custom claim maps here.
        let mut idms_prox_write = idms.proxy_write(ct).await.unwrap();

        let modlist = ModifyList::new_list(vec![
            // Member of a claim map.
            Modify::Present(
                Attribute::OAuth2RsClaimMap,
                Value::OauthClaimMap(
                    "custom_a".to_string(),
                    OauthClaimMapJoin::CommaSeparatedValue,
                ),
            ),
            Modify::Present(
                Attribute::OAuth2RsClaimMap,
                Value::OauthClaimValue(
                    "custom_a".to_string(),
                    UUID_TESTGROUP,
                    btreeset!["value_a".to_string()],
                ),
            ),
            // If you are a member of two groups, the claim maps merge.
            Modify::Present(
                Attribute::OAuth2RsClaimMap,
                Value::OauthClaimValue(
                    "custom_a".to_string(),
                    UUID_IDM_ALL_ACCOUNTS,
                    btreeset!["value_b".to_string()],
                ),
            ),
            // Map with a different separator
            Modify::Present(
                Attribute::OAuth2RsClaimMap,
                Value::OauthClaimMap(
                    "custom_b".to_string(),
                    OauthClaimMapJoin::SpaceSeparatedValue,
                ),
            ),
            Modify::Present(
                Attribute::OAuth2RsClaimMap,
                Value::OauthClaimValue(
                    "custom_b".to_string(),
                    UUID_TESTGROUP,
                    btreeset!["value_a".to_string()],
                ),
            ),
            Modify::Present(
                Attribute::OAuth2RsClaimMap,
                Value::OauthClaimValue(
                    "custom_b".to_string(),
                    UUID_IDM_ALL_ACCOUNTS,
                    btreeset!["value_b".to_string()],
                ),
            ),
            // Not a member of the claim map.
            Modify::Present(
                Attribute::OAuth2RsClaimMap,
                Value::OauthClaimValue(
                    "custom_b".to_string(),
                    UUID_IDM_ADMINS,
                    btreeset!["value_c".to_string()],
                ),
            ),
            // Extended claim name syntax, allows characters beyond scope names.
            Modify::Present(
                Attribute::OAuth2RsClaimMap,
                Value::OauthClaimMap(
                    "custom:claim-name".to_string(),
                    OauthClaimMapJoin::CommaSeparatedValue,
                ),
            ),
            Modify::Present(
                Attribute::OAuth2RsClaimMap,
                Value::OauthClaimValue(
                    "custom:claim-name".to_string(),
                    UUID_TESTGROUP,
                    btreeset!["value:a-a".to_string()],
                ),
            ),
        ]);

        assert!(idms_prox_write
            .qs_write
            .internal_modify(
                &filter!(f_eq(Attribute::Uuid, PartialValue::Uuid(oauth2_rs_uuid))),
                &modlist,
            )
            .is_ok());

        assert!(idms_prox_write.commit().is_ok());

        // Claim maps setup, lets go.
        let client_authz = ClientAuthInfo::encode_basic("test_resource_server", secret.as_str());

        let idms_prox_read = idms.proxy_read().await.unwrap();

        let pkce_secret = PkceS256Secret::default();

        let consent_request = good_authorisation_request!(
            idms_prox_read,
            &ident,
            ct,
            pkce_secret.to_request(),
            OAUTH2_SCOPE_OPENID.to_string()
        );

        let AuthoriseResponse::ConsentRequested { consent_token, .. } = consent_request else {
            unreachable!();
        };

        // == Manually submit the consent token to the permit for the permit_success
        drop(idms_prox_read);
        let mut idms_prox_write = idms.proxy_write(ct).await.unwrap();

        let permit_success = idms_prox_write
            .check_oauth2_authorise_permit(&ident, &consent_token, ct)
            .expect("Failed to perform OAuth2 permit");

        // == Submit the token exchange code.
        let token_req: AccessTokenRequest = GrantTypeReq::AuthorizationCode {
            code: permit_success.code,
            redirect_uri: Url::parse("https://demo.example.com/oauth2/result").unwrap(),
            code_verifier: Some(pkce_secret.to_verifier()),
        }
        .into();

        let token_response = idms_prox_write
            .check_oauth2_token_exchange(&client_authz, &token_req, ct)
            .expect("Failed to perform OAuth2 token exchange");

        // 🎉 We got a token!
        assert_eq!(token_response.token_type, AccessTokenType::Bearer);

        let id_token = token_response.id_token.expect("No id_token in response!");
        let access_token =
            JwsCompact::from_str(&token_response.access_token).expect("Invalid Access Token");

        // Get the read txn for inspecting the tokens
        assert!(idms_prox_write.commit().is_ok());

        let mut idms_prox_read = idms.proxy_read().await.unwrap();

        let mut jwkset = idms_prox_read
            .oauth2_openid_publickey("test_resource_server")
            .expect("Failed to get public key");

        let public_jwk = jwkset.keys.pop().expect("no such jwk");

        let jws_validator =
            JwsEs256Verifier::try_from(&public_jwk).expect("failed to build validator");

        let oidc_unverified =
            OidcUnverified::from_str(&id_token).expect("Failed to parse id_token");

        let iat = ct.as_secs() as i64;

        let oidc = jws_validator
            .verify(&oidc_unverified)
            .unwrap()
            .verify_exp(iat)
            .expect("Failed to verify oidc");

        // Are the id_token values what we expect?
        assert!(
            oidc.iss
                == Url::parse("https://idm.example.com/oauth2/openid/test_resource_server")
                    .unwrap()
        );
        assert_eq!(oidc.sub, OidcSubject::U(UUID_TESTPERSON_1));
        assert_eq!(oidc.aud, "test_resource_server");
        assert_eq!(oidc.iat, iat);
        assert_eq!(oidc.nbf, Some(iat));
        // Previously this was the auth session but it's now inline with the access token expiry.
        assert_eq!(oidc.exp, iat + (OAUTH2_ACCESS_TOKEN_EXPIRY as i64));
        assert!(oidc.auth_time.is_none());
        // Is nonce correctly passed through?
        assert_eq!(oidc.nonce, Some("abcdef".to_string()));
        assert!(oidc.at_hash.is_none());
        assert!(oidc.acr.is_none());
        assert!(oidc.amr.is_none());
        assert_eq!(oidc.azp, Some("test_resource_server".to_string()));
        assert!(oidc.jti.is_some());
        if let Some(jti) = &oidc.jti {
            assert!(Uuid::from_str(jti).is_ok());
        }
        assert_eq!(oidc.s_claims.name, Some("Test Person 1".to_string()));
        assert_eq!(
            oidc.s_claims.preferred_username,
            Some("testperson1@example.com".to_string())
        );
        assert!(
            oidc.s_claims.scopes == vec![OAUTH2_SCOPE_OPENID.to_string(), "supplement".to_string()]
        );

        assert_eq!(
            oidc.claims.get("custom_a").and_then(|v| v.as_str()),
            Some("value_a,value_b")
        );
        assert_eq!(
            oidc.claims.get("custom_b").and_then(|v| v.as_str()),
            Some("value_a value_b")
        );

        assert_eq!(
            oidc.claims
                .get("custom:claim-name")
                .and_then(|v| v.as_str()),
            Some("value:a-a")
        );

        // Does our access token work with the userinfo endpoint?
        // Do the id_token details line up to the userinfo?
        let userinfo = idms_prox_read
            .oauth2_openid_userinfo("test_resource_server", &access_token, ct)
            .expect("failed to get userinfo");

        assert_eq!(oidc.iss, userinfo.iss);
        assert_eq!(oidc.sub, userinfo.sub);
        assert_eq!(oidc.aud, userinfo.aud);
        assert_eq!(oidc.iat, userinfo.iat);
        assert_eq!(oidc.nbf, userinfo.nbf);
        assert_eq!(oidc.exp, userinfo.exp);
        assert!(userinfo.auth_time.is_none());
        assert_eq!(userinfo.nonce, Some("abcdef".to_string()));
        assert!(userinfo.at_hash.is_none());
        assert!(userinfo.jti.is_some());
        if let Some(jti) = &userinfo.jti {
            assert!(Uuid::from_str(jti).is_ok());
        }
        assert_eq!(oidc.amr, userinfo.amr);
        assert_eq!(oidc.azp, userinfo.azp);
        assert!(userinfo.jti.is_some());
        if let Some(jti) = &userinfo.jti {
            assert!(Uuid::from_str(jti).is_ok());
        }
        assert_eq!(oidc.s_claims, userinfo.s_claims);
        assert_eq!(oidc.claims, userinfo.claims);

        // Check the oauth2 introspect bits.
        let intr_request = AccessTokenIntrospectRequest {
            token: token_response.access_token.clone(),
            token_type_hint: None,
            client_post_auth: ClientPostAuth::default(),
        };
        let intr_response = idms_prox_read
            .check_oauth2_token_introspect(&client_authz, &intr_request, ct)
            .expect("Failed to inspect token");

        eprintln!("👉  {intr_response:?}");
        assert!(intr_response.active);
        assert_eq!(
            intr_response.scope,
            btreeset!["openid".to_string(), "supplement".to_string()]
        );
        assert_eq!(
            intr_response.client_id.as_deref(),
            Some("test_resource_server")
        );
        assert_eq!(
            intr_response.username.as_deref(),
            Some("testperson1@example.com")
        );
        assert_eq!(intr_response.token_type, Some(AccessTokenType::Bearer));
        assert_eq!(intr_response.iat, Some(ct.as_secs() as i64));
        assert_eq!(intr_response.nbf, Some(ct.as_secs() as i64));
        // Introspect doesn't have custom claims.

        drop(idms_prox_read);
    }

    #[idm_test]
    async fn test_idm_oauth2_public_allow_localhost_redirect(
        idms: &IdmServer,
        _idms_delayed: &mut IdmServerDelayed,
    ) {
        let ct = Duration::from_secs(TEST_CURRENT_TIME);
        let (_uat, ident, oauth2_rs_uuid) = setup_oauth2_resource_server_public(idms, ct).await;

        let mut idms_prox_write: crate::idm::server::IdmServerProxyWriteTransaction<'_> =
            idms.proxy_write(ct).await.unwrap();

        let redirect_uri = Url::parse("http://localhost:8765/oauth2/result")
            .expect("Failed to parse redirect URL");

        let modlist = ModifyList::new_list(vec![
            Modify::Present(Attribute::OAuth2AllowLocalhostRedirect, Value::Bool(true)),
            Modify::Present(Attribute::OAuth2RsOrigin, Value::Url(redirect_uri.clone())),
        ]);

        assert!(idms_prox_write
            .qs_write
            .internal_modify(
                &filter!(f_eq(Attribute::Uuid, PartialValue::Uuid(oauth2_rs_uuid))),
                &modlist,
            )
            .is_ok());

        assert!(idms_prox_write.commit().is_ok());

        let idms_prox_read = idms.proxy_read().await.unwrap();

        // == Setup the authorisation request
        let pkce_secret = PkceS256Secret::default();

        let auth_req = AuthorisationRequest {
            response_type: ResponseType::Code,
            response_mode: None,
            client_id: "test_resource_server".to_string(),
            state: Some("123".to_string()),
            pkce_request: Some(pkce_secret.to_request()),
            redirect_uri: Url::parse("http://localhost:8765/oauth2/result").unwrap(),
            scope: btreeset![OAUTH2_SCOPE_OPENID.to_string()],
            nonce: Some("abcdef".to_string()),
            oidc_ext: Default::default(),
            max_age: None,
            unknown_keys: Default::default(),
        };

        let consent_request = idms_prox_read
            .check_oauth2_authorisation(Some(&ident), &auth_req, ct)
            .expect("OAuth2 authorisation failed");

        // Should be in the consent phase;
        let AuthoriseResponse::ConsentRequested { consent_token, .. } = consent_request else {
            unreachable!();
        };

        // == Manually submit the consent token to the permit for the permit_success
        drop(idms_prox_read);
        let mut idms_prox_write = idms.proxy_write(ct).await.unwrap();

        let permit_success = idms_prox_write
            .check_oauth2_authorise_permit(&ident, &consent_token, ct)
            .expect("Failed to perform OAuth2 permit");

        // Check we are reflecting the CSRF properly.
        assert_eq!(permit_success.state.as_deref(), Some("123"));

        // == Submit the token exchange code.
        let token_req = AccessTokenRequest {
            grant_type: GrantTypeReq::AuthorizationCode {
                code: permit_success.code,
                redirect_uri,
                code_verifier: Some(pkce_secret.to_verifier()),
            },
            client_post_auth: ClientPostAuth {
                client_id: Some("test_resource_server".to_string()),
                client_secret: None,
            },
        };

        let token_response = idms_prox_write
            .check_oauth2_token_exchange(&ClientAuthInfo::none(), &token_req, ct)
            .expect("Failed to perform OAuth2 token exchange");

        // 🎉 We got a token! In the future we can then check introspection from this point.
        assert_eq!(token_response.token_type, AccessTokenType::Bearer);

        assert!(idms_prox_write.commit().is_ok());
    }

    #[idm_test]
    async fn test_idm_oauth2_service_account_token_exchange(
        idms: &IdmServer,
        _idms_delayed: &mut IdmServerDelayed,
    ) {
        let ct = Duration::from_secs(TEST_CURRENT_TIME);
        let (secret, _uat, _ident, _) =
            setup_oauth2_resource_server_basic(idms, ct, true, false, false).await;

        let mut idms_prox_write = idms.proxy_write(ct).await.unwrap();

        let service_account_uuid = Uuid::new_v4();
        let sa_entry: Entry<EntryInit, EntryNew> = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Account.to_value()),
            (Attribute::Class, EntryClass::ServiceAccount.to_value()),
            (Attribute::Name, Value::new_iname("test_sa_oauth2")),
            (Attribute::Uuid, Value::Uuid(service_account_uuid)),
            (Attribute::DisplayName, Value::new_utf8s("test_sa_oauth2")),
            (Attribute::Description, Value::new_utf8s("test_sa_oauth2"))
        );

        idms_prox_write
            .qs_write
            .internal_create(vec![sa_entry])
            .expect("Failed to create service account");

        idms_prox_write
            .qs_write
            .internal_modify(
                &filter!(f_eq(Attribute::Uuid, PartialValue::Uuid(UUID_TESTGROUP))),
                &ModifyList::new_list(vec![Modify::Present(
                    Attribute::Member,
                    Value::Refer(service_account_uuid),
                )]),
            )
            .expect("Failed to add service account to scope group");

        let gte = GenerateApiTokenEvent::new_internal(service_account_uuid, "sa-token", None);

        let api_token = idms_prox_write
            .service_account_generate_api_token(&gte, ct)
            .expect("failed to generate api token");

        assert!(idms_prox_write.commit().is_ok());

        let client_authz = ClientAuthInfo::encode_basic("test_resource_server", secret.as_str());

        let scopes: BTreeSet<String> =
            btreeset![OAUTH2_SCOPE_OPENID.into(), OAUTH2_SCOPE_GROUPS.into()];

        let build_exchange_request =
            |requested_scopes: BTreeSet<String>, client_secret: Option<String>| {
                AccessTokenRequest {
                    grant_type: GrantTypeReq::TokenExchange {
                        subject_token: api_token.to_string(),
                        subject_token_type: TOKEN_EXCHANGE_SUBJECT_TOKEN_TYPE_ACCESS.into(),
                        requested_token_type: None,
                        audience: Some("test_resource_server".into()),
                        resource: None,
                        actor_token: None,
                        actor_token_type: None,
                        scope: Some(requested_scopes),
                    },
                    client_post_auth: ClientPostAuth {
                        client_id: Some("test_resource_server".into()),
                        client_secret,
                    },
                }
            };

        let token_req = build_exchange_request(scopes.clone(), None);
        let forbidden_secret_req = build_exchange_request(scopes.clone(), Some(secret.clone()));
        let empty_scope_req = build_exchange_request(BTreeSet::new(), None);

        let mut idms_prox_write = idms.proxy_write(ct).await.unwrap();

        assert_eq!(
            idms_prox_write
                .check_oauth2_token_exchange(&client_authz, &forbidden_secret_req, ct)
                .unwrap_err(),
            Oauth2Error::InvalidRequest
        );

        assert_eq!(
            idms_prox_write
                .check_oauth2_token_exchange(&ClientAuthInfo::none(), &empty_scope_req, ct)
                .unwrap_err(),
            Oauth2Error::InvalidRequest
        );

        let token_response = idms_prox_write
            .check_oauth2_token_exchange(&ClientAuthInfo::none(), &token_req, ct)
            .expect("Failed to perform OAuth2 token exchange for service account");

        assert_eq!(token_response.token_type, AccessTokenType::Bearer);
        assert_eq!(
            token_response.issued_token_type,
            Some(IssuedTokenType::AccessToken)
        );
        assert!(token_response.refresh_token.is_some());
        assert!(token_response.id_token.is_some());
        let response_scopes = token_response.scope.clone();
        assert!(response_scopes.contains(OAUTH2_SCOPE_OPENID));
        assert!(response_scopes.contains(OAUTH2_SCOPE_GROUPS));

        assert!(idms_prox_write.commit().is_ok());

        let mut idms_prox_read = idms.proxy_read().await.unwrap();
        let intr_request = AccessTokenIntrospectRequest {
            token: token_response.access_token.clone(),
            token_type_hint: None,
            client_post_auth: ClientPostAuth::default(),
        };
        let intr_response = idms_prox_read
            .check_oauth2_token_introspect(&client_authz, &intr_request, ct)
            .expect("Failed to introspect service account token");

        assert!(intr_response.active);
        assert_eq!(
            intr_response.client_id.as_deref(),
            Some("test_resource_server")
        );
        assert_eq!(
            intr_response.sub.as_deref(),
            Some(service_account_uuid.to_string().as_str())
        );
    }

    #[idm_test]
    async fn test_idm_oauth2_basic_client_credentials_grant_valid(
        idms: &IdmServer,
        _idms_delayed: &mut IdmServerDelayed,
    ) {
        let ct = Duration::from_secs(TEST_CURRENT_TIME);
        let (secret, _uat, _ident, _) =
            setup_oauth2_resource_server_basic(idms, ct, true, false, false).await;
        let client_authz = ClientAuthInfo::encode_basic("test_resource_server", secret.as_str());

        // scope: Some(btreeset!["invalid_scope".to_string()]),
        let mut idms_prox_write = idms.proxy_write(ct).await.unwrap();

        let token_req = AccessTokenRequest {
            grant_type: GrantTypeReq::ClientCredentials { scope: None },

            client_post_auth: ClientPostAuth {
                client_id: Some("test_resource_server".to_string()),
                client_secret: Some(secret),
            },
        };

        let oauth2_token = idms_prox_write
            .check_oauth2_token_exchange(&ClientAuthInfo::none(), &token_req, ct)
            .expect("Failed to perform OAuth2 token exchange");

        assert!(idms_prox_write.commit().is_ok());

        // 🎉 We got a token! In the future we can then check introspection from this point.
        assert_eq!(oauth2_token.token_type, AccessTokenType::Bearer);

        // Check Oauth2 Token Introspection
        let mut idms_prox_read = idms.proxy_read().await.unwrap();

        let intr_request = AccessTokenIntrospectRequest {
            token: oauth2_token.access_token.clone(),
            token_type_hint: None,
            client_post_auth: ClientPostAuth::default(),
        };
        let intr_response = idms_prox_read
            .check_oauth2_token_introspect(&client_authz, &intr_request, ct)
            .expect("Failed to inspect token");

        eprintln!("👉  {intr_response:?}");
        assert!(intr_response.active);
        assert_eq!(intr_response.scope, btreeset!["supplement".to_string()]);
        assert_eq!(
            intr_response.client_id.as_deref(),
            Some("test_resource_server")
        );
        assert_eq!(
            intr_response.username.as_deref(),
            Some("test_resource_server@example.com")
        );
        assert_eq!(intr_response.token_type, Some(AccessTokenType::Bearer));
        assert_eq!(intr_response.iat, Some(ct.as_secs() as i64));
        assert_eq!(intr_response.nbf, Some(ct.as_secs() as i64));

        drop(idms_prox_read);

        // Assert we can revoke.
        let mut idms_prox_write = idms.proxy_write(ct).await.unwrap();
        let revoke_request = TokenRevokeRequest {
            token: oauth2_token.access_token.clone(),
            token_type_hint: None,
            client_post_auth: ClientPostAuth::default(),
        };
        assert!(idms_prox_write
            .oauth2_token_revoke(&client_authz, &revoke_request, ct,)
            .is_ok());
        assert!(idms_prox_write.commit().is_ok());

        // Now must be invalid.
        let ct = ct + AUTH_TOKEN_GRACE_WINDOW;
        let mut idms_prox_read = idms.proxy_read().await.unwrap();

        let intr_request = AccessTokenIntrospectRequest {
            token: oauth2_token.access_token.clone(),
            token_type_hint: None,
            client_post_auth: ClientPostAuth::default(),
        };

        let intr_response = idms_prox_read
            .check_oauth2_token_introspect(&client_authz, &intr_request, ct)
            .expect("Failed to inspect token");
        assert!(!intr_response.active);

        drop(idms_prox_read);
    }

    #[idm_test]
    async fn test_idm_oauth2_basic_client_credentials_grant_invalid(
        idms: &IdmServer,
        _idms_delayed: &mut IdmServerDelayed,
    ) {
        let ct = Duration::from_secs(TEST_CURRENT_TIME);
        let (secret, _uat, _ident, _) =
            setup_oauth2_resource_server_basic(idms, ct, true, false, false).await;

        let mut idms_prox_write = idms.proxy_write(ct).await.unwrap();

        // Public Client
        let token_req = AccessTokenRequest {
            grant_type: GrantTypeReq::ClientCredentials { scope: None },
            client_post_auth: ClientPostAuth {
                client_id: Some("test_resource_server".to_string()),
                client_secret: None,
            },
        };

        assert_eq!(
            idms_prox_write
                .check_oauth2_token_exchange(&ClientAuthInfo::none(), &token_req, ct)
                .unwrap_err(),
            Oauth2Error::AuthenticationRequired
        );

        // Incorrect Password
        let token_req = AccessTokenRequest {
            grant_type: GrantTypeReq::ClientCredentials { scope: None },

            client_post_auth: ClientPostAuth {
                client_id: Some("test_resource_server".to_string()),
                client_secret: Some("wrong password".to_string()),
            },
        };

        assert_eq!(
            idms_prox_write
                .check_oauth2_token_exchange(&ClientAuthInfo::none(), &token_req, ct)
                .unwrap_err(),
            Oauth2Error::AuthenticationRequired
        );

        // Invalid scope
        let scope = Some(btreeset!["💅".to_string()]);
        let token_req = AccessTokenRequest {
            grant_type: GrantTypeReq::ClientCredentials { scope },

            client_post_auth: ClientPostAuth {
                client_id: Some("test_resource_server".to_string()),
                client_secret: Some(secret.clone()),
            },
        };

        assert_eq!(
            idms_prox_write
                .check_oauth2_token_exchange(&ClientAuthInfo::none(), &token_req, ct)
                .unwrap_err(),
            Oauth2Error::InvalidScope
        );

        // Scopes we aren't a member-of
        let scope = Some(btreeset!["invalid_scope".to_string()]);
        let token_req = AccessTokenRequest {
            grant_type: GrantTypeReq::ClientCredentials { scope },

            client_post_auth: ClientPostAuth {
                client_id: Some("test_resource_server".to_string()),
                client_secret: Some(secret.clone()),
            },
        };

        assert_eq!(
            idms_prox_write
                .check_oauth2_token_exchange(&ClientAuthInfo::none(), &token_req, ct)
                .unwrap_err(),
            Oauth2Error::AccessDenied
        );

        assert!(idms_prox_write.commit().is_ok());
    }

    #[test]
    fn test_get_code() {
        use super::{gen_device_code, gen_user_code, parse_user_code};

        assert!(gen_device_code().is_ok());

        let (res_string, res_value) = gen_user_code();

        assert!(res_string.split('-').count() == 3);

        let res_string_clean = res_string.replace("-", "");
        let res_string_as_num = res_string_clean
            .parse::<u32>()
            .expect("Failed to parse as number");
        assert_eq!(res_string_as_num, res_value);

        assert_eq!(
            parse_user_code(&res_string).expect("Failed to parse code"),
            res_value
        );
    }

    #[idm_test]
    async fn handle_oauth2_start_device_flow(
        idms: &IdmServer,
        _idms_delayed: &mut IdmServerDelayed,
    ) {
        let ct = duration_from_epoch_now();

        let client_auth_info = ClientAuthInfo::from(Source::Https(
            "127.0.0.1"
                .parse()
                .expect("Failed to parse 127.0.0.1 as an IP!"),
        ));
        let eventid = Uuid::new_v4();

        let res = idms
            .proxy_write(ct)
            .await
            .expect("Failed to get idmspwt")
            .handle_oauth2_start_device_flow(client_auth_info, "test_rs_id", &None, eventid);
        dbg!(&res);
        assert!(res.is_err());
    }

    #[test]
    fn test_url_localhost_domain() {
        // ref #2390 - localhost with ports for OAuth2 redirect_uri

        // ensure host_is_local isn't true for a non-local host
        let example_is_not_local = "https://example.com/sdfsdf";
        println!("Ensuring that {example_is_not_local} is not local");
        assert!(!host_is_local(
            &Url::parse(example_is_not_local)
                .expect("Failed to parse example.com as a host?")
                .host()
                .unwrap_or_else(|| panic!("Couldn't get a host from {example_is_not_local}"))
        ));

        let test_urls = [
            ("http://localhost:8080/oauth2/callback", "/oauth2/callback"),
            ("https://localhost/foo/bar", "/foo/bar"),
            ("http://127.0.0.1:12345/foo", "/foo"),
            ("http://[::1]:12345/foo", "/foo"),
        ];

        for (url, path) in test_urls.into_iter() {
            println!("Testing URL: {url}");
            let url = Url::parse(url).expect("One of the test values failed!");
            assert!(host_is_local(
                &url.host().expect("Didn't parse a host out?")
            ));

            assert_eq!(url.path(), path);
        }
    }

    #[test]
    fn test_oauth2_rs_type_allow_localhost_redirect() {
        let test_cases = [
            (
                OauthRSType::Public {
                    allow_localhost_redirect: true,
                },
                true,
            ),
            (
                OauthRSType::Public {
                    allow_localhost_redirect: false,
                },
                false,
            ),
            (
                OauthRSType::Basic {
                    authz_secret: "supersecret".to_string(),
                    enable_pkce: false,
                    enable_consent_prompt: true,
                },
                false,
            ),
        ];

        assert!(test_cases.iter().all(|(rs_type, expected)| {
            let actual = rs_type.allow_localhost_redirect();
            println!("Testing {rs_type:?} -> {expected}");
            actual == *expected
        }));
    }

    #[idm_test]
    async fn test_oauth2_auth_with_no_state(
        idms: &IdmServer,
        _idms_delayed: &mut IdmServerDelayed,
    ) {
        let ct = Duration::from_secs(TEST_CURRENT_TIME);
        let (_secret, _uat, ident, _) =
            setup_oauth2_resource_server_basic(idms, ct, true, false, false).await;

        let idms_prox_read = idms.proxy_read().await.unwrap();

        // == Setup the authorisation request
        let pkce_secret = PkceS256Secret::default();

        let scope: BTreeSet<String> = OAUTH2_SCOPE_OPENID
            .split(" ")
            .map(|s| s.to_string())
            .collect();

        let auth_req = AuthorisationRequest {
            response_type: ResponseType::Code,
            response_mode: None,
            client_id: "test_resource_server".to_string(),
            state: None,
            pkce_request: Some(pkce_secret.to_request()),
            redirect_uri: Url::parse("https://demo.example.com/oauth2/result").unwrap(),
            scope,
            nonce: Some("abcdef".to_string()),
            oidc_ext: Default::default(),
            max_age: None,
            unknown_keys: Default::default(),
        };
        println!("{auth_req:?}");

        let consent_request = idms_prox_read
            .check_oauth2_authorisation(Some(&ident), &auth_req, ct)
            .expect("OAuth2 authorisation failed");

        // Should be in the consent phase;
        let AuthoriseResponse::ConsentRequested { .. } = consent_request else {
            unreachable!("Expected a ConsentRequested response, got: {consent_request:?}");
        };
    }

    #[idm_test]
    async fn test_idm_oauth2_consent_prompt_disabled(
        idms: &IdmServer,
        _idms_delayed: &mut IdmServerDelayed,
    ) {
        let ct = Duration::from_secs(TEST_CURRENT_TIME);
        let (_secret, _uat, ident, o2rs_uuid) =
            setup_oauth2_resource_server_basic(idms, ct, true, false, false).await;

        let mut idms_prox_write = idms.proxy_write(ct).await.unwrap();
        idms_prox_write
            .qs_write
            .internal_modify_uuid(
                o2rs_uuid,
                &ModifyList::new_purge_and_set(
                    Attribute::OAuth2ConsentPromptEnable,
                    Value::new_bool(false),
                ),
            )
            .expect("Unable to disable consent prompt");
        assert!(idms_prox_write.commit().is_ok());

        // Assert there are no consent maps yet so consent should be required if not disabled
        assert!(ident.get_oauth2_consent_scopes(o2rs_uuid).is_none());

        let idms_prox_read = idms.proxy_read().await.unwrap();

        let pkce_secret = PkceS256Secret::default();
        let consent_request = good_authorisation_request!(
            idms_prox_read,
            &ident,
            ct,
            pkce_secret.to_request(),
            OAUTH2_SCOPE_OPENID.to_string()
        );

        // Should be permitted
        let AuthoriseResponse::Permitted(_permitted) = consent_request else {
            unreachable!();
        };

        // Assert that it still doesn't have any consent maps
        assert!(ident.get_oauth2_consent_scopes(o2rs_uuid).is_none());
    }
}
