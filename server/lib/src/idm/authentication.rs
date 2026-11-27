use crate::{
    prelude::{OperationError, Url},
    server::identity::Source,
};
use compact_jwt::{JweCompact, JwsCompact};
use crypto_glue::{s256::Sha256Output, x509::Certificate};
use kanidm_proto::{
    internal::UserAuthToken,
    oauth2::{
        AccessTokenIntrospectRequest, AccessTokenIntrospectResponse, AccessTokenRequest,
        AccessTokenResponse, AuthorisationRequest,
    },
    v1::{
        AuthAllowed, AuthCredential as ProtoAuthCredential, AuthIssueSession, AuthMech,
        AuthStep as ProtoAuthStep,
    },
};
use std::fmt;
use webauthn_rs::prelude::PublicKeyCredential;

#[derive(Debug)]
pub enum AuthStep {
    Init(String),
    Init2 {
        username: String,
        issue: AuthIssueSession,
        privileged: bool,
    },
    Begin(AuthMech),
    Cred(AuthCredential),
}

impl From<ProtoAuthStep> for AuthStep {
    fn from(proto: ProtoAuthStep) -> Self {
        match proto {
            ProtoAuthStep::Init(name) => Self::Init(name),
            ProtoAuthStep::Init2 {
                username,
                issue,
                privileged,
            } => Self::Init2 {
                username,
                issue,
                privileged,
            },
            ProtoAuthStep::Begin(mech) => Self::Begin(mech),
            ProtoAuthStep::Cred(proto_cred) => Self::Cred(AuthCredential::from(proto_cred)),
        }
    }
}

pub enum AuthExternal {
    OAuth2AuthorisationRequest {
        authorisation_url: Url,
        request: AuthorisationRequest,
    },
    OAuth2AccessTokenRequest {
        token_url: Url,
        client_id: String,
        client_secret: String,
        request: AccessTokenRequest,
    },
    OAuth2AccessTokenIntrospectionRequest {
        introspection_url: Url,
        client_id: String,
        client_secret: String,
        request: AccessTokenIntrospectRequest,
    },
}

impl fmt::Debug for AuthExternal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OAuth2AuthorisationRequest { .. } => write!(f, "OAuth2AuthorisationRequest"),
            Self::OAuth2AccessTokenRequest { .. } => write!(f, "OAuth2AccessTokenRequest"),
            Self::OAuth2AccessTokenIntrospectionRequest { .. } => {
                write!(f, "OAuth2AccessTokenIntrospectionRequest")
            }
        }
    }
}

// We have to allow large enum variant here because else we can't match on External
// due to boxing.
#[allow(clippy::large_enum_variant)]
pub enum AuthState {
    Choose(Vec<AuthMech>),
    Continue(Vec<AuthAllowed>),

    /// Execute an authentication flow via an external provider.
    /// For example, we may need to issue a redirect to an external OAuth2.
    /// provider, or we may need to do a background query of some kind to proceed.
    External(AuthExternal),
    /// Denied authentication, with a reason.
    Denied(String),
    Success(Box<JwsCompact>, AuthIssueSession),
}

impl fmt::Debug for AuthState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthState::Choose(mechs) => write!(f, "AuthState::Choose({mechs:?})"),
            AuthState::Continue(allow) => write!(f, "AuthState::Continue({allow:?})"),
            AuthState::External(allow) => write!(f, "AuthState::External({allow:?})"),
            AuthState::Denied(reason) => write!(f, "AuthState::Denied({reason:?})"),
            AuthState::Success(_token, issue) => {
                write!(f, "AuthState::Success({})", issue)
            }
        }
    }
}

pub enum AuthCredential {
    Anonymous,
    Password(String),
    Totp(u32),
    SecurityKey(Box<PublicKeyCredential>),
    BackupCode(String),
    Passkey(Box<PublicKeyCredential>),

    // Internal Credential Types
    OAuth2AuthorisationResponse {
        code: String,
        state: Option<String>,
    },
    OAuth2AccessTokenResponse {
        response: AccessTokenResponse,
    },
    OAuth2AccessTokenIntrospectResponse {
        response: AccessTokenIntrospectResponse,
    },
}

impl From<ProtoAuthCredential> for AuthCredential {
    fn from(proto: ProtoAuthCredential) -> Self {
        match proto {
            ProtoAuthCredential::Anonymous => AuthCredential::Anonymous,
            ProtoAuthCredential::Password(p) => AuthCredential::Password(p),
            ProtoAuthCredential::Totp(t) => AuthCredential::Totp(t),
            ProtoAuthCredential::SecurityKey(sk) => AuthCredential::SecurityKey(sk),
            ProtoAuthCredential::BackupCode(bc) => AuthCredential::BackupCode(bc),
            ProtoAuthCredential::Passkey(pkc) => AuthCredential::Passkey(pkc),
        }
    }
}

impl fmt::Debug for AuthCredential {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match self {
            AuthCredential::Anonymous => write!(fmt, "Anonymous"),
            AuthCredential::Password(_) => write!(fmt, "Password(_)"),
            AuthCredential::Totp(_) => write!(fmt, "TOTP(_)"),
            AuthCredential::SecurityKey(_) => write!(fmt, "SecurityKey(_)"),
            AuthCredential::BackupCode(_) => write!(fmt, "BackupCode(_)"),
            AuthCredential::Passkey(_) => write!(fmt, "Passkey(_)"),
            AuthCredential::OAuth2AuthorisationResponse { .. } => {
                write!(fmt, "OAuth2AuthorisationResponse{{..}}")
            }
            AuthCredential::OAuth2AccessTokenResponse { .. } => {
                write!(fmt, "OAuth2AccessTokenResponse{{..}}")
            }
            AuthCredential::OAuth2AccessTokenIntrospectResponse { .. } => {
                write!(fmt, "OAuth2AccessTokenIntrospectResponse{{..}}")
            }
        }
    }
}

#[derive(Default)]
pub enum ReauthRequest {
    #[default]
    VerifyCredentials,
    GrantReadWrite,
}

#[derive(Debug, Clone, Default)]
pub(crate) enum PreValidatedTokenStatus {
    #[default]
    None,
    Valid(Box<UserAuthToken>),
    NotAuthenticated,
    SessionExpired,
}

#[derive(Debug, Clone)]
pub struct ClientAuthInfo {
    pub(crate) source: Source,
    pub(crate) client_cert: Option<ClientCertInfo>,
    pub(crate) bearer_token_jws: Option<JwsCompact>,
    pub(crate) bearer_token_jwe: Option<JweCompact>,
    pub(crate) basic_authz: Option<String>,
    pub(crate) pre_validated_token: PreValidatedTokenStatus,
}

impl ClientAuthInfo {
    pub fn new(
        source: Source,
        client_cert: Option<ClientCertInfo>,
        bearer_token_jws: Option<JwsCompact>,
        bearer_token_jwe: Option<JweCompact>,
        basic_authz: Option<String>,
    ) -> Self {
        Self {
            source,
            client_cert,
            bearer_token_jws,
            bearer_token_jwe,
            basic_authz,
            pre_validated_token: Default::default(),
        }
    }

    pub fn bearer_token_jws(&self) -> Option<&JwsCompact> {
        self.bearer_token_jws.as_ref()
    }

    pub fn bearer_token_jwe(&self) -> Option<&JweCompact> {
        self.bearer_token_jwe.as_ref()
    }

    pub fn pre_validated_uat(&self) -> Result<&UserAuthToken, OperationError> {
        match &self.pre_validated_token {
            PreValidatedTokenStatus::Valid(uat) => Ok(uat),
            PreValidatedTokenStatus::None => Err(OperationError::AU0008ClientAuthInfoPrevalidation),
            PreValidatedTokenStatus::NotAuthenticated => Err(OperationError::NotAuthenticated),
            PreValidatedTokenStatus::SessionExpired => Err(OperationError::SessionExpired),
        }
    }

    pub(crate) fn set_pre_validated_uat(&mut self, status: PreValidatedTokenStatus) {
        self.pre_validated_token = status
    }
}

#[derive(Debug, Clone)]
pub struct ClientCertInfo {
    pub public_key_s256: Sha256Output,
    pub certificate: Certificate,
}

#[cfg(test)]
impl ClientAuthInfo {
    pub(crate) fn none() -> Self {
        ClientAuthInfo {
            source: Source::Internal,
            client_cert: None,
            bearer_token_jws: None,
            bearer_token_jwe: None,
            basic_authz: None,
            pre_validated_token: Default::default(),
        }
    }
}

#[cfg(test)]
impl From<Source> for ClientAuthInfo {
    fn from(value: Source) -> ClientAuthInfo {
        ClientAuthInfo {
            source: value,
            client_cert: None,
            bearer_token_jws: None,
            bearer_token_jwe: None,
            basic_authz: None,
            pre_validated_token: Default::default(),
        }
    }
}

#[cfg(test)]
impl From<JwsCompact> for ClientAuthInfo {
    fn from(value: JwsCompact) -> ClientAuthInfo {
        ClientAuthInfo {
            source: Source::Internal,
            client_cert: None,
            bearer_token_jws: Some(value),
            bearer_token_jwe: None,
            basic_authz: None,
            pre_validated_token: Default::default(),
        }
    }
}

#[cfg(test)]
impl From<JweCompact> for ClientAuthInfo {
    fn from(value: JweCompact) -> ClientAuthInfo {
        ClientAuthInfo {
            source: Source::Internal,
            client_cert: None,
            bearer_token_jws: None,
            bearer_token_jwe: Some(value),
            basic_authz: None,
            pre_validated_token: Default::default(),
        }
    }
}

#[cfg(test)]
impl From<ClientCertInfo> for ClientAuthInfo {
    fn from(value: ClientCertInfo) -> ClientAuthInfo {
        ClientAuthInfo {
            source: Source::Internal,
            client_cert: Some(value),
            bearer_token_jws: None,
            bearer_token_jwe: None,
            basic_authz: None,
            pre_validated_token: Default::default(),
        }
    }
}

#[cfg(test)]
impl From<&str> for ClientAuthInfo {
    fn from(value: &str) -> ClientAuthInfo {
        ClientAuthInfo {
            source: Source::Internal,
            client_cert: None,
            bearer_token_jws: None,
            bearer_token_jwe: None,
            basic_authz: Some(value.to_string()),
            pre_validated_token: Default::default(),
        }
    }
}

#[cfg(test)]
impl ClientAuthInfo {
    pub(crate) fn encode_basic(id: &str, secret: &str) -> ClientAuthInfo {
        use base64::{engine::general_purpose, Engine as _};
        let value = format!("{id}:{secret}");
        let value = general_purpose::STANDARD.encode(&value);
        ClientAuthInfo {
            source: Source::Internal,
            client_cert: None,
            bearer_token_jws: None,
            bearer_token_jwe: None,
            basic_authz: Some(value),
            pre_validated_token: Default::default(),
        }
    }
}
