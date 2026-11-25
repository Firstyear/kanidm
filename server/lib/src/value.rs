//! Inside an entry, the key-value pairs are stored in these [`Value`] types. The components of
//! the [`Value`] module allow storage and transformation of various types of input into strongly
//! typed values, allows their comparison, filtering and more. It also has the code for serialising
//! these into a form for the backend that can be persistent into the [`Backend`](crate::be::Backend).

use crate::{
    be::{dbentry::DbIdentSpn, dbvalue::DbValueOauthClaimMapJoinV1},
    credential::{apppwd::ApplicationPassword, totp::Totp, Credential},
    prelude::*,
    repl::cid::Cid,
    server::{identity::IdentityId, keys::KeyId},
    valueset::{image::ImageValueThings, uuid_to_proto_string},
};
use compact_jwt::{crypto::JwsRs256Signer, JwsEs256Signer};
use crypto_glue::{
    s256::Sha256Output,
    traits::{DecodePem, Zeroizing},
    x509::Certificate,
};
use hashbrown::HashSet;
use kanidm_proto::{
    internal::{ApiTokenPurpose, Filter as ProtoFilter, ImageValue, UiHint},
    scim_v1::ScimOauth2ClaimMapJoinChar,
    v1::UatPurposeStatus,
};
use num_enum::TryFromPrimitive;
use regex::Regex;
use serde::{Deserialize, Serialize};
use sshkey_attest::proto::PublicKey as SshPublicKey;
use std::{
    cmp::Ordering, collections::BTreeSet, convert::TryFrom, fmt, fmt::Formatter, hash::Hash,
    str::FromStr, time::Duration,
};
use time::OffsetDateTime;
use url::Url;
use uuid::Uuid;
use webauthn_rs::prelude::{
    AttestationCaList, AttestedPasskey as AttestedPasskeyV4, Passkey as PasskeyV4,
};

#[cfg(test)]
use base64::{engine::general_purpose, Engine as _};

pub static SPN_RE: LazyLock<Regex> = LazyLock::new(|| {
    #[allow(clippy::expect_used)]
    Regex::new("(?P<name>[^@]+)@(?P<realm>[^@]+)").expect("Invalid SPN regex found")
});

pub static DISALLOWED_NAMES: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    // Most of these were removed in favour of the unixd daemon filtering out
    // local users instead.
    let mut m = HashSet::with_capacity(2);
    m.insert("root");
    m.insert("dn=token");
    m
});

/// Only lowercase+numbers, with limited chars.
pub static INAME_RE: LazyLock<Regex> = LazyLock::new(|| {
    #[allow(clippy::expect_used)]
    Regex::new("^[a-z][a-z0-9-_\\.]{0,63}$").expect("Invalid Iname regex found")
});

/// Only alpha-numeric with limited special chars and space
pub static LABEL_RE: LazyLock<Regex> = LazyLock::new(|| {
    #[allow(clippy::expect_used)]
    Regex::new("^[a-zA-Z0-9][ a-zA-Z0-9-_\\.@]{0,63}$").expect("Invalid Iname regex found")
});

/// Only lowercase+numbers, with limited chars.
pub static HEXSTR_RE: LazyLock<Regex> = LazyLock::new(|| {
    #[allow(clippy::expect_used)]
    Regex::new("^[a-f0-9]+$").expect("Invalid hexstring regex found")
});

pub static EXTRACT_VAL_DN: LazyLock<Regex> = LazyLock::new(|| {
    #[allow(clippy::expect_used)]
    Regex::new("^(([^=,]+)=)?(?P<val>[^=,]+)").expect("extract val from dn regex")
});

pub static NSUNIQUEID_RE: LazyLock<Regex> = LazyLock::new(|| {
    #[allow(clippy::expect_used)]
    Regex::new("^[0-9a-fA-F]{8}-[0-9a-fA-F]{8}-[0-9a-fA-F]{8}-[0-9a-fA-F]{8}$")
        .expect("Invalid Nsunique regex found")
});

/// Must not contain whitespace.
pub static OAUTHSCOPE_RE: LazyLock<Regex> = LazyLock::new(|| {
    #[allow(clippy::expect_used)]
    Regex::new("^[0-9a-zA-Z_]+(([:\\-.]|(://))[0-9a-zA-Z_]+)*$")
        .expect("Invalid oauthscope regex found")
});

/// Must not contain whitespace. Allows "abcd", "abcd:efgh", but ":" and "-" need to be separating
/// groups of characters, and are not able to be leading or trailing.
pub static OAUTH_CLAIMNAME_RE: LazyLock<Regex> = LazyLock::new(|| {
    #[allow(clippy::expect_used)]
    Regex::new("^[0-9a-zA-Z_]+([:\\-][0-9a-zA-Z_]+)*$").expect("Invalid oauth claim regex found")
});

pub static SINGLELINE_RE: LazyLock<Regex> = LazyLock::new(|| {
    #[allow(clippy::expect_used)]
    Regex::new("[\n\r\t]").expect("Invalid singleline regex found")
});

/// Per <https://html.spec.whatwg.org/multipage/input.html#valid-e-mail-address>
/// this regex validates for valid emails.
pub static VALIDATE_EMAIL_RE: LazyLock<Regex> = LazyLock::new(|| {
    #[allow(clippy::expect_used)]
        Regex::new(r"^[a-zA-Z0-9.!#$%&'*+\/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")
            .expect("Invalid singleline regex found")
});

pub static UNICODE_CONTROL_RE: LazyLock<Regex> = LazyLock::new(|| {
    #[allow(clippy::expect_used)]
    Regex::new(r"[[:cntrl:]]").expect("Invalid unicode control regex found")
});

#[derive(Debug, Clone, PartialOrd, Ord, Eq, PartialEq, Hash)]
/// Per <https://openid.net/specs/openid-connect-core-1_0.html#AddressClaim>
pub struct Address {
    pub formatted: String,
    pub street_address: String,
    pub locality: String,
    pub region: String,
    pub postal_code: String,
    // Must be validated.
    pub country: String,
}
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct CredUpdateSessionPerms {
    pub ext_cred_portal_can_view: bool,
    pub primary_can_edit: bool,
    pub passkeys_can_edit: bool,
    pub attested_passkeys_can_edit: bool,
    pub unixcred_can_edit: bool,
    pub sshpubkey_can_edit: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntentTokenState {
    Valid {
        max_ttl: Duration,
        perms: CredUpdateSessionPerms,
    },
    InProgress {
        max_ttl: Duration,
        perms: CredUpdateSessionPerms,
        session_id: Uuid,
        session_ttl: Duration,
    },
    Consumed {
        max_ttl: Duration,
    },
}

#[allow(non_camel_case_types)]
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Deserialize,
    Serialize,
    Hash,
    TryFromPrimitive,
)]
#[repr(u16)]
pub enum IndexType {
    Equality,
    Presence,
    SubString,
    Ordering,
}

impl TryFrom<&str> for IndexType {
    type Error = ();

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let n_value = value.to_uppercase();
        match n_value.as_str() {
            "EQUALITY" => Ok(IndexType::Equality),
            "PRESENCE" => Ok(IndexType::Presence),
            "SUBSTRING" => Ok(IndexType::SubString),
            "ORDERING" => Ok(IndexType::Ordering),
            // UUID map?
            // UUID rev map?
            _ => Err(()),
        }
    }
}

impl IndexType {
    pub fn as_idx_str(&self) -> &str {
        match self {
            IndexType::Equality => "eq",
            IndexType::Presence => "pres",
            IndexType::SubString => "sub",
            IndexType::Ordering => "ord",
        }
    }
}

impl fmt::Display for IndexType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                IndexType::Equality => "EQUALITY",
                IndexType::Presence => "PRESENCE",
                IndexType::SubString => "SUBSTRING",
                IndexType::Ordering => "ORDERING",
            }
        )
    }
}

#[allow(non_camel_case_types)]
#[allow(clippy::derived_hash_with_manual_eq)]
#[derive(
    Hash,
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Deserialize,
    Serialize,
    TryFromPrimitive,
    Default,
)]
#[repr(u16)]
pub enum SyntaxType {
    #[default]
    Utf8String = 0,
    Utf8StringInsensitive = 1,
    Uuid = 2,
    Boolean = 3,
    SyntaxId = 4,
    IndexId = 5,
    ReferenceUuid = 6,
    JsonFilter = 7,
    Credential = 8,
    SecretUtf8String = 9,
    SshKey = 10,
    SecurityPrincipalName = 11,
    Uint32 = 12,
    Cid = 13,
    Utf8StringIname = 14,
    NsUniqueId = 15,
    DateTime = 16,
    EmailAddress = 17,
    Url = 18,
    OauthScope = 19,
    OauthScopeMap = 20,
    PrivateBinary = 21,
    IntentToken = 22,
    Passkey = 23,
    AttestedPasskey = 24,
    Session = 25,
    JwsKeyEs256 = 26,
    JwsKeyRs256 = 27,
    Oauth2Session = 28,
    UiHint = 29,
    TotpSecret = 30,
    ApiToken = 31,
    AuditLogString = 32,
    EcKeyPrivate = 33,
    Image = 34,
    CredentialType = 35,
    WebauthnAttestationCaList = 36,
    OauthClaimMap = 37,
    KeyInternal = 38,
    HexString = 39,
    Certificate = 40,
    ApplicationPassword = 41,
    Json = 42,
    Message = 43,
    Sha256 = 44,
    Int64 = 45,
    Uint64 = 46,

    UuidN = 47,
    Utf8StringInsensitiveN = 48,
    ReferenceUuidN = 49,
    Utf8StringInameN = 50,
    UrlN = 51,
}

impl TryFrom<&str> for SyntaxType {
    type Error = ();

    fn try_from(value: &str) -> Result<SyntaxType, Self::Error> {
        let n_value = value.to_uppercase();
        match n_value.as_str() {
            "UTF8STRING" => Ok(SyntaxType::Utf8String),
            "UTF8STRING_INSENSITIVE" => Ok(SyntaxType::Utf8StringInsensitive),
            "UTF8STRING_INAME" => Ok(SyntaxType::Utf8StringIname),
            "UUID" => Ok(SyntaxType::Uuid),
            "UUID_MULTI" => Ok(SyntaxType::UuidN),
            "BOOLEAN" => Ok(SyntaxType::Boolean),
            "SYNTAX_ID" => Ok(SyntaxType::SyntaxId),
            "INDEX_ID" => Ok(SyntaxType::IndexId),
            "REFERENCE_UUID" => Ok(SyntaxType::ReferenceUuid),
            "JSON_FILTER" => Ok(SyntaxType::JsonFilter),
            "CREDENTIAL" => Ok(SyntaxType::Credential),
            // Compatibility for older syntax name.
            "RADIUS_UTF8STRING" | "SECRET_UTF8STRING" => Ok(SyntaxType::SecretUtf8String),
            "SSHKEY" => Ok(SyntaxType::SshKey),
            "SECURITY_PRINCIPAL_NAME" => Ok(SyntaxType::SecurityPrincipalName),
            "UINT32" => Ok(SyntaxType::Uint32),
            "CID" => Ok(SyntaxType::Cid),
            "NSUNIQUEID" => Ok(SyntaxType::NsUniqueId),
            "DATETIME" => Ok(SyntaxType::DateTime),
            "EMAIL_ADDRESS" => Ok(SyntaxType::EmailAddress),
            "URL" => Ok(SyntaxType::Url),
            "OAUTH_SCOPE" => Ok(SyntaxType::OauthScope),
            "OAUTH_SCOPE_MAP" => Ok(SyntaxType::OauthScopeMap),
            "PRIVATE_BINARY" => Ok(SyntaxType::PrivateBinary),
            "INTENT_TOKEN" => Ok(SyntaxType::IntentToken),
            "PASSKEY" => Ok(SyntaxType::Passkey),
            "ATTESTED_PASSKEY" => Ok(SyntaxType::AttestedPasskey),
            "SESSION" => Ok(SyntaxType::Session),
            "JWS_KEY_ES256" => Ok(SyntaxType::JwsKeyEs256),
            "JWS_KEY_RS256" => Ok(SyntaxType::JwsKeyRs256),
            "OAUTH2SESSION" => Ok(SyntaxType::Oauth2Session),
            "UIHINT" => Ok(SyntaxType::UiHint),
            "TOTPSECRET" => Ok(SyntaxType::TotpSecret),
            "APITOKEN" => Ok(SyntaxType::ApiToken),
            "AUDIT_LOG_STRING" => Ok(SyntaxType::AuditLogString),
            "EC_KEY_PRIVATE" => Ok(SyntaxType::EcKeyPrivate),
            "CREDENTIAL_TYPE" => Ok(SyntaxType::CredentialType),
            "WEBAUTHN_ATTESTATION_CA_LIST" => Ok(SyntaxType::WebauthnAttestationCaList),
            "OAUTH_CLAIM_MAP" => Ok(SyntaxType::OauthClaimMap),
            "KEY_INTERNAL" => Ok(SyntaxType::KeyInternal),
            "HEX_STRING" => Ok(SyntaxType::HexString),
            "CERTIFICATE" => Ok(SyntaxType::Certificate),
            "APPLICATION_PASSWORD" => Ok(SyntaxType::ApplicationPassword),
            "JSON" => Ok(SyntaxType::Json),
            "MESSAGE" => Ok(SyntaxType::Message),
            "SHA256" => Ok(SyntaxType::Sha256),
            "INT64" => Ok(SyntaxType::Int64),
            "UINT64" => Ok(SyntaxType::Uint64),

            "UTF8STRING_INSENSITIVE_MULTI" => Ok(SyntaxType::Utf8StringInsensitiveN),
            "REFERENCE_UUID_MULTI" => Ok(SyntaxType::ReferenceUuidN),
            "UTF8STRING_INAME_MULTI" => Ok(SyntaxType::Utf8StringInameN),
            "URL_MULTI" => Ok(SyntaxType::UrlN),

            _ => Err(()),
        }
    }
}

impl fmt::Display for SyntaxType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(match self {
            SyntaxType::Utf8String => "UTF8STRING",
            SyntaxType::Utf8StringInsensitive => "UTF8STRING_INSENSITIVE",
            SyntaxType::Utf8StringIname => "UTF8STRING_INAME",
            SyntaxType::Uuid => "UUID",
            SyntaxType::UuidN => "UUID_MULTI",
            SyntaxType::Boolean => "BOOLEAN",
            SyntaxType::SyntaxId => "SYNTAX_ID",
            SyntaxType::IndexId => "INDEX_ID",
            SyntaxType::ReferenceUuid => "REFERENCE_UUID",
            SyntaxType::JsonFilter => "JSON_FILTER",
            SyntaxType::Credential => "CREDENTIAL",
            SyntaxType::SecretUtf8String => "SECRET_UTF8STRING",
            SyntaxType::SshKey => "SSHKEY",
            SyntaxType::SecurityPrincipalName => "SECURITY_PRINCIPAL_NAME",
            SyntaxType::Uint32 => "UINT32",
            SyntaxType::Cid => "CID",
            SyntaxType::NsUniqueId => "NSUNIQUEID",
            SyntaxType::DateTime => "DATETIME",
            SyntaxType::EmailAddress => "EMAIL_ADDRESS",
            SyntaxType::Url => "URL",
            SyntaxType::OauthScope => "OAUTH_SCOPE",
            SyntaxType::OauthScopeMap => "OAUTH_SCOPE_MAP",
            SyntaxType::PrivateBinary => "PRIVATE_BINARY",
            SyntaxType::IntentToken => "INTENT_TOKEN",
            SyntaxType::Passkey => "PASSKEY",
            SyntaxType::AttestedPasskey => "ATTESTED_PASSKEY",
            SyntaxType::Session => "SESSION",
            SyntaxType::JwsKeyEs256 => "JWS_KEY_ES256",
            SyntaxType::JwsKeyRs256 => "JWS_KEY_RS256",
            SyntaxType::Oauth2Session => "OAUTH2SESSION",
            SyntaxType::UiHint => "UIHINT",
            SyntaxType::TotpSecret => "TOTPSECRET",
            SyntaxType::ApiToken => "APITOKEN",
            SyntaxType::AuditLogString => "AUDIT_LOG_STRING",
            SyntaxType::EcKeyPrivate => "EC_KEY_PRIVATE",
            SyntaxType::Image => "IMAGE",
            SyntaxType::CredentialType => "CREDENTIAL_TYPE",
            SyntaxType::WebauthnAttestationCaList => "WEBAUTHN_ATTESTATION_CA_LIST",
            SyntaxType::OauthClaimMap => "OAUTH_CLAIM_MAP",
            SyntaxType::KeyInternal => "KEY_INTERNAL",
            SyntaxType::HexString => "HEX_STRING",
            SyntaxType::Certificate => "CERTIFICATE",
            SyntaxType::ApplicationPassword => "APPLICATION_PASSWORD",
            SyntaxType::Json => "JSON",
            SyntaxType::Message => "MESSAGE",
            SyntaxType::Sha256 => "SHA256",
            SyntaxType::Int64 => "INT64",
            SyntaxType::Uint64 => "UINT64",

            SyntaxType::Utf8StringInsensitiveN => "UTF8STRING_INSENSITIVE_MULTI",
            SyntaxType::ReferenceUuidN => "REFERENCE_UUID_MULTI",
            SyntaxType::Utf8StringInameN => "UTF8STRING_INAME_MULTI",
            SyntaxType::UrlN => "URL_MULTI",
        })
    }
}

impl SyntaxType {
    pub fn index_types(&self) -> &[IndexType] {
        match self {
            SyntaxType::Utf8String => &[IndexType::Equality, IndexType::Presence],
            // Used by classes, needs to change ...
            // Probably need an attrname syntax too
            SyntaxType::Utf8StringInsensitiveN | SyntaxType::Utf8StringInsensitive => {
                &[IndexType::Equality, IndexType::Presence]
            }
            SyntaxType::Utf8StringInameN | SyntaxType::Utf8StringIname => &[
                IndexType::Equality,
                IndexType::Presence,
                IndexType::SubString,
            ],
            SyntaxType::Uuid | SyntaxType::UuidN => &[IndexType::Equality, IndexType::Presence],
            SyntaxType::Boolean => &[IndexType::Equality],
            SyntaxType::ReferenceUuidN | SyntaxType::ReferenceUuid => {
                &[IndexType::Equality, IndexType::Presence]
            }
            SyntaxType::Credential => &[IndexType::Equality],
            SyntaxType::SshKey => &[IndexType::Equality, IndexType::Presence],
            SyntaxType::SecurityPrincipalName => &[
                IndexType::Equality,
                IndexType::Presence,
                IndexType::SubString,
            ],
            SyntaxType::Uint32 | SyntaxType::Int64 | SyntaxType::Uint64 => &[
                IndexType::Equality,
                IndexType::Presence,
                IndexType::Ordering,
            ],
            SyntaxType::Cid => &[
                IndexType::Equality,
                IndexType::Presence,
                IndexType::Ordering,
            ],
            SyntaxType::NsUniqueId => &[IndexType::Equality, IndexType::Presence],
            SyntaxType::DateTime => &[
                IndexType::Equality,
                IndexType::Presence,
                IndexType::Ordering,
            ],
            SyntaxType::EmailAddress => &[IndexType::Equality, IndexType::SubString],
            SyntaxType::OauthScopeMap => &[IndexType::Equality],
            SyntaxType::IntentToken => &[IndexType::Equality],
            SyntaxType::Passkey => &[IndexType::Equality],
            SyntaxType::AttestedPasskey => &[IndexType::Equality],
            SyntaxType::Session => &[IndexType::Equality],
            SyntaxType::Oauth2Session => &[IndexType::Equality],
            SyntaxType::ApiToken => &[IndexType::Equality],
            SyntaxType::OauthClaimMap => &[IndexType::Equality],
            SyntaxType::ApplicationPassword => &[IndexType::Equality],
            SyntaxType::Sha256 => &[IndexType::Equality],
            SyntaxType::SecretUtf8String => &[],
            SyntaxType::UrlN => &[],
            SyntaxType::Url => &[],
            SyntaxType::OauthScope => &[],
            SyntaxType::PrivateBinary => &[],
            SyntaxType::JwsKeyEs256 => &[],
            SyntaxType::JwsKeyRs256 => &[],
            SyntaxType::UiHint => &[],
            SyntaxType::TotpSecret => &[],
            SyntaxType::AuditLogString => &[],
            SyntaxType::EcKeyPrivate => &[],
            SyntaxType::Image => &[],
            SyntaxType::CredentialType => &[],
            SyntaxType::WebauthnAttestationCaList => &[],
            SyntaxType::KeyInternal => &[],
            SyntaxType::HexString => &[],
            SyntaxType::Certificate => &[],
            SyntaxType::SyntaxId => &[],
            SyntaxType::IndexId => &[],
            SyntaxType::JsonFilter => &[],
            SyntaxType::Json => &[],
            SyntaxType::Message => &[],
        }
    }
}

#[derive(
    Hash,
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Deserialize,
    Serialize,
    TryFromPrimitive,
    Default,
)]
#[repr(u16)]
pub enum CredentialType {
    Any = 0,
    /// Since we have no control over external authentication providers, we need
    /// to rank these below our own authentication methods.
    External = 5,
    #[default]
    Mfa = 10,
    Passkey = 20,
    AttestedPasskey = 30,
    AttestedResidentkey = 40,
    Invalid = u16::MAX,
}

impl TryFrom<&str> for CredentialType {
    type Error = ();

    fn try_from(value: &str) -> Result<CredentialType, Self::Error> {
        match value {
            "any" => Ok(CredentialType::Any),
            "external" => Ok(CredentialType::External),
            "mfa" => Ok(CredentialType::Mfa),
            "passkey" => Ok(CredentialType::Passkey),
            "attested_passkey" => Ok(CredentialType::AttestedPasskey),
            "attested_residentkey" => Ok(CredentialType::AttestedResidentkey),
            "invalid" => Ok(CredentialType::Invalid),
            _ => Err(()),
        }
    }
}

impl fmt::Display for CredentialType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(match self {
            CredentialType::Any => "any",
            CredentialType::External => "external",
            CredentialType::Mfa => "mfa",
            CredentialType::Passkey => "passkey",
            CredentialType::AttestedPasskey => "attested_passkey",
            CredentialType::AttestedResidentkey => "attested_residentkey",
            CredentialType::Invalid => "invalid",
        })
    }
}

impl From<CredentialType> for Value {
    fn from(ct: CredentialType) -> Value {
        Value::CredentialType(ct)
    }
}

impl From<CredentialType> for PartialValue {
    fn from(ct: CredentialType) -> PartialValue {
        PartialValue::CredentialType(ct)
    }
}

impl From<Attribute> for PartialValue {
    fn from(attr: Attribute) -> PartialValue {
        let s: &str = attr.as_str();
        PartialValue::new_iutf8(s)
    }
}

/// A partial value is a key or key subset that can be used to match for equality or substring
/// against a complete Value within a set in an Entry.
///
/// A partialValue is typically used when you need to match against a value, but without
/// requiring all of its data or expression. This is common in Filters or other direct
/// lookups and requests.
#[derive(Hash, Debug, Clone, Eq, Ord, PartialOrd, PartialEq, Deserialize, Serialize)]
pub enum PartialValue {
    Utf8(String),
    Iutf8(String),
    Iname(String),
    Uuid(Uuid),
    Bool(bool),
    Syntax(SyntaxType),
    Index(IndexType),
    Refer(Uuid),
    // Does this make sense?
    // TODO: We'll probably add tagging to this type for the partial matching
    JsonFilt(ProtoFilter),
    // Tag, matches to a DataValue.
    Cred(String),
    SshKey(String),
    SecretValue,
    Spn(String, String),
    Uint32(u32),
    Cid(Cid),
    Nsuniqueid(String),
    DateTime(OffsetDateTime),
    EmailAddress(String),
    PhoneNumber(String),
    Address(String),
    // Can add other selectors later.
    Url(Url),
    OauthScope(String),
    PrivateBinary,
    PublicBinary(String),
    IntentToken(String),
    UiHint(UiHint),
    Passkey(Uuid),
    AttestedPasskey(Uuid),
    /// We compare on the value hash
    Image(String),
    CredentialType(CredentialType),

    OauthClaim(String, Uuid),
    OauthClaimValue(String, Uuid, String),

    HexString(String),
    Json,
    Sha256(Sha256Output),
    Int64(i64),
    Uint64(u64),
}

impl From<SyntaxType> for PartialValue {
    fn from(s: SyntaxType) -> Self {
        PartialValue::Syntax(s)
    }
}

impl From<IndexType> for PartialValue {
    fn from(i: IndexType) -> Self {
        PartialValue::Index(i)
    }
}

impl From<bool> for PartialValue {
    fn from(b: bool) -> Self {
        PartialValue::Bool(b)
    }
}

impl From<&bool> for PartialValue {
    fn from(b: &bool) -> Self {
        PartialValue::Bool(*b)
    }
}

impl From<ProtoFilter> for PartialValue {
    fn from(i: ProtoFilter) -> Self {
        PartialValue::JsonFilt(i)
    }
}

impl From<u32> for PartialValue {
    fn from(i: u32) -> Self {
        PartialValue::Uint32(i)
    }
}

impl From<OffsetDateTime> for PartialValue {
    fn from(i: OffsetDateTime) -> Self {
        PartialValue::DateTime(i)
    }
}

impl From<Url> for PartialValue {
    fn from(i: Url) -> Self {
        PartialValue::Url(i)
    }
}

impl From<Sha256Output> for PartialValue {
    fn from(i: Sha256Output) -> Self {
        PartialValue::Sha256(i)
    }
}

impl PartialValue {
    pub fn new_utf8(s: String) -> Self {
        PartialValue::Utf8(s)
    }

    pub fn new_utf8s(s: &str) -> Self {
        PartialValue::Utf8(s.to_string())
    }

    pub fn is_utf8(&self) -> bool {
        matches!(self, PartialValue::Utf8(_))
    }

    pub fn new_iutf8(s: &str) -> Self {
        PartialValue::Iutf8(s.to_lowercase())
    }

    pub fn new_iname(s: &str) -> Self {
        PartialValue::Iname(s.to_lowercase())
    }

    pub fn is_iutf8(&self) -> bool {
        matches!(self, PartialValue::Iutf8(_))
    }

    pub fn is_iname(&self) -> bool {
        matches!(self, PartialValue::Iname(_))
    }

    pub const fn new_bool(b: bool) -> Self {
        PartialValue::Bool(b)
    }

    pub fn new_bools(s: &str) -> Option<Self> {
        bool::from_str(s).map(PartialValue::Bool).ok()
    }

    pub fn is_bool(&self) -> bool {
        matches!(self, PartialValue::Bool(_))
    }

    pub fn new_uuid_s(us: &str) -> Option<Self> {
        Uuid::parse_str(us).map(PartialValue::Uuid).ok()
    }

    pub fn is_uuid(&self) -> bool {
        matches!(self, PartialValue::Uuid(_))
    }

    pub fn new_refer_s(us: &str) -> Option<Self> {
        match Uuid::parse_str(us) {
            Ok(u) => Some(PartialValue::Refer(u)),
            Err(_) => None,
        }
    }

    pub fn is_refer(&self) -> bool {
        matches!(self, PartialValue::Refer(_))
    }

    pub fn new_indexes(s: &str) -> Option<Self> {
        IndexType::try_from(s).map(PartialValue::Index).ok()
    }

    pub fn is_index(&self) -> bool {
        matches!(self, PartialValue::Index(_))
    }

    pub fn new_syntaxs(s: &str) -> Option<Self> {
        SyntaxType::try_from(s).map(PartialValue::Syntax).ok()
    }

    pub fn is_syntax(&self) -> bool {
        matches!(self, PartialValue::Syntax(_))
    }

    pub fn new_json_filter_s(s: &str) -> Option<Self> {
        serde_json::from_str(s)
            .map(PartialValue::JsonFilt)
            .map_err(|e| {
                trace!(?e, ?s);
            })
            .ok()
    }

    pub fn is_json_filter(&self) -> bool {
        matches!(self, PartialValue::JsonFilt(_))
    }

    pub fn new_credential_tag(s: &str) -> Self {
        PartialValue::Cred(s.to_lowercase())
    }

    pub fn is_credential(&self) -> bool {
        matches!(self, PartialValue::Cred(_))
    }

    pub fn new_secret_str() -> Self {
        PartialValue::SecretValue
    }

    pub fn is_secret_string(&self) -> bool {
        matches!(self, PartialValue::SecretValue)
    }

    pub fn new_sshkey_tag(s: String) -> Self {
        PartialValue::SshKey(s)
    }

    pub fn new_sshkey_tag_s(s: &str) -> Self {
        PartialValue::SshKey(s.to_string())
    }

    pub fn is_sshkey(&self) -> bool {
        matches!(self, PartialValue::SshKey(_))
    }

    pub fn new_spn_s(s: &str) -> Option<Self> {
        SPN_RE.captures(s).and_then(|caps| {
            let name = match caps.name(Attribute::Name.as_ref()) {
                Some(v) => v.as_str().to_string(),
                None => return None,
            };
            let realm = match caps.name("realm") {
                Some(v) => v.as_str().to_string(),
                None => return None,
            };
            Some(PartialValue::Spn(name, realm))
        })
    }

    pub fn new_spn_nrs(n: &str, r: &str) -> Self {
        PartialValue::Spn(n.to_string(), r.to_string())
    }

    pub fn is_spn(&self) -> bool {
        matches!(self, PartialValue::Spn(_, _))
    }

    pub fn new_uint32(u: u32) -> Self {
        PartialValue::Uint32(u)
    }

    pub fn new_uint32_str(u: &str) -> Option<Self> {
        u.parse::<u32>().ok().map(PartialValue::Uint32)
    }

    pub fn new_int64_str(u: &str) -> Option<Self> {
        u.parse::<i64>().ok().map(PartialValue::Int64)
    }

    pub fn new_uint64_str(u: &str) -> Option<Self> {
        u.parse::<u64>().ok().map(PartialValue::Uint64)
    }

    pub fn is_uint32(&self) -> bool {
        matches!(self, PartialValue::Uint32(_))
    }

    pub fn new_cid(c: Cid) -> Self {
        PartialValue::Cid(c)
    }

    pub fn new_cid_s(_c: &str) -> Option<Self> {
        None
    }

    pub fn is_cid(&self) -> bool {
        matches!(self, PartialValue::Cid(_))
    }

    pub fn new_nsuniqueid_s(s: &str) -> Self {
        PartialValue::Nsuniqueid(s.to_lowercase())
    }

    pub fn is_nsuniqueid(&self) -> bool {
        matches!(self, PartialValue::Nsuniqueid(_))
    }

    pub fn new_datetime_epoch(ts: Duration) -> Self {
        PartialValue::DateTime(OffsetDateTime::UNIX_EPOCH + ts)
    }

    pub fn new_datetime_s(s: &str) -> Option<Self> {
        OffsetDateTime::parse(s, &Rfc3339)
            .ok()
            .map(|odt| odt.to_offset(time::UtcOffset::UTC))
            .map(PartialValue::DateTime)
    }

    pub fn is_datetime(&self) -> bool {
        matches!(self, PartialValue::DateTime(_))
    }

    pub fn new_email_address_s(s: &str) -> Self {
        PartialValue::EmailAddress(s.to_string())
    }

    pub fn is_email_address(&self) -> bool {
        matches!(self, PartialValue::EmailAddress(_))
    }

    pub fn new_phonenumber_s(s: &str) -> Self {
        PartialValue::PhoneNumber(s.to_string())
    }

    pub fn new_address(s: &str) -> Self {
        PartialValue::Address(s.to_string())
    }

    pub fn new_url_s(s: &str) -> Option<Self> {
        Url::parse(s).ok().map(PartialValue::Url)
    }

    pub fn is_url(&self) -> bool {
        matches!(self, PartialValue::Url(_))
    }

    pub fn new_oauthscope(s: &str) -> Self {
        PartialValue::OauthScope(s.to_string())
    }

    pub fn is_oauthscope(&self) -> bool {
        matches!(self, PartialValue::OauthScope(_))
    }

    pub fn is_privatebinary(&self) -> bool {
        matches!(self, PartialValue::PrivateBinary)
    }

    pub fn new_publicbinary_tag_s(s: &str) -> Self {
        PartialValue::PublicBinary(s.to_string())
    }

    pub fn new_intenttoken_s(s: String) -> Option<Self> {
        Some(PartialValue::IntentToken(s))
    }

    pub fn new_passkey_s(us: &str) -> Option<Self> {
        Uuid::parse_str(us).map(PartialValue::Passkey).ok()
    }

    pub fn new_attested_passkey_s(us: &str) -> Option<Self> {
        Uuid::parse_str(us).map(PartialValue::AttestedPasskey).ok()
    }

    pub fn new_hex_string_s(hexstr: &str) -> Option<Self> {
        let hexstr_lower = hexstr.to_lowercase();
        if HEXSTR_RE.is_match(&hexstr_lower) {
            Some(PartialValue::HexString(hexstr_lower))
        } else {
            None
        }
    }

    pub fn new_image(input: &str) -> Self {
        PartialValue::Image(input.to_string())
    }

    pub fn to_str(&self) -> Option<&str> {
        match self {
            PartialValue::Utf8(s) => Some(s.as_str()),
            PartialValue::Iutf8(s) => Some(s.as_str()),
            PartialValue::Iname(s) => Some(s.as_str()),
            _ => None,
        }
    }

    pub fn to_url(&self) -> Option<&Url> {
        match self {
            PartialValue::Url(u) => Some(u),
            _ => None,
        }
    }

    pub fn get_idx_eq_key(&self) -> String {
        match self {
            PartialValue::Utf8(s)
            | PartialValue::Iutf8(s)
            | PartialValue::Iname(s)
            | PartialValue::Nsuniqueid(s)
            | PartialValue::EmailAddress(s) => s.clone(),
            PartialValue::Passkey(u)
            | PartialValue::AttestedPasskey(u)
            | PartialValue::Refer(u)
            | PartialValue::Uuid(u) => u.as_hyphenated().to_string(),
            PartialValue::Bool(b) => b.to_string(),
            PartialValue::Syntax(syn) => syn.to_string(),
            PartialValue::Index(it) => it.to_string(),
            PartialValue::JsonFilt(s) =>
            {
                #[allow(clippy::expect_used)]
                serde_json::to_string(s).expect("A json filter value was corrupted during run-time")
            }
            PartialValue::Cred(tag)
            | PartialValue::PublicBinary(tag)
            | PartialValue::SshKey(tag) => tag.to_string(),
            // This will never match as we never index radius creds! See generate_idx_eq_keys
            PartialValue::SecretValue | PartialValue::PrivateBinary => "_".to_string(),
            PartialValue::Spn(name, realm) => format!("{name}@{realm}"),
            PartialValue::Uint32(u) => u.to_string(),
            PartialValue::Int64(u) => u.to_string(),
            PartialValue::Uint64(u) => u.to_string(),
            PartialValue::DateTime(odt) => {
                debug_assert_eq!(odt.offset(), time::UtcOffset::UTC);
                #[allow(clippy::expect_used)]
                odt.format(&Rfc3339)
                    .expect("Failed to format timestamp into RFC3339")
            }
            PartialValue::Url(u) => u.to_string(),
            PartialValue::OauthScope(u) => u.to_string(),
            PartialValue::Address(a) => a.to_string(),
            PartialValue::PhoneNumber(a) => a.to_string(),
            PartialValue::IntentToken(u) => u.clone(),
            PartialValue::UiHint(u) => (*u as u16).to_string(),
            PartialValue::Image(imagehash) => imagehash.to_owned(),
            PartialValue::CredentialType(ct) => ct.to_string(),
            // This will never work, we don't allow equality searching on Cid's
            PartialValue::Cid(_) => "_".to_string(),
            // We don't allow searching on claim/uuid pairs.
            PartialValue::OauthClaim(_, _) => "_".to_string(),
            PartialValue::OauthClaimValue(_, _, _) => "_".to_string(),
            PartialValue::HexString(hexstr) => hexstr.to_string(),
            PartialValue::Json => "_".to_string(),
            PartialValue::Sha256(bytes) => hex::encode(bytes),
        }
    }

    pub fn get_idx_sub_key(&self) -> Option<String> {
        match self {
            PartialValue::Utf8(s)
            | PartialValue::Iutf8(s)
            | PartialValue::Iname(s)
            // | PartialValue::Nsuniqueid(s)
            | PartialValue::EmailAddress(s) => Some(s.to_lowercase()),

            PartialValue::Cred(tag)
            | PartialValue::PublicBinary(tag)
            | PartialValue::SshKey(tag) => Some(tag.to_lowercase()),

            // PartialValue::Spn(name, realm) => format!("{name}@{realm}"),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApiTokenScope {
    ReadOnly,
    ReadWrite,
    Synchronise,
}

impl fmt::Display for ApiTokenScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ApiTokenScope::ReadOnly => write!(f, "read_only"),
            ApiTokenScope::ReadWrite => write!(f, "read_write"),
            ApiTokenScope::Synchronise => write!(f, "synchronise"),
        }
    }
}

impl TryInto<ApiTokenPurpose> for ApiTokenScope {
    type Error = OperationError;

    fn try_into(self: ApiTokenScope) -> Result<ApiTokenPurpose, OperationError> {
        match self {
            ApiTokenScope::ReadOnly => Ok(ApiTokenPurpose::ReadOnly),
            ApiTokenScope::ReadWrite => Ok(ApiTokenPurpose::ReadWrite),
            ApiTokenScope::Synchronise => Ok(ApiTokenPurpose::Synchronise),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApiToken {
    pub label: String,
    pub expiry: Option<OffsetDateTime>,
    pub issued_at: OffsetDateTime,
    pub issued_by: IdentityId,
    pub scope: ApiTokenScope,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionScope {
    ReadOnly,
    ReadWrite,
    PrivilegeCapable,
    // For migration! To be removed in future!
    Synchronise,
}

impl fmt::Display for SessionScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SessionScope::ReadOnly => write!(f, "read_only"),
            SessionScope::ReadWrite => write!(f, "read_write"),
            SessionScope::PrivilegeCapable => write!(f, "privilege_capable"),
            SessionScope::Synchronise => write!(f, "synchronise"),
        }
    }
}

impl TryInto<UatPurposeStatus> for SessionScope {
    type Error = OperationError;

    fn try_into(self: SessionScope) -> Result<UatPurposeStatus, OperationError> {
        match self {
            SessionScope::ReadOnly => Ok(UatPurposeStatus::ReadOnly),
            SessionScope::ReadWrite => Ok(UatPurposeStatus::ReadWrite),
            SessionScope::PrivilegeCapable => Ok(UatPurposeStatus::PrivilegeCapable),
            SessionScope::Synchronise => Err(OperationError::InvalidEntryState),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SessionState {
    // IMPORTANT - this order allows sorting by
    // lowest to highest, we always want to take
    // the lowest value!
    RevokedAt(Cid),
    ExpiresAt(OffsetDateTime),
    NeverExpires,
}

impl PartialOrd for SessionState {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SessionState {
    fn cmp(&self, other: &Self) -> Ordering {
        // We need this to order by highest -> least which represents
        // priority amongst these elements.
        match (self, other) {
            // RevokedAt with the earliest time = highest
            (SessionState::RevokedAt(c_self), SessionState::RevokedAt(c_other)) => {
                // We need to reverse this - we need the "lower value" to take priority.
                // This is similar to tombstones where the earliest CID must be persisted
                c_other.cmp(c_self)
            }
            (SessionState::RevokedAt(_), _) => Ordering::Greater,
            (_, SessionState::RevokedAt(_)) => Ordering::Less,
            // ExpiresAt with a greater time = higher
            (SessionState::ExpiresAt(e_self), SessionState::ExpiresAt(e_other)) => {
                // Keep the "newer" expiry. This can be because a session was extended
                // by some mechanism, generally in oauth2 during a refresh token exchange.
                e_self.cmp(e_other)
            }
            (SessionState::ExpiresAt(_), _) => Ordering::Greater,
            (_, SessionState::ExpiresAt(_)) => Ordering::Less,
            // NeverExpires = least.
            (SessionState::NeverExpires, SessionState::NeverExpires) => Ordering::Equal,
        }
    }
}

#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub enum AuthType {
    Anonymous,
    Password,
    GeneratedPassword,
    PasswordTotp,
    PasswordBackupCode,
    PasswordSecurityKey,
    Passkey,
    AttestedPasskey,
    OAuth2Trust,
}

impl fmt::Display for AuthType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthType::Anonymous => write!(f, "anonymous"),
            AuthType::Password => write!(f, "password"),
            AuthType::GeneratedPassword => write!(f, "generatedpassword"),
            AuthType::PasswordTotp => write!(f, "passwordtotp"),
            AuthType::PasswordBackupCode => write!(f, "passwordbackupcode"),
            AuthType::PasswordSecurityKey => write!(f, "passwordsecuritykey"),
            AuthType::Passkey => write!(f, "passkey"),
            AuthType::AttestedPasskey => write!(f, "attested_passkey"),
            AuthType::OAuth2Trust => write!(f, "oauth2_trust"),
        }
    }
}

#[derive(Clone, PartialEq, Eq, Default)]
pub enum SessionExtMetadata {
    #[default]
    None,
    OAuth2 {
        access_expires_at: Duration,
        access_token: String,
        refresh_token: Option<String>,
    },
}

impl fmt::Debug for SessionExtMetadata {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            Self::None => f.debug_struct("SessionExtMetadata::None").finish(),
            Self::OAuth2 {
                access_expires_at, ..
            } => f
                .debug_struct("SessionExtMetadata::OAuth2")
                .field("access_expires_at", access_expires_at)
                .finish(),
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct Session {
    pub label: String,
    // pub expiry: Option<OffsetDateTime>,
    pub state: SessionState,
    pub issued_at: OffsetDateTime,
    pub issued_by: IdentityId,
    pub cred_id: Uuid,
    pub scope: SessionScope,
    pub type_: AuthType,
    pub ext_metadata: SessionExtMetadata,
}

impl fmt::Debug for Session {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let issuer = match self.issued_by {
            IdentityId::User(u) => format!("User - {}", uuid_to_proto_string(u)),
            IdentityId::Synch(u) => format!("Synch - {}", uuid_to_proto_string(u)),
            IdentityId::Internal(u) => format!("Internal - {}", uuid_to_proto_string(u)),
        };
        let expiry = match self.state {
            SessionState::ExpiresAt(e) => e.to_string(),
            SessionState::NeverExpires => "never".to_string(),
            SessionState::RevokedAt(_) => "revoked".to_string(),
        };
        write!(
            f,
            "state: {}, issued at: {}, issued by: {}, credential id: {}, scope: {:?}",
            expiry, self.issued_at, issuer, self.cred_id, self.scope
        )
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Default)]
pub enum OauthClaimMapJoin {
    CommaSeparatedValue,
    SpaceSeparatedValue,
    #[default]
    JsonArray,
}

impl From<OauthClaimMapJoin> for ScimOauth2ClaimMapJoinChar {
    fn from(value: OauthClaimMapJoin) -> Self {
        match value {
            OauthClaimMapJoin::CommaSeparatedValue => {
                ScimOauth2ClaimMapJoinChar::CommaSeparatedValue
            }
            OauthClaimMapJoin::SpaceSeparatedValue => {
                ScimOauth2ClaimMapJoinChar::SpaceSeparatedValue
            }
            OauthClaimMapJoin::JsonArray => ScimOauth2ClaimMapJoinChar::JsonArray,
        }
    }
}

impl From<ScimOauth2ClaimMapJoinChar> for OauthClaimMapJoin {
    fn from(value: ScimOauth2ClaimMapJoinChar) -> Self {
        match value {
            ScimOauth2ClaimMapJoinChar::CommaSeparatedValue => {
                OauthClaimMapJoin::CommaSeparatedValue
            }
            ScimOauth2ClaimMapJoinChar::SpaceSeparatedValue => {
                OauthClaimMapJoin::SpaceSeparatedValue
            }
            ScimOauth2ClaimMapJoinChar::JsonArray => OauthClaimMapJoin::JsonArray,
        }
    }
}

impl OauthClaimMapJoin {
    pub(crate) fn to_str(self) -> &'static str {
        match self {
            OauthClaimMapJoin::CommaSeparatedValue => ",",
            OauthClaimMapJoin::SpaceSeparatedValue => " ",
            // Should this be something else?
            OauthClaimMapJoin::JsonArray => ";",
        }
    }
}

impl From<DbValueOauthClaimMapJoinV1> for OauthClaimMapJoin {
    fn from(value: DbValueOauthClaimMapJoinV1) -> OauthClaimMapJoin {
        match value {
            DbValueOauthClaimMapJoinV1::CommaSeparatedValue => {
                OauthClaimMapJoin::CommaSeparatedValue
            }
            DbValueOauthClaimMapJoinV1::SpaceSeparatedValue => {
                OauthClaimMapJoin::SpaceSeparatedValue
            }
            DbValueOauthClaimMapJoinV1::JsonArray => OauthClaimMapJoin::JsonArray,
        }
    }
}

impl From<OauthClaimMapJoin> for DbValueOauthClaimMapJoinV1 {
    fn from(value: OauthClaimMapJoin) -> DbValueOauthClaimMapJoinV1 {
        match value {
            OauthClaimMapJoin::CommaSeparatedValue => {
                DbValueOauthClaimMapJoinV1::CommaSeparatedValue
            }
            OauthClaimMapJoin::SpaceSeparatedValue => {
                DbValueOauthClaimMapJoinV1::SpaceSeparatedValue
            }
            OauthClaimMapJoin::JsonArray => DbValueOauthClaimMapJoinV1::JsonArray,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OAuth2Session {
    pub parent: Option<Uuid>,
    pub state: SessionState,
    pub issued_at: OffsetDateTime,
    pub rs_uuid: Uuid,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyUsage {
    JwsEs256,
    JwsHs256,
    JwsRs256,
    JweA128GCM,
    JweA256GCM,
    HkdfS256,
}

impl fmt::Display for KeyUsage {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                KeyUsage::JwsEs256 => "jws_es256",
                KeyUsage::JwsHs256 => "jws_hs256",
                KeyUsage::JwsRs256 => "jws_rs256",
                KeyUsage::JweA128GCM => "jwe_a128gcm",
                KeyUsage::JweA256GCM => "jwe_a256gcm",
                KeyUsage::HkdfS256 => "hkdf_s256",
            }
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum KeyStatus {
    Valid,
    Retained,
    Revoked,
}

impl fmt::Display for KeyStatus {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                KeyStatus::Valid => "valid",
                KeyStatus::Retained => "retained",
                KeyStatus::Revoked => "revoked",
            }
        )
    }
}

/// A value is a complete unit of data for an attribute. It is made up of a PartialValue, which is
/// used for selection, filtering, searching, matching etc. It also contains supplemental data
/// which may be stored inside of the Value, such as credential secrets, blobs etc.
///
/// This type is used when you need the "full data" of an attribute. Typically this is in a create
/// or modification operation where you are applying a set of complete values into an entry.
#[derive(Clone, Debug)]
pub enum Value {
    Utf8(String),
    /// Case insensitive string
    Iutf8(String),
    Iutf8N(String),
    /// Case insensitive Name for a thing
    Iname(String),
    InameN(String),
    Uuid(Uuid),
    UuidN(Uuid),
    Bool(bool),
    Syntax(SyntaxType),
    Index(IndexType),
    Refer(Uuid),
    ReferN(Uuid),
    JsonFilt(ProtoFilter),
    Cred(String, Credential),
    SshKey(String, SshPublicKey),
    SecretValue(String),
    Spn(String, String),
    Uint32(u32),
    Int64(i64),
    Uint64(u64),
    Cid(Cid),
    Nsuniqueid(String),
    DateTime(OffsetDateTime),
    EmailAddress(String, bool),
    PhoneNumber(String, bool),
    Address(Address),
    Url(Url),
    UrlN(Url),
    OauthScope(String),
    OauthScopeMap(Uuid, BTreeSet<String>),
    PrivateBinary(Vec<u8>),
    PublicBinary(String, Vec<u8>),
    IntentToken(String, IntentTokenState),
    Passkey(Uuid, String, PasskeyV4),
    AttestedPasskey(Uuid, String, AttestedPasskeyV4),

    Session(Uuid, Session),
    ApiToken(Uuid, ApiToken),
    OAuth2Session(Uuid, OAuth2Session),

    JwsKeyEs256(JwsEs256Signer),
    JwsKeyRs256(JwsRs256Signer),
    UiHint(UiHint),

    TotpSecret(String, Totp),
    AuditLogString(Cid, String),

    Image(ImageValue),
    CredentialType(CredentialType),
    WebauthnAttestationCaList(AttestationCaList),

    OauthClaimValue(String, Uuid, BTreeSet<String>),
    OauthClaimMap(String, OauthClaimMapJoin),

    KeyInternal {
        id: KeyId,
        usage: KeyUsage,
        valid_from: u64,
        status: KeyStatus,
        status_cid: Cid,
        der: Zeroizing<Vec<u8>>,
    },

    HexString(String),

    Certificate(Box<Certificate>),
    ApplicationPassword(ApplicationPassword),
    Json(JsonValue),
    Sha256(Sha256Output),
}

impl PartialEq for Value {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Value::Utf8(a), Value::Utf8(b))
            | (Value::Iutf8(a), Value::Iutf8(b))
            | (Value::Iutf8N(a), Value::Iutf8N(b))
            | (Value::Iname(a), Value::Iname(b))
            // Needed during migratinos.
            | (Value::InameN(a), Value::InameN(b))
            | (Value::InameN(a), Value::Iname(b))
            // --
            | (Value::Cred(a, _), Value::Cred(b, _))
            | (Value::SshKey(a, _), Value::SshKey(b, _))
            | (Value::Nsuniqueid(a), Value::Nsuniqueid(b))
            | (Value::EmailAddress(a, _), Value::EmailAddress(b, _))
            | (Value::PhoneNumber(a, _), Value::PhoneNumber(b, _))
            | (Value::OauthScope(a), Value::OauthScope(b))
            | (Value::PublicBinary(a, _), Value::PublicBinary(b, _)) => a.eq(b),
            // Spn - need to check both name and domain.
            (Value::Spn(a, c), Value::Spn(b, d)) => a.eq(b) && c.eq(d),
            // Uuid, Refer
            (Value::Uuid(a), Value::Uuid(b))
            | (Value::Refer(a), Value::Refer(b))
            | (Value::UuidN(a), Value::UuidN(b))
            | (Value::ReferN(a), Value::ReferN(b)) => a.eq(b),
            // Bool
            (Value::Bool(a), Value::Bool(b)) => a.eq(b),
            // Syntax
            (Value::Syntax(a), Value::Syntax(b)) => a.eq(b),
            // Index
            (Value::Index(a), Value::Index(b)) => a.eq(b),
            // JsonFilt
            (Value::JsonFilt(a), Value::JsonFilt(b)) => a.eq(b),
            // Uint32
            (Value::Uint32(a), Value::Uint32(b)) => a.eq(b),
            // Int64
            (Value::Int64(a), Value::Int64(b)) => a.eq(b),
            // Uint64
            (Value::Uint64(a), Value::Uint64(b)) => a.eq(b),
            // Cid
            (Value::Cid(a), Value::Cid(b)) => a.eq(b),
            // DateTime
            (Value::DateTime(a), Value::DateTime(b)) => a.eq(b),
            // Url
            (Value::Url(a), Value::Url(b)) => a.eq(b),
            // OauthScopeMap
            (Value::OauthScopeMap(a, c), Value::OauthScopeMap(b, d)) => a.eq(b) && c.eq(d),

            (Value::Image(image1), Value::Image(image2)) => {
                image1.hash_imagevalue().eq(&image2.hash_imagevalue())
            }
            (Value::Address(_), Value::Address(_))
            | (Value::PrivateBinary(_), Value::PrivateBinary(_))
            | (Value::SecretValue(_), Value::SecretValue(_)) => false,
            // Specifically related to migrations, we allow the invalid comparison.
            (Value::Iutf8(_), Value::Iname(_)) | (Value::Iname(_), Value::Iutf8(_)) => false,
            // When upgrading between uuid -> name -> spn we have to allow some invalid types.
            (Value::Uuid(_), Value::Iname(_))
            | (Value::Iname(_), Value::Spn(_, _))
            | (Value::Uuid(_), Value::Spn(_, _)) => false,
            (l, r) => {
                error!(?l, ?r, "mismatched value types");
                debug_assert!(false);
                false
            }
        }
    }
}

impl Eq for Value {}

impl From<bool> for Value {
    fn from(b: bool) -> Self {
        Value::Bool(b)
    }
}

impl From<&bool> for Value {
    fn from(b: &bool) -> Self {
        Value::Bool(*b)
    }
}

impl From<SyntaxType> for Value {
    fn from(s: SyntaxType) -> Self {
        Value::Syntax(s)
    }
}

impl From<IndexType> for Value {
    fn from(i: IndexType) -> Self {
        Value::Index(i)
    }
}

impl From<ProtoFilter> for Value {
    fn from(i: ProtoFilter) -> Self {
        Value::JsonFilt(i)
    }
}

impl From<OffsetDateTime> for Value {
    fn from(i: OffsetDateTime) -> Self {
        Value::DateTime(i)
    }
}

impl From<u32> for Value {
    fn from(i: u32) -> Self {
        Value::Uint32(i)
    }
}

impl From<Url> for Value {
    fn from(i: Url) -> Self {
        Value::Url(i)
    }
}

// Because these are potentially ambiguous, we limit them to tests where we can contain
// any....mistakes.
#[cfg(test)]
impl From<&str> for Value {
    fn from(s: &str) -> Self {
        // Fuzzy match for uuid's
        match Uuid::parse_str(s) {
            Ok(u) => Value::Uuid(u),
            Err(_) => Value::Utf8(s.to_string()),
        }
    }
}

#[cfg(test)]
impl From<&Uuid> for Value {
    fn from(u: &Uuid) -> Self {
        Value::Uuid(*u)
    }
}

#[cfg(test)]
impl From<Uuid> for Value {
    fn from(u: Uuid) -> Self {
        Value::Uuid(u)
    }
}

impl From<DbIdentSpn> for Value {
    fn from(dis: DbIdentSpn) -> Self {
        match dis {
            DbIdentSpn::Spn(n, r) => Value::Spn(n, r),
            DbIdentSpn::Iname(n) => Value::Iname(n),
            DbIdentSpn::Uuid(u) => Value::Uuid(u),
        }
    }
}

impl Value {
    pub fn new_utf8(s: String) -> Self {
        Value::Utf8(s)
    }

    pub fn new_utf8s(s: &str) -> Self {
        Value::Utf8(s.to_string())
    }

    pub fn is_utf8(&self) -> bool {
        matches!(self, Value::Utf8(_))
    }

    pub fn new_iutf8(s: &str) -> Self {
        Value::Iutf8(s.to_lowercase())
    }

    pub fn new_iutf8n(s: &str) -> Self {
        Value::Iutf8N(s.to_lowercase())
    }

    pub fn is_iutf8(&self) -> bool {
        matches!(self, Value::Iutf8(_))
    }

    pub fn new_attr(s: &str) -> Self {
        Value::Iutf8(s.to_lowercase())
    }

    pub fn is_insensitive_utf8(&self) -> bool {
        matches!(self, Value::Iutf8(_))
    }

    pub fn new_iname(s: &str) -> Self {
        Value::Iname(s.to_lowercase())
    }

    pub fn new_inamen(s: &str) -> Self {
        Value::InameN(s.to_lowercase())
    }

    pub fn is_iname(&self) -> bool {
        matches!(self, Value::Iname(_))
    }

    pub fn new_uuid_s(s: &str) -> Option<Self> {
        Uuid::parse_str(s).map(Value::Uuid).ok()
    }

    // Is this correct? Should ref be separate?
    pub fn is_uuid(&self) -> bool {
        matches!(self, Value::Uuid(_))
    }

    pub fn new_bool(b: bool) -> Self {
        Value::Bool(b)
    }

    pub fn new_bools(s: &str) -> Option<Self> {
        bool::from_str(s).map(Value::Bool).ok()
    }

    pub fn new_audit_log_string(e: (Cid, String)) -> Option<Self> {
        Some(Value::AuditLogString(e.0, e.1))
    }

    #[inline]
    pub fn is_bool(&self) -> bool {
        matches!(self, Value::Bool(_))
    }

    pub fn new_syntaxs(s: &str) -> Option<Self> {
        SyntaxType::try_from(s).map(Value::Syntax).ok()
    }

    pub fn new_syntax(s: SyntaxType) -> Self {
        Value::Syntax(s)
    }

    pub fn is_syntax(&self) -> bool {
        matches!(self, Value::Syntax(_))
    }

    pub fn new_indexes(s: &str) -> Option<Self> {
        IndexType::try_from(s).map(Value::Index).ok()
    }

    pub fn new_index(i: IndexType) -> Self {
        Value::Index(i)
    }

    pub fn is_index(&self) -> bool {
        matches!(self, Value::Index(_))
    }

    pub fn new_refer_s(us: &str) -> Option<Self> {
        Uuid::parse_str(us).map(Value::Refer).ok()
    }

    pub fn is_refer(&self) -> bool {
        matches!(self, Value::Refer(_))
    }

    pub fn new_json_filter_s(s: &str) -> Option<Self> {
        serde_json::from_str(s).map(Value::JsonFilt).ok()
    }

    pub fn new_json_filter(f: ProtoFilter) -> Self {
        Value::JsonFilt(f)
    }

    pub fn is_json_filter(&self) -> bool {
        matches!(self, Value::JsonFilt(_))
    }

    pub fn as_json_filter(&self) -> Option<&ProtoFilter> {
        match &self {
            Value::JsonFilt(f) => Some(f),
            _ => None,
        }
    }

    pub fn new_credential(tag: &str, cred: Credential) -> Self {
        Value::Cred(tag.to_string(), cred)
    }

    pub fn is_credential(&self) -> bool {
        matches!(&self, Value::Cred(_, _))
    }

    pub fn to_credential(&self) -> Option<&Credential> {
        match &self {
            Value::Cred(_, cred) => Some(cred),
            _ => None,
        }
    }

    pub fn new_hex_string_s(hexstr: &str) -> Option<Self> {
        let hexstr_lower = hexstr.to_lowercase();
        if HEXSTR_RE.is_match(&hexstr_lower) {
            Some(Value::HexString(hexstr_lower))
        } else {
            None
        }
    }

    pub fn new_certificate_s(cert_str: &str) -> Option<Self> {
        Certificate::from_pem(cert_str)
            .map(Box::new)
            .map(Value::Certificate)
            .ok()
    }

    /// Want a `Value::Image`? use this!
    pub fn new_image(input: &str) -> Result<Self, OperationError> {
        serde_json::from_str::<ImageValue>(input)
            .map(Value::Image)
            .map_err(|_e| OperationError::InvalidValueState)
    }

    pub fn new_secret_str(cleartext: &str) -> Self {
        Value::SecretValue(cleartext.to_string())
    }

    pub fn is_secret_string(&self) -> bool {
        matches!(&self, Value::SecretValue(_))
    }

    pub fn get_secret_str(&self) -> Option<&str> {
        match &self {
            Value::SecretValue(c) => Some(c.as_str()),
            _ => None,
        }
    }

    pub fn new_sshkey_str(tag: &str, key: &str) -> Result<Self, OperationError> {
        SshPublicKey::from_string(key)
            .map(|pk| Value::SshKey(tag.to_string(), pk))
            .map_err(|err| {
                error!(?err, "value sshkey failed to parse string");
                OperationError::VL0001ValueSshPublicKeyString
            })
    }

    pub fn is_sshkey(&self) -> bool {
        matches!(&self, Value::SshKey(_, _))
    }

    pub fn get_sshkey(&self) -> Option<String> {
        match &self {
            Value::SshKey(_, key) => Some(key.to_string()),
            _ => None,
        }
    }

    pub fn new_spn_parse(s: &str) -> Option<Self> {
        SPN_RE.captures(s).and_then(|caps| {
            let name = match caps.name(Attribute::Name.as_ref()) {
                Some(v) => v.as_str().to_string(),
                None => return None,
            };
            let realm = match caps.name("realm") {
                Some(v) => v.as_str().to_string(),
                None => return None,
            };
            Some(Value::Spn(name, realm))
        })
    }

    pub fn new_spn_str(n: &str, r: &str) -> Self {
        Value::Spn(n.to_string(), r.to_string())
    }

    pub fn is_spn(&self) -> bool {
        matches!(&self, Value::Spn(_, _))
    }

    pub fn new_uint32(u: u32) -> Self {
        Value::Uint32(u)
    }

    pub fn new_uint32_str(u: &str) -> Option<Self> {
        u.parse::<u32>().ok().map(Value::Uint32)
    }

    pub fn is_uint32(&self) -> bool {
        matches!(&self, Value::Uint32(_))
    }

    pub fn new_int64_str(u: &str) -> Option<Self> {
        u.parse::<i64>().ok().map(Value::Int64)
    }

    pub fn new_uint64_str(u: &str) -> Option<Self> {
        u.parse::<u64>().ok().map(Value::Uint64)
    }

    pub fn new_cid(c: Cid) -> Self {
        Value::Cid(c)
    }

    pub fn is_cid(&self) -> bool {
        matches!(&self, Value::Cid(_))
    }

    pub fn new_nsuniqueid_s(s: &str) -> Option<Self> {
        if NSUNIQUEID_RE.is_match(s) {
            Some(Value::Nsuniqueid(s.to_lowercase()))
        } else {
            None
        }
    }

    pub fn is_nsuniqueid(&self) -> bool {
        matches!(&self, Value::Nsuniqueid(_))
    }

    pub fn new_datetime_epoch(ts: Duration) -> Self {
        Value::DateTime(OffsetDateTime::UNIX_EPOCH + ts)
    }

    pub fn new_datetime_s(s: &str) -> Option<Self> {
        OffsetDateTime::parse(s, &Rfc3339)
            .ok()
            .map(|odt| odt.to_offset(time::UtcOffset::UTC))
            .map(Value::DateTime)
    }

    pub fn new_datetime(dt: OffsetDateTime) -> Self {
        Value::DateTime(dt)
    }

    pub fn to_datetime(&self) -> Option<OffsetDateTime> {
        match &self {
            Value::DateTime(odt) => {
                debug_assert_eq!(odt.offset(), time::UtcOffset::UTC);
                Some(*odt)
            }
            _ => None,
        }
    }

    pub fn is_datetime(&self) -> bool {
        matches!(&self, Value::DateTime(_))
    }

    pub fn new_email_address_s(s: &str) -> Option<Self> {
        if VALIDATE_EMAIL_RE.is_match(s) {
            Some(Value::EmailAddress(s.to_string(), false))
        } else {
            None
        }
    }

    pub fn new_email_address_primary_s(s: &str) -> Option<Self> {
        if VALIDATE_EMAIL_RE.is_match(s) {
            Some(Value::EmailAddress(s.to_string(), true))
        } else {
            None
        }
    }

    pub fn is_email_address(&self) -> bool {
        matches!(&self, Value::EmailAddress(_, _))
    }

    pub fn new_phonenumber_s(s: &str) -> Self {
        Value::PhoneNumber(s.to_string(), false)
    }

    pub fn new_address(a: Address) -> Self {
        Value::Address(a)
    }

    pub fn new_url_s(s: &str) -> Option<Self> {
        Url::parse(s).ok().map(Value::Url)
    }

    pub fn new_urln_s(s: &str) -> Option<Self> {
        Url::parse(s).ok().map(Value::UrlN)
    }

    pub fn new_url(u: Url) -> Self {
        Value::Url(u)
    }

    pub fn is_url(&self) -> bool {
        matches!(&self, Value::Url(_))
    }

    pub fn new_oauthscope(s: &str) -> Option<Self> {
        if OAUTHSCOPE_RE.is_match(s) {
            Some(Value::OauthScope(s.to_string()))
        } else {
            None
        }
    }

    pub fn is_oauthscope(&self) -> bool {
        matches!(&self, Value::OauthScope(_))
    }

    pub fn new_oauthscopemap(u: Uuid, m: BTreeSet<String>) -> Option<Self> {
        if m.iter().all(|s| OAUTHSCOPE_RE.is_match(s)) {
            Some(Value::OauthScopeMap(u, m))
        } else {
            None
        }
    }

    pub fn new_oauthclaimmap(n: String, u: Uuid, c: BTreeSet<String>) -> Option<Self> {
        if OAUTH_CLAIMNAME_RE.is_match(&n) && c.iter().all(|s| OAUTH_CLAIMNAME_RE.is_match(s)) {
            Some(Value::OauthClaimValue(n, u, c))
        } else {
            None
        }
    }

    pub fn is_oauthscopemap(&self) -> bool {
        matches!(&self, Value::OauthScopeMap(_, _))
    }

    #[cfg(test)]
    pub fn new_privatebinary_base64(der: &str) -> Self {
        let der = general_purpose::STANDARD
            .decode(der)
            .expect("Failed to decode base64 der value");
        Value::PrivateBinary(der)
    }

    pub fn new_privatebinary(der: &[u8]) -> Self {
        Value::PrivateBinary(der.to_owned())
    }

    pub fn to_privatebinary(&self) -> Option<&Vec<u8>> {
        match &self {
            Value::PrivateBinary(c) => Some(c),
            _ => None,
        }
    }

    pub fn is_privatebinary(&self) -> bool {
        matches!(&self, Value::PrivateBinary(_))
    }

    pub fn new_publicbinary(tag: String, der: Vec<u8>) -> Self {
        Value::PublicBinary(tag, der)
    }

    pub fn new_webauthn_attestation_ca_list(s: &str) -> Option<Self> {
        serde_json::from_str(s)
            .map(Value::WebauthnAttestationCaList)
            .map_err(|err| {
                debug!(?err, ?s);
            })
            .ok()
    }

    #[allow(clippy::unreachable)]
    pub(crate) fn to_db_ident_spn(&self) -> DbIdentSpn {
        // This has to clone due to how the backend works.
        match &self {
            Value::Spn(n, r) => DbIdentSpn::Spn(n.clone(), r.clone()),
            Value::Iname(s) | Value::InameN(s) => DbIdentSpn::Iname(s.clone()),
            Value::Uuid(u) => DbIdentSpn::Uuid(*u),
            // Value::Iutf8(s) => DbValueV1::Iutf8(s.clone()),
            // Value::Utf8(s) => DbValueV1::Utf8(s.clone()),
            // Value::Nsuniqueid(s) => DbValueV1::NsUniqueId(s.clone()),
            v => unreachable!("-> {:?}", v),
        }
    }

    pub fn to_str(&self) -> Option<&str> {
        match &self {
            Value::Utf8(s) => Some(s.as_str()),
            Value::Iutf8(s) => Some(s.as_str()),
            Value::Iutf8N(s) => Some(s.as_str()),
            Value::Iname(s) => Some(s.as_str()),
            _ => None,
        }
    }

    pub fn to_url(&self) -> Option<&Url> {
        match &self {
            Value::Url(u) => Some(u),
            _ => None,
        }
    }

    pub fn as_string(&self) -> Option<&String> {
        match &self {
            Value::Utf8(s) => Some(s),
            Value::Iutf8(s) => Some(s),
            Value::Iname(s) => Some(s),
            _ => None,
        }
    }

    // We need a separate to-ref_uuid to distinguish from normal uuids
    // in refint plugin.
    pub fn to_ref_uuid(&self) -> Option<Uuid> {
        match &self {
            Value::Refer(u) | Value::ReferN(u) => Some(*u),
            Value::OauthScopeMap(u, _) => Some(*u),
            // We need to assert that our reference to our rs exists.
            Value::OAuth2Session(_, m) => Some(m.rs_uuid),
            _ => None,
        }
    }

    pub fn to_uuid(&self) -> Option<&Uuid> {
        match &self {
            Value::Uuid(u) | Value::UuidN(u) => Some(u),
            _ => None,
        }
    }

    pub fn to_indextype(&self) -> Option<&IndexType> {
        match &self {
            Value::Index(i) => Some(i),
            _ => None,
        }
    }

    pub fn to_syntaxtype(&self) -> Option<&SyntaxType> {
        match &self {
            Value::Syntax(s) => Some(s),
            _ => None,
        }
    }

    pub fn to_bool(&self) -> Option<bool> {
        match self {
            // *v is to invoke a copy, but this is cheap af
            Value::Bool(v) => Some(*v),
            _ => None,
        }
    }

    pub fn to_uint32(&self) -> Option<u32> {
        match &self {
            Value::Uint32(v) => Some(*v),
            _ => None,
        }
    }

    pub fn to_utf8(self) -> Option<String> {
        match self {
            Value::Utf8(s) => Some(s),
            _ => None,
        }
    }

    pub fn to_iutf8(self) -> Option<String> {
        match self {
            Value::Iutf8(s) => Some(s),
            _ => None,
        }
    }

    pub fn to_iname(self) -> Option<String> {
        match self {
            Value::Iname(s) => Some(s),
            _ => None,
        }
    }

    pub fn to_jsonfilt(self) -> Option<ProtoFilter> {
        match self {
            Value::JsonFilt(f) => Some(f),
            _ => None,
        }
    }

    pub fn to_cred(self) -> Option<(String, Credential)> {
        match self {
            Value::Cred(tag, c) => Some((tag, c)),
            _ => None,
        }
    }

    pub fn to_spn(self) -> Option<(String, String)> {
        match self {
            Value::Spn(n, d) => Some((n, d)),
            _ => None,
        }
    }

    pub fn to_cid(self) -> Option<Cid> {
        match self {
            Value::Cid(s) => Some(s),
            _ => None,
        }
    }

    pub fn to_nsuniqueid(self) -> Option<String> {
        match self {
            Value::Nsuniqueid(s) => Some(s),
            _ => None,
        }
    }

    pub fn to_emailaddress(self) -> Option<String> {
        match self {
            Value::EmailAddress(s, _) => Some(s),
            _ => None,
        }
    }

    pub fn to_oauthscope(self) -> Option<String> {
        match self {
            Value::OauthScope(s) => Some(s),
            _ => None,
        }
    }

    pub fn to_oauthscopemap(self) -> Option<(Uuid, BTreeSet<String>)> {
        match self {
            Value::OauthScopeMap(u, m) => Some((u, m)),
            _ => None,
        }
    }

    pub fn to_phonenumber(self) -> Option<String> {
        match self {
            Value::PhoneNumber(p, _b) => Some(p),
            _ => None,
        }
    }

    pub fn to_publicbinary(self) -> Option<(String, Vec<u8>)> {
        match self {
            Value::PublicBinary(t, d) => Some((t, d)),
            _ => None,
        }
    }

    pub fn to_address(self) -> Option<Address> {
        match self {
            Value::Address(a) => Some(a),
            _ => None,
        }
    }

    pub fn to_intenttoken(self) -> Option<(String, IntentTokenState)> {
        match self {
            Value::IntentToken(u, s) => Some((u, s)),
            _ => None,
        }
    }

    pub fn to_session(self) -> Option<(Uuid, Session)> {
        match self {
            Value::Session(u, s) => Some((u, s)),
            _ => None,
        }
    }

    pub fn migrate_iutf8_iname(self) -> Option<Self> {
        match self {
            Value::Iutf8(v) => Some(Value::Iname(v)),
            _ => None,
        }
    }

    // !!!! This function is being phased out !!!
    #[allow(clippy::unreachable)]
    pub(crate) fn to_proto_string_clone(&self) -> String {
        match &self {
            Value::Iname(s) | Value::InameN(s) => s.clone(),
            Value::Uuid(u) | Value::UuidN(u) => u.as_hyphenated().to_string(),
            // We display the tag and fingerprint.
            Value::SshKey(tag, key) => format!("{tag}: {key}"),
            Value::Spn(n, r) => format!("{n}@{r}"),
            _ => unreachable!(
                "You've specified the wrong type for the attribute, got: {:?}",
                self
            ),
        }
    }

    pub(crate) fn validate(&self) -> bool {
        // Validate that extra-data constraints on the type exist and are
        // valid. IE json filter is really a filter, or cred types have supplemental
        // data.
        match &self {
            // String security is required here
            Value::Utf8(s)
            | Value::Iutf8(s)
            | Value::Iutf8N(s)
            | Value::Cred(s, _)
            | Value::PublicBinary(s, _)
            | Value::IntentToken(s, _)
            | Value::Passkey(_, s, _)
            | Value::AttestedPasskey(_, s, _)
            | Value::TotpSecret(s, _) => {
                Value::validate_str_escapes(s) && Value::validate_singleline(s)
            }

            Value::Spn(a, b) => {
                Value::validate_str_escapes(a)
                    && Value::validate_str_escapes(b)
                    && Value::validate_singleline(a)
                    && Value::validate_singleline(b)
            }
            Value::Image(image) => image.validate_image().is_ok(),
            Value::Iname(s) | Value::InameN(s) => {
                Value::validate_str_escapes(s)
                    && Value::validate_iname(s)
                    && Value::validate_singleline(s)
            }

            Value::SshKey(s, _key) => {
                Value::validate_str_escapes(s)
                    // && Value::validate_iname(s)
                    && Value::validate_singleline(s)
            }

            Value::ApiToken(_, at) => {
                Value::validate_str_escapes(&at.label) && Value::validate_singleline(&at.label)
            }
            Value::AuditLogString(_, s) => {
                Value::validate_str_escapes(s) && Value::validate_singleline(s)
            }
            Value::ApplicationPassword(ap) => {
                Value::validate_str_escapes(&ap.label) && Value::validate_singleline(&ap.label)
            }

            // These have stricter validators so not needed.
            Value::Nsuniqueid(s) => NSUNIQUEID_RE.is_match(s),
            Value::DateTime(odt) => odt.offset() == time::UtcOffset::UTC,
            Value::EmailAddress(mail, _) => VALIDATE_EMAIL_RE.is_match(mail.as_str()),
            Value::OauthScope(s) => OAUTHSCOPE_RE.is_match(s),
            Value::OauthScopeMap(_, m) => m.iter().all(|s| OAUTHSCOPE_RE.is_match(s)),

            Value::OauthClaimMap(name, _) => OAUTH_CLAIMNAME_RE.is_match(name),
            Value::OauthClaimValue(name, _, value) => {
                OAUTH_CLAIMNAME_RE.is_match(name)
                    && value.iter().all(|s| OAUTH_CLAIMNAME_RE.is_match(s))
            }

            Value::KeyInternal { id, .. } => {
                let s = id.as_str();
                Value::validate_str_escapes(s)
                    && Value::validate_singleline(s)
                    && Value::validate_hexstr(s)
            }
            Value::HexString(id) => {
                Value::validate_str_escapes(id.as_str())
                    && Value::validate_singleline(id.as_str())
                    && Value::validate_hexstr(id.as_str())
            }

            Value::PhoneNumber(_, _) => true,
            Value::Address(_) => true,
            Value::Certificate(_) => true,

            Value::Uuid(_)
            | Value::UuidN(_)
            | Value::Bool(_)
            | Value::Syntax(_)
            | Value::Index(_)
            | Value::Refer(_)
            | Value::ReferN(_)
            | Value::JsonFilt(_)
            | Value::SecretValue(_)
            | Value::Uint32(_)
            | Value::Int64(_)
            | Value::Uint64(_)
            | Value::Url(_)
            | Value::UrlN(_)
            | Value::Cid(_)
            | Value::PrivateBinary(_)
            | Value::JwsKeyEs256(_)
            | Value::Session(_, _)
            | Value::OAuth2Session(_, _)
            | Value::JwsKeyRs256(_)
            | Value::UiHint(_)
            | Value::CredentialType(_)
            | Value::Json(_)
            | Value::Sha256(_)
            | Value::WebauthnAttestationCaList(_) => true,
        }
    }

    pub(crate) fn validate_iname(s: &str) -> bool {
        match Uuid::parse_str(s) {
            // It is a uuid, disallow.
            Ok(_) => {
                error!("iname values may not contain uuids");
                false
            }
            // Not a uuid, check it against the re.
            Err(_) => {
                if !INAME_RE.is_match(s) {
                    error!("iname values may only contain limited characters - \"{}\" does not pass regex pattern \"{}\"", s, *INAME_RE);
                    false
                } else if DISALLOWED_NAMES.contains(s) {
                    error!("iname value \"{}\" is in denied list", s);
                    false
                } else {
                    true
                }
            }
        }
    }

    pub(crate) fn validate_hexstr(s: &str) -> bool {
        if !HEXSTR_RE.is_match(s) {
            error!("hexstrings may only contain limited characters. - \"{}\" does not pass regex pattern \"{}\"", s, *HEXSTR_RE);
            false
        } else {
            true
        }
    }

    pub(crate) fn validate_singleline(s: &str) -> bool {
        if !SINGLELINE_RE.is_match(s) {
            true
        } else {
            error!(
                "value contains invalid whitespace chars forbidden by \"{}\"",
                *SINGLELINE_RE
            );
            // Trace only, could be an injection attack of some kind.
            trace!(?s, "Invalid whitespace");
            false
        }
    }

    pub(crate) fn validate_str_escapes(s: &str) -> bool {
        // Look for and prevent certain types of string escapes and injections.
        if UNICODE_CONTROL_RE.is_match(s) {
            error!("value contains invalid unicode control character",);
            // Trace only, could be an injection attack of some kind.
            trace!(?s, "Invalid Unicode Control");
            false
        } else {
            true
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::value::*;

    #[test]
    fn test_value_index_tryfrom() {
        let r1 = IndexType::try_from("EQualiTY");
        assert_eq!(r1, Ok(IndexType::Equality));

        let r2 = IndexType::try_from("PResenCE");
        assert_eq!(r2, Ok(IndexType::Presence));

        let r3 = IndexType::try_from("SUbstrING");
        assert_eq!(r3, Ok(IndexType::SubString));

        let r4 = IndexType::try_from("thaoeusaneuh");
        assert_eq!(r4, Err(()));
    }

    #[test]
    fn test_value_syntax_tryfrom() {
        let r1 = SyntaxType::try_from("UTF8strinG");
        assert_eq!(r1, Ok(SyntaxType::Utf8String));

        let r2 = SyntaxType::try_from("UTF8STRING_INSensitIVE");
        assert_eq!(r2, Ok(SyntaxType::Utf8StringInsensitive));

        let r3 = SyntaxType::try_from("BOOLEAN");
        assert_eq!(r3, Ok(SyntaxType::Boolean));

        let r4 = SyntaxType::try_from("SYNTAX_ID");
        assert_eq!(r4, Ok(SyntaxType::SyntaxId));

        let r5 = SyntaxType::try_from("INDEX_ID");
        assert_eq!(r5, Ok(SyntaxType::IndexId));

        let r6 = SyntaxType::try_from("zzzzantheou");
        assert_eq!(r6, Err(()));
    }

    #[test]
    fn test_value_sshkey_validation_display() {
        let ecdsa = concat!("ecdsa-sha2-nistp521 AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAAAIbmlzdHA1MjEAAACFBAGyIY7o3B",
        "tOzRiJ9vvjj96bRImwmyy5GvFSIUPlK00HitiAWGhiO1jGZKmK7220Oe4rqU3uAwA00a0758UODs+0OQHLMDRtl81l",
        "zPrVSdrYEDldxH9+a86dBZhdm0e15+ODDts2LHUknsJCRRldO4o9R9VrohlF7cbyBlnhJQrR4S+Oag== william@a",
        "methyst");
        let ed25519 = concat!(
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAeGW1P6Pc2rPq0XqbRaDKBcXZUPRklo0L1EyR30CwoP",
            " william@amethyst"
        );
        let rsa = concat!("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDTcXpclurQpyOHZBM/cDY9EvInSYkYSGe51by/wJP0Njgi",
        "GZUJ3HTaPqoGWux0PKd7KJki+onLYt4IwDV1RhV/GtMML2U9v94+pA8RIK4khCxvpUxlM7Kt/svjOzzzqiZfKdV37/",
        "OUXmM7bwVGOvm3EerDOwmO/QdzNGfkca12aWLoz97YrleXnCoAzr3IN7j3rwmfJGDyuUtGTdmyS/QWhK9FPr8Ic3eM",
        "QK1JSAQqVfGhA8lLbJHmnQ/b/KMl2lzzp7SXej0wPUfvI/IP3NGb8irLzq8+JssAzXGJ+HMql+mNHiSuPaktbFzZ6y",
        "ikMR6Rx/psU07nAkxKZDEYpNVv william@amethyst");

        let sk1 = Value::new_sshkey_str("tag", ecdsa).expect("Invalid ssh key");
        assert!(sk1.validate());
        // to proto them
        let psk1 = sk1.to_proto_string_clone();
        assert_eq!(psk1, format!("tag: {ecdsa}"));

        let sk2 = Value::new_sshkey_str("tag", ed25519).expect("Invalid ssh key");
        assert!(sk2.validate());
        let psk2 = sk2.to_proto_string_clone();
        assert_eq!(psk2, format!("tag: {ed25519}"));

        let sk3 = Value::new_sshkey_str("tag", rsa).expect("Invalid ssh key");
        assert!(sk3.validate());
        let psk3 = sk3.to_proto_string_clone();
        assert_eq!(psk3, format!("tag: {rsa}"));

        let sk4 = Value::new_sshkey_str("tag", "ntaouhtnhtnuehtnuhotnuhtneouhtneouh");
        assert!(sk4.is_err());

        let sk5 = Value::new_sshkey_str(
            "tag",
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAeGW1P6Pc2rPq0XqbRaDKBcXZUPRklo",
        );
        assert!(sk5.is_err());
    }

    /*
    #[test]
    fn test_value_spn() {
        // Create an spn vale
        let spnv = Value::new_spn_str("claire", "example.net.au");
        // create an spn pv
        let spnp = PartialValue::new_spn_nrs("claire", "example.net.au");
        // check it's indexing output
        let vidx_key = spnv.generate_idx_eq_keys().pop().unwrap();
        let idx_key = spnp.get_idx_eq_key();
        assert_eq!(idx_key,vidx_key);
        // check it can parse from name@realm
        let spn_parse = PartialValue::new_spn_s("claire@example.net.au").unwrap();
        assert_eq!(spn_parse,spnp);
        // check it can produce name@realm as str from the pv.
        assert_eq!("claire@example.net.au",spnv.to_proto_string_clone());
    }
    */

    /*
    #[test]
    fn test_value_uint32() {
        assert!(Value::new_uint32_str("test").is_none());
        assert!(Value::new_uint32_str("18446744073709551615").is_none());

        let u32v = Value::new_uint32_str("4000").unwrap();
        let u32pv = PartialValue::new_uint32_str("4000").unwrap();

        let idx_key = u32pv.get_idx_eq_key();
        let vidx_key = u32v.generate_idx_eq_keys().pop().unwrap();

        assert_eq!(idx_key,vidx_key);
    }
    */

    #[test]
    fn test_value_cid() {
        assert!(PartialValue::new_cid_s("_").is_none());
    }

    #[test]
    fn test_value_iname() {
        /*
         * name MUST NOT:
         * - be a pure int (confusion to gid/uid/linux)
         * - a uuid (confuses our name mapper)
         * - contain an @ (confuses SPN)
         * - can not start with _ (... api end points have _ as a magic char)
         * - can not have spaces (confuses too many systems :()
         * - can not have = or , (confuses ldap)
         * - can not have ., /, \ (path injection attacks)
         */
        let inv1 = Value::new_iname("1234");
        let inv2 = Value::new_iname("bc23f637-4439-4c07-b95d-eaed0d9e4b8b");
        let inv3 = Value::new_iname("hello@test.com");
        let inv4 = Value::new_iname("_bad");
        let inv5 = Value::new_iname("no spaces I'm sorry :(");
        let inv6 = Value::new_iname("bad=equals");
        let inv7 = Value::new_iname("bad,comma");
        let inv8 = Value::new_iname("123_456");
        let inv9 = Value::new_iname("🍿");

        let val1 = Value::new_iname("William");
        let val2 = Value::new_iname("this_is_okay");
        let val3 = Value::new_iname("a123_456");

        assert!(!inv1.validate());
        assert!(!inv2.validate());
        assert!(!inv3.validate());
        assert!(!inv4.validate());
        assert!(!inv5.validate());
        assert!(!inv6.validate());
        assert!(!inv7.validate());
        assert!(!inv8.validate());
        assert!(!inv9.validate());

        assert!(val1.validate());
        assert!(val2.validate());
        assert!(val3.validate());
    }

    #[test]
    fn test_value_nsuniqueid() {
        // nsunique
        // d765e707-48e111e6-8c9ebed8-f7926cc3
        // uuid
        // d765e707-48e1-11e6-8c9e-bed8f7926cc3
        let val1 = Value::new_nsuniqueid_s("d765e707-48e111e6-8c9ebed8-f7926cc3");
        let val2 = Value::new_nsuniqueid_s("D765E707-48E111E6-8C9EBED8-F7926CC3");
        let inv1 = Value::new_nsuniqueid_s("d765e707-48e1-11e6-8c9e-bed8f7926cc3");
        let inv2 = Value::new_nsuniqueid_s("xxxx");

        assert!(inv1.is_none());
        assert!(inv2.is_none());
        assert!(val1.unwrap().validate());
        assert!(val2.unwrap().validate());
    }

    #[test]
    fn test_value_datetime() {
        // Datetimes must always convert to UTC, and must always be rfc3339
        let val1 = Value::new_datetime_s("2020-09-25T11:22:02+10:00").expect("Must be valid");
        assert!(val1.validate());
        let val2 = Value::new_datetime_s("2020-09-25T01:22:02+00:00").expect("Must be valid");
        assert!(val2.validate());
        // Spaces are now valid in rfc3339 for parsing.
        let val3 = Value::new_datetime_s("2020-09-25 01:22:02+00:00").expect("Must be valid");
        assert!(val3.validate());

        assert!(Value::new_datetime_s("2020-09-25T01:22:02").is_none());
        assert!(Value::new_datetime_s("2020-09-25").is_none());
        assert!(Value::new_datetime_s("2020-09-25T01:22:02+10").is_none());

        // Manually craft
        let inv1 = Value::DateTime(
            #[allow(clippy::disallowed_methods)]
            OffsetDateTime::now_utc()
                .to_offset(time::UtcOffset::from_whole_seconds(36000).unwrap()),
        );
        assert!(!inv1.validate());
        #[allow(clippy::disallowed_methods)]
        let val3 = Value::DateTime(OffsetDateTime::now_utc());
        assert!(val3.validate());
    }

    #[test]
    fn test_value_email_address() {
        // https://html.spec.whatwg.org/multipage/forms.html#valid-e-mail-address
        let val1 = Value::new_email_address_s("william@blackhats.net.au");
        let val2 = Value::new_email_address_s("alice@idm.example.com");
        let val3 = Value::new_email_address_s("test+mailbox@foo.com");
        let inv1 = Value::new_email_address_s("william");
        let inv2 = Value::new_email_address_s("test~uuid");

        assert!(inv1.is_none());
        assert!(inv2.is_none());
        assert!(val1.unwrap().validate());
        assert!(val2.unwrap().validate());
        assert!(val3.unwrap().validate());
    }

    #[test]
    fn test_value_url() {
        // https://html.spec.whatwg.org/multipage/forms.html#valid-e-mail-address
        let val1 = Value::new_url_s("https://localhost:8000/search?q=text#hello");
        let val2 = Value::new_url_s("https://github.com/kanidm/kanidm");
        let val3 = Value::new_url_s("ldap://foo.com");
        let inv1 = Value::new_url_s("127.0.");
        let inv2 = Value::new_url_s("🤔");

        assert!(inv1.is_none());
        assert!(inv2.is_none());
        assert!(val1.is_some());
        assert!(val2.is_some());
        assert!(val3.is_some());
    }

    #[test]
    fn test_singleline() {
        assert!(Value::validate_singleline("no new lines"));

        assert!(!Value::validate_singleline("contains a \n new line"));
        assert!(!Value::validate_singleline("contains a \r return feed"));
        assert!(!Value::validate_singleline("contains a \t tab char"));
    }

    #[test]
    fn test_str_escapes() {
        assert!(Value::validate_str_escapes("safe str"));
        assert!(Value::validate_str_escapes("🙃 emoji are 👍"));

        assert!(!Value::validate_str_escapes("naughty \x1b[31mred"));
    }

    #[test]
    fn test_value_key_internal_status_order() {
        assert!(KeyStatus::Valid < KeyStatus::Retained);
        assert!(KeyStatus::Retained < KeyStatus::Revoked);
    }

    #[test]
    fn test_value_session_state_order() {
        assert!(
            SessionState::RevokedAt(Cid::new_zero()) > SessionState::RevokedAt(Cid::new_count(1))
        );
        assert!(
            SessionState::RevokedAt(Cid::new_zero())
                > SessionState::ExpiresAt(OffsetDateTime::UNIX_EPOCH)
        );
        assert!(
            SessionState::ExpiresAt(OffsetDateTime::UNIX_EPOCH + Duration::from_secs(1))
                > SessionState::ExpiresAt(OffsetDateTime::UNIX_EPOCH)
        );
        assert!(SessionState::ExpiresAt(OffsetDateTime::UNIX_EPOCH) > SessionState::NeverExpires);
    }

    #[test]
    fn test_extract_val_dn_regexn() {
        fn do_extract(name: &str) -> &str {
            EXTRACT_VAL_DN
                .captures(name)
                .and_then(|caps| caps.name("val"))
                .map(|v| v.as_str())
                .unwrap()
        }

        assert_eq!(do_extract("william"), "william");
        assert_eq!(do_extract("cn=william"), "william");
        assert_eq!(do_extract("cn=william,o=blackhats"), "william");
        assert_eq!(do_extract("cn=william@example.com"), "william@example.com");
    }

    #[test]
    fn test_oauth2_scope_re_valid() {
        // Positive
        assert!(OAUTHSCOPE_RE.is_match("abcd"));
        assert!(OAUTHSCOPE_RE.is_match("https://abcd"));
        assert!(OAUTHSCOPE_RE.is_match("abcd.efgh"));
        assert!(OAUTHSCOPE_RE.is_match("abcd.efgh.xfz"));

        // Negative
        assert!(!OAUTHSCOPE_RE.is_match(""));
        assert!(!OAUTHSCOPE_RE.is_match("."));
        assert!(!OAUTHSCOPE_RE.is_match(":"));
        assert!(!OAUTHSCOPE_RE.is_match("/"));
        assert!(!OAUTHSCOPE_RE.is_match("abcd."));
        assert!(!OAUTHSCOPE_RE.is_match("abcd::blah"));
    }
}
