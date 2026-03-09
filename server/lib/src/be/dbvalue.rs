use crate::prelude::JsonValue;
use hashbrown::HashSet;
use kanidm_proto::internal::ImageType;
use kanidm_proto::v1::OutboundMessage;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::time::Duration;
use time::OffsetDateTime;
use url::Url;
use uuid::Uuid;
use webauthn_rs::prelude::{
    AttestationCaList, AttestedPasskey as AttestedPasskeyV4, Passkey as PasskeyV4,
    SecurityKey as SecurityKeyV4,
};
use webauthn_rs_core::proto::{COSEKey, UserVerificationPolicy};
// Re-export this as though it was here.
use crate::repl::cid::Cid;
use crypto_glue::{s256::Sha256Output, traits::Zeroizing};
pub use kanidm_lib_crypto::DbPasswordV1;

fn unix_epoch() -> OffsetDateTime {
    OffsetDateTime::UNIX_EPOCH
}

#[derive(Serialize, Deserialize, Debug, Ord, PartialOrd, PartialEq, Eq, Clone)]
pub struct DbCidV1 {
    #[serde(rename = "t")]
    pub timestamp: Duration,
    #[serde(rename = "s")]
    pub server_id: Uuid,
}

impl From<Cid> for DbCidV1 {
    fn from(Cid { s_uuid, ts }: Cid) -> Self {
        DbCidV1 {
            timestamp: ts,
            server_id: s_uuid,
        }
    }
}

impl From<&Cid> for DbCidV1 {
    fn from(&Cid { s_uuid, ts }: &Cid) -> Self {
        DbCidV1 {
            timestamp: ts,
            server_id: s_uuid,
        }
    }
}

impl fmt::Display for DbCidV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:032}-{}", self.timestamp.as_nanos(), self.server_id)
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub enum DbValueIntentTokenStateV1 {
    #[serde(rename = "v")]
    Valid {
        max_ttl: Duration,
        #[serde(default)]
        ext_cred_portal_can_view: bool,
        #[serde(default)]
        primary_can_edit: bool,
        #[serde(default)]
        passkeys_can_edit: bool,
        #[serde(default)]
        attested_passkeys_can_edit: bool,
        #[serde(default)]
        unixcred_can_edit: bool,
        #[serde(default)]
        sshpubkey_can_edit: bool,
    },
    #[serde(rename = "p")]
    InProgress {
        max_ttl: Duration,
        session_id: Uuid,
        session_ttl: Duration,
        #[serde(default)]
        ext_cred_portal_can_view: bool,
        #[serde(default)]
        primary_can_edit: bool,
        #[serde(default)]
        passkeys_can_edit: bool,
        #[serde(default)]
        attested_passkeys_can_edit: bool,
        #[serde(default)]
        unixcred_can_edit: bool,
        #[serde(default)]
        sshpubkey_can_edit: bool,
    },
    #[serde(rename = "c")]
    Consumed { max_ttl: Duration },
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub enum DbTotpAlgoV1 {
    S1,
    S256,
    S512,
}

#[derive(Serialize, Deserialize, PartialEq, Eq)]
pub struct DbTotpV1 {
    #[serde(rename = "l")]
    pub label: String,
    #[serde(rename = "k")]
    pub key: Vec<u8>,
    #[serde(rename = "s")]
    pub step: u64,
    #[serde(rename = "a")]
    pub algo: DbTotpAlgoV1,
    #[serde(rename = "d", default)]
    pub digits: Option<u8>,
}

impl std::fmt::Debug for DbTotpV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("DbTotpV1")
            .field("label", &self.label)
            .field("step", &self.step)
            .field("algo", &self.algo)
            .finish()
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DbWebauthnV1 {
    #[serde(rename = "l")]
    pub label: String,
    #[serde(rename = "i")]
    pub id: Vec<u8>,
    #[serde(rename = "c")]
    pub cred: COSEKey,
    #[serde(rename = "t")]
    pub counter: u32,
    #[serde(rename = "v")]
    pub verified: bool,
    #[serde(rename = "p", default)]
    pub registration_policy: UserVerificationPolicy,
}

#[derive(Serialize, Deserialize, PartialEq, Eq)]
pub struct DbBackupCodeV1 {
    pub code_set: HashSet<String>, // has to use std::HashSet for serde
}

impl std::fmt::Debug for DbBackupCodeV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "codes remaining: {}", self.code_set.len())
    }
}

// Allow as this is used in serde, but compiler gets that wrong.
#[allow(dead_code)]
// We have to allow this as serde expects &T for the fn sig.
#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_false(b: &bool) -> bool {
    !b
}

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "type_")]
pub enum DbCred {
    // These are the old v1 versions.
    Pw {
        password: Option<DbPasswordV1>,
        webauthn: Option<Vec<DbWebauthnV1>>,
        totp: Option<DbTotpV1>,
        backup_code: Option<DbBackupCodeV1>,
        claims: Vec<String>,
        uuid: Uuid,
    },
    GPw {
        password: Option<DbPasswordV1>,
        webauthn: Option<Vec<DbWebauthnV1>>,
        totp: Option<DbTotpV1>,
        backup_code: Option<DbBackupCodeV1>,
        claims: Vec<String>,
        uuid: Uuid,
    },
    PwMfa {
        password: Option<DbPasswordV1>,
        webauthn: Option<Vec<DbWebauthnV1>>,
        totp: Option<DbTotpV1>,
        backup_code: Option<DbBackupCodeV1>,
        claims: Vec<String>,
        uuid: Uuid,
    },
    Wn {
        password: Option<DbPasswordV1>,
        webauthn: Option<Vec<DbWebauthnV1>>,
        totp: Option<DbTotpV1>,
        backup_code: Option<DbBackupCodeV1>,
        claims: Vec<String>,
        uuid: Uuid,
    },

    TmpWn {
        webauthn: Vec<(String, PasskeyV4)>,
        uuid: Uuid,
    },

    #[serde(rename = "V2PwMfa")]
    V2PasswordMfa {
        password: DbPasswordV1,
        totp: Option<DbTotpV1>,
        backup_code: Option<DbBackupCodeV1>,
        webauthn: Vec<(String, SecurityKeyV4)>,
        uuid: Uuid,
    },

    // New Formats!
    #[serde(rename = "V2Pw")]
    V2Password {
        password: DbPasswordV1,
        uuid: Uuid,
        #[serde(default = "unix_epoch")]
        timestamp: OffsetDateTime,
    },
    #[serde(rename = "V2GPw")]
    V2GenPassword {
        password: DbPasswordV1,
        uuid: Uuid,
        #[serde(default = "unix_epoch")]
        timestamp: OffsetDateTime,
    },
    #[serde(rename = "V3PwMfa")]
    V3PasswordMfa {
        password: DbPasswordV1,
        totp: Vec<(String, DbTotpV1)>,
        backup_code: Option<DbBackupCodeV1>,
        webauthn: Vec<(String, SecurityKeyV4)>,
        uuid: Uuid,
        #[serde(default = "unix_epoch")]
        timestamp: OffsetDateTime,
    },
}

impl DbCred {
    fn uuid(&self) -> Uuid {
        match self {
            DbCred::Pw { uuid, .. }
            | DbCred::GPw { uuid, .. }
            | DbCred::PwMfa { uuid, .. }
            | DbCred::Wn { uuid, .. }
            | DbCred::TmpWn { uuid, .. }
            | DbCred::V2PasswordMfa { uuid, .. }
            | DbCred::V2Password { uuid, .. }
            | DbCred::V2GenPassword { uuid, .. }
            | DbCred::V3PasswordMfa { uuid, .. } => *uuid,
        }
    }

    pub fn last_changed_timestamp(&self) -> OffsetDateTime {
        match self {
            DbCred::V2Password { timestamp, .. }
            | DbCred::V2GenPassword { timestamp, .. }
            | DbCred::V3PasswordMfa { timestamp, .. } => *timestamp,
            // For v1 creds, we have no timestamp, so return *some* ;p fixed time in the past.
            _ => OffsetDateTime::from_unix_timestamp(932964162_i64)
                .unwrap_or(OffsetDateTime::UNIX_EPOCH),
        }
    }
}

impl Eq for DbCred {}

impl PartialEq for DbCred {
    fn eq(&self, other: &Self) -> bool {
        self.uuid() == other.uuid()
    }
}

impl fmt::Display for DbCred {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DbCred::Pw {
                password,
                webauthn,
                totp,
                backup_code,
                claims,
                uuid,
            } => write!(
                f,
                "Pw (p {}, w {}, t {}, b {}, c {}, u {})",
                password.is_some(),
                webauthn.is_some(),
                totp.is_some(),
                backup_code.is_some(),
                claims.len(),
                uuid
            ),
            DbCred::GPw {
                password,
                webauthn,
                totp,
                backup_code,
                claims,
                uuid,
            } => write!(
                f,
                "GPw (p {}, w {}, t {}, b {}, c {}, u {})",
                password.is_some(),
                webauthn.is_some(),
                totp.is_some(),
                backup_code.is_some(),
                claims.len(),
                uuid
            ),
            DbCred::PwMfa {
                password,
                webauthn,
                totp,
                backup_code,
                claims,
                uuid,
            } => write!(
                f,
                "PwMfa (p {}, w {}, t {}, b {}, c {}, u {})",
                password.is_some(),
                webauthn.is_some(),
                totp.is_some(),
                backup_code.is_some(),
                claims.len(),
                uuid
            ),
            DbCred::Wn {
                password,
                webauthn,
                totp,
                backup_code,
                claims,
                uuid,
            } => write!(
                f,
                "Wn (p {}, w {}, t {}, b {}, c {}, u {})",
                password.is_some(),
                webauthn.is_some(),
                totp.is_some(),
                backup_code.is_some(),
                claims.len(),
                uuid
            ),
            DbCred::TmpWn { webauthn, uuid } => {
                write!(f, "TmpWn ( w {}, u {} )", webauthn.len(), uuid)
            }
            DbCred::V2Password {
                password: _,
                uuid,
                timestamp,
            } => write!(f, "V2Pw ( u {uuid}, t {timestamp} )"),
            DbCred::V2GenPassword {
                password: _,
                uuid,
                timestamp,
            } => write!(f, "V2GPw ( u {uuid}, t {timestamp} )"),
            DbCred::V2PasswordMfa {
                password: _,
                totp,
                backup_code,
                webauthn,
                uuid,
            } => write!(
                f,
                "V2PwMfa (p true, w {}, t {}, b {}, u {})",
                webauthn.len(),
                totp.is_some(),
                backup_code.is_some(),
                uuid
            ),
            DbCred::V3PasswordMfa {
                password: _,
                totp,
                backup_code,
                webauthn,
                uuid,
                timestamp,
            } => write!(
                f,
                "V3PwMfa (p true, w {}, t {}, b {}, u {}, t {})",
                webauthn.len(),
                totp.len(),
                backup_code.is_some(),
                uuid,
                timestamp
            ),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct DbValueCredV1 {
    #[serde(rename = "t")]
    pub tag: String,
    #[serde(rename = "d")]
    pub data: DbCred,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum DbValuePasskeyV1 {
    V4 { u: Uuid, t: String, k: PasskeyV4 },
}

impl Eq for DbValuePasskeyV1 {}

impl PartialEq for DbValuePasskeyV1 {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (
                DbValuePasskeyV1::V4 {
                    u: self_uuid,
                    k: self_key,
                    t: _,
                },
                DbValuePasskeyV1::V4 {
                    u: other_uuid,
                    k: other_key,
                    t: _,
                },
            ) => self_uuid == other_uuid && self_key.cred_id() == other_key.cred_id(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub enum DbValueAttestedPasskeyV1 {
    V4 {
        u: Uuid,
        t: String,
        k: AttestedPasskeyV4,
    },
}

impl Eq for DbValueAttestedPasskeyV1 {}

impl PartialEq for DbValueAttestedPasskeyV1 {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (
                DbValueAttestedPasskeyV1::V4 {
                    u: self_uuid,
                    k: self_key,
                    t: _,
                },
                DbValueAttestedPasskeyV1::V4 {
                    u: other_uuid,
                    k: other_key,
                    t: _,
                },
            ) => self_uuid == other_uuid && self_key.cred_id() == other_key.cred_id(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct DbValueTaggedStringV1 {
    #[serde(rename = "t")]
    pub tag: String,
    #[serde(rename = "d")]
    pub data: String,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct DbValueAddressV1 {
    #[serde(rename = "f")]
    pub formatted: String,
    #[serde(rename = "s")]
    pub street_address: String,
    #[serde(rename = "l")]
    pub locality: String,
    #[serde(rename = "r")]
    pub region: String,
    #[serde(rename = "p")]
    pub postal_code: String,
    #[serde(rename = "c")]
    pub country: String,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone, Copy)]
pub enum DbValueOauthClaimMapJoinV1 {
    #[serde(rename = "c")]
    CommaSeparatedValue,
    #[serde(rename = "s")]
    SpaceSeparatedValue,
    #[serde(rename = "a")]
    JsonArray,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub enum DbValueOauthClaimMap {
    V1 {
        #[serde(rename = "n")]
        name: String,
        #[serde(rename = "j")]
        join: DbValueOauthClaimMapJoinV1,
        #[serde(rename = "d")]
        values: BTreeMap<Uuid, BTreeSet<String>>,
    },
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct DbValueOauthScopeMapV1 {
    #[serde(rename = "u")]
    pub refer: Uuid,
    #[serde(rename = "m")]
    pub data: Vec<String>,
}

#[derive(Default, Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub enum DbValueAccessScopeV1 {
    #[serde(rename = "i")]
    IdentityOnly,
    #[serde(rename = "r")]
    #[default]
    ReadOnly,
    #[serde(rename = "w")]
    ReadWrite,
    #[serde(rename = "p")]
    PrivilegeCapable,
    #[serde(rename = "s")]
    Synchronise,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
#[allow(clippy::enum_variant_names)]
pub enum DbValueIdentityId {
    #[serde(rename = "v1i")]
    V1Internal,
    #[serde(rename = "v2i")]
    V2Internal(Uuid),
    #[serde(rename = "v1u")]
    V1Uuid(Uuid),
    #[serde(rename = "v1s")]
    V1Sync(Uuid),
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub enum DbValueSessionStateV1 {
    #[serde(rename = "ea")]
    ExpiresAt(String),
    #[serde(rename = "nv")]
    Never,
    #[serde(rename = "ra")]
    RevokedAt(DbCidV1),
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub enum DbValueAuthTypeV1 {
    #[serde(rename = "an")]
    Anonymous,
    #[serde(rename = "po")]
    Password,
    #[serde(rename = "pg")]
    GeneratedPassword,
    #[serde(rename = "pt")]
    PasswordTotp,
    #[serde(rename = "pb")]
    PasswordBackupCode,
    #[serde(rename = "ps")]
    PasswordSecurityKey,
    #[serde(rename = "as")]
    Passkey,
    #[serde(rename = "ap")]
    AttestedPasskey,
    #[serde(rename = "ot")]
    OAuth2Trust,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone, Default)]
pub enum DbValueSessionExtMetadataV1 {
    #[default]
    None,
    OAuth2 {
        access_expires_at: Duration,
        access_token: String,
        refresh_token: Option<String>,
    },
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub enum DbValueSession {
    V1 {
        #[serde(rename = "u")]
        refer: Uuid,
        #[serde(rename = "l")]
        label: String,
        #[serde(rename = "e")]
        expiry: Option<String>,
        #[serde(rename = "i")]
        issued_at: String,
        #[serde(rename = "b")]
        issued_by: DbValueIdentityId,
        #[serde(rename = "s", default)]
        scope: DbValueAccessScopeV1,
    },
    V2 {
        #[serde(rename = "u")]
        refer: Uuid,
        #[serde(rename = "l")]
        label: String,
        #[serde(rename = "e")]
        expiry: Option<String>,
        #[serde(rename = "i")]
        issued_at: String,
        #[serde(rename = "b")]
        issued_by: DbValueIdentityId,
        #[serde(rename = "c")]
        cred_id: Uuid,
        #[serde(rename = "s", default)]
        scope: DbValueAccessScopeV1,
    },
    V3 {
        #[serde(rename = "u")]
        refer: Uuid,
        #[serde(rename = "l")]
        label: String,
        #[serde(rename = "e")]
        state: DbValueSessionStateV1,
        #[serde(rename = "i")]
        issued_at: String,
        #[serde(rename = "b")]
        issued_by: DbValueIdentityId,
        #[serde(rename = "c")]
        cred_id: Uuid,
        #[serde(rename = "s", default)]
        scope: DbValueAccessScopeV1,
    },
    V4 {
        #[serde(rename = "u")]
        refer: Uuid,
        #[serde(rename = "l")]
        label: String,
        #[serde(rename = "e")]
        state: DbValueSessionStateV1,
        #[serde(rename = "i")]
        issued_at: String,
        #[serde(rename = "b")]
        issued_by: DbValueIdentityId,
        #[serde(rename = "c")]
        cred_id: Uuid,
        #[serde(rename = "s", default)]
        scope: DbValueAccessScopeV1,
        #[serde(rename = "t")]
        type_: DbValueAuthTypeV1,
        #[serde(rename = "x", default)]
        ext_metadata: DbValueSessionExtMetadataV1,
    },
}

#[derive(Serialize, Deserialize, Debug, Default, PartialEq, Eq)]
pub enum DbValueApiTokenScopeV1 {
    #[serde(rename = "r")]
    #[default]
    ReadOnly,
    #[serde(rename = "w")]
    ReadWrite,
    #[serde(rename = "s")]
    Synchronise,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub enum DbValueApiToken {
    V1 {
        #[serde(rename = "u")]
        refer: Uuid,
        #[serde(rename = "l")]
        label: String,
        #[serde(rename = "e")]
        expiry: Option<String>,
        #[serde(rename = "i")]
        issued_at: String,
        #[serde(rename = "b")]
        issued_by: DbValueIdentityId,
        #[serde(rename = "s", default)]
        scope: DbValueApiTokenScopeV1,
    },
}

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub enum DbValueOauth2Session {
    V1 {
        #[serde(rename = "u")]
        refer: Uuid,
        #[serde(rename = "p")]
        parent: Uuid,
        #[serde(rename = "e")]
        expiry: Option<String>,
        #[serde(rename = "i")]
        issued_at: String,
        #[serde(rename = "r")]
        rs_uuid: Uuid,
    },
    V2 {
        #[serde(rename = "u")]
        refer: Uuid,
        #[serde(rename = "p")]
        parent: Uuid,
        #[serde(rename = "e")]
        state: DbValueSessionStateV1,
        #[serde(rename = "i")]
        issued_at: String,
        #[serde(rename = "r")]
        rs_uuid: Uuid,
    },
    V3 {
        #[serde(rename = "u")]
        refer: Uuid,
        #[serde(rename = "p")]
        parent: Option<Uuid>,
        #[serde(rename = "e")]
        state: DbValueSessionStateV1,
        #[serde(rename = "i")]
        issued_at: String,
        #[serde(rename = "r")]
        rs_uuid: Uuid,
    },
}

// Internal representation of an image
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub enum DbValueImage {
    V1 {
        filename: String,
        filetype: ImageType,
        contents: Vec<u8>,
    },
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub enum DbValueKeyUsage {
    JwsEs256,
    JwsHs256,
    JwsRs256,
    JweA128GCM,
    HkdfS256,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub enum DbValueKeyStatus {
    Valid,
    Retained,
    Revoked,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub enum DbValueKeyInternal {
    V1 {
        id: String,
        usage: DbValueKeyUsage,
        valid_from: u64,
        status: DbValueKeyStatus,
        status_cid: DbCidV1,
        der: Zeroizing<Vec<u8>>,
    },
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub enum DbValueCertificate {
    V1 { certificate_der: Vec<u8> },
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub enum DbValueApplicationPassword {
    V1 {
        #[serde(rename = "u")]
        refer: Uuid,
        #[serde(rename = "a")]
        application_refer: Uuid,
        #[serde(rename = "l")]
        label: String,
        #[serde(rename = "p")]
        password: DbPasswordV1,
    },
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub enum DbValueSetV2 {
    #[serde(rename = "U8")]
    Utf8(Vec<String>),
    #[serde(rename = "I8")]
    Iutf8(Vec<String>),
    #[serde(rename = "N8")]
    Iname(Vec<String>),
    #[serde(rename = "UU")]
    Uuid(Vec<Uuid>),
    #[serde(rename = "BO")]
    Bool(Vec<bool>),
    #[serde(rename = "SY")]
    SyntaxType(Vec<u16>),
    #[serde(rename = "IN")]
    IndexType(Vec<u16>),
    #[serde(rename = "RF")]
    Reference(Vec<Uuid>),
    #[serde(rename = "JF")]
    JsonFilter(Vec<String>),
    #[serde(rename = "CR")]
    Credential(Vec<DbValueCredV1>),
    #[serde(rename = "RU")]
    SecretValue(Vec<String>),
    #[serde(rename = "SK")]
    SshKey(Vec<DbValueTaggedStringV1>),
    #[serde(rename = "SP")]
    Spn(Vec<(String, String)>),
    #[serde(rename = "UI")]
    Uint32(Vec<u32>),
    #[serde(rename = "I64")]
    Int64(Vec<i64>),
    #[serde(rename = "U64")]
    Uint64(Vec<u64>),
    #[serde(rename = "CI")]
    Cid(Vec<DbCidV1>),
    #[serde(rename = "NU")]
    NsUniqueId(Vec<String>),
    #[serde(rename = "DT")]
    DateTime(Vec<String>),
    #[serde(rename = "EM")]
    EmailAddress(String, Vec<String>),
    #[serde(rename = "PN")]
    PhoneNumber(String, Vec<String>),
    #[serde(rename = "AD")]
    Address(Vec<DbValueAddressV1>),
    #[serde(rename = "UR")]
    Url(Vec<Url>),
    #[serde(rename = "OS")]
    OauthScope(Vec<String>),
    #[serde(rename = "OM")]
    OauthScopeMap(Vec<DbValueOauthScopeMapV1>),
    #[serde(rename = "OC")]
    OauthClaimMap(Vec<DbValueOauthClaimMap>),
    #[serde(rename = "E2")]
    PrivateBinary(Vec<Vec<u8>>),
    #[serde(rename = "PB")]
    PublicBinary(Vec<(String, Vec<u8>)>),
    #[serde(rename = "RS")]
    RestrictedString(Vec<String>),
    #[serde(rename = "IT")]
    IntentToken(Vec<(String, DbValueIntentTokenStateV1)>),
    #[serde(rename = "PK")]
    Passkey(Vec<DbValuePasskeyV1>),
    #[serde(rename = "DK")]
    AttestedPasskey(Vec<DbValueAttestedPasskeyV1>),
    #[serde(rename = "TE")]
    TrustedDeviceEnrollment(Vec<Uuid>),
    #[serde(rename = "AS")]
    Session(Vec<DbValueSession>),
    #[serde(rename = "JE")]
    JwsKeyEs256(Vec<Zeroizing<Vec<u8>>>),
    #[serde(rename = "JR")]
    JwsKeyRs256(Vec<Zeroizing<Vec<u8>>>),
    #[serde(rename = "OZ")]
    Oauth2Session(Vec<DbValueOauth2Session>),
    #[serde(rename = "UH")]
    UiHint(Vec<u16>),
    #[serde(rename = "TO")]
    TotpSecret(Vec<(String, DbTotpV1)>),
    #[serde(rename = "AT")]
    ApiToken(Vec<DbValueApiToken>),
    #[serde(rename = "SA")]
    AuditLogString(Vec<(Cid, String)>),
    #[serde(rename = "EK")]
    EcKeyPrivate(Vec<u8>),
    #[serde(rename = "IM")]
    Image(Vec<DbValueImage>),
    #[serde(rename = "CT")]
    CredentialType(Vec<u16>),
    #[serde(rename = "WC")]
    WebauthnAttestationCaList { ca_list: AttestationCaList },
    #[serde(rename = "KI")]
    KeyInternal(Vec<DbValueKeyInternal>),
    #[serde(rename = "HS")]
    HexString(Vec<String>),
    #[serde(rename = "X509")]
    Certificate(Vec<DbValueCertificate>),
    #[serde(rename = "AP")]
    ApplicationPassword(Vec<DbValueApplicationPassword>),
    #[serde(rename = "JO")]
    Json(JsonValue),
    #[serde(rename = "MS")]
    Message(OutboundMessage),
    #[serde(rename = "S256")]
    Sha256(BTreeSet<Sha256Output>),
}

impl DbValueSetV2 {
    pub fn len(&self) -> usize {
        match self {
            DbValueSetV2::Utf8(set)
            | DbValueSetV2::Iutf8(set)
            | DbValueSetV2::HexString(set)
            | DbValueSetV2::Iname(set) => set.len(),
            DbValueSetV2::Uuid(set) => set.len(),
            DbValueSetV2::Bool(set) => set.len(),
            DbValueSetV2::SyntaxType(set) => set.len(),
            DbValueSetV2::IndexType(set) => set.len(),
            DbValueSetV2::Reference(set) => set.len(),
            DbValueSetV2::JsonFilter(set) => set.len(),
            DbValueSetV2::Credential(set) => set.len(),
            DbValueSetV2::SecretValue(set) => set.len(),
            DbValueSetV2::SshKey(set) => set.len(),
            DbValueSetV2::Spn(set) => set.len(),
            DbValueSetV2::Uint32(set) => set.len(),
            DbValueSetV2::Int64(set) => set.len(),
            DbValueSetV2::Uint64(set) => set.len(),
            DbValueSetV2::Cid(set) => set.len(),
            DbValueSetV2::NsUniqueId(set) => set.len(),
            DbValueSetV2::DateTime(set) => set.len(),
            DbValueSetV2::EmailAddress(_primary, set) => set.len(),
            DbValueSetV2::PhoneNumber(_primary, set) => set.len(),
            DbValueSetV2::Address(set) => set.len(),
            DbValueSetV2::Url(set) => set.len(),
            DbValueSetV2::OauthClaimMap(set) => set.len(),
            DbValueSetV2::OauthScope(set) => set.len(),
            DbValueSetV2::OauthScopeMap(set) => set.len(),
            DbValueSetV2::PrivateBinary(set) => set.len(),
            DbValueSetV2::PublicBinary(set) => set.len(),
            DbValueSetV2::RestrictedString(set) => set.len(),
            DbValueSetV2::IntentToken(set) => set.len(),
            DbValueSetV2::Passkey(set) => set.len(),
            DbValueSetV2::AttestedPasskey(set) => set.len(),
            DbValueSetV2::TrustedDeviceEnrollment(set) => set.len(),
            DbValueSetV2::Session(set) => set.len(),
            DbValueSetV2::ApiToken(set) => set.len(),
            DbValueSetV2::Oauth2Session(set) => set.len(),
            DbValueSetV2::JwsKeyEs256(set) => set.len(),
            DbValueSetV2::JwsKeyRs256(set) => set.len(),
            DbValueSetV2::UiHint(set) => set.len(),
            DbValueSetV2::TotpSecret(set) => set.len(),
            DbValueSetV2::AuditLogString(set) => set.len(),
            DbValueSetV2::Image(set) => set.len(),
            DbValueSetV2::EcKeyPrivate(_key) => 1, // here we have to hard code it because the Vec<u8>
            // represents the bytes of  SINGLE(!) key
            DbValueSetV2::CredentialType(set) => set.len(),
            DbValueSetV2::WebauthnAttestationCaList { ca_list } => ca_list.len(),
            DbValueSetV2::KeyInternal(set) => set.len(),
            DbValueSetV2::Certificate(set) => set.len(),
            DbValueSetV2::ApplicationPassword(set) => set.len(),
            DbValueSetV2::Sha256(set) => set.len(),
            DbValueSetV2::Json(_) | DbValueSetV2::Message(_) => 1,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use base64::{engine::general_purpose, Engine as _};
    use serde::{Deserialize, Serialize};
    use serde_with::skip_serializing_none;
    use uuid::Uuid;

    use super::{DbBackupCodeV1, DbCred, DbPasswordV1, DbTotpV1, DbWebauthnV1};

    fn dbcred_type_default_pw() -> DbCredTypeV1 {
        DbCredTypeV1::Pw
    }

    #[derive(Serialize, Deserialize, Debug)]
    pub enum DbCredTypeV1 {
        Pw,
        GPw,
        PwMfa,
        // PwWn,
        Wn,
        // WnVer,
        // PwWnVer,
    }

    #[skip_serializing_none]
    #[derive(Serialize, Deserialize, Debug)]
    pub struct DbCredV1 {
        #[serde(default = "dbcred_type_default_pw")]
        pub type_: DbCredTypeV1,
        pub password: Option<DbPasswordV1>,
        pub webauthn: Option<Vec<DbWebauthnV1>>,
        pub totp: Option<DbTotpV1>,
        pub backup_code: Option<DbBackupCodeV1>,
        pub claims: Vec<String>,
        pub uuid: Uuid,
    }

    #[test]
    fn test_dbcred_pre_totp_decode() {
        // This test exists to prove that the previous dbcredv1 format (without totp)
        // can still decode into the updated dbcredv1 that does have a TOTP field.
        /*
        let dbcred = DbCredV1 {
            password: Some(DbPasswordV1::PBKDF2(0, vec![0], vec![0])),
            claims: vec![],
            uuid: Uuid::new_v4(),
        };
        let data = serde_cbor::to_vec(&dbcred).unwrap();
        let s = general_purpose::STANDARD.encode(data);
        */
        let s = "o2hwYXNzd29yZKFmUEJLREYygwCBAIEAZmNsYWltc4BkdXVpZFAjkHFm4q5M86UcNRi4hBjN";
        let data = general_purpose::STANDARD.decode(s).unwrap();
        let dbcred: DbCredV1 = serde_cbor::from_slice(data.as_slice()).unwrap();

        // Test converting to the new enum format
        let x = vec![dbcred];

        let json = serde_json::to_string(&x).unwrap();
        eprintln!("{json}");

        let _e_dbcred: Vec<DbCred> = serde_json::from_str(&json).unwrap();

        // assert_eq!(dbcred,e_dbcred);
    }
}
