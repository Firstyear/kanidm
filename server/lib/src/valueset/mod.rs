use crate::{
    be::dbvalue::DbValueSetV2,
    credential::{apppwd::ApplicationPassword, totp::Totp, Credential},
    prelude::*,
    repl::cid::Cid,
    schema::SchemaAttribute,
    server::keys::KeyId,
    value::{
        Address, ApiToken, CredentialType, IntentTokenState, OAuth2Session, OauthClaimMapJoin,
        Session,
    },
};
use compact_jwt::{crypto::JwsRs256Signer, JwsEs256Signer};
use crypto_glue::{s256::Sha256Output, x509::Certificate};
use dyn_clone::DynClone;
use hashbrown::HashSet;
use kanidm_proto::{
    internal::{Filter as ProtoFilter, ImageValue, UiHint},
    scim_v1::{JsonValue, ScimOauth2ClaimMapJoinChar},
    v1::OutboundMessage,
};
use smolset::SmolSet;
use sshkey_attest::proto::PublicKey as SshPublicKey;
use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet},
};
use time::OffsetDateTime;
use webauthn_rs::prelude::{
    AttestationCaList, AttestedPasskey as AttestedPasskeyV4, Passkey as PasskeyV4,
};

pub use self::{
    address::{ValueSetAddress, ValueSetEmailAddress},
    auditlogstring::{ValueSetAuditLogString, AUDIT_LOG_STRING_CAPACITY},
    binary::{ValueSetPrivateBinary, ValueSetPublicBinary},
    bool::ValueSetBool,
    certificate::ValueSetCertificate,
    cid::ValueSetCid,
    cred::{
        ValueSetAttestedPasskey, ValueSetCredential, ValueSetCredentialType, ValueSetIntentToken,
        ValueSetPasskey, ValueSetWebauthnAttestationCaList,
    },
    datetime::ValueSetDateTime,
    hexstring::ValueSetHexString,
    iname::{ValueSetIname, ValueSetInameN},
    index::ValueSetIndex,
    int64::ValueSetInt64,
    iutf8::{ValueSetIutf8, ValueSetIutf8N},
    json::{ValueSetJson, ValueSetJsonFilter},
    jws::{ValueSetJwsKeyEs256, ValueSetJwsKeyRs256},
    key_internal::{KeyInternalData, ValueSetKeyInternal},
    message::ValueSetMessage,
    nsuniqueid::ValueSetNsUniqueId,
    oauth::{OauthClaimMapping, ValueSetOauthClaimMap, ValueSetOauthScope, ValueSetOauthScopeMap},
    s256::ValueSetSha256,
    secret::ValueSetSecret,
    session::{ValueSetApiTokenSet, ValueSetOauth2Session, ValueSetSession},
    spn::ValueSetSpn,
    ssh::ValueSetSshKey,
    syntax::ValueSetSyntax,
    totp::ValueSetTotpSecret,
    uihint::ValueSetUiHint,
    uint32::ValueSetUint32,
    uint64::ValueSetUint64,
    url::{ValueSetUrl, ValueSetUrlN},
    utf8::ValueSetUtf8,
    uuid::{ValueSetRefer, ValueSetReferN, ValueSetUuid, ValueSetUuidN},
};
use self::{apppwd::ValueSetApplicationPassword, image::ValueSetImage};

mod address;
mod apppwd;
mod auditlogstring;
mod binary;
mod bool;
mod certificate;
mod cid;
mod cred;
mod datetime;
mod hexstring;
pub mod image;
mod iname;
mod index;
mod int64;
mod iutf8;
mod json;
mod jws;
mod key_internal;
mod message;
mod nsuniqueid;
mod oauth;
mod s256;
mod secret;
mod session;
mod spn;
mod ssh;
mod syntax;
mod totp;
mod uihint;
mod uint32;
mod uint64;
mod url;
mod utf8;
mod uuid;

pub type ValueSet = Box<dyn ValueSetT + Send + Sync + 'static>;

dyn_clone::clone_trait_object!(ValueSetT);

pub trait ValueSetT: std::fmt::Debug + DynClone {
    /// Returns whether the value was newly inserted. That is:
    /// * If the set did not previously contain an equal value, true is returned.
    /// * If the set already contained an equal value, false is returned, and the entry is not updated.
    ///
    fn insert_checked(&mut self, value: Value) -> Result<bool, OperationError>;

    fn clear(&mut self);

    #[must_use]
    fn remove(&mut self, _pv: &PartialValue, _cid: &Cid) -> bool;

    #[must_use]
    fn purge(&mut self, _cid: &Cid) -> bool {
        // Default handling is true.
        true
    }

    fn trim(&mut self, _trim_cid: &Cid) {
        // default to a no-op
    }

    fn contains(&self, pv: &PartialValue) -> bool;

    fn substring(&self, _pv: &crate::value::PartialValue) -> bool {
        false
    }

    fn startswith(&self, _pv: &PartialValue) -> bool {
        false
    }

    fn endswith(&self, _pv: &PartialValue) -> bool {
        false
    }

    fn lessthan(&self, _pv: &crate::value::PartialValue) -> bool {
        false
    }

    fn len(&self) -> usize;

    fn generate_idx_eq_keys(&self) -> Vec<String> {
        Vec::with_capacity(0)
    }

    fn generate_idx_sub_keys(&self) -> Vec<String> {
        Vec::with_capacity(0)
    }

    fn generate_idx_ord_keys(&self) -> Vec<String> {
        Vec::with_capacity(0)
    }

    fn syntax(&self) -> SyntaxType;

    fn validate(&self, schema_attr: &SchemaAttribute) -> bool;

    fn to_proto_string_clone_iter(&self) -> Box<dyn Iterator<Item = String> + '_>;

    fn to_scim_value(&self) -> Option<ScimResolveStatus>;

    fn to_db_valueset_v2(&self) -> DbValueSetV2;

    fn to_partialvalue_iter(&self) -> Box<dyn Iterator<Item = PartialValue> + '_>;

    fn to_value_iter(&self) -> Box<dyn Iterator<Item = Value> + '_>;

    fn equal(&self, other: &ValueSet) -> bool;

    fn cmp(&self, _other: &ValueSet) -> Ordering {
        // IMPORTANT - in the case we attempt to compare the ordering of two value sets
        // that are different syntaxs or types, the CORRECT and reliable thing to do is
        // report them as equal such that any sorting function won't rearrange the values.
        error!("cmp should not be called on {:?}", self.syntax());
        debug_assert!(false);
        Ordering::Equal
    }

    fn merge(&mut self, other: &ValueSet) -> Result<(), OperationError>;

    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn migrate(&self) -> Result<Option<ValueSet>, OperationError> {
        Ok(None)
    }

    fn get_ssh_tag(&self, _tag: &str) -> Option<&SshPublicKey> {
        None
    }

    fn as_ref_uuid_iter(&self) -> Option<Box<dyn Iterator<Item = Uuid> + '_>> {
        None
    }

    fn as_utf8_iter(&self) -> Option<Box<dyn Iterator<Item = &str> + '_>> {
        error!("as_utf8_iter should not be called on {:?}", self.syntax());
        debug_assert!(false);
        None
    }

    fn as_iutf8_iter(&self) -> Option<Box<dyn Iterator<Item = &str> + '_>> {
        error!("as_iutf8_iter should not be called on {:?}", self.syntax());
        debug_assert!(false);
        None
    }

    fn as_iname_iter(&self) -> Option<Box<dyn Iterator<Item = &str> + '_>> {
        error!("as_iname_iter should not be called on {:?}", self.syntax());
        debug_assert!(false);
        None
    }

    fn as_indextype_iter(&self) -> Option<Box<dyn Iterator<Item = IndexType> + '_>> {
        error!(
            "as_indextype_set should not be called on {:?}",
            self.syntax()
        );
        None
    }

    fn as_restricted_string_iter(&self) -> Option<Box<dyn Iterator<Item = &str> + '_>> {
        error!(
            "as_restricted_string_iter should not be called on {:?}",
            self.syntax()
        );
        None
    }

    fn as_oauthscope_iter(&self) -> Option<Box<dyn Iterator<Item = &str> + '_>> {
        error!(
            "as_oauthscope_iter should not be called on {:?}",
            self.syntax()
        );
        None
    }

    fn as_sshpubkey_string_iter(&self) -> Option<Box<dyn Iterator<Item = String> + '_>> {
        None
    }

    fn as_email_str_iter(&self) -> Option<Box<dyn Iterator<Item = &str> + '_>> {
        None
    }

    fn as_utf8_set(&self) -> Option<&BTreeSet<String>> {
        debug_assert!(false);
        None
    }

    fn as_iutf8_set(&self) -> Option<&BTreeSet<String>> {
        debug_assert!(false);
        None
    }

    fn as_iname_set(&self) -> Option<&BTreeSet<String>> {
        debug_assert!(false);
        None
    }

    fn as_uuid_set(&self) -> Option<&BTreeSet<Uuid>> {
        None
    }

    fn as_refer_set(&self) -> Option<&BTreeSet<Uuid>> {
        None
    }

    fn as_refer_set_mut(&mut self) -> Option<&mut BTreeSet<Uuid>> {
        debug_assert!(false);
        None
    }

    fn as_bool_set(&self) -> Option<&SmolSet<[bool; 1]>> {
        debug_assert!(false);
        None
    }

    fn as_uint32_set(&self) -> Option<&SmolSet<[u32; 1]>> {
        debug_assert!(false);
        None
    }

    fn as_int64_set(&self) -> Option<&SmolSet<[i64; 1]>> {
        debug_assert!(false);
        None
    }

    fn as_uint64_set(&self) -> Option<&SmolSet<[u64; 1]>> {
        debug_assert!(false);
        None
    }

    fn as_syntax_set(&self) -> Option<&SmolSet<[SyntaxType; 1]>> {
        debug_assert!(false);
        None
    }

    fn as_index_set(&self) -> Option<&SmolSet<[IndexType; 3]>> {
        debug_assert!(false);
        None
    }

    fn as_secret_set(&self) -> Option<&SmolSet<[String; 1]>> {
        debug_assert!(false);
        None
    }

    fn as_restricted_string_set(&self) -> Option<&BTreeSet<String>> {
        debug_assert!(false);
        None
    }

    fn as_spn_set(&self) -> Option<&SmolSet<[(String, String); 1]>> {
        debug_assert!(false);
        None
    }

    fn as_cid_set(&self) -> Option<&SmolSet<[Cid; 1]>> {
        debug_assert!(false);
        None
    }

    fn as_json_filter_set(&self) -> Option<&SmolSet<[ProtoFilter; 1]>> {
        debug_assert!(false);
        None
    }

    fn as_nsuniqueid_set(&self) -> Option<&SmolSet<[String; 1]>> {
        debug_assert!(false);
        None
    }

    fn as_url_set(&self) -> Option<&BTreeSet<Url>> {
        debug_assert!(false);
        None
    }

    fn as_datetime_set(&self) -> Option<&SmolSet<[OffsetDateTime; 1]>> {
        debug_assert!(false);
        None
    }

    fn as_private_binary_set(&self) -> Option<&SmolSet<[Vec<u8>; 1]>> {
        debug_assert!(false);
        None
    }

    fn as_oauthscope_set(&self) -> Option<&BTreeSet<String>> {
        debug_assert!(false);
        None
    }

    fn as_address_set(&self) -> Option<&SmolSet<[Address; 1]>> {
        debug_assert!(false);
        None
    }

    fn as_credential_map(&self) -> Option<&BTreeMap<String, Credential>> {
        debug_assert!(false);
        None
    }

    fn as_totp_map(&self) -> Option<&BTreeMap<String, Totp>> {
        debug_assert!(false);
        None
    }

    fn as_emailaddress_set(&self) -> Option<(&String, &BTreeSet<String>)> {
        debug_assert!(false);
        None
    }

    fn as_sshkey_map(&self) -> Option<&BTreeMap<String, SshPublicKey>> {
        None
    }

    fn as_oauthscopemap(&self) -> Option<&BTreeMap<Uuid, BTreeSet<String>>> {
        /*
        error!(
            "as_oauthscopemap should not be called on {:?}",
            self.syntax()
        );
        */
        None
    }

    fn as_publicbinary_map(&self) -> Option<&BTreeMap<String, Vec<u8>>> {
        debug_assert!(false);
        None
    }

    fn as_intenttoken_map(&self) -> Option<&BTreeMap<String, IntentTokenState>> {
        debug_assert!(false);
        None
    }

    fn as_passkey_map(&self) -> Option<&BTreeMap<Uuid, (String, PasskeyV4)>> {
        debug_assert!(false);
        None
    }

    fn as_attestedpasskey_map(&self) -> Option<&BTreeMap<Uuid, (String, AttestedPasskeyV4)>> {
        debug_assert!(false);
        None
    }

    fn as_webauthn_attestation_ca_list(&self) -> Option<&AttestationCaList> {
        debug_assert!(false);
        None
    }

    fn as_oauthclaim_map(&self) -> Option<&BTreeMap<String, OauthClaimMapping>> {
        None
    }

    fn as_key_internal_map(&self) -> Option<&BTreeMap<KeyId, KeyInternalData>> {
        debug_assert!(false);
        None
    }

    fn as_hexstring_set(&self) -> Option<&BTreeSet<String>> {
        debug_assert!(false);
        None
    }

    fn as_application_password_map(&self) -> Option<&BTreeMap<Uuid, Vec<ApplicationPassword>>> {
        debug_assert!(false);
        None
    }

    fn to_value_single(&self) -> Option<Value> {
        if self.len() != 1 {
            None
        } else {
            self.to_value_iter().take(1).next()
        }
    }

    fn to_proto_string_single(&self) -> Option<String> {
        if self.len() != 1 {
            None
        } else {
            self.to_proto_string_clone_iter().take(1).next()
        }
    }

    fn to_uuid_single(&self) -> Option<Uuid> {
        error!("to_uuid_single should not be called on {:?}", self.syntax());
        None
    }

    fn to_cid_single(&self) -> Option<Cid> {
        error!("to_cid_single should not be called on {:?}", self.syntax());
        None
    }

    fn to_refer_single(&self) -> Option<Uuid> {
        error!(
            "to_refer_single should not be called on {:?}",
            self.syntax()
        );
        debug_assert!(false);
        None
    }

    fn to_bool_single(&self) -> Option<bool> {
        error!("to_bool_single should not be called on {:?}", self.syntax());
        None
    }

    fn to_uint32_single(&self) -> Option<u32> {
        error!(
            "to_uint32_single should not be called on {:?}",
            self.syntax()
        );
        debug_assert!(false);
        None
    }

    fn to_int64_single(&self) -> Option<i64> {
        error!(
            "to_int64_single should not be called on {:?}",
            self.syntax()
        );
        debug_assert!(false);
        None
    }

    fn to_uint64_single(&self) -> Option<u64> {
        error!(
            "to_uint64_single should not be called on {:?}",
            self.syntax()
        );
        debug_assert!(false);
        None
    }

    fn to_syntaxtype_single(&self) -> Option<SyntaxType> {
        error!(
            "to_syntaxtype_single should not be called on {:?}",
            self.syntax()
        );
        None
    }

    fn to_credential_single(&self) -> Option<&Credential> {
        error!(
            "to_credential_single should not be called on {:?}",
            self.syntax()
        );
        debug_assert!(false);
        None
    }

    fn to_secret_single(&self) -> Option<&str> {
        error!(
            "to_secret_single should not be called on {:?}",
            self.syntax()
        );
        debug_assert!(false);
        None
    }

    fn to_restricted_string_single(&self) -> Option<&str> {
        error!(
            "to_restricted_string_single should not be called on {:?}",
            self.syntax()
        );
        debug_assert!(false);
        None
    }

    fn to_utf8_single(&self) -> Option<&str> {
        error!("to_utf8_single should not be called on {:?}", self.syntax());
        debug_assert!(false);
        None
    }

    fn to_iutf8_single(&self) -> Option<&str> {
        error!(
            "to_iutf8_single should not be called on {:?}",
            self.syntax()
        );
        debug_assert!(false);
        None
    }

    fn to_iname_single(&self) -> Option<&str> {
        error!(
            "to_iname_single should not be called on {:?}",
            self.syntax()
        );
        debug_assert!(false);
        None
    }

    fn to_datetime_single(&self) -> Option<OffsetDateTime> {
        error!(
            "to_datetime_single should not be called on {:?}",
            self.syntax()
        );
        debug_assert!(false);
        None
    }

    fn to_url_single(&self) -> Option<&Url> {
        error!("to_url_single should not be called on {:?}", self.syntax());
        debug_assert!(false);
        None
    }

    fn to_json_filter_single(&self) -> Option<&ProtoFilter> {
        error!(
            "to_json_filter_single should not be called on {:?}",
            self.syntax()
        );
        // debug_assert!(false);
        None
    }

    fn to_email_address_primary_str(&self) -> Option<&str> {
        debug_assert!(false);
        None
    }

    fn to_private_binary_single(&self) -> Option<&[u8]> {
        debug_assert!(false);
        None
    }

    fn to_passkey_single(&self) -> Option<&PasskeyV4> {
        debug_assert!(false);
        None
    }

    fn as_session_map(&self) -> Option<&BTreeMap<Uuid, Session>> {
        debug_assert!(false);
        None
    }

    fn as_apitoken_map(&self) -> Option<&BTreeMap<Uuid, ApiToken>> {
        debug_assert!(false);
        None
    }

    fn as_oauth2session_map(&self) -> Option<&BTreeMap<Uuid, OAuth2Session>> {
        debug_assert!(false);
        None
    }

    fn to_jws_key_es256_single(&self) -> Option<&JwsEs256Signer> {
        debug_assert!(false);
        None
    }

    fn as_jws_key_es256_set(&self) -> Option<&HashSet<JwsEs256Signer>> {
        debug_assert!(false);
        None
    }

    fn to_jws_key_rs256_single(&self) -> Option<&JwsRs256Signer> {
        debug_assert!(false);
        None
    }

    fn as_jws_key_rs256_set(&self) -> Option<&HashSet<JwsRs256Signer>> {
        debug_assert!(false);
        None
    }

    fn as_uihint_set(&self) -> Option<&BTreeSet<UiHint>> {
        debug_assert!(false);
        None
    }

    fn as_uihint_iter(&self) -> Option<Box<dyn Iterator<Item = UiHint> + '_>> {
        debug_assert!(false);
        None
    }

    fn as_audit_log_string(&self) -> Option<&BTreeMap<Cid, String>> {
        debug_assert!(false);
        None
    }

    fn as_imageset(&self) -> Option<&HashSet<ImageValue>> {
        debug_assert!(false);
        None
    }

    fn to_credentialtype_single(&self) -> Option<CredentialType> {
        debug_assert!(false);
        None
    }

    fn as_credentialtype_set(&self) -> Option<&SmolSet<[CredentialType; 1]>> {
        debug_assert!(false);
        None
    }

    fn to_certificate_single(&self) -> Option<&Certificate> {
        debug_assert!(false);
        None
    }

    fn as_certificate_set(&self) -> Option<&BTreeMap<Sha256Output, Box<Certificate>>> {
        debug_assert!(false);
        None
    }

    fn as_json_object(&self) -> Option<&JsonValue> {
        debug_assert!(false);
        None
    }

    fn as_message(&self) -> Option<&OutboundMessage> {
        debug_assert!(false);
        None
    }

    fn as_s256_set(&self) -> Option<&BTreeSet<Sha256Output>> {
        debug_assert!(false);
        None
    }

    fn as_s256_set_mut(&mut self) -> Option<&mut BTreeSet<Sha256Output>> {
        debug_assert!(false);
        None
    }

    fn repl_merge_valueset(
        &self,
        _older: &ValueSet,
        _trim_cid: &Cid, // schema_attr: &SchemaAttribute
    ) -> Option<ValueSet> {
        // Self is the "latest" content. Older contains the earlier
        // state of the attribute.
        //
        // In most cases we don't actually need a merge strategy. We just need the
        // newer state of the attribute.
        //
        // However when we have a merge strategy that is required we return
        // Some(new_state) if and only if merges were applied that need to be added
        // to the change state.
        //
        // If no merge was required, we just return None.
        //
        // Examples where we need merging is session states. This has an internal
        // attribute state machine that works similarly to tombstones to ensure that
        // after a certain period that attributes are cleaned up.
        None
    }
}

pub trait ValueSetScimPut {
    fn from_scim_json_put(value: JsonValue) -> Result<ValueSetResolveStatus, OperationError>;
}

impl PartialEq for ValueSet {
    fn eq(&self, other: &ValueSet) -> bool {
        self.equal(other)
    }
}

pub struct UnresolvedScimValueOauth2ClaimMap {
    pub group_uuid: Uuid,
    pub claim: String,
    pub join_char: ScimOauth2ClaimMapJoinChar,
    pub values: BTreeSet<String>,
}

pub struct UnresolvedScimValueOauth2ScopeMap {
    pub group_uuid: Uuid,
    pub scopes: BTreeSet<String>,
}

#[derive(Debug)]
pub enum UnresolvedReferenceState {
    Uuid(Uuid),
    Value(String),
    Complete { uuid: Uuid, value: String },
}

pub enum ScimValueIntermediate {
    Reference(Uuid),
    References(Vec<Uuid>),
    Oauth2ClaimMap(Vec<UnresolvedScimValueOauth2ClaimMap>),
    Oauth2ScopeMap(Vec<UnresolvedScimValueOauth2ScopeMap>),
}

pub enum ScimResolveStatus {
    Resolved(ScimValueKanidm),
    NeedsResolution(ScimValueIntermediate),
}

impl<T> From<T> for ScimResolveStatus
where
    T: Into<ScimValueKanidm>,
{
    fn from(v: T) -> Self {
        Self::Resolved(v.into())
    }
}

#[cfg(test)]
impl ScimResolveStatus {
    pub fn assume_resolved(self) -> ScimValueKanidm {
        match self {
            ScimResolveStatus::Resolved(v) => v,
            ScimResolveStatus::NeedsResolution(_) => {
                panic!("assume_resolved called on NeedsResolution")
            }
        }
    }

    pub fn assume_unresolved(self) -> ScimValueIntermediate {
        match self {
            ScimResolveStatus::Resolved(_) => panic!("assume_unresolved called on Resolved"),
            ScimResolveStatus::NeedsResolution(svi) => svi,
        }
    }
}

pub enum ValueSetResolveStatus {
    Resolved(ValueSet),
    NeedsResolution(ValueSetIntermediate),
}

#[cfg(test)]
impl ValueSetResolveStatus {
    pub fn assume_resolved(self) -> ValueSet {
        match self {
            ValueSetResolveStatus::Resolved(v) => v,
            ValueSetResolveStatus::NeedsResolution(_) => {
                panic!("assume_resolved called on NeedsResolution")
            }
        }
    }

    pub fn assume_unresolved(self) -> ValueSetIntermediate {
        match self {
            ValueSetResolveStatus::Resolved(_) => panic!("assume_unresolved called on Resolved"),
            ValueSetResolveStatus::NeedsResolution(svi) => svi,
        }
    }
}

pub enum ValueSetIntermediate {
    Reference(UnresolvedReferenceState),
    References {
        unresolved: Vec<UnresolvedReferenceState>,
    },
    Oauth2ClaimMap {
        resolved: Vec<ResolvedValueSetOauth2ClaimMap>,
        unresolved: Vec<UnresolvedValueSetOauth2ClaimMap>,
    },
    Oauth2ScopeMap {
        resolved: Vec<ResolvedValueSetOauth2ScopeMap>,
        unresolved: Vec<UnresolvedValueSetOauth2ScopeMap>,
    },
}

pub struct UnresolvedValueSetOauth2ClaimMap {
    pub group_name: String,
    pub claim: String,
    pub join_char: OauthClaimMapJoin,
    pub claim_values: BTreeSet<String>,
}

pub struct ResolvedValueSetOauth2ClaimMap {
    pub group_uuid: Uuid,
    pub claim: String,
    pub join_char: OauthClaimMapJoin,
    pub claim_values: BTreeSet<String>,
}

pub struct UnresolvedValueSetOauth2ScopeMap {
    pub group_name: String,
    pub scopes: BTreeSet<String>,
}

pub struct ResolvedValueSetOauth2ScopeMap {
    pub group_uuid: Uuid,
    pub scopes: BTreeSet<String>,
}

pub fn uuid_to_proto_string(u: Uuid) -> String {
    u.as_hyphenated().to_string()
}

pub fn from_result_value_iter(
    mut iter: impl Iterator<Item = Result<Value, OperationError>>,
) -> Result<ValueSet, OperationError> {
    let Some(init) = iter.next() else {
        trace!("Empty value iterator");
        return Err(OperationError::InvalidValueState);
    };

    let init = init?;

    let mut vs: ValueSet = match init {
        Value::Utf8(s) => ValueSetUtf8::new(s),
        Value::Iutf8(s) => ValueSetIutf8::new(&s),
        Value::Iutf8N(s) => ValueSetIutf8N::new(&s),
        Value::Iname(s) => ValueSetIname::new(&s),
        Value::InameN(s) => ValueSetInameN::new(&s),
        Value::Uuid(u) | Value::UuidN(u) => ValueSetUuid::new(u),
        Value::Refer(u) => ValueSetRefer::new(u),
        Value::ReferN(u) => ValueSetReferN::new(u),
        Value::Bool(u) => ValueSetBool::new(u),
        Value::Uint32(u) => ValueSetUint32::new(u),
        Value::Int64(u) => ValueSetInt64::new(u),
        Value::Uint64(u) => ValueSetUint64::new(u),
        Value::Syntax(u) => ValueSetSyntax::new(u),
        Value::Index(u) => ValueSetIndex::new(u),
        Value::SecretValue(u) => ValueSetSecret::new(u),
        Value::Spn(n, d) => ValueSetSpn::new((n, d)),
        Value::Cid(u) => ValueSetCid::new(u),
        Value::JsonFilt(u) => ValueSetJsonFilter::new(u),
        Value::Nsuniqueid(u) => ValueSetNsUniqueId::new(u),
        Value::Url(u) => ValueSetUrl::new(u),
        Value::UrlN(u) => ValueSetUrlN::new(u),
        Value::DateTime(u) => ValueSetDateTime::new(u),
        Value::PrivateBinary(u) => ValueSetPrivateBinary::new(u),
        Value::OauthScope(u) => ValueSetOauthScope::new(u),
        Value::Address(u) => ValueSetAddress::new(u),
        Value::Cred(t, c) => ValueSetCredential::new(t, c),
        Value::SshKey(t, k) => ValueSetSshKey::new(t, k),
        Value::OauthScopeMap(u, m) => ValueSetOauthScopeMap::new(u, m),
        Value::PublicBinary(t, b) => ValueSetPublicBinary::new(t, b),
        Value::IntentToken(u, s) => ValueSetIntentToken::new(u, s),
        Value::EmailAddress(a, _) => ValueSetEmailAddress::new(a),
        Value::UiHint(u) => ValueSetUiHint::new(u),
        Value::AuditLogString(c, s) => ValueSetAuditLogString::new((c, s)),
        Value::Image(imagevalue) => image::ValueSetImage::new(imagevalue),
        Value::CredentialType(c) => ValueSetCredentialType::new(c),
        Value::Certificate(c) => ValueSetCertificate::new(c)?,
        Value::WebauthnAttestationCaList(_)
        | Value::PhoneNumber(_, _)
        | Value::ApplicationPassword(_)
        | Value::Passkey(_, _, _)
        | Value::AttestedPasskey(_, _, _)
        | Value::TotpSecret(_, _)
        | Value::Session(_, _)
        | Value::ApiToken(_, _)
        | Value::OAuth2Session(_, _)
        | Value::OauthClaimMap(_, _)
        | Value::OauthClaimValue(_, _, _)
        | Value::JwsKeyEs256(_)
        | Value::JwsKeyRs256(_)
        | Value::HexString(_)
        | Value::Json(_)
        | Value::Sha256(_)
        | Value::KeyInternal { .. } => {
            debug_assert!(false);
            return Err(OperationError::InvalidValueState);
        }
    };

    for maybe_v in iter {
        let v = maybe_v?;
        // Need to error if wrong type (but shouldn't be due to the way qs works)
        vs.insert_checked(v)?;
    }
    Ok(vs)
}

pub fn from_value_iter(mut iter: impl Iterator<Item = Value>) -> Result<ValueSet, OperationError> {
    let Some(init) = iter.next() else {
        trace!("Empty value iterator");
        return Err(OperationError::InvalidValueState);
    };

    let mut vs: ValueSet = match init {
        Value::Utf8(s) => ValueSetUtf8::new(s),
        Value::Iutf8(s) => ValueSetIutf8::new(&s),
        Value::Iutf8N(s) => ValueSetIutf8N::new(&s),
        Value::Iname(s) => ValueSetIname::new(&s),
        Value::InameN(s) => ValueSetInameN::new(&s),
        Value::Uuid(u) | Value::UuidN(u) => ValueSetUuid::new(u),
        Value::Refer(u) => ValueSetRefer::new(u),
        Value::ReferN(u) => ValueSetReferN::new(u),
        Value::Bool(u) => ValueSetBool::new(u),
        Value::Uint32(u) => ValueSetUint32::new(u),
        Value::Int64(u) => ValueSetInt64::new(u),
        Value::Uint64(u) => ValueSetUint64::new(u),
        Value::Syntax(u) => ValueSetSyntax::new(u),
        Value::Index(u) => ValueSetIndex::new(u),
        Value::SecretValue(u) => ValueSetSecret::new(u),
        Value::Spn(n, d) => ValueSetSpn::new((n, d)),
        Value::Cid(u) => ValueSetCid::new(u),
        Value::JsonFilt(u) => ValueSetJsonFilter::new(u),
        Value::Nsuniqueid(u) => ValueSetNsUniqueId::new(u),
        Value::Url(u) => ValueSetUrl::new(u),
        Value::UrlN(u) => ValueSetUrlN::new(u),
        Value::DateTime(u) => ValueSetDateTime::new(u),
        Value::PrivateBinary(u) => ValueSetPrivateBinary::new(u),
        Value::OauthScope(u) => ValueSetOauthScope::new(u),
        Value::Address(u) => ValueSetAddress::new(u),
        Value::Cred(t, c) => ValueSetCredential::new(t, c),
        Value::SshKey(t, k) => ValueSetSshKey::new(t, k),
        Value::OauthScopeMap(u, m) => ValueSetOauthScopeMap::new(u, m),
        Value::PublicBinary(t, b) => ValueSetPublicBinary::new(t, b),
        Value::IntentToken(u, s) => ValueSetIntentToken::new(u, s),
        Value::EmailAddress(a, _) => ValueSetEmailAddress::new(a),
        Value::Passkey(u, t, k) => ValueSetPasskey::new(u, t, k),
        Value::AttestedPasskey(u, t, k) => ValueSetAttestedPasskey::new(u, t, k),
        Value::JwsKeyEs256(k) => ValueSetJwsKeyEs256::new(k),
        Value::JwsKeyRs256(k) => ValueSetJwsKeyRs256::new(k),
        Value::Session(u, m) => ValueSetSession::new(u, m),
        Value::ApiToken(u, m) => ValueSetApiTokenSet::new(u, m),
        Value::OAuth2Session(u, m) => ValueSetOauth2Session::new(u, m),
        Value::UiHint(u) => ValueSetUiHint::new(u),
        Value::TotpSecret(l, t) => ValueSetTotpSecret::new(l, t),
        Value::AuditLogString(c, s) => ValueSetAuditLogString::new((c, s)),
        Value::Image(imagevalue) => image::ValueSetImage::new(imagevalue),
        Value::CredentialType(c) => ValueSetCredentialType::new(c),
        Value::WebauthnAttestationCaList(ca_list) => {
            ValueSetWebauthnAttestationCaList::new(ca_list)
        }
        Value::OauthClaimMap(name, join) => ValueSetOauthClaimMap::new(name, join),
        Value::OauthClaimValue(name, group, claims) => {
            ValueSetOauthClaimMap::new_value(name, group, claims)
        }
        Value::HexString(s) => ValueSetHexString::new(s),

        Value::KeyInternal {
            id,
            usage,
            valid_from,
            status,
            status_cid,
            der,
        } => ValueSetKeyInternal::new(id, usage, valid_from, status, status_cid, der),
        Value::Certificate(certificate) => ValueSetCertificate::new(certificate)?,
        Value::PhoneNumber(_, _) => {
            debug_assert!(false);
            return Err(OperationError::InvalidValueState);
        }
        Value::ApplicationPassword(ap) => ValueSetApplicationPassword::new(ap),
        Value::Sha256(_) => {
            debug_assert!(false);
            return Err(OperationError::InvalidValueState);
        }
        Value::Json(_) => {
            debug_assert!(false);
            return Err(OperationError::InvalidValueState);
        }
    };

    for v in iter {
        vs.insert_checked(v)?;
    }
    Ok(vs)
}

pub fn from_db_valueset_v2(dbvs: DbValueSetV2) -> Result<ValueSet, OperationError> {
    match dbvs {
        DbValueSetV2::Utf8(set) => ValueSetUtf8::from_dbvs2(set),
        DbValueSetV2::Iutf8(set) => ValueSetIutf8N::from_dbvs2(set),
        DbValueSetV2::Iutf8Single(set) => ValueSetIutf8::from_dbvs2(set),
        DbValueSetV2::Iname(set) => ValueSetInameN::from_dbvs2(set),
        DbValueSetV2::InameSingle(set) => ValueSetIname::from_dbvs2(set),
        DbValueSetV2::Uuid(set) => ValueSetUuidN::from_dbvs2(set),
        DbValueSetV2::UuidSingle(uuid) => ValueSetUuid::from_dbvs2(uuid),

        DbValueSetV2::Reference(set) => ValueSetReferN::from_dbvs2(set),
        DbValueSetV2::ReferenceSingle(set) => ValueSetRefer::from_dbvs2(set),
        DbValueSetV2::Bool(set) => ValueSetBool::from_dbvs2(set),
        DbValueSetV2::Uint32(set) => ValueSetUint32::from_dbvs2(set),
        DbValueSetV2::Int64(set) => ValueSetInt64::from_dbvs2(set),
        DbValueSetV2::Uint64(set) => ValueSetUint64::from_dbvs2(set),
        DbValueSetV2::SyntaxType(set) => ValueSetSyntax::from_dbvs2(set),
        DbValueSetV2::IndexType(set) => ValueSetIndex::from_dbvs2(set),
        DbValueSetV2::SecretValue(set) => ValueSetSecret::from_dbvs2(set),
        DbValueSetV2::Spn(set) => ValueSetSpn::from_dbvs2(set),
        DbValueSetV2::Cid(set) => ValueSetCid::from_dbvs2(set),
        DbValueSetV2::JsonFilter(set) => ValueSetJsonFilter::from_dbvs2(&set),
        DbValueSetV2::NsUniqueId(set) => ValueSetNsUniqueId::from_dbvs2(set),
        DbValueSetV2::Url(set) => ValueSetUrlN::from_dbvs2(set),
        DbValueSetV2::UrlSingle(set) => ValueSetUrl::from_dbvs2(set),
        DbValueSetV2::DateTime(set) => ValueSetDateTime::from_dbvs2(set),
        DbValueSetV2::PrivateBinary(set) => ValueSetPrivateBinary::from_dbvs2(set),
        DbValueSetV2::OauthScope(set) => ValueSetOauthScope::from_dbvs2(set),
        DbValueSetV2::Address(set) => ValueSetAddress::from_dbvs2(set),
        DbValueSetV2::Credential(set) => ValueSetCredential::from_dbvs2(set),
        DbValueSetV2::SshKey(set) => ValueSetSshKey::from_dbvs2(set),
        DbValueSetV2::OauthScopeMap(set) => ValueSetOauthScopeMap::from_dbvs2(set),
        DbValueSetV2::PublicBinary(set) => ValueSetPublicBinary::from_dbvs2(set),
        DbValueSetV2::IntentToken(set) => ValueSetIntentToken::from_dbvs2(set),
        DbValueSetV2::EmailAddress(primary, set) => ValueSetEmailAddress::from_dbvs2(primary, set),
        DbValueSetV2::Passkey(set) => ValueSetPasskey::from_dbvs2(set),
        DbValueSetV2::AttestedPasskey(set) => ValueSetAttestedPasskey::from_dbvs2(set),
        DbValueSetV2::Session(set) => ValueSetSession::from_dbvs2(&set),
        DbValueSetV2::ApiTokenSet(set) => ValueSetApiTokenSet::from_dbvs2(set),
        DbValueSetV2::Oauth2Session(set) => ValueSetOauth2Session::from_dbvs2(set),
        DbValueSetV2::JwsKeyEs256(set) => ValueSetJwsKeyEs256::from_dbvs2(&set),
        DbValueSetV2::JwsKeyRs256(set) => ValueSetJwsKeyEs256::from_dbvs2(&set),
        DbValueSetV2::UiHint(set) => ValueSetUiHint::from_dbvs2(set),
        DbValueSetV2::TotpSecret(set) => ValueSetTotpSecret::from_dbvs2(set),
        DbValueSetV2::AuditLogString(set) => ValueSetAuditLogString::from_dbvs2(set),
        DbValueSetV2::PhoneNumber(_, _) | DbValueSetV2::TrustedDeviceEnrollment(_) => {
            debug_assert!(false);
            Err(OperationError::InvalidValueState)
        }
        DbValueSetV2::Image(set) => ValueSetImage::from_dbvs2(&set),
        DbValueSetV2::CredentialType(set) => ValueSetCredentialType::from_dbvs2(set),
        DbValueSetV2::WebauthnAttestationCaList { ca_list } => {
            ValueSetWebauthnAttestationCaList::from_dbvs2(ca_list)
        }
        DbValueSetV2::OauthClaimMap(set) => ValueSetOauthClaimMap::from_dbvs2(set),
        DbValueSetV2::KeyInternal(set) => ValueSetKeyInternal::from_dbvs2(set),
        DbValueSetV2::HexString(set) => ValueSetHexString::from_dbvs2(set),
        DbValueSetV2::Certificate(set) => ValueSetCertificate::from_dbvs2(set),
        DbValueSetV2::ApplicationPassword(set) => ValueSetApplicationPassword::from_dbvs2(set),
        DbValueSetV2::Json(object) => Ok(ValueSetJson::new(object)),
        DbValueSetV2::Sha256(set) => ValueSetSha256::from_dbvs2(set),
        DbValueSetV2::Message(object) => Ok(ValueSetMessage::new(object)),
        DbValueSetV2::EcKeyPrivate(_) | DbValueSetV2::RestrictedString(_) => {
            error!("Use of a deprecated database type");
            debug_assert!(false);
            Err(OperationError::InvalidState)
        }
    }
}

#[cfg(test)]
pub(crate) fn scim_json_reflexive(vs: &ValueSet, data: &str) {
    let scim_value = vs.to_scim_value().unwrap().assume_resolved();

    let strout = serde_json::to_string_pretty(&scim_value).unwrap();
    eprintln!("{strout}");

    let json_value: serde_json::Value = serde_json::to_value(&scim_value).unwrap();

    eprintln!("{data}");
    let expect: serde_json::Value = serde_json::from_str(data).unwrap();

    assert_eq!(json_value, expect);
}

#[cfg(test)]
pub(crate) fn scim_json_reflexive_unresolved(
    write_txn: &mut QueryServerWriteTransaction,
    vs: &ValueSet,
    data: &str,
) {
    let scim_int_value = vs.to_scim_value().unwrap().assume_unresolved();
    let scim_value = write_txn.resolve_scim_interim(scim_int_value).unwrap();

    let strout = serde_json::to_string_pretty(&scim_value).expect("Failed to serialize");
    eprintln!("{strout}");

    let json_value: serde_json::Value =
        serde_json::to_value(&scim_value).expect("Failed to convert to JSON");

    let expect: serde_json::Value =
        serde_json::from_str(data).expect("Failed to parse expected JSON");

    assert_eq!(json_value, expect);
}

#[cfg(test)]
pub(crate) fn scim_json_put_reflexive<T: ValueSetScimPut>(
    expect_vs: &ValueSet,
    additional_tests: &[(JsonValue, ValueSet)],
) {
    let scim_value = expect_vs.to_scim_value().unwrap().assume_resolved();

    let strout = serde_json::to_string_pretty(&scim_value).unwrap();
    eprintln!("{strout}");

    let generic = serde_json::to_value(scim_value).unwrap();
    // Check that we can turn back into a vs from the generic version.
    let vs = T::from_scim_json_put(generic).unwrap().assume_resolved();
    assert_eq!(&vs, expect_vs);

    // For each additional check, assert they work as expected.
    for (jv, expect_vs) in additional_tests {
        let vs = T::from_scim_json_put(jv.clone()).unwrap().assume_resolved();
        assert_eq!(&vs, expect_vs);
    }
}

#[cfg(test)]
pub(crate) fn scim_json_put_reflexive_unresolved<T: ValueSetScimPut>(
    write_txn: &mut QueryServerWriteTransaction,
    expect_vs: &ValueSet,
    additional_tests: &[(JsonValue, ValueSet)],
) {
    let scim_int_value = expect_vs.to_scim_value().unwrap().assume_unresolved();
    let scim_value = write_txn.resolve_scim_interim(scim_int_value).unwrap();

    let generic = serde_json::to_value(scim_value).unwrap();
    // Check that we can turn back into a vs from the generic version.
    let vs_inter = T::from_scim_json_put(generic).unwrap().assume_unresolved();
    let vs = write_txn.resolve_valueset_intermediate(vs_inter).unwrap();
    assert_eq!(&vs, expect_vs);

    // For each additional check, assert they work as expected.
    for (jv, expect_vs) in additional_tests {
        let vs_inter = T::from_scim_json_put(jv.clone())
            .unwrap()
            .assume_unresolved();
        let vs = write_txn.resolve_valueset_intermediate(vs_inter).unwrap();
        assert_eq!(&vs, expect_vs);
    }
}
