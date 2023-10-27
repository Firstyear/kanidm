//! Constant Entries for the IDM
use crate::prelude::{idm_builtin_admin_groups, AttrString};
use enum_iterator::Sequence;
use std::fmt::Display;

use crate::constants::uuids::*;
use crate::entry::{Entry, EntryInit, EntryInitNew, EntryNew};
use crate::idm::account::Account;
use crate::value::PartialValue;
use crate::value::Value;
use kanidm_proto::constants::*;
use kanidm_proto::v1::{AccountType, OperationError};

#[cfg(test)]
use uuid::uuid;

use uuid::Uuid;

#[test]
fn test_valueattribute_as_str() {
    assert!(Attribute::Class.as_ref() == "class");
    assert!(Attribute::Class.to_string() == String::from("class"));
}

#[test]
// this ensures we cover both ends of the conversion to/from string-types
fn test_valueattribute_round_trip() {
    use enum_iterator::all;
    let the_list = all::<Attribute>().collect::<Vec<_>>();
    for attr in the_list {
        let s: &'static str = attr.into();
        let attr2 = Attribute::try_from(s.to_string()).unwrap();
        assert!(attr == attr2);
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Sequence, Hash)]
pub enum Attribute {
    Account,
    AccountExpire,
    AccountValidFrom,
    AcpCreateAttr,
    AcpCreateClass,
    AcpEnable,
    AcpModifyClass,
    AcpModifyPresentAttr,
    AcpModifyRemovedAttr,
    AcpReceiver,
    AcpReceiverGroup,
    AcpSearchAttr,
    AcpTargetScope,
    ApiTokenSession,
    Attr,
    AttributeName,
    AttributeType,
    AuthSessionExpiry,
    BadlistPassword,
    Claim,
    Class,
    ClassName,
    Cn,
    CookiePrivateKey,
    CredentialUpdateIntentToken,
    DeniedName,
    Description,
    DeviceKeys,
    DirectMemberOf,
    DisplayName,
    Dn,
    Domain,
    DomainDisplayName,
    DomainLdapBasedn,
    DomainName,
    DomainSsid,
    DomainTokenKey,
    DomainUuid,
    DynGroup,
    DynGroupFilter,
    DynMember,
    Email,
    EmailAlternative,
    EmailPrimary,
    EntryDn,
    EntryUuid,
    Es256PrivateKeyDer,
    Excludes,
    FernetPrivateKeyStr,
    GidNumber,
    GrantUiHint,
    Group,
    IdVerificationEcKey,
    Image,
    Index,
    IpaNtHash,
    IpaSshPubKey,
    JwsEs256PrivateKey,
    LastModifiedCid,
    LdapAllowUnixPwBind,
    /// An LDAP Compatible emailAddress
    LdapEmailAddress,
    /// An LDAP Compatible sshkeys virtual attribute
    LdapKeys,
    LegalName,
    LoginShell,
    Mail,
    May,
    Member,
    MemberOf,
    MultiValue,
    Must,
    Name,
    NameHistory,
    NoIndex,
    NsUniqueId,
    OAuth2AllowInsecureClientDisablePkce,
    OAuth2ConsentScopeMap,
    OAuth2JwtLegacyCryptoEnable,
    OAuth2PreferShortUsername,
    OAuth2RsBasicSecret,
    OAuth2RsImplicitScopes,
    OAuth2RsName,
    OAuth2RsOrigin,
    OAuth2RsOriginLanding,
    OAuth2RsScopeMap,
    OAuth2RsSupScopeMap,
    OAuth2RsTokenKey,
    OAuth2Session,
    ObjectClass,
    OtherNoIndex,
    PassKeys,
    PasswordImport,
    Phantom,
    PrimaryCredential,
    PrivateCookieKey,
    PrivilegeExpiry,
    RadiusSecret,
    Replicated,
    Rs256PrivateKeyDer,
    Scope,
    SourceUuid,
    Spn,
    /// An LDAP-compatible sshpublickey
    LdapSshPublicKey,
    /// The Kanidm-local ssh_publickey
    SshPublicKey,
    Supplements,
    SystemSupplements,
    SyncAllowed,
    SyncClass,
    SyncCookie,
    SyncCredentialPortal,
    SyncExternalId,
    SyncParentUuid,
    SyncTokenSession,
    SyncYieldAuthority,
    Syntax,
    SystemExcludes,
    SystemMay,
    SystemMust,
    Term,
    TotpImport,
    Uid,
    UidNumber,
    Unique,
    UnixPassword,
    UserAuthTokenSession,
    UserId,
    UserPassword,
    Uuid,
    Version,

    #[cfg(any(debug_assertions, test))]
    NonExist,
    #[cfg(any(debug_assertions, test))]
    TestAttr,
    #[cfg(any(debug_assertions, test))]
    TestNumber,
    #[cfg(any(debug_assertions, test))]
    Extra,
    #[cfg(any(debug_assertions, test))]
    TestNotAllowed,
}

impl AsRef<str> for Attribute {
    fn as_ref(&self) -> &str {
        self.into()
    }
}

impl From<&Attribute> for &'static str {
    fn from(value: &Attribute) -> Self {
        (*value).into()
    }
}

impl TryFrom<&str> for Attribute {
    type Error = OperationError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Attribute::try_from(value.to_string())
    }
}

impl TryFrom<&AttrString> for Attribute {
    type Error = OperationError;

    fn try_from(value: &AttrString) -> Result<Self, Self::Error> {
        Attribute::try_from(value.to_string())
    }
}

impl TryFrom<String> for Attribute {
    type Error = OperationError;
    fn try_from(val: String) -> Result<Self, OperationError> {
        let res = match val.as_str() {
            ATTR_ACCOUNT => Attribute::Account,
            ATTR_ACCOUNT_EXPIRE => Attribute::AccountExpire,
            ATTR_ACCOUNT_VALID_FROM => Attribute::AccountValidFrom,
            ATTR_ACP_CREATE_ATTR => Attribute::AcpCreateAttr,
            ATTR_ACP_CREATE_CLASS => Attribute::AcpCreateClass,
            ATTR_ACP_ENABLE => Attribute::AcpEnable,
            ATTR_ACP_MODIFY_CLASS => Attribute::AcpModifyClass,
            ATTR_ACP_MODIFY_PRESENTATTR => Attribute::AcpModifyPresentAttr,
            ATTR_ACP_MODIFY_REMOVEDATTR => Attribute::AcpModifyRemovedAttr,
            ATTR_ACP_RECEIVER => Attribute::AcpReceiver,
            ATTR_ACP_RECEIVER_GROUP => Attribute::AcpReceiverGroup,
            ATTR_ACP_SEARCH_ATTR => Attribute::AcpSearchAttr,
            ATTR_ACP_TARGET_SCOPE => Attribute::AcpTargetScope,
            ATTR_API_TOKEN_SESSION => Attribute::ApiTokenSession,
            ATTR_ATTR => Attribute::Attr,
            ATTR_ATTRIBUTENAME => Attribute::AttributeName,
            ATTR_ATTRIBUTETYPE => Attribute::AttributeType,
            ATTR_AUTH_SESSION_EXPIRY => Attribute::AuthSessionExpiry,
            ATTR_BADLIST_PASSWORD => Attribute::BadlistPassword,
            ATTR_CLAIM => Attribute::Claim,
            ATTR_CLASS => Attribute::Class,
            ATTR_CLASSNAME => Attribute::ClassName,
            ATTR_CN => Attribute::Cn,
            ATTR_COOKIE_PRIVATE_KEY => Attribute::CookiePrivateKey,
            ATTR_CREDENTIAL_UPDATE_INTENT_TOKEN => Attribute::CredentialUpdateIntentToken,
            ATTR_DENIED_NAME => Attribute::DeniedName,
            ATTR_DESCRIPTION => Attribute::Description,
            ATTR_DEVICEKEYS => Attribute::DeviceKeys,
            ATTR_DIRECTMEMBEROF => Attribute::DirectMemberOf,
            ATTR_DISPLAYNAME => Attribute::DisplayName,
            ATTR_DN => Attribute::Dn,
            ATTR_DOMAIN => Attribute::Domain,
            ATTR_DOMAIN_DISPLAY_NAME => Attribute::DomainDisplayName,
            ATTR_DOMAIN_LDAP_BASEDN => Attribute::DomainLdapBasedn,
            ATTR_DOMAIN_NAME => Attribute::DomainName,
            ATTR_DOMAIN_SSID => Attribute::DomainSsid,
            ATTR_DOMAIN_TOKEN_KEY => Attribute::DomainTokenKey,
            ATTR_DOMAIN_UUID => Attribute::DomainUuid,
            ATTR_DYNGROUP => Attribute::DynGroup,
            ATTR_DYNGROUP_FILTER => Attribute::DynGroupFilter,
            ATTR_DYNMEMBER => Attribute::DynMember,
            ATTR_EMAIL => Attribute::Email,
            ATTR_EMAIL_ALTERNATIVE => Attribute::EmailAlternative,
            ATTR_EMAIL_PRIMARY => Attribute::EmailPrimary,
            ATTR_ENTRYDN => Attribute::EntryDn,
            ATTR_ENTRYUUID => Attribute::EntryUuid,
            ATTR_ES256_PRIVATE_KEY_DER => Attribute::Es256PrivateKeyDer,
            ATTR_EXCLUDES => Attribute::Excludes,
            ATTR_FERNET_PRIVATE_KEY_STR => Attribute::FernetPrivateKeyStr,
            ATTR_GIDNUMBER => Attribute::GidNumber,
            ATTR_GRANT_UI_HINT => Attribute::GrantUiHint,
            ATTR_GROUP => Attribute::Group,
            ATTR_ID_VERIFICATION_ECKEY => Attribute::IdVerificationEcKey,
            ATTR_IMAGE => Attribute::Image,
            ATTR_INDEX => Attribute::Index,
            ATTR_IPANTHASH => Attribute::IpaNtHash,
            ATTR_IPASSHPUBKEY => Attribute::IpaSshPubKey,
            ATTR_JWS_ES256_PRIVATE_KEY => Attribute::JwsEs256PrivateKey,
            ATTR_LAST_MODIFIED_CID => Attribute::LastModifiedCid,
            ATTR_LDAP_ALLOW_UNIX_PW_BIND => Attribute::LdapAllowUnixPwBind,
            ATTR_LDAP_EMAIL_ADDRESS => Attribute::LdapEmailAddress,
            ATTR_LDAP_KEYS => Attribute::LdapKeys,
            ATTR_SSH_PUBLICKEY => Attribute::SshPublicKey,
            ATTR_LEGALNAME => Attribute::LegalName,
            ATTR_LOGINSHELL => Attribute::LoginShell,
            ATTR_MAIL => Attribute::Mail,
            ATTR_MAY => Attribute::May,
            ATTR_MEMBER => Attribute::Member,
            ATTR_MEMBEROF => Attribute::MemberOf,
            ATTR_MULTIVALUE => Attribute::MultiValue,
            ATTR_MUST => Attribute::Must,
            ATTR_NAME => Attribute::Name,
            ATTR_NAME_HISTORY => Attribute::NameHistory,
            ATTR_NO_INDEX => Attribute::NoIndex,
            ATTR_NSUNIQUEID => Attribute::NsUniqueId,
            ATTR_OAUTH2_ALLOW_INSECURE_CLIENT_DISABLE_PKCE => {
                Attribute::OAuth2AllowInsecureClientDisablePkce
            }
            ATTR_OAUTH2_CONSENT_SCOPE_MAP => Attribute::OAuth2ConsentScopeMap,
            ATTR_OAUTH2_JWT_LEGACY_CRYPTO_ENABLE => Attribute::OAuth2JwtLegacyCryptoEnable,
            ATTR_OAUTH2_PREFER_SHORT_USERNAME => Attribute::OAuth2PreferShortUsername,
            ATTR_OAUTH2_RS_BASIC_SECRET => Attribute::OAuth2RsBasicSecret,
            ATTR_OAUTH2_RS_IMPLICIT_SCOPES => Attribute::OAuth2RsImplicitScopes,
            ATTR_OAUTH2_RS_NAME => Attribute::OAuth2RsName,
            ATTR_OAUTH2_RS_ORIGIN => Attribute::OAuth2RsOrigin,
            ATTR_OAUTH2_RS_ORIGIN_LANDING => Attribute::OAuth2RsOriginLanding,
            ATTR_OAUTH2_RS_SCOPE_MAP => Attribute::OAuth2RsScopeMap,
            ATTR_OAUTH2_RS_SUP_SCOPE_MAP => Attribute::OAuth2RsSupScopeMap,
            ATTR_OAUTH2_RS_TOKEN_KEY => Attribute::OAuth2RsTokenKey,
            ATTR_OAUTH2_SESSION => Attribute::OAuth2Session,
            ATTR_OBJECTCLASS => Attribute::ObjectClass,
            ATTR_OTHER_NO_INDEX => Attribute::OtherNoIndex,
            ATTR_PASSKEYS => Attribute::PassKeys,
            ATTR_PASSWORD_IMPORT => Attribute::PasswordImport,
            ATTR_PHANTOM => Attribute::Phantom,
            ATTR_PRIMARY_CREDENTIAL => Attribute::PrimaryCredential,
            ATTR_PRIVATE_COOKIE_KEY => Attribute::PrivateCookieKey,
            ATTR_PRIVILEGE_EXPIRY => Attribute::PrivilegeExpiry,
            ATTR_RADIUS_SECRET => Attribute::RadiusSecret,
            ATTR_REPLICATED => Attribute::Replicated,
            ATTR_RS256_PRIVATE_KEY_DER => Attribute::Rs256PrivateKeyDer,
            ATTR_SCOPE => Attribute::Scope,
            ATTR_SOURCE_UUID => Attribute::SourceUuid,
            ATTR_SPN => Attribute::Spn,
            ATTR_LDAP_SSHPUBLICKEY => Attribute::LdapSshPublicKey,
            ATTR_SUPPLEMENTS => Attribute::Supplements,
            ATTR_SYNC_ALLOWED => Attribute::SyncAllowed,
            ATTR_SYNC_CLASS => Attribute::SyncClass,
            ATTR_SYNC_COOKIE => Attribute::SyncCookie,
            ATTR_SYNC_CREDENTIAL_PORTAL => Attribute::SyncCredentialPortal,
            ATTR_SYNC_EXTERNAL_ID => Attribute::SyncExternalId,
            ATTR_SYNC_PARENT_UUID => Attribute::SyncParentUuid,
            ATTR_SYNC_TOKEN_SESSION => Attribute::SyncTokenSession,
            ATTR_SYNC_YIELD_AUTHORITY => Attribute::SyncYieldAuthority,
            ATTR_SYNTAX => Attribute::Syntax,
            ATTR_SYSTEMEXCLUDES => Attribute::SystemExcludes,
            ATTR_SYSTEMMAY => Attribute::SystemMay,
            ATTR_SYSTEMMUST => Attribute::SystemMust,
            ATTR_SYSTEMSUPPLEMENTS => Attribute::SystemSupplements,
            ATTR_TERM => Attribute::Term,
            ATTR_TOTP_IMPORT => Attribute::TotpImport,
            ATTR_UID => Attribute::Uid,
            ATTR_UIDNUMBER => Attribute::UidNumber,
            ATTR_UNIQUE => Attribute::Unique,
            ATTR_UNIX_PASSWORD => Attribute::UnixPassword,
            ATTR_USER_AUTH_TOKEN_SESSION => Attribute::UserAuthTokenSession,
            ATTR_USERID => Attribute::UserId,
            ATTR_USERPASSWORD => Attribute::UserPassword,
            ATTR_UUID => Attribute::Uuid,
            ATTR_VERSION => Attribute::Version,

            #[cfg(any(debug_assertions, test))]
            TEST_ATTR_NON_EXIST => Attribute::NonExist,
            #[cfg(any(debug_assertions, test))]
            TEST_ATTR_TEST_ATTR => Attribute::TestAttr,
            #[cfg(any(debug_assertions, test))]
            TEST_ATTR_EXTRA => Attribute::Extra,
            #[cfg(any(debug_assertions, test))]
            TEST_ATTR_NUMBER => Attribute::TestNumber,
            #[cfg(any(debug_assertions, test))]
            TEST_ATTR_NOTALLOWED => Attribute::TestNotAllowed,
            _ => {
                trace!("Failed to convert {} to Attribute", val);
                return Err(OperationError::InvalidAttributeName(val));
            }
        };
        Ok(res)
    }
}

impl From<Attribute> for &'static str {
    fn from(val: Attribute) -> Self {
        match val {
            Attribute::Account => ATTR_ACCOUNT,
            Attribute::AccountExpire => ATTR_ACCOUNT_EXPIRE,
            Attribute::AccountValidFrom => ATTR_ACCOUNT_VALID_FROM,
            Attribute::AcpCreateAttr => ATTR_ACP_CREATE_ATTR,
            Attribute::AcpCreateClass => ATTR_ACP_CREATE_CLASS,
            Attribute::AcpEnable => ATTR_ACP_ENABLE,
            Attribute::AcpModifyClass => ATTR_ACP_MODIFY_CLASS,
            Attribute::AcpModifyPresentAttr => ATTR_ACP_MODIFY_PRESENTATTR,
            Attribute::AcpModifyRemovedAttr => ATTR_ACP_MODIFY_REMOVEDATTR,
            Attribute::AcpReceiver => ATTR_ACP_RECEIVER,
            Attribute::AcpReceiverGroup => ATTR_ACP_RECEIVER_GROUP,
            Attribute::AcpSearchAttr => ATTR_ACP_SEARCH_ATTR,
            Attribute::AcpTargetScope => ATTR_ACP_TARGET_SCOPE,
            Attribute::ApiTokenSession => ATTR_API_TOKEN_SESSION,
            Attribute::Attr => ATTR_ATTR,
            Attribute::AttributeName => ATTR_ATTRIBUTENAME,
            Attribute::AttributeType => ATTR_ATTRIBUTETYPE,
            Attribute::AuthSessionExpiry => ATTR_AUTH_SESSION_EXPIRY,
            Attribute::BadlistPassword => ATTR_BADLIST_PASSWORD,
            Attribute::Claim => ATTR_CLAIM,
            Attribute::Class => ATTR_CLASS,
            Attribute::ClassName => ATTR_CLASSNAME,
            Attribute::Cn => ATTR_CN,
            Attribute::CookiePrivateKey => ATTR_COOKIE_PRIVATE_KEY,
            Attribute::CredentialUpdateIntentToken => ATTR_CREDENTIAL_UPDATE_INTENT_TOKEN,
            Attribute::DeniedName => ATTR_DENIED_NAME,
            Attribute::Description => ATTR_DESCRIPTION,
            Attribute::DeviceKeys => ATTR_DEVICEKEYS,
            Attribute::DirectMemberOf => ATTR_DIRECTMEMBEROF,
            Attribute::DisplayName => ATTR_DISPLAYNAME,
            Attribute::Dn => ATTR_DN,
            Attribute::Domain => ATTR_DOMAIN,
            Attribute::DomainDisplayName => ATTR_DOMAIN_DISPLAY_NAME,
            Attribute::DomainLdapBasedn => ATTR_DOMAIN_LDAP_BASEDN,
            Attribute::DomainName => ATTR_DOMAIN_NAME,
            Attribute::DomainSsid => ATTR_DOMAIN_SSID,
            Attribute::DomainTokenKey => ATTR_DOMAIN_TOKEN_KEY,
            Attribute::DomainUuid => ATTR_DOMAIN_UUID,
            Attribute::DynGroup => ATTR_DYNGROUP,
            Attribute::DynGroupFilter => ATTR_DYNGROUP_FILTER,
            Attribute::DynMember => ATTR_DYNMEMBER,
            Attribute::Email => ATTR_EMAIL,
            Attribute::EmailAlternative => ATTR_EMAIL_ALTERNATIVE,
            Attribute::EmailPrimary => ATTR_EMAIL_PRIMARY,
            Attribute::EntryDn => ATTR_ENTRYDN,
            Attribute::EntryUuid => ATTR_ENTRYUUID,
            Attribute::Es256PrivateKeyDer => ATTR_ES256_PRIVATE_KEY_DER,
            Attribute::Excludes => ATTR_EXCLUDES,
            Attribute::FernetPrivateKeyStr => ATTR_FERNET_PRIVATE_KEY_STR,
            Attribute::GidNumber => ATTR_GIDNUMBER,
            Attribute::GrantUiHint => ATTR_GRANT_UI_HINT,
            Attribute::Group => ATTR_GROUP,
            Attribute::IdVerificationEcKey => ATTR_ID_VERIFICATION_ECKEY,
            Attribute::Image => ATTR_IMAGE,
            Attribute::Index => ATTR_INDEX,
            Attribute::IpaNtHash => ATTR_IPANTHASH,
            Attribute::IpaSshPubKey => ATTR_IPASSHPUBKEY,
            Attribute::JwsEs256PrivateKey => ATTR_JWS_ES256_PRIVATE_KEY,
            Attribute::LastModifiedCid => ATTR_LAST_MODIFIED_CID,
            Attribute::LdapAllowUnixPwBind => ATTR_LDAP_ALLOW_UNIX_PW_BIND,
            Attribute::LdapEmailAddress => ATTR_LDAP_EMAIL_ADDRESS,
            Attribute::LdapKeys => ATTR_LDAP_KEYS,
            Attribute::LdapSshPublicKey => ATTR_LDAP_SSHPUBLICKEY,
            Attribute::LegalName => ATTR_LEGALNAME,
            Attribute::LoginShell => ATTR_LOGINSHELL,
            Attribute::Mail => ATTR_MAIL,
            Attribute::May => ATTR_MAY,
            Attribute::Member => ATTR_MEMBER,
            Attribute::MemberOf => ATTR_MEMBEROF,
            Attribute::MultiValue => ATTR_MULTIVALUE,
            Attribute::Must => ATTR_MUST,
            Attribute::Name => ATTR_NAME,
            Attribute::NameHistory => ATTR_NAME_HISTORY,
            Attribute::NoIndex => ATTR_NO_INDEX,
            Attribute::NsUniqueId => ATTR_NSUNIQUEID,
            Attribute::OAuth2AllowInsecureClientDisablePkce => {
                ATTR_OAUTH2_ALLOW_INSECURE_CLIENT_DISABLE_PKCE
            }
            Attribute::OAuth2ConsentScopeMap => ATTR_OAUTH2_CONSENT_SCOPE_MAP,
            Attribute::OAuth2JwtLegacyCryptoEnable => ATTR_OAUTH2_JWT_LEGACY_CRYPTO_ENABLE,
            Attribute::OAuth2PreferShortUsername => ATTR_OAUTH2_PREFER_SHORT_USERNAME,
            Attribute::OAuth2RsBasicSecret => ATTR_OAUTH2_RS_BASIC_SECRET,
            Attribute::OAuth2RsImplicitScopes => ATTR_OAUTH2_RS_IMPLICIT_SCOPES,
            Attribute::OAuth2RsName => ATTR_OAUTH2_RS_NAME,
            Attribute::OAuth2RsOrigin => ATTR_OAUTH2_RS_ORIGIN,
            Attribute::OAuth2RsOriginLanding => ATTR_OAUTH2_RS_ORIGIN_LANDING,
            Attribute::OAuth2RsScopeMap => ATTR_OAUTH2_RS_SCOPE_MAP,
            Attribute::OAuth2RsSupScopeMap => ATTR_OAUTH2_RS_SUP_SCOPE_MAP,
            Attribute::OAuth2RsTokenKey => ATTR_OAUTH2_RS_TOKEN_KEY,
            Attribute::OAuth2Session => ATTR_OAUTH2_SESSION,
            Attribute::ObjectClass => ATTR_OBJECTCLASS,
            Attribute::OtherNoIndex => ATTR_OTHER_NO_INDEX,
            Attribute::PassKeys => ATTR_PASSKEYS,
            Attribute::PasswordImport => ATTR_PASSWORD_IMPORT,
            Attribute::Phantom => ATTR_PHANTOM,
            Attribute::PrimaryCredential => ATTR_PRIMARY_CREDENTIAL,
            Attribute::PrivateCookieKey => ATTR_PRIVATE_COOKIE_KEY,
            Attribute::PrivilegeExpiry => ATTR_PRIVILEGE_EXPIRY,
            Attribute::RadiusSecret => ATTR_RADIUS_SECRET,
            Attribute::Replicated => ATTR_REPLICATED,
            Attribute::Rs256PrivateKeyDer => ATTR_RS256_PRIVATE_KEY_DER,
            Attribute::Scope => ATTR_SCOPE,
            Attribute::SourceUuid => ATTR_SOURCE_UUID,
            Attribute::Spn => ATTR_SPN,
            Attribute::SshPublicKey => ATTR_SSH_PUBLICKEY,
            Attribute::Supplements => ATTR_SUPPLEMENTS,
            Attribute::SyncAllowed => ATTR_SYNC_ALLOWED,
            Attribute::SyncClass => ATTR_SYNC_CLASS,
            Attribute::SyncCookie => ATTR_SYNC_COOKIE,
            Attribute::SyncCredentialPortal => ATTR_SYNC_CREDENTIAL_PORTAL,
            Attribute::SyncExternalId => ATTR_SYNC_EXTERNAL_ID,
            Attribute::SyncParentUuid => ATTR_SYNC_PARENT_UUID,
            Attribute::SyncTokenSession => ATTR_SYNC_TOKEN_SESSION,
            Attribute::SyncYieldAuthority => ATTR_SYNC_YIELD_AUTHORITY,
            Attribute::Syntax => ATTR_SYNTAX,
            Attribute::SystemExcludes => ATTR_SYSTEMEXCLUDES,
            Attribute::SystemMay => ATTR_SYSTEMMAY,
            Attribute::SystemMust => ATTR_SYSTEMMUST,
            Attribute::SystemSupplements => ATTR_SYSTEMSUPPLEMENTS,
            Attribute::Term => ATTR_TERM,
            Attribute::TotpImport => ATTR_TOTP_IMPORT,
            Attribute::Uid => ATTR_UID,
            Attribute::UidNumber => ATTR_UIDNUMBER,
            Attribute::Unique => ATTR_UNIQUE,
            Attribute::UnixPassword => ATTR_UNIX_PASSWORD,
            Attribute::UserAuthTokenSession => ATTR_USER_AUTH_TOKEN_SESSION,
            Attribute::UserId => ATTR_USERID,
            Attribute::UserPassword => ATTR_USERPASSWORD,
            Attribute::Uuid => ATTR_UUID,
            Attribute::Version => ATTR_VERSION,

            #[cfg(any(debug_assertions, test))]
            Attribute::NonExist => TEST_ATTR_NON_EXIST,
            #[cfg(any(debug_assertions, test))]
            Attribute::TestAttr => TEST_ATTR_TEST_ATTR,
            #[cfg(any(debug_assertions, test))]
            Attribute::Extra => TEST_ATTR_EXTRA,
            #[cfg(any(debug_assertions, test))]
            Attribute::TestNumber => TEST_ATTR_NUMBER,
            #[cfg(any(debug_assertions, test))]
            Attribute::TestNotAllowed => TEST_ATTR_NOTALLOWED,
        }
    }
}

impl From<Attribute> for AttrString {
    fn from(val: Attribute) -> Self {
        AttrString::from(val.to_string())
    }
}

impl Display for Attribute {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s: &'static str = (*self).into();
        write!(f, "{}", s)
    }
}

impl Attribute {
    pub fn to_value(self) -> Value {
        let s: &'static str = self.into();
        Value::new_iutf8(s)
    }

    pub fn to_partialvalue(self) -> PartialValue {
        let s: &'static str = self.into();
        PartialValue::new_iutf8(s)
    }
}

impl<'a> serde::Deserialize<'a> for Attribute {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'a>,
    {
        let s = String::deserialize(deserializer)?;
        Attribute::try_from(s).map_err(|e| serde::de::Error::custom(format!("{:?}", e)))
    }
}

#[derive(Copy, Clone, Debug)]
pub enum EntryClass {
    AccessControlCreate,
    AccessControlDelete,
    AccessControlModify,
    AccessControlProfile,
    AccessControlSearch,
    Account,
    AccountPolicy,
    AttributeType,
    Class,
    ClassType,
    Conflict,
    DomainInfo,
    DynGroup,
    ExtensibleObject,
    Group,
    MemberOf,
    OAuth2ResourceServer,
    OAuth2ResourceServerBasic,
    OAuth2ResourceServerPublic,
    Object,
    OrgPerson,
    Person,
    PosixAccount,
    PosixGroup,
    Recycled,
    Service,
    ServiceAccount,
    SyncAccount,
    SyncObject,
    Tombstone,
    User,
    System,
    SystemInfo,
    SystemConfig,
    #[cfg(any(test, debug_assertions))]
    TestClass,
}

impl From<EntryClass> for &'static str {
    fn from(val: EntryClass) -> Self {
        match val {
            EntryClass::AccessControlCreate => "access_control_create",
            EntryClass::AccessControlDelete => "access_control_delete",
            EntryClass::AccessControlModify => "access_control_modify",
            EntryClass::AccessControlProfile => "access_control_profile",
            EntryClass::AccessControlSearch => "access_control_search",
            EntryClass::Account => "account",
            EntryClass::AccountPolicy => "account_policy",
            EntryClass::AttributeType => "attributetype",
            EntryClass::Class => ATTR_CLASS,
            EntryClass::ClassType => "classtype",
            EntryClass::Conflict => "conflict",
            EntryClass::DomainInfo => "domain_info",
            EntryClass::DynGroup => ATTR_DYNGROUP,
            EntryClass::ExtensibleObject => "extensibleobject",
            EntryClass::Group => ATTR_GROUP,
            EntryClass::MemberOf => "memberof",
            EntryClass::OAuth2ResourceServer => "oauth2_resource_server",
            EntryClass::OAuth2ResourceServerBasic => "oauth2_resource_server_basic",
            EntryClass::OAuth2ResourceServerPublic => "oauth2_resource_server_public",
            EntryClass::Object => "object",
            EntryClass::OrgPerson => "orgperson",
            EntryClass::Person => "person",
            EntryClass::PosixAccount => "posixaccount",
            EntryClass::PosixGroup => "posixgroup",
            EntryClass::Recycled => "recycled",
            EntryClass::Service => "service",
            EntryClass::ServiceAccount => "service_account",
            EntryClass::SyncAccount => "sync_account",
            EntryClass::SyncObject => "sync_object",
            EntryClass::System => "system",
            EntryClass::SystemConfig => "system_config",
            EntryClass::SystemInfo => "system_info",
            EntryClass::Tombstone => "tombstone",
            #[cfg(any(test, debug_assertions))]
            EntryClass::TestClass => "testclass",
            EntryClass::User => "user",
        }
    }
}

impl AsRef<str> for EntryClass {
    fn as_ref(&self) -> &str {
        self.into()
    }
}

impl From<&EntryClass> for &'static str {
    fn from(value: &EntryClass) -> Self {
        (*value).into()
    }
}

impl From<EntryClass> for String {
    fn from(val: EntryClass) -> Self {
        let s: &'static str = val.into();
        s.to_string()
    }
}

impl From<EntryClass> for Value {
    fn from(val: EntryClass) -> Self {
        Value::new_iutf8(val.into())
    }
}

impl From<EntryClass> for PartialValue {
    fn from(val: EntryClass) -> Self {
        PartialValue::new_iutf8(val.into())
    }
}

impl From<EntryClass> for crate::prelude::AttrString {
    fn from(val: EntryClass) -> Self {
        crate::prelude::AttrString::from(val.to_string())
    }
}

impl Display for EntryClass {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> std::fmt::Result {
        let s: String = (*self).into();
        write!(f, "{}", s)
    }
}

impl EntryClass {
    pub fn to_value(self) -> Value {
        let s: &'static str = self.into();
        Value::new_iutf8(s)
    }

    pub fn to_partialvalue(self) -> PartialValue {
        let s: &'static str = self.into();
        PartialValue::new_iutf8(s)
    }

    /// Return a filter that'll match this class
    pub fn as_f_eq(&self) -> crate::filter::FC {
        crate::filter::f_eq(Attribute::Class, self.to_partialvalue())
    }
}

lazy_static! {
    /// Builtin System Admin account.
    pub static ref BUILTIN_ACCOUNT_IDM_ADMIN: BuiltinAccount = BuiltinAccount {
        account_type: AccountType::ServiceAccount,
        name: "idm_admin",
        uuid: UUID_IDM_ADMIN,
        description: "Builtin IDM Admin account.",
        displayname: "IDM Administrator",
    };

    pub static ref E_SYSTEM_INFO_V1: EntryInitNew = entry_init!(
        (Attribute::Class, EntryClass::Object.to_value()),
        (Attribute::Class, EntryClass::SystemInfo.to_value()),
        (Attribute::Class, EntryClass::System.to_value()),
        (Attribute::Uuid, Value::Uuid(UUID_SYSTEM_INFO)),
        (
Attribute::Description,
            Value::new_utf8s("System (local) info and metadata object.")
        ),
        (Attribute::Version, Value::Uint32(16))
    );

    pub static ref E_DOMAIN_INFO_V1: EntryInitNew = entry_init!(
        (Attribute::Class, EntryClass::Object.to_value()),
        (Attribute::Class, EntryClass::DomainInfo.to_value()),
        (Attribute::Class, EntryClass::System.to_value()),
        (Attribute::Name, Value::new_iname("domain_local")),
        (Attribute::Uuid, Value::Uuid(UUID_DOMAIN_INFO)),
        (
Attribute::Description,
            Value::new_utf8s("This local domain's info and metadata object.")
        )
    );
}

#[derive(Debug, Clone)]
/// Built in accounts such as anonymous, idm_admin and admin
pub struct BuiltinAccount {
    pub account_type: kanidm_proto::v1::AccountType,
    pub name: &'static str,
    pub uuid: Uuid,
    pub description: &'static str,
    pub displayname: &'static str,
}

impl Default for BuiltinAccount {
    fn default() -> Self {
        BuiltinAccount {
            account_type: AccountType::ServiceAccount,
            name: "",
            uuid: Uuid::new_v4(),
            description: "<set description>",
            displayname: "<set displayname>",
        }
    }
}

impl From<BuiltinAccount> for Account {
    fn from(value: BuiltinAccount) -> Self {
        Account {
            name: value.name.to_string(),
            uuid: value.uuid,
            displayname: value.displayname.to_string(),
            spn: format!("{}@example.com", value.name),
            mail_primary: None,
            mail: Vec::new(),
            ..Default::default()
        }
    }
}

impl From<BuiltinAccount> for EntryInitNew {
    fn from(value: BuiltinAccount) -> Self {
        let mut entry = EntryInitNew::new();
        entry.add_ava(Attribute::Name, Value::new_iname(value.name));
        entry.add_ava(Attribute::Uuid, Value::Uuid(value.uuid));
        entry.add_ava(Attribute::Description, Value::new_utf8s(value.description));
        entry.add_ava(Attribute::DisplayName, Value::new_utf8s(value.displayname));

        entry.set_ava(
            Attribute::Class,
            vec![
                EntryClass::Account.to_value(),
                EntryClass::MemberOf.to_value(),
                EntryClass::Object.to_value(),
            ],
        );
        match value.account_type {
            AccountType::Person => entry.add_ava(Attribute::Class, EntryClass::Person.to_value()),
            AccountType::ServiceAccount => {
                entry.add_ava(Attribute::Class, EntryClass::ServiceAccount.to_value())
            }
        }
        entry
    }
}

lazy_static! {

    /// Builtin System Admin account.
    pub static ref BUILTIN_ACCOUNT_ADMIN: BuiltinAccount = BuiltinAccount {
        account_type: AccountType::ServiceAccount,
        name: "admin",
        uuid: UUID_ADMIN,
        description: "Builtin System Admin account.",
        displayname: "System Administrator",
    };
    pub static ref BUILTIN_ACCOUNT_ANONYMOUS_V1: BuiltinAccount = BuiltinAccount {
        account_type: AccountType::ServiceAccount,
        name: "anonymous",
        uuid: UUID_ANONYMOUS,
        description: "Anonymous access account.",
        displayname: "Anonymous",
    };
}

pub fn builtin_accounts() -> Vec<&'static BuiltinAccount> {
    vec![
        &BUILTIN_ACCOUNT_ANONYMOUS_V1,
        &BUILTIN_ACCOUNT_ADMIN,
        &BUILTIN_ACCOUNT_IDM_ADMIN,
    ]
}

// ============ TEST DATA ============
#[cfg(test)]
pub const UUID_TESTPERSON_1: Uuid = uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930");

#[cfg(test)]
pub const UUID_TESTPERSON_2: Uuid = uuid!("538faac7-4d29-473b-a59d-23023ac19955");

#[cfg(test)]
lazy_static! {
    pub static ref E_TESTPERSON_1: EntryInitNew = entry_init!(
        (Attribute::Class, EntryClass::Object.to_value()),
        (Attribute::Name, Value::new_iname("testperson1")),
        (Attribute::Uuid, Value::Uuid(UUID_TESTPERSON_1))
    );
    pub static ref E_TESTPERSON_2: EntryInitNew = entry_init!(
        (Attribute::Class, EntryClass::Object.to_value()),
        (Attribute::Name, Value::new_iname("testperson2")),
        (Attribute::Uuid, Value::Uuid(UUID_TESTPERSON_2))
    );
}

/// Build a list of internal admin entries
pub fn idm_builtin_admin_entries() -> Result<Vec<EntryInitNew>, OperationError> {
    let mut res: Vec<EntryInitNew> = vec![
        BUILTIN_ACCOUNT_ANONYMOUS_V1.clone().into(),
        BUILTIN_ACCOUNT_ADMIN.clone().into(),
        BUILTIN_ACCOUNT_IDM_ADMIN.clone().into(),
    ];
    for group in idm_builtin_admin_groups() {
        let g: EntryInitNew = group.clone().try_into()?;
        res.push(g);
    }
    Ok(res)
}
