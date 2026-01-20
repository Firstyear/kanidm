use crate::constants::*;
use crate::internal::OperationError;
use serde::{Deserialize, Serialize};
use std::convert::Infallible;
use std::fmt;
use std::str::FromStr;
use utoipa::ToSchema;

pub use smartstring::alias::String as AttrString;

#[derive(
    Serialize, Deserialize, Clone, Debug, Eq, PartialEq, PartialOrd, Ord, Hash, Default, ToSchema,
)]
#[cfg_attr(test, derive(enum_iterator::Sequence))]
#[serde(rename_all = "lowercase", from = "String", into = "AttrString")]
pub enum Attribute {
    Account,
    AccountExpire,
    AccountValidFrom,
    AccountSoftlockExpire,
    AcpCreateAttr,
    AcpCreateClass,
    AcpEnable,
    AcpModifyClass,
    AcpModifyPresentClass,
    AcpModifyRemoveClass,
    AcpModifyPresentAttr,
    AcpModifyRemovedAttr,
    AcpReceiver,
    AcpReceiverGroup,
    AcpSearchAttr,
    AcpTargetScope,
    ApiTokenSession,
    ApplicationPassword,
    ApplicationUrl,
    AttestedPasskeys,
    #[default]
    Attr,
    AttributeName,
    AttributeType,
    AuthSessionExpiry,
    AuthPasswordMinimumLength,
    BadlistPassword,
    Certificate,
    CascadeDeleted,
    Claim,
    Class,
    ClassName,
    Cn,
    CookiePrivateKey,
    CreatedAtCid,
    CredentialUpdateIntentToken,
    CredentialTypeMinimum,
    DeniedName,
    DeleteAfter,
    Description,
    DirectMemberOf,
    DisplayName,
    Dn,
    Domain,
    DomainAllowEasterEggs,
    DomainDevelopmentTaint,
    DomainDisplayName,
    DomainLdapBasedn,
    DomainName,
    DomainSsid,
    DomainTokenKey,
    DomainUuid,
    DynGroup,
    DynGroupFilter,
    DynMember,
    Enabled,
    Email,
    EmailAlternative,
    EmailPrimary,
    EntryDn,
    EntryManagedBy,
    EntryUuid,
    Es256PrivateKeyDer,
    Excludes,
    FernetPrivateKeyStr,
    Gecos,
    GidNumber,
    GrantUiHint,
    Group,
    HmacNameHistory,
    HomeDirectory,
    IdVerificationEcKey,
    Image,
    Index,
    Indexed,
    InMemoriam,
    IpaNtHash,
    IpaSshPubKey,
    JwsEs256PrivateKey,
    KeyActionRotate,
    KeyActionRevoke,
    KeyActionImportJwsEs256,
    KeyActionImportJwsRs256,
    KeyInternalData,
    KeyProvider,
    LastModifiedCid,
    LdapAllowUnixPwBind,
    /// An LDAP Compatible emailAddress
    LdapEmailAddress,
    /// An LDAP Compatible sshkeys virtual attribute
    LdapKeys,
    LdapMaxQueryableAttrs,
    LegalName,
    LimitSearchMaxResults,
    LimitSearchMaxFilterTest,
    LinkedGroup,
    LoginShell,
    Mail,
    MailDestination,
    May,
    Member,
    MemberCreateOnce,
    MemberOf,
    MessageTemplate,
    MultiValue,
    Must,
    Name,
    NameHistory,
    NoIndex,
    NsUniqueId,
    NsAccountLock,
    OAuth2AllowInsecureClientDisablePkce,
    OAuth2AllowLocalhostRedirect,
    OAuth2AuthorisationEndpoint,
    OAuth2ClientId,
    OAuth2ClientSecret,
    OAuth2ConsentScopeMap,
    OAuth2DeviceFlowEnable,
    OAuth2JwtLegacyCryptoEnable,
    OAuth2PreferShortUsername,
    OAuth2RequestScopes,
    OAuth2RsBasicSecret,
    OAuth2RsClaimMap,
    OAuth2RsImplicitScopes,
    OAuth2RsName,
    OAuth2RsOrigin,
    OAuth2RsOriginLanding,
    OAuth2RsScopeMap,
    OAuth2RsSupScopeMap,
    OAuth2RsTokenKey,
    OAuth2Session,
    OAuth2StrictRedirectUri,
    OAuth2TokenEndpoint,
    OAuth2AccountCredentialUuid,
    OAuth2AccountProvider,
    OAuth2AccountUniqueUserId,
    OAuth2ConsentPromptEnable,
    ObjectClass,
    OtherNoIndex,
    PassKeys,
    PasswordImport,
    PasswordChangedTime,
    PatchLevel,
    Phantom,
    PrimaryCredential,
    PrivateCookieKey,
    PrivilegeExpiry,
    RadiusSecret,
    RecycledDirectMemberOf,
    Refers,
    Replicated,
    Rs256PrivateKeyDer,
    S256,
    /// A set of scim schemas. This is similar to a kanidm class.
    #[serde(rename = "schemas")]
    ScimSchemas,
    Scope,
    SendAfter,
    SentAt,
    SourceUuid,
    Spn,
    /// An LDAP-compatible sshpublickey
    LdapSshPublicKey,
    /// The Kanidm-local ssh_publickey
    SshPublicKey,
    SudoHost,
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
    UnixPasswordImport,
    UserAuthTokenSession,
    UserId,
    UserPassword,
    Uuid,
    Version,
    WebauthnAttestationCaList,
    AllowPrimaryCredFallback,

    #[cfg(any(debug_assertions, test, feature = "test"))]
    NonExist,
    #[cfg(any(debug_assertions, test, feature = "test"))]
    TestAttr,
    #[cfg(test)]
    TestAttrA,
    #[cfg(test)]
    TestAttrB,
    #[cfg(test)]
    TestAttrC,
    #[cfg(test)]
    TestAttrD,
    #[cfg(any(debug_assertions, test, feature = "test"))]
    TestNumber,
    #[cfg(any(debug_assertions, test, feature = "test"))]
    Extra,
    #[cfg(any(debug_assertions, test, feature = "test"))]
    TestNotAllowed,

    #[cfg(not(test))]
    #[schema(value_type = String)]
    Custom(AttrString),
}

impl AsRef<str> for Attribute {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl AsRef<Attribute> for Attribute {
    fn as_ref(&self) -> &Attribute {
        self
    }
}

impl TryFrom<&AttrString> for Attribute {
    type Error = OperationError;

    fn try_from(value: &AttrString) -> Result<Self, Self::Error> {
        Ok(Attribute::inner_from_str(value.as_str()))
    }
}

impl From<&str> for Attribute {
    fn from(value: &str) -> Self {
        Self::inner_from_str(value)
    }
}

impl From<String> for Attribute {
    fn from(value: String) -> Self {
        Self::inner_from_str(value.as_str())
    }
}

impl<'a> From<&'a Attribute> for &'a str {
    fn from(val: &'a Attribute) -> Self {
        val.as_str()
    }
}

impl From<Attribute> for AttrString {
    fn from(val: Attribute) -> Self {
        AttrString::from(val.as_str())
    }
}

impl FromStr for Attribute {
    type Err = Infallible;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Ok(Self::inner_from_str(value))
    }
}

impl Attribute {
    pub fn as_str(&self) -> &str {
        match self {
            Attribute::Account => ATTR_ACCOUNT,
            Attribute::AccountExpire => ATTR_ACCOUNT_EXPIRE,
            Attribute::AccountValidFrom => ATTR_ACCOUNT_VALID_FROM,
            Attribute::AccountSoftlockExpire => ATTR_ACCOUNT_SOFTLOCK_EXPIRE,
            Attribute::AcpCreateAttr => ATTR_ACP_CREATE_ATTR,
            Attribute::AcpCreateClass => ATTR_ACP_CREATE_CLASS,
            Attribute::AcpEnable => ATTR_ACP_ENABLE,
            Attribute::AcpModifyClass => ATTR_ACP_MODIFY_CLASS,
            Attribute::AcpModifyPresentClass => ATTR_ACP_MODIFY_PRESENT_CLASS,
            Attribute::AcpModifyRemoveClass => ATTR_ACP_MODIFY_REMOVE_CLASS,
            Attribute::AcpModifyPresentAttr => ATTR_ACP_MODIFY_PRESENTATTR,
            Attribute::AcpModifyRemovedAttr => ATTR_ACP_MODIFY_REMOVEDATTR,
            Attribute::AcpReceiver => ATTR_ACP_RECEIVER,
            Attribute::AcpReceiverGroup => ATTR_ACP_RECEIVER_GROUP,
            Attribute::AcpSearchAttr => ATTR_ACP_SEARCH_ATTR,
            Attribute::AcpTargetScope => ATTR_ACP_TARGET_SCOPE,
            Attribute::AllowPrimaryCredFallback => ATTR_ALLOW_PRIMARY_CRED_FALLBACK,
            Attribute::ApiTokenSession => ATTR_API_TOKEN_SESSION,
            Attribute::ApplicationPassword => ATTR_APPLICATION_PASSWORD,
            Attribute::ApplicationUrl => ATTR_APPLICATION_URL,
            Attribute::AttestedPasskeys => ATTR_ATTESTED_PASSKEYS,
            Attribute::Attr => ATTR_ATTR,
            Attribute::AttributeName => ATTR_ATTRIBUTENAME,
            Attribute::AttributeType => ATTR_ATTRIBUTETYPE,
            Attribute::AuthSessionExpiry => ATTR_AUTH_SESSION_EXPIRY,
            Attribute::AuthPasswordMinimumLength => ATTR_AUTH_PASSWORD_MINIMUM_LENGTH,
            Attribute::BadlistPassword => ATTR_BADLIST_PASSWORD,
            Attribute::Certificate => ATTR_CERTIFICATE,
            Attribute::CascadeDeleted => ATTR_CASCADE_DELETED,
            Attribute::Claim => ATTR_CLAIM,
            Attribute::Class => ATTR_CLASS,
            Attribute::ClassName => ATTR_CLASSNAME,
            Attribute::Cn => ATTR_CN,
            Attribute::CookiePrivateKey => ATTR_COOKIE_PRIVATE_KEY,
            Attribute::CreatedAtCid => ATTR_CREATED_AT_CID,
            Attribute::CredentialUpdateIntentToken => ATTR_CREDENTIAL_UPDATE_INTENT_TOKEN,
            Attribute::CredentialTypeMinimum => ATTR_CREDENTIAL_TYPE_MINIMUM,
            Attribute::DeniedName => ATTR_DENIED_NAME,
            Attribute::DeleteAfter => ATTR_DELETE_AFTER,
            Attribute::Description => ATTR_DESCRIPTION,
            Attribute::DirectMemberOf => ATTR_DIRECTMEMBEROF,
            Attribute::DisplayName => ATTR_DISPLAYNAME,
            Attribute::Dn => ATTR_DN,
            Attribute::Domain => ATTR_DOMAIN,
            Attribute::DomainAllowEasterEggs => ATTR_DOMAIN_ALLOW_EASTER_EGGS,
            Attribute::DomainDevelopmentTaint => ATTR_DOMAIN_DEVELOPMENT_TAINT,
            Attribute::DomainDisplayName => ATTR_DOMAIN_DISPLAY_NAME,
            Attribute::DomainLdapBasedn => ATTR_DOMAIN_LDAP_BASEDN,
            Attribute::DomainName => ATTR_DOMAIN_NAME,
            Attribute::DomainSsid => ATTR_DOMAIN_SSID,
            Attribute::DomainTokenKey => ATTR_DOMAIN_TOKEN_KEY,
            Attribute::DomainUuid => ATTR_DOMAIN_UUID,
            Attribute::DynGroup => ATTR_DYNGROUP,
            Attribute::DynGroupFilter => ATTR_DYNGROUP_FILTER,
            Attribute::DynMember => ATTR_DYNMEMBER,
            Attribute::Enabled => ATTR_ENABLED,
            Attribute::Email => ATTR_EMAIL,
            Attribute::EmailAlternative => ATTR_EMAIL_ALTERNATIVE,
            Attribute::EmailPrimary => ATTR_EMAIL_PRIMARY,
            Attribute::EntryDn => ATTR_ENTRYDN,
            Attribute::EntryManagedBy => ATTR_ENTRY_MANAGED_BY,
            Attribute::EntryUuid => ATTR_ENTRYUUID,
            Attribute::Es256PrivateKeyDer => ATTR_ES256_PRIVATE_KEY_DER,
            Attribute::Excludes => ATTR_EXCLUDES,
            Attribute::FernetPrivateKeyStr => ATTR_FERNET_PRIVATE_KEY_STR,
            Attribute::Gecos => ATTR_GECOS,
            Attribute::GidNumber => ATTR_GIDNUMBER,
            Attribute::GrantUiHint => ATTR_GRANT_UI_HINT,
            Attribute::Group => ATTR_GROUP,
            Attribute::HmacNameHistory => ATTR_HMAC_NAME_HISTORY,
            Attribute::HomeDirectory => ATTR_HOME_DIRECTORY,
            Attribute::IdVerificationEcKey => ATTR_ID_VERIFICATION_ECKEY,
            Attribute::Image => ATTR_IMAGE,
            Attribute::Index => ATTR_INDEX,
            Attribute::Indexed => ATTR_INDEXED,
            Attribute::InMemoriam => ATTR_IN_MEMORIAM,
            Attribute::IpaNtHash => ATTR_IPANTHASH,
            Attribute::IpaSshPubKey => ATTR_IPASSHPUBKEY,
            Attribute::JwsEs256PrivateKey => ATTR_JWS_ES256_PRIVATE_KEY,
            Attribute::KeyActionRotate => ATTR_KEY_ACTION_ROTATE,
            Attribute::KeyActionRevoke => ATTR_KEY_ACTION_REVOKE,
            Attribute::KeyActionImportJwsEs256 => ATTR_KEY_ACTION_IMPORT_JWS_ES256,
            Attribute::KeyActionImportJwsRs256 => ATTR_KEY_ACTION_IMPORT_JWS_RS256,
            Attribute::KeyInternalData => ATTR_KEY_INTERNAL_DATA,
            Attribute::KeyProvider => ATTR_KEY_PROVIDER,
            Attribute::LastModifiedCid => ATTR_LAST_MODIFIED_CID,
            Attribute::LdapAllowUnixPwBind => ATTR_LDAP_ALLOW_UNIX_PW_BIND,
            Attribute::LdapEmailAddress => ATTR_LDAP_EMAIL_ADDRESS,
            Attribute::LdapKeys => ATTR_LDAP_KEYS,
            Attribute::LdapMaxQueryableAttrs => ATTR_LDAP_MAX_QUERYABLE_ATTRS,
            Attribute::LdapSshPublicKey => ATTR_LDAP_SSHPUBLICKEY,
            Attribute::LegalName => ATTR_LEGALNAME,
            Attribute::LimitSearchMaxResults => ATTR_LIMIT_SEARCH_MAX_RESULTS,
            Attribute::LimitSearchMaxFilterTest => ATTR_LIMIT_SEARCH_MAX_FILTER_TEST,
            Attribute::LinkedGroup => ATTR_LINKEDGROUP,
            Attribute::LoginShell => ATTR_LOGINSHELL,
            Attribute::Mail => ATTR_MAIL,
            Attribute::MailDestination => ATTR_MAIL_DESTINATION,
            Attribute::May => ATTR_MAY,
            Attribute::Member => ATTR_MEMBER,
            Attribute::MemberCreateOnce => ATTR_MEMBER_CREATE_ONCE,
            Attribute::MemberOf => ATTR_MEMBEROF,
            Attribute::MessageTemplate => ATTR_MESSAGE_TEMPLATE,
            Attribute::MultiValue => ATTR_MULTIVALUE,
            Attribute::Must => ATTR_MUST,
            Attribute::Name => ATTR_NAME,
            Attribute::NameHistory => ATTR_NAME_HISTORY,
            Attribute::NoIndex => ATTR_NO_INDEX,
            Attribute::NsUniqueId => ATTR_NSUNIQUEID,
            Attribute::NsAccountLock => ATTR_NSACCOUNTLOCK,
            Attribute::OAuth2AllowInsecureClientDisablePkce => {
                ATTR_OAUTH2_ALLOW_INSECURE_CLIENT_DISABLE_PKCE
            }
            Attribute::OAuth2AllowLocalhostRedirect => ATTR_OAUTH2_ALLOW_LOCALHOST_REDIRECT,
            Attribute::OAuth2AuthorisationEndpoint => ATTR_OAUTH2_AUTHORISATION_ENDPOINT,
            Attribute::OAuth2ClientId => ATTR_OAUTH2_CLIENT_ID,
            Attribute::OAuth2ClientSecret => ATTR_OAUTH2_CLIENT_SECRET,
            Attribute::OAuth2ConsentScopeMap => ATTR_OAUTH2_CONSENT_SCOPE_MAP,
            Attribute::OAuth2DeviceFlowEnable => ATTR_OAUTH2_DEVICE_FLOW_ENABLE,
            Attribute::OAuth2JwtLegacyCryptoEnable => ATTR_OAUTH2_JWT_LEGACY_CRYPTO_ENABLE,
            Attribute::OAuth2PreferShortUsername => ATTR_OAUTH2_PREFER_SHORT_USERNAME,
            Attribute::OAuth2RequestScopes => ATTR_OAUTH2_REQUEST_SCOPES,
            Attribute::OAuth2RsBasicSecret => ATTR_OAUTH2_RS_BASIC_SECRET,
            Attribute::OAuth2RsClaimMap => ATTR_OAUTH2_RS_CLAIM_MAP,
            Attribute::OAuth2RsImplicitScopes => ATTR_OAUTH2_RS_IMPLICIT_SCOPES,
            Attribute::OAuth2RsName => ATTR_OAUTH2_RS_NAME,
            Attribute::OAuth2RsOrigin => ATTR_OAUTH2_RS_ORIGIN,
            Attribute::OAuth2RsOriginLanding => ATTR_OAUTH2_RS_ORIGIN_LANDING,
            Attribute::OAuth2RsScopeMap => ATTR_OAUTH2_RS_SCOPE_MAP,
            Attribute::OAuth2RsSupScopeMap => ATTR_OAUTH2_RS_SUP_SCOPE_MAP,
            Attribute::OAuth2RsTokenKey => ATTR_OAUTH2_RS_TOKEN_KEY,
            Attribute::OAuth2Session => ATTR_OAUTH2_SESSION,
            Attribute::OAuth2StrictRedirectUri => ATTR_OAUTH2_STRICT_REDIRECT_URI,
            Attribute::OAuth2TokenEndpoint => ATTR_OAUTH2_TOKEN_ENDPOINT,
            Attribute::OAuth2AccountCredentialUuid => ATTR_OAUTH2_ACCOUNT_CREDENTIAL_UUID,
            Attribute::OAuth2AccountProvider => ATTR_OAUTH2_ACCOUNT_PROVIDER,
            Attribute::OAuth2AccountUniqueUserId => ATTR_OAUTH2_ACCOUNT_UNIQUE_USER_ID,
            Attribute::OAuth2ConsentPromptEnable => ATTR_OAUTH2_CONSENT_PROMPT_ENABLE,
            Attribute::ObjectClass => ATTR_OBJECTCLASS,
            Attribute::OtherNoIndex => ATTR_OTHER_NO_INDEX,
            Attribute::PassKeys => ATTR_PASSKEYS,
            Attribute::PasswordChangedTime => ATTR_PWD_CHANGED_TIME,
            Attribute::PasswordImport => ATTR_PASSWORD_IMPORT,
            Attribute::PatchLevel => ATTR_PATCH_LEVEL,
            Attribute::Phantom => ATTR_PHANTOM,
            Attribute::PrimaryCredential => ATTR_PRIMARY_CREDENTIAL,
            Attribute::PrivateCookieKey => ATTR_PRIVATE_COOKIE_KEY,
            Attribute::PrivilegeExpiry => ATTR_PRIVILEGE_EXPIRY,
            Attribute::RadiusSecret => ATTR_RADIUS_SECRET,
            Attribute::RecycledDirectMemberOf => ATTR_RECYCLEDDIRECTMEMBEROF,
            Attribute::Refers => ATTR_REFERS,
            Attribute::Replicated => ATTR_REPLICATED,
            Attribute::Rs256PrivateKeyDer => ATTR_RS256_PRIVATE_KEY_DER,
            Attribute::S256 => ATTR_S256,
            Attribute::Scope => ATTR_SCOPE,
            Attribute::ScimSchemas => ATTR_SCIM_SCHEMAS,
            Attribute::SendAfter => ATTR_SEND_AFTER,
            Attribute::SentAt => ATTR_SENT_AT,
            Attribute::SourceUuid => ATTR_SOURCE_UUID,
            Attribute::Spn => ATTR_SPN,
            Attribute::SshPublicKey => ATTR_SSH_PUBLICKEY,
            Attribute::SudoHost => ATTR_SUDOHOST,
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
            Attribute::UnixPasswordImport => ATTR_UNIX_PASSWORD_IMPORT,
            Attribute::UserAuthTokenSession => ATTR_USER_AUTH_TOKEN_SESSION,
            Attribute::UserId => ATTR_USERID,
            Attribute::UserPassword => ATTR_USERPASSWORD,
            Attribute::Uuid => ATTR_UUID,
            Attribute::Version => ATTR_VERSION,
            Attribute::WebauthnAttestationCaList => ATTR_WEBAUTHN_ATTESTATION_CA_LIST,

            #[cfg(any(debug_assertions, test, feature = "test"))]
            Attribute::NonExist => TEST_ATTR_NON_EXIST,
            #[cfg(any(debug_assertions, test, feature = "test"))]
            Attribute::TestAttr => TEST_ATTR_TEST_ATTR,

            #[cfg(test)]
            Attribute::TestAttrA => TEST_ATTR_TEST_ATTR_A,
            #[cfg(test)]
            Attribute::TestAttrB => TEST_ATTR_TEST_ATTR_B,
            #[cfg(test)]
            Attribute::TestAttrC => TEST_ATTR_TEST_ATTR_C,
            #[cfg(test)]
            Attribute::TestAttrD => TEST_ATTR_TEST_ATTR_D,

            #[cfg(any(debug_assertions, test, feature = "test"))]
            Attribute::Extra => TEST_ATTR_EXTRA,
            #[cfg(any(debug_assertions, test, feature = "test"))]
            Attribute::TestNumber => TEST_ATTR_NUMBER,
            #[cfg(any(debug_assertions, test, feature = "test"))]
            Attribute::TestNotAllowed => TEST_ATTR_NOTALLOWED,

            #[cfg(not(test))]
            Attribute::Custom(value) => value.as_str(),
        }
    }

    // We allow this because the standard lib from_str is fallible, and we want an infallible version.
    #[allow(clippy::should_implement_trait)]
    fn inner_from_str(value: &str) -> Self {
        // Could this be something like heapless to save allocations? Also gives a way
        // to limit length of str?
        match value.to_lowercase().as_str() {
            ATTR_ACCOUNT => Attribute::Account,
            ATTR_ACCOUNT_EXPIRE => Attribute::AccountExpire,
            ATTR_ACCOUNT_VALID_FROM => Attribute::AccountValidFrom,
            ATTR_ACCOUNT_SOFTLOCK_EXPIRE => Attribute::AccountSoftlockExpire,
            ATTR_ACP_CREATE_ATTR => Attribute::AcpCreateAttr,
            ATTR_ACP_CREATE_CLASS => Attribute::AcpCreateClass,
            ATTR_ACP_ENABLE => Attribute::AcpEnable,
            ATTR_ACP_MODIFY_CLASS => Attribute::AcpModifyClass,
            ATTR_ACP_MODIFY_PRESENT_CLASS => Attribute::AcpModifyPresentClass,
            ATTR_ACP_MODIFY_REMOVE_CLASS => Attribute::AcpModifyRemoveClass,
            ATTR_ACP_MODIFY_PRESENTATTR => Attribute::AcpModifyPresentAttr,
            ATTR_ACP_MODIFY_REMOVEDATTR => Attribute::AcpModifyRemovedAttr,
            ATTR_ACP_RECEIVER => Attribute::AcpReceiver,
            ATTR_ACP_RECEIVER_GROUP => Attribute::AcpReceiverGroup,
            ATTR_ACP_SEARCH_ATTR => Attribute::AcpSearchAttr,
            ATTR_ACP_TARGET_SCOPE => Attribute::AcpTargetScope,
            ATTR_ALLOW_PRIMARY_CRED_FALLBACK => Attribute::AllowPrimaryCredFallback,
            ATTR_API_TOKEN_SESSION => Attribute::ApiTokenSession,
            ATTR_APPLICATION_PASSWORD => Attribute::ApplicationPassword,
            ATTR_APPLICATION_URL => Attribute::ApplicationUrl,
            ATTR_ATTESTED_PASSKEYS => Attribute::AttestedPasskeys,
            ATTR_ATTR => Attribute::Attr,
            ATTR_ATTRIBUTENAME => Attribute::AttributeName,
            ATTR_ATTRIBUTETYPE => Attribute::AttributeType,
            ATTR_AUTH_SESSION_EXPIRY => Attribute::AuthSessionExpiry,
            ATTR_AUTH_PASSWORD_MINIMUM_LENGTH => Attribute::AuthPasswordMinimumLength,
            ATTR_BADLIST_PASSWORD => Attribute::BadlistPassword,
            ATTR_CERTIFICATE => Attribute::Certificate,
            ATTR_CASCADE_DELETED => Attribute::CascadeDeleted,
            ATTR_CLAIM => Attribute::Claim,
            ATTR_CLASS => Attribute::Class,
            ATTR_CLASSNAME => Attribute::ClassName,
            ATTR_CN => Attribute::Cn,
            ATTR_COOKIE_PRIVATE_KEY => Attribute::CookiePrivateKey,
            ATTR_CREATED_AT_CID => Attribute::CreatedAtCid,
            ATTR_CREDENTIAL_UPDATE_INTENT_TOKEN => Attribute::CredentialUpdateIntentToken,
            ATTR_CREDENTIAL_TYPE_MINIMUM => Attribute::CredentialTypeMinimum,
            ATTR_DENIED_NAME => Attribute::DeniedName,
            ATTR_DELETE_AFTER => Attribute::DeleteAfter,
            ATTR_DESCRIPTION => Attribute::Description,
            ATTR_DIRECTMEMBEROF => Attribute::DirectMemberOf,
            ATTR_DISPLAYNAME => Attribute::DisplayName,
            ATTR_DN => Attribute::Dn,
            ATTR_DOMAIN => Attribute::Domain,
            ATTR_DOMAIN_ALLOW_EASTER_EGGS => Attribute::DomainAllowEasterEggs,
            ATTR_DOMAIN_DISPLAY_NAME => Attribute::DomainDisplayName,
            ATTR_DOMAIN_DEVELOPMENT_TAINT => Attribute::DomainDevelopmentTaint,
            ATTR_DOMAIN_LDAP_BASEDN => Attribute::DomainLdapBasedn,
            ATTR_DOMAIN_NAME => Attribute::DomainName,
            ATTR_DOMAIN_SSID => Attribute::DomainSsid,
            ATTR_DOMAIN_TOKEN_KEY => Attribute::DomainTokenKey,
            ATTR_DOMAIN_UUID => Attribute::DomainUuid,
            ATTR_DYNGROUP => Attribute::DynGroup,
            ATTR_DYNGROUP_FILTER => Attribute::DynGroupFilter,
            ATTR_DYNMEMBER => Attribute::DynMember,
            ATTR_ENABLED => Attribute::Enabled,
            ATTR_EMAIL => Attribute::Email,
            ATTR_EMAIL_ALTERNATIVE => Attribute::EmailAlternative,
            ATTR_EMAIL_PRIMARY => Attribute::EmailPrimary,
            ATTR_ENTRYDN => Attribute::EntryDn,
            ATTR_ENTRY_MANAGED_BY => Attribute::EntryManagedBy,
            ATTR_ENTRYUUID => Attribute::EntryUuid,
            ATTR_ES256_PRIVATE_KEY_DER => Attribute::Es256PrivateKeyDer,
            ATTR_EXCLUDES => Attribute::Excludes,
            ATTR_FERNET_PRIVATE_KEY_STR => Attribute::FernetPrivateKeyStr,
            ATTR_GECOS => Attribute::Gecos,
            ATTR_GIDNUMBER => Attribute::GidNumber,
            ATTR_GRANT_UI_HINT => Attribute::GrantUiHint,
            ATTR_GROUP => Attribute::Group,
            ATTR_HMAC_NAME_HISTORY => Attribute::HmacNameHistory,
            ATTR_HOME_DIRECTORY => Attribute::HomeDirectory,
            ATTR_ID_VERIFICATION_ECKEY => Attribute::IdVerificationEcKey,
            ATTR_IMAGE => Attribute::Image,
            ATTR_INDEX => Attribute::Index,
            ATTR_INDEXED => Attribute::Indexed,
            ATTR_IN_MEMORIAM => Attribute::InMemoriam,
            ATTR_IPANTHASH => Attribute::IpaNtHash,
            ATTR_IPASSHPUBKEY => Attribute::IpaSshPubKey,
            ATTR_JWS_ES256_PRIVATE_KEY => Attribute::JwsEs256PrivateKey,
            ATTR_KEY_ACTION_ROTATE => Attribute::KeyActionRotate,
            ATTR_KEY_ACTION_REVOKE => Attribute::KeyActionRevoke,
            ATTR_KEY_ACTION_IMPORT_JWS_ES256 => Attribute::KeyActionImportJwsEs256,
            ATTR_KEY_ACTION_IMPORT_JWS_RS256 => Attribute::KeyActionImportJwsRs256,
            ATTR_KEY_INTERNAL_DATA => Attribute::KeyInternalData,
            ATTR_KEY_PROVIDER => Attribute::KeyProvider,
            ATTR_LAST_MODIFIED_CID => Attribute::LastModifiedCid,
            ATTR_LDAP_ALLOW_UNIX_PW_BIND => Attribute::LdapAllowUnixPwBind,
            ATTR_LDAP_EMAIL_ADDRESS => Attribute::LdapEmailAddress,
            ATTR_LDAP_KEYS => Attribute::LdapKeys,
            ATTR_LDAP_MAX_QUERYABLE_ATTRS => Attribute::LdapMaxQueryableAttrs,
            ATTR_SSH_PUBLICKEY => Attribute::SshPublicKey,
            ATTR_LEGALNAME => Attribute::LegalName,
            ATTR_LINKEDGROUP => Attribute::LinkedGroup,
            ATTR_LOGINSHELL => Attribute::LoginShell,
            ATTR_LIMIT_SEARCH_MAX_RESULTS => Attribute::LimitSearchMaxResults,
            ATTR_LIMIT_SEARCH_MAX_FILTER_TEST => Attribute::LimitSearchMaxFilterTest,
            ATTR_MAIL => Attribute::Mail,
            ATTR_MAIL_DESTINATION => Attribute::MailDestination,
            ATTR_MAY => Attribute::May,
            ATTR_MEMBER => Attribute::Member,
            ATTR_MEMBER_CREATE_ONCE => Attribute::MemberCreateOnce,
            ATTR_MEMBEROF => Attribute::MemberOf,
            ATTR_MESSAGE_TEMPLATE => Attribute::MessageTemplate,
            ATTR_MULTIVALUE => Attribute::MultiValue,
            ATTR_MUST => Attribute::Must,
            ATTR_NAME => Attribute::Name,
            ATTR_NAME_HISTORY => Attribute::NameHistory,
            ATTR_NO_INDEX => Attribute::NoIndex,
            ATTR_NSUNIQUEID => Attribute::NsUniqueId,
            ATTR_NSACCOUNTLOCK => Attribute::NsAccountLock,
            ATTR_OAUTH2_ALLOW_INSECURE_CLIENT_DISABLE_PKCE => {
                Attribute::OAuth2AllowInsecureClientDisablePkce
            }
            ATTR_OAUTH2_ALLOW_LOCALHOST_REDIRECT => Attribute::OAuth2AllowLocalhostRedirect,
            ATTR_OAUTH2_AUTHORISATION_ENDPOINT => Attribute::OAuth2AuthorisationEndpoint,
            ATTR_OAUTH2_CLIENT_ID => Attribute::OAuth2ClientId,
            ATTR_OAUTH2_CLIENT_SECRET => Attribute::OAuth2ClientSecret,
            ATTR_OAUTH2_CONSENT_SCOPE_MAP => Attribute::OAuth2ConsentScopeMap,
            ATTR_OAUTH2_DEVICE_FLOW_ENABLE => Attribute::OAuth2DeviceFlowEnable,
            ATTR_OAUTH2_JWT_LEGACY_CRYPTO_ENABLE => Attribute::OAuth2JwtLegacyCryptoEnable,
            ATTR_OAUTH2_PREFER_SHORT_USERNAME => Attribute::OAuth2PreferShortUsername,
            ATTR_OAUTH2_REQUEST_SCOPES => Attribute::OAuth2RequestScopes,
            ATTR_OAUTH2_RS_BASIC_SECRET => Attribute::OAuth2RsBasicSecret,
            ATTR_OAUTH2_RS_CLAIM_MAP => Attribute::OAuth2RsClaimMap,
            ATTR_OAUTH2_RS_IMPLICIT_SCOPES => Attribute::OAuth2RsImplicitScopes,
            ATTR_OAUTH2_RS_NAME => Attribute::OAuth2RsName,
            ATTR_OAUTH2_RS_ORIGIN => Attribute::OAuth2RsOrigin,
            ATTR_OAUTH2_RS_ORIGIN_LANDING => Attribute::OAuth2RsOriginLanding,
            ATTR_OAUTH2_RS_SCOPE_MAP => Attribute::OAuth2RsScopeMap,
            ATTR_OAUTH2_RS_SUP_SCOPE_MAP => Attribute::OAuth2RsSupScopeMap,
            ATTR_OAUTH2_RS_TOKEN_KEY => Attribute::OAuth2RsTokenKey,
            ATTR_OAUTH2_SESSION => Attribute::OAuth2Session,
            ATTR_OAUTH2_STRICT_REDIRECT_URI => Attribute::OAuth2StrictRedirectUri,
            ATTR_OAUTH2_TOKEN_ENDPOINT => Attribute::OAuth2TokenEndpoint,
            ATTR_OAUTH2_ACCOUNT_CREDENTIAL_UUID => Attribute::OAuth2AccountCredentialUuid,
            ATTR_OAUTH2_ACCOUNT_PROVIDER => Attribute::OAuth2AccountProvider,
            ATTR_OAUTH2_ACCOUNT_UNIQUE_USER_ID => Attribute::OAuth2AccountUniqueUserId,
            ATTR_OAUTH2_CONSENT_PROMPT_ENABLE => Attribute::OAuth2ConsentPromptEnable,
            ATTR_OBJECTCLASS => Attribute::ObjectClass,
            ATTR_OTHER_NO_INDEX => Attribute::OtherNoIndex,
            ATTR_PASSKEYS => Attribute::PassKeys,
            ATTR_PASSWORD_IMPORT => Attribute::PasswordImport,
            ATTR_PATCH_LEVEL => Attribute::PatchLevel,
            ATTR_PHANTOM => Attribute::Phantom,
            ATTR_PRIMARY_CREDENTIAL => Attribute::PrimaryCredential,
            ATTR_PRIVATE_COOKIE_KEY => Attribute::PrivateCookieKey,
            ATTR_PRIVILEGE_EXPIRY => Attribute::PrivilegeExpiry,
            ATTR_PWD_CHANGED_TIME => Attribute::PasswordChangedTime,
            ATTR_RADIUS_SECRET => Attribute::RadiusSecret,
            ATTR_RECYCLEDDIRECTMEMBEROF => Attribute::RecycledDirectMemberOf,
            ATTR_REFERS => Attribute::Refers,
            ATTR_REPLICATED => Attribute::Replicated,
            ATTR_RS256_PRIVATE_KEY_DER => Attribute::Rs256PrivateKeyDer,
            ATTR_S256 => Attribute::S256,
            ATTR_SCIM_SCHEMAS => Attribute::ScimSchemas,
            ATTR_SEND_AFTER => Attribute::SendAfter,
            ATTR_SENT_AT => Attribute::SentAt,
            ATTR_SCOPE => Attribute::Scope,
            ATTR_SOURCE_UUID => Attribute::SourceUuid,
            ATTR_SPN => Attribute::Spn,
            ATTR_LDAP_SSHPUBLICKEY => Attribute::LdapSshPublicKey,
            ATTR_SUDOHOST => Attribute::SudoHost,
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
            ATTR_UNIX_PASSWORD_IMPORT => Attribute::UnixPasswordImport,
            ATTR_USER_AUTH_TOKEN_SESSION => Attribute::UserAuthTokenSession,
            ATTR_USERID => Attribute::UserId,
            ATTR_USERPASSWORD => Attribute::UserPassword,
            ATTR_UUID => Attribute::Uuid,
            ATTR_VERSION => Attribute::Version,
            ATTR_WEBAUTHN_ATTESTATION_CA_LIST => Attribute::WebauthnAttestationCaList,

            #[cfg(any(debug_assertions, test, feature = "test"))]
            TEST_ATTR_NON_EXIST => Attribute::NonExist,
            #[cfg(any(debug_assertions, test, feature = "test"))]
            TEST_ATTR_TEST_ATTR => Attribute::TestAttr,

            #[cfg(test)]
            TEST_ATTR_TEST_ATTR_A => Attribute::TestAttrA,
            #[cfg(test)]
            TEST_ATTR_TEST_ATTR_B => Attribute::TestAttrB,
            #[cfg(test)]
            TEST_ATTR_TEST_ATTR_C => Attribute::TestAttrC,
            #[cfg(test)]
            TEST_ATTR_TEST_ATTR_D => Attribute::TestAttrD,

            #[cfg(any(debug_assertions, test, feature = "test"))]
            TEST_ATTR_EXTRA => Attribute::Extra,
            #[cfg(any(debug_assertions, test, feature = "test"))]
            TEST_ATTR_NUMBER => Attribute::TestNumber,
            #[cfg(any(debug_assertions, test, feature = "test"))]
            TEST_ATTR_NOTALLOWED => Attribute::TestNotAllowed,

            #[cfg(not(test))]
            _ => Attribute::Custom(AttrString::from(value)),
            // Allowed only in tests
            #[allow(clippy::unreachable)]
            #[cfg(test)]
            _ => {
                unreachable!(
                    "Check that you've implemented the Attribute conversion for {:?}",
                    value
                );
            }
        }
    }
}

impl fmt::Display for Attribute {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl From<Attribute> for String {
    fn from(attr: Attribute) -> String {
        attr.to_string()
    }
}

/// Sub attributes are a component of SCIM, allowing tagged sub properties of a complex
/// attribute to be accessed.
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, PartialOrd, Ord, Hash, ToSchema)]
#[serde(rename_all = "lowercase", try_from = "&str", into = "AttrString")]
pub enum SubAttribute {
    /// Denotes a primary value.
    Primary,
    /// The type of value
    Type,
    /// The data associated to a value
    Value,

    #[cfg(not(test))]
    #[schema(value_type = String)]
    Custom(AttrString),
}

impl fmt::Display for SubAttribute {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl From<SubAttribute> for AttrString {
    fn from(val: SubAttribute) -> Self {
        AttrString::from(val.as_str())
    }
}

impl From<&str> for SubAttribute {
    fn from(value: &str) -> Self {
        Self::inner_from_str(value)
    }
}

impl FromStr for SubAttribute {
    type Err = Infallible;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Ok(Self::inner_from_str(value))
    }
}

impl SubAttribute {
    pub fn as_str(&self) -> &str {
        match self {
            SubAttribute::Primary => SUB_ATTR_PRIMARY,
            SubAttribute::Type => SUB_ATTR_TYPE,
            SubAttribute::Value => SUB_ATTR_VALUE,
            #[cfg(not(test))]
            SubAttribute::Custom(s) => s,
        }
    }

    // We allow this because the standard lib from_str is fallible, and we want an infallible version.
    #[allow(clippy::should_implement_trait)]
    fn inner_from_str(value: &str) -> Self {
        // Could this be something like heapless to save allocations? Also gives a way
        // to limit length of str?
        match value.to_lowercase().as_str() {
            SUB_ATTR_PRIMARY => SubAttribute::Primary,
            SUB_ATTR_TYPE => SubAttribute::Type,
            SUB_ATTR_VALUE => SubAttribute::Value,

            #[cfg(not(test))]
            _ => SubAttribute::Custom(AttrString::from(value)),

            // Allowed only in tests
            #[allow(clippy::unreachable)]
            #[cfg(test)]
            _ => {
                unreachable!(
                    "Check that you've implemented the SubAttribute conversion for {:?}",
                    value
                );
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::Attribute;

    #[test]
    fn test_valueattribute_from_str() {
        assert_eq!(Attribute::Uuid, Attribute::from("UUID"));
        assert_eq!(Attribute::Uuid, Attribute::from("UuiD"));
        assert_eq!(Attribute::Uuid, Attribute::from("uuid"));
    }

    #[test]
    fn test_valueattribute_as_str() {
        assert_eq!(Attribute::Class.as_str(), "class");
        assert_eq!(Attribute::Class.to_string(), "class".to_string());
    }

    #[test]
    // this ensures we cover both ends of the conversion to/from string-types
    fn test_valueattribute_round_trip() {
        use enum_iterator::all;
        let the_list = all::<Attribute>().collect::<Vec<_>>();
        for attr in the_list {
            let attr2 = Attribute::from(attr.as_str());
            assert!(
                attr == attr2,
                "Round-trip failed for {attr} <=> {attr2} check you've implemented a from and to string"
            );
        }
    }
}
