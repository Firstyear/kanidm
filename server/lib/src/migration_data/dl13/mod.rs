mod access;
pub(super) mod accounts;
mod groups;
mod key_providers;
mod schema;
mod system_config;

use self::access::*;
use self::accounts::*;
use self::groups::*;
use self::key_providers::*;
use self::schema::*;
use self::system_config::*;
use crate::constants::UUID_SCHEMA_ATTR_EC_KEY_PRIVATE;
use crate::prelude::EntryInitNew;
use kanidm_proto::internal::OperationError;
use uuid::Uuid;

pub fn phase_1_schema_attrs() -> Vec<EntryInitNew> {
    vec![
        SCHEMA_ATTR_SYNC_CREDENTIAL_PORTAL.clone().into(),
        SCHEMA_ATTR_SYNC_YIELD_AUTHORITY.clone().into(),
        SCHEMA_ATTR_ACCOUNT_EXPIRE.clone().into(),
        SCHEMA_ATTR_ACCOUNT_VALID_FROM.clone().into(),
        SCHEMA_ATTR_API_TOKEN_SESSION.clone().into(),
        SCHEMA_ATTR_AUTH_SESSION_EXPIRY.clone().into(),
        SCHEMA_ATTR_AUTH_PRIVILEGE_EXPIRY.clone().into(),
        SCHEMA_ATTR_AUTH_PASSWORD_MINIMUM_LENGTH.clone().into(),
        SCHEMA_ATTR_BADLIST_PASSWORD.clone().into(),
        SCHEMA_ATTR_CREDENTIAL_UPDATE_INTENT_TOKEN.clone().into(),
        SCHEMA_ATTR_ATTESTED_PASSKEYS.clone().into(),
        SCHEMA_ATTR_DOMAIN_DISPLAY_NAME.clone().into(),
        SCHEMA_ATTR_DOMAIN_LDAP_BASEDN.clone().into(),
        SCHEMA_ATTR_DOMAIN_NAME.clone().into(),
        SCHEMA_ATTR_LDAP_ALLOW_UNIX_PW_BIND.clone().into(),
        SCHEMA_ATTR_DOMAIN_SSID.clone().into(),
        SCHEMA_ATTR_DOMAIN_TOKEN_KEY.clone().into(),
        SCHEMA_ATTR_DOMAIN_UUID.clone().into(),
        SCHEMA_ATTR_DYNGROUP_FILTER.clone().into(),
        SCHEMA_ATTR_ES256_PRIVATE_KEY_DER.clone().into(),
        SCHEMA_ATTR_FERNET_PRIVATE_KEY_STR.clone().into(),
        SCHEMA_ATTR_GIDNUMBER.clone().into(),
        SCHEMA_ATTR_GRANT_UI_HINT.clone().into(),
        SCHEMA_ATTR_JWS_ES256_PRIVATE_KEY.clone().into(),
        SCHEMA_ATTR_LOGINSHELL.clone().into(),
        SCHEMA_ATTR_NAME_HISTORY.clone().into(),
        SCHEMA_ATTR_NSUNIQUEID.clone().into(),
        SCHEMA_ATTR_OAUTH2_ALLOW_INSECURE_CLIENT_DISABLE_PKCE
            .clone()
            .into(),
        SCHEMA_ATTR_OAUTH2_CONSENT_SCOPE_MAP.clone().into(),
        SCHEMA_ATTR_OAUTH2_JWT_LEGACY_CRYPTO_ENABLE.clone().into(),
        SCHEMA_ATTR_OAUTH2_PREFER_SHORT_USERNAME.clone().into(),
        SCHEMA_ATTR_OAUTH2_RS_BASIC_SECRET.clone().into(),
        SCHEMA_ATTR_OAUTH2_RS_IMPLICIT_SCOPES.clone().into(),
        SCHEMA_ATTR_OAUTH2_RS_NAME.clone().into(),
        SCHEMA_ATTR_OAUTH2_RS_ORIGIN_LANDING.clone().into(),
        SCHEMA_ATTR_OAUTH2_RS_SCOPE_MAP.clone().into(),
        SCHEMA_ATTR_OAUTH2_RS_SUP_SCOPE_MAP.clone().into(),
        SCHEMA_ATTR_OAUTH2_RS_TOKEN_KEY.clone().into(),
        SCHEMA_ATTR_OAUTH2_SESSION.clone().into(),
        SCHEMA_ATTR_PASSKEYS.clone().into(),
        SCHEMA_ATTR_PRIMARY_CREDENTIAL.clone().into(),
        SCHEMA_ATTR_PRIVATE_COOKIE_KEY.clone().into(),
        SCHEMA_ATTR_RADIUS_SECRET.clone().into(),
        SCHEMA_ATTR_RS256_PRIVATE_KEY_DER.clone().into(),
        SCHEMA_ATTR_SSH_PUBLICKEY.clone().into(),
        SCHEMA_ATTR_SYNC_COOKIE.clone().into(),
        SCHEMA_ATTR_SYNC_TOKEN_SESSION.clone().into(),
        SCHEMA_ATTR_UNIX_PASSWORD.clone().into(),
        SCHEMA_ATTR_USER_AUTH_TOKEN_SESSION.clone().into(),
        SCHEMA_ATTR_CREDENTIAL_TYPE_MINIMUM.clone().into(),
        SCHEMA_ATTR_WEBAUTHN_ATTESTATION_CA_LIST.clone().into(),
        // DL4
        SCHEMA_ATTR_OAUTH2_RS_CLAIM_MAP_DL4.clone().into(),
        SCHEMA_ATTR_OAUTH2_ALLOW_LOCALHOST_REDIRECT_DL4
            .clone()
            .into(),
        // DL5
        // DL6
        SCHEMA_ATTR_LIMIT_SEARCH_MAX_RESULTS_DL6.clone().into(),
        SCHEMA_ATTR_LIMIT_SEARCH_MAX_FILTER_TEST_DL6.clone().into(),
        SCHEMA_ATTR_KEY_INTERNAL_DATA_DL6.clone().into(),
        SCHEMA_ATTR_KEY_PROVIDER_DL6.clone().into(),
        SCHEMA_ATTR_KEY_ACTION_ROTATE_DL6.clone().into(),
        SCHEMA_ATTR_KEY_ACTION_REVOKE_DL6.clone().into(),
        SCHEMA_ATTR_KEY_ACTION_IMPORT_JWS_ES256_DL6.clone().into(),
        // DL7
        SCHEMA_ATTR_PATCH_LEVEL_DL7.clone().into(),
        SCHEMA_ATTR_DOMAIN_DEVELOPMENT_TAINT_DL7.clone().into(),
        SCHEMA_ATTR_CERTIFICATE_DL7.clone().into(),
        SCHEMA_ATTR_OAUTH2_RS_ORIGIN_DL7.clone().into(),
        SCHEMA_ATTR_OAUTH2_STRICT_REDIRECT_URI_DL7.clone().into(),
        SCHEMA_ATTR_MAIL_DL7.clone().into(),
        SCHEMA_ATTR_LEGALNAME_DL7.clone().into(),
        SCHEMA_ATTR_DISPLAYNAME_DL7.clone().into(),
        // DL8
        SCHEMA_ATTR_LINKED_GROUP_DL8.clone().into(),
        SCHEMA_ATTR_APPLICATION_PASSWORD_DL8.clone().into(),
        SCHEMA_ATTR_ALLOW_PRIMARY_CRED_FALLBACK_DL8.clone().into(),
        // DL9
        SCHEMA_ATTR_DOMAIN_ALLOW_EASTER_EGGS_DL9.clone().into(),
        // DL10
        SCHEMA_ATTR_DENIED_NAME_DL10.clone().into(),
        SCHEMA_ATTR_LDAP_MAXIMUM_QUERYABLE_ATTRIBUTES.clone().into(),
        SCHEMA_ATTR_KEY_ACTION_IMPORT_JWS_RS256_DL6.clone().into(),
        // DL11
        SCHEMA_ATTR_APPLICATION_URL.clone().into(),
        // DL12
        SCHEMA_ATTR_IMAGE.clone().into(),
        SCHEMA_ATTR_OAUTH2_DEVICE_FLOW_ENABLE.clone().into(),
        SCHEMA_ATTR_MESSAGE_TEMPLATE.clone().into(),
        SCHEMA_ATTR_SEND_AFTER.clone().into(),
        SCHEMA_ATTR_DELETE_AFTER.clone().into(),
        SCHEMA_ATTR_SENT_AT.clone().into(),
        SCHEMA_ATTR_MAIL_DESTINATION.clone().into(),
        SCHEMA_ATTR_OAUTH2_ACCOUNT_PROVIDER.clone().into(),
        SCHEMA_ATTR_OAUTH2_ACCOUNT_UNIQUE_USER_ID.clone().into(),
        SCHEMA_ATTR_OAUTH2_ACCOUNT_CREDENTIAL_UUID.clone().into(),
        SCHEMA_ATTR_OAUTH2_CLIENT_ID.clone().into(),
        SCHEMA_ATTR_OAUTH2_CLIENT_SECRET.clone().into(),
        SCHEMA_ATTR_OAUTH2_AUTHORISATION_ENDPOINT.clone().into(),
        SCHEMA_ATTR_OAUTH2_TOKEN_ENDPOINT.clone().into(),
        SCHEMA_ATTR_OAUTH2_REQUEST_SCOPES.clone().into(),
        SCHEMA_ATTR_HMAC_NAME_HISTORY.clone().into(),
        SCHEMA_ATTR_ENABLED.clone().into(),
        SCHEMA_ATTR_IN_MEMORIAM.clone().into(),
        // DL13
        SCHEMA_ATTR_OAUTH2_CONSENT_PROMPT_ENABLE.clone().into(),
        SCHEMA_ATTR_S256.clone().into(),
        SCHEMA_ATTR_ACCOUNT_SOFTLOCK_EXPIRE.clone().into(),
    ]
}

pub fn phase_2_schema_classes() -> Vec<EntryInitNew> {
    vec![
        SCHEMA_CLASS_DYNGROUP.clone().into(),
        SCHEMA_CLASS_ORGPERSON.clone().into(),
        SCHEMA_CLASS_POSIXACCOUNT.clone().into(),
        SCHEMA_CLASS_POSIXGROUP.clone().into(),
        SCHEMA_CLASS_SYSTEM_CONFIG.clone().into(),
        // DL4
        SCHEMA_CLASS_OAUTH2_RS_PUBLIC_DL4.clone().into(),
        // DL5
        SCHEMA_CLASS_ACCOUNT_DL5.clone().into(),
        SCHEMA_CLASS_OAUTH2_RS_BASIC_DL5.clone().into(),
        // DL6
        SCHEMA_CLASS_GROUP_DL6.clone().into(),
        SCHEMA_CLASS_KEY_PROVIDER_DL6.clone().into(),
        SCHEMA_CLASS_KEY_PROVIDER_INTERNAL_DL6.clone().into(),
        SCHEMA_CLASS_KEY_OBJECT_DL6.clone().into(),
        SCHEMA_CLASS_KEY_OBJECT_JWT_ES256_DL6.clone().into(),
        SCHEMA_CLASS_KEY_OBJECT_JWE_A128GCM_DL6.clone().into(),
        SCHEMA_CLASS_KEY_OBJECT_INTERNAL_DL6.clone().into(),
        // DL7
        SCHEMA_CLASS_SERVICE_ACCOUNT_DL7.clone().into(),
        SCHEMA_CLASS_SYNC_ACCOUNT_DL7.clone().into(),
        SCHEMA_CLASS_CLIENT_CERTIFICATE_DL7.clone().into(),
        // DL8
        SCHEMA_CLASS_ACCOUNT_POLICY_DL8.clone().into(),
        SCHEMA_CLASS_PERSON_DL8.clone().into(),
        // DL9
        SCHEMA_CLASS_OAUTH2_RS_DL9.clone().into(),
        // DL10
        SCHEMA_CLASS_DOMAIN_INFO_DL10.clone().into(),
        SCHEMA_CLASS_KEY_OBJECT_JWT_RS256.clone().into(),
        // DL11
        SCHEMA_CLASS_APPLICATION.clone().into(),
        // DL12
        SCHEMA_CLASS_KEY_OBJECT_HKDF_S256.clone().into(),
        SCHEMA_CLASS_OUTBOUND_MESSAGE.clone().into(),
        SCHEMA_CLASS_OAUTH2_ACCOUNT.clone().into(),
        SCHEMA_CLASS_OAUTH2_CLIENT.clone().into(),
        SCHEMA_CLASS_FEATURE.clone().into(),
        SCHEMA_CLASS_MEMORIAL.clone().into(),
        // DL 13
        SCHEMA_CLASS_KEY_OBJECT_JWT_HS256_DL6.clone().into(),
        SCHEMA_CLASS_ASSERTION_NONCE.clone().into(),
        SCHEMA_CLASS_KEY_OBJECT_JWT_HS256_DL6.clone().into(),
        SCHEMA_CLASS_ASSERTION_NONCE.clone().into(),
    ]
}

pub fn phase_3_key_provider() -> Vec<EntryInitNew> {
    vec![E_KEY_PROVIDER_INTERNAL_DL6.clone()]
}

pub fn phase_4_system_entries() -> Vec<EntryInitNew> {
    vec![
        E_SYSTEM_INFO_V1.clone(),
        E_DOMAIN_INFO_DL6.clone(),
        e_system_config_v1(),
        E_UUID_DOMAIN_ID_VERIFICATION_KEY_V1.clone(),
        E_HMAC_NAME_HISTORY_FEATURE.clone(),
    ]
}

pub fn phase_5_builtin_admin_entries() -> Result<Vec<EntryInitNew>, OperationError> {
    Ok(vec![
        BUILTIN_ACCOUNT_ADMIN.clone().into(),
        BUILTIN_ACCOUNT_IDM_ADMIN.clone().into(),
        BUILTIN_GROUP_SYSTEM_ADMINS_V1.clone().try_into()?,
        BUILTIN_GROUP_IDM_ADMINS_V1.clone().try_into()?,
        // We need to push anonymous *after* groups due to entry-managed-by
        BUILTIN_ACCOUNT_ANONYMOUS_DL6.clone().into(),
    ])
}

pub fn phase_6_builtin_non_admin_entries() -> Result<Vec<EntryInitNew>, OperationError> {
    Ok(vec![
        IDM_ALL_PERSONS.clone().try_into()?,
        IDM_ALL_ACCOUNTS.clone().try_into()?,
        BUILTIN_GROUP_DOMAIN_ADMINS.clone().try_into()?,
        BUILTIN_GROUP_SCHEMA_ADMINS.clone().try_into()?,
        BUILTIN_GROUP_ACCESS_CONTROL_ADMINS.clone().try_into()?,
        BUILTIN_GROUP_UNIX_ADMINS.clone().try_into()?,
        BUILTIN_GROUP_IDM_UNIX_AUTHENTICATION_READ_V1
            .clone()
            .try_into()?,
        BUILTIN_GROUP_RECYCLE_BIN_ADMINS.clone().try_into()?,
        BUILTIN_GROUP_SERVICE_DESK.clone().try_into()?,
        BUILTIN_GROUP_OAUTH2_ADMINS.clone().try_into()?,
        BUILTIN_GROUP_RADIUS_SERVICE_ADMINS.clone().try_into()?,
        BUILTIN_GROUP_ACCOUNT_POLICY_ADMINS.clone().try_into()?,
        BUILTIN_GROUP_PEOPLE_ADMINS.clone().try_into()?,
        BUILTIN_GROUP_PEOPLE_PII_READ.clone().try_into()?,
        BUILTIN_GROUP_PEOPLE_ON_BOARDING.clone().try_into()?,
        BUILTIN_GROUP_SERVICE_ACCOUNT_ADMINS.clone().try_into()?,
        BUILTIN_GROUP_MAIL_SERVICE_ADMINS_DL8.clone().try_into()?,
        IDM_GROUP_ADMINS_V1.clone().try_into()?,
        BUILTIN_IDM_RADIUS_SERVERS_V1.clone().try_into()?,
        BUILTIN_IDM_MAIL_SERVERS_DL8.clone().try_into()?,
        BUILTIN_GROUP_PEOPLE_SELF_NAME_WRITE_DL7
            .clone()
            .try_into()?,
        IDM_PEOPLE_SELF_MAIL_WRITE_DL7.clone().try_into()?,
        BUILTIN_GROUP_CLIENT_CERTIFICATE_ADMINS_DL7
            .clone()
            .try_into()?,
        BUILTIN_GROUP_APPLICATION_ADMINS_DL8.clone().try_into()?,
        BUILTIN_GROUP_MESSAGE_ADMINS.clone().try_into()?,
        BUILTIN_GROUP_MESSAGE_SENDERS.clone().try_into()?,
        BUILTIN_GROUP_OAUTH2_CLIENT_ADMINS.clone().try_into()?,
        BUILTIN_GROUP_OAUTH2_ACCOUNT_ADMINS.clone().try_into()?,
        // Write deps on read.clone().try_into()?, so write must be added first.
        // All members must exist before we write HP
        IDM_HIGH_PRIVILEGE_DL8.clone().try_into()?,
        // other things
        IDM_UI_ENABLE_EXPERIMENTAL_FEATURES.clone().try_into()?,
        IDM_ACCOUNT_MAIL_READ.clone().try_into()?,
    ])
}

pub fn phase_7_builtin_access_control_profiles() -> Vec<EntryInitNew> {
    vec![
        // Built in access controls.
        IDM_ACP_RECYCLE_BIN_SEARCH_V1.clone().into(),
        IDM_ACP_RECYCLE_BIN_REVIVE_V1.clone().into(),
        IDM_ACP_SCHEMA_WRITE_ATTRS_V1.clone().into(),
        IDM_ACP_SCHEMA_WRITE_CLASSES_V1.clone().into(),
        IDM_ACP_ACP_MANAGE_V1.clone().into(),
        IDM_ACP_GROUP_ENTRY_MANAGED_BY_MODIFY_V1.clone().into(),
        IDM_ACP_GROUP_ENTRY_MANAGER_V1.clone().into(),
        IDM_ACP_SYNC_ACCOUNT_MANAGE_V1.clone().into(),
        IDM_ACP_RADIUS_SERVERS_V1.clone().into(),
        IDM_ACP_RADIUS_SECRET_MANAGE_V1.clone().into(),
        IDM_ACP_PEOPLE_SELF_WRITE_MAIL_V1.clone().into(),
        IDM_ACP_ACCOUNT_SELF_WRITE_V1.clone().into(),
        IDM_ACP_ALL_ACCOUNTS_POSIX_READ_V1.clone().into(),
        IDM_ACP_SYSTEM_CONFIG_ACCOUNT_POLICY_MANAGE_V1
            .clone()
            .into(),
        IDM_ACP_GROUP_UNIX_MANAGE_V1.clone().into(),
        IDM_ACP_HP_GROUP_UNIX_MANAGE_V1.clone().into(),
        IDM_ACP_GROUP_READ_V1.clone().into(),
        IDM_ACP_ACCOUNT_UNIX_EXTEND_V1.clone().into(),
        IDM_ACP_PEOPLE_PII_READ_V1.clone().into(),
        IDM_ACP_PEOPLE_PII_MANAGE_V1.clone().into(),
        IDM_ACP_PEOPLE_READ_V1.clone().into(),
        IDM_ACP_PEOPLE_MANAGE_V1.clone().into(),
        IDM_ACP_PEOPLE_DELETE_V1.clone().into(),
        IDM_ACP_PEOPLE_CREDENTIAL_RESET_V1.clone().into(),
        IDM_ACP_HP_PEOPLE_CREDENTIAL_RESET_V1.clone().into(),
        IDM_ACP_SERVICE_ACCOUNT_CREATE_V1.clone().into(),
        IDM_ACP_SERVICE_ACCOUNT_DELETE_V1.clone().into(),
        IDM_ACP_SERVICE_ACCOUNT_ENTRY_MANAGER_V1.clone().into(),
        IDM_ACP_SERVICE_ACCOUNT_ENTRY_MANAGED_BY_MODIFY_V1
            .clone()
            .into(),
        IDM_ACP_HP_SERVICE_ACCOUNT_ENTRY_MANAGED_BY_MODIFY_V1
            .clone()
            .into(),
        IDM_ACP_SERVICE_ACCOUNT_MANAGE_V1.clone().into(),
        // DL4
        // DL5
        // DL6
        IDM_ACP_PEOPLE_CREATE_DL6.clone().into(),
        IDM_ACP_ACCOUNT_MAIL_READ_DL6.clone().into(),
        // DL7
        IDM_ACP_SELF_NAME_WRITE_DL7.clone().into(),
        IDM_ACP_HP_CLIENT_CERTIFICATE_MANAGER_DL7.clone().into(),
        // DL8
        IDM_ACP_SELF_READ_DL8.clone().into(),
        IDM_ACP_SELF_WRITE_DL8.clone().into(),
        IDM_ACP_APPLICATION_MANAGE_DL8.clone().into(),
        IDM_ACP_APPLICATION_ENTRY_MANAGER_DL8.clone().into(),
        IDM_ACP_MAIL_SERVERS_DL8.clone().into(),
        IDM_ACP_GROUP_ACCOUNT_POLICY_MANAGE_DL8.clone().into(),
        // DL9
        IDM_ACP_GROUP_MANAGE_DL9.clone().into(),
        IDM_ACP_DOMAIN_ADMIN_DL9.clone().into(),
        // DL10
        IDM_ACP_OAUTH2_MANAGE.clone().into(),
        // DL12
        IDM_ACP_MESSAGE_MANAGE.clone().into(),
        IDM_ACP_MESSAGE_SENDER.clone().into(),
        IDM_ACP_OAUTH2_CLIENT_ADMIN.clone().into(),
        IDM_ACP_OAUTH2_ACCOUNT_ENROL.clone().into(),
        // DL13
        IDM_ACP_OAUTH2_MANAGE_BASIC.clone().into(),
    ]
}

pub fn phase_8_delete_uuids() -> Vec<Uuid> {
    vec![UUID_SCHEMA_ATTR_EC_KEY_PRIVATE]
}
