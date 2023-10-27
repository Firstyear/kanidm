//! Because consistency is great!

pub const CONTENT_TYPE_JPG: &str = "image/jpeg";
pub const CONTENT_TYPE_PNG: &str = "image/png";
pub const CONTENT_TYPE_GIF: &str = "image/gif";
pub const CONTENT_TYPE_SVG: &str = "image/svg+xml";
pub const CONTENT_TYPE_WEBP: &str = "image/webp";

// for when the user uploads things to the various image endpoints
pub const VALID_IMAGE_UPLOAD_CONTENT_TYPES: [&str; 5] = [
    CONTENT_TYPE_JPG,
    CONTENT_TYPE_PNG,
    CONTENT_TYPE_GIF,
    CONTENT_TYPE_SVG,
    CONTENT_TYPE_WEBP,
];

pub const APPLICATION_JSON: &str = "application/json";

/// The "system" path for Kanidm client config
pub const DEFAULT_CLIENT_CONFIG_PATH: &str = "/etc/kanidm/config";
/// The user-owned path for Kanidm client config
pub const DEFAULT_CLIENT_CONFIG_PATH_HOME: &str = "~/.config/kanidm";

/// The default bind address for the Kanidm server
pub const DEFAULT_SERVER_ADDRESS: &str = "127.0.0.1:8443";
pub const DEFAULT_SERVER_LOCALHOST: &str = "localhost:8443";
pub const DEFAULT_LDAP_ADDRESS: &str = "127.0.0.1:636";
pub const DEFAULT_LDAP_LOCALHOST: &str = "localhost:636";

/// IF YOU CHANGE THESE VALUES YOU BREAK EVERYTHING
pub const ATTR_ACCOUNT_EXPIRE: &str = "account_expire";
pub const ATTR_ACCOUNT_VALID_FROM: &str = "account_valid_from";
pub const ATTR_ACCOUNT: &str = "account";
pub const ATTR_ACP_CREATE_ATTR: &str = "acp_create_attr";
pub const ATTR_ACP_CREATE_CLASS: &str = "acp_create_class";
pub const ATTR_ACP_ENABLE: &str = "acp_enable";
pub const ATTR_ACP_MODIFY_CLASS: &str = "acp_modify_class";
pub const ATTR_ACP_MODIFY_PRESENTATTR: &str = "acp_modify_presentattr";
pub const ATTR_ACP_MODIFY_REMOVEDATTR: &str = "acp_modify_removedattr";
pub const ATTR_ACP_RECEIVER_GROUP: &str = "acp_receiver_group";
pub const ATTR_ACP_RECEIVER: &str = "acp_receiver";
pub const ATTR_ACP_SEARCH_ATTR: &str = "acp_search_attr";
pub const ATTR_ACP_TARGET_SCOPE: &str = "acp_targetscope";
pub const ATTR_API_TOKEN_SESSION: &str = "api_token_session";
pub const ATTR_ATTR: &str = "attr";
pub const ATTR_ATTRIBUTENAME: &str = "attributename";
pub const ATTR_ATTRIBUTETYPE: &str = "attributetype";
pub const ATTR_AUTH_SESSION_EXPIRY: &str = "authsession_expiry";
pub const ATTR_BADLIST_PASSWORD: &str = "badlist_password";
pub const ATTR_CLAIM: &str = "claim";
pub const ATTR_CLASS: &str = "class";
pub const ATTR_CLASSNAME: &str = "classname";
pub const ATTR_CN: &str = "cn";
pub const ATTR_COOKIE_PRIVATE_KEY: &str = "cookie_private_key";
pub const ATTR_CREDENTIAL_UPDATE_INTENT_TOKEN: &str = "credential_update_intent_token";
pub const ATTR_DENIED_NAME: &str = "denied_name";
pub const ATTR_DESCRIPTION: &str = "description";
pub const ATTR_DEVICEKEYS: &str = "devicekeys";
pub const ATTR_DIRECTMEMBEROF: &str = "directmemberof";
pub const ATTR_DISPLAYNAME: &str = "displayname";
pub const ATTR_DN: &str = "dn";
pub const ATTR_DOMAIN_DISPLAY_NAME: &str = "domain_display_name";
pub const ATTR_DOMAIN_LDAP_BASEDN: &str = "domain_ldap_basedn";
pub const ATTR_DOMAIN_NAME: &str = "domain_name";
pub const ATTR_DOMAIN_LDAP_ALLOW_UNIX_PW_BIND: &str = "domain_ldap_allow_unix_pw_bind";
pub const ATTR_DOMAIN_SSID: &str = "domain_ssid";
pub const ATTR_DOMAIN_TOKEN_KEY: &str = "domain_token_key";
pub const ATTR_DOMAIN_UUID: &str = "domain_uuid";
pub const ATTR_DOMAIN: &str = "domain";
pub const ATTR_DYNGROUP_FILTER: &str = "dyngroup_filter";
pub const ATTR_DYNGROUP: &str = "dyngroup";
pub const ATTR_DYNMEMBER: &str = "dynmember";
pub const ATTR_LDAP_EMAIL_ADDRESS: &str = "emailaddress";
pub const ATTR_EMAIL_ALTERNATIVE: &str = "emailalternative";
pub const ATTR_EMAIL_PRIMARY: &str = "emailprimary";
pub const ATTR_EMAIL: &str = "email";
pub const ATTR_ENTRYDN: &str = "entrydn";
pub const ATTR_ENTRYUUID: &str = "entryuuid";
pub const ATTR_LDAP_KEYS: &str = "keys";
pub const ATTR_EXCLUDES: &str = "excludes";
pub const ATTR_ES256_PRIVATE_KEY_DER: &str = "es256_private_key_der";
pub const ATTR_FERNET_PRIVATE_KEY_STR: &str = "fernet_private_key_str";
pub const ATTR_GIDNUMBER: &str = "gidnumber";
pub const ATTR_GRANT_UI_HINT: &str = "grant_ui_hint";
pub const ATTR_GROUP: &str = "group";
pub const ATTR_ID_VERIFICATION_ECKEY: &str = "id_verification_eckey";
pub const ATTR_IMAGE: &str = "image";
pub const ATTR_INDEX: &str = "index";
pub const ATTR_IPANTHASH: &str = "ipanthash";
pub const ATTR_IPASSHPUBKEY: &str = "ipasshpubkey";
pub const ATTR_JWS_ES256_PRIVATE_KEY: &str = "jws_es256_private_key";
pub const ATTR_LAST_MODIFIED_CID: &str = "last_modified_cid";
pub const ATTR_LEGALNAME: &str = "legalname";
pub const ATTR_LOGINSHELL: &str = "loginshell";
pub const ATTR_MAIL: &str = "mail";
pub const ATTR_MAY: &str = "may";
pub const ATTR_MEMBER: &str = "member";
pub const ATTR_MEMBEROF: &str = "memberof";
pub const ATTR_MULTIVALUE: &str = "multivalue";
pub const ATTR_MUST: &str = "must";
pub const ATTR_NAME_HISTORY: &str = "name_history";
pub const ATTR_NAME: &str = "name";
pub const ATTR_NO_INDEX: &str = "no-index";
pub const ATTR_NSUNIQUEID: &str = "nsuniqueid";

pub const ATTR_OAUTH2_ALLOW_INSECURE_CLIENT_DISABLE_PKCE: &str =
    "oauth2_allow_insecure_client_disable_pkce";
pub const ATTR_OAUTH2_CONSENT_SCOPE_MAP: &str = "oauth2_consent_scope_map";
pub const ATTR_OAUTH2_JWT_LEGACY_CRYPTO_ENABLE: &str = "oauth2_jwt_legacy_crypto_enable";
pub const ATTR_OAUTH2_PREFER_SHORT_USERNAME: &str = "oauth2_prefer_short_username";
pub const ATTR_OAUTH2_RS_BASIC_SECRET: &str = "oauth2_rs_basic_secret";
pub const ATTR_OAUTH2_RS_IMPLICIT_SCOPES: &str = "oauth2_rs_implicit_scopes";
pub const ATTR_OAUTH2_RS_NAME: &str = "oauth2_rs_name";
pub const ATTR_OAUTH2_RS_ORIGIN_LANDING: &str = "oauth2_rs_origin_landing";
pub const ATTR_OAUTH2_RS_ORIGIN: &str = "oauth2_rs_origin";
pub const ATTR_OAUTH2_RS_SCOPE_MAP: &str = "oauth2_rs_scope_map";
pub const ATTR_OAUTH2_RS_SUP_SCOPE_MAP: &str = "oauth2_rs_sup_scope_map";
pub const ATTR_OAUTH2_RS_TOKEN_KEY: &str = "oauth2_rs_token_key";
pub const ATTR_OAUTH2_SESSION: &str = "oauth2_session";
pub const ATTR_OBJECTCLASS: &str = "objectclass";
pub const ATTR_OTHER_NO_INDEX: &str = "other-no-index";
pub const ATTR_PASSKEYS: &str = "passkeys";
pub const ATTR_PASSWORD_IMPORT: &str = "password_import";
pub const ATTR_PHANTOM: &str = "phantom";
pub const ATTR_PRIMARY_CREDENTIAL: &str = "primary_credential";
pub const ATTR_TOTP_IMPORT: &str = "totp_import";
pub const ATTR_PRIVATE_COOKIE_KEY: &str = "private_cookie_key";
pub const ATTR_PRIVILEGE_EXPIRY: &str = "privilege_expiry";
pub const ATTR_RADIUS_SECRET: &str = "radius_secret";
pub const ATTR_RECYCLED: &str = "recycled";
pub const ATTR_REPLICATED: &str = "replicated";
pub const ATTR_RS256_PRIVATE_KEY_DER: &str = "rs256_private_key_der";
pub const ATTR_SCOPE: &str = "scope";
pub const ATTR_SELF: &str = "self";
pub const ATTR_SOURCE_UUID: &str = "source_uuid";
pub const ATTR_SPN: &str = "spn";
pub const ATTR_SUPPLEMENTS: &str = "supplements";
pub const ATTR_LDAP_SSHPUBLICKEY: &str = "sshpublickey";
pub const ATTR_SSH_PUBLICKEY: &str = "ssh_publickey";
pub const ATTR_SYNC_ALLOWED: &str = "sync_allowed";
pub const ATTR_SYNC_CLASS: &str = "sync_class";
pub const ATTR_SYNC_COOKIE: &str = "sync_cookie";
pub const ATTR_SYNC_CREDENTIAL_PORTAL: &str = "sync_credential_portal";
pub const ATTR_SYNC_EXTERNAL_ID: &str = "sync_external_id";
pub const ATTR_SYNC_EXTERNAL_UUID: &str = "sync_external_uuid";
pub const ATTR_SYNC_PARENT_UUID: &str = "sync_parent_uuid";
pub const ATTR_SYNC_TOKEN_SESSION: &str = "sync_token_session";
pub const ATTR_SYNC_YIELD_AUTHORITY: &str = "sync_yield_authority";
pub const ATTR_SYNTAX: &str = "syntax";
pub const ATTR_SYSTEMEXCLUDES: &str = "systemexcludes";
pub const ATTR_SYSTEMMAY: &str = "systemmay";
pub const ATTR_SYSTEMMUST: &str = "systemmust";
pub const ATTR_SYSTEMSUPPLEMENTS: &str = "systemsupplements";
pub const ATTR_TERM: &str = "term";
pub const ATTR_UID: &str = "uid";
pub const ATTR_UIDNUMBER: &str = "uidnumber";
pub const ATTR_UNIQUE: &str = "unique";
pub const ATTR_UNIX_PASSWORD: &str = "unix_password";
pub const ATTR_USER_AUTH_TOKEN_SESSION: &str = "user_auth_token_session";
pub const ATTR_USERID: &str = "userid";
pub const ATTR_USERPASSWORD: &str = "userpassword";
pub const ATTR_UUID: &str = "uuid";
pub const ATTR_VERSION: &str = "version";

pub const OAUTH2_SCOPE_EMAIL: &str = ATTR_EMAIL;
pub const OAUTH2_SCOPE_GROUPS: &str = "groups";
pub const OAUTH2_SCOPE_OPENID: &str = "openid";
pub const OAUTH2_SCOPE_READ: &str = "read";
pub const OAUTH2_SCOPE_SUPPLEMENT: &str = "supplement";

pub const LDAP_ATTR_CN: &str = "cn";
pub const LDAP_ATTR_DISPLAY_NAME: &str = "displayName";
pub const LDAP_ATTR_EMAIL_ALTERNATIVE: &str = "emailalternative";
pub const LDAP_ATTR_EMAIL_PRIMARY: &str = "emailprimary";
pub const LDAP_ATTR_ENTRYDN: &str = "entrydn";
pub const LDAP_ATTR_ENTRYUUID: &str = "entryuuid";
pub const LDAP_ATTR_GROUPS: &str = "groups";
pub const LDAP_ATTR_KEYS: &str = "keys";
pub const LDAP_ATTR_MAIL_ALTERNATIVE: &str = "mail;alternative";
pub const LDAP_ATTR_MAIL_PRIMARY: &str = "mail;primary";
pub const LDAP_ATTR_MAIL: &str = "mail";
pub const LDAP_ATTR_MEMBER: &str = "member";
pub const LDAP_ATTR_NAME: &str = "name";
pub const LDAP_ATTR_OBJECTCLASS: &str = "objectClass";
pub const LDAP_ATTR_OU: &str = "ou";
pub const LDAP_CLASS_GROUPOFNAMES: &str = "groupofnames";

// rust can't deal with this being compiled out, don't try and #[cfg()] them
pub const TEST_ATTR_NON_EXIST: &str = "non-exist";
pub const TEST_ATTR_TEST_ATTR: &str = "testattr";
pub const TEST_ATTR_EXTRA: &str = "extra";
pub const TEST_ATTR_NUMBER: &str = "testattrnumber";
pub const TEST_ATTR_NOTALLOWED: &str = "notallowed";

pub const KSESSIONID: &str = "X-KANIDM-AUTH-SESSION-ID";
pub const KOPID: &str = "X-KANIDM-OPID";
pub const KVERSION: &str = "X-KANIDM-VERSION";

pub const X_FORWARDED_FOR: &str = "x-forwarded-for";
