use clap::{Args, Subcommand};

#[derive(Debug, Args)]
pub struct Named {
    pub name: String,
    #[clap(flatten)]
    pub copt: CommonOpt,
}

#[derive(Debug, Args)]
pub struct DebugOpt {
    /// Enable debugging of the kanidm tool
    #[clap(short, long, env = "KANIDM_DEBUG")]
    pub debug: bool,
}

#[derive(Debug, Clone)]
/// The CLI output mode, either text or json, falls back to text if you ask for something other than text/json
pub enum OutputMode {
    Text,
    Json,
}

impl std::str::FromStr for OutputMode {
    type Err = String;
    fn from_str(s: &str) -> Result<OutputMode, std::string::String> {
        match s.to_lowercase().as_str() {
            "text" => Ok(OutputMode::Text),
            "json" => Ok(OutputMode::Json),
            _ => Ok(OutputMode::Text),
        }
    }
}

#[derive(Debug, Args, Clone)]
pub struct CommonOpt {
    /// Enable debugging of the kanidm tool
    #[clap(short, long, env = "KANIDM_DEBUG")]
    pub debug: bool,
    /// The URL of the kanidm instance
    #[clap(short = 'H', long = "url", env = "KANIDM_URL")]
    pub addr: Option<String>,
    /// User which will initiate requests
    #[clap(short = 'D', long = "name", env = "KANIDM_NAME")]
    pub username: Option<String>,
    /// Path to a CA certificate file
    #[clap(value_parser, short = 'C', long = "ca", env = "KANIDM_CA_PATH")]
    pub ca_path: Option<PathBuf>,
    /// Log format (still in very early development)
    #[clap(short, long = "output", env = "KANIDM_OUTPUT", default_value = "text")]
    output_mode: OutputMode,
    /// Skip hostname verification
    #[clap(
        long = "skip-hostname-verification",
        env = "KANIDM_SKIP_HOSTNAME_VERIFICATION",
        default_value_t = false
    )]
    skip_hostname_verification: bool,
}

#[derive(Debug, Args)]
pub struct GroupNamedMembers {
    name: String,
    #[clap(required = true, num_args(1..))]
    members: Vec<String>,
    #[clap(flatten)]
    copt: CommonOpt,
}

#[derive(Debug, Args)]
pub struct GroupPosixOpt {
    name: String,
    #[clap(long)]
    gidnumber: Option<u32>,
    #[clap(flatten)]
    copt: CommonOpt,
}

#[derive(Debug, Subcommand)]
pub enum GroupPosix {
    /// Show details of a specific posix group
    #[clap(name = "show")]
    Show(Named),
    /// Setup posix group properties, or alter them
    #[clap(name = "set")]
    Set(GroupPosixOpt),
}

#[derive(Debug, Subcommand)]
pub enum GroupAccountPolicyOpt {
    /// Enable account policy for this group
    #[clap(name = "enable")]
    Enable {
        name: String,
        #[clap(flatten)]
        copt: CommonOpt,
    },
    /// Set the maximum time for session expiry
    #[clap(name = "auth-expiry")]
    AuthSessionExpiry {
        name: String,
        expiry: u32,
        #[clap(flatten)]
        copt: CommonOpt,
    },
    /// Configure and display the privilege session expiry
    /// Set the maximum time for privilege session expiry
    #[clap(name = "privilege-expiry")]
    PrivilegedSessionExpiry {
        name: String,
        expiry: u32,
        #[clap(flatten)]
        copt: CommonOpt,
    },
}

#[derive(Debug, Subcommand)]
pub enum GroupOpt {
    /// List all groups
    #[clap(name = "list")]
    List(CommonOpt),
    /// View a specific group
    #[clap(name = "get")]
    Get(Named),
    /// Create a new group
    #[clap(name = "create")]
    Create(Named),
    /// Delete a group
    #[clap(name = "delete")]
    Delete(Named),
    /// List the members of a group
    #[clap(name = "list-members")]
    ListMembers(Named),
    /// Set the exact list of members that this group should contain, removing any not listed in the
    /// set operation.
    #[clap(name = "set-members")]
    SetMembers(GroupNamedMembers),
    /// Delete all members of a group.
    #[clap(name = "purge-members")]
    PurgeMembers(Named),
    /// Add new members to a group
    #[clap(name = "add-members")]
    AddMembers(GroupNamedMembers),
    /// Remove the named members from this group
    #[clap(name = "remove-members")]
    RemoveMembers(GroupNamedMembers),
    /// Manage posix extensions for this group allowing groups to be used on unix/linux systems
    #[clap(name = "posix")]
    Posix {
        #[clap(subcommand)]
        commands: GroupPosix,
    },
    /// Manage the policies that apply to members of this group.
    #[clap(name = "account-policy")]
    AccountPolicy {
        #[clap(subcommand)]
        commands: GroupAccountPolicyOpt
    }
}

#[derive(Debug, Args)]
pub struct AccountCommonOpt {
    #[clap()]
    account_id: String,
}

#[derive(Debug, Args)]
pub struct AccountNamedOpt {
    #[clap(flatten)]
    aopts: AccountCommonOpt,
    #[clap(flatten)]
    copt: CommonOpt,
}

#[derive(Debug, Args)]
pub struct AccountNamedExpireDateTimeOpt {
    #[clap(flatten)]
    aopts: AccountCommonOpt,
    #[clap(flatten)]
    copt: CommonOpt,
    #[clap(name = "datetime", verbatim_doc_comment)]
    /// This accepts multiple options:
    /// - An RFC3339 time of the format "YYYY-MM-DDTHH:MM:SS+TZ", "2020-09-25T11:22:02+10:00"
    /// - One of "any", "clear" or "never" to remove account expiry.
    /// - "epoch" to set the expiry to the UNIX epoch
    /// - "now" to expire immediately (this will affect authentication with Kanidm, but external systems may not be aware of the change until next time it's validated, typically ~15 minutes)
    datetime: String,
}

#[derive(Debug, Args)]
pub struct AccountNamedValidDateTimeOpt {
    #[clap(flatten)]
    aopts: AccountCommonOpt,
    #[clap(flatten)]
    copt: CommonOpt,
    #[clap(name = "datetime")]
    /// An rfc3339 time of the format "YYYY-MM-DDTHH:MM:SS+TZ", "2020-09-25T11:22:02+10:00"
    /// or the word "any", "clear" to remove valid from enforcement.
    datetime: String,
}

#[derive(Debug, Args)]
pub struct AccountNamedTagOpt {
    #[clap(flatten)]
    aopts: AccountCommonOpt,
    #[clap(flatten)]
    copt: CommonOpt,
    #[clap(name = "tag")]
    tag: String,
}

#[derive(Debug, Args)]
pub struct AccountNamedTagPkOpt {
    #[clap(flatten)]
    aopts: AccountCommonOpt,
    #[clap(flatten)]
    copt: CommonOpt,
    #[clap(name = "tag")]
    tag: String,
    #[clap(name = "pubkey")]
    pubkey: String,
}

#[derive(Debug, Args)]
/// Command-line options for account credental use-reset-token
pub struct UseResetTokenOpt {
    #[clap(flatten)]
    copt: CommonOpt,
    #[clap(name = "token")]
    token: String,
}

#[derive(Debug, Args)]
pub struct AccountCreateOpt {
    #[clap(flatten)]
    aopts: AccountCommonOpt,
    #[clap(name = "display-name")]
    display_name: String,
    #[clap(flatten)]
    copt: CommonOpt,
}

#[derive(Debug, Subcommand)]
pub enum AccountCredential {
    /// Show the status of this accounts credentials.
    #[clap(name = "status")]
    Status(AccountNamedOpt),
    /// Interactively update/change the credentials for an account
    #[clap(name = "update")]
    Update(AccountNamedOpt),
    /// Using a reset token, interactively reset credentials for a user
    #[clap(name = "use-reset-token")]
    UseResetToken(UseResetTokenOpt),
    /// Create a reset token that can be given to another person so they can
    /// recover or reset their account credentials.
    #[clap(name = "create-reset-token")]
    CreateResetToken {
        #[clap(flatten)]
        aopts: AccountCommonOpt,
        #[clap(flatten)]
        copt: CommonOpt,
        /// Optionally set how many seconds the reset token should be valid for.
        #[clap(long = "ttl")]
        ttl: Option<u32>,
    },
}

/// RADIUS secret management
#[derive(Debug, Subcommand)]
pub enum AccountRadius {
    /// Show the RADIUS secret for a user.
    #[clap(name = "show-secret")]
    Show(AccountNamedOpt),
    /// Generate a randomized RADIUS secret for a user.
    #[clap(name = "generate-secret")]
    Generate(AccountNamedOpt),
    #[clap(name = "delete-secret")]
    /// Remove the configured RADIUS secret for the user.
    DeleteSecret(AccountNamedOpt),
}

#[derive(Debug, Args)]
pub struct AccountPosixOpt {
    #[clap(flatten)]
    aopts: AccountCommonOpt,
    #[clap(long)]
    gidnumber: Option<u32>,
    #[clap(long)]
    shell: Option<String>,
    #[clap(flatten)]
    copt: CommonOpt,
}

#[derive(Debug, Subcommand)]
pub enum PersonPosix {
    #[clap(name = "show")]
    Show(AccountNamedOpt),
    #[clap(name = "set")]
    Set(AccountPosixOpt),
    #[clap(name = "set-password")]
    SetPassword(AccountNamedOpt),
}

#[derive(Debug, Subcommand)]
pub enum ServiceAccountPosix {
    #[clap(name = "show")]
    Show(AccountNamedOpt),
    #[clap(name = "set")]
    Set(AccountPosixOpt),
}

#[derive(Debug, Args)]
pub struct PersonUpdateOpt {
    #[clap(flatten)]
    aopts: AccountCommonOpt,
    #[clap(long, short, help = "Set the legal name for the person.")]
    legalname: Option<String>,
    #[clap(long, short, help = "Set the account name for the person.")]
    newname: Option<String>,
    #[clap(long, short = 'i', help = "Set the display name for the person.")]
    displayname: Option<String>,
    #[clap(
        long,
        short,
        help = "Set the mail address, can be set multiple times for multiple addresses. The first listed mail address is the 'primary'"
    )]
    mail: Option<Vec<String>>,
    #[clap(flatten)]
    copt: CommonOpt,
}

#[derive(Debug, Subcommand)]
pub enum AccountSsh {
    #[clap(name = "list-publickeys")]
    List(AccountNamedOpt),
    #[clap(name = "add-publickey")]
    Add(AccountNamedTagPkOpt),
    #[clap(name = "delete-publickey")]
    Delete(AccountNamedTagOpt),
}

#[derive(Debug, Subcommand)]
pub enum AccountValidity {
    /// Show an accounts validity window
    #[clap(name = "show")]
    Show(AccountNamedOpt),
    /// Set an accounts expiry time
    #[clap(name = "expire-at")]
    ExpireAt(AccountNamedExpireDateTimeOpt),
    /// Set an account valid from time
    #[clap(name = "begin-from")]
    BeginFrom(AccountNamedValidDateTimeOpt),
}

#[derive(Debug, Subcommand)]
pub enum AccountUserAuthToken {
    /// Show the status of logged in sessions associated to this account.
    #[clap(name = "status")]
    Status(AccountNamedOpt),
    /// Destroy / revoke a session for this account. Access to the
    /// session (user auth token) is NOT required, only the uuid of the session.
    #[clap(name = "destroy")]
    Destroy {
        #[clap(flatten)]
        aopts: AccountCommonOpt,
        #[clap(flatten)]
        copt: CommonOpt,
        /// The UUID of the token to destroy.
        #[clap(name = "session-id")]
        session_id: Uuid,
    },
}

#[derive(Debug, Subcommand)]
pub enum PersonOpt {
    /// Manage the credentials this person uses for authentication
    #[clap(name = "credential")]
    Credential {
        #[clap(subcommand)]
        commands: AccountCredential,
    },
    /// Manage radius access for this person
    #[clap(name = "radius")]
    Radius {
        #[clap(subcommand)]
        commands: AccountRadius,
    },
    /// Manage posix extensions for this person allowing access to unix/linux systems
    #[clap(name = "posix")]
    Posix {
        #[clap(subcommand)]
        commands: PersonPosix,
    },
    /// Manage sessions (user auth tokens) associated to this person.
    #[clap(name = "session")]
    Session {
        #[clap(subcommand)]
        commands: AccountUserAuthToken,
    },
    /// Manage ssh public key's associated to this person
    #[clap(name = "ssh")]
    Ssh {
        #[clap(subcommand)]
        commands: AccountSsh,
    },
    /// List all persons
    #[clap(name = "list")]
    List(CommonOpt),
    /// View a specific person
    #[clap(name = "get")]
    Get(AccountNamedOpt),
    /// Update a specific person's attributes
    #[clap(name = "update")]
    Update(PersonUpdateOpt),
    /// Create a new person's account
    #[clap(name = "create")]
    Create(AccountCreateOpt),
    /// Delete a person's account
    #[clap(name = "delete")]
    Delete(AccountNamedOpt),
    /// Manage a person's account validity, such as expiry time (account lock/unlock)
    #[clap(name = "validity")]
    Validity {
        #[clap(subcommand)]
        commands: AccountValidity,
    },
}

#[derive(Debug, Subcommand)]
pub enum ServiceAccountCredential {
    /// Show the status of this accounts password
    #[clap(name = "status")]
    Status(AccountNamedOpt),
    /// Reset and generate a new service account password. This password can NOT
    /// be used with the LDAP interface.
    #[clap(name = "generate")]
    GeneratePw(AccountNamedOpt),
}

#[derive(Debug, Subcommand)]
pub enum ServiceAccountApiToken {
    /// Show the status of api tokens associated to this service account.
    #[clap(name = "status")]
    Status(AccountNamedOpt),
    /// Generate a new api token for this service account.
    #[clap(name = "generate")]
    Generate {
        #[clap(flatten)]
        aopts: AccountCommonOpt,
        #[clap(flatten)]
        copt: CommonOpt,
        /// A string describing the token. This is not used to identify the token, it is only
        /// for human description of the tokens purpose.
        #[clap(name = "label")]
        label: String,
        #[clap(name = "expiry")]
        /// An optional rfc3339 time of the format "YYYY-MM-DDTHH:MM:SS+TZ", "2020-09-25T11:22:02+10:00".
        /// After this time the api token will no longer be valid.
        expiry: Option<String>,
        #[clap(long = "rw")]
        read_write: bool,
    },
    /// Destroy / revoke an api token from this service account. Access to the
    /// token is NOT required, only the tag/uuid of the token.
    #[clap(name = "destroy")]
    Destroy {
        #[clap(flatten)]
        aopts: AccountCommonOpt,
        #[clap(flatten)]
        copt: CommonOpt,
        /// The UUID of the token to destroy.
        #[clap(name = "token-id")]
        token_id: Uuid,
    },
}

#[derive(Debug, Args)]
pub struct ServiceAccountUpdateOpt {
    #[clap(flatten)]
    aopts: AccountCommonOpt,
    #[clap(long, short, help = "Set the account name for the service account.")]
    newname: Option<String>,
    #[clap(
        long,
        short = 'i',
        help = "Set the display name for the service account."
    )]
    displayname: Option<String>,
    #[clap(
        long,
        short,
        help = "Set the mail address, can be set multiple times for multiple addresses. The first listed mail address is the 'primary'"
    )]
    mail: Option<Vec<String>>,
    #[clap(flatten)]
    copt: CommonOpt,
}

#[derive(Debug, Subcommand)]
pub enum ServiceAccountOpt {
    /// Manage the generated password of this service account.
    #[clap(name = "credential")]
    Credential {
        #[clap(subcommand)]
        commands: ServiceAccountCredential,
    },
    /// Manage api tokens associated to this service account.
    #[clap(name = "api-token")]
    ApiToken {
        #[clap(subcommand)]
        commands: ServiceAccountApiToken,
    },
    /// Manage posix extensions for this service account allowing access to unix/linux systems
    #[clap(name = "posix")]
    Posix {
        #[clap(subcommand)]
        commands: ServiceAccountPosix,
    },
    /// Manage sessions (user auth tokens) associated to this service account.
    #[clap(name = "session")]
    Session {
        #[clap(subcommand)]
        commands: AccountUserAuthToken,
    },
    /// Manage ssh public key's associated to this person
    #[clap(name = "ssh")]
    Ssh {
        #[clap(subcommand)]
        commands: AccountSsh,
    },
    /// List all service accounts
    #[clap(name = "list")]
    List(CommonOpt),
    /// View a specific service account
    #[clap(name = "get")]
    Get(AccountNamedOpt),
    /// Create a new service account
    #[clap(name = "create")]
    Create(AccountCreateOpt),
    /// Update a specific service account's attributes
    #[clap(name = "update")]
    Update(ServiceAccountUpdateOpt),
    /// Delete a service account
    #[clap(name = "delete")]
    Delete(AccountNamedOpt),
    /// Manage a service account validity, such as expiry time (account lock/unlock)
    #[clap(name = "validity")]
    Validity {
        #[clap(subcommand)]
        commands: AccountValidity,
    },
    /// (Deprecated - due for removal in v1.1.0-15) - Convert a service account into a person. This is used during the alpha.9
    /// to alpha.10 migration to "fix up" accounts that were not previously marked
    /// as persons.
    #[clap(name = "into-person")]
    IntoPerson(AccountNamedOpt),
}

#[derive(Debug, Subcommand)]
pub enum RecycleOpt {
    #[clap(name = "list")]
    /// List objects that are in the recycle bin
    List(CommonOpt),
    #[clap(name = "get")]
    /// Display an object from the recycle bin
    Get(Named),
    #[clap(name = "revive")]
    /// Revive a recycled object into a live (accessible) state - this is the opposite of "delete"
    Revive(Named),
}

#[derive(Debug, Args)]
pub struct LoginOpt {
    #[clap(flatten)]
    copt: CommonOpt,
    #[clap(short, long, env = "KANIDM_PASSWORD", hide = true)]
    /// Supply a password to the login option
    password: Option<String>,
}

#[derive(Debug, Args)]
pub struct ReauthOpt {
    #[clap(flatten)]
    copt: CommonOpt,
}

#[derive(Debug, Args)]
pub struct LogoutOpt {
    #[clap(flatten)]
    copt: CommonOpt,
    #[clap(short, long, hide = true)]
    /// Do not send the logout to the server - only remove the session token locally
    local_only: bool,
}

#[derive(Debug, Subcommand)]
pub enum SessionOpt {
    #[clap(name = "list")]
    /// List current active sessions
    List(DebugOpt),
    #[clap(name = "cleanup")]
    /// Remove sessions that have expired or are invalid.
    Cleanup(DebugOpt),
}

#[derive(Debug, Args)]
pub struct FilterOpt {
    #[clap()]
    filter: String,
    #[clap(flatten)]
    commonopts: CommonOpt,
}

#[derive(Debug, Args)]
pub struct CreateOpt {
    #[clap(value_parser)]
    file: PathBuf,
    #[clap(flatten)]
    commonopts: CommonOpt,
}

#[derive(Debug, Args)]
pub struct ModifyOpt {
    #[clap(flatten)]
    commonopts: CommonOpt,
    #[clap()]
    filter: String,
    #[clap(value_parser)]
    file: PathBuf,
}

#[derive(Debug, Subcommand)]
pub enum RawOpt {
    #[clap(name = "search")]
    Search(FilterOpt),
    #[clap(name = "create")]
    Create(CreateOpt),
    #[clap(name = "modify")]
    Modify(ModifyOpt),
    #[clap(name = "delete")]
    Delete(FilterOpt),
}

#[derive(Debug, Subcommand)]
pub enum SelfOpt {
    /// Use the identify user feature
    #[clap(name = "identify-user")]
    IdentifyUser(CommonOpt),
    /// Show the current authenticated user's identity
    Whoami(CommonOpt),
}

#[derive(Debug, Args)]
pub struct Oauth2SetDisplayname {
    #[clap(flatten)]
    nopt: Named,
    #[clap(name = "displayname")]
    displayname: String,
}

#[derive(Debug, Args)]
pub struct Oauth2SetImplicitScopes {
    #[clap(flatten)]
    nopt: Named,
    #[clap(name = "scopes")]
    scopes: Vec<String>,
}

#[derive(Debug, Args)]
pub struct Oauth2CreateScopeMapOpt {
    #[clap(flatten)]
    nopt: Named,
    #[clap(name = "group")]
    group: String,
    #[clap(name = "scopes")]
    scopes: Vec<String>,
}

#[derive(Debug, Args)]
pub struct Oauth2DeleteScopeMapOpt {
    #[clap(flatten)]
    nopt: Named,
    #[clap(name = "group")]
    group: String,
}

#[derive(Debug, Subcommand)]
pub enum Oauth2Opt {
    #[clap(name = "list")]
    /// List all configured oauth2 resource servers
    List(CommonOpt),
    #[clap(name = "get")]
    /// Display a selected oauth2 resource server
    Get(Named),
    // #[clap(name = "set")]
    // /// Set options for a selected oauth2 resource server
    // Set(),
    #[clap(name = "create")]
    /// Create a new oauth2 confidential resource server that is protected by basic auth.
    CreateBasic {
        #[clap(name = "name")]
        name: String,
        #[clap(name = "displayname")]
        displayname: String,
        #[clap(name = "origin")]
        origin: String,
        #[clap(flatten)]
        copt: CommonOpt,
    },
    #[clap(name = "create-public")]
    /// Create a new OAuth2 public resource server that requires PKCE. You should prefer
    /// using confidential resource server types if possible over public ones.
    ///
    /// Public clients have many limitations and can not access all API's of OAuth2. For
    /// example rfc7662 token introspection requires client authentication.
    CreatePublic {
        #[clap(name = "name")]
        name: String,
        #[clap(name = "displayname")]
        displayname: String,
        #[clap(name = "origin")]
        origin: String,
        #[clap(flatten)]
        copt: CommonOpt,
    },
    #[clap(name = "update-scope-map", visible_aliases=&["create-scope-map"])]
    /// Update or add a new mapping from a group to scopes that it provides to members
    UpdateScopeMap(Oauth2CreateScopeMapOpt),
    #[clap(name = "delete-scope-map")]
    /// Remove a mapping from groups to scopes
    DeleteScopeMap(Oauth2DeleteScopeMapOpt),

    #[clap(name = "update-sup-scope-map", visible_aliases=&["create-sup-scope-map"])]
    /// Update or add a new mapping from a group to scopes that it provides to members
    UpdateSupScopeMap(Oauth2CreateScopeMapOpt),
    #[clap(name = "delete-sup-scope-map")]
    /// Remove a mapping from groups to scopes
    DeleteSupScopeMap(Oauth2DeleteScopeMapOpt),

    #[clap(name = "reset-secrets")]
    /// Reset the secrets associated to this resource server
    ResetSecrets(Named),
    #[clap(name = "show-basic-secret")]
    /// Show the associated basic secret for this resource server
    ShowBasicSecret(Named),
    #[clap(name = "delete")]
    /// Delete a oauth2 resource server
    Delete(Named),
    /// Set a new displayname for a resource server
    #[clap(name = "set-displayname")]
    SetDisplayname(Oauth2SetDisplayname),
    /// Set a new name for this resource server. You may need to update
    /// your integrated applications after this so that they continue to
    /// function correctly.
    #[clap(name = "set-name")]
    SetName {
        #[clap(flatten)]
        nopt: Named,
        #[clap(name = "newname")]
        name: String,
    },
    /// When redirecting from the Kanidm Apps Listing page, some linked applications may need to
    /// land on a specific page to trigger oauth2/oidc interactions.
    #[clap(name = "set-landing-url")]
    SetLandingUrl {
        #[clap(flatten)]
        nopt: Named,
        #[clap(name = "landing-url")]
        url: String,
    },
    #[clap(name = "enable-pkce")]
    /// Enable PKCE on this oauth2 resource server. This defaults to being enabled.
    EnablePkce(Named),
    /// Disable PKCE on this oauth2 resource server to work around insecure clients that
    /// may not support it. You should request the client to enable PKCE!
    #[clap(name = "warning-insecure-client-disable-pkce")]
    DisablePkce(Named),
    #[clap(name = "warning-enable-legacy-crypto")]
    /// Enable legacy signing crypto on this oauth2 resource server. This defaults to being disabled.
    /// You only need to enable this for openid clients that do not support modern crytopgraphic
    /// operations.
    EnableLegacyCrypto(Named),
    /// Disable legacy signing crypto on this oauth2 resource server. This is the default.
    #[clap(name = "disable-legacy-crypto")]
    DisableLegacyCrypto(Named),
    #[clap(name = "prefer-short-username")]
    /// Use the 'name' attribute instead of 'spn' for the preferred_username
    PreferShortUsername(Named),
    #[clap(name = "prefer-spn-username")]
    /// Use the 'spn' attribute instead of 'name' for the preferred_username
    PreferSPNUsername(Named),
}

#[derive(Args, Debug)]
pub struct OptSetDomainDisplayName {
    #[clap(flatten)]
    copt: CommonOpt,
    #[clap(name = "new-display-name")]
    new_display_name: String,
}

#[derive(Debug, Subcommand)]
pub enum PwBadlistOpt {
    #[clap[name = "show"]]
    /// Show information about this system's password badlist
    Show(CommonOpt),
    #[clap[name = "upload"]]
    /// Upload an extra badlist, appending to the currently configured one.
    /// This badlist will be preprocessed to remove items that are already
    /// caught by "zxcvbn" at the configured level.
    Upload {
        #[clap(flatten)]
        copt: CommonOpt,
        #[clap(value_parser, required = true, num_args(1..))]
        paths: Vec<PathBuf>,
        /// Perform a dry run and display the list that would have been uploaded instead.
        #[clap(short = 'n', long)]
        dryrun: bool,
    },
    #[clap[name = "remove", hide = true]]
    /// Remove the content of these lists if present in the configured
    /// badlist.
    Remove {
        #[clap(flatten)]
        copt: CommonOpt,
        #[clap(value_parser, required = true, num_args(1..))]
        paths: Vec<PathBuf>,
    },
}

#[derive(Debug, Subcommand)]
pub enum DeniedNamesOpt {
    #[clap[name = "show"]]
    /// Show information about this system's denied name list
    Show {
        #[clap(flatten)]
        copt: CommonOpt,
    },
    #[clap[name = "append"]]
    Append {
        #[clap(flatten)]
        copt: CommonOpt,
        #[clap(value_parser, required = true, num_args(1..))]
        names: Vec<String>,
    },
    #[clap[name = "remove"]]
    /// Remove a name from the denied name list.
    Remove {
        #[clap(flatten)]
        copt: CommonOpt,
        #[clap(value_parser, required = true, num_args(1..))]
        names: Vec<String>,
    },
}


#[derive(Debug, Subcommand)]
pub enum DomainOpt {
    #[clap[name = "set-display-name"]]
    /// Set the domain display name
    SetDisplayName(OptSetDomainDisplayName),
    #[clap[name = "set-ldap-basedn"]]
    /// Change the basedn of this server. Takes effect after a server restart.
    /// Examples are `o=organisation` or `dc=domain,dc=name`. Must be a valid ldap
    /// dn containing only alphanumerics, and dn components must be org (o), domain (dc) or
    /// orgunit (ou).
    SetLdapBasedn {
        #[clap(flatten)]
        copt: CommonOpt,
        #[clap(name = "new-basedn")]
        new_basedn: String,
    },
    /// Enable or disable unix passwords being used to bind via LDAP. Unless you have a specific
    /// requirement for this, you should disable this.
    SetLdapAllowUnixPasswordBind {
        #[clap(flatten)]
        copt: CommonOpt,
        #[clap(name = "allow", action = clap::ArgAction::Set)]
        enable: bool,
    },
    #[clap(name = "show")]
    /// Show information about this system's domain
    Show(CommonOpt),
    #[clap(name = "reset-token-key")]
    /// Reset this domain token signing key. This will cause all user sessions to be
    /// invalidated (logged out).
    ResetTokenKey(CommonOpt),
}

#[derive(Debug, Subcommand)]
pub enum SynchOpt {
    #[clap(name = "list")]
    /// List all configured IDM sync accounts
    List(CommonOpt),
    #[clap(name = "get")]
    /// Display a selected IDM sync account
    Get(Named),
    #[clap(name = "set-credential-portal")]
    /// Set the url to the external credential portal. This will be displayed to synced users
    /// so that they can be redirected to update their credentials on this portal.
    SetCredentialPortal {
        #[clap()]
        account_id: String,
        #[clap(flatten)]
        copt: CommonOpt,
        #[clap(name = "url")]
        url: Option<Url>,
    },
    /// Create a new IDM sync account
    #[clap(name = "create")]
    Create {
        #[clap()]
        account_id: String,
        #[clap(flatten)]
        copt: CommonOpt,
        #[clap(name = "description")]
        description: Option<String>,
    },
    /// Generate a bearer token for an IDM sync account
    #[clap(name = "generate-token")]
    GenerateToken {
        #[clap()]
        account_id: String,
        #[clap()]
        label: String,
        #[clap(flatten)]
        copt: CommonOpt,
    },
    /// Destroy (revoke) the bearer token for an IDM sync account
    #[clap(name = "destroy-token")]
    DestroyToken {
        #[clap()]
        account_id: String,
        #[clap(flatten)]
        copt: CommonOpt,
    },
    /// Set the list of attributes that have their authority yielded from the sync account
    /// and are allowed to be modified by kanidm and users. Any attributes not listed in
    /// in this command will have their authority returned to the sync account.
    #[clap(name = "set-yield-attributes")]
    SetYieldAttributes {
        #[clap()]
        account_id: String,
        #[clap(flatten)]
        copt: CommonOpt,
        #[clap(name = "attributes")]
        attrs: Vec<String>,
    },
    /// Reset the sync cookie of this connector, so that on the next operation of the sync tool
    /// a full refresh of the provider is requested. Kanidm attributes that have been granted
    /// authority will *not* be lost or deleted.
    #[clap(name = "force-refresh")]
    ForceRefresh {
        #[clap()]
        account_id: String,
        #[clap(flatten)]
        copt: CommonOpt,
    },
    /// Finalise and remove this sync account. This will transfer all synchronised entries into
    /// the authority of Kanidm. This signals the end of a migration from an external IDM into
    /// Kanidm. ⚠️  This action can NOT be undone. Once complete, it is most likely
    /// that attempting to recreate a sync account from the same IDM will fail due to conflicting
    /// entries that Kanidm now owns.
    #[clap(name = "finalise")]
    Finalise {
        #[clap()]
        account_id: String,
        #[clap(flatten)]
        copt: CommonOpt,
    },
    /// Terminate and remove this sync account. This will DELETE all entries that were imported
    /// from the external IDM source. ⚠️  This action can NOT be undone, and will require you to
    /// recreate the sync account if you
    /// wish to re-import data. Recreating the sync account may fail until the recycle bin and
    /// and tombstones are purged.
    #[clap(name = "terminate")]
    Terminate {
        #[clap()]
        account_id: String,
        #[clap(flatten)]
        copt: CommonOpt,
    },
}

#[derive(Debug, Subcommand)]
pub enum AuthSessionExpiryOpt {
    #[clap[name = "get"]]
    /// Show information about this system auth session expiry
    Get(CommonOpt),
    #[clap[name = "set"]]
    /// Sets the system auth session expiry in seconds
    Set {
        #[clap(flatten)]
        copt: CommonOpt,
        #[clap(name = "expiry")]
        expiry: u32,
    },
}

#[derive(Debug, Subcommand)]
pub enum PrivilegedSessionExpiryOpt {
    #[clap[name = "get"]]
    /// Show information about this system privileged session expiry
    Get(CommonOpt),
    #[clap[name = "set"]]
    /// Sets the system auth privilege session expiry in seconds
    Set {
        #[clap(flatten)]
        copt: CommonOpt,
        #[clap(name = "expiry")]
        expiry: u32,
    },
}

#[derive(Debug, Subcommand)]
pub enum SystemOpt {
    #[clap(name = "pw-badlist")]
    /// Configure and manage the password badlist entry
    PwBadlist {
        #[clap(subcommand)]
        commands: PwBadlistOpt,
    },
    #[clap(name = "denied-names")]
    /// Configure and manage denied names
    DeniedNames {
        #[clap(subcommand)]
        commands: DeniedNamesOpt,
    },
    #[clap(name = "oauth2")]
    /// Configure and display oauth2/oidc resource server configuration
    Oauth2 {
        #[clap(subcommand)]
        commands: Oauth2Opt,
    },
    #[clap(name = "domain")]
    /// Configure and display domain configuration
    Domain {
        #[clap(subcommand)]
        commands: DomainOpt,
    },
    #[clap(name = "sync")]
    /// Configure synchronisation from an external IDM system
    Synch {
        #[clap(subcommand)]
        commands: SynchOpt,
    },
}

#[derive(Debug, Subcommand)]
#[clap(about = "Kanidm Client Utility")]
pub enum KanidmClientOpt {
    /// Login to an account to use with future cli operations
    Login(LoginOpt),
    /// Reauthenticate to access privileged functions of this account for a short period.
    Reauth(ReauthOpt),
    /// Logout of an active cli session
    Logout(LogoutOpt),
    /// Manage active cli sessions
    Session {
        #[clap(subcommand)]
        commands: SessionOpt,
    },
    #[clap(name = "self")]
    /// Actions for the current authenticated account
    CSelf {
        #[clap(subcommand)]
        commands: SelfOpt,
    },
    /// Actions to manage and view person (user) accounts
    Person {
        #[clap(subcommand)]
        commands: PersonOpt,
    },
    /// Actions to manage groups
    Group {
        #[clap(subcommand)]
        commands: GroupOpt,
    },
    /// Actions to manage and view service accounts
    #[clap(name = "service-account")]
    ServiceAccount {
        #[clap(subcommand)]
        commands: ServiceAccountOpt,
    },
    /// System configuration operations
    System {
        #[clap(subcommand)]
        commands: SystemOpt,
    },
    #[clap(name = "recycle-bin")]
    /// Recycle Bin operations
    Recycle {
        #[clap(subcommand)]
        commands: RecycleOpt,
    },
    /// Unsafe - low level, raw database queries and operations.
    #[clap(hide = true)]
    Raw {
        #[clap(subcommand)]
        commands: RawOpt,
    },
    /// Print the program version and exit
    Version {},
}

#[derive(Debug, clap::Parser)]
#[clap(about = "Kanidm Client Utility")]
pub struct KanidmClientParser {
    #[clap(subcommand)]
    pub commands: KanidmClientOpt,
}
