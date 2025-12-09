use crate::unix_passwd::{EtcDb, EtcGroup, EtcUser};
use kanidm_proto::internal::OperationError;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct NssUser {
    pub name: String,
    pub uid: u32,
    pub gid: u32,
    pub gecos: String,
    pub homedir: String,
    pub shell: String,
}

impl<T> From<&T> for NssUser
where
    T: AsRef<EtcUser>,
{
    fn from(etc_user: &T) -> Self {
        let etc_user = etc_user.as_ref();
        NssUser {
            name: etc_user.name.clone(),
            uid: etc_user.uid,
            gid: etc_user.gid,
            gecos: etc_user.gecos.clone(),
            homedir: etc_user.homedir.clone(),
            shell: etc_user.shell.clone(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct NssGroup {
    pub name: String,
    pub gid: u32,
    pub members: Vec<String>,
}

impl<T> From<&T> for NssGroup
where
    T: AsRef<EtcGroup>,
{
    fn from(etc_group: &T) -> Self {
        let etc_group = etc_group.as_ref();
        NssGroup {
            name: etc_group.name.clone(),
            gid: etc_group.gid,
            members: etc_group.members.clone(),
        }
    }
}

/* RFC8628: 3.2. Device Authorization Response */
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DeviceAuthorizationResponse {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub verification_uri_complete: Option<String>,
    pub expires_in: u32,
    pub interval: Option<u32>,
    /* The message is not part of RFC8628, but an add-on from MS. Listed
     * optional here to support all implementations. */
    pub message: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum PamAuthResponse {
    Unknown,
    Success,
    Denied,
    Password,
    DeviceAuthorizationGrant {
        data: DeviceAuthorizationResponse,
    },
    /// PAM must prompt for an authentication code
    MFACode {
        msg: String,
    },
    /// PAM will poll for an external response
    MFAPoll {
        /// Initial message to display as the polling begins.
        msg: String,
        /// Seconds between polling attempts.
        polling_interval: u32,
    },
    MFAPollWait,
    /// PAM must prompt for a new PIN and confirm that PIN input
    SetupPin {
        msg: String,
    },
    Pin,
    // CTAP2
}

#[derive(Serialize, Deserialize, Debug)]
pub enum PamAuthRequest {
    Password { cred: String },
    DeviceAuthorizationGrant { data: DeviceAuthorizationResponse },
    MFACode { cred: String },
    MFAPoll,
    SetupPin { pin: String },
    Pin { cred: String },
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PamServiceInfo {
    pub service: String,
    // Somehow SDDM doesn't set this ...
    pub tty: Option<String>,
    // Only set if it really is a remote host?
    pub rhost: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum ClientRequest {
    SshKey(String),
    NssAccounts,
    NssAccountByUid(u32),
    NssAccountByName(String),
    NssGroups,
    NssGroupByGid(u32),
    NssGroupByName(String),
    PamAuthenticateInit {
        account_id: String,
        info: PamServiceInfo,
    },
    PamAuthenticateStep {
        request: PamAuthRequest,
        session_id: u64,
    },
    PamAccountAllowed(String),
    PamAccountBeginSession(String),
    InvalidateCache,
    ClearCache,
    Status,
}

impl ClientRequest {
    /// Get a safe display version of the request, without credentials.
    pub fn as_safe_string(&self) -> String {
        match self {
            ClientRequest::SshKey(id) => format!("SshKey({id})"),
            ClientRequest::NssAccounts => "NssAccounts".to_string(),
            ClientRequest::NssAccountByUid(id) => format!("NssAccountByUid({id})"),
            ClientRequest::NssAccountByName(id) => format!("NssAccountByName({id})"),
            ClientRequest::NssGroups => "NssGroups".to_string(),
            ClientRequest::NssGroupByGid(id) => format!("NssGroupByGid({id})"),
            ClientRequest::NssGroupByName(id) => format!("NssGroupByName({id})"),
            ClientRequest::PamAuthenticateInit { account_id, info } => format!(
                "PamAuthenticateInit{{ account_id={} tty={} pam_secvice{} rhost={} }}",
                account_id,
                info.service,
                info.tty.as_deref().unwrap_or(""),
                info.rhost.as_deref().unwrap_or("")
            ),
            ClientRequest::PamAuthenticateStep { .. } => "PamAuthenticateStep".to_string(),
            ClientRequest::PamAccountAllowed(id) => {
                format!("PamAccountAllowed({id})")
            }
            ClientRequest::PamAccountBeginSession(_) => "PamAccountBeginSession".to_string(),
            ClientRequest::InvalidateCache => "InvalidateCache".to_string(),
            ClientRequest::ClearCache => "ClearCache".to_string(),
            ClientRequest::Status => "Status".to_string(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ProviderStatus {
    pub name: String,
    pub online: bool,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum ClientResponse {
    SshKeys(Vec<String>),
    NssAccounts(Vec<NssUser>),
    NssAccount(Option<NssUser>),
    NssGroups(Vec<NssGroup>),
    NssGroup(Option<NssGroup>),

    PamStatus(Option<bool>),
    PamAuthenticateStepResponse {
        response: PamAuthResponse,
        session_id: u64,
    },

    ProviderStatus(Vec<ProviderStatus>),

    Ok,
    Error(OperationError),
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct HomeDirectoryInfo {
    pub uid: u32,
    pub gid: u32,
    pub name: String,
    pub aliases: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TaskRequestFrame {
    pub id: u64,
    pub req: TaskRequest,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum TaskRequest {
    HomeDirectory(HomeDirectoryInfo),
}

#[derive(Serialize, Deserialize, Debug)]
pub enum TaskResponse {
    Success(u64),
    Error(String),
    NotifyShadowChange(EtcDb),
}

#[test]
fn test_clientrequest_as_safe_string() {
    assert_eq!(
        ClientRequest::NssAccounts.as_safe_string(),
        "NssAccounts".to_string()
    );
    assert_eq!(
        ClientRequest::SshKey("cheese".to_string()).as_safe_string(),
        format!("SshKey({})", "cheese")
    );
}
