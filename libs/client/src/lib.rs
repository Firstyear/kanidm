#![deny(warnings)]
#![warn(unused_extern_crates)]
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::unreachable)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::needless_pass_by_value)]
#![deny(clippy::trivially_copy_pass_by_ref)]

#[macro_use]
extern crate tracing;

use std::collections::{BTreeMap, BTreeSet as Set};
use std::fmt::{Display, Formatter};
use std::fs::File;
#[cfg(target_family = "unix")] // not needed for windows builds
use std::fs::{metadata, Metadata};
use std::io::{ErrorKind, Read};
#[cfg(target_family = "unix")] // not needed for windows builds
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::time::Duration;

use kanidm_proto::constants::{APPLICATION_JSON, ATTR_NAME, KOPID, KSESSIONID, KVERSION};
use kanidm_proto::v1::*;
use reqwest::header::CONTENT_TYPE;
use reqwest::Response;
pub use reqwest::StatusCode;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::error::Error as SerdeJsonError;
use serde_json::json;
use tokio::sync::{Mutex, RwLock};
use url::Url;
use uuid::Uuid;
use webauthn_rs_proto::{
    PublicKeyCredential, RegisterPublicKeyCredential, RequestChallengeResponse,
};

mod group;
mod oauth;
mod person;
mod scim;
mod service_account;
mod sync_account;
mod system;

const EXPECT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug)]
pub enum ClientError {
    Unauthorized,
    Http(reqwest::StatusCode, Option<OperationError>, String),
    Transport(reqwest::Error),
    AuthenticationFailed,
    EmptyResponse,
    TotpVerifyFailed(Uuid, TotpSecret),
    TotpInvalidSha1(Uuid),
    JsonDecode(reqwest::Error, String),
    InvalidResponseFormat(String),
    JsonEncode(SerdeJsonError),
    SystemError,
    ConfigParseIssue(String),
    CertParseIssue(String),
    UntrustedCertificate(String),
}

#[derive(Debug, Deserialize, Serialize)]
pub struct KanidmClientConfig {
    pub uri: Option<String>,
    pub verify_ca: Option<bool>,
    pub verify_hostnames: Option<bool>,
    pub ca_path: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct KanidmClientBuilder {
    address: Option<String>,
    verify_ca: bool,
    verify_hostnames: bool,
    ca: Option<reqwest::Certificate>,
    connect_timeout: Option<u64>,
    use_system_proxies: bool,
}

impl Display for KanidmClientBuilder {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match &self.address {
            Some(value) => writeln!(f, "address: {}", value)?,
            None => writeln!(f, "address: unset")?,
        }
        writeln!(f, "verify_ca: {}", self.verify_ca)?;
        writeln!(f, "verify_hostnames: {}", self.verify_hostnames)?;
        match &self.ca {
            Some(value) => writeln!(f, "ca: {:#?}", value)?,
            None => writeln!(f, "ca: unset")?,
        }
        match self.connect_timeout {
            Some(value) => writeln!(f, "connect_timeout: {}", value)?,
            None => writeln!(f, "connect_timeout: unset")?,
        }
        writeln!(f, "use_system_proxies: {}", self.use_system_proxies)
    }
}

#[test]
fn test_kanidmclientbuilder_display() {
    let foo = KanidmClientBuilder::default();
    println!("{}", foo);
    assert!(foo.to_string().contains("verify_ca"));

    let testclient = KanidmClientBuilder {
        address: Some("https://example.com".to_string()),
        verify_ca: true,
        verify_hostnames: true,
        ca: None,
        connect_timeout: Some(420),
        use_system_proxies: true,
    };
    println!("foo {}", testclient);
    assert!(testclient.to_string().contains("verify_ca: true"));
    assert!(testclient.to_string().contains("verify_hostnames: true"));

    let badness = testclient.danger_accept_invalid_hostnames(true);
    let badness = badness.danger_accept_invalid_certs(true);
    println!("badness: {}", badness);
    assert!(badness.to_string().contains("verify_ca: false"));
    assert!(badness.to_string().contains("verify_hostnames: false"));
}

#[derive(Debug)]
pub struct KanidmClient {
    pub(crate) client: reqwest::Client,
    pub(crate) addr: String,
    pub(crate) origin: Url,
    pub(crate) builder: KanidmClientBuilder,
    pub(crate) bearer_token: RwLock<Option<String>>,
    pub(crate) auth_session_id: RwLock<Option<String>>,
    pub(crate) check_version: Mutex<bool>,
}

#[cfg(target_family = "unix")]
fn read_file_metadata<P: AsRef<Path>>(path: &P) -> Result<Metadata, ()> {
    metadata(path).map_err(|e| {
        error!(
            "Unable to read metadata for {} - {:?}",
            path.as_ref().to_str().unwrap_or("Alert: invalid path"),
            e
        );
    })
}

impl KanidmClientBuilder {
    pub fn new() -> Self {
        KanidmClientBuilder {
            address: None,
            verify_ca: true,
            verify_hostnames: true,
            ca: None,
            connect_timeout: None,
            use_system_proxies: true,
        }
    }

    fn parse_certificate(ca_path: &str) -> Result<reqwest::Certificate, ClientError> {
        let mut buf = Vec::new();
        // Is the CA secure?
        #[cfg(target_family = "windows")]
        warn!("File metadata checks on Windows aren't supported right now, this could be a security risk.");

        #[cfg(target_family = "unix")]
        {
            let path = Path::new(ca_path);
            let ca_meta = read_file_metadata(&path).map_err(|e| {
                error!("{:?}", e);
                ClientError::ConfigParseIssue(format!("{:?}", e))
            })?;

            trace!("uid:gid {}:{}", ca_meta.uid(), ca_meta.gid());

            #[cfg(not(debug_assertions))]
            if ca_meta.uid() != 0 || ca_meta.gid() != 0 {
                warn!(
                    "{} should be owned be root:root to prevent tampering",
                    ca_path
                );
            }

            trace!("mode={:o}", ca_meta.mode());
            if (ca_meta.mode() & 0o7133) != 0 {
                warn!("permissions on {} are NOT secure. 0644 is a secure default. Should not be setuid, executable or allow group/other writes.", ca_path);
            }
        }

        let mut f = File::open(ca_path).map_err(|e| {
            error!("{:?}", e);
            ClientError::ConfigParseIssue(format!("{:?}", e))
        })?;
        f.read_to_end(&mut buf).map_err(|e| {
            error!("{:?}", e);
            ClientError::ConfigParseIssue(format!("{:?}", e))
        })?;
        reqwest::Certificate::from_pem(&buf).map_err(|e| {
            error!("{:?}", e);
            ClientError::CertParseIssue(format!("{:?}", e))
        })
    }

    fn apply_config_options(self, kcc: KanidmClientConfig) -> Result<Self, ClientError> {
        let KanidmClientBuilder {
            address,
            verify_ca,
            verify_hostnames,
            ca,
            connect_timeout,
            use_system_proxies,
        } = self;
        // Process and apply all our options if they exist.
        let address = match kcc.uri {
            Some(uri) => Some(uri),
            None => {
                debug!("No URI in config supplied to apply_config_options");
                address
            }
        };
        let verify_ca = kcc.verify_ca.unwrap_or(verify_ca);
        let verify_hostnames = kcc.verify_hostnames.unwrap_or(verify_hostnames);
        let ca = match kcc.ca_path {
            Some(ca_path) => Some(Self::parse_certificate(&ca_path)?),
            None => ca,
        };

        Ok(KanidmClientBuilder {
            address,
            verify_ca,
            verify_hostnames,
            ca,
            connect_timeout,
            use_system_proxies,
        })
    }

    #[allow(clippy::result_unit_err)]
    pub fn read_options_from_optional_config<P: AsRef<Path> + std::fmt::Debug>(
        self,
        config_path: P,
    ) -> Result<Self, ClientError> {
        debug!("Attempting to load configuration from {:#?}", &config_path);

        // We have to check the .exists case manually, because there are some weird overlayfs
        // issues in docker where when the file does NOT exist, but we "open it" we get an
        // error describing that the file is actually a directory rather than a not exists
        // error. This check enforces that we get the CORRECT error message instead.
        if !config_path.as_ref().exists() {
            debug!("{:?} does not exist", config_path);
            let diag = kanidm_lib_file_permissions::diagnose_path(config_path.as_ref());
            info!(%diag);
            return Ok(self);
        };

        // If the file does not exist, we skip this function.
        let mut f = match File::open(&config_path) {
            Ok(f) => {
                debug!("Successfully opened configuration file {:#?}", &config_path);
                f
            }
            Err(e) => {
                match e.kind() {
                    ErrorKind::NotFound => {
                        debug!(
                            "Configuration file {:#?} not found, skipping.",
                            &config_path
                        );
                    }
                    ErrorKind::PermissionDenied => {
                        warn!(
                            "Permission denied loading configuration file {:#?}, skipping.",
                            &config_path
                        );
                    }
                    _ => {
                        debug!(
                            "Unable to open config file {:#?} [{:?}], skipping ...",
                            &config_path, e
                        );
                    }
                };
                let diag = kanidm_lib_file_permissions::diagnose_path(config_path.as_ref());
                info!(%diag);

                return Ok(self);
            }
        };

        let mut contents = String::new();
        f.read_to_string(&mut contents).map_err(|e| {
            error!("{:?}", e);
            ClientError::ConfigParseIssue(format!("{:?}", e))
        })?;

        let config: KanidmClientConfig = toml::from_str(&contents).map_err(|e| {
            error!("{:?}", e);
            ClientError::ConfigParseIssue(format!("{:?}", e))
        })?;

        self.apply_config_options(config)
    }

    pub fn address(self, address: String) -> Self {
        KanidmClientBuilder {
            address: Some(address),
            verify_ca: self.verify_ca,
            verify_hostnames: self.verify_hostnames,
            ca: self.ca,
            connect_timeout: self.connect_timeout,
            use_system_proxies: self.use_system_proxies,
        }
    }

    pub fn danger_accept_invalid_hostnames(self, accept_invalid_hostnames: bool) -> Self {
        KanidmClientBuilder {
            address: self.address,
            verify_ca: self.verify_ca,
            // We have to flip the bool state here due to english language.
            verify_hostnames: !accept_invalid_hostnames,
            ca: self.ca,
            connect_timeout: self.connect_timeout,
            use_system_proxies: self.use_system_proxies,
        }
    }

    pub fn danger_accept_invalid_certs(self, accept_invalid_certs: bool) -> Self {
        KanidmClientBuilder {
            address: self.address,
            // We have to flip the bool state here due to english language.
            verify_ca: !accept_invalid_certs,
            verify_hostnames: self.verify_hostnames,
            ca: self.ca,
            connect_timeout: self.connect_timeout,
            use_system_proxies: self.use_system_proxies,
        }
    }

    pub fn connect_timeout(self, secs: u64) -> Self {
        KanidmClientBuilder {
            address: self.address,
            verify_ca: self.verify_ca,
            verify_hostnames: self.verify_hostnames,
            ca: self.ca,
            connect_timeout: Some(secs),
            use_system_proxies: self.use_system_proxies,
        }
    }

    pub fn no_proxy(self) -> Self {
        KanidmClientBuilder {
            address: self.address,
            verify_ca: self.verify_ca,
            verify_hostnames: self.verify_hostnames,
            ca: self.ca,
            connect_timeout: self.connect_timeout,
            use_system_proxies: false,
        }
    }

    #[allow(clippy::result_unit_err)]
    pub fn add_root_certificate_filepath(self, ca_path: &str) -> Result<Self, ClientError> {
        //Okay we have a ca to add. Let's read it in and setup.
        let ca = Self::parse_certificate(ca_path).map_err(|e| {
            error!("{:?}", e);
            ClientError::CertParseIssue(format!("{:?}", e))
        })?;

        Ok(KanidmClientBuilder {
            address: self.address,
            verify_ca: self.verify_ca,
            verify_hostnames: self.verify_hostnames,
            ca: Some(ca),
            connect_timeout: self.connect_timeout,
            use_system_proxies: self.use_system_proxies,
        })
    }

    fn display_warnings(&self, address: &str) {
        // Check for problems now
        if !self.verify_ca {
            warn!("verify_ca set to false in client configuration - this may allow network interception of passwords!");
        }

        if !self.verify_hostnames {
            warn!(
                "verify_hostnames set to false in client configuration - this may allow network interception of passwords!"
            );
        }

        if !address.starts_with("https://") {
            warn!("Address does not start with 'https://' - this may allow network interception of passwords!");
        }
    }

    /// Generates a useragent header based on the package name and version
    pub fn user_agent() -> &'static str {
        static APP_USER_AGENT: &str =
            concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"),);
        APP_USER_AGENT
    }

    /*
    /// Consume self and return an async client.
    pub fn build(self) -> Result<KanidmClient, reqwest::Error> {
        self.build_async().map(|asclient| KanidmClient { asclient })
    }
    */

    /// Build the client ready for usage.
    pub fn build(self) -> Result<KanidmClient, ClientError> {
        // Errghh, how to handle this cleaner.
        let address = match &self.address {
            Some(a) => a.clone(),
            None => {
                error!("Configuration option 'uri' missing from client configuration, cannot continue client startup without specifying a server to connect to. 🤔");
                return Err(ClientError::ConfigParseIssue(
                    "Configuration option 'uri' missing from client configuration, cannot continue client startup without specifying a server to connect to. 🤔".to_string(),
                ));
            }
        };

        self.display_warnings(&address);

        let client_builder = reqwest::Client::builder()
            .user_agent(KanidmClientBuilder::user_agent())
            .danger_accept_invalid_hostnames(!self.verify_hostnames)
            .danger_accept_invalid_certs(!self.verify_ca);

        let client_builder = match self.use_system_proxies {
            true => client_builder,
            false => client_builder.no_proxy(),
        };

        let client_builder = match &self.ca {
            Some(cert) => client_builder.add_root_certificate(cert.clone()),
            None => client_builder,
        };

        let client_builder = match &self.connect_timeout {
            Some(secs) => client_builder
                .connect_timeout(Duration::from_secs(*secs))
                .timeout(Duration::from_secs(*secs)),
            None => client_builder,
        };

        let client = client_builder.build().map_err(ClientError::Transport)?;

        // Now get the origin.
        #[allow(clippy::expect_used)]
        let uri = Url::parse(&address).expect("failed to parse address");

        #[allow(clippy::expect_used)]
        let origin =
            Url::parse(&uri.origin().ascii_serialization()).expect("failed to parse origin");

        Ok(KanidmClient {
            client,
            addr: address,
            builder: self,
            bearer_token: RwLock::new(None),
            origin,
            auth_session_id: RwLock::new(None),
            check_version: Mutex::new(true),
        })
    }
}

#[test]
fn test_make_url() {
    use kanidm_proto::constants::DEFAULT_SERVER_ADDRESS;
    let client: KanidmClient = KanidmClientBuilder::new()
        .address(format!("https://{}", DEFAULT_SERVER_ADDRESS))
        .build()
        .unwrap();
    assert_eq!(
        client.get_url(),
        Url::parse(&format!("https://{}", DEFAULT_SERVER_ADDRESS)).unwrap()
    );
    assert_eq!(
        client.make_url("/hello"),
        Url::parse(&format!("https://{}/hello", DEFAULT_SERVER_ADDRESS)).unwrap()
    );

    let client: KanidmClient = KanidmClientBuilder::new()
        .address(format!("https://{}/cheese/", DEFAULT_SERVER_ADDRESS))
        .build()
        .unwrap();
    assert_eq!(
        client.make_url("hello"),
        Url::parse(&format!("https://{}/cheese/hello", DEFAULT_SERVER_ADDRESS)).unwrap()
    );
}

/// This is probably pretty jank but it works and was pulled from here:
/// <https://github.com/seanmonstar/reqwest/issues/1602#issuecomment-1220996681>
fn find_reqwest_error_source<E: std::error::Error + 'static>(
    orig: &dyn std::error::Error,
) -> Option<&E> {
    let mut cause = orig.source();
    while let Some(err) = cause {
        if let Some(typed) = err.downcast_ref::<E>() {
            return Some(typed);
        }
        cause = err.source();
    }

    // else
    None
}

impl KanidmClient {
    pub fn get_origin(&self) -> &Url {
        &self.origin
    }

    /// Returns the base URL of the server
    pub fn get_url(&self) -> Url {
        #[allow(clippy::panic)]
        match self.addr.parse::<Url>() {
            Ok(val) => val,
            Err(err) => panic!("Failed to parse {} into URL: {:?}", self.addr, err),
        }
    }

    /// Get a URL based on adding an endpoint to the base URL of the server
    pub fn make_url(&self, endpoint: &str) -> Url {
        #[allow(clippy::expect_used)]
        self.get_url().join(endpoint).expect("Failed to join URL")
    }

    pub async fn set_token(&self, new_token: String) {
        let mut tguard = self.bearer_token.write().await;
        *tguard = Some(new_token);
    }

    pub async fn get_token(&self) -> Option<String> {
        let tguard = self.bearer_token.read().await;
        (*tguard).as_ref().cloned()
    }

    pub fn new_session(&self) -> Result<Self, ClientError> {
        // Copy our builder, and then just process it.
        let builder = self.builder.clone();
        builder.build()
    }

    pub async fn logout(&self) -> Result<(), ClientError> {
        self.perform_get_request("/v1/logout").await?;
        let mut tguard = self.bearer_token.write().await;
        *tguard = None;
        Ok(())
    }

    /// Check that we're getting the right version back from the server.
    async fn expect_version(&self, response: &reqwest::Response) {
        let mut guard = self.check_version.lock().await;

        if !*guard {
            return;
        }

        let ver = response
            .headers()
            .get(KVERSION)
            .and_then(|hv| hv.to_str().ok())
            .unwrap_or("");

        let matching = ver == EXPECT_VERSION;

        if !matching {
            warn!(server_version = ?ver, client_version = ?EXPECT_VERSION, "Mismatched client and server version - features may not work, or other unforeseen errors may occur.")
        }

        #[cfg(any(test, debug_assertions))]
        if !matching {
            error!("You're in debug/dev mode, so we're going to quit here.");
            std::process::exit(1);
        }

        // Check is done once, mark as no longer needing to occur
        *guard = false;
    }

    /// You've got the response from a reqwest and you want to turn it into a `ClientError`
    pub fn handle_response_error(&self, error: reqwest::Error) -> ClientError {
        if error.is_connect() {
            if find_reqwest_error_source::<std::io::Error>(&error).is_some() {
                // TODO: one day handle IO errors better
                trace!("Got an IO error! {:?}", &error);
                return ClientError::Transport(error);
            }
            if let Some(hyper_error) = find_reqwest_error_source::<hyper::Error>(&error) {
                // hyper errors can be *anything* depending on the underlying client libraries
                // ref: https://github.com/hyperium/hyper/blob/9feb70e9249d9fb99634ec96f83566e6bb3b3128/src/error.rs#L26C2-L26C2
                if format!("{:?}", hyper_error)
                    .to_lowercase()
                    .contains("certificate")
                {
                    return ClientError::UntrustedCertificate(format!("{}", hyper_error));
                }
            }
        }
        ClientError::Transport(error)
    }

    fn get_kopid_from_response(&self, response: &Response) -> String {
        let opid = response
            .headers()
            .get(KOPID)
            .and_then(|hv| hv.to_str().ok())
            .unwrap_or("missing_kopid")
            .to_string();

        debug!("opid -> {:?}", opid);
        opid
    }

    async fn perform_simple_post_request<R: Serialize, T: DeserializeOwned>(
        &self,
        dest: &str,
        request: &R,
    ) -> Result<T, ClientError> {
        let req_string = serde_json::to_string(request).map_err(ClientError::JsonEncode)?;

        let response = self
            .client
            .post(self.make_url(dest))
            .body(req_string)
            .header(CONTENT_TYPE, APPLICATION_JSON);

        let response = response
            .send()
            .await
            .map_err(|err| self.handle_response_error(err))?;

        self.expect_version(&response).await;

        let opid = self.get_kopid_from_response(&response);

        match response.status() {
            reqwest::StatusCode::OK => {}
            unexpect => {
                return Err(ClientError::Http(
                    unexpect,
                    response.json().await.ok(),
                    opid,
                ))
            }
        }

        response
            .json()
            .await
            .map_err(|e| ClientError::JsonDecode(e, opid))
    }

    async fn perform_auth_post_request<R: Serialize, T: DeserializeOwned>(
        &self,
        dest: &str,
        request: R,
    ) -> Result<T, ClientError> {
        trace!("perform_auth_post_request connecting to {}", dest);
        let req_string = serde_json::to_string(&request).map_err(ClientError::JsonEncode)?;

        let response = self
            .client
            .post(self.make_url(dest))
            .body(req_string)
            .header(CONTENT_TYPE, APPLICATION_JSON);

        // If we have a bearer token, set it now.
        let response = {
            let tguard = self.bearer_token.read().await;
            if let Some(token) = &(*tguard) {
                response.bearer_auth(token)
            } else {
                response
            }
        };

        // If we have a session header, set it now.
        let response = {
            let sguard = self.auth_session_id.read().await;
            if let Some(sessionid) = &(*sguard) {
                response.header(KSESSIONID, sessionid)
            } else {
                response
            }
        };

        let response = response
            .send()
            .await
            .map_err(|err| self.handle_response_error(err))?;

        self.expect_version(&response).await;

        // If we have a sessionid header in the response, get it now.

        let headers = response.headers();

        {
            let mut sguard = self.auth_session_id.write().await;
            *sguard = headers
                .get(KSESSIONID)
                .and_then(|hv| hv.to_str().ok().map(str::to_string));
        }

        let opid = self.get_kopid_from_response(&response);

        match response.status() {
            reqwest::StatusCode::OK => {}
            unexpect => {
                return Err(ClientError::Http(
                    unexpect,
                    response.json().await.ok(),
                    opid,
                ))
            }
        }

        response
            .json()
            .await
            .map_err(|e| ClientError::JsonDecode(e, opid))
    }

    pub async fn perform_post_request<R: Serialize, T: DeserializeOwned>(
        &self,
        dest: &str,
        request: R,
    ) -> Result<T, ClientError> {
        let req_string = serde_json::to_string(&request).map_err(ClientError::JsonEncode)?;
        let response = self
            .client
            .post(self.make_url(dest))
            .body(req_string)
            .header(CONTENT_TYPE, APPLICATION_JSON);

        let response = {
            let tguard = self.bearer_token.read().await;
            if let Some(token) = &(*tguard) {
                response.bearer_auth(token)
            } else {
                response
            }
        };

        let response = response
            .send()
            .await
            .map_err(|err| self.handle_response_error(err))?;

        self.expect_version(&response).await;

        let opid = self.get_kopid_from_response(&response);

        match response.status() {
            reqwest::StatusCode::OK => {}
            unexpect => {
                return Err(ClientError::Http(
                    unexpect,
                    response.json().await.ok(),
                    opid,
                ))
            }
        }

        response
            .json()
            .await
            .map_err(|e| ClientError::JsonDecode(e, opid))
    }

    async fn perform_put_request<R: Serialize, T: DeserializeOwned>(
        &self,
        dest: &str,
        request: R,
    ) -> Result<T, ClientError> {
        let req_string = serde_json::to_string(&request).map_err(ClientError::JsonEncode)?;

        let response = self
            .client
            .put(self.make_url(dest))
            .header(CONTENT_TYPE, APPLICATION_JSON);
        let response = {
            let tguard = self.bearer_token.read().await;
            if let Some(token) = &(*tguard) {
                response.bearer_auth(token)
            } else {
                response
            }
        };

        let response = response
            .body(req_string)
            .send()
            .await
            .map_err(|err| self.handle_response_error(err))?;

        self.expect_version(&response).await;

        let opid = self.get_kopid_from_response(&response);

        match response.status() {
            reqwest::StatusCode::OK => {}
            unexpect => {
                return Err(ClientError::Http(
                    unexpect,
                    response.json().await.ok(),
                    opid,
                ))
            }
        }

        response
            .json()
            .await
            .map_err(|e| ClientError::JsonDecode(e, opid))
    }

    async fn perform_patch_request<R: Serialize, T: DeserializeOwned>(
        &self,
        dest: &str,
        request: R,
    ) -> Result<T, ClientError> {
        let req_string = serde_json::to_string(&request).map_err(ClientError::JsonEncode)?;
        let response = self
            .client
            .patch(self.make_url(dest))
            .body(req_string)
            .header(CONTENT_TYPE, APPLICATION_JSON);

        let response = {
            let tguard = self.bearer_token.read().await;
            if let Some(token) = &(*tguard) {
                response.bearer_auth(token)
            } else {
                response
            }
        };

        let response = response
            .send()
            .await
            .map_err(|err| self.handle_response_error(err))?;

        self.expect_version(&response).await;

        let opid = self.get_kopid_from_response(&response);

        match response.status() {
            reqwest::StatusCode::OK => {}
            unexpect => {
                return Err(ClientError::Http(
                    unexpect,
                    response.json().await.ok(),
                    opid,
                ))
            }
        }

        response
            .json()
            .await
            .map_err(|e| ClientError::JsonDecode(e, opid))
    }

    #[instrument(level = "debug", skip(self))]
    pub async fn perform_get_request<T: DeserializeOwned>(
        &self,
        dest: &str,
    ) -> Result<T, ClientError> {
        let response = self.client.get(self.make_url(dest));
        let response = {
            let tguard = self.bearer_token.read().await;
            if let Some(token) = &(*tguard) {
                response.bearer_auth(token)
            } else {
                response
            }
        };

        let response = response
            .send()
            .await
            .map_err(|err| self.handle_response_error(err))?;

        self.expect_version(&response).await;

        let opid = self.get_kopid_from_response(&response);

        match response.status() {
            reqwest::StatusCode::OK => {}
            unexpect => {
                return Err(ClientError::Http(
                    unexpect,
                    response.json().await.ok(),
                    opid,
                ))
            }
        }

        response
            .json()
            .await
            .map_err(|e| ClientError::JsonDecode(e, opid))
    }

    async fn perform_delete_request(&self, dest: &str) -> Result<(), ClientError> {
        let response = self
            .client
            .delete(self.make_url(dest))
            // empty-ish body that makes the parser happy
            .json(&json!([]));

        let response = {
            let tguard = self.bearer_token.read().await;
            if let Some(token) = &(*tguard) {
                response.bearer_auth(token)
            } else {
                response
            }
        };

        let response = response
            .send()
            .await
            .map_err(|err| self.handle_response_error(err))?;

        self.expect_version(&response).await;

        let opid = self.get_kopid_from_response(&response);

        match response.status() {
            reqwest::StatusCode::OK => {}
            unexpect => {
                return Err(ClientError::Http(
                    unexpect,
                    response.json().await.ok(),
                    opid,
                ))
            }
        }

        response
            .json()
            .await
            .map_err(|e| ClientError::JsonDecode(e, opid))
    }

    async fn perform_delete_request_with_body<R: Serialize>(
        &self,
        dest: &str,
        request: R,
    ) -> Result<(), ClientError> {
        let response = self.client.delete(self.make_url(dest)).json(&request);

        let response = {
            let tguard = self.bearer_token.read().await;
            if let Some(token) = &(*tguard) {
                response.bearer_auth(token)
            } else {
                response
            }
        };

        let response = response
            .send()
            .await
            .map_err(|err| self.handle_response_error(err))?;

        self.expect_version(&response).await;

        let opid = self.get_kopid_from_response(&response);

        match response.status() {
            reqwest::StatusCode::OK => {}
            unexpect => {
                return Err(ClientError::Http(
                    unexpect,
                    response.json().await.ok(),
                    opid,
                ))
            }
        }

        response
            .json()
            .await
            .map_err(|e| ClientError::JsonDecode(e, opid))
    }

    #[instrument(level = "debug", skip(self))]
    pub async fn auth_step_init(&self, ident: &str) -> Result<Set<AuthMech>, ClientError> {
        let auth_init = AuthRequest {
            step: AuthStep::Init2 {
                username: ident.to_string(),
                issue: AuthIssueSession::Token,
                privileged: false,
            },
        };

        let r: Result<AuthResponse, _> =
            self.perform_auth_post_request("/v1/auth", auth_init).await;
        r.map(|v| {
            debug!("Authentication Session ID -> {:?}", v.sessionid);
            // Stash the session ID header.
            v.state
        })
        .and_then(|state| match state {
            AuthState::Choose(mechs) => Ok(mechs),
            _ => Err(ClientError::AuthenticationFailed),
        })
        .map(|mechs| mechs.into_iter().collect())
    }

    #[instrument(level = "debug", skip(self))]
    pub async fn auth_step_begin(&self, mech: AuthMech) -> Result<Vec<AuthAllowed>, ClientError> {
        let auth_begin = AuthRequest {
            step: AuthStep::Begin(mech),
        };

        let r: Result<AuthResponse, _> =
            self.perform_auth_post_request("/v1/auth", auth_begin).await;
        r.map(|v| {
            debug!("Authentication Session ID -> {:?}", v.sessionid);
            v.state
        })
        .and_then(|state| match state {
            AuthState::Continue(allowed) => Ok(allowed),
            _ => Err(ClientError::AuthenticationFailed),
        })
        // For converting to a Set
        // .map(|allowed| allowed.into_iter().collect())
    }

    #[instrument(level = "debug", skip_all)]
    pub async fn auth_step_anonymous(&self) -> Result<AuthResponse, ClientError> {
        let auth_anon = AuthRequest {
            step: AuthStep::Cred(AuthCredential::Anonymous),
        };
        let r: Result<AuthResponse, _> =
            self.perform_auth_post_request("/v1/auth", auth_anon).await;

        if let Ok(ar) = &r {
            if let AuthState::Success(token) = &ar.state {
                self.set_token(token.clone()).await;
            };
        };
        r
    }

    #[instrument(level = "debug", skip_all)]
    pub async fn auth_step_password(&self, password: &str) -> Result<AuthResponse, ClientError> {
        let auth_req = AuthRequest {
            step: AuthStep::Cred(AuthCredential::Password(password.to_string())),
        };
        let r: Result<AuthResponse, _> = self.perform_auth_post_request("/v1/auth", auth_req).await;

        if let Ok(ar) = &r {
            if let AuthState::Success(token) = &ar.state {
                self.set_token(token.clone()).await;
            };
        };
        r
    }

    #[instrument(level = "debug", skip_all)]
    pub async fn auth_step_backup_code(
        &self,
        backup_code: &str,
    ) -> Result<AuthResponse, ClientError> {
        let auth_req = AuthRequest {
            step: AuthStep::Cred(AuthCredential::BackupCode(backup_code.to_string())),
        };
        let r: Result<AuthResponse, _> = self.perform_auth_post_request("/v1/auth", auth_req).await;

        if let Ok(ar) = &r {
            if let AuthState::Success(token) = &ar.state {
                self.set_token(token.clone()).await;
            };
        };
        r
    }

    #[instrument(level = "debug", skip_all)]
    pub async fn auth_step_totp(&self, totp: u32) -> Result<AuthResponse, ClientError> {
        let auth_req = AuthRequest {
            step: AuthStep::Cred(AuthCredential::Totp(totp)),
        };
        let r: Result<AuthResponse, _> = self.perform_auth_post_request("/v1/auth", auth_req).await;

        if let Ok(ar) = &r {
            if let AuthState::Success(token) = &ar.state {
                self.set_token(token.clone()).await;
            };
        };
        r
    }

    #[instrument(level = "debug", skip_all)]
    pub async fn auth_step_securitykey_complete(
        &self,
        pkc: Box<PublicKeyCredential>,
    ) -> Result<AuthResponse, ClientError> {
        let auth_req = AuthRequest {
            step: AuthStep::Cred(AuthCredential::SecurityKey(pkc)),
        };
        let r: Result<AuthResponse, _> = self.perform_auth_post_request("/v1/auth", auth_req).await;

        if let Ok(ar) = &r {
            if let AuthState::Success(token) = &ar.state {
                self.set_token(token.clone()).await;
            };
        };
        r
    }

    #[instrument(level = "debug", skip_all)]
    pub async fn auth_step_passkey_complete(
        &self,
        pkc: Box<PublicKeyCredential>,
    ) -> Result<AuthResponse, ClientError> {
        let auth_req = AuthRequest {
            step: AuthStep::Cred(AuthCredential::Passkey(pkc)),
        };
        let r: Result<AuthResponse, _> = self.perform_auth_post_request("/v1/auth", auth_req).await;

        if let Ok(ar) = &r {
            if let AuthState::Success(token) = &ar.state {
                self.set_token(token.clone()).await;
            };
        };
        r
    }

    #[instrument(level = "debug", skip(self))]
    pub async fn auth_anonymous(&self) -> Result<(), ClientError> {
        let mechs = match self.auth_step_init("anonymous").await {
            Ok(s) => s,
            Err(e) => return Err(e),
        };

        if !mechs.contains(&AuthMech::Anonymous) {
            debug!("Anonymous mech not presented");
            return Err(ClientError::AuthenticationFailed);
        }

        let _state = match self.auth_step_begin(AuthMech::Anonymous).await {
            Ok(s) => s,
            Err(e) => return Err(e),
        };

        let r = self.auth_step_anonymous().await?;

        match r.state {
            AuthState::Success(token) => {
                self.set_token(token.clone()).await;
                Ok(())
            }
            _ => Err(ClientError::AuthenticationFailed),
        }
    }

    #[instrument(level = "debug", skip(self, password))]
    pub async fn auth_simple_password(
        &self,
        ident: &str,
        password: &str,
    ) -> Result<(), ClientError> {
        trace!("Init auth step");
        let mechs = match self.auth_step_init(ident).await {
            Ok(s) => s,
            Err(e) => return Err(e),
        };

        if !mechs.contains(&AuthMech::Password) {
            debug!("Password mech not presented");
            return Err(ClientError::AuthenticationFailed);
        }

        let _state = match self.auth_step_begin(AuthMech::Password).await {
            Ok(s) => s,
            Err(e) => return Err(e),
        };

        let r = self.auth_step_password(password).await?;

        match r.state {
            AuthState::Success(_) => Ok(()),
            _ => Err(ClientError::AuthenticationFailed),
        }
    }

    #[instrument(level = "debug", skip(self, password, totp))]
    pub async fn auth_password_totp(
        &self,
        ident: &str,
        password: &str,
        totp: u32,
    ) -> Result<(), ClientError> {
        let mechs = match self.auth_step_init(ident).await {
            Ok(s) => s,
            Err(e) => return Err(e),
        };

        if !mechs.contains(&AuthMech::PasswordMfa) {
            debug!("PasswordMfa mech not presented");
            return Err(ClientError::AuthenticationFailed);
        }

        let state = match self.auth_step_begin(AuthMech::PasswordMfa).await {
            Ok(s) => s,
            Err(e) => return Err(e),
        };

        if !state.contains(&AuthAllowed::Totp) {
            debug!("TOTP step not offered.");
            return Err(ClientError::AuthenticationFailed);
        }

        let r = self.auth_step_totp(totp).await?;

        // Should need to continue.
        match r.state {
            AuthState::Continue(allowed) => {
                if !allowed.contains(&AuthAllowed::Password) {
                    debug!("Password step not offered.");
                    return Err(ClientError::AuthenticationFailed);
                }
            }
            _ => {
                debug!("Invalid AuthState presented.");
                return Err(ClientError::AuthenticationFailed);
            }
        };

        let r = self.auth_step_password(password).await?;

        match r.state {
            AuthState::Success(_token) => Ok(()),
            _ => Err(ClientError::AuthenticationFailed),
        }
    }

    #[instrument(level = "debug", skip(self, password, backup_code))]
    pub async fn auth_password_backup_code(
        &self,
        ident: &str,
        password: &str,
        backup_code: &str,
    ) -> Result<(), ClientError> {
        let mechs = match self.auth_step_init(ident).await {
            Ok(s) => s,
            Err(e) => return Err(e),
        };

        if !mechs.contains(&AuthMech::PasswordMfa) {
            debug!("PasswordMfa mech not presented");
            return Err(ClientError::AuthenticationFailed);
        }

        let state = match self.auth_step_begin(AuthMech::PasswordMfa).await {
            Ok(s) => s,
            Err(e) => return Err(e),
        };

        if !state.contains(&AuthAllowed::BackupCode) {
            debug!("Backup Code step not offered.");
            return Err(ClientError::AuthenticationFailed);
        }

        let r = self.auth_step_backup_code(backup_code).await?;

        // Should need to continue.
        match r.state {
            AuthState::Continue(allowed) => {
                if !allowed.contains(&AuthAllowed::Password) {
                    debug!("Password step not offered.");
                    return Err(ClientError::AuthenticationFailed);
                }
            }
            _ => {
                debug!("Invalid AuthState presented.");
                return Err(ClientError::AuthenticationFailed);
            }
        };

        let r = self.auth_step_password(password).await?;

        match r.state {
            AuthState::Success(_token) => Ok(()),
            _ => Err(ClientError::AuthenticationFailed),
        }
    }

    #[instrument(level = "debug", skip(self))]
    pub async fn auth_passkey_begin(
        &self,
        ident: &str,
    ) -> Result<RequestChallengeResponse, ClientError> {
        let mechs = match self.auth_step_init(ident).await {
            Ok(s) => s,
            Err(e) => return Err(e),
        };

        if !mechs.contains(&AuthMech::Passkey) {
            debug!("Webauthn mech not presented");
            return Err(ClientError::AuthenticationFailed);
        }

        let state = match self.auth_step_begin(AuthMech::Passkey).await {
            Ok(mut s) => s.pop(),
            Err(e) => return Err(e),
        };

        // State is now a set of auth continues.
        match state {
            Some(AuthAllowed::Passkey(r)) => Ok(r),
            _ => Err(ClientError::AuthenticationFailed),
        }
    }

    #[instrument(level = "debug", skip_all)]
    pub async fn auth_passkey_complete(
        &self,
        pkc: Box<PublicKeyCredential>,
    ) -> Result<(), ClientError> {
        let r = self.auth_step_passkey_complete(pkc).await?;
        match r.state {
            AuthState::Success(_token) => Ok(()),
            _ => Err(ClientError::AuthenticationFailed),
        }
    }

    pub async fn reauth_begin(&self) -> Result<Vec<AuthAllowed>, ClientError> {
        let issue = AuthIssueSession::Token;
        let r: Result<AuthResponse, _> = self.perform_auth_post_request("/v1/reauth", issue).await;

        r.map(|v| {
            debug!("Authentication Session ID -> {:?}", v.sessionid);
            v.state
        })
        .and_then(|state| match state {
            AuthState::Continue(allowed) => Ok(allowed),
            _ => Err(ClientError::AuthenticationFailed),
        })
    }

    #[instrument(level = "debug", skip_all)]
    pub async fn reauth_simple_password(&self, password: &str) -> Result<(), ClientError> {
        let state = match self.reauth_begin().await {
            Ok(mut s) => s.pop(),
            Err(e) => return Err(e),
        };

        match state {
            Some(AuthAllowed::Password) => {}
            _ => {
                return Err(ClientError::AuthenticationFailed);
            }
        };

        let r = self.auth_step_password(password).await?;

        match r.state {
            AuthState::Success(_) => Ok(()),
            _ => Err(ClientError::AuthenticationFailed),
        }
    }

    #[instrument(level = "debug", skip_all)]
    pub async fn reauth_password_totp(&self, password: &str, totp: u32) -> Result<(), ClientError> {
        let state = match self.reauth_begin().await {
            Ok(s) => s,
            Err(e) => return Err(e),
        };

        if !state.contains(&AuthAllowed::Totp) {
            debug!("TOTP step not offered.");
            return Err(ClientError::AuthenticationFailed);
        }

        let r = self.auth_step_totp(totp).await?;

        // Should need to continue.
        match r.state {
            AuthState::Continue(allowed) => {
                if !allowed.contains(&AuthAllowed::Password) {
                    debug!("Password step not offered.");
                    return Err(ClientError::AuthenticationFailed);
                }
            }
            _ => {
                debug!("Invalid AuthState presented.");
                return Err(ClientError::AuthenticationFailed);
            }
        };

        let r = self.auth_step_password(password).await?;

        match r.state {
            AuthState::Success(_token) => Ok(()),
            _ => Err(ClientError::AuthenticationFailed),
        }
    }

    #[instrument(level = "debug", skip_all)]
    pub async fn reauth_passkey_begin(&self) -> Result<RequestChallengeResponse, ClientError> {
        let state = match self.reauth_begin().await {
            Ok(mut s) => s.pop(),
            Err(e) => return Err(e),
        };

        // State is now a set of auth continues.
        match state {
            Some(AuthAllowed::Passkey(r)) => Ok(r),
            _ => Err(ClientError::AuthenticationFailed),
        }
    }

    #[instrument(level = "debug", skip_all)]
    pub async fn reauth_passkey_complete(
        &self,
        pkc: Box<PublicKeyCredential>,
    ) -> Result<(), ClientError> {
        let r = self.auth_step_passkey_complete(pkc).await?;
        match r.state {
            AuthState::Success(_token) => Ok(()),
            _ => Err(ClientError::AuthenticationFailed),
        }
    }

    pub async fn auth_valid(&self) -> Result<(), ClientError> {
        self.perform_get_request("/v1/auth/valid").await
    }

    pub async fn whoami(&self) -> Result<Option<Entry>, ClientError> {
        let response = self.client.get(self.make_url("/v1/self"));

        let response = {
            let tguard = self.bearer_token.read().await;
            if let Some(token) = &(*tguard) {
                response.bearer_auth(token)
            } else {
                response
            }
        };

        let response = response
            .send()
            .await
            .map_err(|err| self.handle_response_error(err))?;

        self.expect_version(&response).await;

        let opid = self.get_kopid_from_response(&response);
        match response.status() {
            // Continue to process.
            reqwest::StatusCode::OK => {}
            reqwest::StatusCode::UNAUTHORIZED => return Ok(None),
            unexpect => {
                return Err(ClientError::Http(
                    unexpect,
                    response.json().await.ok(),
                    opid,
                ))
            }
        }

        let r: WhoamiResponse = response
            .json()
            .await
            .map_err(|e| ClientError::JsonDecode(e, opid))?;

        Ok(Some(r.youare))
    }

    // Raw DB actions
    pub async fn search(&self, filter: Filter) -> Result<Vec<Entry>, ClientError> {
        let sr = SearchRequest { filter };
        let r: Result<SearchResponse, _> = self.perform_post_request("/v1/raw/search", sr).await;
        r.map(|v| v.entries)
    }

    pub async fn create(&self, entries: Vec<Entry>) -> Result<(), ClientError> {
        let c = CreateRequest { entries };
        self.perform_post_request("/v1/raw/create", c).await
    }

    pub async fn modify(&self, filter: Filter, modlist: ModifyList) -> Result<(), ClientError> {
        let mr = ModifyRequest { filter, modlist };
        self.perform_post_request("/v1/raw/modify", mr).await
    }

    pub async fn delete(&self, filter: Filter) -> Result<(), ClientError> {
        let dr = DeleteRequest { filter };
        self.perform_post_request("/v1/raw/delete", dr).await
    }

    // === idm actions here ==

    // ===== GROUPS
    pub async fn idm_group_list(&self) -> Result<Vec<Entry>, ClientError> {
        self.perform_get_request("/v1/group").await
    }

    pub async fn idm_group_get(&self, id: &str) -> Result<Option<Entry>, ClientError> {
        self.perform_get_request(&format!("/v1/group/{}", id)).await
    }

    pub async fn idm_group_get_members(
        &self,
        id: &str,
    ) -> Result<Option<Vec<String>>, ClientError> {
        self.perform_get_request(&format!("/v1/group/{}/_attr/member", id))
            .await
    }

    pub async fn idm_group_create(&self, name: &str) -> Result<(), ClientError> {
        let mut new_group = Entry {
            attrs: BTreeMap::new(),
        };
        new_group
            .attrs
            .insert(ATTR_NAME.to_string(), vec![name.to_string()]);
        self.perform_post_request("/v1/group", new_group).await
    }

    pub async fn idm_group_set_members(
        &self,
        id: &str,
        members: &[&str],
    ) -> Result<(), ClientError> {
        let m: Vec<_> = members.iter().map(|v| (*v).to_string()).collect();
        self.perform_put_request(&format!("/v1/group/{}/_attr/member", id), m)
            .await
    }

    pub async fn idm_group_add_members(
        &self,
        id: &str,
        members: &[&str],
    ) -> Result<(), ClientError> {
        let m: Vec<_> = members.iter().map(|v| (*v).to_string()).collect();
        self.perform_post_request(&format!("/v1/group/{}/_attr/member", id), m)
            .await
    }

    pub async fn idm_group_remove_members(
        &self,
        group: &str,
        members: &[&str],
    ) -> Result<(), ClientError> {
        debug!(
            "Asked to remove members {} from {}",
            &members.join(","),
            group
        );
        self.perform_delete_request_with_body(
            &format!("/v1/group/{}/_attr/member", group),
            &members,
        )
        .await
    }

    pub async fn idm_group_purge_members(&self, id: &str) -> Result<(), ClientError> {
        self.perform_delete_request(&format!("/v1/group/{}/_attr/member", id))
            .await
    }

    pub async fn idm_group_unix_extend(
        &self,
        id: &str,
        gidnumber: Option<u32>,
    ) -> Result<(), ClientError> {
        let gx = GroupUnixExtend { gidnumber };
        self.perform_post_request(&format!("/v1/group/{}/_unix", id), gx)
            .await
    }

    pub async fn idm_group_unix_token_get(&self, id: &str) -> Result<UnixGroupToken, ClientError> {
        self.perform_get_request(&format!("/v1/group/{}/_unix/_token", id))
            .await
    }

    pub async fn idm_group_delete(&self, id: &str) -> Result<(), ClientError> {
        self.perform_delete_request(&format!("/v1/group/{}", id))
            .await
    }

    // ==== ACCOUNTS

    pub async fn idm_account_unix_token_get(&self, id: &str) -> Result<UnixUserToken, ClientError> {
        self.perform_get_request(&format!("/v1/account/{}/_unix/_token", id))
            .await
    }

    // == new credential update session code.
    #[instrument(level = "debug", skip(self))]
    pub async fn idm_person_account_credential_update_intent(
        &self,
        id: &str,
        ttl: Option<u32>,
    ) -> Result<CUIntentToken, ClientError> {
        if let Some(ttl) = ttl {
            self.perform_get_request(&format!(
                "/v1/person/{}/_credential/_update_intent?ttl={}",
                id, ttl
            ))
            .await
        } else {
            self.perform_get_request(&format!("/v1/person/{}/_credential/_update_intent", id))
                .await
        }
    }

    pub async fn idm_account_credential_update_begin(
        &self,
        id: &str,
    ) -> Result<(CUSessionToken, CUStatus), ClientError> {
        self.perform_get_request(&format!("/v1/person/{}/_credential/_update", id))
            .await
    }

    pub async fn idm_account_credential_update_exchange(
        &self,
        intent_token: CUIntentToken,
    ) -> Result<(CUSessionToken, CUStatus), ClientError> {
        // We don't need to send the UAT with these, which is why we use the different path.
        self.perform_simple_post_request("/v1/credential/_exchange_intent", &intent_token)
            .await
    }

    pub async fn idm_account_credential_update_status(
        &self,
        session_token: &CUSessionToken,
    ) -> Result<CUStatus, ClientError> {
        self.perform_simple_post_request("/v1/credential/_status", &session_token)
            .await
    }

    pub async fn idm_account_credential_update_set_password(
        &self,
        session_token: &CUSessionToken,
        pw: &str,
    ) -> Result<CUStatus, ClientError> {
        let scr = CURequest::Password(pw.to_string());
        self.perform_simple_post_request("/v1/credential/_update", &(scr, &session_token))
            .await
    }

    pub async fn idm_account_credential_update_cancel_mfareg(
        &self,
        session_token: &CUSessionToken,
    ) -> Result<CUStatus, ClientError> {
        let scr = CURequest::CancelMFAReg;
        self.perform_simple_post_request("/v1/credential/_update", &(scr, &session_token))
            .await
    }

    pub async fn idm_account_credential_update_init_totp(
        &self,
        session_token: &CUSessionToken,
    ) -> Result<CUStatus, ClientError> {
        let scr = CURequest::TotpGenerate;
        self.perform_simple_post_request("/v1/credential/_update", &(scr, &session_token))
            .await
    }

    pub async fn idm_account_credential_update_check_totp(
        &self,
        session_token: &CUSessionToken,
        totp_chal: u32,
        label: &str,
    ) -> Result<CUStatus, ClientError> {
        let scr = CURequest::TotpVerify(totp_chal, label.to_string());
        self.perform_simple_post_request("/v1/credential/_update", &(scr, &session_token))
            .await
    }

    // TODO: add test coverage
    pub async fn idm_account_credential_update_accept_sha1_totp(
        &self,
        session_token: &CUSessionToken,
    ) -> Result<CUStatus, ClientError> {
        let scr = CURequest::TotpAcceptSha1;
        self.perform_simple_post_request("/v1/credential/_update", &(scr, &session_token))
            .await
    }

    pub async fn idm_account_credential_update_remove_totp(
        &self,
        session_token: &CUSessionToken,
        label: &str,
    ) -> Result<CUStatus, ClientError> {
        let scr = CURequest::TotpRemove(label.to_string());
        self.perform_simple_post_request("/v1/credential/_update", &(scr, &session_token))
            .await
    }

    // TODO: add test coverage
    pub async fn idm_account_credential_update_backup_codes_generate(
        &self,
        session_token: &CUSessionToken,
    ) -> Result<CUStatus, ClientError> {
        let scr = CURequest::BackupCodeGenerate;
        self.perform_simple_post_request("/v1/credential/_update", &(scr, &session_token))
            .await
    }

    // TODO: add test coverage
    pub async fn idm_account_credential_update_primary_remove(
        &self,
        session_token: &CUSessionToken,
    ) -> Result<CUStatus, ClientError> {
        let scr = CURequest::PrimaryRemove;
        self.perform_simple_post_request("/v1/credential/_update", &(scr, &session_token))
            .await
    }

    pub async fn idm_account_credential_update_passkey_init(
        &self,
        session_token: &CUSessionToken,
    ) -> Result<CUStatus, ClientError> {
        let scr = CURequest::PasskeyInit;
        self.perform_simple_post_request("/v1/credential/_update", &(scr, &session_token))
            .await
    }

    pub async fn idm_account_credential_update_passkey_finish(
        &self,
        session_token: &CUSessionToken,
        label: String,
        registration: RegisterPublicKeyCredential,
    ) -> Result<CUStatus, ClientError> {
        let scr = CURequest::PasskeyFinish(label, registration);
        self.perform_simple_post_request("/v1/credential/_update", &(scr, &session_token))
            .await
    }

    // TODO: add test coverage
    pub async fn idm_account_credential_update_passkey_remove(
        &self,
        session_token: &CUSessionToken,
        uuid: Uuid,
    ) -> Result<CUStatus, ClientError> {
        let scr = CURequest::PasskeyRemove(uuid);
        self.perform_simple_post_request("/v1/credential/_update", &(scr, &session_token))
            .await
    }

    pub async fn idm_account_credential_update_commit(
        &self,
        session_token: &CUSessionToken,
    ) -> Result<(), ClientError> {
        self.perform_simple_post_request("/v1/credential/_commit", &session_token)
            .await
    }

    // == radius

    pub async fn idm_account_radius_token_get(
        &self,
        id: &str,
    ) -> Result<RadiusAuthToken, ClientError> {
        self.perform_get_request(&format!("/v1/account/{}/_radius/_token", id))
            .await
    }

    pub async fn idm_account_unix_cred_verify(
        &self,
        id: &str,
        cred: &str,
    ) -> Result<Option<UnixUserToken>, ClientError> {
        let req = SingleStringRequest {
            value: cred.to_string(),
        };
        self.perform_post_request(&format!("/v1/account/{}/_unix/_auth", id), req)
            .await
    }

    // == generic ssh key handlers
    pub async fn idm_account_get_ssh_pubkey(
        &self,
        id: &str,
        tag: &str,
    ) -> Result<Option<String>, ClientError> {
        self.perform_get_request(&format!("/v1/account/{}/_ssh_pubkeys/{}", id, tag))
            .await
    }

    pub async fn idm_account_get_ssh_pubkeys(&self, id: &str) -> Result<Vec<String>, ClientError> {
        self.perform_get_request(&format!("/v1/account/{}/_ssh_pubkeys", id))
            .await
    }

    // ==== domain_info (aka domain)
    pub async fn idm_domain_get(&self) -> Result<Entry, ClientError> {
        let r: Result<Vec<Entry>, ClientError> = self.perform_get_request("/v1/domain").await;
        r.and_then(|mut v| v.pop().ok_or(ClientError::EmptyResponse))
    }

    /// Sets the domain display name using a PUT request
    pub async fn idm_domain_set_display_name(
        &self,
        new_display_name: &str,
    ) -> Result<(), ClientError> {
        self.perform_put_request(
            "/v1/domain/_attr/domain_display_name",
            vec![new_display_name.to_string()],
        )
        .await
    }

    pub async fn idm_domain_set_ldap_basedn(&self, new_basedn: &str) -> Result<(), ClientError> {
        self.perform_put_request(
            "/v1/domain/_attr/domain_ldap_basedn",
            vec![new_basedn.to_string()],
        )
        .await
    }

    pub async fn idm_set_ldap_allow_unix_password_bind(
        &self,
        enable: bool,
    ) -> Result<(), ClientError> {
        self.perform_put_request("/v1/domain/_attr/ldap_allow_unix_pw_bind", vec![enable])
            .await
    }

    pub async fn idm_domain_get_ssid(&self) -> Result<String, ClientError> {
        self.perform_get_request("/v1/domain/_attr/domain_ssid")
            .await
            .and_then(|mut r: Vec<String>|
                // Get the first result
                r.pop()
                .ok_or(
                    ClientError::EmptyResponse
                ))
    }

    pub async fn idm_domain_set_ssid(&self, ssid: &str) -> Result<(), ClientError> {
        self.perform_put_request("/v1/domain/_attr/domain_ssid", vec![ssid.to_string()])
            .await
    }

    pub async fn idm_domain_reset_token_key(&self) -> Result<(), ClientError> {
        self.perform_delete_request("/v1/domain/_attr/es256_private_key_der")
            .await
    }

    // ==== schema
    pub async fn idm_schema_list(&self) -> Result<Vec<Entry>, ClientError> {
        self.perform_get_request("/v1/schema").await
    }

    pub async fn idm_schema_attributetype_list(&self) -> Result<Vec<Entry>, ClientError> {
        self.perform_get_request("/v1/schema/attributetype").await
    }

    pub async fn idm_schema_attributetype_get(
        &self,
        id: &str,
    ) -> Result<Option<Entry>, ClientError> {
        self.perform_get_request(&format!("/v1/schema/attributetype/{}", id))
            .await
    }

    pub async fn idm_schema_classtype_list(&self) -> Result<Vec<Entry>, ClientError> {
        self.perform_get_request("/v1/schema/classtype").await
    }

    pub async fn idm_schema_classtype_get(&self, id: &str) -> Result<Option<Entry>, ClientError> {
        self.perform_get_request(&format!("/v1/schema/classtype/{}", id))
            .await
    }

    // ==== recycle bin
    pub async fn recycle_bin_list(&self) -> Result<Vec<Entry>, ClientError> {
        self.perform_get_request("/v1/recycle_bin").await
    }

    pub async fn recycle_bin_get(&self, id: &str) -> Result<Option<Entry>, ClientError> {
        self.perform_get_request(&format!("/v1/recycle_bin/{}", id))
            .await
    }

    pub async fn recycle_bin_revive(&self, id: &str) -> Result<(), ClientError> {
        self.perform_post_request(&format!("/v1/recycle_bin/{}/_revive", id), ())
            .await
    }
}
