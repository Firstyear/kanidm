use crate::constants::PamResultCode;
use crate::module::PamResult;
use crate::pam::ModuleOptions;
use kanidm_unix_common::client_sync::DaemonClientBlocking;
use kanidm_unix_common::constants::{SYSTEM_PASSWD_PATH, SYSTEM_SHADOW_PATH};
use kanidm_unix_common::unix_config::PamNssConfig;
use kanidm_unix_common::unix_passwd::{
    read_etc_passwd_file, read_etc_shadow_file, EtcShadow, EtcUser,
};
use kanidm_unix_common::unix_proto::{ClientRequest, ClientResponse};
use kanidm_unix_common::unix_proto::{
    DeviceAuthorizationResponse, PamAuthRequest, PamAuthResponse, PamServiceInfo,
};
use std::cell::RefCell;
use std::time::Duration;
use time::OffsetDateTime;
use tracing::{debug, error};

#[cfg(test)]
use kanidm_unix_common::client_sync::UnixStream;

pub enum RequestOptions {
    Main {
        config_path: &'static str,
    },
    #[cfg(test)]
    Test {
        socket: Option<UnixStream>,
        users: Vec<EtcUser>,
        // groups: Vec<EtcGroup>,
        shadow: Vec<EtcShadow>,
    },
}

thread_local! {
    pub static CLIENT: RefCell<Option<DaemonClientBlocking>> = const { RefCell::new(None) };
}

enum Source {
    Daemon(DaemonClientBlocking),
    Fallback {
        users: Vec<EtcUser>,
        // groups: Vec<EtcGroup>,
        shadow: Vec<EtcShadow>,
    },
}

impl RequestOptions {
    fn connect_to_daemon(self) -> Source {
        let maybe_blocking_client = CLIENT.with_borrow(|tls_value| tls_value.clone());

        if let Some(client) = maybe_blocking_client {
            // We already initialised the client in this thread, return it.
            return Source::Daemon(client);
        }

        match self {
            RequestOptions::Main { config_path } => {
                let maybe_client = PamNssConfig::new()
                    .read_options_from_optional_config(config_path)
                    .ok()
                    .and_then(|cfg| {
                        DaemonClientBlocking::new(cfg.sock_path.as_str(), cfg.unix_sock_timeout)
                            .ok()
                    });

                if let Some(client) = maybe_client {
                    // Store a copy of the client in thread local storage.
                    let _ = CLIENT.replace(Some(client.clone()));
                    Source::Daemon(client)
                } else {
                    let users = read_etc_passwd_file(SYSTEM_PASSWD_PATH).unwrap_or_default();
                    // let groups = read_etc_group_file(SYSTEM_GROUP_PATH).unwrap_or_default();
                    let shadow = read_etc_shadow_file(SYSTEM_SHADOW_PATH).unwrap_or_default();
                    Source::Fallback {
                        users,
                        // groups,
                        shadow,
                    }
                }
            }
            #[cfg(test)]
            RequestOptions::Test {
                socket,
                users,
                // groups,
                shadow,
            } => {
                if let Some(socket) = socket {
                    let client = DaemonClientBlocking::from(socket);
                    let _ = CLIENT.replace(Some(client.clone()));
                    Source::Daemon(client)
                } else {
                    Source::Fallback { users, shadow }
                }
            }
        }
    }
}

pub trait PamHandler {
    fn account_id(&self) -> PamResult<String>;

    fn service_info(&self) -> PamResult<PamServiceInfo>;

    fn authtok(&self) -> PamResult<Option<String>>;

    /// Display a message to the user.
    fn message(&self, prompt: &str) -> PamResult<()>;

    /// Display a device grant request to the user.
    fn message_device_grant(&self, data: &DeviceAuthorizationResponse) -> PamResult<()>;

    /// Request a password from the user.
    fn prompt_for_password(&self) -> PamResult<Option<String>>;

    fn prompt_for_pin(&self, msg: Option<&str>) -> PamResult<Option<String>>;

    fn prompt_for_mfacode(&self) -> PamResult<Option<String>>;
}

pub fn sm_authenticate_connected<P: PamHandler>(
    pamh: &P,
    opts: &ModuleOptions,
    _current_time: OffsetDateTime,
    daemon_client: &DaemonClientBlocking,
) -> PamResultCode {
    let info = match pamh.service_info() {
        Ok(info) => info,
        Err(e) => {
            error!(err = ?e, "get_pam_info");
            return e;
        }
    };

    let account_id = match pamh.account_id() {
        Ok(acc) => acc,
        Err(err) => return err,
    };

    let mut timeout: Option<u64> = None;
    let mut active_polling_interval = Duration::from_secs(1);

    let mut stacked_authtok = if opts.use_first_pass {
        match pamh.authtok() {
            Ok(authtok) => authtok,
            Err(err) => return err,
        }
    } else {
        None
    };

    let mut req = ClientRequest::PamAuthenticateInit { account_id, info };

    loop {
        let client_response = match daemon_client.call_and_wait(req, timeout) {
            Ok(r) => r,
            Err(err) => {
                // Something unrecoverable occurred, bail and stop everything
                error!(?err, "PAM_AUTH_ERR");
                return PamResultCode::PAM_AUTH_ERR;
            }
        };

        match client_response {
            ClientResponse::PamAuthenticateStepResponse {
                response: PamAuthResponse::Success,
                session_id: _,
            } => {
                return PamResultCode::PAM_SUCCESS;
            }
            ClientResponse::PamAuthenticateStepResponse {
                response: PamAuthResponse::Denied,
                session_id: _,
            } => {
                return PamResultCode::PAM_AUTH_ERR;
            }
            ClientResponse::PamAuthenticateStepResponse {
                response: PamAuthResponse::Unknown,
                session_id: _,
            } => {
                if opts.ignore_unknown_user {
                    return PamResultCode::PAM_IGNORE;
                } else {
                    return PamResultCode::PAM_USER_UNKNOWN;
                }
            }
            ClientResponse::PamAuthenticateStepResponse {
                response: PamAuthResponse::Password,
                session_id,
            } => {
                let mut authtok = None;
                std::mem::swap(&mut authtok, &mut stacked_authtok);

                let cred = if let Some(cred) = authtok {
                    cred
                } else {
                    match pamh.prompt_for_password() {
                        Ok(Some(cred)) => cred,
                        Ok(None) => return PamResultCode::PAM_CRED_INSUFFICIENT,
                        Err(err) => return err,
                    }
                };

                // Now setup the request for the next loop.
                timeout = None;
                req = ClientRequest::PamAuthenticateStep {
                    request: PamAuthRequest::Password { cred },
                    session_id,
                };
                continue;
            }
            ClientResponse::PamAuthenticateStepResponse {
                response: PamAuthResponse::DeviceAuthorizationGrant { data },
                session_id,
            } => {
                if let Err(err) = pamh.message_device_grant(&data) {
                    return err;
                };

                timeout = Some(u64::from(data.expires_in));
                req = ClientRequest::PamAuthenticateStep {
                    request: PamAuthRequest::DeviceAuthorizationGrant { data },
                    session_id,
                };
                continue;
            }
            ClientResponse::PamAuthenticateStepResponse {
                response: PamAuthResponse::MFACode { msg: _ },
                session_id,
            } => {
                let cred = match pamh.prompt_for_mfacode() {
                    Ok(Some(cred)) => cred,
                    Ok(None) => return PamResultCode::PAM_CRED_INSUFFICIENT,
                    Err(err) => return err,
                };

                // Now setup the request for the next loop.
                timeout = None;
                req = ClientRequest::PamAuthenticateStep {
                    request: PamAuthRequest::MFACode { cred },
                    session_id,
                };
                continue;
            }
            ClientResponse::PamAuthenticateStepResponse {
                response:
                    PamAuthResponse::MFAPoll {
                        msg,
                        polling_interval,
                    },
                session_id,
            } => {
                if let Err(err) = pamh.message(msg.as_str()) {
                    if opts.debug {
                        println!("Message prompt failed");
                    }
                    return err;
                }

                active_polling_interval = Duration::from_secs(polling_interval.into());

                timeout = None;
                req = ClientRequest::PamAuthenticateStep {
                    request: PamAuthRequest::MFAPoll,
                    session_id,
                };
                // We don't need to actually sleep here as we immediately will poll and then go
                // into the MFAPollWait response below.
            }
            ClientResponse::PamAuthenticateStepResponse {
                response: PamAuthResponse::MFAPollWait,
                session_id,
            } => {
                // Counter intuitive, but we don't need a max poll attempts here because
                // if the resolver goes away, then this will error on the sock and
                // will shutdown. This allows the resolver to dynamically extend the
                // timeout if needed, and removes logic from the front end.
                std::thread::sleep(active_polling_interval);
                timeout = None;
                req = ClientRequest::PamAuthenticateStep {
                    request: PamAuthRequest::MFAPoll,
                    session_id,
                };
            }

            ClientResponse::PamAuthenticateStepResponse {
                response: PamAuthResponse::SetupPin { msg },
                session_id,
            } => {
                if let Err(err) = pamh.message(msg.as_str()) {
                    return err;
                }

                let mut pin;
                let mut confirm;

                loop {
                    pin = match pamh.prompt_for_pin(Some("New PIN: ")) {
                        Ok(Some(p)) => p,
                        Ok(None) => {
                            debug!("no pin");
                            return PamResultCode::PAM_CRED_INSUFFICIENT;
                        }
                        Err(err) => {
                            debug!("unable to get pin");
                            return err;
                        }
                    };

                    confirm = match pamh.prompt_for_pin(Some("Confirm PIN: ")) {
                        Ok(Some(p)) => p,
                        Ok(None) => {
                            debug!("no pin");
                            return PamResultCode::PAM_CRED_INSUFFICIENT;
                        }
                        Err(err) => {
                            debug!("unable to get pin");
                            return err;
                        }
                    };

                    if pin == confirm {
                        break;
                    } else if let Err(err) = pamh.message("Inputs did not match. Try again.") {
                        return err;
                    }
                }

                // Now setup the request for the next loop.
                timeout = None;
                req = ClientRequest::PamAuthenticateStep {
                    request: PamAuthRequest::SetupPin { pin },
                    session_id,
                };
                continue;
            }
            ClientResponse::PamAuthenticateStepResponse {
                response: PamAuthResponse::Pin,
                session_id,
            } => {
                let mut authtok = None;
                std::mem::swap(&mut authtok, &mut stacked_authtok);

                let cred = if let Some(cred) = authtok {
                    cred
                } else {
                    match pamh.prompt_for_pin(None) {
                        Ok(Some(cred)) => cred,
                        Ok(None) => return PamResultCode::PAM_CRED_INSUFFICIENT,
                        Err(err) => return err,
                    }
                };

                // Now setup the request for the next loop.
                timeout = None;
                req = ClientRequest::PamAuthenticateStep {
                    request: PamAuthRequest::Pin { cred },
                    session_id,
                };
                continue;
            }

            ClientResponse::Error(err) => {
                error!("Error from kanidm-unixd: {}", err);
                return PamResultCode::PAM_AUTH_ERR;
            }
            ClientResponse::Ok
            | ClientResponse::SshKeys(_)
            | ClientResponse::NssAccounts(_)
            | ClientResponse::NssAccount(_)
            | ClientResponse::NssGroups(_)
            | ClientResponse::PamStatus(_)
            | ClientResponse::ProviderStatus(_)
            | ClientResponse::NssGroup(_) => {
                debug!("PamResultCode::PAM_AUTH_ERR");
                return PamResultCode::PAM_AUTH_ERR;
            }
        }
    } // while true, continue calling PamAuthenticateStep until we get a decision.
}

pub fn sm_authenticate_fallback<P: PamHandler>(
    pamh: &P,
    opts: &ModuleOptions,
    current_time: OffsetDateTime,
    users: Vec<EtcUser>,
    shadow: Vec<EtcShadow>,
) -> PamResultCode {
    let account_id = match pamh.account_id() {
        Ok(acc) => acc,
        Err(err) => return err,
    };

    let user = users.into_iter().find(|etcuser| etcuser.name == account_id);

    let shadow = shadow
        .into_iter()
        .find(|etcshadow| etcshadow.name == account_id);

    let (_user, shadow) = match (user, shadow) {
        (Some(user), Some(shadow)) => (user, shadow),
        _ => {
            if opts.ignore_unknown_user {
                debug!("PamResultCode::PAM_IGNORE");
                return PamResultCode::PAM_IGNORE;
            } else {
                debug!("PamResultCode::PAM_USER_UNKNOWN");
                return PamResultCode::PAM_USER_UNKNOWN;
            }
        }
    };

    let expiration_date = shadow.epoch_expire_seconds;

    if let Some(expire) = expiration_date {
        if current_time >= expire {
            debug!("PamResultCode::PAM_ACCT_EXPIRED");
            return PamResultCode::PAM_ACCT_EXPIRED;
        }
    };

    // All checks passed! We can now proceed to authenticate the account.
    let mut stacked_authtok = if opts.use_first_pass {
        match pamh.authtok() {
            Ok(authtok) => authtok,
            Err(err) => return err,
        }
    } else {
        None
    };

    let mut authtok = None;
    std::mem::swap(&mut authtok, &mut stacked_authtok);

    let cred = if let Some(cred) = authtok {
        cred
    } else {
        match pamh.prompt_for_password() {
            Ok(Some(cred)) => cred,
            Ok(None) => return PamResultCode::PAM_CRED_INSUFFICIENT,
            Err(err) => return err,
        }
    };

    if shadow.password.check_pw(cred.as_str()) {
        PamResultCode::PAM_SUCCESS
    } else {
        PamResultCode::PAM_AUTH_ERR
    }
}

pub fn sm_authenticate<P: PamHandler>(
    pamh: &P,
    opts: &ModuleOptions,
    req_opt: RequestOptions,
    current_time: OffsetDateTime,
) -> PamResultCode {
    match req_opt.connect_to_daemon() {
        Source::Daemon(daemon_client) => {
            sm_authenticate_connected(pamh, opts, current_time, &daemon_client)
        }
        Source::Fallback { users, shadow } => {
            sm_authenticate_fallback(pamh, opts, current_time, users, shadow)
        }
    }
}

pub fn acct_mgmt<P: PamHandler>(
    pamh: &P,
    opts: &ModuleOptions,
    req_opt: RequestOptions,
    current_time: OffsetDateTime,
) -> PamResultCode {
    let account_id = match pamh.account_id() {
        Ok(acc) => acc,
        Err(err) => return err,
    };

    match req_opt.connect_to_daemon() {
        Source::Daemon(daemon_client) => {
            let req = ClientRequest::PamAccountAllowed(account_id);
            match daemon_client.call_and_wait(req, None) {
                Ok(r) => match r {
                    ClientResponse::PamStatus(Some(true)) => {
                        debug!("PamResultCode::PAM_SUCCESS");
                        PamResultCode::PAM_SUCCESS
                    }
                    ClientResponse::PamStatus(Some(false)) => {
                        debug!("PamResultCode::PAM_AUTH_ERR");
                        PamResultCode::PAM_AUTH_ERR
                    }
                    ClientResponse::PamStatus(None) => {
                        if opts.ignore_unknown_user {
                            debug!("PamResultCode::PAM_IGNORE");
                            PamResultCode::PAM_IGNORE
                        } else {
                            debug!("PamResultCode::PAM_USER_UNKNOWN");
                            PamResultCode::PAM_USER_UNKNOWN
                        }
                    }
                    _ => {
                        // unexpected response.
                        error!(err = ?r, "PAM_IGNORE, unexpected resolver response");
                        PamResultCode::PAM_IGNORE
                    }
                },
                Err(e) => {
                    error!(err = ?e, "PamResultCode::PAM_IGNORE");
                    PamResultCode::PAM_IGNORE
                }
            }
        }
        Source::Fallback { users, shadow } => {
            let user = users.into_iter().find(|etcuser| etcuser.name == account_id);

            let shadow = shadow
                .into_iter()
                .find(|etcshadow| etcshadow.name == account_id);

            let (_user, shadow) = match (user, shadow) {
                (Some(user), Some(shadow)) => (user, shadow),
                _ => {
                    if opts.ignore_unknown_user {
                        debug!("PamResultCode::PAM_IGNORE");
                        return PamResultCode::PAM_IGNORE;
                    } else {
                        debug!("PamResultCode::PAM_USER_UNKNOWN");
                        return PamResultCode::PAM_USER_UNKNOWN;
                    }
                }
            };

            let expiration_date = shadow.epoch_expire_seconds;

            if let Some(expire) = expiration_date {
                if current_time >= expire {
                    debug!("PamResultCode::PAM_ACCT_EXPIRED");
                    return PamResultCode::PAM_ACCT_EXPIRED;
                }
            };

            // All checks passed!

            debug!("PAM_SUCCESS");
            PamResultCode::PAM_SUCCESS
        }
    }
}

pub fn sm_open_session<P: PamHandler>(
    pamh: &P,
    _opts: &ModuleOptions,
    req_opt: RequestOptions,
) -> PamResultCode {
    let account_id = match pamh.account_id() {
        Ok(acc) => acc,
        Err(err) => return err,
    };

    match req_opt.connect_to_daemon() {
        Source::Daemon(daemon_client) => {
            let req = ClientRequest::PamAccountBeginSession(account_id);

            match daemon_client.call_and_wait(req, None) {
                Ok(ClientResponse::Ok) => {
                    debug!("PAM_SUCCESS");
                    PamResultCode::PAM_SUCCESS
                }
                other => {
                    debug!(err = ?other, "PAM_IGNORE");
                    PamResultCode::PAM_IGNORE
                }
            }
        }
        Source::Fallback {
            users: _,
            shadow: _,
        } => {
            debug!("PAM_SUCCESS");
            PamResultCode::PAM_SUCCESS
        }
    }
}

pub fn sm_close_session<P: PamHandler>(_pamh: &P, _opts: &ModuleOptions) -> PamResultCode {
    PamResultCode::PAM_SUCCESS
}

pub fn sm_chauthtok<P: PamHandler>(_pamh: &P, _opts: &ModuleOptions) -> PamResultCode {
    PamResultCode::PAM_IGNORE
}

pub fn sm_setcred<P: PamHandler>(_pamh: &P, _opts: &ModuleOptions) -> PamResultCode {
    PamResultCode::PAM_SUCCESS
}
