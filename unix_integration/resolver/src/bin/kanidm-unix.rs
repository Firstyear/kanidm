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

use std::process::ExitCode;

use clap::Parser;
use kanidm_unix_common::client::DaemonClient;
use kanidm_unix_common::constants::DEFAULT_CONFIG_PATH;
use kanidm_unix_common::unix_config::PamNssConfig;
use kanidm_unix_common::unix_proto::{
    ClientRequest, ClientResponse, PamAuthRequest, PamAuthResponse, PamServiceInfo,
};
use std::path::PathBuf;

include!("../opt/tool.rs");

macro_rules! setup_client {
    () => {{
        let Ok(cfg) = PamNssConfig::new().read_options_from_optional_config(DEFAULT_CONFIG_PATH)
        else {
            error!("Failed to parse {}", DEFAULT_CONFIG_PATH);
            return ExitCode::FAILURE;
        };

        debug!("Connecting to resolver ...");

        debug!(
            "Using kanidm_unixd socket path: {:?}",
            cfg.sock_path.as_str()
        );

        // see if the kanidm_unixd socket exists and quit if not
        if !PathBuf::from(&cfg.sock_path).exists() {
            error!(
                "Failed to find unix socket at {}, quitting!",
                cfg.sock_path.as_str()
            );
            return ExitCode::FAILURE;
        }

        match DaemonClient::new(cfg.sock_path.as_str(), cfg.unix_sock_timeout).await {
            Ok(dc) => dc,
            Err(err) => {
                error!(
                    "Failed to connect to resolver at {}-> {:?}",
                    cfg.sock_path.as_str(),
                    err
                );
                return ExitCode::FAILURE;
            }
        }
    }};
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let opt = KanidmUnixParser::parse();

    let debug = match opt.commands {
        KanidmUnixOpt::AuthTest {
            debug,
            account_id: _,
        } => debug,
        KanidmUnixOpt::CacheClear { debug, really: _ } => debug,
        KanidmUnixOpt::CacheInvalidate { debug } => debug,
        KanidmUnixOpt::Status { debug } => debug,
        KanidmUnixOpt::Version { debug } => debug,
    };

    if debug {
        ::std::env::set_var("RUST_LOG", "kanidm=debug,kanidm_client=debug");
    }
    sketching::tracing_subscriber::fmt::init();

    match opt.commands {
        KanidmUnixOpt::AuthTest {
            debug: _,
            account_id,
        } => {
            debug!("Starting PAM auth tester tool ...");

            let mut daemon_client = setup_client!();

            info!("Sending request for user {}", &account_id);

            let mut req = ClientRequest::PamAuthenticateInit {
                account_id: account_id.clone(),
                info: PamServiceInfo {
                    service: "kanidm-unix".to_string(),
                    tty: None,
                    rhost: None,
                },
            };
            loop {
                match daemon_client.call(req, None).await {
                    Ok(r) => match r {
                        ClientResponse::PamAuthenticateStepResponse {
                            response: PamAuthResponse::Success,
                            session_id: _,
                        } => {
                            println!("auth success!");
                            break;
                        }
                        ClientResponse::PamAuthenticateStepResponse {
                            response: PamAuthResponse::Denied,
                            session_id: _,
                        } => {
                            println!("auth failed!");
                            break;
                        }
                        ClientResponse::PamAuthenticateStepResponse {
                            response: PamAuthResponse::Unknown,
                            session_id: _,
                        } => {
                            debug!("User may need to be in allow_local_account_override");
                            println!("auth user unknown");
                            break;
                        }
                        ClientResponse::PamAuthenticateStepResponse {
                            response: PamAuthResponse::Password,
                            session_id,
                        } => {
                            // Prompt for and get the password
                            let cred = match dialoguer::Password::new()
                                .with_prompt("Enter Unix password")
                                .interact()
                            {
                                Ok(p) => p,
                                Err(e) => {
                                    error!("Problem getting input: {}", e);
                                    return ExitCode::FAILURE;
                                }
                            };

                            // Setup the req for the next loop.
                            req = ClientRequest::PamAuthenticateStep {
                                request: PamAuthRequest::Password { cred },
                                session_id,
                            };
                            continue;
                        }
                        ClientResponse::Error(err) => {
                            error!("Error from kanidm-unixd: {}", err);
                            break;
                        }
                        ClientResponse::PamAuthenticateStepResponse { .. }
                        | ClientResponse::SshKeys(_)
                        | ClientResponse::NssAccounts(_)
                        | ClientResponse::NssAccount(_)
                        | ClientResponse::NssGroup(_)
                        | ClientResponse::NssGroups(_)
                        | ClientResponse::ProviderStatus(_)
                        | ClientResponse::Ok
                        | ClientResponse::PamStatus(_) => {
                            // unexpected response.
                            error!("Error: unexpected response -> {:?}", r);
                            break;
                        }
                    },
                    Err(e) => {
                        error!("Error -> {:?}", e);
                        break;
                    }
                }
            }

            let sereq = ClientRequest::PamAccountAllowed(account_id);

            match daemon_client.call(sereq, None).await {
                Ok(r) => match r {
                    ClientResponse::PamStatus(Some(true)) => {
                        println!("account success!");
                    }
                    ClientResponse::PamStatus(Some(false)) => {
                        println!("account failed!");
                    }
                    ClientResponse::PamStatus(None) => {
                        println!("account user unknown");
                    }
                    _ => {
                        // unexpected response.
                        error!("Error: unexpected response -> {:?}", r);
                    }
                },
                Err(e) => {
                    error!("Error -> {:?}", e);
                }
            };
            ExitCode::SUCCESS
        }
        KanidmUnixOpt::CacheClear { debug: _, really } => {
            debug!("Starting cache clear tool ...");

            let mut daemon_client = setup_client!();

            if !really {
                error!("Are you sure you want to proceed? If so use --really");
                return ExitCode::SUCCESS;
            }

            let req = ClientRequest::ClearCache;

            match daemon_client.call(req, None).await {
                Ok(r) => match r {
                    ClientResponse::Ok => info!("success"),
                    _ => {
                        error!("Error: unexpected response -> {:?}", r);
                    }
                },
                Err(e) => {
                    error!("Error -> {:?}", e);
                }
            };
            println!("success");
            ExitCode::SUCCESS
        }
        KanidmUnixOpt::CacheInvalidate { debug: _ } => {
            debug!("Starting cache invalidate tool ...");

            let mut daemon_client = setup_client!();

            let req = ClientRequest::InvalidateCache;

            match daemon_client.call(req, None).await {
                Ok(r) => match r {
                    ClientResponse::Ok => info!("success"),
                    _ => {
                        error!("Error: unexpected response -> {:?}", r);
                    }
                },
                Err(e) => {
                    error!("Error -> {:?}", e);
                }
            };
            println!("success");
            ExitCode::SUCCESS
        }
        KanidmUnixOpt::Status { debug: _ } => {
            trace!("Starting cache status tool ...");

            let mut daemon_client = setup_client!();
            let req = ClientRequest::Status;

            match daemon_client.call(req, None).await {
                Ok(r) => match r {
                    ClientResponse::ProviderStatus(results) => {
                        for provider in results {
                            println!(
                                "{}: {}",
                                provider.name,
                                if provider.online { "online" } else { "offline" }
                            );
                        }
                    }
                    _ => {
                        error!("Error: unexpected response -> {:?}", r);
                    }
                },
                Err(e) => {
                    error!("Error -> {:?}", e);
                }
            }
            ExitCode::SUCCESS
        }
        KanidmUnixOpt::Version { debug: _ } => {
            println!("kanidm-unix {}", env!("KANIDM_PKG_VERSION"));
            ExitCode::SUCCESS
        }
    }
}
