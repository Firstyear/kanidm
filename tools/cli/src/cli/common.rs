use std::env;

use compact_jwt::{traits::JwsVerifiable, JwsCompact, JwsEs256Verifier, JwsVerifier, JwtError};
use dialoguer::theme::ColorfulTheme;
use dialoguer::{Confirm, Select};
use kanidm_client::{KanidmClient, KanidmClientBuilder};
use kanidm_proto::constants::{DEFAULT_CLIENT_CONFIG_PATH, DEFAULT_CLIENT_CONFIG_PATH_HOME};
use kanidm_proto::internal::UserAuthToken;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::session::read_tokens;
use crate::{CommonOpt, LoginOpt, ReauthOpt};

#[derive(Clone)]
pub enum OpType {
    Read,
    Write,
}

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum ToClientError {
    NeedLogin(String),
    NeedReauth(String, KanidmClient),
    Other,
}

impl CommonOpt {
    pub fn to_unauth_client(&self) -> KanidmClient {
        let config_path: String = shellexpand::tilde(DEFAULT_CLIENT_CONFIG_PATH_HOME).into_owned();

        let instance_name: Option<&str> = self.instance.as_deref();

        let client_builder = KanidmClientBuilder::new()
            .read_options_from_optional_instance_config(DEFAULT_CLIENT_CONFIG_PATH, instance_name)
            .map_err(|e| {
                error!(
                    "Failed to parse config ({:?}) -- {:?}",
                    DEFAULT_CLIENT_CONFIG_PATH, e
                );
                e
            })
            .and_then(|cb| {
                cb.read_options_from_optional_instance_config(&config_path, instance_name)
                    .map_err(|e| {
                        error!("Failed to parse config ({:?}) -- {:?}", config_path, e);
                        e
                    })
            })
            .unwrap_or_else(|_e| {
                std::process::exit(1);
            });
        debug!(
            "Successfully loaded configuration, looked in {} and {} - client builder state: {:?}",
            DEFAULT_CLIENT_CONFIG_PATH, DEFAULT_CLIENT_CONFIG_PATH_HOME, &client_builder
        );

        let client_builder = match &self.addr {
            Some(a) => client_builder.address(a.to_string()),
            None => client_builder,
        };

        let ca_path: Option<&str> = self.ca_path.as_ref().and_then(|p| p.to_str());
        let client_builder = match ca_path {
            Some(p) => {
                debug!("Adding trusted CA cert {:?}", p);
                let client_builder = client_builder
                    .add_root_certificate_filepath(p)
                    .unwrap_or_else(|e| {
                        error!("Failed to add ca certificate -- {:?}", e);
                        std::process::exit(1);
                    });

                debug!(
                    "After attempting to add trusted CA cert, client builder state: {:?}",
                    client_builder
                );
                client_builder
            }
            None => client_builder,
        };

        let client_builder = match self.skip_hostname_verification {
            true => {
                warn!(
                    "Accepting invalid hostnames on the certificate for {:?}",
                    &self.addr
                );
                client_builder.danger_accept_invalid_hostnames(true)
            }
            false => client_builder,
        };

        let client_builder = match self.accept_invalid_certs {
            true => {
                warn!(
                    "TLS Certificate Verification disabled!!! This can lead to credential and account compromise!!!"
                );
                client_builder.danger_accept_invalid_certs(true)
            }
            false => client_builder,
        };

        let client_builder = client_builder.set_token_cache_path(self.token_cache_path.clone());

        client_builder.build().unwrap_or_else(|e| {
            error!("Failed to build client instance -- {:?}", e);
            std::process::exit(1);
        })
    }

    pub(crate) async fn try_to_client(
        &self,
        optype: OpType,
    ) -> Result<KanidmClient, ToClientError> {
        let client = self.to_unauth_client();

        // Read the token file.
        let token_store = match read_tokens(&client.get_token_cache_path()) {
            Ok(t) => t,
            Err(_e) => {
                error!("Error retrieving authentication token store");
                return Err(ToClientError::Other);
            }
        };

        let Some(token_instance) = token_store.instances(&self.instance) else {
            error!(
                "No valid authentication tokens found. Please login with the 'login' subcommand."
            );
            return Err(ToClientError::Other);
        };

        // If we have a username, use that to select tokens
        let (spn, jwsc) = match &self.username {
            Some(filter_username) => {
                let possible_token = if filter_username.contains('@') {
                    // If there is an @, it's an spn so just get the token directly.
                    token_instance
                        .tokens()
                        .get(filter_username)
                        .map(|t| (filter_username.clone(), t.clone()))
                } else {
                    // first we try to find user@hostname
                    let filter_username_with_hostname = format!(
                        "{}@{}",
                        filter_username,
                        client.get_origin().host_str().unwrap_or("localhost")
                    );
                    debug!(
                        "Looking for tokens matching {}",
                        filter_username_with_hostname
                    );

                    let mut token_refs: Vec<_> = token_instance
                        .tokens()
                        .iter()
                        .filter(|(t, _)| *t == &filter_username_with_hostname)
                        .map(|(k, v)| (k.clone(), v.clone()))
                        .collect();

                    if token_refs.len() == 1 {
                        // return the token
                        token_refs.pop()
                    } else {
                        // otherwise let's try the fallback
                        let filter_username = format!("{}@", filter_username);
                        // Filter for tokens that match the pattern
                        let mut token_refs: Vec<_> = token_instance
                            .tokens()
                            .iter()
                            .filter(|(t, _)| t.starts_with(&filter_username))
                            .map(|(s, j)| (s.clone(), j.clone()))
                            .collect();

                        match token_refs.len() {
                            0 => None,
                            1 => token_refs.pop(),
                            _ => {
                                error!("Multiple authentication tokens found for {}. Please specify the full spn to proceed", filter_username);
                                return Err(ToClientError::Other);
                            }
                        }
                    }
                };

                // Is it in the store?
                match possible_token {
                    Some(t) => t,
                    None => {
                        error!(
                            "No valid authentication tokens found for {}.",
                            filter_username
                        );
                        return Err(ToClientError::NeedLogin(filter_username.clone()));
                    }
                }
            }
            None => {
                if token_instance.tokens().len() == 1 {
                    #[allow(clippy::expect_used)]
                    let (f_uname, f_token) = token_instance
                        .tokens()
                        .iter()
                        .next()
                        .expect("Memory Corruption");
                    // else pick the first token
                    debug!("Using cached token for name {}", f_uname);
                    (f_uname.clone(), f_token.clone())
                } else {
                    // Unable to automatically select the user because multiple tokens exist
                    // so we'll prompt the user to select one
                    match prompt_for_username_get_values(
                        &client.get_token_cache_path(),
                        &self.instance,
                    ) {
                        Ok(tuple) => tuple,
                        Err(msg) => {
                            error!("Error: {}", msg);
                            std::process::exit(1);
                        }
                    }
                }
            }
        };

        let Some(key_id) = jwsc.kid() else {
            error!("token invalid, not key id associated");
            return Err(ToClientError::Other);
        };

        let Some(pub_jwk) = token_instance.keys().get(key_id) else {
            error!("token invalid, no cached jwk available");
            return Err(ToClientError::Other);
        };

        // Is the token (probably) valid?
        let jws_verifier = match JwsEs256Verifier::try_from(pub_jwk) {
            Ok(verifier) => verifier,
            Err(err) => {
                error!(?err, "Unable to configure jws verifier");
                return Err(ToClientError::Other);
            }
        };

        match jws_verifier.verify(&jwsc).and_then(|jws| {
            jws.from_json::<UserAuthToken>().map_err(|serde_err| {
                error!(?serde_err);
                JwtError::InvalidJwt
            })
        }) {
            Ok(uat) => {
                let now_utc = time::OffsetDateTime::now_utc();
                if let Some(exp) = uat.expiry {
                    if now_utc >= exp {
                        error!(
                            "Session has expired for {} - you may need to login again.",
                            uat.spn
                        );
                        return Err(ToClientError::NeedLogin(spn));
                    }
                }

                // It's probably valid, set into the client
                client.set_token(jwsc.to_string()).await;

                // Check what we are doing based on op.
                match optype {
                    OpType::Read => {}
                    OpType::Write => {
                        if !uat.purpose_readwrite_active(now_utc + time::Duration::new(20, 0)) {
                            error!(
                                "Privileges have expired for {} - you need to re-authenticate again.",
                                uat.spn
                            );
                            return Err(ToClientError::NeedReauth(spn, client));
                        }
                    }
                }
            }
            Err(e) => {
                error!("Unable to read token for requested user - you may need to login again.");
                debug!(?e, "JWT Error");
                return Err(ToClientError::NeedLogin(spn));
            }
        };

        Ok(client)
    }

    pub async fn to_client(&self, optype: OpType) -> KanidmClient {
        let mut copt_mut = self.clone();
        loop {
            match self.try_to_client(optype.clone()).await {
                Ok(c) => break c,
                Err(ToClientError::NeedLogin(username)) => {
                    if !Confirm::new()
                        .with_prompt("Would you like to login again?")
                        .default(true)
                        .interact()
                        .expect("Failed to interact with interactive session")
                    {
                        std::process::exit(1);
                    }

                    copt_mut.username = Some(username);
                    let copt = copt_mut.clone();
                    let login_opt = LoginOpt {
                        copt,
                        password: env::var("KANIDM_PASSWORD").ok(),
                    };

                    login_opt.exec().await;
                    // Okay, try again ...
                    continue;
                }
                Err(ToClientError::NeedReauth(username, client)) => {
                    if !Confirm::new()
                        .with_prompt("Would you like to re-authenticate?")
                        .default(true)
                        .interact()
                        .expect("Failed to interact with interactive session")
                    {
                        std::process::exit(1);
                    }
                    copt_mut.username = Some(username);
                    let copt = copt_mut.clone();
                    let reauth_opt = ReauthOpt { copt };
                    reauth_opt.inner(client).await;

                    // Okay, re-auth should have passed, lets loop
                    continue;
                }
                Err(ToClientError::Other) => {
                    std::process::exit(1);
                }
            }
        }
    }
}

/// This parses the token store and prompts the user to select their username, returns the username/token as a tuple of Strings
///
/// Used to reduce duplication in implementing [prompt_for_username_get_username] and `prompt_for_username_get_token`
pub fn prompt_for_username_get_values(
    token_cache_path: &str,
    instance_name: &Option<String>,
) -> Result<(String, JwsCompact), String> {
    let token_store = match read_tokens(token_cache_path) {
        Ok(value) => value,
        _ => return Err("Error retrieving authentication token store".to_string()),
    };

    let Some(token_instance) = token_store.instances(instance_name) else {
        error!("No tokens in store, quitting!");
        std::process::exit(1);
    };

    if token_instance.tokens().is_empty() {
        error!("No tokens in store, quitting!");
        std::process::exit(1);
    }
    let mut options = Vec::new();
    for option in token_instance.tokens().iter() {
        options.push(String::from(option.0));
    }
    let user_select = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Multiple authentication tokens exist. Please select one")
        .default(0)
        .items(&options)
        .interact();
    let selection = match user_select {
        Err(error) => {
            error!("Failed to handle user input: {:?}", error);
            std::process::exit(1);
        }
        Ok(value) => value,
    };
    debug!("Index of the chosen menu item: {:?}", selection);

    match token_instance.tokens().iter().nth(selection) {
        Some(value) => {
            let (f_uname, f_token) = value;
            debug!("Using cached token for name {}", f_uname);
            debug!("Cached token: {}", f_token);
            Ok((f_uname.to_string(), f_token.clone()))
        }
        None => {
            error!("Memory corruption trying to read token store, quitting!");
            std::process::exit(1);
        }
    }
}

/// This parses the token store and prompts the user to select their username, returns the username as a String
///
/// Powered by [prompt_for_username_get_values]
pub fn prompt_for_username_get_username(
    token_cache_path: &str,
    instance_name: &Option<String>,
) -> Result<String, String> {
    match prompt_for_username_get_values(token_cache_path, instance_name) {
        Ok(value) => {
            let (f_user, _) = value;
            Ok(f_user)
        }
        Err(err) => Err(err),
    }
}

/*
/// This parses the token store and prompts the user to select their username, returns the token as a String
///
/// Powered by [prompt_for_username_get_values]
pub fn prompt_for_username_get_token() -> Result<String, String> {
    match prompt_for_username_get_values() {
        Ok(value) => {
            let (_, f_token) = value;
            Ok(f_token)
        }
        Err(err) => Err(err),
    }
}
*/

/// This parses the input for the person/service-account expire-at CLI commands
///
/// If it fails, return error, if it needs to *clear* the result, return Ok(None),
/// otherwise return Ok(Some(String)) which is the new value to set.
pub(crate) fn try_expire_at_from_string(input: &str) -> Result<Option<String>, ()> {
    match input {
        "any" | "never" | "clear" => Ok(None),
        "now" => match OffsetDateTime::now_utc().format(&Rfc3339) {
            Ok(s) => Ok(Some(s)),
            Err(e) => {
                error!(err = ?e, "Unable to format current time to rfc3339");
                Err(())
            }
        },
        "epoch" => match OffsetDateTime::UNIX_EPOCH.format(&Rfc3339) {
            Ok(val) => Ok(Some(val)),
            Err(err) => {
                error!("Failed to format epoch timestamp as RFC3339: {:?}", err);
                Err(())
            }
        },
        _ => {
            // fall back to parsing it as a date
            match OffsetDateTime::parse(input, &Rfc3339) {
                Ok(_) => Ok(Some(input.to_string())),
                Err(err) => {
                    error!("Failed to parse supplied timestamp: {:?}", err);
                    Err(())
                }
            }
        }
    }
}
