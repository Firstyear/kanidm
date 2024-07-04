use askama::Template;

use axum::{
    extract::State,
    response::{IntoResponse, Redirect, Response},
    Extension, Form, Json,
};

use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};

use compact_jwt::{Jws, JwsSigner};

use kanidmd_lib::prelude::OperationError;

use kanidm_proto::v1::{
    AuthAllowed, AuthCredential, AuthIssueSession, AuthMech, AuthRequest, AuthStep,
};

use kanidmd_lib::prelude::*;

use kanidm_proto::internal::{COOKIE_AUTH_SESSION_ID, COOKIE_BEARER_TOKEN};

use kanidmd_lib::idm::AuthState;

use kanidmd_lib::idm::event::AuthResult;

use serde::Deserialize;

use crate::https::{
    extractors::VerifiedClientInformation, middleware::KOpId, v1::SessionId, ServerState,
};

use webauthn_rs::prelude::PublicKeyCredential;

use std::str::FromStr;

use super::{HtmlTemplate, UnrecoverableErrorView};

#[derive(Template)]
#[template(path = "login.html")]
struct LoginView<'a> {
    username: &'a str,
    remember_me: bool,
}

pub struct Mech<'a> {
    name: AuthMech,
    value: &'a str,
}

#[derive(Template)]
#[template(path = "login_mech_choose_partial.html")]
struct LoginMechPartialView<'a> {
    mechs: Vec<Mech<'a>>,
}

#[derive(Default)]
enum LoginTotpError {
    #[default]
    None,
    Syntax,
}

#[derive(Template, Default)]
#[template(path = "login_totp_partial.html")]
struct LoginTotpPartialView {
    errors: LoginTotpError,
}

#[derive(Template)]
#[template(path = "login_password_partial.html")]
struct LoginPasswordPartialView {}

#[derive(Template)]
#[template(path = "login_backupcode_partial.html")]
struct LoginBackupCodePartialView {}

#[derive(Template)]
#[template(path = "login_webauthn_partial.html")]
struct LoginWebauthnPartialView {
    // Control if we are rendering in security key or passkey mode.
    passkey: bool,
    // chal: RequestChallengeResponse,
    chal: String,
}

pub async fn view_index_get(
    State(state): State<ServerState>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    Extension(kopid): Extension<KOpId>,
    _jar: CookieJar,
) -> Response {
    // If we are authenticated, redirect to the landing.
    let session_valid_result = state
        .qe_r_ref
        .handle_auth_valid(client_auth_info, kopid.eventid)
        .await;

    match session_valid_result {
        Ok(()) => {
            // Send the user to the landing.
            Redirect::to("/ui/apps").into_response()
        }
        Err(OperationError::NotAuthenticated) | Err(OperationError::SessionExpired) => {
            // cookie jar with remember me.

            HtmlTemplate(LoginView {
                username: "",
                remember_me: false,
            })
            .into_response()
        }
        Err(err_code) => HtmlTemplate(UnrecoverableErrorView {
            err_code,
            operation_id: kopid.eventid,
        })
        .into_response(),
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct LoginBeginForm {
    username: String,
    #[serde(default)]
    remember_me: Option<u8>,
}

pub async fn partial_view_login_begin_post(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    jar: CookieJar,
    Form(login_begin_form): Form<LoginBeginForm>,
) -> Response {
    trace!(?login_begin_form);

    let LoginBeginForm {
        username,
        remember_me,
    } = login_begin_form;

    trace!(?remember_me);

    // Init the login.
    let inter = state // This may change in the future ...
        .qe_r_ref
        .handle_auth(
            None,
            AuthRequest {
                step: AuthStep::Init2 {
                    username,
                    issue: AuthIssueSession::Cookie,
                    privileged: false,
                },
            },
            kopid.eventid,
            client_auth_info.clone(),
        )
        .await;

    // Now process the response if ok.
    match inter {
        Ok(ar) => {
            match partial_view_login_step(state, kopid.clone(), jar, ar, client_auth_info).await {
                Ok(r) => r,
                // Okay, these errors are actually REALLY bad.
                Err(err_code) => HtmlTemplate(UnrecoverableErrorView {
                    err_code,
                    operation_id: kopid.eventid,
                })
                .into_response(),
            }
        }
        // Probably needs to be way nicer on login, especially something like no matching users ...
        Err(err_code) => HtmlTemplate(UnrecoverableErrorView {
            err_code,
            operation_id: kopid.eventid,
        })
        .into_response(),
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct LoginMechForm {
    mech: AuthMech,
}

pub async fn partial_view_login_mech_choose_post(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    jar: CookieJar,
    Form(login_mech_form): Form<LoginMechForm>,
) -> Response {
    let maybe_sessionid = jar
        .get(COOKIE_AUTH_SESSION_ID)
        .map(|c| c.value())
        .and_then(|s| {
            trace!(id_jws = %s);
            state.reinflate_uuid_from_bytes(s)
        });

    debug!("Session ID: {:?}", maybe_sessionid);

    let LoginMechForm { mech } = login_mech_form;

    let inter = state // This may change in the future ...
        .qe_r_ref
        .handle_auth(
            maybe_sessionid,
            AuthRequest {
                step: AuthStep::Begin(mech),
            },
            kopid.eventid,
            client_auth_info.clone(),
        )
        .await;

    // Now process the response if ok.
    match inter {
        Ok(ar) => {
            match partial_view_login_step(state, kopid.clone(), jar, ar, client_auth_info).await {
                Ok(r) => r,
                // Okay, these errors are actually REALLY bad.
                Err(err_code) => HtmlTemplate(UnrecoverableErrorView {
                    err_code,
                    operation_id: kopid.eventid,
                })
                .into_response(),
            }
        }
        // Probably needs to be way nicer on login, especially something like no matching users ...
        Err(err_code) => HtmlTemplate(UnrecoverableErrorView {
            err_code,
            operation_id: kopid.eventid,
        })
        .into_response(),
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct LoginTotpForm {
    totp: String,
}

pub async fn partial_view_login_totp_post(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    jar: CookieJar,
    Form(login_totp_form): Form<LoginTotpForm>,
) -> Response {
    // trim leading and trailing white space.
    let Ok(totp) = u32::from_str(&login_totp_form.totp.trim()) else {
        // If not an int, we need to re-render with an error
        return HtmlTemplate(LoginTotpPartialView {
            errors: LoginTotpError::Syntax,
        })
        .into_response();
    };

    let auth_cred = AuthCredential::Totp(totp);
    credential_step(state, kopid, jar, client_auth_info, auth_cred).await
}

#[derive(Debug, Clone, Deserialize)]
pub struct LoginPwForm {
    password: String,
}

pub async fn partial_view_login_pw_post(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    jar: CookieJar,
    Form(login_pw_form): Form<LoginPwForm>,
) -> Response {
    let auth_cred = AuthCredential::Password(login_pw_form.password);
    credential_step(state, kopid, jar, client_auth_info, auth_cred).await
}

#[derive(Debug, Clone, Deserialize)]
pub struct LoginBackupCodeForm {
    backupcode: String,
}

pub async fn partial_view_login_backupcode_post(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    jar: CookieJar,
    Form(login_bc_form): Form<LoginBackupCodeForm>,
) -> Response {
    // People (like me) may copy-paste the bc with whitespace that causes issues. Trim it now.
    let trimmed = login_bc_form.backupcode.trim().to_string();
    let auth_cred = AuthCredential::BackupCode(trimmed);
    credential_step(state, kopid, jar, client_auth_info, auth_cred).await
}

pub async fn partial_view_login_passkey_post(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    jar: CookieJar,
    Json(assertion): Json<Box<PublicKeyCredential>>,
) -> Response {
    let auth_cred = AuthCredential::Passkey(assertion);
    credential_step(state, kopid, jar, client_auth_info, auth_cred).await
}

pub async fn partial_view_login_seckey_post(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
    VerifiedClientInformation(client_auth_info): VerifiedClientInformation,
    jar: CookieJar,
    Json(assertion): Json<Box<PublicKeyCredential>>,
) -> Response {
    let auth_cred = AuthCredential::SecurityKey(assertion);
    credential_step(state, kopid, jar, client_auth_info, auth_cred).await
}

async fn credential_step(
    state: ServerState,
    kopid: KOpId,
    jar: CookieJar,
    client_auth_info: ClientAuthInfo,
    auth_cred: AuthCredential,
) -> Response {
    let maybe_sessionid = jar
        .get(COOKIE_AUTH_SESSION_ID)
        .map(|c| c.value())
        .and_then(|s| {
            trace!(id_jws = %s);
            state.reinflate_uuid_from_bytes(s)
        });

    debug!("Session ID: {:?}", maybe_sessionid);

    let inter = state // This may change in the future ...
        .qe_r_ref
        .handle_auth(
            maybe_sessionid,
            AuthRequest {
                step: AuthStep::Cred(auth_cred),
            },
            kopid.eventid,
            client_auth_info.clone(),
        )
        .await;

    // Now process the response if ok.
    match inter {
        Ok(ar) => {
            match partial_view_login_step(state, kopid.clone(), jar, ar, client_auth_info).await {
                Ok(r) => r,
                // Okay, these errors are actually REALLY bad.
                Err(err_code) => HtmlTemplate(UnrecoverableErrorView {
                    err_code,
                    operation_id: kopid.eventid,
                })
                .into_response(),
            }
        }
        // Probably needs to be way nicer on login, especially something like no matching users ...
        Err(err_code) => HtmlTemplate(UnrecoverableErrorView {
            err_code,
            operation_id: kopid.eventid,
        })
        .into_response(),
    }
}

async fn partial_view_login_step(
    state: ServerState,
    kopid: KOpId,
    mut jar: CookieJar,
    auth_result: AuthResult,
    client_auth_info: ClientAuthInfo,
) -> Result<Response, OperationError> {
    trace!(?auth_result);

    let AuthResult {
        state: mut auth_state,
        sessionid,
    } = auth_result;

    let mut safety = 3;

    // Unlike the api version, only set the cookie.
    let response = loop {
        if safety == 0 {
            error!("loop safety triggered - auth state was unable to resolve. This should NEVER HAPPEN.");
            debug_assert!(false);
            return Err(OperationError::InvalidSessionState);
        }
        // The slow march to the heat death of the loop.
        safety -= 1;

        match auth_state {
            AuthState::Choose(allowed) => {
                debug!("🧩 -> AuthState::Choose");
                let kref = &state.jws_signer;
                let jws = Jws::into_json(&SessionId { sessionid }).map_err(|e| {
                    error!(?e);
                    OperationError::InvalidSessionState
                })?;

                // Get the header token ready.
                let token = kref.sign(&jws).map(|jwss| jwss.to_string()).map_err(|e| {
                    error!(?e);
                    OperationError::InvalidSessionState
                })?;

                let mut token_cookie = Cookie::new(COOKIE_AUTH_SESSION_ID, token);
                token_cookie.set_secure(state.secure_cookies);
                token_cookie.set_same_site(SameSite::Strict);
                token_cookie.set_http_only(true);
                // Not setting domains limits the cookie to precisely this
                // url that was used.
                // token_cookie.set_domain(state.domain.clone());
                jar = jar.add(token_cookie);

                let res = match allowed.len() {
                    // Should never happen.
                    0 => {
                        error!("auth state choose allowed mechs is empty");
                        HtmlTemplate(UnrecoverableErrorView {
                            err_code: OperationError::InvalidState,
                            operation_id: kopid.eventid,
                        })
                        .into_response()
                    }
                    1 => {
                        let mech = allowed[0].clone();
                        // submit the choice and then loop updating our auth_state.
                        let inter = state // This may change in the future ...
                            .qe_r_ref
                            .handle_auth(
                                Some(sessionid),
                                AuthRequest {
                                    step: AuthStep::Begin(mech),
                                },
                                kopid.eventid,
                                client_auth_info.clone(),
                            )
                            .await?;

                        // Set the state now for the next loop.
                        auth_state = inter.state;

                        // Autoselect was hit.
                        continue;
                    }

                    // Render the list of options.
                    _ => {
                        let mechs = allowed
                            .into_iter()
                            .map(|m| Mech {
                                value: m.to_value(),
                                name: m,
                            })
                            .collect();
                        HtmlTemplate(LoginMechPartialView { mechs }).into_response()
                    }
                };
                // break acts as return in a loop.
                break res;
            }
            AuthState::Continue(allowed) => {
                let res = match allowed.len() {
                    // Shouldn't be possible.
                    0 => {
                        error!("auth state continued allowed mechs is empty");
                        HtmlTemplate(UnrecoverableErrorView {
                            err_code: OperationError::InvalidState,
                            operation_id: kopid.eventid,
                        })
                        .into_response()
                    }
                    1 => {
                        let auth_allowed = allowed[0].clone();

                        match auth_allowed {
                            AuthAllowed::Totp => {
                                HtmlTemplate(LoginTotpPartialView::default()).into_response()
                            }
                            AuthAllowed::Password => {
                                HtmlTemplate(LoginPasswordPartialView {}).into_response()
                            }
                            AuthAllowed::BackupCode => {
                                HtmlTemplate(LoginBackupCodePartialView {}).into_response()
                            }
                            AuthAllowed::SecurityKey(chal) => {
                                let chal_json = serde_json::to_string(&chal).unwrap();
                                HtmlTemplate(LoginWebauthnPartialView {
                                    passkey: false,
                                    chal: chal_json,
                                })
                                .into_response()
                            }
                            AuthAllowed::Passkey(chal) => {
                                let chal_json = serde_json::to_string(&chal).unwrap();
                                HtmlTemplate(LoginWebauthnPartialView {
                                    passkey: true,
                                    chal: chal_json,
                                })
                                .into_response()
                            }
                            _ => return Err(OperationError::InvalidState),
                        }
                    }
                    _ => {
                        // We have changed auth session to only ever return one possibility, and
                        // that one option encodes the possible challenges.
                        return Err(OperationError::InvalidState);
                    }
                };

                // break acts as return in a loop.
                break res;
            }
            AuthState::Success(token, issue) => {
                debug!("🧩 -> AuthState::Success");

                match issue {
                    AuthIssueSession::Token => {
                        error!(
                            "Impossible state, should not recieve token in a htmx view auth flow"
                        );
                        return Err(OperationError::InvalidState);
                    }
                    AuthIssueSession::Cookie => {
                        // Update jar
                        let token_str = token.to_string();
                        let mut bearer_cookie = Cookie::new(COOKIE_BEARER_TOKEN, token_str.clone());
                        bearer_cookie.set_secure(state.secure_cookies);
                        bearer_cookie.set_same_site(SameSite::Lax);
                        bearer_cookie.set_http_only(true);
                        // We set a domain here because it allows subdomains
                        // of the idm to share the cookie. If domain was incorrect
                        // then webauthn won't work anyway!
                        bearer_cookie.set_domain(state.domain.clone());
                        bearer_cookie.set_path("/");
                        jar = jar
                            .add(bearer_cookie)
                            .remove(Cookie::from(COOKIE_AUTH_SESSION_ID));

                        let res = Redirect::to("/ui/apps").into_response();

                        break res;
                    }
                }
            }
            AuthState::Denied(_reason) => {
                debug!("🧩 -> AuthState::Denied");
                jar = jar.remove(Cookie::from(COOKIE_AUTH_SESSION_ID));

                // Render a denial.
                break Redirect::temporary("/ui/getrekt").into_response();
            }
        }
    };

    Ok((jar, response).into_response())
}
