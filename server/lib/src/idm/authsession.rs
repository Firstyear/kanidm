//! This module contains the logic to conduct an authentication of an account.
//! Generally this has to process an authentication attempt, and validate each
//! factor to assert that the user is legitimate. This also contains some
//! support code for asynchronous task execution.
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use compact_jwt::Jws;
use hashbrown::HashSet;
use kanidm_proto::internal::UserAuthToken;
use kanidm_proto::v1::{AuthAllowed, AuthCredential, AuthIssueSession, AuthMech};
use nonempty::NonEmpty;
use tokio::sync::mpsc::UnboundedSender as Sender;
use uuid::Uuid;
use webauthn_rs::prelude::{
    AttestationCaList, AttestedPasskey as AttestedPasskeyV4, AttestedPasskeyAuthentication,
    CredentialID, Passkey as PasskeyV4, PasskeyAuthentication, RequestChallengeResponse,
    SecurityKeyAuthentication, Webauthn,
};

use crate::credential::totp::Totp;
use crate::credential::{BackupCodes, Credential, CredentialType, Password};
use crate::idm::account::Account;
use crate::idm::audit::AuditEvent;
use crate::idm::delayed::{
    AuthSessionRecord, BackupCodeRemoval, DelayedAction, PasswordUpgrade, WebauthnCounterIncrement,
};
use crate::idm::AuthState;
use crate::prelude::*;
use crate::server::keys::KeyObject;
use crate::value::{AuthType, Session, SessionState};
use time::OffsetDateTime;

use super::accountpolicy::ResolvedAccountPolicy;

// Each CredHandler takes one or more credentials and determines if the
// handlers requirements can be 100% fulfilled. This is where MFA or other
// auth policies would exist, but each credHandler has to be a whole
// encapsulated unit of function.

const BAD_PASSWORD_MSG: &str = "incorrect password";
const BAD_TOTP_MSG: &str = "incorrect totp";
const BAD_WEBAUTHN_MSG: &str = "invalid webauthn authentication";
const BAD_ACCOUNT_POLICY: &str = "the credential no longer meets account policy requirements";
const BAD_BACKUPCODE_MSG: &str = "invalid backup code";
const BAD_AUTH_TYPE_MSG: &str = "invalid authentication method in this context";
const BAD_CREDENTIALS: &str = "invalid credential message";
const ACCOUNT_EXPIRED: &str = "account expired";
const PW_BADLIST_MSG: &str = "password is in badlist";

#[derive(Debug, Clone)]
enum AuthIntent {
    InitialAuth {
        privileged: bool,
    },
    Reauth {
        session_id: Uuid,
        session_expiry: Option<OffsetDateTime>,
    },
}

/// A response type to indicate the progress and potential result of an authentication attempt.
enum CredState {
    Success { auth_type: AuthType, cred_id: Uuid },
    Continue(Box<NonEmpty<AuthAllowed>>),
    Denied(&'static str),
}

#[derive(Clone, Debug, PartialEq)]
/// The state of verification of an individual credential during an authentication.
enum CredVerifyState {
    Init,
    Success,
    Fail,
}

#[derive(Clone, Debug)]
/// The state of a multifactor authenticator during authentication.
struct CredTotp {
    pw: Password,
    pw_state: CredVerifyState,
    totp: BTreeMap<String, Totp>,
    mfa_state: CredVerifyState,
}

#[derive(Clone, Debug)]
/// The state of a multifactor authenticator during authentication.
struct CredBackupCode {
    pw: Password,
    pw_state: CredVerifyState,
    backup_code: BackupCodes,
    mfa_state: CredVerifyState,
}

#[derive(Clone, Debug)]
/// The state of a multifactor authenticator during authentication.
struct CredSecurityKey {
    pw: Password,
    pw_state: CredVerifyState,
    chal: RequestChallengeResponse,
    ska: SecurityKeyAuthentication,
    mfa_state: CredVerifyState,
}

#[derive(Clone, Debug)]
/// The state of a passkey during authentication
struct CredPasskey {
    chal: RequestChallengeResponse,
    wan_state: PasskeyAuthentication,
    state: CredVerifyState,
}

#[derive(Clone, Debug)]
/// The state of an attested passkey during authentication
struct CredAttestedPasskey {
    chal: RequestChallengeResponse,
    wan_state: AttestedPasskeyAuthentication,
    state: CredVerifyState,
}

/// The current active handler for this authentication session. This is determined from what credentials
/// are possible from the account, and what the user selected as the preferred authentication
/// mechanism.
#[derive(Clone, Debug)]
enum CredHandler {
    Anonymous {
        cred_id: Uuid,
    },
    Password {
        pw: Password,
        generated: bool,
        cred_id: Uuid,
    },
    PasswordTotp {
        cmfa: CredTotp,
        cred_id: Uuid,
    },
    PasswordBackupCode {
        cmfa: CredBackupCode,
        cred_id: Uuid,
    },
    PasswordSecurityKey {
        cmfa: CredSecurityKey,
        cred_id: Uuid,
    },
    Passkey {
        c_wan: CredPasskey,
        cred_ids: BTreeMap<CredentialID, Uuid>,
    },
    AttestedPasskey {
        c_wan: CredAttestedPasskey,
        // To verify the attestation post auth
        att_ca_list: AttestationCaList,
        // AP does `PartialEq` on cred_id
        creds: BTreeMap<AttestedPasskeyV4, Uuid>,
    },
}

impl CredHandler {
    /// Given a credential and some external configuration, Generate the credential handler
    /// that will be used for this session. This credential handler is a "self contained"
    /// unit that defines what is possible to use during this authentication session to prevent
    /// inconsistency.
    fn build_from_set_passkey(
        wan: impl Iterator<Item = (Uuid, PasskeyV4)>,
        webauthn: &Webauthn,
    ) -> Option<Self> {
        let mut pks = Vec::with_capacity(wan.size_hint().0);
        let mut cred_ids = BTreeMap::default();

        for (uuid, pk) in wan {
            cred_ids.insert(pk.cred_id().clone(), uuid);
            pks.push(pk);
        }

        if pks.is_empty() {
            debug!("Account does not have any passkeys");
            return None;
        };

        webauthn
            .start_passkey_authentication(&pks)
            .map(|(chal, wan_state)| CredHandler::Passkey {
                c_wan: CredPasskey {
                    chal,
                    wan_state,
                    state: CredVerifyState::Init,
                },
                cred_ids,
            })
            .map_err(|e| {
                security_info!(
                    ?e,
                    "Unable to create passkey webauthn authentication challenge"
                );
                // maps to unit.
            })
            .ok()
    }

    fn build_from_single_passkey(
        cred_id: Uuid,
        pk: PasskeyV4,
        webauthn: &Webauthn,
    ) -> Option<Self> {
        let cred_ids = btreemap!((pk.cred_id().clone(), cred_id));
        let pks = vec![pk];

        webauthn
            .start_passkey_authentication(pks.as_slice())
            .map(|(chal, wan_state)| CredHandler::Passkey {
                c_wan: CredPasskey {
                    chal,
                    wan_state,
                    state: CredVerifyState::Init,
                },
                cred_ids,
            })
            .map_err(|e| {
                security_info!(
                    ?e,
                    "Unable to create passkey webauthn authentication challenge"
                );
                // maps to unit.
            })
            .ok()
    }

    fn build_from_set_attested_pk(
        wan: &BTreeMap<Uuid, (String, AttestedPasskeyV4)>,
        att_ca_list: &AttestationCaList,
        webauthn: &Webauthn,
    ) -> Option<Self> {
        if wan.is_empty() {
            debug!("Account does not have any attested passkeys");
            return None;
        };

        let pks: Vec<_> = wan.values().map(|(_, k)| k).cloned().collect();
        let creds: BTreeMap<_, _> = wan.iter().map(|(u, (_, k))| (k.clone(), *u)).collect();

        webauthn
            .start_attested_passkey_authentication(&pks)
            .map(|(chal, wan_state)| CredHandler::AttestedPasskey {
                c_wan: CredAttestedPasskey {
                    chal,
                    wan_state,
                    state: CredVerifyState::Init,
                },
                att_ca_list: att_ca_list.clone(),
                creds,
            })
            .map_err(|e| {
                security_info!(
                    ?e,
                    "Unable to create attested passkey webauthn authentication challenge"
                );
                // maps to unit.
            })
            .ok()
    }

    fn build_from_single_attested_pk(
        cred_id: Uuid,
        pk: &AttestedPasskeyV4,
        att_ca_list: &AttestationCaList,
        webauthn: &Webauthn,
    ) -> Option<Self> {
        let creds = btreemap!((pk.clone(), cred_id));
        let pks = vec![pk.clone()];

        webauthn
            .start_attested_passkey_authentication(pks.as_slice())
            .map(|(chal, wan_state)| CredHandler::AttestedPasskey {
                c_wan: CredAttestedPasskey {
                    chal,
                    wan_state,
                    state: CredVerifyState::Init,
                },
                att_ca_list: att_ca_list.clone(),
                creds,
            })
            .map_err(|e| {
                security_info!(
                    ?e,
                    "Unable to create attested passkey webauthn authentication challenge"
                );
                // maps to unit.
            })
            .ok()
    }

    fn build_from_password_totp(cred: &Credential) -> Option<Self> {
        match &cred.type_ {
            CredentialType::PasswordMfa(pw, maybe_totp, _, _) => {
                if maybe_totp.is_empty() {
                    None
                } else {
                    let cmfa = CredTotp {
                        pw: pw.clone(),
                        pw_state: CredVerifyState::Init,
                        totp: maybe_totp
                            .iter()
                            .map(|(l, t)| (l.clone(), t.clone()))
                            .collect(),
                        mfa_state: CredVerifyState::Init,
                    };

                    Some(CredHandler::PasswordTotp {
                        cmfa,
                        cred_id: cred.uuid,
                    })
                }
            }
            _ => None,
        }
    }

    fn build_from_password_backup_code(cred: &Credential) -> Option<Self> {
        match &cred.type_ {
            CredentialType::PasswordMfa(pw, _, _, Some(backup_code)) => {
                let cmfa = CredBackupCode {
                    pw: pw.clone(),
                    pw_state: CredVerifyState::Init,
                    backup_code: backup_code.clone(),
                    mfa_state: CredVerifyState::Init,
                };

                Some(CredHandler::PasswordBackupCode {
                    cmfa,
                    cred_id: cred.uuid,
                })
            }
            _ => None,
        }
    }

    fn build_from_password_security_key(cred: &Credential, webauthn: &Webauthn) -> Option<Self> {
        match &cred.type_ {
            CredentialType::PasswordMfa(pw, _, maybe_wan, _) => {
                if !maybe_wan.is_empty() {
                    let sks: Vec<_> = maybe_wan.values().cloned().collect();
                    let (chal, ska) = webauthn
                        .start_securitykey_authentication(&sks)
                        .map_err(|err| {
                            warn!(?err, "Unable to create webauthn authentication challenge")
                        })
                        .ok()?;

                    let cmfa = CredSecurityKey {
                        pw: pw.clone(),
                        pw_state: CredVerifyState::Init,
                        ska,
                        chal,
                        mfa_state: CredVerifyState::Init,
                    };

                    Some(CredHandler::PasswordSecurityKey {
                        cmfa,
                        cred_id: cred.uuid,
                    })
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    fn build_from_password_only(cred: &Credential) -> Option<Self> {
        match &cred.type_ {
            CredentialType::Password(pw) => Some(CredHandler::Password {
                pw: pw.clone(),
                generated: false,
                cred_id: cred.uuid,
            }),
            CredentialType::GeneratedPassword(pw) => Some(CredHandler::Password {
                pw: pw.clone(),
                generated: true,
                cred_id: cred.uuid,
            }),
            _ => None,
        }
    }

    /// Determine if this password factor requires an upgrade of it's cryptographic type. If
    /// so, send an asynchronous event into the queue that will allow the password to have it's
    /// content upgraded later.
    fn maybe_pw_upgrade(
        pw: &Password,
        who: Uuid,
        cleartext: &str,
        async_tx: &Sender<DelayedAction>,
    ) {
        if pw.requires_upgrade() {
            if let Err(_e) = async_tx.send(DelayedAction::PwUpgrade(PasswordUpgrade {
                target_uuid: who,
                existing_password: cleartext.to_string(),
            })) {
                admin_warn!("unable to queue delayed pwupgrade, continuing ... ");
            };
        }
    }

    /// validate that the client wants to authenticate as the anonymous user.
    fn validate_anonymous(cred: &AuthCredential, cred_id: Uuid) -> CredState {
        match cred {
            AuthCredential::Anonymous => {
                // For anonymous, no claims will ever be issued.
                security_debug!("Handler::Anonymous -> Result::Success");
                CredState::Success {
                    auth_type: AuthType::Anonymous,
                    cred_id,
                }
            }
            _ => {
                security_error!(
                    "Handler::Anonymous -> Result::Denied - invalid cred type for handler"
                );
                CredState::Denied(BAD_AUTH_TYPE_MSG)
            }
        }
    }

    /// Validate a single password credential of the account.
    fn validate_password(
        cred: &AuthCredential,
        cred_id: Uuid,
        pw: &mut Password,
        generated: bool,
        who: Uuid,
        async_tx: &Sender<DelayedAction>,
        pw_badlist_set: &HashSet<String>,
    ) -> CredState {
        match cred {
            AuthCredential::Password(cleartext) => {
                if pw.verify(cleartext.as_str()).unwrap_or(false) {
                    if pw_badlist_set.contains(&cleartext.to_lowercase()) {
                        security_error!("Handler::Password -> Result::Denied - Password found in badlist during login");
                        CredState::Denied(PW_BADLIST_MSG)
                    } else {
                        security_info!("Handler::Password -> Result::Success");
                        Self::maybe_pw_upgrade(pw, who, cleartext.as_str(), async_tx);
                        if generated {
                            CredState::Success {
                                auth_type: AuthType::GeneratedPassword,
                                cred_id,
                            }
                        } else {
                            CredState::Success {
                                auth_type: AuthType::Password,
                                cred_id,
                            }
                        }
                    }
                } else {
                    security_error!("Handler::Password -> Result::Denied - incorrect password");
                    CredState::Denied(BAD_PASSWORD_MSG)
                }
            }
            // All other cases fail.
            _ => {
                security_error!(
                    "Handler::Password -> Result::Denied - invalid cred type for handler"
                );
                CredState::Denied(BAD_AUTH_TYPE_MSG)
            }
        }
    }

    /// Proceed with the next step in a multifactor authentication, based on the current
    /// verification results and state. If this logic of this statemachine is violated, the
    /// authentication will fail.
    fn validate_password_totp(
        cred: &AuthCredential,
        cred_id: Uuid,
        ts: Duration,
        pw_mfa: &mut CredTotp,
        who: Uuid,
        async_tx: &Sender<DelayedAction>,
        pw_badlist_set: &HashSet<String>,
    ) -> CredState {
        match (&pw_mfa.mfa_state, &pw_mfa.pw_state) {
            (CredVerifyState::Init, CredVerifyState::Init) => {
                // MFA first
                match cred {
                    AuthCredential::Totp(totp_chal) => {
                        // So long as one totp matches, success. Log which token was used.
                        // We don't need to worry about the empty case since none will match and we
                        // will get the failure.
                        if let Some(label) = pw_mfa
                            .totp
                            .iter()
                            .find(|(_, t)| t.verify(*totp_chal, ts))
                            .map(|(l, _)| l)
                        {
                            pw_mfa.mfa_state = CredVerifyState::Success;
                            security_info!(
                                "Handler::PasswordMfa -> Result::Continue - TOTP ({}) OK, password -", label
                            );
                            CredState::Continue(Box::new(NonEmpty {
                                head: AuthAllowed::Password,
                                tail: Vec::with_capacity(0),
                            }))
                        } else {
                            pw_mfa.mfa_state = CredVerifyState::Fail;
                            security_error!(
                                "Handler::PasswordMfa -> Result::Denied - TOTP Fail, password -"
                            );
                            CredState::Denied(BAD_TOTP_MSG)
                        }
                    }
                    _ => {
                        security_error!("Handler::PasswordMfa -> Result::Denied - invalid cred type for handler");
                        CredState::Denied(BAD_AUTH_TYPE_MSG)
                    }
                }
            }
            (CredVerifyState::Success, CredVerifyState::Init) => {
                // PW second.
                match cred {
                    AuthCredential::Password(cleartext) => {
                        if pw_mfa.pw.verify(cleartext.as_str()).unwrap_or(false) {
                            if pw_badlist_set.contains(&cleartext.to_lowercase()) {
                                pw_mfa.pw_state = CredVerifyState::Fail;
                                security_error!("Handler::PasswordMfa -> Result::Denied - Password found in badlist during login");
                                CredState::Denied(PW_BADLIST_MSG)
                            } else {
                                pw_mfa.pw_state = CredVerifyState::Success;
                                security_info!("Handler::PasswordMfa -> Result::Success - TOTP OK, password OK");
                                Self::maybe_pw_upgrade(
                                    &pw_mfa.pw,
                                    who,
                                    cleartext.as_str(),
                                    async_tx,
                                );
                                CredState::Success {
                                    auth_type: AuthType::PasswordTotp,
                                    cred_id,
                                }
                            }
                        } else {
                            pw_mfa.pw_state = CredVerifyState::Fail;
                            security_error!(
                                "Handler::PasswordMfa -> Result::Denied - TOTP OK, password Fail"
                            );
                            CredState::Denied(BAD_PASSWORD_MSG)
                        }
                    }
                    _ => {
                        security_error!("Handler::PasswordMfa -> Result::Denied - invalid cred type for handler");
                        CredState::Denied(BAD_AUTH_TYPE_MSG)
                    }
                }
            }
            _ => {
                security_error!(
                    "Handler::PasswordMfa -> Result::Denied - invalid credential mfa and pw state"
                );
                CredState::Denied(BAD_AUTH_TYPE_MSG)
            }
        }
    } // end CredHandler::PasswordTotp

    /// Proceed with the next step in a multifactor authentication, based on the current
    /// verification results and state. If this logic of this statemachine is violated, the
    /// authentication will fail.
    fn validate_password_security_key(
        cred: &AuthCredential,
        cred_id: Uuid,
        pw_mfa: &mut CredSecurityKey,
        webauthn: &Webauthn,
        who: Uuid,
        async_tx: &Sender<DelayedAction>,
        pw_badlist_set: &HashSet<String>,
    ) -> CredState {
        match (&pw_mfa.mfa_state, &pw_mfa.pw_state) {
            (CredVerifyState::Init, CredVerifyState::Init) => {
                // MFA first
                match cred {
                    AuthCredential::SecurityKey(resp) => {
                        match webauthn.finish_securitykey_authentication(resp, &pw_mfa.ska) {
                            Ok(auth_result) => {
                                pw_mfa.mfa_state = CredVerifyState::Success;
                                // Success. Determine if we need to update the counter
                                // async from r.
                                if auth_result.needs_update() {
                                    // Do async
                                    if let Err(_e) =
                                        async_tx.send(DelayedAction::WebauthnCounterIncrement(
                                            WebauthnCounterIncrement {
                                                target_uuid: who,
                                                auth_result,
                                            },
                                        ))
                                    {
                                        admin_warn!("unable to queue delayed webauthn property update, continuing ... ");
                                    };
                                };
                                CredState::Continue(Box::new(NonEmpty {
                                    head: AuthAllowed::Password,
                                    tail: Vec::with_capacity(0),
                                }))
                            }
                            Err(e) => {
                                pw_mfa.mfa_state = CredVerifyState::Fail;
                                // Denied.
                                security_error!(
                                    ?e,
                                    "Handler::Webauthn -> Result::Denied - webauthn error"
                                );
                                CredState::Denied(BAD_WEBAUTHN_MSG)
                            }
                        }
                    }
                    _ => {
                        security_error!("Handler::PasswordMfa -> Result::Denied - invalid cred type for handler");
                        CredState::Denied(BAD_AUTH_TYPE_MSG)
                    }
                }
            }
            (CredVerifyState::Success, CredVerifyState::Init) => {
                // PW second.
                match cred {
                    AuthCredential::Password(cleartext) => {
                        if pw_mfa.pw.verify(cleartext.as_str()).unwrap_or(false) {
                            if pw_badlist_set.contains(&cleartext.to_lowercase()) {
                                pw_mfa.pw_state = CredVerifyState::Fail;
                                security_error!("Handler::PasswordMfa -> Result::Denied - Password found in badlist during login");
                                CredState::Denied(PW_BADLIST_MSG)
                            } else {
                                pw_mfa.pw_state = CredVerifyState::Success;
                                security_info!("Handler::PasswordMfa -> Result::Success - SecurityKey OK, password OK");
                                Self::maybe_pw_upgrade(
                                    &pw_mfa.pw,
                                    who,
                                    cleartext.as_str(),
                                    async_tx,
                                );
                                CredState::Success {
                                    auth_type: AuthType::PasswordSecurityKey,
                                    cred_id,
                                }
                            }
                        } else {
                            pw_mfa.pw_state = CredVerifyState::Fail;
                            security_error!("Handler::PasswordMfa -> Result::Denied - SecurityKey OK, password Fail");
                            CredState::Denied(BAD_PASSWORD_MSG)
                        }
                    }
                    _ => {
                        security_error!("Handler::PasswordMfa -> Result::Denied - invalid cred type for handler");
                        CredState::Denied(BAD_AUTH_TYPE_MSG)
                    }
                }
            }
            _ => {
                security_error!(
                    "Handler::PasswordMfa -> Result::Denied - invalid credential mfa and pw state"
                );
                CredState::Denied(BAD_AUTH_TYPE_MSG)
            }
        }
    }

    /// Proceed with the next step in a multifactor authentication, based on the current
    /// verification results and state. If this logic of this statemachine is violated, the
    /// authentication will fail.
    fn validate_password_backup_code(
        cred: &AuthCredential,
        cred_id: Uuid,
        pw_mfa: &mut CredBackupCode,
        who: Uuid,
        async_tx: &Sender<DelayedAction>,
        pw_badlist_set: &HashSet<String>,
    ) -> CredState {
        match (&pw_mfa.mfa_state, &pw_mfa.pw_state) {
            (CredVerifyState::Init, CredVerifyState::Init) => {
                // MFA first
                match cred {
                    AuthCredential::BackupCode(code_chal) => {
                        if pw_mfa.backup_code.verify(code_chal) {
                            if let Err(_e) =
                                async_tx.send(DelayedAction::BackupCodeRemoval(BackupCodeRemoval {
                                    target_uuid: who,
                                    code_to_remove: code_chal.to_string(),
                                }))
                            {
                                admin_warn!(
                                    "unable to queue delayed backup code removal, continuing ... "
                                );
                            };
                            pw_mfa.mfa_state = CredVerifyState::Success;
                            security_info!("Handler::PasswordMfa -> Result::Continue - BackupCode OK, password -");
                            CredState::Continue(Box::new(NonEmpty {
                                head: AuthAllowed::Password,
                                tail: Vec::with_capacity(0),
                            }))
                        } else {
                            pw_mfa.mfa_state = CredVerifyState::Fail;
                            security_error!("Handler::PasswordMfa -> Result::Denied - BackupCode Fail, password -");
                            CredState::Denied(BAD_BACKUPCODE_MSG)
                        }
                    }
                    _ => {
                        security_error!("Handler::PasswordMfa -> Result::Denied - invalid cred type for handler");
                        CredState::Denied(BAD_AUTH_TYPE_MSG)
                    }
                }
            }
            (CredVerifyState::Success, CredVerifyState::Init) => {
                // PW second.
                match cred {
                    AuthCredential::Password(cleartext) => {
                        if pw_mfa.pw.verify(cleartext.as_str()).unwrap_or(false) {
                            if pw_badlist_set.contains(&cleartext.to_lowercase()) {
                                pw_mfa.pw_state = CredVerifyState::Fail;
                                security_error!("Handler::PasswordMfa -> Result::Denied - Password found in badlist during login");
                                CredState::Denied(PW_BADLIST_MSG)
                            } else {
                                pw_mfa.pw_state = CredVerifyState::Success;
                                security_info!("Handler::PasswordMfa -> Result::Success - BackupCode OK, password OK");
                                Self::maybe_pw_upgrade(
                                    &pw_mfa.pw,
                                    who,
                                    cleartext.as_str(),
                                    async_tx,
                                );
                                CredState::Success {
                                    auth_type: AuthType::PasswordBackupCode,
                                    cred_id,
                                }
                            }
                        } else {
                            pw_mfa.pw_state = CredVerifyState::Fail;
                            security_error!("Handler::PasswordMfa -> Result::Denied - BackupCode OK, password Fail");
                            CredState::Denied(BAD_PASSWORD_MSG)
                        }
                    }
                    _ => {
                        security_error!("Handler::PasswordMfa -> Result::Denied - invalid cred type for handler");
                        CredState::Denied(BAD_AUTH_TYPE_MSG)
                    }
                }
            }
            _ => {
                security_error!(
                    "Handler::PasswordMfa -> Result::Denied - invalid credential mfa and pw state"
                );
                CredState::Denied(BAD_AUTH_TYPE_MSG)
            }
        }
    }

    /// Validate a webauthn authentication attempt
    pub fn validate_passkey(
        cred: &AuthCredential,
        cred_ids: &BTreeMap<CredentialID, Uuid>,
        wan_cred: &mut CredPasskey,
        webauthn: &Webauthn,
        who: Uuid,
        async_tx: &Sender<DelayedAction>,
    ) -> CredState {
        if wan_cred.state != CredVerifyState::Init {
            security_error!("Handler::Webauthn -> Result::Denied - Internal State Already Fail");
            return CredState::Denied(BAD_WEBAUTHN_MSG);
        }

        match cred {
            AuthCredential::Passkey(resp) => {
                // lets see how we go.
                match webauthn.finish_passkey_authentication(resp, &wan_cred.wan_state) {
                    Ok(auth_result) => {
                        if let Some(cred_id) = cred_ids.get(auth_result.cred_id()).copied() {
                            wan_cred.state = CredVerifyState::Success;
                            // Success. Determine if we need to update the counter
                            // async from r.
                            if auth_result.needs_update() {
                                // Do async
                                if let Err(_e) =
                                    async_tx.send(DelayedAction::WebauthnCounterIncrement(
                                        WebauthnCounterIncrement {
                                            target_uuid: who,
                                            auth_result,
                                        },
                                    ))
                                {
                                    admin_warn!("unable to queue delayed webauthn property update, continuing ... ");
                                };
                            };

                            CredState::Success {
                                auth_type: AuthType::Passkey,
                                cred_id,
                            }
                        } else {
                            wan_cred.state = CredVerifyState::Fail;
                            // Denied.
                            security_error!("Handler::Webauthn -> Result::Denied - webauthn credential id not found");
                            CredState::Denied(BAD_WEBAUTHN_MSG)
                        }
                    }
                    Err(e) => {
                        wan_cred.state = CredVerifyState::Fail;
                        // Denied.
                        security_error!(?e, "Handler::Webauthn -> Result::Denied - webauthn error");
                        CredState::Denied(BAD_WEBAUTHN_MSG)
                    }
                }
            }
            _ => {
                security_error!(
                    "Handler::Webauthn -> Result::Denied - invalid cred type for handler"
                );
                CredState::Denied(BAD_AUTH_TYPE_MSG)
            }
        }
    }

    /// Validate a webauthn authentication attempt
    pub fn validate_attested_passkey(
        cred: &AuthCredential,
        creds: &BTreeMap<AttestedPasskeyV4, Uuid>,
        wan_cred: &mut CredAttestedPasskey,
        webauthn: &Webauthn,
        who: Uuid,
        async_tx: &Sender<DelayedAction>,
        att_ca_list: &AttestationCaList,
    ) -> CredState {
        if wan_cred.state != CredVerifyState::Init {
            security_error!("Handler::Webauthn -> Result::Denied - Internal State Already Fail");
            return CredState::Denied(BAD_WEBAUTHN_MSG);
        }

        match cred {
            AuthCredential::Passkey(resp) => {
                // lets see how we go.
                match webauthn.finish_attested_passkey_authentication(resp, &wan_cred.wan_state) {
                    Ok(auth_result) => {
                        if let Some((apk, cred_id)) = creds.get_key_value(auth_result.cred_id()) {
                            // Verify attestation of the key.

                            if let Err(webauthn_err) = apk.verify_attestation(att_ca_list) {
                                wan_cred.state = CredVerifyState::Fail;
                                // Denied.
                                debug!(?webauthn_err);
                                security_error!("Handler::Webauthn -> Result::Denied - webauthn credential fails attestation");
                                return CredState::Denied(BAD_ACCOUNT_POLICY);
                            }

                            wan_cred.state = CredVerifyState::Success;
                            // Success. Determine if we need to update the counter
                            // async from r.
                            if auth_result.needs_update() {
                                // Do async
                                if let Err(_e) =
                                    async_tx.send(DelayedAction::WebauthnCounterIncrement(
                                        WebauthnCounterIncrement {
                                            target_uuid: who,
                                            auth_result,
                                        },
                                    ))
                                {
                                    admin_warn!("unable to queue delayed webauthn property update, continuing ... ");
                                };
                            };

                            CredState::Success {
                                auth_type: AuthType::AttestedPasskey,
                                cred_id: *cred_id,
                            }
                        } else {
                            wan_cred.state = CredVerifyState::Fail;
                            // Denied.
                            security_error!("Handler::Webauthn -> Result::Denied - webauthn credential id not found");
                            CredState::Denied(BAD_WEBAUTHN_MSG)
                        }
                    }
                    Err(e) => {
                        wan_cred.state = CredVerifyState::Fail;
                        // Denied.
                        security_error!(?e, "Handler::Webauthn -> Result::Denied - webauthn error");
                        CredState::Denied(BAD_WEBAUTHN_MSG)
                    }
                }
            }
            _ => {
                security_error!(
                    "Handler::Webauthn -> Result::Denied - invalid cred type for handler"
                );
                CredState::Denied(BAD_AUTH_TYPE_MSG)
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    /// Given the current handler, proceed to authenticate the attempted credential step.
    pub fn validate(
        &mut self,
        cred: &AuthCredential,
        ts: Duration,
        who: Uuid,
        async_tx: &Sender<DelayedAction>,
        webauthn: &Webauthn,
        pw_badlist_set: &HashSet<String>,
    ) -> CredState {
        match self {
            CredHandler::Anonymous { cred_id } => Self::validate_anonymous(cred, *cred_id),
            CredHandler::Password {
                ref mut pw,
                generated,
                cred_id,
            } => Self::validate_password(
                cred,
                *cred_id,
                pw,
                *generated,
                who,
                async_tx,
                pw_badlist_set,
            ),
            CredHandler::PasswordTotp {
                ref mut cmfa,
                cred_id,
            } => Self::validate_password_totp(
                cred,
                *cred_id,
                ts,
                cmfa,
                who,
                async_tx,
                pw_badlist_set,
            ),
            CredHandler::PasswordBackupCode {
                ref mut cmfa,
                cred_id,
            } => Self::validate_password_backup_code(
                cred,
                *cred_id,
                cmfa,
                who,
                async_tx,
                pw_badlist_set,
            ),
            CredHandler::PasswordSecurityKey {
                ref mut cmfa,
                cred_id,
            } => Self::validate_password_security_key(
                cred,
                *cred_id,
                cmfa,
                webauthn,
                who,
                async_tx,
                pw_badlist_set,
            ),
            CredHandler::Passkey {
                ref mut c_wan,
                cred_ids,
            } => Self::validate_passkey(cred, cred_ids, c_wan, webauthn, who, async_tx),
            CredHandler::AttestedPasskey {
                ref mut c_wan,
                ref att_ca_list,
                creds,
            } => Self::validate_attested_passkey(
                cred,
                creds,
                c_wan,
                webauthn,
                who,
                async_tx,
                att_ca_list,
            ),
        }
    }

    /// Determine based on the current status, what is the next allowed step that
    /// can proceed.
    pub fn next_auth_allowed(&self) -> Vec<AuthAllowed> {
        match &self {
            CredHandler::Anonymous { .. } => vec![AuthAllowed::Anonymous],
            CredHandler::Password { .. } => vec![AuthAllowed::Password],
            CredHandler::PasswordTotp { .. } => vec![AuthAllowed::Totp],
            CredHandler::PasswordBackupCode { .. } => vec![AuthAllowed::BackupCode],

            CredHandler::PasswordSecurityKey { ref cmfa, .. } => {
                vec![AuthAllowed::SecurityKey(cmfa.chal.clone())]
            }
            CredHandler::Passkey { c_wan, .. } => vec![AuthAllowed::Passkey(c_wan.chal.clone())],
            CredHandler::AttestedPasskey { c_wan, .. } => {
                vec![AuthAllowed::Passkey(c_wan.chal.clone())]
            }
        }
    }

    /// Determine which mechanismes can proceed given the requested mechanism.
    fn can_proceed(&self, mech: &AuthMech) -> bool {
        match (self, mech) {
            (CredHandler::Anonymous { .. }, AuthMech::Anonymous)
            | (CredHandler::Password { .. }, AuthMech::Password)
            | (CredHandler::PasswordTotp { .. }, AuthMech::PasswordTotp)
            | (CredHandler::PasswordBackupCode { .. }, AuthMech::PasswordBackupCode)
            | (CredHandler::PasswordSecurityKey { .. }, AuthMech::PasswordSecurityKey)
            | (CredHandler::Passkey { .. }, AuthMech::Passkey)
            | (CredHandler::AttestedPasskey { .. }, AuthMech::Passkey) => true,
            (_, _) => false,
        }
    }

    fn allows_mech(&self) -> AuthMech {
        match self {
            CredHandler::Anonymous { .. } => AuthMech::Anonymous,
            CredHandler::Password { .. } => AuthMech::Password,
            CredHandler::PasswordTotp { .. } => AuthMech::PasswordTotp,
            CredHandler::PasswordBackupCode { .. } => AuthMech::PasswordBackupCode,
            CredHandler::PasswordSecurityKey { .. } => AuthMech::PasswordSecurityKey,
            CredHandler::Passkey { .. } => AuthMech::Passkey,
            CredHandler::AttestedPasskey { .. } => AuthMech::Passkey,
        }
    }
}

#[allow(clippy::large_enum_variant)]
#[derive(Clone)]
/// This interleaves with the client auth step. The client sends an "init"
/// and we go to the init state, sending back the list of what can proceed.
/// The client then sends a "begin" with the chosen mech that moves to
/// "InProgress", "Success" or "Denied". From there the CredHandler
/// is interacted with until we move to either "Success" or "Denied".
enum AuthSessionState {
    Init(NonEmpty<CredHandler>),
    // Stop! Don't make this a vec - make the credhandler able to hold multiple
    // internal copies of it's type and check against them all.
    //
    // Clippy wants this to be boxxed, however match on box types is a pain / problematic,
    // so I'm not sure it can be done.
    InProgress(CredHandler),
    Success,
    Denied(&'static str),
}

impl AuthSessionState {
    fn is_denied(&self) -> Option<&'static str> {
        match &self {
            AuthSessionState::Denied(x) => Some(x),
            _ => None,
        }
    }
}

pub(crate) struct AuthSessionData<'a> {
    pub(crate) account: Account,
    pub(crate) account_policy: ResolvedAccountPolicy,
    pub(crate) issue: AuthIssueSession,
    pub(crate) webauthn: &'a Webauthn,
    pub(crate) ct: Duration,
    pub(crate) client_auth_info: ClientAuthInfo,
}

#[derive(Clone)]
/// The current state of an authentication session that is in progress.
pub(crate) struct AuthSession {
    // Do we store a copy of the entry?
    // How do we know what claims to add?
    account: Account,
    // This policies that apply to this account
    account_policy: ResolvedAccountPolicy,

    // Store how we plan to handle this sessions authentication: this is generally
    // made apparent by the presentation of an application id or not. If none is presented
    // we want the primary-interaction credentials.
    //
    // This handler will then handle the mfa and stepping up through to generate the auth states
    state: AuthSessionState,

    // The type of session we will issue if successful
    issue: AuthIssueSession,

    // What is the "intent" behind this auth session? Are we doing an initial auth? Or a re-auth
    // for a privilege grant?
    intent: AuthIntent,

    // Where did the event come from?
    source: Source,

    // The cryptographic provider to encrypt or sign anything in this operation.
    key_object: Arc<KeyObject>,
}

impl AuthSession {
    /// Create a new auth session, based on the available credential handlers of the account.
    /// the session is a whole encapsulated unit of what we need to proceed, so that subsequent
    /// or interleved write operations do not cause inconsistency in this process.
    pub fn new(
        asd: AuthSessionData<'_>,
        privileged: bool,
        key_object: Arc<KeyObject>,
    ) -> (Option<Self>, AuthState) {
        // During this setup, determine the credential handler that we'll be using
        // for this session. This is currently based on presentation of an application
        // id.
        let state = if asd.account.is_within_valid_time(asd.ct) {
            // We want the primary handler - this is where we make a decision
            // based on the anonymous ... in theory this could be cleaner
            // and interact with the account more?
            if asd.account.is_anonymous() {
                AuthSessionState::Init(NonEmpty {
                    head: CredHandler::Anonymous {
                        cred_id: asd.account.uuid,
                    },
                    tail: Vec::with_capacity(0),
                })
            } else {
                let mut handlers = Vec::with_capacity(4);

                // TODO: We can't yet fully enforce account policy on auth, there is a bit of work
                // to do to be able to check for pw / mfa etc.
                // A possible gotcha is service accounts which can't be affected by these policies?

                // let cred_type_min = asd.account_policy.credential_policy();

                if let Some(cred) = &asd.account.primary {
                    // Is it a pw-only credential?
                    if let Some(ch) = CredHandler::build_from_password_totp(cred) {
                        handlers.push(ch);
                    }

                    if let Some(ch) = CredHandler::build_from_password_backup_code(cred) {
                        handlers.push(ch);
                    }

                    if let Some(ch) =
                        CredHandler::build_from_password_security_key(cred, asd.webauthn)
                    {
                        handlers.push(ch);
                    }

                    if handlers.is_empty() {
                        // No MFA types were setup, allow the PW only to proceed then.
                        if let Some(ch) = CredHandler::build_from_password_only(cred) {
                            handlers.push(ch);
                        }
                    }
                }

                trace!(?handlers);

                // Important - if attested is present, don't use passkeys
                if let Some(att_ca_list) = asd.account_policy.webauthn_attestation_ca_list() {
                    if let Some(ch) = CredHandler::build_from_set_attested_pk(
                        &asd.account.attested_passkeys,
                        att_ca_list,
                        asd.webauthn,
                    ) {
                        handlers.push(ch);
                    }
                } else {
                    let credential_iter = asd
                        .account
                        .passkeys
                        .iter()
                        .map(|(u, (_, pk))| (*u, pk.clone()))
                        .chain(
                            asd.account
                                .attested_passkeys
                                .iter()
                                .map(|(u, (_, pk))| (*u, pk.into())),
                        );

                    if let Some(ch) =
                        CredHandler::build_from_set_passkey(credential_iter, asd.webauthn)
                    {
                        handlers.push(ch);
                    }
                };

                if let Some(non_empty_handlers) = NonEmpty::collect(handlers) {
                    AuthSessionState::Init(non_empty_handlers)
                } else {
                    security_info!("account has no available credentials");
                    AuthSessionState::Denied("invalid credential state")
                }
            }
        } else {
            security_info!("account expired");
            AuthSessionState::Denied(ACCOUNT_EXPIRED)
        };

        // if credhandler == deny, finish = true.
        if let Some(reason) = state.is_denied() {
            // Already denied, lets send that result
            (None, AuthState::Denied(reason.to_string()))
        } else {
            // We can proceed
            let auth_session = AuthSession {
                account: asd.account,
                account_policy: asd.account_policy,
                state,
                issue: asd.issue,
                intent: AuthIntent::InitialAuth { privileged },
                source: asd.client_auth_info.source,
                key_object,
            };
            // Get the set of mechanisms that can proceed. This is tied
            // to the session so that it can mutate state and have progression
            // of what's next, or ordering.
            let valid_mechs = auth_session.valid_auth_mechs();

            security_debug!(?valid_mechs, "Offering auth mechanisms");
            let as_state = AuthState::Choose(valid_mechs);
            (Some(auth_session), as_state)
        }
    }

    /// Build a new auth session which has been preconfigured for re-authentication.
    /// This differs from [`AuthSession::new`] as we preselect the credential that
    /// will be used in this operation based on the credential id that was used in the
    /// initial authentication.
    pub(crate) fn new_reauth(
        asd: AuthSessionData<'_>,
        session_id: Uuid,
        session: &Session,
        cred_id: Uuid,
        key_object: Arc<KeyObject>,
    ) -> (Option<Self>, AuthState) {
        #[allow(clippy::large_enum_variant)]
        /// An inner enum to allow us to more easily define state within this fn
        enum State {
            Expired,
            NoMatchingCred,
            Proceed(CredHandler),
        }

        let state = if asd.account.is_within_valid_time(asd.ct) {
            // Get the credential that matches this cred_id and auth type used in the
            // initial authentication.

            // We can't yet fully enforce account policy on auth, there is a bit of work
            // to do to be able to check the credential types match what we expect.

            let mut cred_handler = None;

            match session.type_ {
                AuthType::Password
                | AuthType::GeneratedPassword
                // If a backup code was used, since the code was scrubbed at use we need to
                // fall back to the password of the account instead.
                | AuthType::PasswordBackupCode => {
                    if let Some(primary) = asd.account.primary.as_ref() {
                        if primary.uuid == cred_id {
                            cred_handler = CredHandler::build_from_password_only(primary)
                        }
                    }
                }
                AuthType::PasswordTotp => {
                    if let Some(primary) = asd.account.primary.as_ref() {
                        if primary.uuid == cred_id {
                            cred_handler = CredHandler::build_from_password_totp(primary)
                        }
                    }
                }
                AuthType::PasswordSecurityKey => {
                    if let Some(primary) = asd.account.primary.as_ref() {
                        if primary.uuid == cred_id {
                            cred_handler =
                                CredHandler::build_from_password_security_key(primary, asd.webauthn)
                        }
                    }
                }
                AuthType::Passkey => {
                    // Scan both attested and passkeys for the possible credential.
                    let maybe_pk: Option<PasskeyV4> = asd
                        .account
                        .attested_passkeys
                        .get(&cred_id)
                        .map(|(_, apk)| apk.into())
                        .or_else(|| asd.account.passkeys.get(&cred_id).map(|(_, pk)| pk.clone()));

                    if let Some(pk) = maybe_pk {
                        if let Some(ch) =
                            CredHandler::build_from_single_passkey(cred_id, pk, asd.webauthn)
                        {
                            // Update it.
                            debug_assert!(cred_handler.is_none());
                            cred_handler = Some(ch);
                        } else {
                            security_critical!(
                                "corrupt credentials, unable to start passkey credhandler"
                            );
                        }
                    }
                }
                AuthType::AttestedPasskey => {
                    if let Some(att_ca_list) = asd.account_policy.webauthn_attestation_ca_list() {
                        if let Some(pk) = asd
                            .account
                            .attested_passkeys
                            .get(&cred_id)
                            .map(|(_, pk)| pk)
                        {
                            if let Some(ch) = CredHandler::build_from_single_attested_pk(
                                cred_id,
                                pk,
                                att_ca_list,
                                asd.webauthn,
                            ) {
                                // Update it.
                                debug_assert!(cred_handler.is_none());
                                cred_handler = Some(ch);
                            } else {
                                security_critical!(
                            "corrupt credentials, unable to start attested passkey credhandler"
                        );
                            }
                        }
                    }
                }
                AuthType::Anonymous => {}
            }

            // Did anything get set-up?

            if let Some(cred_handler) = cred_handler {
                State::Proceed(cred_handler)
            } else {
                State::NoMatchingCred
            }
        } else {
            State::Expired
        };

        let session_expiry = match session.state {
            SessionState::ExpiresAt(odt) => Some(odt),
            SessionState::NeverExpires => None,
            SessionState::RevokedAt(_) => {
                security_error!(
                    "Invalid State - Should not be possible to trigger re-auth on revoked session."
                );
                return (None, AuthState::Denied(ACCOUNT_EXPIRED.to_string()));
            }
        };

        match state {
            State::Proceed(handler) => {
                let allow = handler.next_auth_allowed();
                let auth_session = AuthSession {
                    account: asd.account,
                    account_policy: asd.account_policy,
                    state: AuthSessionState::InProgress(handler),
                    issue: asd.issue,
                    intent: AuthIntent::Reauth {
                        session_id,
                        session_expiry,
                    },
                    source: asd.client_auth_info.source,
                    key_object,
                };

                let as_state = AuthState::Continue(allow);
                (Some(auth_session), as_state)
            }
            State::Expired => {
                security_info!("account expired");
                (None, AuthState::Denied(ACCOUNT_EXPIRED.to_string()))
            }
            State::NoMatchingCred => {
                security_error!("Unable to select a credential for authentication");
                (None, AuthState::Denied(BAD_CREDENTIALS.to_string()))
            }
        }
    }

    /// If the credential class can be softlocked, retrieve the credential ID. This is
    /// only used when a credential requires softlocking.
    pub fn get_credential_uuid(&self) -> Result<Option<Uuid>, OperationError> {
        match &self.state {
            AuthSessionState::InProgress(CredHandler::Password { cred_id, .. })
            | AuthSessionState::InProgress(CredHandler::PasswordTotp { cred_id, .. })
            | AuthSessionState::InProgress(CredHandler::PasswordBackupCode { cred_id, .. }) => {
                Ok(Some(*cred_id))
            }
            AuthSessionState::InProgress(CredHandler::Anonymous { .. })
            | AuthSessionState::InProgress(CredHandler::PasswordSecurityKey { .. })
            | AuthSessionState::InProgress(CredHandler::Passkey { .. })
            | AuthSessionState::InProgress(CredHandler::AttestedPasskey { .. }) => Ok(None),

            AuthSessionState::Init(_) => {
                debug!(
                    "Request for credential uuid invalid as auth session state not yet initialised"
                );
                Err(OperationError::AU0001InvalidState)
            }
            AuthSessionState::Success | AuthSessionState::Denied(_) => {
                debug!("Request for credential uuid invalid as auth session state has progressed");
                Err(OperationError::AU0001InvalidState)
            }
        }
    }

    /// Given the users indicated and preferred authentication mechanism that they want to proceed
    /// with, select the credential handler and begin the process of stepping through the
    /// authentication process.
    pub fn start_session(
        &mut self,
        mech: &AuthMech,
        // time: &Duration,
        // webauthn: &WebauthnCore,
    ) -> Result<AuthState, OperationError> {
        // Given some auth mech, select which credential(s) are appropriate
        // and attempt to use them.

        // Today we only select one, but later we could have *multiple* that
        // match the selector.
        let (next_state, response) = match &mut self.state {
            AuthSessionState::Success
            | AuthSessionState::Denied(_)
            | AuthSessionState::InProgress(_) => (
                None,
                Err(OperationError::InvalidAuthState(
                    "session already finalised!".to_string(),
                )),
            ),
            AuthSessionState::Init(handlers) => {
                // Which handlers are relevant?
                let mut allowed_handlers: Vec<_> = handlers
                    .iter()
                    .filter(|ch| ch.can_proceed(mech))
                    .cloned()
                    .collect();

                if let Some(allowed_handler) = allowed_handlers.pop() {
                    let allowed: Vec<_> = allowed_handler.next_auth_allowed();

                    if allowed.is_empty() {
                        security_info!("Unable to negotiate credentials");
                        (
                            None,
                            Err(OperationError::InvalidAuthState(
                                "unable to negotiate credentials".to_string(),
                            )),
                        )
                    } else {
                        (
                            Some(AuthSessionState::InProgress(allowed_handler)),
                            Ok(AuthState::Continue(allowed)),
                        )
                    }
                } else {
                    security_error!("Unable to select a credential for authentication");
                    (
                        Some(AuthSessionState::Denied(BAD_CREDENTIALS)),
                        Ok(AuthState::Denied(BAD_CREDENTIALS.to_string())),
                    )
                }
            }
        };

        if let Some(mut next_state) = next_state {
            std::mem::swap(&mut self.state, &mut next_state);
        };

        response
    }

    /// Conduct a step of the authentication process. This validates the next credential factor
    /// presented and returns a result of Success, Continue, or Denied. Only in the success
    /// case is a UAT granted -- all others do not, including raised operation errors.
    pub fn validate_creds(
        &mut self,
        cred: &AuthCredential,
        time: Duration,
        async_tx: &Sender<DelayedAction>,
        audit_tx: &Sender<AuditEvent>,
        webauthn: &Webauthn,
        pw_badlist: &HashSet<String>,
    ) -> Result<AuthState, OperationError> {
        let (next_state, response) = match &mut self.state {
            AuthSessionState::Init(_) | AuthSessionState::Success | AuthSessionState::Denied(_) => {
                return Err(OperationError::InvalidAuthState(
                    "session already finalised!".to_string(),
                ));
            }
            AuthSessionState::InProgress(ref mut handler) => {
                match handler.validate(
                    cred,
                    time,
                    self.account.uuid,
                    async_tx,
                    webauthn,
                    pw_badlist,
                ) {
                    CredState::Success { auth_type, cred_id } => {
                        // Issue the uat based on a set of factors.
                        let uat = self.issue_uat(auth_type, time, async_tx, cred_id)?;

                        let jwt = Jws::into_json(&uat).map_err(|e| {
                            admin_error!(?e, "Failed to serialise into Jws");
                            OperationError::AU0002JwsSerialisation
                        })?;

                        // Now encrypt and prepare the token for return to the client.
                        let token = self.key_object.jws_es256_sign(&jwt, time).map_err(|e| {
                            admin_error!(?e, "Failed to sign UserAuthToken to Jwt");
                            OperationError::AU0003JwsSignature
                        })?;

                        (
                            Some(AuthSessionState::Success),
                            Ok(AuthState::Success(Box::new(token), self.issue)),
                        )
                    }
                    CredState::Continue(allowed) => {
                        security_info!(?allowed, "Request credential continuation");
                        (None, Ok(AuthState::Continue(allowed.into_iter().collect())))
                    }
                    CredState::Denied(reason) => {
                        if audit_tx
                            .send(AuditEvent::AuthenticationDenied {
                                source: self.source.clone().into(),
                                spn: self.account.spn.clone(),
                                uuid: self.account.uuid,
                                time: OffsetDateTime::UNIX_EPOCH + time,
                            })
                            .is_err()
                        {
                            error!("Unable to submit audit event to queue");
                        }
                        security_info!(%reason, "Credentials denied");
                        (
                            Some(AuthSessionState::Denied(reason)),
                            Ok(AuthState::Denied(reason.to_string())),
                        )
                    }
                }
            }
        };

        if let Some(mut next_state) = next_state {
            std::mem::swap(&mut self.state, &mut next_state);
        };

        // Also send an async message to self to log the auth as provided.
        // Alternately, open a write, and commit the needed security metadata here
        // now rather than async (probably better for lock-outs etc)
        //
        // TODO #59: Async message the account owner about the login?
        // If this fails, how can we in memory lock the account?
        //
        // The lockouts could also be an in-memory concept too?

        // If this succeeds audit?
        //  If success, to authtoken?

        response
    }

    fn issue_uat(
        &mut self,
        auth_type: AuthType,
        time: Duration,
        async_tx: &Sender<DelayedAction>,
        cred_id: Uuid,
    ) -> Result<UserAuthToken, OperationError> {
        security_debug!("Successful cred handling");
        match self.intent {
            AuthIntent::InitialAuth { privileged } => {
                let session_id = Uuid::new_v4();
                // We need to actually work this out better, and then
                // pass it to to_userauthtoken
                let scope = match auth_type {
                    AuthType::Anonymous => SessionScope::ReadOnly,
                    AuthType::GeneratedPassword => SessionScope::ReadWrite,
                    AuthType::Password
                    | AuthType::PasswordTotp
                    | AuthType::PasswordBackupCode
                    | AuthType::PasswordSecurityKey
                    | AuthType::Passkey
                    | AuthType::AttestedPasskey => {
                        if privileged {
                            SessionScope::ReadWrite
                        } else {
                            SessionScope::PrivilegeCapable
                        }
                    }
                };

                security_info!(
                    "Issuing {:?} session ({:?}) {} for {} {}",
                    self.issue,
                    scope,
                    session_id,
                    self.account.spn,
                    self.account.uuid
                );

                let uat = self
                    .account
                    .to_userauthtoken(session_id, scope, time, &self.account_policy)
                    .ok_or(OperationError::AU0004UserAuthTokenInvalid)?;

                // Queue the session info write.
                // This is dependent on the type of authentication factors
                // used. Generally we won't submit for Anonymous. Add an extra
                // safety barrier for auth types that shouldn't be here. Generally we
                // submit session info for everything else.
                match auth_type {
                    AuthType::Anonymous => {
                        // Skip - these sessions are not validated by session id.
                    }
                    AuthType::Password
                    | AuthType::GeneratedPassword
                    | AuthType::PasswordTotp
                    | AuthType::PasswordBackupCode
                    | AuthType::PasswordSecurityKey
                    | AuthType::Passkey
                    | AuthType::AttestedPasskey => {
                        trace!("⚠️   Queued AuthSessionRecord for {}", self.account.uuid);
                        async_tx.send(DelayedAction::AuthSessionRecord(AuthSessionRecord {
                            target_uuid: self.account.uuid,
                            session_id,
                            cred_id,
                            label: "Auth Session".to_string(),
                            expiry: uat.expiry,
                            issued_at: uat.issued_at,
                            issued_by: IdentityId::User(self.account.uuid),
                            scope,
                            type_: auth_type,
                        }))
                        .map_err(|e| {
                            debug!(?e, "queue failure");
                            admin_error!("unable to queue failing authentication as the session will not validate ... ");
                            OperationError::AU0005DelayedProcessFailure
                        })?;
                    }
                };

                Ok(uat)
            }
            AuthIntent::Reauth {
                session_id,
                session_expiry,
            } => {
                // Sanity check - We have already been really strict about what session types
                // can actually trigger a re-auth, but we recheck here for paranoia!
                let scope = match auth_type {
                    AuthType::Anonymous | AuthType::GeneratedPassword => {
                        error!("AuthType used in Reauth is not valid for session re-issuance. Rejecting");
                        return Err(OperationError::AU0006CredentialMayNotReauthenticate);
                    }
                    AuthType::Password
                    | AuthType::PasswordTotp
                    | AuthType::PasswordBackupCode
                    | AuthType::PasswordSecurityKey
                    | AuthType::Passkey
                    | AuthType::AttestedPasskey => SessionScope::PrivilegeCapable,
                };

                let uat = self
                    .account
                    .to_reissue_userauthtoken(
                        session_id,
                        session_expiry,
                        scope,
                        time,
                        &self.account_policy,
                    )
                    .ok_or(OperationError::AU0007UserAuthTokenInvalid)?;

                Ok(uat)
            }
        }
    }

    /// End the session, defaulting to a denied.
    pub fn end_session(&mut self, reason: &'static str) -> Result<AuthState, OperationError> {
        let mut next_state = AuthSessionState::Denied(reason);
        std::mem::swap(&mut self.state, &mut next_state);
        Ok(AuthState::Denied(reason.to_string()))
    }

    fn valid_auth_mechs(&self) -> Vec<AuthMech> {
        match &self.state {
            AuthSessionState::Success
            | AuthSessionState::Denied(_)
            | AuthSessionState::InProgress(_) => Vec::with_capacity(0),
            AuthSessionState::Init(handlers) => {
                // Iterate over the handlers into what mechs they are
                // and filter to unique?
                handlers.iter().map(|h| h.allows_mech()).collect()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use compact_jwt::{dangernoverify::JwsDangerReleaseWithoutVerify, JwsVerifier};
    use hashbrown::HashSet;
    use kanidm_proto::internal::{UatPurpose, UserAuthToken};
    use kanidm_proto::v1::{AuthAllowed, AuthCredential, AuthIssueSession, AuthMech};
    use tokio::sync::mpsc::unbounded_channel as unbounded;
    use webauthn_authenticator_rs::softpasskey::SoftPasskey;
    use webauthn_authenticator_rs::WebauthnAuthenticator;
    use webauthn_rs::prelude::{RequestChallengeResponse, Webauthn};

    use crate::credential::totp::{Totp, TOTP_DEFAULT_STEP};
    use crate::credential::{BackupCodes, Credential};
    use crate::idm::account::Account;
    use crate::idm::accountpolicy::ResolvedAccountPolicy;
    use crate::idm::audit::AuditEvent;
    use crate::idm::authsession::{
        AuthSession, AuthSessionData, BAD_AUTH_TYPE_MSG, BAD_BACKUPCODE_MSG, BAD_PASSWORD_MSG,
        BAD_TOTP_MSG, BAD_WEBAUTHN_MSG, PW_BADLIST_MSG,
    };
    use crate::idm::delayed::DelayedAction;
    use crate::idm::AuthState;
    use crate::migration_data::{BUILTIN_ACCOUNT_ANONYMOUS, BUILTIN_ACCOUNT_TEST_PERSON};
    use crate::prelude::*;
    use crate::server::keys::KeyObjectInternal;
    use crate::utils::readable_password_from_random;
    use kanidm_lib_crypto::CryptoPolicy;

    fn create_pw_badlist_cache() -> HashSet<String> {
        let mut s = HashSet::new();
        s.insert("list@no3IBTyqHu$bad".to_lowercase());
        s
    }

    fn create_webauthn() -> webauthn_rs::Webauthn {
        webauthn_rs::WebauthnBuilder::new(
            "example.com",
            &url::Url::parse("https://idm.example.com").unwrap(),
        )
        .and_then(|builder| builder.build())
        .unwrap()
    }

    #[test]
    fn test_idm_authsession_anonymous_auth_mech() {
        sketching::test_init();

        let webauthn = create_webauthn();

        let anon_account: Account = BUILTIN_ACCOUNT_ANONYMOUS.clone().into();

        let asd = AuthSessionData {
            account: anon_account,
            account_policy: ResolvedAccountPolicy::default(),
            issue: AuthIssueSession::Token,
            webauthn: &webauthn,
            ct: duration_from_epoch_now(),
            client_auth_info: Source::Internal.into(),
        };

        let key_object = KeyObjectInternal::new_test();
        let (session, state) = AuthSession::new(asd, false, key_object);
        if let AuthState::Choose(auth_mechs) = state {
            assert!(auth_mechs.iter().any(|x| matches!(x, AuthMech::Anonymous)));
        } else {
            panic!("Invalid auth state")
        }

        let state = session
            .expect("Missing auth session?")
            .start_session(&AuthMech::Anonymous)
            .expect("Failed to select anonymous mech.");

        if let AuthState::Continue(auth_mechs) = state {
            assert!(auth_mechs
                .iter()
                .any(|x| matches!(x, AuthAllowed::Anonymous)));
        } else {
            panic!("Invalid auth state")
        }
    }

    macro_rules! start_password_session {
        (
            $audit:expr,
            $account:expr,
            $webauthn:expr,
            $privileged:expr
        ) => {{
            let asd = AuthSessionData {
                account: $account.clone(),
                account_policy: ResolvedAccountPolicy::default(),
                issue: AuthIssueSession::Token,
                webauthn: $webauthn,
                ct: duration_from_epoch_now(),
                client_auth_info: Source::Internal.into(),
            };
            let key_object = KeyObjectInternal::new_test();
            let (session, state) = AuthSession::new(asd, $privileged, key_object);
            let mut session = session.unwrap();

            if let AuthState::Choose(auth_mechs) = state {
                assert!(auth_mechs.iter().any(|x| matches!(x, AuthMech::Password)));
            } else {
                panic!();
            }

            let state = session
                .start_session(&AuthMech::Password)
                .expect("Failed to select anonymous mech.");

            if let AuthState::Continue(auth_mechs) = state {
                assert!(auth_mechs
                    .iter()
                    .any(|x| matches!(x, AuthAllowed::Password)));
            } else {
                panic!("Invalid auth state")
            }

            (session, create_pw_badlist_cache())
        }};
    }

    fn start_session_simple_password_mech(privileged: bool) -> UserAuthToken {
        let webauthn = create_webauthn();
        // create the ent
        let mut account: Account = BUILTIN_ACCOUNT_TEST_PERSON.clone().into();
        // manually load in a cred
        let p = CryptoPolicy::minimum();
        let cred = Credential::new_password_only(&p, "test_password").unwrap();
        account.primary = Some(cred);

        let (async_tx, mut async_rx) = unbounded();
        let (audit_tx, mut audit_rx) = unbounded();

        // now check
        let (mut session, pw_badlist_cache) =
            start_password_session!(&mut audit, account, &webauthn, false);

        let attempt = AuthCredential::Password("bad_password".to_string());
        match session.validate_creds(
            &attempt,
            Duration::from_secs(0),
            &async_tx,
            &audit_tx,
            &webauthn,
            &pw_badlist_cache,
        ) {
            Ok(AuthState::Denied(_)) => {}
            _ => panic!(),
        };

        match audit_rx.try_recv() {
            Ok(AuditEvent::AuthenticationDenied { .. }) => {}
            _ => panic!("Oh no"),
        }

        // === Now begin a new session, and use a good pw.

        let (mut session, pw_badlist_cache) =
            start_password_session!(&mut audit, account, &webauthn, privileged);

        let attempt = AuthCredential::Password("test_password".to_string());
        let uat: UserAuthToken = match session.validate_creds(
            &attempt,
            Duration::from_secs(0),
            &async_tx,
            &audit_tx,
            &webauthn,
            &pw_badlist_cache,
        ) {
            Ok(AuthState::Success(jwsc, AuthIssueSession::Token)) => {
                let jws_verifier = JwsDangerReleaseWithoutVerify::default();

                jws_verifier
                    .verify(&*jwsc)
                    .unwrap()
                    .from_json::<UserAuthToken>()
                    .unwrap()
            }
            _ => panic!(),
        };

        match async_rx.blocking_recv() {
            Some(DelayedAction::AuthSessionRecord(_)) => {}
            _ => panic!("Oh no"),
        }

        drop(async_tx);
        assert!(async_rx.blocking_recv().is_none());
        drop(audit_tx);
        assert!(audit_rx.blocking_recv().is_none());

        uat
    }

    #[test]
    fn test_idm_authsession_simple_password_mech() {
        sketching::test_init();
        let uat = start_session_simple_password_mech(false);
        match uat.purpose {
            UatPurpose::ReadOnly => panic!("Unexpected UatPurpose::ReadOnly"),
            UatPurpose::ReadWrite { expiry } => {
                // Long lived RO session capable of reauth
                assert!(expiry.is_none())
            }
        }
    }

    #[test]
    fn test_idm_authsession_simple_password_mech_priv_shortcut() {
        sketching::test_init();
        let uat = start_session_simple_password_mech(true);
        match uat.purpose {
            UatPurpose::ReadOnly => panic!("Unexpected UatPurpose::ReadOnly"),
            UatPurpose::ReadWrite { expiry } => {
                // Short lived RW session
                assert!(expiry.is_some())
            }
        }
    }

    #[test]
    fn test_idm_authsession_simple_password_badlist() {
        sketching::test_init();
        let webauthn = create_webauthn();
        // create the ent
        let mut account: Account = BUILTIN_ACCOUNT_TEST_PERSON.clone().into();
        // manually load in a cred
        let p = CryptoPolicy::minimum();
        let cred = Credential::new_password_only(&p, "list@no3IBTyqHu$bad").unwrap();
        account.primary = Some(cred);

        let (async_tx, mut async_rx) = unbounded();
        let (audit_tx, mut audit_rx) = unbounded();

        // now check, even though the password is correct, Auth should be denied since it is in badlist
        let (mut session, pw_badlist_cache) =
            start_password_session!(&mut audit, account, &webauthn, false);

        let attempt = AuthCredential::Password("list@no3IBTyqHu$bad".to_string());
        match session.validate_creds(
            &attempt,
            Duration::from_secs(0),
            &async_tx,
            &audit_tx,
            &webauthn,
            &pw_badlist_cache,
        ) {
            Ok(AuthState::Denied(msg)) => assert_eq!(msg, PW_BADLIST_MSG),
            _ => panic!(),
        };

        match audit_rx.try_recv() {
            Ok(AuditEvent::AuthenticationDenied { .. }) => {}
            _ => panic!("Oh no"),
        }

        drop(async_tx);
        assert!(async_rx.blocking_recv().is_none());
        drop(audit_tx);
        assert!(audit_rx.blocking_recv().is_none());
    }

    fn start_password_totp_session(
        account: &Account,
        webauthn: &Webauthn,
    ) -> (AuthSession, HashSet<String>) {
        let asd = AuthSessionData {
            account: account.clone(),
            account_policy: ResolvedAccountPolicy::default(),
            issue: AuthIssueSession::Token,
            webauthn,
            ct: duration_from_epoch_now(),
            client_auth_info: Source::Internal.into(),
        };
        let key_object = KeyObjectInternal::new_test();
        let (session, state) = AuthSession::new(asd, false, key_object);
        let mut session = session.expect("Session was unable to be created.");

        if let AuthState::Choose(auth_mechs) = state {
            assert!(auth_mechs
                .iter()
                .any(|x| matches!(x, AuthMech::PasswordTotp)))
        } else {
            panic!();
        }

        let state = session
            .start_session(&AuthMech::PasswordTotp)
            .expect("Failed to select password totp mech.");

        if let AuthState::Continue(auth_mechs) = state {
            assert!(auth_mechs.iter().fold(false, |acc, x| match x {
                AuthAllowed::Totp => true,
                _ => acc,
            }));
        } else {
            panic!("Invalid auth state")
        }

        (session, create_pw_badlist_cache())
    }

    fn start_password_sk_session(
        account: &Account,
        webauthn: &Webauthn,
    ) -> (AuthSession, RequestChallengeResponse, HashSet<String>) {
        let asd = AuthSessionData {
            account: account.clone(),
            account_policy: ResolvedAccountPolicy::default(),
            issue: AuthIssueSession::Token,
            webauthn,
            ct: duration_from_epoch_now(),
            client_auth_info: Source::Internal.into(),
        };
        let key_object = KeyObjectInternal::new_test();
        let (session, state) = AuthSession::new(asd, false, key_object);
        let mut session = session.expect("Session was unable to be created.");

        if let AuthState::Choose(auth_mechs) = state {
            assert!(auth_mechs
                .iter()
                .any(|x| matches!(x, AuthMech::PasswordSecurityKey)))
        } else {
            panic!();
        }

        let state = session
            .start_session(&AuthMech::PasswordSecurityKey)
            .expect("Failed to select password security key mech.");

        let mut rchal = None;

        if let AuthState::Continue(auth_mechs) = state {
            assert!(auth_mechs.iter().fold(false, |acc, x| match x {
                AuthAllowed::SecurityKey(chal) => {
                    rchal = Some(chal.clone());
                    true
                }
                _ => acc,
            }));
        } else {
            panic!("Invalid auth state")
        }

        (session, rchal.unwrap(), create_pw_badlist_cache())
    }

    fn start_password_bc_session(
        account: &Account,
        webauthn: &Webauthn,
    ) -> (AuthSession, HashSet<String>) {
        let asd = AuthSessionData {
            account: account.clone(),
            account_policy: ResolvedAccountPolicy::default(),
            issue: AuthIssueSession::Token,
            webauthn,
            ct: duration_from_epoch_now(),
            client_auth_info: Source::Internal.into(),
        };
        let key_object = KeyObjectInternal::new_test();
        let (session, state) = AuthSession::new(asd, false, key_object);
        let mut session = session.expect("Session was unable to be created.");

        if let AuthState::Choose(auth_mechs) = state {
            assert!(auth_mechs
                .iter()
                .any(|x| matches!(x, AuthMech::PasswordBackupCode)))
        } else {
            panic!();
        }

        let state = session
            .start_session(&AuthMech::PasswordBackupCode)
            .expect("Failed to select password backup code mech.");

        if let AuthState::Continue(auth_mechs) = state {
            assert!(auth_mechs.iter().fold(false, |acc, x| match x {
                AuthAllowed::BackupCode => true,
                _ => acc,
            }));
        } else {
            panic!("Invalid auth state")
        }

        (session, create_pw_badlist_cache())
    }

    #[test]
    fn test_idm_authsession_totp_password_mech() {
        sketching::test_init();
        let webauthn = create_webauthn();
        // create the ent
        let mut account: Account = BUILTIN_ACCOUNT_TEST_PERSON.clone().into();

        // Setup a fake time stamp for consistency.
        let ts = Duration::from_secs(12345);

        // manually load in a cred
        let totp = Totp::generate_secure(TOTP_DEFAULT_STEP);

        let totp_good = totp
            .do_totp_duration_from_epoch(&ts)
            .expect("failed to perform totp.");
        let totp_bad = totp
            .do_totp_duration_from_epoch(&Duration::from_secs(1234567))
            .expect("failed to perform totp.");
        assert!(totp_bad != totp_good);

        let pw_good = "test_password";
        let pw_bad = "bad_password";

        let p = CryptoPolicy::minimum();
        let cred = Credential::new_password_only(&p, pw_good)
            .unwrap()
            .append_totp("totp".to_string(), totp);
        // add totp also
        account.primary = Some(cred);

        let (async_tx, mut async_rx) = unbounded();
        let (audit_tx, mut audit_rx) = unbounded();

        // now check

        // check send anon (fail)
        {
            let (mut session, pw_badlist_cache) = start_password_totp_session(&account, &webauthn);

            match session.validate_creds(
                &AuthCredential::Anonymous,
                ts,
                &async_tx,
                &audit_tx,
                &webauthn,
                &pw_badlist_cache,
            ) {
                Ok(AuthState::Denied(msg)) => assert_eq!(msg, BAD_AUTH_TYPE_MSG),
                _ => panic!(),
            };

            match audit_rx.try_recv() {
                Ok(AuditEvent::AuthenticationDenied { .. }) => {}
                _ => panic!("Oh no"),
            }
        }

        // == two step checks

        // Sending a PW first is an immediate fail.
        {
            let (mut session, pw_badlist_cache) = start_password_totp_session(&account, &webauthn);

            match session.validate_creds(
                &AuthCredential::Password(pw_bad.to_string()),
                ts,
                &async_tx,
                &audit_tx,
                &webauthn,
                &pw_badlist_cache,
            ) {
                Ok(AuthState::Denied(msg)) => assert_eq!(msg, BAD_AUTH_TYPE_MSG),
                _ => panic!(),
            };

            match audit_rx.try_recv() {
                Ok(AuditEvent::AuthenticationDenied { .. }) => {}
                _ => panic!("Oh no"),
            }
        }
        // check send bad totp, should fail immediate
        {
            let (mut session, pw_badlist_cache) = start_password_totp_session(&account, &webauthn);

            match session.validate_creds(
                &AuthCredential::Totp(totp_bad),
                ts,
                &async_tx,
                &audit_tx,
                &webauthn,
                &pw_badlist_cache,
            ) {
                Ok(AuthState::Denied(msg)) => assert_eq!(msg, BAD_TOTP_MSG),
                _ => panic!(),
            };

            match audit_rx.try_recv() {
                Ok(AuditEvent::AuthenticationDenied { .. }) => {}
                _ => panic!("Oh no"),
            }
        }

        // check send good totp, should continue
        //      then bad pw, fail pw
        {
            let (mut session, pw_badlist_cache) = start_password_totp_session(&account, &webauthn);

            match session.validate_creds(
                &AuthCredential::Totp(totp_good),
                ts,
                &async_tx,
                &audit_tx,
                &webauthn,
                &pw_badlist_cache,
            ) {
                Ok(AuthState::Continue(cont)) => assert_eq!(cont, vec![AuthAllowed::Password]),
                _ => panic!(),
            };
            match session.validate_creds(
                &AuthCredential::Password(pw_bad.to_string()),
                ts,
                &async_tx,
                &audit_tx,
                &webauthn,
                &pw_badlist_cache,
            ) {
                Ok(AuthState::Denied(msg)) => assert_eq!(msg, BAD_PASSWORD_MSG),
                _ => panic!(),
            };

            match audit_rx.try_recv() {
                Ok(AuditEvent::AuthenticationDenied { .. }) => {}
                _ => panic!("Oh no"),
            }
        }

        // check send good totp, should continue
        //      then good pw, success
        {
            let (mut session, pw_badlist_cache) = start_password_totp_session(&account, &webauthn);

            match session.validate_creds(
                &AuthCredential::Totp(totp_good),
                ts,
                &async_tx,
                &audit_tx,
                &webauthn,
                &pw_badlist_cache,
            ) {
                Ok(AuthState::Continue(cont)) => assert_eq!(cont, vec![AuthAllowed::Password]),
                _ => panic!(),
            };
            match session.validate_creds(
                &AuthCredential::Password(pw_good.to_string()),
                ts,
                &async_tx,
                &audit_tx,
                &webauthn,
                &pw_badlist_cache,
            ) {
                Ok(AuthState::Success(_, AuthIssueSession::Token)) => {}
                _ => panic!(),
            };

            match async_rx.blocking_recv() {
                Some(DelayedAction::AuthSessionRecord(_)) => {}
                _ => panic!("Oh no"),
            }
        }

        drop(async_tx);
        assert!(async_rx.blocking_recv().is_none());
        drop(audit_tx);
        assert!(audit_rx.blocking_recv().is_none());
    }

    #[test]
    fn test_idm_authsession_password_mfa_badlist() {
        sketching::test_init();
        let webauthn = create_webauthn();
        // create the ent
        let mut account: Account = BUILTIN_ACCOUNT_TEST_PERSON.clone().into();

        // Setup a fake time stamp for consistency.
        let ts = Duration::from_secs(12345);

        // manually load in a cred
        let totp = Totp::generate_secure(TOTP_DEFAULT_STEP);

        let totp_good = totp
            .do_totp_duration_from_epoch(&ts)
            .expect("failed to perform totp.");

        let pw_badlist = "list@no3IBTyqHu$bad";

        let p = CryptoPolicy::minimum();
        let cred = Credential::new_password_only(&p, pw_badlist)
            .unwrap()
            .append_totp("totp".to_string(), totp);
        // add totp also
        account.primary = Some(cred);

        let (async_tx, mut async_rx) = unbounded();
        let (audit_tx, mut audit_rx) = unbounded();

        // now check

        // == two step checks

        // check send good totp, should continue
        //      then badlist pw, failed
        {
            let (mut session, pw_badlist_cache) = start_password_totp_session(&account, &webauthn);

            match session.validate_creds(
                &AuthCredential::Totp(totp_good),
                ts,
                &async_tx,
                &audit_tx,
                &webauthn,
                &pw_badlist_cache,
            ) {
                Ok(AuthState::Continue(cont)) => assert_eq!(cont, vec![AuthAllowed::Password]),
                _ => panic!(),
            };
            match session.validate_creds(
                &AuthCredential::Password(pw_badlist.to_string()),
                ts,
                &async_tx,
                &audit_tx,
                &webauthn,
                &pw_badlist_cache,
            ) {
                Ok(AuthState::Denied(msg)) => assert_eq!(msg, PW_BADLIST_MSG),
                _ => panic!(),
            };

            match audit_rx.try_recv() {
                Ok(AuditEvent::AuthenticationDenied { .. }) => {}
                _ => panic!("Oh no"),
            }
        }

        drop(async_tx);
        assert!(async_rx.blocking_recv().is_none());
        drop(audit_tx);
        assert!(audit_rx.blocking_recv().is_none());
    }

    macro_rules! start_webauthn_only_session {
        (
            $audit:expr,
            $account:expr,
            $webauthn:expr
        ) => {{
            let asd = AuthSessionData {
                account: $account.clone(),
                account_policy: ResolvedAccountPolicy::default(),
                issue: AuthIssueSession::Token,
                webauthn: $webauthn,
                ct: duration_from_epoch_now(),
                client_auth_info: Source::Internal.into(),
            };
            let key_object = KeyObjectInternal::new_test();
            let (session, state) = AuthSession::new(asd, false, key_object);
            let mut session = session.unwrap();

            if let AuthState::Choose(auth_mechs) = state {
                assert!(auth_mechs.iter().any(|x| matches!(x, AuthMech::Passkey)));
            } else {
                panic!();
            }

            let state = session
                .start_session(&AuthMech::Passkey)
                .expect("Failed to select Passkey mech.");

            let wan_chal = if let AuthState::Continue(auth_mechs) = state {
                assert_eq!(auth_mechs.len(), 1);
                auth_mechs
                    .into_iter()
                    .fold(None, |_acc, x| match x {
                        AuthAllowed::Passkey(chal) => Some(chal),
                        _ => None,
                    })
                    .expect("No securitykey challenge found.")
            } else {
                panic!();
            };

            (session, wan_chal)
        }};
    }

    fn setup_webauthn_passkey(
        name: &str,
    ) -> (
        webauthn_rs::prelude::Webauthn,
        webauthn_authenticator_rs::WebauthnAuthenticator<SoftPasskey>,
        webauthn_rs::prelude::Passkey,
    ) {
        let webauthn = create_webauthn();
        // Setup a soft token
        let mut wa = WebauthnAuthenticator::new(SoftPasskey::new(true));

        let uuid = Uuid::new_v4();

        let (chal, reg_state) = webauthn
            .start_passkey_registration(uuid, name, name, None)
            .expect("Failed to setup passkey rego challenge");

        let r = wa
            .do_registration(webauthn.get_allowed_origins()[0].clone(), chal)
            .expect("Failed to create soft passkey");

        let wan_cred = webauthn
            .finish_passkey_registration(&r, &reg_state)
            .expect("Failed to register soft token");

        (webauthn, wa, wan_cred)
    }

    fn setup_webauthn_securitykey(
        name: &str,
    ) -> (
        webauthn_rs::prelude::Webauthn,
        webauthn_authenticator_rs::WebauthnAuthenticator<SoftPasskey>,
        webauthn_rs::prelude::SecurityKey,
    ) {
        let webauthn = create_webauthn();
        // Setup a soft token
        let mut wa = WebauthnAuthenticator::new(SoftPasskey::new(true));

        let uuid = Uuid::new_v4();

        let (chal, reg_state) = webauthn
            .start_securitykey_registration(uuid, name, name, None, None, None)
            .expect("Failed to setup passkey rego challenge");

        let r = wa
            .do_registration(webauthn.get_allowed_origins()[0].clone(), chal)
            .expect("Failed to create soft securitykey");

        let wan_cred = webauthn
            .finish_securitykey_registration(&r, &reg_state)
            .expect("Failed to register soft token");

        (webauthn, wa, wan_cred)
    }

    #[test]
    fn test_idm_authsession_webauthn_only_mech() {
        sketching::test_init();
        let (async_tx, mut async_rx) = unbounded();
        let (audit_tx, mut audit_rx) = unbounded();
        let ts = duration_from_epoch_now();
        // create the ent
        let mut account: Account = BUILTIN_ACCOUNT_TEST_PERSON.clone().into();

        let (webauthn, mut wa, wan_cred) = setup_webauthn_passkey(account.name.as_str());

        // Now create the credential for the account.
        account.passkeys = btreemap![(Uuid::new_v4(), ("soft".to_string(), wan_cred))];

        // now check correct mech was offered.

        // check send anon (fail)
        {
            let (mut session, _inv_chal) =
                start_webauthn_only_session!(&mut audit, account, &webauthn);

            match session.validate_creds(
                &AuthCredential::Anonymous,
                ts,
                &async_tx,
                &audit_tx,
                &webauthn,
                &Default::default(),
            ) {
                Ok(AuthState::Denied(msg)) => assert_eq!(msg, BAD_AUTH_TYPE_MSG),
                _ => panic!(),
            };

            match audit_rx.try_recv() {
                Ok(AuditEvent::AuthenticationDenied { .. }) => {}
                _ => panic!("Oh no"),
            }
        }

        // Check good challenge
        {
            let (mut session, chal) = start_webauthn_only_session!(&mut audit, account, &webauthn);

            let resp = wa
                .do_authentication(webauthn.get_allowed_origins()[0].clone(), chal)
                .map(Box::new)
                .expect("failed to use softtoken to authenticate");

            match session.validate_creds(
                &AuthCredential::Passkey(resp),
                ts,
                &async_tx,
                &audit_tx,
                &webauthn,
                &Default::default(),
            ) {
                Ok(AuthState::Success(_, AuthIssueSession::Token)) => {}
                _ => panic!(),
            };

            // Check the async counter update was sent.
            match async_rx.blocking_recv() {
                Some(DelayedAction::WebauthnCounterIncrement(_)) => {}
                _ => panic!("Oh no"),
            }
            match async_rx.blocking_recv() {
                Some(DelayedAction::AuthSessionRecord(_)) => {}
                _ => panic!("Oh no"),
            }
        }

        // Check bad challenge.
        {
            let (_session, inv_chal) = start_webauthn_only_session!(&mut audit, account, &webauthn);
            let (mut session, _chal) = start_webauthn_only_session!(&mut audit, account, &webauthn);

            let resp = wa
                // HERE -> we use inv_chal instead.
                .do_authentication(webauthn.get_allowed_origins()[0].clone(), inv_chal)
                .map(Box::new)
                .expect("failed to use softtoken to authenticate");

            match session.validate_creds(
                &AuthCredential::Passkey(resp),
                ts,
                &async_tx,
                &audit_tx,
                &webauthn,
                &Default::default(),
            ) {
                Ok(AuthState::Denied(msg)) => assert_eq!(msg, BAD_WEBAUTHN_MSG),
                _ => panic!(),
            };

            match audit_rx.try_recv() {
                Ok(AuditEvent::AuthenticationDenied { .. }) => {}
                _ => panic!("Oh no"),
            }
        }

        // Use an incorrect softtoken.
        {
            let mut inv_wa = WebauthnAuthenticator::new(SoftPasskey::new(true));
            let (chal, reg_state) = webauthn
                .start_passkey_registration(account.uuid, &account.name, &account.displayname, None)
                .expect("Failed to setup webauthn rego challenge");

            let r = inv_wa
                .do_registration(webauthn.get_allowed_origins()[0].clone(), chal)
                .expect("Failed to create soft token");

            let inv_cred = webauthn
                .finish_passkey_registration(&r, &reg_state)
                .expect("Failed to register soft token");

            // Discard the auth_state, we only need the invalid challenge.
            let (chal, _auth_state) = webauthn
                .start_passkey_authentication(&vec![inv_cred])
                .expect("Failed to generate challenge for in inv softtoken");

            // Create the response.
            let resp = inv_wa
                .do_authentication(webauthn.get_allowed_origins()[0].clone(), chal)
                .map(Box::new)
                .expect("Failed to use softtoken for response.");

            let (mut session, _chal) = start_webauthn_only_session!(&mut audit, account, &webauthn);
            // Ignore the real cred, use the diff cred. Normally this shouldn't even
            // get this far, because the client should identify that the cred id's are
            // not inline.
            match session.validate_creds(
                &AuthCredential::Passkey(resp),
                ts,
                &async_tx,
                &audit_tx,
                &webauthn,
                &Default::default(),
            ) {
                Ok(AuthState::Denied(msg)) => assert_eq!(msg, BAD_WEBAUTHN_MSG),
                _ => panic!(),
            };

            match audit_rx.try_recv() {
                Ok(AuditEvent::AuthenticationDenied { .. }) => {}
                _ => panic!("Oh no"),
            }
        }

        drop(async_tx);
        assert!(async_rx.blocking_recv().is_none());
        drop(audit_tx);
        assert!(audit_rx.blocking_recv().is_none());
    }

    #[test]
    fn test_idm_authsession_webauthn_password_mech() {
        sketching::test_init();
        let (async_tx, mut async_rx) = unbounded();
        let (audit_tx, mut audit_rx) = unbounded();
        let ts = duration_from_epoch_now();
        // create the ent
        let mut account: Account = BUILTIN_ACCOUNT_TEST_PERSON.clone().into();

        let (webauthn, mut wa, wan_cred) = setup_webauthn_securitykey(account.name.as_str());
        let pw_good = "test_password";
        let pw_bad = "bad_password";

        // Now create the credential for the account.
        let p = CryptoPolicy::minimum();
        let cred = Credential::new_password_only(&p, pw_good)
            .unwrap()
            .append_securitykey("soft".to_string(), wan_cred)
            .unwrap();

        account.primary = Some(cred);

        // check pw first (fail)
        {
            let (mut session, _, pw_badlist_cache) = start_password_sk_session(&account, &webauthn);

            match session.validate_creds(
                &AuthCredential::Password(pw_bad.to_string()),
                ts,
                &async_tx,
                &audit_tx,
                &webauthn,
                &pw_badlist_cache,
            ) {
                Ok(AuthState::Denied(msg)) => assert_eq!(msg, BAD_AUTH_TYPE_MSG),
                _ => panic!(),
            };

            match audit_rx.try_recv() {
                Ok(AuditEvent::AuthenticationDenied { .. }) => {}
                _ => panic!("Oh no"),
            }
        }

        // Check totp first attempt fails.
        {
            let (mut session, _, pw_badlist_cache) = start_password_sk_session(&account, &webauthn);

            match session.validate_creds(
                &AuthCredential::Totp(0),
                ts,
                &async_tx,
                &audit_tx,
                &webauthn,
                &pw_badlist_cache,
            ) {
                Ok(AuthState::Denied(msg)) => assert_eq!(msg, BAD_AUTH_TYPE_MSG),
                _ => panic!(),
            };

            match audit_rx.try_recv() {
                Ok(AuditEvent::AuthenticationDenied { .. }) => {}
                _ => panic!("Oh no"),
            }
        }

        // check bad webauthn (fail)
        // NOTE: We only check bad challenge here as bad softtoken is already
        // extensively tested.
        {
            let (_session, inv_chal, pw_badlist_cache) =
                start_password_sk_session(&account, &webauthn);
            let (mut session, _chal, _) = start_password_sk_session(&account, &webauthn);

            let resp = wa
                // HERE -> we use inv_chal instead.
                .do_authentication(webauthn.get_allowed_origins()[0].clone(), inv_chal)
                .map(Box::new)
                .expect("failed to use softtoken to authenticate");

            match session.validate_creds(
                &AuthCredential::SecurityKey(resp),
                ts,
                &async_tx,
                &audit_tx,
                &webauthn,
                &pw_badlist_cache,
            ) {
                Ok(AuthState::Denied(msg)) => assert_eq!(msg, BAD_WEBAUTHN_MSG),
                _ => panic!(),
            };

            match audit_rx.try_recv() {
                Ok(AuditEvent::AuthenticationDenied { .. }) => {}
                _ => panic!("Oh no"),
            }
        }

        // check good webauthn/bad pw (fail)
        {
            let (mut session, chal, pw_badlist_cache) =
                start_password_sk_session(&account, &webauthn);

            let resp = wa
                .do_authentication(webauthn.get_allowed_origins()[0].clone(), chal)
                .map(Box::new)
                .expect("failed to use softtoken to authenticate");

            match session.validate_creds(
                &AuthCredential::SecurityKey(resp),
                ts,
                &async_tx,
                &audit_tx,
                &webauthn,
                &pw_badlist_cache,
            ) {
                Ok(AuthState::Continue(cont)) => assert_eq!(cont, vec![AuthAllowed::Password]),
                _ => panic!(),
            };
            match session.validate_creds(
                &AuthCredential::Password(pw_bad.to_string()),
                ts,
                &async_tx,
                &audit_tx,
                &webauthn,
                &pw_badlist_cache,
            ) {
                Ok(AuthState::Denied(msg)) => assert_eq!(msg, BAD_PASSWORD_MSG),
                _ => panic!(),
            };

            match audit_rx.try_recv() {
                Ok(AuditEvent::AuthenticationDenied { .. }) => {}
                _ => panic!("Oh no"),
            }

            // Check the async counter update was sent.
            match async_rx.blocking_recv() {
                Some(DelayedAction::WebauthnCounterIncrement(_)) => {}
                _ => panic!("Oh no"),
            }
        }

        // Check good webauthn/good pw (pass)
        {
            let (mut session, chal, pw_badlist_cache) =
                start_password_sk_session(&account, &webauthn);

            let resp = wa
                .do_authentication(webauthn.get_allowed_origins()[0].clone(), chal)
                .map(Box::new)
                .expect("failed to use softtoken to authenticate");

            match session.validate_creds(
                &AuthCredential::SecurityKey(resp),
                ts,
                &async_tx,
                &audit_tx,
                &webauthn,
                &pw_badlist_cache,
            ) {
                Ok(AuthState::Continue(cont)) => assert_eq!(cont, vec![AuthAllowed::Password]),
                _ => panic!(),
            };
            match session.validate_creds(
                &AuthCredential::Password(pw_good.to_string()),
                ts,
                &async_tx,
                &audit_tx,
                &webauthn,
                &pw_badlist_cache,
            ) {
                Ok(AuthState::Success(_, AuthIssueSession::Token)) => {}
                _ => panic!(),
            };

            // Check the async counter update was sent.
            match async_rx.blocking_recv() {
                Some(DelayedAction::WebauthnCounterIncrement(_)) => {}
                _ => panic!("Oh no"),
            }
            match async_rx.blocking_recv() {
                Some(DelayedAction::AuthSessionRecord(_)) => {}
                _ => panic!("Oh no"),
            }
        }

        drop(async_tx);
        assert!(async_rx.blocking_recv().is_none());
        drop(audit_tx);
        assert!(audit_rx.blocking_recv().is_none());
    }

    #[test]
    fn test_idm_authsession_webauthn_password_totp_mech() {
        sketching::test_init();
        let (async_tx, mut async_rx) = unbounded();
        let (audit_tx, mut audit_rx) = unbounded();
        let ts = duration_from_epoch_now();
        // create the ent
        let mut account: Account = BUILTIN_ACCOUNT_TEST_PERSON.clone().into();

        let (webauthn, mut wa, wan_cred) = setup_webauthn_securitykey(account.name.as_str());

        let totp = Totp::generate_secure(TOTP_DEFAULT_STEP);
        let totp_good = totp
            .do_totp_duration_from_epoch(&ts)
            .expect("failed to perform totp.");
        let totp_bad = totp
            .do_totp_duration_from_epoch(&Duration::from_secs(1234567))
            .expect("failed to perform totp.");
        assert!(totp_bad != totp_good);

        let pw_good = "test_password";
        let pw_bad = "bad_password";

        // Now create the credential for the account.
        let p = CryptoPolicy::minimum();
        let cred = Credential::new_password_only(&p, pw_good)
            .unwrap()
            .append_securitykey("soft".to_string(), wan_cred)
            .unwrap()
            .append_totp("totp".to_string(), totp);

        account.primary = Some(cred);

        // check pw first (fail)
        {
            let (mut session, pw_badlist_cache) = start_password_totp_session(&account, &webauthn);

            match session.validate_creds(
                &AuthCredential::Password(pw_bad.to_string()),
                ts,
                &async_tx,
                &audit_tx,
                &webauthn,
                &pw_badlist_cache,
            ) {
                Ok(AuthState::Denied(msg)) => assert_eq!(msg, BAD_AUTH_TYPE_MSG),
                _ => panic!(),
            };

            match audit_rx.try_recv() {
                Ok(AuditEvent::AuthenticationDenied { .. }) => {}
                _ => panic!("Oh no"),
            }
        }

        // Check bad totp (fail)
        {
            let (mut session, pw_badlist_cache) = start_password_totp_session(&account, &webauthn);

            match session.validate_creds(
                &AuthCredential::Totp(totp_bad),
                ts,
                &async_tx,
                &audit_tx,
                &webauthn,
                &pw_badlist_cache,
            ) {
                Ok(AuthState::Denied(msg)) => assert_eq!(msg, BAD_TOTP_MSG),
                _ => panic!(),
            };

            match audit_rx.try_recv() {
                Ok(AuditEvent::AuthenticationDenied { .. }) => {}
                _ => panic!("Oh no"),
            }
        }

        // check bad webauthn (fail)
        {
            let (_session, inv_chal, pw_badlist_cache) =
                start_password_sk_session(&account, &webauthn);
            let (mut session, _chal, _) = start_password_sk_session(&account, &webauthn);

            let resp = wa
                // HERE -> we use inv_chal instead.
                .do_authentication(webauthn.get_allowed_origins()[0].clone(), inv_chal)
                .map(Box::new)
                .expect("failed to use softtoken to authenticate");

            match session.validate_creds(
                &AuthCredential::SecurityKey(resp),
                ts,
                &async_tx,
                &audit_tx,
                &webauthn,
                &pw_badlist_cache,
            ) {
                Ok(AuthState::Denied(msg)) => assert_eq!(msg, BAD_WEBAUTHN_MSG),
                _ => panic!(),
            };

            match audit_rx.try_recv() {
                Ok(AuditEvent::AuthenticationDenied { .. }) => {}
                _ => panic!("Oh no"),
            }
        }

        // check good webauthn/bad pw (fail)
        {
            let (mut session, chal, pw_badlist_cache) =
                start_password_sk_session(&account, &webauthn);

            let resp = wa
                .do_authentication(webauthn.get_allowed_origins()[0].clone(), chal)
                .map(Box::new)
                .expect("failed to use softtoken to authenticate");

            match session.validate_creds(
                &AuthCredential::SecurityKey(resp),
                ts,
                &async_tx,
                &audit_tx,
                &webauthn,
                &pw_badlist_cache,
            ) {
                Ok(AuthState::Continue(cont)) => assert_eq!(cont, vec![AuthAllowed::Password]),
                _ => panic!(),
            };
            match session.validate_creds(
                &AuthCredential::Password(pw_bad.to_string()),
                ts,
                &async_tx,
                &audit_tx,
                &webauthn,
                &pw_badlist_cache,
            ) {
                Ok(AuthState::Denied(msg)) => assert_eq!(msg, BAD_PASSWORD_MSG),
                _ => panic!(),
            };

            match audit_rx.try_recv() {
                Ok(AuditEvent::AuthenticationDenied { .. }) => {}
                _ => panic!("Oh no"),
            }

            // Check the async counter update was sent.
            match async_rx.blocking_recv() {
                Some(DelayedAction::WebauthnCounterIncrement(_)) => {}
                _ => panic!("Oh no"),
            }
        }

        // check good totp/bad pw (fail)
        {
            let (mut session, pw_badlist_cache) = start_password_totp_session(&account, &webauthn);

            match session.validate_creds(
                &AuthCredential::Totp(totp_good),
                ts,
                &async_tx,
                &audit_tx,
                &webauthn,
                &pw_badlist_cache,
            ) {
                Ok(AuthState::Continue(cont)) => assert_eq!(cont, vec![AuthAllowed::Password]),
                _ => panic!(),
            };
            match session.validate_creds(
                &AuthCredential::Password(pw_bad.to_string()),
                ts,
                &async_tx,
                &audit_tx,
                &webauthn,
                &pw_badlist_cache,
            ) {
                Ok(AuthState::Denied(msg)) => assert_eq!(msg, BAD_PASSWORD_MSG),
                _ => panic!(),
            };

            match audit_rx.try_recv() {
                Ok(AuditEvent::AuthenticationDenied { .. }) => {}
                _ => panic!("Oh no"),
            }
        }

        // check good totp/good pw (pass)
        {
            let (mut session, pw_badlist_cache) = start_password_totp_session(&account, &webauthn);

            match session.validate_creds(
                &AuthCredential::Totp(totp_good),
                ts,
                &async_tx,
                &audit_tx,
                &webauthn,
                &pw_badlist_cache,
            ) {
                Ok(AuthState::Continue(cont)) => assert_eq!(cont, vec![AuthAllowed::Password]),
                _ => panic!(),
            };
            match session.validate_creds(
                &AuthCredential::Password(pw_good.to_string()),
                ts,
                &async_tx,
                &audit_tx,
                &webauthn,
                &pw_badlist_cache,
            ) {
                Ok(AuthState::Success(_, AuthIssueSession::Token)) => {}
                _ => panic!(),
            };

            match async_rx.blocking_recv() {
                Some(DelayedAction::AuthSessionRecord(_)) => {}
                _ => panic!("Oh no"),
            }
        }

        // Check good webauthn/good pw (pass)
        {
            let (mut session, chal, pw_badlist_cache) =
                start_password_sk_session(&account, &webauthn);

            let resp = wa
                .do_authentication(webauthn.get_allowed_origins()[0].clone(), chal)
                .map(Box::new)
                .expect("failed to use softtoken to authenticate");

            match session.validate_creds(
                &AuthCredential::SecurityKey(resp),
                ts,
                &async_tx,
                &audit_tx,
                &webauthn,
                &pw_badlist_cache,
            ) {
                Ok(AuthState::Continue(cont)) => assert_eq!(cont, vec![AuthAllowed::Password]),
                _ => panic!(),
            };
            match session.validate_creds(
                &AuthCredential::Password(pw_good.to_string()),
                ts,
                &async_tx,
                &audit_tx,
                &webauthn,
                &pw_badlist_cache,
            ) {
                Ok(AuthState::Success(_, AuthIssueSession::Token)) => {}
                _ => panic!(),
            };

            // Check the async counter update was sent.
            match async_rx.blocking_recv() {
                Some(DelayedAction::WebauthnCounterIncrement(_)) => {}
                _ => panic!("Oh no"),
            }
            match async_rx.blocking_recv() {
                Some(DelayedAction::AuthSessionRecord(_)) => {}
                _ => panic!("Oh no"),
            }
        }

        drop(async_tx);
        assert!(async_rx.blocking_recv().is_none());
        drop(audit_tx);
        assert!(audit_rx.blocking_recv().is_none());
    }

    #[test]
    fn test_idm_authsession_backup_code_mech() {
        sketching::test_init();
        let webauthn = create_webauthn();
        // create the ent
        let mut account: Account = BUILTIN_ACCOUNT_TEST_PERSON.clone().into();

        // Setup a fake time stamp for consistency.
        let ts = Duration::from_secs(12345);

        // manually load in a cred
        let totp = Totp::generate_secure(TOTP_DEFAULT_STEP);

        let totp_good = totp
            .do_totp_duration_from_epoch(&ts)
            .expect("failed to perform totp.");

        let pw_good = "test_password";
        let pw_bad = "bad_password";

        let backup_code_good = readable_password_from_random();
        let backup_code_bad = readable_password_from_random();
        assert!(backup_code_bad != backup_code_good);
        let mut code_set = HashSet::new();
        code_set.insert(backup_code_good.clone());

        let backup_codes = BackupCodes::new(code_set);

        // add totp and backup codes also
        let p = CryptoPolicy::minimum();
        let cred = Credential::new_password_only(&p, pw_good)
            .unwrap()
            .append_totp("totp".to_string(), totp)
            .update_backup_code(backup_codes)
            .unwrap();

        account.primary = Some(cred);

        let (async_tx, mut async_rx) = unbounded();
        let (audit_tx, mut audit_rx) = unbounded();

        // now check
        // == two step checks

        // Sending a PW first is an immediate fail.
        {
            let (mut session, pw_badlist_cache) = start_password_bc_session(&account, &webauthn);

            match session.validate_creds(
                &AuthCredential::Password(pw_bad.to_string()),
                ts,
                &async_tx,
                &audit_tx,
                &webauthn,
                &pw_badlist_cache,
            ) {
                Ok(AuthState::Denied(msg)) => assert_eq!(msg, BAD_AUTH_TYPE_MSG),
                _ => panic!(),
            };

            match audit_rx.try_recv() {
                Ok(AuditEvent::AuthenticationDenied { .. }) => {}
                _ => panic!("Oh no"),
            }
        }
        // check send wrong backup code, should fail immediate
        {
            let (mut session, pw_badlist_cache) = start_password_bc_session(&account, &webauthn);

            match session.validate_creds(
                &AuthCredential::BackupCode(backup_code_bad),
                ts,
                &async_tx,
                &audit_tx,
                &webauthn,
                &pw_badlist_cache,
            ) {
                Ok(AuthState::Denied(msg)) => assert_eq!(msg, BAD_BACKUPCODE_MSG),
                _ => panic!(),
            };

            match audit_rx.try_recv() {
                Ok(AuditEvent::AuthenticationDenied { .. }) => {}
                _ => panic!("Oh no"),
            }
        }
        // check send good backup code, should continue
        //      then bad pw, fail pw
        {
            let (mut session, pw_badlist_cache) = start_password_bc_session(&account, &webauthn);

            match session.validate_creds(
                &AuthCredential::BackupCode(backup_code_good.clone()),
                ts,
                &async_tx,
                &audit_tx,
                &webauthn,
                &pw_badlist_cache,
            ) {
                Ok(AuthState::Continue(cont)) => assert_eq!(cont, vec![AuthAllowed::Password]),
                _ => panic!(),
            };
            match session.validate_creds(
                &AuthCredential::Password(pw_bad.to_string()),
                ts,
                &async_tx,
                &audit_tx,
                &webauthn,
                &pw_badlist_cache,
            ) {
                Ok(AuthState::Denied(msg)) => assert_eq!(msg, BAD_PASSWORD_MSG),
                _ => panic!(),
            };

            match audit_rx.try_recv() {
                Ok(AuditEvent::AuthenticationDenied { .. }) => {}
                _ => panic!("Oh no"),
            }
        }
        // Can't process BackupCodeRemoval without the server instance
        match async_rx.blocking_recv() {
            Some(DelayedAction::BackupCodeRemoval(_)) => {}
            _ => panic!("Oh no"),
        }

        // check send good backup code, should continue
        //      then good pw, success
        {
            let (mut session, pw_badlist_cache) = start_password_bc_session(&account, &webauthn);

            match session.validate_creds(
                &AuthCredential::BackupCode(backup_code_good),
                ts,
                &async_tx,
                &audit_tx,
                &webauthn,
                &pw_badlist_cache,
            ) {
                Ok(AuthState::Continue(cont)) => assert_eq!(cont, vec![AuthAllowed::Password]),
                _ => panic!(),
            };
            match session.validate_creds(
                &AuthCredential::Password(pw_good.to_string()),
                ts,
                &async_tx,
                &audit_tx,
                &webauthn,
                &pw_badlist_cache,
            ) {
                Ok(AuthState::Success(_, AuthIssueSession::Token)) => {}
                _ => panic!(),
            };
        }
        // Can't process BackupCodeRemoval without the server instance
        match async_rx.blocking_recv() {
            Some(DelayedAction::BackupCodeRemoval(_)) => {}
            _ => panic!("Oh no"),
        }

        // There will be a auth session record too
        match async_rx.blocking_recv() {
            Some(DelayedAction::AuthSessionRecord(_)) => {}
            _ => panic!("Oh no"),
        }

        // TOTP should also work:
        // check send good TOTP, should continue
        //      then good pw, success
        {
            let (mut session, pw_badlist_cache) = start_password_totp_session(&account, &webauthn);

            match session.validate_creds(
                &AuthCredential::Totp(totp_good),
                ts,
                &async_tx,
                &audit_tx,
                &webauthn,
                &pw_badlist_cache,
            ) {
                Ok(AuthState::Continue(cont)) => assert_eq!(cont, vec![AuthAllowed::Password]),
                _ => panic!(),
            };
            match session.validate_creds(
                &AuthCredential::Password(pw_good.to_string()),
                ts,
                &async_tx,
                &audit_tx,
                &webauthn,
                &pw_badlist_cache,
            ) {
                Ok(AuthState::Success(_, AuthIssueSession::Token)) => {}
                _ => panic!(),
            };
        }

        // There will be a auth session record too
        match async_rx.blocking_recv() {
            Some(DelayedAction::AuthSessionRecord(_)) => {}
            _ => panic!("Oh no"),
        }

        drop(async_tx);
        assert!(async_rx.blocking_recv().is_none());
        drop(audit_tx);
        assert!(audit_rx.blocking_recv().is_none());
    }

    #[test]
    fn test_idm_authsession_multiple_totp_password_mech() {
        // Slightly different to the other TOTP test, this
        // checks handling when multiple TOTP's are registered.
        sketching::test_init();
        let webauthn = create_webauthn();
        // create the ent
        let mut account: Account = BUILTIN_ACCOUNT_TEST_PERSON.clone().into();

        // Setup a fake time stamp for consistency.
        let ts = Duration::from_secs(12345);

        // manually load in a cred
        let totp_a = Totp::generate_secure(TOTP_DEFAULT_STEP);
        let totp_b = Totp::generate_secure(TOTP_DEFAULT_STEP);

        let totp_good_a = totp_a
            .do_totp_duration_from_epoch(&ts)
            .expect("failed to perform totp.");

        let totp_good_b = totp_b
            .do_totp_duration_from_epoch(&ts)
            .expect("failed to perform totp.");

        assert!(totp_good_a != totp_good_b);

        let pw_good = "test_password";

        let p = CryptoPolicy::minimum();
        let cred = Credential::new_password_only(&p, pw_good)
            .unwrap()
            .append_totp("totp_a".to_string(), totp_a)
            .append_totp("totp_b".to_string(), totp_b);
        // add totp also
        account.primary = Some(cred);

        let (async_tx, mut async_rx) = unbounded();
        let (audit_tx, mut audit_rx) = unbounded();

        // Test totp_a
        {
            let (mut session, pw_badlist_cache) = start_password_totp_session(&account, &webauthn);

            match session.validate_creds(
                &AuthCredential::Totp(totp_good_a),
                ts,
                &async_tx,
                &audit_tx,
                &webauthn,
                &pw_badlist_cache,
            ) {
                Ok(AuthState::Continue(cont)) => assert_eq!(cont, vec![AuthAllowed::Password]),
                _ => panic!(),
            };
            match session.validate_creds(
                &AuthCredential::Password(pw_good.to_string()),
                ts,
                &async_tx,
                &audit_tx,
                &webauthn,
                &pw_badlist_cache,
            ) {
                Ok(AuthState::Success(_, AuthIssueSession::Token)) => {}
                _ => panic!(),
            };

            match async_rx.blocking_recv() {
                Some(DelayedAction::AuthSessionRecord(_)) => {}
                _ => panic!("Oh no"),
            }
        }

        // Test totp_b
        {
            let (mut session, pw_badlist_cache) = start_password_totp_session(&account, &webauthn);

            match session.validate_creds(
                &AuthCredential::Totp(totp_good_b),
                ts,
                &async_tx,
                &audit_tx,
                &webauthn,
                &pw_badlist_cache,
            ) {
                Ok(AuthState::Continue(cont)) => assert_eq!(cont, vec![AuthAllowed::Password]),
                _ => panic!(),
            };
            match session.validate_creds(
                &AuthCredential::Password(pw_good.to_string()),
                ts,
                &async_tx,
                &audit_tx,
                &webauthn,
                &pw_badlist_cache,
            ) {
                Ok(AuthState::Success(_, AuthIssueSession::Token)) => {}
                _ => panic!(),
            };

            match async_rx.blocking_recv() {
                Some(DelayedAction::AuthSessionRecord(_)) => {}
                _ => panic!("Oh no"),
            }
        }

        drop(async_tx);
        assert!(async_rx.blocking_recv().is_none());
        drop(audit_tx);
        assert!(audit_rx.blocking_recv().is_none());
    }
}
