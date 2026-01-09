use std::convert::TryFrom;

use hashbrown::{HashMap as Map, HashSet};
use kanidm_proto::internal::{CredentialDetail, CredentialDetailType, OperationError};
use time::OffsetDateTime;
use uuid::Uuid;
use webauthn_rs::prelude::{AuthenticationResult, Passkey, SecurityKey};
use webauthn_rs_core::proto::{Credential as WebauthnCredential, CredentialV3};

use crate::be::dbvalue::{DbBackupCodeV1, DbCred};

pub mod apppwd;
pub mod softlock;
pub mod totp;

use self::totp::TOTP_DEFAULT_STEP;

use kanidm_lib_crypto::CryptoPolicy;

use crate::credential::softlock::CredSoftLockPolicy;
use crate::credential::totp::Totp;

// These are in order of "relative" strength.
/*
#[derive(Clone, Debug)]
pub enum Policy {
    PasswordOnly,
    WebauthnOnly,
    GeneratedPassword,
    PasswordAndWebauthn,
}
*/

pub use kanidm_lib_crypto::Password;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BackupCodes {
    code_set: HashSet<String>,
}

impl TryFrom<DbBackupCodeV1> for BackupCodes {
    type Error = ();

    fn try_from(value: DbBackupCodeV1) -> Result<Self, Self::Error> {
        Ok(BackupCodes {
            code_set: value.code_set,
        })
    }
}

impl BackupCodes {
    pub fn new(code_set: HashSet<String>) -> Self {
        BackupCodes { code_set }
    }

    pub fn verify(&self, code_chal: &str) -> bool {
        self.code_set.contains(code_chal)
    }

    pub fn remove(&mut self, code_chal: &str) -> bool {
        self.code_set.remove(code_chal)
    }

    pub fn to_dbbackupcodev1(&self) -> DbBackupCodeV1 {
        DbBackupCodeV1 {
            code_set: self.code_set.clone(),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
/// This is how we store credentials in the server. An account can have many credentials, and
/// a credential can have many factors. Only successful auth to a credential as a whole unit
/// will succeed. For example:
/// A: Credential { password: aaa }
/// B: Credential { password: bbb, otp: ... }
/// In this case, if we selected credential B, and then provided password "aaa" we would deny
/// the auth as the password of B was incorrect. Additionally, while A only needs the "password",
/// B requires both the password and otp to be valid.
///
/// In this way, each Credential provides its own password requirements and policy, and requires
/// some metadata to support this such as it's source and strength etc.
pub struct Credential {
    // policy: Policy,
    pub(crate) type_: CredentialType,
    // Uuid of Credential, used by auth session to lock this specific credential
    // if required.
    pub(crate) uuid: Uuid,
    // TODO #59: Add auth policy IE validUntil, lock state ...
    // locked: bool
    timestamp: OffsetDateTime,
}

#[derive(Clone, Debug, PartialEq)]
/// The type of credential that is stored. Each of these represents a full set of 'what is required'
/// to complete an authentication session. The reason to have these typed like this is so we can
/// apply policy later to what classes or levels of credentials can be used. We use these types
/// to also know what type of auth session handler to initiate.
pub enum CredentialType {
    // Anonymous,
    Password(Password),
    GeneratedPassword(Password),
    PasswordMfa(
        Password,
        Map<String, Totp>,
        Map<String, SecurityKey>,
        Option<BackupCodes>,
    ),
    Webauthn(Map<String, Passkey>),
}

impl From<&Credential> for CredentialDetail {
    fn from(value: &Credential) -> Self {
        CredentialDetail {
            uuid: value.uuid,
            type_: match &value.type_ {
                CredentialType::Password(_) => CredentialDetailType::Password,
                CredentialType::GeneratedPassword(_) => CredentialDetailType::GeneratedPassword,
                CredentialType::Webauthn(wan) => {
                    let labels: Vec<_> = wan.keys().cloned().collect();
                    CredentialDetailType::Passkey(labels)
                }
                CredentialType::PasswordMfa(_, totp, wan, backup_code) => {
                    // Don't sort - we need these in order to match to what the user
                    // sees so they can remove by index.
                    let wan_labels: Vec<_> = wan.keys().cloned().collect();
                    let totp_labels: Vec<_> = totp.keys().cloned().collect();

                    CredentialDetailType::PasswordMfa(
                        totp_labels,
                        wan_labels,
                        backup_code.as_ref().map(|c| c.code_set.len()).unwrap_or(0),
                    )
                }
            },
        }
    }
}

impl TryFrom<DbCred> for Credential {
    type Error = ();

    fn try_from(value: DbCred) -> Result<Self, Self::Error> {
        let timestamp = value.last_changed_timestamp();
        // Work out what the policy is?
        match value {
            DbCred::V2Password {
                password: db_password,
                uuid,
                ..
            }
            | DbCred::Pw {
                password: Some(db_password),
                webauthn: _,
                totp: _,
                backup_code: _,
                claims: _,
                uuid,
            } => {
                let v_password = Password::try_from(db_password)?;
                let type_ = CredentialType::Password(v_password);
                if type_.is_valid() {
                    Ok(Credential {
                        type_,
                        uuid,
                        timestamp,
                    })
                } else {
                    Err(())
                }
            }
            DbCred::V2GenPassword {
                password: db_password,
                uuid,
                ..
            }
            | DbCred::GPw {
                password: Some(db_password),
                webauthn: _,
                totp: _,
                backup_code: _,
                claims: _,
                uuid,
            } => {
                let v_password = Password::try_from(db_password)?;
                let type_ = CredentialType::GeneratedPassword(v_password);
                if type_.is_valid() {
                    Ok(Credential {
                        type_,
                        uuid,
                        timestamp,
                    })
                } else {
                    Err(())
                }
            }
            DbCred::PwMfa {
                password: Some(db_password),
                webauthn: maybe_db_webauthn,
                totp,
                backup_code,
                claims: _,
                uuid,
            } => {
                let v_password = Password::try_from(db_password)?;

                let v_totp = match totp {
                    Some(dbt) => {
                        let l = "totp".to_string();
                        let t = Totp::try_from(dbt)?;
                        Map::from([(l, t)])
                    }
                    None => Map::default(),
                };

                let v_webauthn = match maybe_db_webauthn {
                    Some(db_webauthn) => db_webauthn
                        .into_iter()
                        .map(|wc| {
                            (
                                wc.label,
                                SecurityKey::from(WebauthnCredential::from(CredentialV3 {
                                    cred_id: wc.id,
                                    cred: wc.cred,
                                    counter: wc.counter,
                                    verified: wc.verified,
                                    registration_policy: wc.registration_policy,
                                })),
                            )
                        })
                        .collect(),
                    None => Default::default(),
                };

                let v_backup_code = match backup_code {
                    Some(dbb) => Some(BackupCodes::try_from(dbb)?),
                    None => None,
                };

                let type_ =
                    CredentialType::PasswordMfa(v_password, v_totp, v_webauthn, v_backup_code);

                if type_.is_valid() {
                    Ok(Credential {
                        type_,
                        uuid,
                        timestamp,
                    })
                } else {
                    Err(())
                }
            }
            DbCred::Wn {
                password: _,
                webauthn: Some(db_webauthn),
                totp: _,
                backup_code: _,
                claims: _,
                uuid,
            } => {
                let v_webauthn = db_webauthn
                    .into_iter()
                    .map(|wc| {
                        (
                            wc.label,
                            Passkey::from(WebauthnCredential::from(CredentialV3 {
                                cred_id: wc.id,
                                cred: wc.cred,
                                counter: wc.counter,
                                verified: wc.verified,
                                registration_policy: wc.registration_policy,
                            })),
                        )
                    })
                    .collect();

                let type_ = CredentialType::Webauthn(v_webauthn);

                if type_.is_valid() {
                    Ok(Credential {
                        type_,
                        uuid,
                        timestamp,
                    })
                } else {
                    Err(())
                }
            }
            DbCred::TmpWn {
                webauthn: db_webauthn,
                uuid,
            } => {
                let v_webauthn = db_webauthn.into_iter().collect();
                let type_ = CredentialType::Webauthn(v_webauthn);

                if type_.is_valid() {
                    Ok(Credential {
                        type_,
                        uuid,
                        timestamp,
                    })
                } else {
                    Err(())
                }
            }
            DbCred::V2PasswordMfa {
                password: db_password,
                totp: maybe_db_totp,
                backup_code,
                webauthn: db_webauthn,
                uuid,
            } => {
                let v_password = Password::try_from(db_password)?;

                let v_totp = match maybe_db_totp {
                    Some(dbt) => {
                        let l = "totp".to_string();
                        let t = Totp::try_from(dbt)?;
                        Map::from([(l, t)])
                    }
                    None => Map::default(),
                };

                let v_backup_code = match backup_code {
                    Some(dbb) => Some(BackupCodes::try_from(dbb)?),
                    None => None,
                };

                let v_webauthn = db_webauthn.into_iter().collect();

                let type_ =
                    CredentialType::PasswordMfa(v_password, v_totp, v_webauthn, v_backup_code);

                if type_.is_valid() {
                    Ok(Credential {
                        type_,
                        uuid,
                        timestamp,
                    })
                } else {
                    Err(())
                }
            }
            DbCred::V3PasswordMfa {
                password: db_password,
                totp: db_totp,
                backup_code,
                webauthn: db_webauthn,
                uuid,
                ..
            } => {
                let v_password = Password::try_from(db_password)?;

                let v_totp = db_totp
                    .into_iter()
                    .map(|(l, dbt)| Totp::try_from(dbt).map(|t| (l, t)))
                    .collect::<Result<Map<_, _>, _>>()?;

                let v_backup_code = match backup_code {
                    Some(dbb) => Some(BackupCodes::try_from(dbb)?),
                    None => None,
                };

                let v_webauthn = db_webauthn.into_iter().collect();

                let type_ =
                    CredentialType::PasswordMfa(v_password, v_totp, v_webauthn, v_backup_code);

                if type_.is_valid() {
                    Ok(Credential {
                        type_,
                        uuid,
                        timestamp,
                    })
                } else {
                    Err(())
                }
            }
            credential => {
                error!("Database content may be corrupt - invalid credential state");
                debug!(%credential);
                debug!(?credential);
                Err(())
            }
        }
    }
}

impl Credential {
    /// Create a new credential that contains a CredentialType::Password
    pub fn new_password_only(
        policy: &CryptoPolicy,
        cleartext: &str,
    ) -> Result<Self, OperationError> {
        Password::new(policy, cleartext)
            .map_err(|e| {
                error!(crypto_err = ?e);
                OperationError::CryptographyError
            })
            .map(Self::new_from_password)
    }

    /// Create a new credential that contains a CredentialType::GeneratedPassword
    pub fn new_generatedpassword_only(
        policy: &CryptoPolicy,
        cleartext: &str,
    ) -> Result<Self, OperationError> {
        Password::new(policy, cleartext)
            .map_err(|e| {
                error!(crypto_err = ?e);
                OperationError::CryptographyError
            })
            .map(Self::new_from_generatedpassword)
    }

    /// Update the state of the Password on this credential, if a password is present. If possible
    /// this will convert the credential to a PasswordMFA in some cases, or fail in others.
    pub fn set_password(
        &self,
        policy: &CryptoPolicy,
        cleartext: &str,
    ) -> Result<Self, OperationError> {
        Password::new(policy, cleartext)
            .map_err(|e| {
                error!(crypto_err = ?e);
                OperationError::CryptographyError
            })
            .map(|pw| self.update_password(pw))
    }

    pub fn upgrade_password(
        &self,
        policy: &CryptoPolicy,
        cleartext: &str,
    ) -> Result<Option<Self>, OperationError> {
        let valid = self.password_ref().and_then(|pw| {
            pw.verify(cleartext).map_err(|e| {
                error!(crypto_err = ?e);
                OperationError::CryptographyError
            })
        })?;

        if valid {
            let pw = Password::new(policy, cleartext).map_err(|e| {
                error!(crypto_err = ?e);
                OperationError::CryptographyError
            })?;

            // Note, during update_password we normally rotate the uuid, here we
            // set it back to our current value. This is because we are just
            // updating the hash value, not actually changing the password itself.
            let mut cred = self.update_password(pw);
            cred.uuid = self.uuid;

            Ok(Some(cred))
        } else {
            // No updates needed, password has changed.
            Ok(None)
        }
    }

    /// Extend this credential with another alternate webauthn credential. This is especially
    /// useful for `PasswordMfa` where you can have many webauthn credentials and a password
    /// generally so that one is a backup.
    pub fn append_securitykey(
        &self,
        label: String,
        cred: SecurityKey,
    ) -> Result<Self, OperationError> {
        let type_ = match &self.type_ {
            CredentialType::Password(pw) | CredentialType::GeneratedPassword(pw) => {
                let mut wan = Map::new();
                wan.insert(label, cred);
                CredentialType::PasswordMfa(pw.clone(), Map::default(), wan, None)
            }
            CredentialType::PasswordMfa(pw, totp, map, backup_code) => {
                let mut nmap = map.clone();
                if nmap.insert(label.clone(), cred).is_some() {
                    return Err(OperationError::InvalidAttribute(format!(
                        "Webauthn label '{label:?}' already exists"
                    )));
                }
                CredentialType::PasswordMfa(pw.clone(), totp.clone(), nmap, backup_code.clone())
            }
            // Ignore
            CredentialType::Webauthn(map) => CredentialType::Webauthn(map.clone()),
        };

        // Check stuff
        Ok(Credential {
            type_,
            // Rotate the credential id on any change to invalidate sessions.
            uuid: Uuid::new_v4(),
            // Update the timestamp to signify a changed credential
            timestamp: OffsetDateTime::now_utc(),
        })
    }

    /// Remove a webauthn token identified by `label` from this Credential.
    pub fn remove_securitykey(&self, label: &str) -> Result<Self, OperationError> {
        let type_ = match &self.type_ {
            CredentialType::Password(_)
            | CredentialType::GeneratedPassword(_)
            | CredentialType::Webauthn(_) => {
                return Err(OperationError::InvalidAttribute(
                    "SecurityKey is not present on this credential".to_string(),
                ));
            }
            CredentialType::PasswordMfa(pw, totp, map, backup_code) => {
                let mut nmap = map.clone();
                if nmap.remove(label).is_none() {
                    return Err(OperationError::InvalidAttribute(format!(
                        "Removing Webauthn token with label '{label:?}': does not exist"
                    )));
                }
                if nmap.is_empty() {
                    if !totp.is_empty() {
                        CredentialType::PasswordMfa(
                            pw.clone(),
                            totp.clone(),
                            nmap,
                            backup_code.clone(),
                        )
                    } else {
                        // Note: No need to keep backup code if it is no longer MFA
                        CredentialType::Password(pw.clone())
                    }
                } else {
                    CredentialType::PasswordMfa(pw.clone(), totp.clone(), nmap, backup_code.clone())
                }
            }
        };

        // Check stuff
        Ok(Credential {
            type_,
            // Rotate the credential id on any change to invalidate sessions.
            uuid: Uuid::new_v4(),
            // Update the timestamp to signify a changed credential
            timestamp: OffsetDateTime::now_utc(),
        })
    }

    #[allow(clippy::ptr_arg)]
    /// After a successful authentication with Webauthn, we need to advance the credentials
    /// counter value to prevent certain classes of replay attacks.
    pub fn update_webauthn_properties(
        &self,
        auth_result: &AuthenticationResult,
    ) -> Result<Option<Self>, OperationError> {
        let type_ = match &self.type_ {
            CredentialType::Password(_pw) | CredentialType::GeneratedPassword(_pw) => {
                // Should not be possible!
                // -- this does occur when we have mixed pw/passkey
                // and we need to do an update, so we just mask this no Ok(None).
                // return Err(OperationError::InvalidState);
                return Ok(None);
            }
            CredentialType::Webauthn(map) => {
                let mut nmap = map.clone();
                nmap.values_mut().for_each(|pk| {
                    pk.update_credential(auth_result);
                });
                CredentialType::Webauthn(nmap)
            }
            CredentialType::PasswordMfa(pw, totp, map, backup_code) => {
                let mut nmap = map.clone();
                nmap.values_mut().for_each(|sk| {
                    sk.update_credential(auth_result);
                });
                CredentialType::PasswordMfa(pw.clone(), totp.clone(), nmap, backup_code.clone())
            }
        };

        Ok(Some(Credential {
            type_,
            // Rotate the credential id on any change to invalidate sessions.
            uuid: Uuid::new_v4(),
            // Update the timestamp to signify a changed credential
            timestamp: OffsetDateTime::now_utc(),
        }))
    }

    pub(crate) fn has_securitykey(&self) -> bool {
        match &self.type_ {
            CredentialType::PasswordMfa(_, _, map, _) => !map.is_empty(),
            _ => false,
        }
    }

    /// Get a reference to the contained webuthn credentials, if any.
    pub fn securitykey_ref(&self) -> Result<&Map<String, SecurityKey>, OperationError> {
        match &self.type_ {
            CredentialType::Webauthn(_)
            | CredentialType::Password(_)
            | CredentialType::GeneratedPassword(_) => Err(OperationError::InvalidAccountState(
                "non-webauthn cred type?".to_string(),
            )),
            CredentialType::PasswordMfa(_, _, map, _) => Ok(map),
        }
    }

    pub fn passkey_ref(&self) -> Result<&Map<String, Passkey>, OperationError> {
        match &self.type_ {
            CredentialType::PasswordMfa(_, _, _, _)
            | CredentialType::Password(_)
            | CredentialType::GeneratedPassword(_) => Err(OperationError::InvalidAccountState(
                "non-webauthn cred type?".to_string(),
            )),
            CredentialType::Webauthn(map) => Ok(map),
        }
    }

    /// Get a reference to the contained password, if any.
    pub fn password_ref(&self) -> Result<&Password, OperationError> {
        match &self.type_ {
            CredentialType::Password(pw)
            | CredentialType::GeneratedPassword(pw)
            | CredentialType::PasswordMfa(pw, _, _, _) => Ok(pw),
            CredentialType::Webauthn(_) => Err(OperationError::InvalidAccountState(
                "non-password cred type?".to_string(),
            )),
        }
    }

    pub fn is_mfa(&self) -> bool {
        match &self.type_ {
            CredentialType::Password(_) | CredentialType::GeneratedPassword(_) => false,
            CredentialType::PasswordMfa(..) | CredentialType::Webauthn(_) => true,
        }
    }

    #[cfg(test)]
    pub fn verify_password(&self, cleartext: &str) -> Result<bool, OperationError> {
        self.password_ref().and_then(|pw| {
            pw.verify(cleartext).map_err(|e| {
                error!(crypto_err = ?e);
                OperationError::CryptographyError
            })
        })
    }

    /// Extract this credential into it's Serialisable Database form, ready for persistence.
    pub fn to_db_valuev1(&self) -> DbCred {
        let uuid = self.uuid;
        match &self.type_ {
            CredentialType::Password(pw) => DbCred::V2Password {
                password: pw.to_dbpasswordv1(),
                uuid,
                timestamp: self.timestamp,
            },
            CredentialType::GeneratedPassword(pw) => DbCred::V2GenPassword {
                password: pw.to_dbpasswordv1(),
                uuid,
                timestamp: self.timestamp,
            },
            CredentialType::PasswordMfa(pw, totp, map, backup_code) => DbCred::V3PasswordMfa {
                password: pw.to_dbpasswordv1(),
                totp: totp
                    .iter()
                    .map(|(l, t)| (l.clone(), t.to_dbtotpv1()))
                    .collect(),
                backup_code: backup_code.as_ref().map(|b| b.to_dbbackupcodev1()),
                webauthn: map.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
                uuid,
                timestamp: self.timestamp,
            },
            CredentialType::Webauthn(map) => DbCred::TmpWn {
                webauthn: map.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
                uuid,
            },
        }
    }

    pub(crate) fn update_password(&self, pw: Password) -> Self {
        let type_ = match &self.type_ {
            CredentialType::Password(_) | CredentialType::GeneratedPassword(_) => {
                CredentialType::Password(pw)
            }
            CredentialType::PasswordMfa(_, totp, wan, backup_code) => {
                CredentialType::PasswordMfa(pw, totp.clone(), wan.clone(), backup_code.clone())
            }
            // Ignore
            CredentialType::Webauthn(wan) => CredentialType::Webauthn(wan.clone()),
        };
        Credential {
            type_,
            // Rotate the credential id on any change to invalidate sessions.
            uuid: Uuid::new_v4(),
            // Update the timestamp to signify a changed credential
            timestamp: OffsetDateTime::now_utc(),
        }
    }

    // We don't make totp accessible from outside the crate for now.
    pub(crate) fn append_totp(&self, label: String, totp: Totp) -> Self {
        let type_ = match &self.type_ {
            CredentialType::Password(pw) | CredentialType::GeneratedPassword(pw) => {
                CredentialType::PasswordMfa(
                    pw.clone(),
                    Map::from([(label, totp)]),
                    Map::new(),
                    None,
                )
            }
            CredentialType::PasswordMfa(pw, totps, wan, backup_code) => {
                let mut totps = totps.clone();
                let replaced = totps.insert(label, totp).is_none();
                debug_assert!(replaced);

                CredentialType::PasswordMfa(pw.clone(), totps, wan.clone(), backup_code.clone())
            }
            CredentialType::Webauthn(wan) => {
                debug_assert!(false);
                CredentialType::Webauthn(wan.clone())
            }
        };
        Credential {
            type_,
            // Rotate the credential id on any change to invalidate sessions.
            uuid: Uuid::new_v4(),
            // Update the timestamp to signify a changed credential
            timestamp: OffsetDateTime::now_utc(),
        }
    }

    pub(crate) fn remove_totp(&self, label: &str) -> Self {
        let type_ = match &self.type_ {
            CredentialType::PasswordMfa(pw, totp, wan, backup_code) => {
                let mut totp = totp.clone();
                let removed = totp.remove(label).is_some();
                debug_assert!(removed);

                if wan.is_empty() && totp.is_empty() {
                    // Note: No need to keep backup code if it is no longer MFA
                    CredentialType::Password(pw.clone())
                } else {
                    CredentialType::PasswordMfa(pw.clone(), totp, wan.clone(), backup_code.clone())
                }
            }
            _ => self.type_.clone(),
        };
        Credential {
            type_,
            // Rotate the credential id on any change to invalidate sessions.
            uuid: Uuid::new_v4(),
            // Update the timestamp to signify a changed credential
            timestamp: OffsetDateTime::now_utc(),
        }
    }

    pub(crate) fn has_totp_by_name(&self, label: &str) -> bool {
        match &self.type_ {
            CredentialType::PasswordMfa(_, totp, _, _) => totp.contains_key(label),
            _ => false,
        }
    }

    pub(crate) fn new_from_generatedpassword(pw: Password) -> Self {
        Credential {
            type_: CredentialType::GeneratedPassword(pw),
            uuid: Uuid::new_v4(),
            timestamp: OffsetDateTime::now_utc(),
        }
    }

    pub(crate) fn new_from_password(pw: Password) -> Self {
        Credential {
            type_: CredentialType::Password(pw),
            uuid: Uuid::new_v4(),
            timestamp: OffsetDateTime::now_utc(),
        }
    }

    pub(crate) fn softlock_policy(&self) -> CredSoftLockPolicy {
        match &self.type_ {
            CredentialType::Password(_pw) | CredentialType::GeneratedPassword(_pw) => {
                CredSoftLockPolicy::Password
            }
            CredentialType::PasswordMfa(_pw, totp, wan, _) => {
                // For backup code, use totp/wan policy (whatever is available)
                if !totp.is_empty() {
                    // What's the min step?
                    let min_step = totp
                        .iter()
                        .map(|(_, t)| t.step)
                        .min()
                        .unwrap_or(TOTP_DEFAULT_STEP);
                    CredSoftLockPolicy::Totp(min_step)
                } else if !wan.is_empty() {
                    CredSoftLockPolicy::Webauthn
                } else {
                    CredSoftLockPolicy::Password
                }
            }
            CredentialType::Webauthn(_wan) => CredSoftLockPolicy::Webauthn,
        }
    }

    pub(crate) fn update_backup_code(
        &self,
        backup_codes: BackupCodes,
    ) -> Result<Self, OperationError> {
        match &self.type_ {
            CredentialType::PasswordMfa(pw, totp, wan, _) => Ok(Credential {
                type_: CredentialType::PasswordMfa(
                    pw.clone(),
                    totp.clone(),
                    wan.clone(),
                    Some(backup_codes),
                ),
                // Rotate the credential id on any change to invalidate sessions.
                uuid: Uuid::new_v4(),
                // Update the timestamp to signify a changed credential
                timestamp: OffsetDateTime::now_utc(),
            }),
            _ => Err(OperationError::InvalidAccountState(
                "Non-MFA credential type".to_string(),
            )),
        }
    }

    pub(crate) fn invalidate_backup_code(
        self,
        code_to_remove: &str,
    ) -> Result<Self, OperationError> {
        match self.type_ {
            CredentialType::PasswordMfa(pw, totp, wan, opt_backup_codes) => {
                match opt_backup_codes {
                    Some(mut backup_codes) => {
                        backup_codes.remove(code_to_remove);
                        Ok(Credential {
                            type_: CredentialType::PasswordMfa(pw, totp, wan, Some(backup_codes)),
                            // Don't rotate uuid here since this is a consumption of a backup
                            // code.
                            uuid: self.uuid,
                            timestamp: self.timestamp,
                        })
                    }
                    _ => Err(OperationError::InvalidAccountState(
                        "backup code does not exist".to_string(),
                    )),
                }
            }
            _ => Err(OperationError::InvalidAccountState(
                "Non-MFA credential type".to_string(),
            )),
        }
    }

    pub(crate) fn remove_backup_code(&self) -> Result<Self, OperationError> {
        match &self.type_ {
            CredentialType::PasswordMfa(pw, totp, wan, _) => Ok(Credential {
                type_: CredentialType::PasswordMfa(pw.clone(), totp.clone(), wan.clone(), None),
                // Rotate the credential id on any change to invalidate sessions.
                uuid: Uuid::new_v4(),
                // Update the timestamp to signify a changed credential
                timestamp: OffsetDateTime::now_utc(),
            }),
            _ => Err(OperationError::InvalidAccountState(
                "Non-MFA credential type".to_string(),
            )),
        }
    }
}

impl CredentialType {
    fn is_valid(&self) -> bool {
        match self {
            CredentialType::Password(_) | CredentialType::GeneratedPassword(_) => true,
            CredentialType::PasswordMfa(_, m_totp, webauthn, _) => {
                !m_totp.is_empty() || !webauthn.is_empty() // ignore backup code (it should only be a complement for totp/webauth)
            }
            CredentialType::Webauthn(webauthn) => !webauthn.is_empty(),
        }
    }
}
