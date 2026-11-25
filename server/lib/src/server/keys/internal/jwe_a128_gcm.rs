use super::KeyId;
use crate::{
    prelude::*,
    value::{KeyStatus, KeyUsage},
    valueset::KeyInternalData,
};
use compact_jwt::{
    compact::JweCompact,
    crypto::{JweA128GCMEncipher, JweA128KWEncipher},
    jwe::Jwe,
};
use crypto_glue::{aes128, traits::Zeroizing};
use std::{
    collections::BTreeMap,
    ops::Bound::{Included, Unbounded},
};

#[derive(Clone)]
pub enum InternalJweA128GCMStatus {
    Valid { cipher: JweA128KWEncipher },
    Retained { cipher: JweA128KWEncipher },
    Revoked,
}

#[derive(Clone)]
pub struct InternalJweA128GCM {
    valid_from: u64,
    status: InternalJweA128GCMStatus,
    status_cid: Cid,
}

#[derive(Default, Clone)]
pub struct KeyObjectInternalJweA128GCM {
    // active signing keys are in a BTreeMap indexed by their valid_from
    // time so that we can retrieve the active key.
    //
    // We don't need to worry about manipulating this at runtime, since any expiry
    // event will cause the keyObject to reload, which will reflect to this map.
    active: BTreeMap<u64, JweA128KWEncipher>,

    // All keys are stored by their KeyId for fast lookup. Only valid or retained
    // keys can be used to decrypt
    all: BTreeMap<KeyId, InternalJweA128GCM>,
}

impl KeyObjectInternalJweA128GCM {
    pub fn get_valid_cipher(&self, time: Duration) -> Option<&JweA128KWEncipher> {
        let ct_secs = time.as_secs();

        self.active
            .range((Unbounded, Included(ct_secs)))
            .next_back()
            .map(|(_time, cipher)| cipher)
    }

    pub fn assert_active(&mut self, valid_from: Duration, cid: &Cid) -> Result<(), OperationError> {
        if self.get_valid_cipher(valid_from).is_none() {
            // This means there is no active signing key, so we need to create one.
            debug!("no active jwe a128gcm found, creating a new one ...");
            self.new_active(valid_from, cid)
        } else {
            Ok(())
        }
    }

    #[instrument(level = "debug", name = "keyobject::jwe_a128_gcm::new", skip_all)]
    pub fn new_active(&mut self, valid_from: Duration, cid: &Cid) -> Result<(), OperationError> {
        let valid_from = valid_from.as_secs();

        let key = aes128::new_key();

        let mut cipher = JweA128KWEncipher::from(key);
        cipher.set_sign_option_embed_kid(true);
        let kid = cipher.get_kid().to_string();
        let kid = KeyId::from(kid);

        self.active.insert(valid_from, cipher.clone());

        self.all.insert(
            kid,
            InternalJweA128GCM {
                valid_from,
                status: InternalJweA128GCMStatus::Valid { cipher },
                status_cid: *cid,
            },
        );

        Ok(())
    }

    pub fn to_kid_iter(&self) -> impl Iterator<Item = &KeyId> {
        self.all.keys()
    }

    pub fn to_key_iter(&self) -> impl Iterator<Item = (KeyId, KeyInternalData)> + '_ {
        self.all.iter().map(|(key_id, internal_jwe)| {
            let usage = KeyUsage::JweA128GCM;

            let valid_from = internal_jwe.valid_from;
            let status_cid = internal_jwe.status_cid;

            let (status, der) = match &internal_jwe.status {
                InternalJweA128GCMStatus::Valid { cipher } => {
                    (KeyStatus::Valid, cipher.as_ref().as_slice().to_vec().into())
                }
                InternalJweA128GCMStatus::Retained { cipher } => (
                    KeyStatus::Retained,
                    cipher.as_ref().as_slice().to_vec().into(),
                ),
                InternalJweA128GCMStatus::Revoked => {
                    (KeyStatus::Revoked, Zeroizing::new(Vec::with_capacity(0)))
                }
            };

            (
                key_id.clone(),
                KeyInternalData {
                    usage,
                    valid_from,
                    der,
                    status,
                    status_cid,
                },
            )
        })
    }

    pub fn revoke(&mut self, revoke_key_id: &str, cid: &Cid) -> Result<bool, OperationError> {
        if let Some(key_to_revoke) = self.all.get_mut(revoke_key_id) {
            key_to_revoke.status = InternalJweA128GCMStatus::Revoked;
            key_to_revoke.status_cid = *cid;

            let valid_from = key_to_revoke.valid_from;

            // Remove it from the active set.
            self.active.remove(&valid_from);

            Ok(true)
        } else {
            // We didn't revoke anything
            Ok(false)
        }
    }

    pub fn load(
        &mut self,
        id: &KeyId,
        status: KeyStatus,
        status_cid: Cid,
        der: &[u8],
        valid_from: u64,
    ) -> Result<(), OperationError> {
        let status = match status {
            KeyStatus::Valid => {
                let key = aes128::key_from_slice(der).ok_or_else(|| {
                    error!(?id, "Unable to load A128GCM retained cipher");
                    OperationError::KP0037KeyObjectImportJweA128GCMInvalid
                })?;

                let mut cipher = JweA128KWEncipher::from(key);
                cipher.set_sign_option_embed_kid(true);
                // Ensure we have a coherent kid
                cipher.set_kid(id.as_str());

                self.active.insert(valid_from, cipher.clone());

                InternalJweA128GCMStatus::Valid { cipher }
            }
            KeyStatus::Retained => {
                let key = aes128::key_from_slice(der).ok_or_else(|| {
                    error!(?id, "Unable to load A128GCM retained cipher");
                    OperationError::KP0038KeyObjectImportJweA128GCMInvalid
                })?;

                let mut cipher = JweA128KWEncipher::from(key);
                cipher.set_sign_option_embed_kid(true);
                // Ensure we have a coherent kid
                cipher.set_kid(id.as_str());

                InternalJweA128GCMStatus::Retained { cipher }
            }
            KeyStatus::Revoked => InternalJweA128GCMStatus::Revoked,
        };

        let internal_jwe = InternalJweA128GCM {
            valid_from,
            status,
            status_cid,
        };

        self.all.insert(id.clone(), internal_jwe);

        Ok(())
    }

    pub fn decipher(&self, jwec: &JweCompact) -> Result<Jwe, OperationError> {
        let internal_jwe = jwec
            .kid()
            .map(KeyId::from)
            .and_then(|kid| {
                debug!(?kid);
                self.all.get(&kid)
            })
            .ok_or_else(|| {
                error!("JWE is encrypted by a key that is not present in this KeyObject");
                for pres_kid in self.all.keys() {
                    debug!(?pres_kid);
                }
                OperationError::KP0039KeyObjectJweNotAssociated
            })?;

        match &internal_jwe.status {
            InternalJweA128GCMStatus::Valid { cipher, .. }
            | InternalJweA128GCMStatus::Retained { cipher, .. } => {
                cipher.decipher(jwec).map_err(|jwt_err| {
                    error!(?jwt_err, "Failed to decrypt jwe");
                    OperationError::KP0040KeyObjectJweInvalid
                })
            }
            InternalJweA128GCMStatus::Revoked => {
                error!("The key used to encrypt this JWE has been revoked.");
                Err(OperationError::KP0041KeyObjectJweRevoked)
            }
        }
    }

    pub fn encipher(
        &self,
        jwe: &Jwe,
        current_time: Duration,
    ) -> Result<JweCompact, OperationError> {
        let Some(cipher) = self.get_valid_cipher(current_time) else {
            error!("No encryption keys available. This may indicate that no keys are valid yet!");
            return Err(OperationError::KP0042KeyObjectNoActiveEncryptionKeys);
        };

        cipher.encipher::<JweA128GCMEncipher>(jwe).map_err(|err| {
            error!(?err, "Unable to sign jwe");
            OperationError::KP0043KeyObjectJweA128GCMEncryption
        })
    }
}
