use super::KeyId;
use crate::{
    prelude::*,
    value::{KeyStatus, KeyUsage},
    valueset::KeyInternalData,
};
use compact_jwt::{
    compact::JweCompact,
    crypto::{JweA256GCMEncipher, JweA256KWEncipher},
    jwe::Jwe,
};
use crypto_glue::{aes256, traits::Zeroizing};
use std::{
    collections::BTreeMap,
    ops::Bound::{Included, Unbounded},
};

#[derive(Clone)]
pub enum InternalJweA256GCMStatus {
    Valid { cipher: JweA256KWEncipher },
    Retained { cipher: JweA256KWEncipher },
    Revoked,
}

#[derive(Clone)]
pub struct InternalJweA256GCM {
    valid_from: u64,
    status: InternalJweA256GCMStatus,
    status_cid: Cid,
}

#[derive(Default, Clone)]
pub struct KeyObjectInternalJweA256GCM {
    // active signing keys are in a BTreeMap indexed by their valid_from
    // time so that we can retrieve the active key.
    //
    // We don't need to worry about manipulating this at runtime, since any expiry
    // event will cause the keyObject to reload, which will reflect to this map.
    active: BTreeMap<u64, JweA256KWEncipher>,

    // All keys are stored by their KeyId for fast lookup. Only valid or retained
    // keys can be used to decrypt
    all: BTreeMap<KeyId, InternalJweA256GCM>,
}

impl KeyObjectInternalJweA256GCM {
    pub fn get_valid_cipher(&self, time: Duration) -> Option<&JweA256KWEncipher> {
        let ct_secs = time.as_secs();

        self.active
            .range((Unbounded, Included(ct_secs)))
            .next_back()
            .map(|(_time, cipher)| cipher)
    }

    pub fn assert_active(&mut self, valid_from: Duration, cid: &Cid) -> Result<(), OperationError> {
        if self.get_valid_cipher(valid_from).is_none() {
            // This means there is no active signing key, so we need to create one.
            debug!("no active jwe a256gcm found, creating a new one ...");
            self.new_active(valid_from, cid)
        } else {
            Ok(())
        }
    }

    #[instrument(level = "debug", name = "keyobject::jwe_a256_gcm::new", skip_all)]
    pub fn new_active(&mut self, valid_from: Duration, cid: &Cid) -> Result<(), OperationError> {
        let valid_from = valid_from.as_secs();

        let key = aes256::new_key();

        let mut cipher = JweA256KWEncipher::from(key);
        cipher.set_sign_option_embed_kid(true);
        let kid = cipher.get_kid();
        let kid = KeyId::from(kid);

        self.active.insert(valid_from, cipher.clone());

        self.all.insert(
            kid,
            InternalJweA256GCM {
                valid_from,
                status: InternalJweA256GCMStatus::Valid { cipher },
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
            let usage = KeyUsage::JweA256GCM;

            let valid_from = internal_jwe.valid_from;
            let status_cid = internal_jwe.status_cid;

            let (status, der) = match &internal_jwe.status {
                InternalJweA256GCMStatus::Valid { cipher } => {
                    (KeyStatus::Valid, cipher.as_ref().as_slice().to_vec().into())
                }
                InternalJweA256GCMStatus::Retained { cipher } => (
                    KeyStatus::Retained,
                    cipher.as_ref().as_slice().to_vec().into(),
                ),
                InternalJweA256GCMStatus::Revoked => {
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
            key_to_revoke.status = InternalJweA256GCMStatus::Revoked;
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
                let key = aes256::key_from_slice(der).ok_or_else(|| {
                    error!(?id, "Unable to load A256GCM retained cipher");
                    OperationError::KP0081KeyObjectImportJweA256GCMInvalid
                })?;

                let mut cipher = JweA256KWEncipher::from(key);
                // Ensure we have a coherent kid
                cipher.set_kid(Some(String::from(id.as_str())));

                self.active.insert(valid_from, cipher.clone());

                InternalJweA256GCMStatus::Valid { cipher }
            }
            KeyStatus::Retained => {
                let key = aes256::key_from_slice(der).ok_or_else(|| {
                    error!(?id, "Unable to load A256GCM retained cipher");
                    OperationError::KP0082KeyObjectImportJweA256GCMInvalid
                })?;

                let mut cipher = JweA256KWEncipher::from(key);
                // Ensure we have a coherent kid
                cipher.set_kid(Some(String::from(id.as_str())));

                InternalJweA256GCMStatus::Retained { cipher }
            }
            KeyStatus::Revoked => InternalJweA256GCMStatus::Revoked,
        };

        let internal_jwe = InternalJweA256GCM {
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
                OperationError::KP0083KeyObjectJweNotAssociated
            })?;

        match &internal_jwe.status {
            InternalJweA256GCMStatus::Valid { cipher, .. }
            | InternalJweA256GCMStatus::Retained { cipher, .. } => {
                cipher.decipher(jwec).map_err(|jwt_err| {
                    error!(?jwt_err, "Failed to decrypt jwe");
                    OperationError::KP0084KeyObjectJweInvalid
                })
            }
            InternalJweA256GCMStatus::Revoked => {
                error!("The key used to encrypt this JWE has been revoked.");
                Err(OperationError::KP0085KeyObjectJweRevoked)
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
            return Err(OperationError::KP0086KeyObjectNoActiveEncryptionKeys);
        };

        cipher.encipher::<JweA256GCMEncipher>(jwe).map_err(|err| {
            error!(?err, "Unable to sign jwe");
            OperationError::KP0087KeyObjectJweA256GCMEncryption
        })
    }
}
