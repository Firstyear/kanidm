use crate::{
    be::dbvalue::{DbValueKeyInternal, DbValueKeyStatus, DbValueKeyUsage},
    prelude::*,
    server::keys::KeyId,
    value::{KeyStatus, KeyUsage},
    valueset::{DbValueSetV2, ScimResolveStatus, ValueSet},
};
use crypto_glue::traits::Zeroizing;
use kanidm_proto::scim_v1::server::ScimKeyInternal;
use std::{collections::BTreeMap, fmt};
use time::OffsetDateTime;

#[derive(Clone, PartialEq, Eq)]
pub struct KeyInternalData {
    pub usage: KeyUsage,
    pub valid_from: u64,
    pub status: KeyStatus,
    pub status_cid: Cid,
    pub der: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for KeyInternalData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyInternalData")
            .field("usage", &self.usage)
            .field("valid_from", &self.valid_from)
            .field("status", &self.status)
            .field("status_cid", &self.status_cid)
            .finish()
    }
}

#[derive(Debug, Clone)]
pub struct ValueSetKeyInternal {
    map: BTreeMap<KeyId, KeyInternalData>,
}

impl ValueSetKeyInternal {
    pub fn new(
        id: KeyId,
        usage: KeyUsage,
        valid_from: u64,
        status: KeyStatus,
        status_cid: Cid,
        der: Zeroizing<Vec<u8>>,
    ) -> Box<Self> {
        let map = BTreeMap::from([(
            id,
            KeyInternalData {
                usage,
                valid_from,
                status,
                status_cid,
                der,
            },
        )]);

        Box::new(ValueSetKeyInternal { map })
    }

    pub fn from_key_iter(
        keys: impl Iterator<Item = (KeyId, KeyInternalData)>,
    ) -> Result<ValueSet, OperationError> {
        let map = keys.collect();

        Ok(Box::new(ValueSetKeyInternal { map }))
    }

    fn from_dbv_iter(
        keys: impl Iterator<Item = DbValueKeyInternal>,
    ) -> Result<ValueSet, OperationError> {
        let map = keys
            .map(|dbv_key| {
                match dbv_key {
                    DbValueKeyInternal::V1 {
                        id,
                        usage,
                        valid_from,
                        status,
                        status_cid,
                        der,
                    } => {
                        // Type cast, for now, these are both Vec<u8>
                        let id = KeyId::from(id);
                        let usage = match usage {
                            DbValueKeyUsage::JwsEs256 => KeyUsage::JwsEs256,
                            DbValueKeyUsage::JwsHs256 => KeyUsage::JwsHs256,
                            DbValueKeyUsage::JwsRs256 => KeyUsage::JwsRs256,
                            DbValueKeyUsage::JweA128GCM => KeyUsage::JweA128GCM,
                            DbValueKeyUsage::JweA256GCM => KeyUsage::JweA256GCM,
                            DbValueKeyUsage::HkdfS256 => KeyUsage::HkdfS256,
                        };
                        let status_cid = status_cid.into();
                        let status = match status {
                            DbValueKeyStatus::Valid => KeyStatus::Valid,
                            DbValueKeyStatus::Retained => KeyStatus::Retained,
                            DbValueKeyStatus::Revoked => KeyStatus::Revoked,
                        };

                        Ok((
                            id,
                            KeyInternalData {
                                usage,
                                valid_from,
                                status,
                                status_cid,
                                der,
                            },
                        ))
                    }
                }
            })
            .collect::<Result<BTreeMap<_, _>, _>>()?;

        Ok(Box::new(ValueSetKeyInternal { map }))
    }

    pub fn from_dbvs2(keys: Vec<DbValueKeyInternal>) -> Result<ValueSet, OperationError> {
        Self::from_dbv_iter(keys.into_iter())
    }

    fn to_vec_dbvs(&self) -> Vec<DbValueKeyInternal> {
        self.map
            .iter()
            .map(
                |(
                    id,
                    KeyInternalData {
                        usage,
                        status,
                        status_cid,
                        valid_from,
                        der,
                    },
                )| {
                    let id: String = id.to_string();
                    let usage = match usage {
                        KeyUsage::JwsEs256 => DbValueKeyUsage::JwsEs256,
                        KeyUsage::JwsHs256 => DbValueKeyUsage::JwsHs256,
                        KeyUsage::JwsRs256 => DbValueKeyUsage::JwsRs256,
                        KeyUsage::JweA128GCM => DbValueKeyUsage::JweA128GCM,
                        KeyUsage::JweA256GCM => DbValueKeyUsage::JweA256GCM,
                        KeyUsage::HkdfS256 => DbValueKeyUsage::HkdfS256,
                    };
                    let status_cid = status_cid.into();
                    let status = match status {
                        KeyStatus::Valid => DbValueKeyStatus::Valid,
                        KeyStatus::Retained => DbValueKeyStatus::Retained,
                        KeyStatus::Revoked => DbValueKeyStatus::Revoked,
                    };

                    DbValueKeyInternal::V1 {
                        id,
                        usage,
                        status,
                        status_cid,
                        der: der.clone(),
                        valid_from: *valid_from,
                    }
                },
            )
            .collect()
    }
}

impl ValueSetT for ValueSetKeyInternal {
    fn insert_checked(&mut self, _value: crate::value::Value) -> Result<bool, OperationError> {
        // match value {
        // I'm not sure we ever need to actually push this?
        /*
        Value::KeyInternal {
            id,
            usage,
            valid_from,
            status,
            der,
        } => {
            todo!();
        }
        */
        // _ => {
        debug_assert!(false);
        Err(OperationError::InvalidValueState)
        // }
        // }
    }

    fn clear(&mut self) {
        // When is this called?
        debug_assert!(false);
        self.map.clear();
    }

    fn remove(&mut self, pv: &crate::value::PartialValue, _cid: &Cid) -> bool {
        if let PartialValue::HexString(kid) = pv {
            if let Some(key_object) = self.map.get_mut(kid) {
                if !matches!(key_object.status, KeyStatus::Revoked) {
                    // Do we need to track the Cid like sessions?
                    key_object.status = KeyStatus::Revoked;
                }
            }
        }
        self.map.is_empty()
    }

    fn purge(&mut self, cid: &Cid) -> bool {
        for key_object in self.map.values_mut() {
            if !matches!(key_object.status, KeyStatus::Revoked) {
                key_object.status_cid = *cid;
                key_object.status = KeyStatus::Revoked;
            }
        }
        false
    }

    fn trim(&mut self, trim_cid: &Cid) {
        self.map.retain(|_, key_internal| {
            match &key_internal.status {
                KeyStatus::Revoked if &key_internal.status_cid < trim_cid => {
                    // This value is past the replication trim window and can now safely
                    // be removed
                    false
                }
                // Retain all else
                _ => true,
            }
        });
    }

    fn contains(&self, pv: &crate::value::PartialValue) -> bool {
        match pv {
            PartialValue::HexString(kid) => self.map.contains_key(kid),
            _ => false,
        }
    }

    fn substring(&self, _pv: &crate::value::PartialValue) -> bool {
        false
    }

    fn startswith(&self, _pv: &PartialValue) -> bool {
        false
    }

    fn endswith(&self, _pv: &PartialValue) -> bool {
        false
    }

    fn lessthan(&self, _pv: &crate::value::PartialValue) -> bool {
        false
    }

    fn len(&self) -> usize {
        self.map.len()
    }

    fn generate_idx_eq_keys(&self) -> Vec<String> {
        self.map
            .keys()
            .map(KeyId::to_string)
            // .map(hex::encode)
            .collect()
    }

    fn syntax(&self) -> SyntaxType {
        SyntaxType::KeyInternal
    }

    fn validate(&self, _schema_attr: &crate::schema::SchemaAttribute) -> bool {
        // Validate that every key id is a valid iname.
        self.map.keys().map(KeyId::as_str).all(|s| {
            // We validate these two first to prevent injection attacks.
            Value::validate_str_escapes(s)
                && Value::validate_singleline(s)
                && Value::validate_hexstr(s)
        })
    }

    fn to_proto_string_clone_iter(&self) -> Box<dyn Iterator<Item = String> + '_> {
        Box::new(self.map.iter().map(|(kid, key_object)| {
            format!(
                "{}: {} {} {}",
                kid, key_object.status, key_object.usage, key_object.valid_from
            )
        }))
    }

    fn to_scim_value(&self) -> Option<ScimResolveStatus> {
        Some(ScimResolveStatus::Resolved(ScimValueKanidm::from(
            self.map
                .iter()
                .map(|(kid, key_object)| {
                    let odt: OffsetDateTime =
                        OffsetDateTime::UNIX_EPOCH + Duration::from_secs(key_object.valid_from);

                    ScimKeyInternal {
                        key_id: kid.to_string(),
                        status: key_object.status.to_string(),
                        usage: key_object.usage.to_string(),
                        valid_from: odt,
                    }
                })
                .collect::<Vec<_>>(),
        )))
    }

    fn to_db_valueset_v2(&self) -> DbValueSetV2 {
        let keys = self.to_vec_dbvs();
        DbValueSetV2::KeyInternal(keys)
    }

    fn to_partialvalue_iter(&self) -> Box<dyn Iterator<Item = crate::value::PartialValue> + '_> {
        Box::new(
            self.map
                .keys()
                .map(KeyId::to_string)
                .map(PartialValue::HexString),
        )
    }

    fn to_value_iter(&self) -> Box<dyn Iterator<Item = crate::value::Value> + '_> {
        debug_assert!(false);
        Box::new(self.map.iter().map(
            |(
                id,
                KeyInternalData {
                    usage,
                    status,
                    status_cid,
                    der,
                    valid_from,
                },
            )| {
                Value::KeyInternal {
                    id: id.clone(),
                    usage: *usage,
                    status: *status,
                    status_cid: *status_cid,
                    der: der.clone(),
                    valid_from: *valid_from,
                }
            },
        ))
    }

    fn equal(&self, other: &super::ValueSet) -> bool {
        if let Some(other) = other.as_key_internal_map() {
            &self.map == other
        } else {
            debug_assert!(false);
            false
        }
    }

    fn merge(&mut self, other: &ValueSet) -> Result<(), OperationError> {
        let Some(b) = other.as_key_internal_map() else {
            debug_assert!(false);
            return Err(OperationError::InvalidValueState);
        };

        for (k_other, v_other) in b.iter() {
            if let Some(v_self) = self.map.get_mut(k_other) {
                // Revoked is always a greater status than retained or valid.
                if v_other.status > v_self.status {
                    *v_self = v_other.clone();
                }
            } else {
                // Not present, just insert.
                self.map.insert(k_other.clone(), v_other.clone());
            }
        }

        Ok(())
    }

    fn as_key_internal_map(&self) -> Option<&BTreeMap<KeyId, KeyInternalData>> {
        Some(&self.map)
    }

    fn repl_merge_valueset(&self, older: &ValueSet, trim_cid: &Cid) -> Option<ValueSet> {
        let b = older.as_key_internal_map()?;

        let mut map = self.map.clone();

        for (k_other, v_other) in b.iter() {
            if let Some(v_self) = map.get_mut(k_other) {
                // Revoked is always a greater status than retained or valid.
                if v_other.status > v_self.status {
                    *v_self = v_other.clone();
                }
            } else {
                // Not present, just insert.
                map.insert(k_other.clone(), v_other.clone());
            }
        }

        let mut vs = Box::new(ValueSetKeyInternal { map });

        vs.trim(trim_cid);

        Some(vs)
    }
}

#[cfg(test)]
mod tests {
    use super::{KeyInternalData, ValueSetKeyInternal};
    use crate::{prelude::*, server::keys::KeyId, value::*};
    use crypto_glue::traits::Zeroizing;

    #[test]
    fn test_valueset_key_internal_purge_trim() {
        let kid = KeyId::from("test".to_string());
        let usage = KeyUsage::JwsEs256;
        let valid_from = 0;
        let status = KeyStatus::Valid;
        let status_cid = Cid::new_zero();
        let der = Zeroizing::new(Vec::with_capacity(0));

        let mut vs_a: ValueSet =
            ValueSetKeyInternal::new(kid.clone(), usage, valid_from, status, status_cid, der);

        let one_cid = Cid::new_count(1);

        // Simulate session revocation.
        let r = vs_a.purge(&one_cid);

        assert!(!r);
        assert_eq!(vs_a.len(), 1);

        let key_internal = vs_a
            .as_key_internal_map()
            .and_then(|map| map.get(&kid))
            .expect("Unable to locate session");

        assert_eq!(key_internal.status, KeyStatus::Revoked);
        assert_eq!(key_internal.status_cid, one_cid);

        // Now trim
        let two_cid = Cid::new_count(2);

        vs_a.trim(&two_cid);

        assert!(vs_a.is_empty());
    }

    #[test]
    fn test_valueset_key_internal_merge_left() {
        let kid = KeyId::from("test".to_string());
        let usage = KeyUsage::JwsEs256;
        let valid_from = 0;
        let status = KeyStatus::Valid;
        let status_cid = Cid::new_zero();
        let der = Zeroizing::new(Vec::with_capacity(0));

        let mut vs_a: ValueSet = ValueSetKeyInternal::new(
            kid.clone(),
            usage,
            valid_from,
            status,
            status_cid.clone(),
            der.clone(),
        );

        let status = KeyStatus::Revoked;

        let vs_b: ValueSet =
            ValueSetKeyInternal::new(kid.clone(), usage, valid_from, status, status_cid, der);

        vs_a.merge(&vs_b).expect("Failed to merge");

        assert_eq!(vs_a.len(), 1);
        let key_internal = vs_a
            .as_key_internal_map()
            .and_then(|map| map.get(&kid))
            .expect("Unable to locate session");

        assert_eq!(key_internal.status, KeyStatus::Revoked);
    }

    #[test]
    fn test_valueset_key_internal_merge_right() {
        let kid = KeyId::from("test".to_string());
        let usage = KeyUsage::JwsEs256;
        let valid_from = 0;
        let status = KeyStatus::Valid;
        let status_cid = Cid::new_zero();
        let der = Zeroizing::new(Vec::with_capacity(0));

        let vs_a: ValueSet = ValueSetKeyInternal::new(
            kid.clone(),
            usage,
            valid_from,
            status,
            status_cid.clone(),
            der.clone(),
        );

        let status = KeyStatus::Revoked;

        let mut vs_b: ValueSet =
            ValueSetKeyInternal::new(kid.clone(), usage, valid_from, status, status_cid, der);

        vs_b.merge(&vs_a).expect("Failed to merge");

        assert_eq!(vs_b.len(), 1);

        let key_internal = vs_b
            .as_key_internal_map()
            .and_then(|map| map.get(&kid))
            .expect("Unable to locate session");

        assert_eq!(key_internal.status, KeyStatus::Revoked);
    }

    #[test]
    fn test_valueset_key_internal_repl_merge_left() {
        let kid = KeyId::from("test".to_string());
        let usage = KeyUsage::JwsEs256;
        let valid_from = 0;
        let status = KeyStatus::Valid;
        let zero_cid = Cid::new_zero();
        let one_cid = Cid::new_count(1);
        let two_cid = Cid::new_count(2);
        let der = Zeroizing::new(Vec::with_capacity(0));

        let kid_2 = KeyId::from("key_2".to_string());

        let vs_a: ValueSet = ValueSetKeyInternal::from_key_iter(
            [
                (
                    kid.clone(),
                    KeyInternalData {
                        usage,
                        valid_from,
                        status,
                        status_cid: two_cid.clone(),
                        der: der.clone(),
                    },
                ),
                (
                    kid_2.clone(),
                    KeyInternalData {
                        usage,
                        valid_from,
                        status: KeyStatus::Revoked,
                        status_cid: zero_cid.clone(),
                        der: der.clone(),
                    },
                ),
            ]
            .into_iter(),
        )
        .expect("Failed to build valueset");

        let status = KeyStatus::Revoked;

        let vs_b: ValueSet =
            ValueSetKeyInternal::new(kid.clone(), usage, valid_from, status, two_cid, der);

        let vs_r = vs_a
            .repl_merge_valueset(&vs_b, &one_cid)
            .expect("Failed to merge");

        let key_internal_map = vs_r.as_key_internal_map().expect("Unable to access map");

        eprintln!("{key_internal_map:?}");

        assert_eq!(vs_r.len(), 1);

        let key_internal = key_internal_map.get(&kid).expect("Unable to access key");

        assert_eq!(key_internal.status, KeyStatus::Revoked);

        // Assert the item was trimmed
        assert!(!key_internal_map.contains_key(&kid_2));
    }

    #[test]
    fn test_valueset_key_internal_repl_merge_right() {
        let kid = KeyId::from("test".to_string());
        let usage = KeyUsage::JwsEs256;
        let valid_from = 0;
        let status = KeyStatus::Valid;
        let zero_cid = Cid::new_zero();
        let one_cid = Cid::new_count(1);
        let two_cid = Cid::new_count(2);
        let der = Zeroizing::new(Vec::with_capacity(0));

        let kid_2 = KeyId::from("key_2".to_string());

        let vs_a: ValueSet = ValueSetKeyInternal::from_key_iter(
            [
                (
                    kid.clone(),
                    KeyInternalData {
                        usage,
                        valid_from,
                        status,
                        status_cid: two_cid.clone(),
                        der: der.clone(),
                    },
                ),
                (
                    kid_2.clone(),
                    KeyInternalData {
                        usage,
                        valid_from,
                        status: KeyStatus::Revoked,
                        status_cid: zero_cid.clone(),
                        der: der.clone(),
                    },
                ),
            ]
            .into_iter(),
        )
        .expect("Failed to build valueset");

        let status = KeyStatus::Revoked;

        let vs_b: ValueSet =
            ValueSetKeyInternal::new(kid.clone(), usage, valid_from, status, two_cid, der);

        let vs_r = vs_b
            .repl_merge_valueset(&vs_a, &one_cid)
            .expect("Failed to merge");

        let key_internal_map = vs_r.as_key_internal_map().expect("Unable to access map");

        eprintln!("{key_internal_map:?}");

        assert_eq!(vs_r.len(), 1);

        let key_internal = key_internal_map.get(&kid).expect("Unable to access key");

        assert_eq!(key_internal.status, KeyStatus::Revoked);

        // Assert the item was trimmed
        assert!(!key_internal_map.contains_key(&kid_2));
    }

    #[test]
    fn test_scim_key_internal() {
        let kid = KeyId::from("test".to_string());
        let usage = KeyUsage::JwsEs256;
        let valid_from = 0;
        let status = KeyStatus::Valid;
        let status_cid = Cid::new_zero();
        let der = Zeroizing::new(Vec::with_capacity(0));

        let vs: ValueSet =
            ValueSetKeyInternal::new(kid.clone(), usage, valid_from, status, status_cid, der);

        let data = r#"
[
  {
    "keyId": "test",
    "status": "valid",
    "usage": "jws_es256",
    "validFrom": "1970-01-01T00:00:00Z"
  }
]
        "#;
        crate::valueset::scim_json_reflexive(&vs, data);
    }
}
