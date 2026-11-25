use crate::{
    prelude::*,
    repl::cid::Cid,
    schema::SchemaAttribute,
    valueset::{DbValueSetV2, ScimResolveStatus, ValueSet},
};
use kanidm_proto::scim_v1::server::ScimAuditString;
use std::collections::BTreeMap;
use time::OffsetDateTime;

type AuditLogStringType = (Cid, String);

pub const AUDIT_LOG_STRING_CAPACITY: usize = 9;

#[derive(Debug, Clone)]
pub struct ValueSetAuditLogString {
    map: BTreeMap<Cid, String>,
}

impl ValueSetAuditLogString {
    fn remove_oldest(&mut self) {
        // pop to size.
        while self.map.len() > AUDIT_LOG_STRING_CAPACITY {
            self.map.pop_first();
        }
    }

    pub fn new((c, s): AuditLogStringType) -> Box<Self> {
        let mut map = BTreeMap::new();
        map.insert(c, s);
        Box::new(ValueSetAuditLogString { map })
    }

    pub fn from_dbvs2(data: Vec<AuditLogStringType>) -> Result<ValueSet, OperationError> {
        let map = data.into_iter().collect();
        Ok(Box::new(ValueSetAuditLogString { map }))
    }
}

impl ValueSetT for ValueSetAuditLogString {
    fn insert_checked(&mut self, value: Value) -> Result<bool, OperationError> {
        match value {
            Value::AuditLogString(c, s) => {
                let r = self.map.insert(c, s);
                self.remove_oldest();
                // true if insert was a new value.
                Ok(r.is_none())
            }
            _ => {
                debug_assert!(false);
                Err(OperationError::InvalidValueState)
            }
        }
    }

    fn clear(&mut self) {
        self.map.clear();
    }

    fn remove(&mut self, _pv: &PartialValue, _cid: &Cid) -> bool {
        self.map.is_empty()
    }

    fn contains(&self, pv: &PartialValue) -> bool {
        match pv {
            PartialValue::Utf8(s) => self.map.values().any(|current| s.eq(current)),
            PartialValue::Cid(c) => self.map.contains_key(c),
            _ => {
                debug_assert!(false);
                true
            }
        }
    }

    fn substring(&self, _pv: &PartialValue) -> bool {
        false
    }

    fn startswith(&self, _pv: &PartialValue) -> bool {
        false
    }

    fn endswith(&self, _pv: &PartialValue) -> bool {
        false
    }

    fn lessthan(&self, _pv: &PartialValue) -> bool {
        false
    }

    fn len(&self) -> usize {
        self.map.len()
    }

    fn generate_idx_eq_keys(&self) -> Vec<String> {
        self.map.iter().map(|(d, s)| format!("{d}-{s}")).collect()
    }

    fn syntax(&self) -> SyntaxType {
        SyntaxType::AuditLogString
    }

    fn validate(&self, _schema_attr: &SchemaAttribute) -> bool {
        self.map
            .iter()
            .all(|(_, s)| Value::validate_str_escapes(s) && Value::validate_singleline(s))
            && self.map.len() <= AUDIT_LOG_STRING_CAPACITY
    }

    fn to_proto_string_clone_iter(&self) -> Box<dyn Iterator<Item = String> + '_> {
        Box::new(self.map.iter().map(|(d, s)| format!("{d}-{s}")))
    }

    fn to_scim_value(&self) -> Option<ScimResolveStatus> {
        Some(ScimResolveStatus::Resolved(ScimValueKanidm::from(
            self.map
                .iter()
                .map(|(cid, strdata)| {
                    let odt: OffsetDateTime = cid.into();
                    ScimAuditString {
                        date_time: odt,
                        value: strdata.clone(),
                    }
                })
                .collect::<Vec<_>>(),
        )))
    }

    fn to_db_valueset_v2(&self) -> DbValueSetV2 {
        DbValueSetV2::AuditLogString(self.map.iter().map(|(c, s)| (*c, s.clone())).collect())
    }

    fn to_partialvalue_iter(&self) -> Box<dyn Iterator<Item = PartialValue> + '_> {
        Box::new(self.map.keys().map(|c| PartialValue::Cid(*c)))
    }

    fn to_value_iter(&self) -> Box<dyn Iterator<Item = Value> + '_> {
        Box::new(
            self.map
                .iter()
                .map(|(c, s)| Value::AuditLogString(*c, s.clone())),
        )
    }

    fn equal(&self, other: &ValueSet) -> bool {
        if let Some(other) = other.as_audit_log_string() {
            &self.map == other
        } else {
            debug_assert!(false);
            false
        }
    }

    fn merge(&mut self, other: &ValueSet) -> Result<(), OperationError> {
        if let Some(b) = other.as_audit_log_string() {
            mergemaps!(self.map, b)?;
            self.remove_oldest();
            Ok(())
        } else {
            debug_assert!(false);
            Err(OperationError::InvalidValueState)
        }
    }

    #[allow(clippy::todo)]
    fn repl_merge_valueset(&self, older: &ValueSet, _trim_cid: &Cid) -> Option<ValueSet> {
        if let Some(mut map) = older.as_audit_log_string().cloned() {
            // Merge maps is right-preferencing, so this means that
            // newer content always wins over.
            mergemaps!(map, self.map)
                .map_err(|_: OperationError| ())
                .ok()?;
            let mut new_vs = Box::new(ValueSetAuditLogString { map });
            new_vs.remove_oldest();
            Some(new_vs)
        } else {
            debug_assert!(false);
            None
        }
    }

    fn as_audit_log_string(&self) -> Option<&BTreeMap<Cid, String>> {
        Some(&self.map)
    }
}

#[cfg(test)]
mod tests {
    use super::{ValueSetAuditLogString, AUDIT_LOG_STRING_CAPACITY};
    use crate::{repl::cid::Cid, value::Value, valueset::ValueSet};
    use std::time::Duration;

    #[test]
    fn test_valueset_auditlogstring_merge() {
        let mut vs: ValueSet = ValueSetAuditLogString::new((Cid::new_count(0), "A".to_string()));
        assert_eq!(vs.len(), 1);

        for i in 1..AUDIT_LOG_STRING_CAPACITY {
            vs.insert_checked(Value::AuditLogString(
                Cid::new_count(i as u64),
                "A".to_string(),
            ))
            .unwrap();
        }

        assert_eq!(vs.len(), AUDIT_LOG_STRING_CAPACITY);

        // Add one extra
        vs.insert_checked(Value::AuditLogString(
            Cid::new_count(AUDIT_LOG_STRING_CAPACITY as u64),
            "A".to_string(),
        ))
        .unwrap();

        assert_eq!(vs.len(), AUDIT_LOG_STRING_CAPACITY);

        let mut v_iter = vs.to_value_iter();
        let Some(Value::AuditLogString(c, _s)) = v_iter.next() else {
            unreachable!();
        };
        // Should always be '1' since the set merge would have pushed '0' (ring-buffer);
        assert_eq!(c.ts, Duration::from_secs(1));
        println!("{c:?}");
        drop(v_iter);

        // Make a second set.
        let other_vs: ValueSet = ValueSetAuditLogString::new(
            // Notice that 0 here is older than our other set items.
            (Cid::new_count(0), "A".to_string()),
        );
        assert_eq!(other_vs.len(), 1);

        // Merge. The content of other_vs should be dropped.
        vs.merge(&other_vs)
            .expect("Failed to merge, incorrect types");

        // No change in the state of the set.
        assert_eq!(vs.len(), AUDIT_LOG_STRING_CAPACITY);
        let mut v_iter = vs.to_value_iter();
        let Some(Value::AuditLogString(c, _s)) = v_iter.next() else {
            unreachable!();
        };
        // Should always be '1' since the set merge would have pushed '0' (ring-buffer);
        assert_eq!(c.ts, Duration::from_secs(1));
        println!("{c:?}");
        drop(v_iter);

        // Now merge in with a set that has a value that is newer.

        #[allow(clippy::bool_assert_comparison, clippy::assertions_on_constants)]
        {
            assert!(100 > AUDIT_LOG_STRING_CAPACITY);
        }

        let other_vs: ValueSet = ValueSetAuditLogString::new(
            // Notice that 0 here is older than our other set items.
            (Cid::new_count(100), "A".to_string()),
        );
        assert_eq!(other_vs.len(), 1);

        vs.merge(&other_vs)
            .expect("Failed to merge, incorrect types");

        // New value has pushed out the next oldest.
        assert_eq!(vs.len(), AUDIT_LOG_STRING_CAPACITY);
        let mut v_iter = vs.to_value_iter();
        let Some(Value::AuditLogString(c, _s)) = v_iter.next() else {
            unreachable!();
        };
        // Should always be '1' since the set merge would have pushed '0' (ring-buffer);
        println!("{c:?}");
        assert_eq!(c.ts, Duration::from_secs(2));
        drop(v_iter);
    }

    #[test]
    fn test_valueset_auditlogstring_repl_merge() {
        let zero_cid = Cid::new_zero();
        let mut vs: ValueSet = ValueSetAuditLogString::new((Cid::new_count(1), "A".to_string()));
        assert_eq!(vs.len(), 1);

        for i in 2..(AUDIT_LOG_STRING_CAPACITY + 1) {
            vs.insert_checked(Value::AuditLogString(
                Cid::new_count(i as u64),
                "A".to_string(),
            ))
            .unwrap();
        }

        assert_eq!(vs.len(), AUDIT_LOG_STRING_CAPACITY);

        // Make a second set.
        let other_vs: ValueSet = ValueSetAuditLogString::new(
            // Notice that 0 here is older than our other set items.
            (Cid::new_count(0), "A".to_string()),
        );
        assert_eq!(other_vs.len(), 1);

        // Merge. The content of other_vs should be dropped.
        let r_vs = vs
            .repl_merge_valueset(&other_vs, &zero_cid)
            .expect("merge did not occur");

        // No change in the state of the set.
        assert_eq!(r_vs.len(), AUDIT_LOG_STRING_CAPACITY);
        let mut v_iter = r_vs.to_value_iter();
        let Some(Value::AuditLogString(c, _s)) = v_iter.next() else {
            unreachable!();
        };
        // Should always be '1' since the set merge would have pushed '0' (ring-buffer);
        assert_eq!(c.ts, Duration::from_secs(1));
        println!("{c:?}");
        drop(v_iter);

        // Now merge in with a set that has a value that is newer.

        #[allow(clippy::bool_assert_comparison, clippy::assertions_on_constants)]
        {
            assert!(100 > AUDIT_LOG_STRING_CAPACITY);
        }

        let other_vs: ValueSet = ValueSetAuditLogString::new(
            // Notice that 0 here is older than our other set items.
            (Cid::new_count(100), "A".to_string()),
        );
        assert_eq!(other_vs.len(), 1);

        let r_vs = vs
            .repl_merge_valueset(&other_vs, &zero_cid)
            .expect("merge did not occur");

        // New value has pushed out the next oldest.
        assert_eq!(r_vs.len(), AUDIT_LOG_STRING_CAPACITY);
        let mut v_iter = r_vs.to_value_iter();
        let Some(Value::AuditLogString(c, _s)) = v_iter.next() else {
            unreachable!();
        };
        // Should always be '1' since the set merge would have pushed '0' (ring-buffer);
        println!("{c:?}");
        assert_eq!(c.ts, Duration::from_secs(2));
        drop(v_iter);
    }

    #[test]
    fn test_scim_auditlog_string() {
        let mut vs: ValueSet = ValueSetAuditLogString::new((Cid::new_count(0), "A".to_string()));
        assert!(vs.len() == 1);

        for i in 1..AUDIT_LOG_STRING_CAPACITY {
            vs.insert_checked(Value::AuditLogString(
                Cid::new_count(i as u64),
                "A".to_string(),
            ))
            .unwrap();
        }

        let data = r#"
[
  {
    "dateTime": "1970-01-01T00:00:00Z",
    "value": "A"
  },
  {
    "dateTime": "1970-01-01T00:00:01Z",
    "value": "A"
  },
  {
    "dateTime": "1970-01-01T00:00:02Z",
    "value": "A"
  },
  {
    "dateTime": "1970-01-01T00:00:03Z",
    "value": "A"
  },
  {
    "dateTime": "1970-01-01T00:00:04Z",
    "value": "A"
  },
  {
    "dateTime": "1970-01-01T00:00:05Z",
    "value": "A"
  },
  {
    "dateTime": "1970-01-01T00:00:06Z",
    "value": "A"
  },
  {
    "dateTime": "1970-01-01T00:00:07Z",
    "value": "A"
  },
  {
    "dateTime": "1970-01-01T00:00:08Z",
    "value": "A"
  }
]
"#;
        crate::valueset::scim_json_reflexive(&vs, data);
    }
}
