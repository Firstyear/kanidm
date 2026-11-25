use crate::{
    entry::{EntryInvalidCommitted, EntrySealedCommitted},
    event::ModifyEvent,
    plugins::Plugin,
    prelude::{BatchModifyEvent, QueryServerWriteTransaction, *},
    repl::cid::Cid,
};
use std::sync::Arc;

pub struct NameHistory {}

impl NameHistory {
    fn handle_name_updates(
        pre_cand: &[Arc<EntrySealedCommitted>],
        cand: &mut Vec<EntryInvalidCommitted>,
        cid: &Cid,
    ) -> Result<(), OperationError> {
        for (pre, post) in pre_cand.iter().zip(cand) {
            // here we check if the current entry has at least one of the classes we intend to target
            if post.has_class(&EntryClass::Account) {
                let pre_name_option = pre.get_ava_single(Attribute::Name);
                let post_name_option = post.get_ava_single(Attribute::Name);
                if let (Some(pre_name), Some(post_name)) = (pre_name_option, post_name_option) {
                    if pre_name != post_name {
                        match post_name {
                            Value::Iname(n) => post.add_ava_if_not_exist(
                                Attribute::NameHistory,
                                Value::AuditLogString(*cid, n),
                            ),
                            value => {
                                trace!(?value);
                                return Err(OperationError::InvalidValueState);
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn handle_name_creation(
        cands: &mut [EntryInvalidNew],
        cid: &Cid,
    ) -> Result<(), OperationError> {
        for cand in cands.iter_mut() {
            if cand.has_class(&EntryClass::Account) {
                if let Some(name) = cand.get_ava_single(Attribute::Name) {
                    match name {
                        Value::Iname(n) => cand.add_ava_if_not_exist(
                            Attribute::NameHistory,
                            Value::AuditLogString(*cid, n),
                        ),
                        value => {
                            trace!(?value);
                            return Err(OperationError::InvalidValueState);
                        }
                    }
                }
            }
        }

        Ok(())
    }
}

impl Plugin for NameHistory {
    fn id() -> &'static str {
        "plugin_name_history"
    }

    #[instrument(level = "debug", name = "name_history::pre_create_transform", skip_all)]
    fn pre_create_transform(
        qs: &mut QueryServerWriteTransaction,
        cand: &mut Vec<EntryInvalidNew>,
        _ce: &CreateEvent,
    ) -> Result<(), OperationError> {
        Self::handle_name_creation(cand, qs.get_txn_cid())
    }

    #[instrument(level = "debug", name = "name_history::pre_modify", skip_all)]
    fn pre_modify(
        qs: &mut QueryServerWriteTransaction,
        pre_cand: &[Arc<EntrySealedCommitted>],
        cand: &mut Vec<EntryInvalidCommitted>,
        _me: &ModifyEvent,
    ) -> Result<(), OperationError> {
        Self::handle_name_updates(pre_cand, cand, qs.get_txn_cid())
    }

    #[instrument(level = "debug", name = "name_history::pre_batch_modify", skip_all)]
    fn pre_batch_modify(
        qs: &mut QueryServerWriteTransaction,
        pre_cand: &[Arc<EntrySealedCommitted>],
        cand: &mut Vec<EntryInvalidCommitted>,
        _me: &BatchModifyEvent,
    ) -> Result<(), OperationError> {
        Self::handle_name_updates(pre_cand, cand, qs.get_txn_cid())
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use crate::{
        entry::{Entry, EntryInit, EntryNew},
        prelude::{entries::Attribute, uuid, EntryClass},
        repl::cid::Cid,
        value::Value,
        valueset::AUDIT_LOG_STRING_CAPACITY,
    };

    #[test]
    fn name_purge_and_set() {
        // Add another uuid to a type
        let cid = Cid::new(
            uuid!("d2b496bd-8493-47b7-8142-f568b5cf47ee"),
            Duration::new(20, 2),
        );
        let ea = entry_init!(
            (Attribute::Class, EntryClass::Account.to_value()),
            (Attribute::Class, EntryClass::Person.to_value()),
            (Attribute::Name, Value::new_iname("old_name")),
            (
                Attribute::Uuid,
                Value::Uuid(uuid!("d2b496bd-8493-47b7-8142-f568b5cf47ee"))
            ),
            (
                Attribute::NameHistory,
                Value::new_audit_log_string((cid.clone(), "old_name".to_string())).unwrap()
            ),
            (Attribute::Description, Value::new_utf8s("testperson")),
            (Attribute::DisplayName, Value::new_utf8s("old name person"))
        );
        let preload = vec![ea];
        run_modify_test!(
            Ok(()),
            preload,
            filter!(f_eq(Attribute::Name, PartialValue::new_iname("old_name"))),
            modlist!([
                m_purge(Attribute::Name),
                m_pres(Attribute::Name, &Value::new_iname("new_name_1"))
            ]),
            None,
            |_| {},
            |qs: &mut QueryServerWriteTransaction| {
                let e = qs
                    .internal_search_uuid(uuid!("d2b496bd-8493-47b7-8142-f568b5cf47ee"))
                    .expect("failed to get entry");
                let c = e
                    .get_ava_set(Attribute::NameHistory)
                    .expect("failed to get primary cred.");
                trace!("{:?}", c.clone());
                assert!(
                    c.contains(&PartialValue::new_utf8s("old_name"))
                        && c.contains(&PartialValue::new_utf8s("new_name_1"))
                )
            }
        );
    }

    #[test]
    fn name_creation() {
        // Add another uuid to a type
        let ea = entry_init!(
            (Attribute::Class, EntryClass::Account.to_value()),
            (Attribute::Class, EntryClass::Person.to_value()),
            (Attribute::Name, Value::new_iname("old_name")),
            (
                Attribute::Uuid,
                Value::Uuid(uuid!("d2b496bd-8493-47b7-8142-f568b5cf47e1"))
            ),
            (Attribute::Description, Value::new_utf8s("testperson")),
            (Attribute::DisplayName, Value::new_utf8s("old name person"))
        );
        let preload = Vec::with_capacity(0);
        let create = vec![ea];
        run_create_test!(
            Ok(None),
            preload,
            create,
            None,
            |qs: &mut QueryServerWriteTransaction| {
                let e = qs
                    .internal_search_uuid(uuid!("d2b496bd-8493-47b7-8142-f568b5cf47e1"))
                    .expect("failed to get entry");
                trace!("{:?}", e.get_ava());
                let name_history = e
                    .get_ava_set(Attribute::NameHistory)
                    .expect("failed to get name_history ava");

                assert!(name_history.contains(&PartialValue::new_utf8s("old_name")))
            }
        );
    }

    #[test]
    fn name_purge_and_set_with_filled_history() {
        let mut cids: Vec<Cid> = Vec::with_capacity(0);
        for i in 1..AUDIT_LOG_STRING_CAPACITY {
            cids.push(Cid::new(
                uuid!("d2b496bd-8493-47b7-8142-f568b5cf47e1"),
                Duration::new(20 + i as u64, 0),
            ))
        }
        // Add another uuid to a type
        let mut ea = entry_init!(
            (Attribute::Class, EntryClass::Account.to_value()),
            (Attribute::Class, EntryClass::Person.to_value()),
            (Attribute::Name, Value::new_iname("old_name8")),
            (
                Attribute::Uuid,
                Value::Uuid(uuid!("d2b496bd-8493-47b7-8142-f568b5cf47ee"))
            ),
            (Attribute::Description, Value::new_utf8s("testperson")),
            (Attribute::DisplayName, Value::new_utf8s("old name person"))
        );
        for (i, cid) in cids.iter().enumerate() {
            let index = 1 + i;
            let name = format!("old_name{index}");
            ea.add_ava(
                Attribute::NameHistory,
                Value::AuditLogString(cid.clone(), name),
            )
        }
        let preload = vec![ea];
        run_modify_test!(
            Ok(()),
            preload,
            filter!(f_eq(Attribute::Name, PartialValue::new_iname("old_name8"))),
            modlist!([
                m_purge(Attribute::Name),
                m_pres(Attribute::Name, &Value::new_iname("new_name"))
            ]),
            None,
            |_| {},
            |qs: &mut QueryServerWriteTransaction| {
                let e = qs
                    .internal_search_uuid(uuid!("d2b496bd-8493-47b7-8142-f568b5cf47ee"))
                    .expect("failed to get entry");
                let c = e
                    .get_ava_set(Attribute::NameHistory)
                    .expect("failed to get name_history ava :/");
                trace!(?c);
                assert!(
                    !c.contains(&PartialValue::new_utf8s("old_name1"))
                        && c.contains(&PartialValue::new_utf8s("new_name"))
                )
            }
        );
    }
}
