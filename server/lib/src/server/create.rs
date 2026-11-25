use crate::{
    prelude::*,
    server::{ChangeFlag, CreateEvent, Plugins},
};

impl QueryServerWriteTransaction<'_> {
    #[instrument(level = "debug", skip_all)]
    /// The create event is a raw, read only representation of the request
    /// that was made to us, including information about the identity
    /// performing the request.
    pub fn create(&mut self, ce: &CreateEvent) -> Result<Option<Vec<Uuid>>, OperationError> {
        if !ce.ident.is_internal() {
            security_info!(name = %ce.ident, "create initiator");
        }

        if ce.entries.is_empty() {
            request_error!("create: empty create request");
            return Err(OperationError::EmptyRequest);
        }

        // TODO #67: Do we need limits on number of creates, or do we constraint
        // based on request size in the frontend?

        // Copy the entries to a writeable form, this involves assigning a
        // change id so we can track what's happening.
        let candidates: Vec<Entry<EntryInit, EntryNew>> = ce.entries.clone();

        // Do we have rights to perform these creates?
        // create_allow_operation
        let access = self.get_accesscontrols();
        let op_allow = access
            .create_allow_operation(ce, &candidates)
            .map_err(|e| {
                admin_error!("Failed to check create access {:?}", e);
                e
            })?;
        if !op_allow {
            return Err(OperationError::AccessDenied);
        }

        // Before we assign replication metadata, we need to assert these entries
        // are valid to create within the set of replication transitions. This
        // means they *can not* be recycled or tombstones!
        if candidates.iter().any(|e| e.mask_recycled_ts().is_none()) {
            warn!("Refusing to create invalid entries that are attempting to bypass replication state machine.");
            return Err(OperationError::AccessDenied);
        }

        // Assign our replication metadata now, since we can proceed with this operation.
        let mut candidates: Vec<Entry<EntryInvalid, EntryNew>> = candidates
            .into_iter()
            .map(|e| e.assign_cid(*self.cid, &self.schema))
            .collect();

        // run any pre plugins, giving them the list of mutable candidates.
        // pre-plugins are defined here in their correct order of calling!
        // I have no intent to make these dynamic or configurable.
        Plugins::run_pre_create_transform(self, &mut candidates, ce).map_err(|e| {
            admin_error!("Create operation failed (pre_transform plugin), {:?}", e);
            e
        })?;

        // Now, normalise AND validate!
        let norm_cand = candidates
            .into_iter()
            .map(|e| {
                e.validate(&self.schema)
                    .map_err(|e| {
                        admin_error!("Schema Violation in create validate {:?}", e);
                        OperationError::SchemaViolation(e)
                    })
                    .map(|e| {
                        // Then seal the changes?
                        e.seal(&self.schema)
                    })
            })
            .collect::<Result<Vec<EntrySealedNew>, _>>()?;

        // Run any pre-create plugins now with schema validated entries.
        // This is important for normalisation of certain types i.e. class
        // or attributes for these checks.
        Plugins::run_pre_create(self, &norm_cand, ce).map_err(|e| {
            admin_error!("Create operation failed (plugin), {:?}", e);
            e
        })?;

        // We may change from ce.entries later to something else?
        let commit_cand = self.be_txn.create(&self.cid, norm_cand).map_err(|e| {
            admin_error!("betxn create failure {:?}", e);
            e
        })?;

        // Run any post plugins
        Plugins::run_post_create(self, &commit_cand, ce).map_err(|e| {
            admin_error!("Create operation failed (post plugin), {:?}", e);
            e
        })?;

        // We have finished all plugins and now have a successful operation - flag if
        // schema or acp requires reload.
        if !self.changed_flags.contains(ChangeFlag::SCHEMA)
            && commit_cand.iter().any(|e| {
                e.attribute_equality(Attribute::Class, &EntryClass::ClassType.into())
                    || e.attribute_equality(Attribute::Class, &EntryClass::AttributeType.into())
            })
        {
            self.changed_flags.insert(ChangeFlag::SCHEMA)
        }
        if !self.changed_flags.contains(ChangeFlag::ACP)
            && commit_cand.iter().any(|e| {
                e.attribute_equality(Attribute::Class, &EntryClass::AccessControlProfile.into())
            })
        {
            self.changed_flags.insert(ChangeFlag::ACP)
        }

        if !self.changed_flags.contains(ChangeFlag::APPLICATION)
            && commit_cand
                .iter()
                .any(|e| e.attribute_equality(Attribute::Class, &EntryClass::Application.into()))
        {
            self.changed_flags.insert(ChangeFlag::APPLICATION)
        }

        if !self.changed_flags.contains(ChangeFlag::OAUTH2)
            && commit_cand.iter().any(|e| {
                e.attribute_equality(Attribute::Class, &EntryClass::OAuth2ResourceServer.into())
            })
        {
            self.changed_flags.insert(ChangeFlag::OAUTH2)
        }

        if !self.changed_flags.contains(ChangeFlag::OAUTH2_CLIENT)
            && commit_cand
                .iter()
                .any(|e| e.attribute_equality(Attribute::Class, &EntryClass::OAuth2Client.into()))
        {
            self.changed_flags.insert(ChangeFlag::OAUTH2_CLIENT)
        }

        if !self.changed_flags.contains(ChangeFlag::FEATURE)
            && commit_cand
                .iter()
                .any(|e| e.attribute_equality(Attribute::Class, &EntryClass::Feature.into()))
        {
            self.changed_flags.insert(ChangeFlag::FEATURE)
        }

        if !self.changed_flags.contains(ChangeFlag::DOMAIN)
            && commit_cand
                .iter()
                .any(|e| e.attribute_equality(Attribute::Uuid, &PVUUID_DOMAIN_INFO))
        {
            self.changed_flags.insert(ChangeFlag::DOMAIN)
        }
        if !self.changed_flags.contains(ChangeFlag::SYSTEM_CONFIG)
            && commit_cand
                .iter()
                .any(|e| e.attribute_equality(Attribute::Uuid, &PVUUID_SYSTEM_CONFIG))
        {
            self.changed_flags.insert(ChangeFlag::SYSTEM_CONFIG)
        }

        if !self.changed_flags.contains(ChangeFlag::SYNC_AGREEMENT)
            && commit_cand
                .iter()
                .any(|e| e.attribute_equality(Attribute::Class, &EntryClass::SyncAccount.into()))
        {
            self.changed_flags.insert(ChangeFlag::SYNC_AGREEMENT)
        }

        if !self.changed_flags.contains(ChangeFlag::KEY_MATERIAL)
            && commit_cand.iter().any(|e| {
                e.attribute_equality(Attribute::Class, &EntryClass::KeyProvider.into())
                    || e.attribute_equality(Attribute::Class, &EntryClass::KeyObject.into())
            })
        {
            self.changed_flags.insert(ChangeFlag::KEY_MATERIAL)
        }

        self.changed_uuid
            .extend(commit_cand.iter().map(|e| e.get_uuid()));

        trace!(
            changed = ?self.changed_flags.iter_names().collect::<Vec<_>>(),
        );

        // We are complete, finalise logging and return

        if ce.ident.is_internal() {
            trace!("Create operation success");
        } else {
            admin_info!("Create operation success");
        }

        if ce.return_created_uuids {
            Ok(Some(commit_cand.iter().map(|e| e.get_uuid()).collect()))
        } else {
            Ok(None)
        }
    }

    pub fn internal_create(&mut self, entries: Vec<EntryInitNew>) -> Result<(), OperationError> {
        let ce = CreateEvent::new_internal(entries);
        self.create(&ce).map(|_| ())
    }

    pub fn impersonate_create(
        &mut self,
        ident: &Identity,
        entries: Vec<EntryInitNew>,
    ) -> Result<(), OperationError> {
        let ce = CreateEvent::new_impersonate_identity(ident.clone(), entries);
        self.create(&ce).map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use crate::prelude::*;
    use std::sync::Arc;

    #[qs_test]
    async fn test_create_user(server: &QueryServer) {
        let mut server_txn = server.write(duration_from_epoch_now()).await.unwrap();
        let filt = filter!(f_eq(Attribute::Name, PartialValue::new_iname("testperson")));
        let idm_admin = server_txn
            .internal_search_uuid(UUID_IDM_ADMIN)
            .expect("failed");

        let se1 = SearchEvent::new_impersonate_entry(idm_admin, filt);

        let mut e = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Person.to_value()),
            (Attribute::Class, EntryClass::Account.to_value()),
            (Attribute::Name, Value::new_iname("testperson")),
            (
                Attribute::Spn,
                Value::new_spn_str("testperson", "example.com")
            ),
            (
                Attribute::Uuid,
                Value::Uuid(uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"))
            ),
            (Attribute::Description, Value::new_utf8s("testperson")),
            (Attribute::DisplayName, Value::new_utf8s("testperson"))
        );

        let ce = CreateEvent::new_internal(vec![e.clone()]);

        let r1 = server_txn.search(&se1).expect("search failure");
        assert!(r1.is_empty());

        let cr = server_txn.create(&ce);
        assert!(cr.is_ok());

        let r2 = server_txn.search(&se1).expect("search failure");
        debug!("--> {:?}", r2);
        assert_eq!(r2.len(), 1);

        // We apply some member-of in the server now, so we add these before we seal.
        e.add_ava(Attribute::Class, EntryClass::MemberOf.into());
        e.add_ava(Attribute::MemberOf, Value::ReferN(UUID_IDM_ALL_PERSONS));
        e.add_ava(
            Attribute::DirectMemberOf,
            Value::ReferN(UUID_IDM_ALL_PERSONS),
        );
        e.add_ava(Attribute::MemberOf, Value::ReferN(UUID_IDM_ALL_ACCOUNTS));
        e.add_ava(
            Attribute::DirectMemberOf,
            Value::ReferN(UUID_IDM_ALL_ACCOUNTS),
        );
        // Indirectly via all persons
        e.add_ava(
            Attribute::MemberOf,
            Value::ReferN(UUID_IDM_PEOPLE_SELF_NAME_WRITE),
        );
        // we also add the name_history ava!
        e.add_ava(
            Attribute::NameHistory,
            Value::AuditLogString(server_txn.get_txn_cid().clone(), "testperson".to_string()),
        );

        let expected = vec![Arc::new(e.into_sealed_committed())];

        error!("{:#?}", r2);
        error!("{:#?}", expected);

        assert_eq!(r2, expected);

        assert!(server_txn.commit().is_ok());
    }

    #[qs_pair_test]
    async fn test_pair_create_user(server_a: &QueryServer, server_b: &QueryServer) {
        let mut server_a_txn = server_a.write(duration_from_epoch_now()).await.unwrap();
        let mut server_b_txn = server_b.write(duration_from_epoch_now()).await.unwrap();

        // Create on server a
        let filt = filter!(f_eq(Attribute::Name, PartialValue::new_iname("testperson")));

        let idm_admin = server_a_txn
            .internal_search_uuid(UUID_IDM_ADMIN)
            .expect("failed");
        let se_a = SearchEvent::new_impersonate_entry(idm_admin, filt.clone());

        // Can't clone admin here as these are two separate servers.
        let idm_admin = server_b_txn
            .internal_search_uuid(UUID_IDM_ADMIN)
            .expect("failed");
        let se_b = SearchEvent::new_impersonate_entry(idm_admin, filt);

        let e = entry_init!(
            (Attribute::Class, EntryClass::Person.to_value()),
            (Attribute::Class, EntryClass::Account.to_value()),
            (Attribute::Name, Value::new_iname("testperson")),
            (Attribute::Description, Value::new_utf8s("testperson")),
            (Attribute::DisplayName, Value::new_utf8s("testperson"))
        );

        let cr = server_a_txn.internal_create(vec![e.clone()]);
        assert!(cr.is_ok());

        let r1 = server_a_txn.search(&se_a).expect("search failure");
        assert!(!r1.is_empty());

        // Not on sb
        let r2 = server_b_txn.search(&se_b).expect("search failure");
        assert!(r2.is_empty());

        let cr = server_b_txn.internal_create(vec![e]);
        assert!(cr.is_ok());

        // Now is present
        let r2 = server_b_txn.search(&se_b).expect("search failure");
        assert!(!r2.is_empty());

        assert!(server_a_txn.commit().is_ok());
        assert!(server_b_txn.commit().is_ok());
    }
}
