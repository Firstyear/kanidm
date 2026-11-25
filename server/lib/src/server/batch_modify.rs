use super::{ChangeFlag, QueryServerWriteTransaction};
use crate::{prelude::*, server::Plugins};
use std::collections::BTreeMap;

pub type ModSetValid = BTreeMap<Uuid, ModifyList<ModifyValid>>;
pub type ModSetInvalid = BTreeMap<Uuid, ModifyList<ModifyInvalid>>;

pub struct BatchModifyEvent {
    pub ident: Identity,
    pub modset: ModSetValid,
}

impl QueryServerWriteTransaction<'_> {
    /// This function behaves different to modify. Modify applies the same
    /// modification operation en-mass to 1 -> N entries. This takes a set of modifications
    /// that define a precise entry to apply a change to and only modifies that.
    ///
    /// modify is for all entries matching this condition, do this change.
    ///
    /// batch_modify is for entry X apply mod A, for entry Y apply mod B etc. It allows you
    /// to do per-entry mods.
    ///
    /// The drawback is you need to know ahead of time what uuids you are affecting. This
    /// has parallels to scim, so it's not a significant issue.
    ///
    /// Otherwise, we follow the same pattern here as modify, and inside the transform
    /// the same modlists are used.
    #[instrument(level = "debug", skip_all)]
    pub fn batch_modify(&mut self, me: &BatchModifyEvent) -> Result<(), OperationError> {
        // ⚠️  =========
        // Effectively this is the same as modify but instead of apply modlist
        // we do it by uuid.

        // Get the candidates.
        // Modify applies a modlist to a filter, so we need to internal search
        // then apply.
        if !me.ident.is_internal() {
            security_info!(name = %me.ident, "batch modify initiator");
        }

        // Validate input.

        // Is the modlist non zero?
        if me.modset.is_empty() {
            request_error!("empty modify request");
            return Err(OperationError::EmptyRequest);
        }

        let filter_or = me
            .modset
            .keys()
            .copied()
            .map(|u| f_eq(Attribute::Uuid, PartialValue::Uuid(u)))
            .collect();

        let filter = filter_all!(f_or(filter_or))
            .validate(self.get_schema())
            .map_err(OperationError::SchemaViolation)?;

        // This also checks access controls due to use of the impersonation.
        let pre_candidates = self
            .impersonate_search_valid(filter.clone(), filter.clone(), &me.ident)
            .map_err(|e| {
                admin_error!("error in pre-candidate selection {:?}", e);
                e
            })?;

        if pre_candidates.is_empty() {
            if me.ident.is_internal() {
                trace!("no candidates match filter ... continuing {:?}", filter);
                return Ok(());
            } else {
                request_error!("no candidates match modset request, failure {:?}", filter);
                return Err(OperationError::NoMatchingEntries);
            }
        };

        if pre_candidates.len() != me.modset.len() {
            error!("Inconsistent modify, some uuids were not found in request.");
            return Err(OperationError::MissingEntries);
        }

        trace!("pre_candidates -> {:?}", pre_candidates);
        trace!("modset -> {:?}", me.modset);

        // Are we allowed to make the changes we want to?
        // modify_allow_operation
        let access = self.get_accesscontrols();

        let op_allow = access
            .batch_modify_allow_operation(me, &pre_candidates)
            .map_err(|e| {
                admin_error!("Unable to check batch modify access {:?}", e);
                e
            })?;
        if !op_allow {
            return Err(OperationError::AccessDenied);
        }

        // Clone a set of writeables.
        // Apply the modlist -> Remember, we have a set of origs
        // and the new modified ents.
        // =========
        // The primary difference to modify is here - notice we do per-uuid mods.
        let mut candidates = pre_candidates
            .iter()
            .map(|er| {
                let u = er.get_uuid();
                let mut ent_mut = er.as_ref().clone().invalidate(*self.cid, &self.trim_cid);

                me.modset
                    .get(&u)
                    .ok_or_else(|| {
                        error!("No entry for uuid {} was found, aborting", u);
                        OperationError::NoMatchingEntries
                    })
                    .and_then(|modlist| {
                        ent_mut
                            .apply_modlist(modlist)
                            // Return if success
                            .map(|()| ent_mut)
                            // Error log otherwise.
                            .inspect_err(|_e| {
                                error!("Modification failed for {}", u);
                            })
                    })
            })
            .collect::<Result<Vec<EntryInvalidCommitted>, _>>()?;

        // Did any of the candidates now become masked?
        if std::iter::zip(
            pre_candidates
                .iter()
                .map(|e| e.mask_recycled_ts().is_none()),
            candidates.iter().map(|e| e.mask_recycled_ts().is_none()),
        )
        .any(|(a, b)| a != b)
        {
            admin_warn!("Refusing to apply modifications that are attempting to bypass replication state machine.");
            return Err(OperationError::AccessDenied);
        }

        // Pre mod plugins
        // We should probably supply the pre-post cands here.
        Plugins::run_pre_batch_modify(self, &pre_candidates, &mut candidates, me).map_err(|e| {
            admin_error!("Pre-Modify operation failed (plugin), {:?}", e);
            e
        })?;

        let norm_cand = candidates
            .into_iter()
            .map(|entry| {
                entry
                    .validate(&self.schema)
                    .map_err(|e| {
                        admin_error!("Schema Violation in validation of modify_pre_apply {:?}", e);
                        OperationError::SchemaViolation(e)
                    })
                    .map(|entry| entry.seal(&self.schema))
            })
            .collect::<Result<Vec<EntrySealedCommitted>, _>>()?;

        // Backend Modify
        self.be_txn
            .modify(&self.cid, &pre_candidates, &norm_cand)
            .map_err(|e| {
                admin_error!("Modify operation failed (backend), {:?}", e);
                e
            })?;

        // Post Plugins
        //
        // memberOf actually wants the pre cand list and the norm_cand list to see what
        // changed. Could be optimised, but this is correct still ...
        Plugins::run_post_batch_modify(self, &pre_candidates, &norm_cand, me).map_err(|e| {
            admin_error!("Post-Modify operation failed (plugin), {:?}", e);
            e
        })?;

        // We have finished all plugs and now have a successful operation - flag if
        // schema or acp requires reload. Remember, this is a modify, so we need to check
        // pre and post cands.
        if !self.changed_flags.contains(ChangeFlag::SCHEMA)
            && norm_cand
                .iter()
                .chain(pre_candidates.iter().map(|e| e.as_ref()))
                .any(|e| {
                    e.attribute_equality(Attribute::Class, &EntryClass::ClassType.into())
                        || e.attribute_equality(Attribute::Class, &EntryClass::AttributeType.into())
                })
        {
            self.changed_flags.insert(ChangeFlag::SCHEMA)
        }

        if !self.changed_flags.contains(ChangeFlag::ACP)
            && norm_cand
                .iter()
                .chain(pre_candidates.iter().map(|e| e.as_ref()))
                .any(|e| {
                    e.attribute_equality(Attribute::Class, &EntryClass::AccessControlProfile.into())
                })
        {
            self.changed_flags.insert(ChangeFlag::ACP)
        }

        if !self.changed_flags.contains(ChangeFlag::APPLICATION)
            && norm_cand
                .iter()
                .chain(pre_candidates.iter().map(|e| e.as_ref()))
                .any(|e| e.attribute_equality(Attribute::Class, &EntryClass::Application.into()))
        {
            self.changed_flags.insert(ChangeFlag::APPLICATION)
        }

        if !self.changed_flags.contains(ChangeFlag::OAUTH2)
            && norm_cand
                .iter()
                .chain(pre_candidates.iter().map(|e| e.as_ref()))
                .any(|e| {
                    e.attribute_equality(Attribute::Class, &EntryClass::OAuth2ResourceServer.into())
                })
        {
            self.changed_flags.insert(ChangeFlag::OAUTH2)
        }

        if !self.changed_flags.contains(ChangeFlag::OAUTH2_CLIENT)
            && norm_cand
                .iter()
                .chain(pre_candidates.iter().map(|e| e.as_ref()))
                .any(|e| e.attribute_equality(Attribute::Class, &EntryClass::OAuth2Client.into()))
        {
            self.changed_flags.insert(ChangeFlag::OAUTH2_CLIENT)
        }

        if !self.changed_flags.contains(ChangeFlag::FEATURE)
            && norm_cand
                .iter()
                .chain(pre_candidates.iter().map(|e| e.as_ref()))
                .any(|e| e.attribute_equality(Attribute::Class, &EntryClass::Feature.into()))
        {
            self.changed_flags.insert(ChangeFlag::FEATURE)
        }

        if !self.changed_flags.contains(ChangeFlag::DOMAIN)
            && norm_cand
                .iter()
                .chain(pre_candidates.iter().map(|e| e.as_ref()))
                .any(|e| e.attribute_equality(Attribute::Uuid, &PVUUID_DOMAIN_INFO))
        {
            self.changed_flags.insert(ChangeFlag::DOMAIN)
        }

        if !self.changed_flags.contains(ChangeFlag::SYSTEM_CONFIG)
            && norm_cand
                .iter()
                .chain(pre_candidates.iter().map(|e| e.as_ref()))
                .any(|e| e.attribute_equality(Attribute::Uuid, &PVUUID_SYSTEM_CONFIG))
        {
            self.changed_flags.insert(ChangeFlag::SYSTEM_CONFIG)
        }

        if !self.changed_flags.contains(ChangeFlag::SYNC_AGREEMENT)
            && norm_cand
                .iter()
                .chain(pre_candidates.iter().map(|e| e.as_ref()))
                .any(|e| e.attribute_equality(Attribute::Class, &EntryClass::SyncAccount.into()))
        {
            self.changed_flags.insert(ChangeFlag::SYNC_AGREEMENT)
        }

        if !self.changed_flags.contains(ChangeFlag::KEY_MATERIAL)
            && norm_cand
                .iter()
                .chain(pre_candidates.iter().map(|e| e.as_ref()))
                .any(|e| {
                    e.attribute_equality(Attribute::Class, &EntryClass::KeyProvider.into())
                        || e.attribute_equality(Attribute::Class, &EntryClass::KeyObject.into())
                })
        {
            self.changed_flags.insert(ChangeFlag::KEY_MATERIAL)
        }

        self.changed_uuid.extend(
            norm_cand
                .iter()
                .map(|e| e.get_uuid())
                .chain(pre_candidates.iter().map(|e| e.get_uuid())),
        );

        trace!(
            changed = ?self.changed_flags.iter_names().collect::<Vec<_>>(),
        );

        // return
        if me.ident.is_internal() {
            trace!("Modify operation success");
        } else {
            admin_info!("Modify operation success");
        }
        Ok(())
    }

    pub fn internal_batch_modify(
        &mut self,
        mods_iter: impl Iterator<Item = (Uuid, ModifyList<ModifyInvalid>)>,
    ) -> Result<(), OperationError> {
        let modset = mods_iter
            .map(|(u, ml)| {
                ml.validate(self.get_schema())
                    .map(|modlist| (u, modlist))
                    .map_err(OperationError::SchemaViolation)
            })
            .collect::<Result<ModSetValid, _>>()?;
        let bme = BatchModifyEvent {
            ident: Identity::from_internal(),
            modset,
        };
        self.batch_modify(&bme)
    }
}

#[cfg(test)]
mod tests {
    use crate::prelude::*;

    #[qs_test]
    async fn test_batch_modify_basic(server: &QueryServer) {
        let mut server_txn = server.write(duration_from_epoch_now()).await.unwrap();
        // Setup entries.
        let uuid_a = Uuid::new_v4();
        let uuid_b = Uuid::new_v4();
        assert!(server_txn
            .internal_create(vec![
                entry_init!(
                    (Attribute::Class, EntryClass::Object.to_value()),
                    (Attribute::Uuid, Value::Uuid(uuid_a))
                ),
                entry_init!(
                    (Attribute::Class, EntryClass::Object.to_value()),
                    (Attribute::Uuid, Value::Uuid(uuid_b))
                ),
            ])
            .is_ok());

        // Do a batch mod.
        server_txn
            .internal_batch_modify(
                [
                    (
                        uuid_a,
                        ModifyList::new_append(Attribute::Description, Value::Utf8("a".into())),
                    ),
                    (
                        uuid_b,
                        ModifyList::new_append(Attribute::Description, Value::Utf8("b".into())),
                    ),
                ]
                .into_iter(),
            )
            .unwrap();

        // Now check them
        let ent_a = server_txn
            .internal_search_uuid(uuid_a)
            .expect("Failed to get entry.");
        let ent_b = server_txn
            .internal_search_uuid(uuid_b)
            .expect("Failed to get entry.");

        assert_eq!(ent_a.get_ava_single_utf8(Attribute::Description), Some("a"));
        assert_eq!(ent_b.get_ava_single_utf8(Attribute::Description), Some("b"));
    }
}
