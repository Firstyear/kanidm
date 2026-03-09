use std::sync::Arc;

use super::ChangeFlag;
use crate::plugins::Plugins;
use crate::prelude::*;

pub(crate) struct ModifyPartial<'a> {
    pub norm_cand: Vec<Entry<EntrySealed, EntryCommitted>>,
    pub pre_candidates: Vec<Arc<Entry<EntrySealed, EntryCommitted>>>,
    pub me: &'a ModifyEvent,
}

impl QueryServerWriteTransaction<'_> {
    #[instrument(level = "debug", skip_all)]
    pub fn modify(&mut self, me: &ModifyEvent) -> Result<(), OperationError> {
        let mp = self.modify_pre_apply(me)?;
        if let Some(mp) = mp {
            self.modify_apply(mp)
        } else {
            // No action to apply, the pre-apply said nothing to be done.
            Ok(())
        }
    }

    /// SAFETY: This is unsafe because you need to be careful about how you handle and check
    /// the Ok(None) case which occurs during internal operations, and that you DO NOT re-order
    /// and call multiple pre-applies at the same time, else you can cause DB corruption.
    #[instrument(level = "debug", skip_all)]
    pub(crate) fn modify_pre_apply<'x>(
        &mut self,
        me: &'x ModifyEvent,
    ) -> Result<Option<ModifyPartial<'x>>, OperationError> {
        trace!(?me);

        // Get the candidates.
        // Modify applies a modlist to a filter, so we need to internal search
        // then apply.
        if !me.ident.is_internal() {
            security_info!(name = %me.ident, "modify initiator");
        }

        // Validate input.

        // Is the modlist non zero?
        if me.modlist.is_empty() {
            request_error!("modify: empty modify request");
            return Err(OperationError::EmptyRequest);
        }

        // Is the modlist valid?
        // This is now done in the event transform

        // Is the filter invalid to schema?
        // This is now done in the event transform

        // This also checks access controls due to use of the impersonation.
        let pre_candidates = self
            .impersonate_search_valid(me.filter.clone(), me.filter_orig.clone(), &me.ident)
            .map_err(|e| {
                admin_error!("modify: error in pre-candidate selection {:?}", e);
                e
            })?;

        if pre_candidates.is_empty() {
            if me.ident.is_internal() {
                trace!(
                    "modify_pre_apply: no candidates match filter ... continuing {:?}",
                    me.filter
                );
                return Ok(None);
            } else {
                request_error!(
                    "modify: no candidates match filter, failure {:?}",
                    me.filter
                );
                return Err(OperationError::NoMatchingEntries);
            }
        };

        trace!("modify_pre_apply: pre_candidates -> {:?}", pre_candidates);
        trace!("modify_pre_apply: modlist -> {:?}", me.modlist);

        // Are we allowed to make the changes we want to?
        // modify_allow_operation
        let access = self.get_accesscontrols();
        let op_allow = access
            .modify_allow_operation(me, &pre_candidates)
            .map_err(|e| {
                admin_error!("Unable to check modify access {:?}", e);
                e
            })?;
        if !op_allow {
            return Err(OperationError::AccessDenied);
        }

        // Clone a set of writeables.
        // Apply the modlist -> Remember, we have a set of origs
        // and the new modified ents.
        let mut candidates: Vec<Entry<EntryInvalid, EntryCommitted>> = pre_candidates
            .iter()
            .map(|er| {
                er.as_ref()
                    .clone()
                    .invalidate(self.cid.clone(), &self.trim_cid)
            })
            .collect();

        candidates.iter_mut().try_for_each(|er| {
            er.apply_modlist(&me.modlist).inspect_err(|_e| {
                error!("Modification failed for {:?}", er.get_uuid());
            })
        })?;

        trace!("modify: candidates -> {:?}", candidates);

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
        Plugins::run_pre_modify(self, &pre_candidates, &mut candidates, me).map_err(|e| {
            admin_error!("Pre-Modify operation failed (plugin), {:?}", e);
            e
        })?;

        // NOTE: There is a potential optimisation here, where if
        // candidates == pre-candidates, then we don't need to store anything
        // because we effectively just did an assert. However, like all
        // optimisations, this could be premature - so we for now, just
        // do the CORRECT thing and recommit as we may find later we always
        // want to add CSN's or other.

        let res: Result<Vec<EntrySealedCommitted>, OperationError> = candidates
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
            .collect();

        let norm_cand: Vec<Entry<_, _>> = res?;

        Ok(Some(ModifyPartial {
            norm_cand,
            pre_candidates,
            me,
        }))
    }

    #[instrument(level = "debug", skip_all)]
    pub(crate) fn modify_apply(&mut self, mp: ModifyPartial<'_>) -> Result<(), OperationError> {
        let ModifyPartial {
            norm_cand,
            pre_candidates,
            me,
        } = mp;

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
        Plugins::run_post_modify(self, &pre_candidates, &norm_cand, me).map_err(|e| {
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
                .zip(pre_candidates.iter().map(|e| e.as_ref()))
                .any(|(post, pre)| {
                    // This is in the modify path only - because sessions can update the RS
                    // this can trigger reloads of all the oauth2 clients. That would make
                    // client credentials grant pretty expensive in these cases. To avoid this
                    // we check if "anything else" beside the oauth2session changed in this
                    // txn.
                    (post.attribute_equality(
                        Attribute::Class,
                        &EntryClass::OAuth2ResourceServer.into(),
                    ) || pre.attribute_equality(
                        Attribute::Class,
                        &EntryClass::OAuth2ResourceServer.into(),
                    )) && post
                        .entry_changed_excluding_attribute(Attribute::OAuth2Session, &self.cid)
                })
        {
            self.changed_flags.insert(ChangeFlag::OAUTH2)
        }

        if !self.changed_flags.contains(ChangeFlag::OAUTH2_CLIENT)
            && norm_cand
                .iter()
                .zip(pre_candidates.iter().map(|e| e.as_ref()))
                .any(|(post, pre)| {
                    post.attribute_equality(Attribute::Class, &EntryClass::OAuth2Client.into())
                        || pre
                            .attribute_equality(Attribute::Class, &EntryClass::OAuth2Client.into())
                })
        {
            self.changed_flags.insert(ChangeFlag::OAUTH2_CLIENT)
        }

        if !self.changed_flags.contains(ChangeFlag::FEATURE)
            && norm_cand
                .iter()
                .zip(pre_candidates.iter().map(|e| e.as_ref()))
                .any(|(post, pre)| {
                    post.attribute_equality(Attribute::Class, &EntryClass::Feature.into())
                        || pre.attribute_equality(Attribute::Class, &EntryClass::Feature.into())
                })
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
}

impl QueryServerWriteTransaction<'_> {
    /// Used in conjunction with internal_apply_writable, to get a pre/post
    /// pair, where post is pre-configured with metadata to allow
    /// modificiation before submit back to internal_apply_writable
    #[instrument(level = "debug", skip_all)]
    pub(crate) fn internal_search_writeable(
        &mut self,
        filter: &Filter<FilterInvalid>,
    ) -> Result<Vec<EntryTuple>, OperationError> {
        let f_valid = filter
            .validate(self.get_schema())
            .map_err(OperationError::SchemaViolation)?;
        let se = SearchEvent::new_internal(f_valid);
        self.search(&se).map(|vs| {
            vs.into_iter()
                .map(|e| {
                    let writeable = e
                        .as_ref()
                        .clone()
                        .invalidate(self.cid.clone(), &self.trim_cid);
                    (e, writeable)
                })
                .collect()
        })
    }

    /// Allows writing batches of modified entries without going through
    /// the modlist path. This allows more efficient batch transformations
    /// such as memberof, but at the expense that YOU must guarantee you
    /// uphold all other plugin and state rules that are important. You
    /// probably want modify instead.
    #[allow(clippy::needless_pass_by_value)]
    #[instrument(level = "debug", skip_all)]
    pub(crate) fn internal_apply_writable(
        &mut self,
        candidate_tuples: Vec<(Arc<EntrySealedCommitted>, EntryInvalidCommitted)>,
    ) -> Result<(), OperationError> {
        if candidate_tuples.is_empty() {
            // No action needed.
            return Ok(());
        }

        let (pre_candidates, candidates): (
            Vec<Arc<EntrySealedCommitted>>,
            Vec<EntryInvalidCommitted>,
        ) = candidate_tuples.into_iter().unzip();

        /*
        let mut pre_candidates = Vec::with_capacity(candidate_tuples.len());
        let mut candidates = Vec::with_capacity(candidate_tuples.len());

        for (pre, post) in candidate_tuples.into_iter() {
            pre_candidates.push(pre);
            candidates.push(post);
        }
        */

        let res: Result<Vec<Entry<EntrySealed, EntryCommitted>>, OperationError> = candidates
            .into_iter()
            .map(|e| {
                e.validate(&self.schema)
                    .map_err(|e| {
                        admin_error!(
                            "Schema Violation in internal_apply_writable validate: {:?}",
                            e
                        );
                        OperationError::SchemaViolation(e)
                    })
                    .map(|e| e.seal(&self.schema))
            })
            .collect();

        let norm_cand: Vec<Entry<_, _>> = res?;

        if cfg!(debug_assertions) || cfg!(test) {
            pre_candidates
                .iter()
                .zip(norm_cand.iter())
                .try_for_each(|(pre, post)| {
                    if pre.get_uuid() == post.get_uuid() {
                        Ok(())
                    } else {
                        admin_error!("modify - cand sets not correctly aligned");
                        Err(OperationError::InvalidRequestState)
                    }
                })?;
        }

        // Backend Modify
        self.be_txn
            .modify(&self.cid, &pre_candidates, &norm_cand)
            .map_err(|e| {
                admin_error!("Modify operation failed (backend), {:?}", e);
                e
            })?;

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
            && norm_cand.iter().any(|e| {
                e.attribute_equality(Attribute::Class, &EntryClass::OAuth2ResourceServer.into())
            })
        {
            self.changed_flags.insert(ChangeFlag::OAUTH2)
        }

        if !self.changed_flags.contains(ChangeFlag::OAUTH2_CLIENT)
            && norm_cand
                .iter()
                .any(|e| e.attribute_equality(Attribute::Class, &EntryClass::OAuth2Client.into()))
        {
            self.changed_flags.insert(ChangeFlag::OAUTH2_CLIENT)
        }

        if !self.changed_flags.contains(ChangeFlag::FEATURE)
            && norm_cand
                .iter()
                .any(|e| e.attribute_equality(Attribute::Class, &EntryClass::Feature.into()))
        {
            self.changed_flags.insert(ChangeFlag::FEATURE)
        }

        if !self.changed_flags.contains(ChangeFlag::DOMAIN)
            && norm_cand
                .iter()
                .any(|e| e.attribute_equality(Attribute::Uuid, &PVUUID_DOMAIN_INFO))
        {
            self.changed_flags.insert(ChangeFlag::DOMAIN)
        }
        if !self.changed_flags.contains(ChangeFlag::SYSTEM_CONFIG)
            && norm_cand
                .iter()
                .any(|e| e.attribute_equality(Attribute::Uuid, &PVUUID_SYSTEM_CONFIG))
        {
            self.changed_flags.insert(ChangeFlag::DOMAIN)
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

        trace!("Modify operation success");
        Ok(())
    }

    #[instrument(level = "debug", skip_all)]
    pub fn internal_modify(
        &mut self,
        filter: &Filter<FilterInvalid>,
        modlist: &ModifyList<ModifyInvalid>,
    ) -> Result<(), OperationError> {
        let f_valid = filter
            .validate(self.get_schema())
            .map_err(OperationError::SchemaViolation)?;
        let m_valid = modlist
            .validate(self.get_schema())
            .map_err(OperationError::SchemaViolation)?;
        let me = ModifyEvent::new_internal(f_valid, m_valid);
        self.modify(&me)
    }

    pub fn internal_modify_uuid(
        &mut self,
        target_uuid: Uuid,
        modlist: &ModifyList<ModifyInvalid>,
    ) -> Result<(), OperationError> {
        let filter = filter!(f_eq(Attribute::Uuid, PartialValue::Uuid(target_uuid)));
        let f_valid = filter
            .validate(self.get_schema())
            .map_err(OperationError::SchemaViolation)?;
        let m_valid = modlist
            .validate(self.get_schema())
            .map_err(OperationError::SchemaViolation)?;
        let me = ModifyEvent::new_internal(f_valid, m_valid);
        self.modify(&me)
    }

    pub fn impersonate_modify_valid(
        &mut self,
        f_valid: Filter<FilterValid>,
        f_intent_valid: Filter<FilterValid>,
        m_valid: ModifyList<ModifyValid>,
        event: &Identity,
    ) -> Result<(), OperationError> {
        let me = ModifyEvent::new_impersonate(event, f_valid, f_intent_valid, m_valid);
        self.modify(&me)
    }

    pub fn impersonate_modify(
        &mut self,
        filter: &Filter<FilterInvalid>,
        filter_intent: &Filter<FilterInvalid>,
        modlist: &ModifyList<ModifyInvalid>,
        event: &Identity,
    ) -> Result<(), OperationError> {
        let f_valid = filter.validate(self.get_schema()).map_err(|e| {
            admin_error!("filter Schema Invalid {:?}", e);
            OperationError::SchemaViolation(e)
        })?;
        let f_intent_valid = filter_intent.validate(self.get_schema()).map_err(|e| {
            admin_error!("f_intent Schema Invalid {:?}", e);
            OperationError::SchemaViolation(e)
        })?;
        let m_valid = modlist.validate(self.get_schema()).map_err(|e| {
            admin_error!("modlist Schema Invalid {:?}", e);
            OperationError::SchemaViolation(e)
        })?;
        self.impersonate_modify_valid(f_valid, f_intent_valid, m_valid, event)
    }

    pub fn impersonate_modify_gen_event(
        &mut self,
        filter: &Filter<FilterInvalid>,
        filter_intent: &Filter<FilterInvalid>,
        modlist: &ModifyList<ModifyInvalid>,
        event: &Identity,
    ) -> Result<ModifyEvent, OperationError> {
        let f_valid = filter.validate(self.get_schema()).map_err(|e| {
            admin_error!("filter Schema Invalid {:?}", e);
            OperationError::SchemaViolation(e)
        })?;
        let f_intent_valid = filter_intent.validate(self.get_schema()).map_err(|e| {
            admin_error!("f_intent Schema Invalid {:?}", e);
            OperationError::SchemaViolation(e)
        })?;
        let m_valid = modlist.validate(self.get_schema()).map_err(|e| {
            admin_error!("modlist Schema Invalid {:?}", e);
            OperationError::SchemaViolation(e)
        })?;
        Ok(ModifyEvent::new_impersonate(
            event,
            f_valid,
            f_intent_valid,
            m_valid,
        ))
    }
}

#[cfg(test)]
mod tests {
    use crate::credential::Credential;
    use crate::prelude::*;
    use kanidm_lib_crypto::CryptoPolicy;
    use time::OffsetDateTime;

    #[qs_test]
    async fn test_modify(server: &QueryServer) {
        // Create an object
        let mut server_txn = server.write(duration_from_epoch_now()).await.unwrap();

        let e1 = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Account.to_value()),
            (Attribute::Class, EntryClass::Person.to_value()),
            (Attribute::Name, Value::new_iname("testperson1")),
            (
                Attribute::Uuid,
                Value::Uuid(uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"))
            ),
            (Attribute::Description, Value::new_utf8s("testperson1")),
            (Attribute::DisplayName, Value::new_utf8s("testperson1"))
        );

        let e2 = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Account.to_value()),
            (Attribute::Class, EntryClass::Person.to_value()),
            (Attribute::Name, Value::new_iname("testperson2")),
            (
                Attribute::Uuid,
                Value::Uuid(uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63932"))
            ),
            (Attribute::Description, Value::new_utf8s("testperson2")),
            (Attribute::DisplayName, Value::new_utf8s("testperson2"))
        );

        let ce = CreateEvent::new_internal(vec![e1, e2]);

        let cr = server_txn.create(&ce);
        assert!(cr.is_ok());

        // Empty Modlist (filter is valid)
        let me_emp = ModifyEvent::new_internal_invalid(
            filter!(f_pres(Attribute::Class)),
            ModifyList::new_list(vec![]),
        );
        assert_eq!(
            server_txn.modify(&me_emp),
            Err(OperationError::EmptyRequest)
        );

        let idm_admin = server_txn.internal_search_uuid(UUID_IDM_ADMIN).unwrap();

        // Mod changes no objects
        let me_nochg = ModifyEvent::new_impersonate_entry(
            idm_admin,
            filter!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("flarbalgarble")
            )),
            ModifyList::new_list(vec![Modify::Present(
                Attribute::Description,
                Value::from("anusaosu"),
            )]),
        );
        assert_eq!(
            server_txn.modify(&me_nochg),
            Err(OperationError::NoMatchingEntries)
        );

        // TODO: can we can this, since the filter's defined as an enum now
        // Filter is invalid to schema - to check this due to changes in the way events are
        // handled, we put this via the internal modify function to get the modlist
        // checked for us. Normal server operation doesn't allow weird bypasses like
        // this.
        // let r_inv_1 = server_txn.internal_modify(
        //     &filter!(f_eq(
        //         Attribute::TestAttr,
        //         PartialValue::new_iname("Flarbalgarble")
        //     )),
        //     &ModifyList::new_list(vec![Modify::Present(
        //         Attribute::Description.into(),
        //         Value::from("anusaosu"),
        //     )]),
        // );
        // assert!(
        //     r_inv_1
        //         == Err(OperationError::SchemaViolation(
        //             SchemaError::InvalidAttribute("tnanuanou".to_string())
        //         ))
        // );

        // Mod is invalid to schema
        let me_inv_m = ModifyEvent::new_internal_invalid(
            filter!(f_pres(Attribute::Class)),
            ModifyList::new_list(vec![Modify::Present(
                Attribute::NonExist,
                Value::from("anusaosu"),
            )]),
        );
        assert!(
            server_txn.modify(&me_inv_m)
                == Err(OperationError::SchemaViolation(
                    SchemaError::InvalidAttribute(Attribute::NonExist.to_string())
                ))
        );

        // Mod single object
        let me_sin = ModifyEvent::new_internal_invalid(
            filter!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson2")
            )),
            ModifyList::new_list(vec![
                Modify::Purged(Attribute::Description),
                Modify::Present(Attribute::Description, Value::from("anusaosu")),
            ]),
        );
        assert!(server_txn.modify(&me_sin).is_ok());

        // Mod multiple object
        let me_mult = ModifyEvent::new_internal_invalid(
            filter!(f_or!([
                f_eq(Attribute::Name, PartialValue::new_iname("testperson1")),
                f_eq(Attribute::Name, PartialValue::new_iname("testperson2")),
            ])),
            ModifyList::new_list(vec![
                Modify::Purged(Attribute::Description),
                Modify::Present(Attribute::Description, Value::from("anusaosu")),
            ]),
        );
        assert!(server_txn.modify(&me_mult).is_ok());

        assert!(server_txn.commit().is_ok());
    }

    #[qs_test]
    async fn test_modify_assert(server: &QueryServer) {
        let mut server_txn = server.write(duration_from_epoch_now()).await.unwrap();

        let t_uuid = Uuid::new_v4();
        let r_uuid = Uuid::new_v4();

        assert!(server_txn
            .internal_create(vec![entry_init!(
                (Attribute::Class, EntryClass::Object.to_value()),
                (Attribute::Uuid, Value::Uuid(t_uuid))
            ),])
            .is_ok());

        // This assertion will FAIL
        assert!(matches!(
            server_txn.internal_modify_uuid(
                t_uuid,
                &ModifyList::new_list(vec![
                    m_assert(Attribute::Uuid, &PartialValue::Uuid(r_uuid)),
                    m_pres(Attribute::Description, &Value::Utf8("test".into()))
                ])
            ),
            Err(OperationError::ModifyAssertionFailed)
        ));

        // This assertion will PASS
        assert!(server_txn
            .internal_modify_uuid(
                t_uuid,
                &ModifyList::new_list(vec![
                    m_assert(Attribute::Uuid, &PartialValue::Uuid(t_uuid)),
                    m_pres(Attribute::Description, &Value::Utf8("test".into()))
                ])
            )
            .is_ok());
    }

    #[qs_test]
    async fn test_modify_invalid_class(server: &QueryServer) {
        // Test modifying an entry and adding an extra class, that would cause the entry
        // to no longer conform to schema.
        let mut server_txn = server.write(duration_from_epoch_now()).await.unwrap();

        let e1 = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Account.to_value()),
            (Attribute::Class, EntryClass::Person.to_value()),
            (Attribute::Name, Value::new_iname("testperson1")),
            (
                Attribute::Uuid,
                Value::Uuid(uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"))
            ),
            (Attribute::Description, Value::new_utf8s("testperson1")),
            (Attribute::DisplayName, Value::new_utf8s("testperson1"))
        );

        let ce = CreateEvent::new_internal(vec![e1]);

        let cr = server_txn.create(&ce);
        assert!(cr.is_ok());

        // Add class but no values
        let me_sin = ModifyEvent::new_internal_invalid(
            filter!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson1")
            )),
            ModifyList::new_list(vec![Modify::Present(
                Attribute::Class,
                EntryClass::SystemInfo.to_value(),
            )]),
        );
        assert!(server_txn.modify(&me_sin).is_err());

        // Add multivalue where not valid
        let me_sin = ModifyEvent::new_internal_invalid(
            filter!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson1")
            )),
            ModifyList::new_list(vec![Modify::Present(
                Attribute::Name,
                Value::new_iname("testpersonx"),
            )]),
        );
        assert!(server_txn.modify(&me_sin).is_err());

        // add class and valid values?
        let me_sin = ModifyEvent::new_internal_invalid(
            filter!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson1")
            )),
            ModifyList::new_list(vec![
                Modify::Present(Attribute::Class, EntryClass::SystemInfo.to_value()),
                // Modify::Present(Attribute::Domain.into(), Value::new_iutf8("domain.name")),
                Modify::Present(Attribute::Version, Value::new_uint32(1)),
            ]),
        );
        assert!(server_txn.modify(&me_sin).is_ok());

        // Replace a value
        let me_sin = ModifyEvent::new_internal_invalid(
            filter!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson1")
            )),
            ModifyList::new_list(vec![
                Modify::Purged(Attribute::Name),
                Modify::Present(Attribute::Name, Value::new_iname("testpersonx")),
            ]),
        );
        assert!(server_txn.modify(&me_sin).is_ok());
    }

    #[qs_test]
    async fn test_modify_password_only(server: &QueryServer) {
        let e1 = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Person.to_value()),
            (Attribute::Class, EntryClass::Account.to_value()),
            (Attribute::Name, Value::new_iname("testperson1")),
            (
                Attribute::Uuid,
                Value::Uuid(uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"))
            ),
            (Attribute::Description, Value::new_utf8s("testperson1")),
            (Attribute::DisplayName, Value::new_utf8s("testperson1"))
        );
        let mut server_txn = server.write(duration_from_epoch_now()).await.unwrap();
        // Add the entry. Today we have no syntax to take simple str to a credential
        // but honestly, that's probably okay :)
        let ce = CreateEvent::new_internal(vec![e1]);
        let cr = server_txn.create(&ce);
        assert!(cr.is_ok());

        // Build the credential.
        let p = CryptoPolicy::minimum();
        let cred =
            Credential::new_password_only(&p, "test_password", OffsetDateTime::UNIX_EPOCH).unwrap();
        let v_cred = Value::new_credential("primary", cred);
        assert!(v_cred.validate());

        // now modify and provide a primary credential.
        let me_inv_m = ModifyEvent::new_internal_invalid(
            filter!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson1")
            )),
            ModifyList::new_list(vec![Modify::Present(Attribute::PrimaryCredential, v_cred)]),
        );
        // go!
        assert!(server_txn.modify(&me_inv_m).is_ok());

        // assert it exists and the password checks out
        let test_ent = server_txn
            .internal_search_uuid(uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"))
            .expect("failed");
        // get the primary ava
        let cred_ref = test_ent
            .get_ava_single_credential(Attribute::PrimaryCredential)
            .expect("Failed");
        // do a pw check.
        assert!(cred_ref.verify_password("test_password").unwrap());
    }

    #[qs_test]
    async fn test_modify_name_self_write(server: &QueryServer) {
        let user_uuid = uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930");
        let e1 = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Person.to_value()),
            (Attribute::Class, EntryClass::Account.to_value()),
            (Attribute::Name, Value::new_iname("testperson1")),
            (Attribute::Uuid, Value::Uuid(user_uuid)),
            (Attribute::Description, Value::new_utf8s("testperson1")),
            (Attribute::DisplayName, Value::new_utf8s("testperson1"))
        );
        let mut server_txn = server.write(duration_from_epoch_now()).await.unwrap();

        assert!(server_txn.internal_create(vec![e1]).is_ok());

        // Impersonate the user.

        let testperson_entry = server_txn.internal_search_uuid(user_uuid).unwrap();

        let user_ident = Identity::from_impersonate_entry_readwrite(testperson_entry);

        // Can we change ourself?
        let me_inv_m = ModifyEvent::new_impersonate_identity(
            user_ident,
            filter!(f_eq(Attribute::Uuid, PartialValue::Uuid(user_uuid),)),
            ModifyList::new_list(vec![
                Modify::Purged(Attribute::Name),
                Modify::Present(Attribute::Name, Value::new_iname("test_person_renamed")),
                Modify::Purged(Attribute::DisplayName),
                Modify::Present(
                    Attribute::DisplayName,
                    Value::Utf8("test_person_renamed".into()),
                ),
                Modify::Purged(Attribute::LegalName),
                Modify::Present(
                    Attribute::LegalName,
                    Value::Utf8("test_person_renamed".into()),
                ),
            ]),
        );

        // Modify success.
        assert!(server_txn.modify(&me_inv_m).is_ok());

        // Alter the deal.
        let modify_remove_person = ModifyEvent::new_internal_invalid(
            filter!(f_eq(
                Attribute::Uuid,
                PartialValue::Uuid(UUID_IDM_PEOPLE_SELF_NAME_WRITE),
            )),
            ModifyList::new_list(vec![Modify::Purged(Attribute::Member)]),
        );

        assert!(server_txn.modify(&modify_remove_person).is_ok());

        // Reload the users identity which will cause the memberships to be reflected now.
        let testperson_entry = server_txn.internal_search_uuid(user_uuid).unwrap();

        let user_ident = Identity::from_impersonate_entry_readwrite(testperson_entry);

        let me_inv_m = ModifyEvent::new_impersonate_identity(
            user_ident,
            filter!(f_eq(Attribute::Uuid, PartialValue::Uuid(user_uuid),)),
            ModifyList::new_list(vec![
                Modify::Purged(Attribute::Name),
                Modify::Present(Attribute::Name, Value::new_iname("test_person_renamed")),
                Modify::Purged(Attribute::DisplayName),
                Modify::Present(
                    Attribute::DisplayName,
                    Value::Utf8("test_person_renamed".into()),
                ),
                Modify::Purged(Attribute::LegalName),
                Modify::Present(
                    Attribute::LegalName,
                    Value::Utf8("test_person_renamed".into()),
                ),
            ]),
        );

        // The modification must now fail.
        assert_eq!(
            server_txn.modify(&me_inv_m),
            Err(OperationError::AccessDenied)
        );
    }
}
