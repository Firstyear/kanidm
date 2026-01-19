// Referential Integrity
//
// Given an entry, modification or change, ensure that all referential links
// in the database are maintained. IE there are no dangling references that
// are unable to be resolved, as this may cause errors in Item -> ProtoItem
// translation.
//
// It will be important to understand the interaction of this plugin with memberof
// when that is written, as they *both* manipulate and alter entry reference
// data, so we should be careful not to step on each other.

use crate::event::{CreateEvent, DeleteEvent, ModifyEvent};
use crate::plugins::Plugin;
use crate::prelude::*;
use crate::schema::{SchemaAttribute, SchemaTransaction};
use hashbrown::{HashMap, HashSet};
use std::collections::BTreeSet;
use std::sync::Arc;

pub struct ReferentialIntegrity;

impl ReferentialIntegrity {
    #[instrument(level = "debug", name = "check_uuids_exist_fast", skip_all)]
    fn check_uuids_exist_fast(
        qs: &mut QueryServerWriteTransaction,
        inner: &[Uuid],
    ) -> Result<bool, OperationError> {
        if inner.is_empty() {
            // There is nothing to check! Move on.
            trace!("no reference types modified, skipping check");
            return Ok(true);
        }

        let inner: Vec<_> = inner
            .iter()
            .map(|u| f_eq(Attribute::Uuid, PartialValue::Uuid(*u)))
            .collect();

        // F_inc(lusion). All items of inner must be 1 or more, or the filter
        // will fail. This will return the union of the inclusion after the
        // operation.
        let filt_in = filter!(f_inc(inner));
        let b = qs.internal_exists(&filt_in).inspect_err(|err| {
            error!(?err, filter = ?filt_in, "internal exists failure");
        })?;

        // Is the existence of all id's confirmed?
        if b {
            Ok(true)
        } else {
            Ok(false)
        }
    }

    #[instrument(level = "debug", name = "check_uuids_exist_slow", skip_all)]
    fn check_uuids_exist_slow(
        qs: &mut QueryServerWriteTransaction,
        inner: &[Uuid],
    ) -> Result<Vec<Uuid>, OperationError> {
        if inner.is_empty() {
            // There is nothing to check! Move on.
            // Should be unreachable.
            trace!("no reference types modified, skipping check");
            return Ok(Vec::with_capacity(0));
        }

        let mut missing = Vec::with_capacity(inner.len());
        for u in inner {
            let filt_in = filter!(f_eq(Attribute::Uuid, PartialValue::Uuid(*u)));
            let b = qs.internal_exists(&filt_in).inspect_err(|err| {
                error!(?err, filter = ?filt_in, "internal exists failure");
            })?;

            // If it's missing, we push it to the missing set.
            if !b {
                missing.push(*u)
            }
        }

        Ok(missing)
    }

    /// This function performs two actions. It needs to cleanup any reference entries that should
    /// be removed (aka delete cascade) as a related entry has been removed. Second, it needs to
    /// remove dangling references from entries that are still alive. Importantly, we need to perform
    /// these actions in *order* so that reference entries that relate to something retain their
    /// references to their related entry, so that revival of those entries works as we expect.
    fn remove_references(
        qs: &mut QueryServerWriteTransaction,
        uuids: Vec<Uuid>,
    ) -> Result<(), OperationError> {
        trace!(?uuids);

        // Find all reference types in the schema
        let schema = qs.get_schema();
        let ref_types = schema.get_reference_types();

        let removed_ids: BTreeSet<_> = uuids.iter().map(|u| PartialValue::Refer(*u)).collect();

        // Generate a filter which is the set of all schema reference types
        // as EQ to all uuid of all entries in delete. - this INCLUDES recycled
        // types too!
        let filt = filter_all!(f_or(
            uuids
                .into_iter()
                .flat_map(|u| ref_types
                    .values()
                    .map(move |r_type| { f_eq(r_type.name.clone(), PartialValue::Refer(u)) }))
                .collect(),
        ));

        trace!("refint post_delete filter {:?}", filt);

        let mut work_set = qs.internal_search_writeable(&filt)?;

        for (_, post) in work_set.iter_mut() {
            for schema_attribute in ref_types.values() {
                post.remove_avas(&schema_attribute.name, &removed_ids);
            }
        }

        qs.internal_apply_writable(work_set)
    }

    #[instrument(level = "debug", skip_all)]
    fn check_refers_to_target_loop_fast(
        qs: &mut QueryServerWriteTransaction,
        inner: &[Uuid],
    ) -> Result<bool, OperationError> {
        if inner.is_empty() {
            // There is nothing to check! Move on.
            trace!("no refers types modified, skipping check");
            return Ok(false);
        }

        let inner: Vec<_> = inner
            .iter()
            .map(|u| {
                f_and(vec![
                    f_eq(Attribute::Uuid, PartialValue::Uuid(*u)),
                    f_andnot(f_pres(Attribute::Refers)),
                ])
            })
            .collect();

        // F_inc(lusion). All items of inner must be 1 or more, or the filter
        // will fail. This will return the union of the inclusion after the
        // operation.
        let filt_in = filter!(f_inc(inner));

        let b = qs.internal_exists(&filt_in).inspect_err(|err| {
            error!(?err, filter = ?filt_in, "internal exists failure");
        })?;

        // If this is true, it means all uuids do NOT have the attribute refers
        // present. So we have to invert this boolean here as we do not have a loop.
        if b {
            Ok(false)
        } else {
            // A loop exists
            Ok(true)
        }
    }

    #[instrument(level = "debug", skip_all)]
    fn check_refers_to_target_loop_slow(
        qs: &mut QueryServerWriteTransaction,
        inner: &[Uuid],
    ) -> Result<Vec<Uuid>, OperationError> {
        if inner.is_empty() {
            // There is nothing to check! Move on.
            // Should be unreachable.
            trace!("no refers types modified, skipping check");
            return Ok(Vec::with_capacity(0));
        }

        let mut looping = Vec::with_capacity(inner.len());
        for u in inner {
            let filt_in = filter!(f_and(vec![
                f_eq(Attribute::Uuid, PartialValue::Uuid(*u)),
                f_pres(Attribute::Refers)
            ]));
            let b = qs.internal_exists(&filt_in).inspect_err(|err| {
                error!(?err, filter = ?filt_in, "internal exists failure");
            })?;

            // If it's missing, we push it to the missing set.
            if !b {
                looping.push(*u)
            }
        }

        Ok(looping)
    }
}

impl Plugin for ReferentialIntegrity {
    fn id() -> &'static str {
        "referential_integrity"
    }

    // Why are these checks all in post?
    //
    // There is a situation to account for which is that a create or mod
    // may introduce the entry which is also to be referenced in the same
    // transaction. Rather than have separate verification paths - one to
    // check the UUID is in the cand set, and one to check the UUID exists
    // in the DB, we do the "correct" thing, write to the DB, and then assert
    // that the DB content is complete and valid instead.
    //
    // Yes, this does mean we do more work to add/index/rollback in an error
    // condition, *but* it means we only have developed a single verification
    // so we can assert stronger trust in it's correct operation and interaction
    // in complex scenarios - It actually simplifies the check from "could
    // be in cand AND db" to simply "is it in the DB?".
    #[instrument(level = "debug", name = "refint_post_create", skip(qs, cand, _ce))]
    fn post_create(
        qs: &mut QueryServerWriteTransaction,
        cand: &[Entry<EntrySealed, EntryCommitted>],
        _ce: &CreateEvent,
    ) -> Result<(), OperationError> {
        Self::post_modify_inner(qs, None, cand)
    }

    #[instrument(level = "debug", name = "refint_post_modify", skip_all)]
    fn post_modify(
        qs: &mut QueryServerWriteTransaction,
        pre_cand: &[Arc<EntrySealedCommitted>],
        cand: &[Entry<EntrySealed, EntryCommitted>],
        _me: &ModifyEvent,
    ) -> Result<(), OperationError> {
        Self::post_modify_inner(qs, Some(pre_cand), cand)
    }

    #[instrument(level = "debug", name = "refint_post_batch_modify", skip_all)]
    fn post_batch_modify(
        qs: &mut QueryServerWriteTransaction,
        pre_cand: &[Arc<EntrySealedCommitted>],
        cand: &[Entry<EntrySealed, EntryCommitted>],
        _me: &BatchModifyEvent,
    ) -> Result<(), OperationError> {
        Self::post_modify_inner(qs, Some(pre_cand), cand)
    }

    #[instrument(level = "debug", name = "refint_post_repl_refresh", skip_all)]
    fn post_repl_refresh(
        qs: &mut QueryServerWriteTransaction,
        cand: &[EntrySealedCommitted],
    ) -> Result<(), OperationError> {
        Self::post_modify_inner(qs, None, cand)
    }

    #[instrument(level = "debug", name = "attrunique_post_repl_incremental", skip_all)]
    fn post_repl_incremental_conflict(
        qs: &mut QueryServerWriteTransaction,
        _cand: &[(EntrySealedCommitted, Arc<EntrySealedCommitted>)],
        conflict_uuids: &mut BTreeSet<Uuid>,
    ) -> Result<(), OperationError> {
        // Any item that is now a conflict, must have all refers that point to it removed.
        // This is because we can't tell the intent of the refers any more, and so we don't
        // want a refers to linger pointing to an entry that it should not.
        if conflict_uuids.is_empty() {
            return Ok(());
        }

        // Find anything that is a refers to the conflicted uuids.
        let filt_inner = conflict_uuids
            .iter()
            .copied()
            .map(|conflict_uuid| f_eq(Attribute::Refers, PartialValue::Refer(conflict_uuid)))
            .collect::<Vec<_>>();

        let filt = filter!(f_or(filt_inner));

        // Does anything match?
        let conflict_cand = qs.internal_exists(&filt).inspect_err(|err| {
            error!(?err, "internal exists error");
        })?;

        // If so, time to run the filter again on the slow path and actually conflict them.
        if conflict_cand {
            let mut work_set = qs.internal_search_writeable(&filt)?;

            for (_, entry) in work_set.iter_mut() {
                let Some(uuid) = entry.get_uuid() else {
                    error!("Impossible state. Entry that was declared in conflict map does not have a uuid.");
                    return Err(OperationError::InvalidState);
                };

                // Add the uuid to the conflict uuids now.
                conflict_uuids.insert(uuid);

                // Mark that we conflicted against ourself.
                entry.to_conflict([uuid]);
            }

            qs.internal_apply_writable(work_set).map_err(|e| {
                admin_error!("Failed to commit memberof group set {:?}", e);
                e
            })?;
        }

        // Okay we *finally got here. We are done!
        Ok(())
    }

    #[instrument(level = "debug", name = "refint_post_repl_incremental", skip_all)]
    fn post_repl_incremental(
        qs: &mut QueryServerWriteTransaction,
        pre_cand: &[Arc<EntrySealedCommitted>],
        cand: &[EntrySealedCommitted],
        conflict_uuids: &BTreeSet<Uuid>,
    ) -> Result<(), OperationError> {
        // I think we need to check that all values in the ref type values here
        // exist, and if not, we *need to remove them*. We should probably rewrite
        // how we do modify/create inner to actually return missing uuids, so that
        // this fn can delete, and the other parts can report what's missing.
        //
        // This also becomes a path to a "ref int fixup" too?

        let uuids = Self::cand_references_to_uuid_filter(qs, Some(pre_cand), cand)?;

        let all_exist_fast = Self::check_uuids_exist_fast(qs, uuids.as_slice())?;

        let mut missing_uuids = if !all_exist_fast {
            debug!("Not all uuids referenced by these candidates exist. Slow path to remove them.");
            Self::check_uuids_exist_slow(qs, uuids.as_slice())?
        } else {
            debug!("All references are valid!");
            Vec::with_capacity(0)
        };

        // If the entry has moved from a live to a deleted state we need to clean it's reference's
        // that *may* have been added on this server - the same that other references would be
        // deleted.
        let inactive_entries: Vec<_> = std::iter::zip(pre_cand, cand)
            .filter_map(|(pre, post)| {
                let pre_live = pre.mask_recycled_ts().is_some();
                let post_live = post.mask_recycled_ts().is_some();

                if !post_live && (pre_live != post_live) {
                    // We have moved from live to recycled/tombstoned. We need to
                    // ensure that these references are masked.
                    Some(post.get_uuid())
                } else {
                    None
                }
            })
            .collect();

        if event_enabled!(tracing::Level::DEBUG) {
            debug!("Removing the following reference uuids for entries that have become recycled or tombstoned");
            for missing in &inactive_entries {
                debug!(?missing);
            }
        }

        // We can now combine this with the conflict uuids from the incoming set.

        // In a conflict case, we need to also add these uuids to the delete logic
        // since on the originator node the original uuid will still persist
        // meaning the member won't be removed.
        // However, on a non-primary conflict handler it will remove the member
        // as well. This is annoyingly a worst case, since then *every* node will
        // attempt to update the cid of this group. But I think the potential cost
        // in the short term will be worth consistent references.

        if !conflict_uuids.is_empty() {
            warn!("conflict uuids have been found, and must be cleaned from existing references. This is to prevent group memberships leaking to un-intended recipients.");
        }

        // Now, we need to find for each of the missing uuids, which values had them.
        // We could use a clever query to internal_search_writeable?
        missing_uuids.extend(conflict_uuids.iter().copied());
        missing_uuids.extend_from_slice(&inactive_entries);

        if missing_uuids.is_empty() {
            trace!("Nothing to do, shortcut");
            return Ok(());
        }

        if event_enabled!(tracing::Level::DEBUG) {
            debug!("Removing the following missing reference uuids");
            for missing in &missing_uuids {
                debug!(?missing);
            }
        }

        // Now we have to look them up and clean it up. Turns out this is the
        // same code path as "post delete" so we can share that!
        Self::remove_references(qs, missing_uuids)

        // Complete!
    }

    #[instrument(level = "debug", name = "refint_post_delete", skip_all)]
    fn post_delete(
        qs: &mut QueryServerWriteTransaction,
        cand: &[Entry<EntrySealed, EntryCommitted>],
        _ce: &DeleteEvent,
    ) -> Result<(), OperationError> {
        // Delete is pretty different to the other pre checks. This is
        // actually the bulk of the work we'll do to clean up references
        // when they are deleted.

        // Get the UUID of all entries we are deleting
        let uuids: Vec<Uuid> = cand.iter().map(|e| e.get_uuid()).collect();

        Self::remove_references(qs, uuids)
    }

    #[instrument(level = "debug", name = "refint::verify", skip_all)]
    fn verify(qs: &mut QueryServerReadTransaction) -> Vec<Result<(), ConsistencyError>> {
        // Get all entries as cand
        //      build a cand-uuid set
        let filt_in = filter_all!(f_pres(Attribute::Class));

        let all_cand = match qs
            .internal_search(filt_in)
            .map_err(|_| Err(ConsistencyError::QueryServerSearchFailure))
        {
            Ok(all_cand) => all_cand,
            Err(e) => return vec![e],
        };

        let acu_map: HashSet<Uuid> = all_cand.iter().map(|e| e.get_uuid()).collect();

        let schema = qs.get_schema();
        let ref_types = schema.get_reference_types();

        let mut res = Vec::with_capacity(0);
        // For all cands
        for c in &all_cand {
            // For all reference in each cand.
            for rtype in ref_types.values() {
                // If the attribute is present
                if let Some(vs) = c.get_ava_set(&rtype.name) {
                    // For each value in the set.
                    match vs.as_ref_uuid_iter() {
                        Some(uuid_iter) => {
                            for vu in uuid_iter {
                                if acu_map.get(&vu).is_none() {
                                    res.push(Err(ConsistencyError::RefintNotUpheld(c.get_id())))
                                }
                            }
                        }
                        None => res.push(Err(ConsistencyError::InvalidAttributeType(
                            "A non-value-ref type was found.".to_string(),
                        ))),
                    }
                }
            }
        }

        res
    }
}

fn update_reference_set<'a, I>(
    ref_types: &HashMap<Attribute, SchemaAttribute>,
    entry_iter: I,
    reference_set: &mut BTreeSet<Uuid>,
) -> Result<(), OperationError>
where
    I: Iterator<Item = &'a EntrySealedCommitted>,
{
    for cand in entry_iter {
        trace!(cand_id = %cand.get_display_id());
        // If it's dyngroup, skip member since this will be reset in the next step.
        let dyn_group = cand.attribute_equality(Attribute::Class, &EntryClass::DynGroup.into());

        // For all reference types that exist in the schema.
        let cand_ref_valuesets = ref_types.values().filter_map(|rtype| {
            // If the entry is a dyn-group, skip dyn member.
            let skip_mb = dyn_group && rtype.name == Attribute::DynMember;
            // MemberOf is always recalculated, so it can be skipped
            let skip_mo = rtype.name == Attribute::MemberOf;

            if skip_mb || skip_mo {
                None
            } else {
                cand.get_ava_set(&rtype.name)
            }
        });

        for vs in cand_ref_valuesets {
            if let Some(uuid_iter) = vs.as_ref_uuid_iter() {
                reference_set.extend(uuid_iter);
                Ok(())
            } else {
                error!(?vs, "reference value could not convert to reference uuid.");
                error!("If you are sure the name/uuid/spn exist, and that this is in error, you should run a verify task.");
                Err(OperationError::InvalidAttribute(
                    "uuid could not become reference value".to_string(),
                ))
            }?;
        }
    }
    Ok(())
}

impl ReferentialIntegrity {
    fn cand_references_to_uuid_filter(
        qs: &mut QueryServerWriteTransaction,
        pre_cand: Option<&[Arc<EntrySealedCommitted>]>,
        post_cand: &[EntrySealedCommitted],
    ) -> Result<Vec<Uuid>, OperationError> {
        let schema = qs.get_schema();
        let ref_types = schema.get_reference_types();

        let mut previous_reference_set = BTreeSet::new();
        let mut reference_set = BTreeSet::new();

        if let Some(pre_cand) = pre_cand {
            update_reference_set(
                ref_types,
                pre_cand.iter().map(|e| e.as_ref()),
                &mut previous_reference_set,
            )?;
        }

        update_reference_set(ref_types, post_cand.iter(), &mut reference_set)?;

        // Now build the reference set from the current candidates.

        // Return only the values that are present in the new reference set. These are the values
        // we actually need to check the integrity of.
        Ok(reference_set
            .difference(&previous_reference_set)
            .copied()
            .collect())
    }

    fn cand_refers_to_target_uuid(post_cand: &[EntrySealedCommitted]) -> Vec<Uuid> {
        post_cand
            .iter()
            .filter_map(|entry| entry.get_ava_single_refer(Attribute::Refers))
            .collect()
    }

    fn post_modify_inner(
        qs: &mut QueryServerWriteTransaction,
        pre_cand: Option<&[Arc<EntrySealedCommitted>]>,
        post_cand: &[EntrySealedCommitted],
    ) -> Result<(), OperationError> {
        let uuids = Self::cand_references_to_uuid_filter(qs, pre_cand, post_cand)?;

        let all_exist_fast = Self::check_uuids_exist_fast(qs, uuids.as_slice())?;

        if !all_exist_fast {
            // Okay taking the slow path now ...
            let missing_uuids = Self::check_uuids_exist_slow(qs, uuids.as_slice())?;

            error!("some uuids that were referenced in this operation do not exist.");
            for missing in missing_uuids {
                error!(?missing);
            }

            return Err(OperationError::Plugin(PluginError::ReferentialIntegrity(
                "Uuid referenced not found in database".to_string(),
            )));
        }

        // Now we prevent refers from ouroborosing.

        // These are the targets that Refers point at.
        let refers_target_uuids = Self::cand_refers_to_target_uuid(post_cand);

        // Now search to ensure that these targets also do NOT have an Attribute::Refers
        // present. If they do, that means we have a Refers pointing to a Refers.
        let loops_present =
            Self::check_refers_to_target_loop_fast(qs, refers_target_uuids.as_slice())?;

        if loops_present {
            let looping_uuids =
                Self::check_refers_to_target_loop_slow(qs, refers_target_uuids.as_slice())?;

            error!("some entries introduce an invalid reference to another reference.");
            error!(?looping_uuids);

            return Err(OperationError::ReferenceLoop);
        }

        // All good!
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::credential::Credential;
    use crate::event::CreateEvent;
    use crate::prelude::*;
    use crate::value::{AuthType, Oauth2Session, OauthClaimMapJoin, Session, SessionState};
    use kanidm_lib_crypto::x509_cert::{der::DecodePem, Certificate};
    use kanidm_lib_crypto::CryptoPolicy;
    use kanidm_proto::internal::Filter as ProtoFilter;
    use time::OffsetDateTime;

    const TEST_TESTGROUP_A_UUID: &str = "d2b496bd-8493-47b7-8142-f568b5cf47ee";
    const TEST_TESTGROUP_B_UUID: &str = "8cef42bc-2cac-43e4-96b3-8f54561885ca";

    // The create references a uuid that doesn't exist - reject
    #[test]
    fn test_create_uuid_reference_not_exist() {
        let e = entry_init!(
            (Attribute::Class, EntryClass::Group.to_value()),
            (Attribute::Name, Value::new_iname("testgroup")),
            (Attribute::Description, Value::new_utf8s("testgroup")),
            (
                Attribute::Member,
                Value::Refer(Uuid::parse_str(TEST_TESTGROUP_B_UUID).unwrap())
            )
        );

        let create = vec![e];
        let preload = Vec::with_capacity(0);
        run_create_test!(
            Err(OperationError::Plugin(PluginError::ReferentialIntegrity(
                "Uuid referenced not found in database".to_string()
            ))),
            preload,
            create,
            None,
            |_| {}
        );
    }

    // The create references a uuid that does exist - validate
    #[test]
    fn test_create_uuid_reference_exist() {
        let ea = entry_init!(
            (Attribute::Class, EntryClass::Group.to_value()),
            (Attribute::Name, Value::new_iname("testgroup_a")),
            (Attribute::Description, Value::new_utf8s("testgroup")),
            (
                Attribute::Uuid,
                Value::Uuid(Uuid::parse_str(TEST_TESTGROUP_A_UUID).unwrap())
            )
        );
        let eb = entry_init!(
            (Attribute::Class, EntryClass::Group.to_value()),
            (Attribute::Name, Value::new_iname("testgroup_b")),
            (Attribute::Description, Value::new_utf8s("testgroup")),
            (
                Attribute::Member,
                Value::Refer(Uuid::parse_str(TEST_TESTGROUP_A_UUID).unwrap())
            )
        );

        let preload = vec![ea];
        let create = vec![eb];

        run_create_test!(
            Ok(None),
            preload,
            create,
            None,
            |qs: &mut QueryServerWriteTransaction| {
                let cands = qs
                    .internal_search(filter!(f_eq(
                        Attribute::Name,
                        PartialValue::new_iname("testgroup_b")
                    )))
                    .expect("Internal search failure");
                let _ue = cands.first().expect("No cand");
            }
        );
    }

    // The create references itself - allow
    #[test]
    fn test_create_uuid_reference_self() {
        let preload: Vec<Entry<EntryInit, EntryNew>> = Vec::with_capacity(0);

        let id = uuid::uuid!("8cef42bc-2cac-43e4-96b3-8f54561885ca");

        let e_group = entry_init!(
            (Attribute::Class, EntryClass::Group.to_value()),
            (Attribute::Name, Value::new_iname("testgroup")),
            (Attribute::Uuid, Value::Uuid(id)),
            (Attribute::Member, Value::Refer(id))
        );

        let create = vec![e_group];

        run_create_test!(
            Ok(None),
            preload,
            create,
            None,
            |qs: &mut QueryServerWriteTransaction| {
                let cands = qs
                    .internal_search(filter!(f_eq(
                        Attribute::Name,
                        PartialValue::new_iname("testgroup")
                    )))
                    .expect("Internal search failure");
                let _ue = cands.first().expect("No cand");
            }
        );
    }

    // Modify references a different object - allow
    #[test]
    fn test_modify_uuid_reference_exist() {
        let ea = entry_init!(
            (Attribute::Class, EntryClass::Group.to_value()),
            (Attribute::Name, Value::new_iname("testgroup_a")),
            (
                Attribute::Uuid,
                Value::Uuid(uuid::uuid!(TEST_TESTGROUP_A_UUID))
            )
        );

        let eb = entry_init!(
            (Attribute::Class, EntryClass::Group.to_value()),
            (Attribute::Name, Value::new_iname("testgroup_b"))
        );

        let preload = vec![ea, eb];

        run_modify_test!(
            Ok(()),
            preload,
            filter!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testgroup_b")
            )),
            ModifyList::new_list(vec![Modify::Present(
                Attribute::Member,
                Value::new_refer_s(TEST_TESTGROUP_A_UUID).unwrap()
            )]),
            None,
            |_| {},
            |_| {}
        );
    }

    // Modify reference something that doesn't exist - must be rejected
    #[test]
    fn test_modify_uuid_reference_not_exist() {
        let eb = entry_init!(
            (Attribute::Class, EntryClass::Group.to_value()),
            (Attribute::Name, Value::new_iname("testgroup_b"))
        );

        let preload = vec![eb];

        run_modify_test!(
            Err(OperationError::Plugin(PluginError::ReferentialIntegrity(
                "Uuid referenced not found in database".to_string()
            ))),
            preload,
            filter!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testgroup_b")
            )),
            ModifyList::new_list(vec![Modify::Present(
                Attribute::Member,
                Value::new_refer_s(TEST_TESTGROUP_A_UUID).unwrap()
            )]),
            None,
            |_| {},
            |_| {}
        );
    }

    // Check that even when SOME references exist, so long as one does not,
    // we fail.
    #[test]
    fn test_modify_uuid_reference_partial_not_exist() {
        let ea = entry_init!(
            (Attribute::Class, EntryClass::Group.to_value()),
            (Attribute::Name, Value::new_iname("testgroup_a")),
            (
                Attribute::Uuid,
                Value::Uuid(uuid::uuid!(TEST_TESTGROUP_A_UUID))
            )
        );

        let eb = entry_init!(
            (Attribute::Class, EntryClass::Group.to_value()),
            (Attribute::Name, Value::new_iname("testgroup_b"))
        );

        let preload = vec![ea, eb];

        run_modify_test!(
            Err(OperationError::Plugin(PluginError::ReferentialIntegrity(
                "Uuid referenced not found in database".to_string()
            ))),
            preload,
            filter!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testgroup_b")
            )),
            ModifyList::new_list(vec![
                Modify::Present(
                    Attribute::Member,
                    Value::Refer(Uuid::parse_str(TEST_TESTGROUP_A_UUID).unwrap())
                ),
                Modify::Present(Attribute::Member, Value::Refer(UUID_DOES_NOT_EXIST)),
            ]),
            None,
            |_| {},
            |_| {}
        );
    }

    // Modify removes the reference to an entry
    #[test]
    fn test_modify_remove_referee() {
        let ea = entry_init!(
            (Attribute::Class, EntryClass::Group.to_value()),
            (Attribute::Name, Value::new_iname("testgroup_a")),
            (
                Attribute::Uuid,
                Value::Uuid(uuid::uuid!(TEST_TESTGROUP_A_UUID))
            )
        );

        let eb = entry_init!(
            (Attribute::Class, EntryClass::Group.to_value()),
            (Attribute::Name, Value::new_iname("testgroup_b")),
            (
                Attribute::Member,
                Value::Refer(uuid::uuid!(TEST_TESTGROUP_A_UUID))
            )
        );

        let preload = vec![ea, eb];

        run_modify_test!(
            Ok(()),
            preload,
            filter!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testgroup_b")
            )),
            ModifyList::new_list(vec![Modify::Purged(Attribute::Member)]),
            None,
            |_| {},
            |_| {}
        );
    }

    // Modify adds reference to self - allow
    #[test]
    fn test_modify_uuid_reference_self() {
        let ea = entry_init!(
            (Attribute::Class, EntryClass::Group.to_value()),
            (Attribute::Name, Value::new_iname("testgroup_a")),
            (
                Attribute::Uuid,
                Value::Uuid(uuid::uuid!(TEST_TESTGROUP_A_UUID))
            )
        );

        let preload = vec![ea];

        run_modify_test!(
            Ok(()),
            preload,
            filter!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testgroup_a")
            )),
            ModifyList::new_list(vec![Modify::Present(
                Attribute::Member,
                Value::new_refer_s(TEST_TESTGROUP_A_UUID).unwrap()
            )]),
            None,
            |_| {},
            |_| {}
        );
    }

    // Test that deleted entries can not be referenced
    #[test]
    fn test_modify_reference_deleted() {
        let ea = entry_init!(
            (Attribute::Class, EntryClass::Group.to_value()),
            (Attribute::Name, Value::new_iname("testgroup_a")),
            (
                Attribute::Uuid,
                Value::Uuid(uuid::uuid!(TEST_TESTGROUP_A_UUID))
            )
        );

        let eb = entry_init!(
            (Attribute::Class, EntryClass::Group.to_value()),
            (Attribute::Name, Value::new_iname("testgroup_b"))
        );

        let preload = vec![ea, eb];

        run_modify_test!(
            Err(OperationError::Plugin(PluginError::ReferentialIntegrity(
                "Uuid referenced not found in database".to_string()
            ))),
            preload,
            filter!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testgroup_b")
            )),
            ModifyList::new_list(vec![Modify::Present(
                Attribute::Member,
                Value::new_refer_s(TEST_TESTGROUP_A_UUID).unwrap()
            )]),
            None,
            |qs: &mut QueryServerWriteTransaction| {
                // Any pre_hooks we need. In this case, we need to trigger the delete of testgroup_a
                let de_sin =
                    crate::event::DeleteEvent::new_internal_invalid(filter!(f_or!([f_eq(
                        Attribute::Name,
                        PartialValue::new_iname("testgroup_a")
                    )])));
                assert!(qs.delete(&de_sin).is_ok());
            },
            |_| {}
        );
    }

    // Delete of something that is referenced - must remove ref in other (unless would make inconsistent)
    //
    // This is the valid case, where the reference is MAY.
    #[test]
    fn test_delete_remove_referent_valid() {
        let ea: Entry<EntryInit, EntryNew> = entry_init!(
            (Attribute::Class, EntryClass::Group.to_value()),
            (Attribute::Name, Value::new_iname("testgroup_a")),
            (Attribute::Description, Value::new_utf8s("testgroup")),
            (
                Attribute::Uuid,
                Value::Uuid(Uuid::parse_str(TEST_TESTGROUP_A_UUID).unwrap())
            )
        );
        let eb: Entry<EntryInit, EntryNew> = entry_init!(
            (Attribute::Class, EntryClass::Group.to_value()),
            (Attribute::Name, Value::new_iname("testgroup_b")),
            (Attribute::Description, Value::new_utf8s("testgroup")),
            (
                Attribute::Member,
                Value::Refer(Uuid::parse_str(TEST_TESTGROUP_A_UUID).unwrap())
            )
        );

        let preload = vec![ea, eb];

        run_delete_test!(
            Ok(()),
            preload,
            filter!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testgroup_a")
            )),
            None,
            |_qs: &mut QueryServerWriteTransaction| {}
        );
    }

    // Delete of something that is referenced - must remove ref in other (unless would make inconsistent)
    //
    // this is the invalid case, where the reference is MUST.
    //
    // There are very few types in the server where this condition exists. The primary example
    // is access controls, where a target group is a must condition referencing the
    // group that the access control applies to.
    //
    // This means that the delete of the group will be blocked because it would make the access control
    // structurally invalid.
    #[test]
    fn test_delete_remove_referent_invalid() {
        let target_uuid = Uuid::new_v4();

        let e_group: Entry<EntryInit, EntryNew> = entry_init!(
            (Attribute::Class, EntryClass::Group.to_value()),
            (Attribute::Name, Value::new_iname("testgroup_a")),
            (Attribute::Description, Value::new_utf8s("testgroup")),
            (Attribute::Uuid, Value::Uuid(target_uuid))
        );

        let e_acp: Entry<EntryInit, EntryNew> = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (
                Attribute::Class,
                EntryClass::AccessControlProfile.to_value()
            ),
            (
                Attribute::Class,
                EntryClass::AccessControlReceiverGroup.to_value()
            ),
            (
                Attribute::Class,
                EntryClass::AccessControlTargetScope.to_value()
            ),
            (Attribute::Name, Value::new_iname("acp_referer")),
            (Attribute::AcpReceiverGroup, Value::Refer(target_uuid)),
            (
                Attribute::AcpTargetScope,
                Value::new_json_filter_s("{\"eq\":[\"name\",\"a\"]}").expect("filter")
            )
        );

        let preload = vec![e_group, e_acp];

        run_delete_test!(
            Err(OperationError::SchemaViolation(
                SchemaError::MissingMustAttribute(vec![Attribute::AcpReceiverGroup])
            )),
            preload,
            filter!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testgroup_a")
            )),
            None,
            |_qs: &mut QueryServerWriteTransaction| {}
        );
    }

    // Delete of something that holds references.
    #[test]
    fn test_delete_remove_referee() {
        let ea: Entry<EntryInit, EntryNew> = entry_init!(
            (Attribute::Class, EntryClass::Group.to_value()),
            (Attribute::Name, Value::new_iname("testgroup_a")),
            (Attribute::Description, Value::new_utf8s("testgroup")),
            (
                Attribute::Uuid,
                Value::Uuid(Uuid::parse_str(TEST_TESTGROUP_A_UUID).unwrap())
            )
        );
        let eb: Entry<EntryInit, EntryNew> = entry_init!(
            (Attribute::Class, EntryClass::Group.to_value()),
            (Attribute::Name, Value::new_iname("testgroup_b")),
            (Attribute::Description, Value::new_utf8s("testgroup")),
            (
                Attribute::Member,
                Value::Refer(Uuid::parse_str(TEST_TESTGROUP_A_UUID).unwrap())
            )
        );

        let preload = vec![ea, eb];

        run_delete_test!(
            Ok(()),
            preload,
            filter!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testgroup_b")
            )),
            None,
            |_qs: &mut QueryServerWriteTransaction| {}
        );
    }

    // Delete something that has a self reference.
    #[test]
    fn test_delete_remove_reference_self() {
        let eb: Entry<EntryInit, EntryNew> = entry_init!(
            (Attribute::Class, EntryClass::Group.to_value()),
            (Attribute::Name, Value::new_iname("testgroup_b")),
            (Attribute::Description, Value::new_utf8s("testgroup")),
            (
                Attribute::Uuid,
                Value::Uuid(Uuid::parse_str(TEST_TESTGROUP_A_UUID).unwrap())
            ),
            (
                Attribute::Member,
                Value::Refer(Uuid::parse_str(TEST_TESTGROUP_A_UUID).unwrap())
            )
        );
        let preload = vec![eb];

        run_delete_test!(
            Ok(()),
            preload,
            filter!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testgroup_b")
            )),
            None,
            |_qs: &mut QueryServerWriteTransaction| {}
        );
    }

    #[test]
    fn test_delete_remove_reference_oauth2() {
        // Oauth2 types are also capable of uuid referencing to groups for their
        // scope maps, so we need to check that when the group is deleted, that the
        // scope map is also appropriately affected.
        let ea: Entry<EntryInit, EntryNew> = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Account.to_value()),
            (
                Attribute::Class,
                EntryClass::OAuth2ResourceServer.to_value()
            ),
            // (Attribute::Class, EntryClass::OAuth2ResourceServerBasic.into()),
            (Attribute::Name, Value::new_iname("test_resource_server")),
            (
                Attribute::DisplayName,
                Value::new_utf8s("test_resource_server")
            ),
            (
                Attribute::OAuth2RsOriginLanding,
                Value::new_url_s("https://demo.example.com").unwrap()
            ),
            (
                Attribute::OAuth2RsScopeMap,
                Value::new_oauthscopemap(
                    Uuid::parse_str(TEST_TESTGROUP_B_UUID).unwrap(),
                    btreeset![OAUTH2_SCOPE_READ.to_string()]
                )
                .expect("Invalid scope")
            )
        );

        let eb: Entry<EntryInit, EntryNew> = entry_init!(
            (Attribute::Class, EntryClass::Group.to_value()),
            (Attribute::Name, Value::new_iname("testgroup")),
            (
                Attribute::Uuid,
                Value::Uuid(Uuid::parse_str(TEST_TESTGROUP_B_UUID).unwrap())
            ),
            (Attribute::Description, Value::new_utf8s("testgroup"))
        );

        let preload = vec![ea, eb];

        run_delete_test!(
            Ok(()),
            preload,
            filter!(f_eq(Attribute::Name, PartialValue::new_iname("testgroup"))),
            None,
            |qs: &mut QueryServerWriteTransaction| {
                let cands = qs
                    .internal_search(filter!(f_eq(
                        Attribute::Name,
                        PartialValue::new_iname("test_resource_server")
                    )))
                    .expect("Internal search failure");
                let ue = cands.first().expect("No entry");
                assert!(ue
                    .get_ava_as_oauthscopemaps(Attribute::OAuth2RsScopeMap)
                    .is_none())
            }
        );
    }

    #[qs_test]
    async fn test_delete_oauth2_rs_remove_sessions(server: &QueryServer) {
        let curtime = duration_from_epoch_now();
        let curtime_odt = OffsetDateTime::UNIX_EPOCH + curtime;

        let p = CryptoPolicy::minimum();
        let cred = Credential::new_password_only(&p, "test_password", OffsetDateTime::UNIX_EPOCH).unwrap();
        let cred_id = cred.uuid;

        // Create a user
        let mut server_txn = server.write(curtime).await.unwrap();

        let tuuid = Uuid::parse_str(TEST_TESTGROUP_B_UUID).unwrap();
        let rs_uuid = Uuid::new_v4();

        let e1 = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Person.to_value()),
            (Attribute::Class, EntryClass::Account.to_value()),
            (Attribute::Name, Value::new_iname("testperson1")),
            (Attribute::Uuid, Value::Uuid(tuuid)),
            (Attribute::Description, Value::new_utf8s("testperson1")),
            (Attribute::DisplayName, Value::new_utf8s("testperson1")),
            (
                Attribute::PrimaryCredential,
                Value::Cred("primary".to_string(), cred.clone())
            )
        );

        let e2 = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Account.to_value()),
            (
                Attribute::Class,
                EntryClass::OAuth2ResourceServer.to_value()
            ),
            (Attribute::Uuid, Value::Uuid(rs_uuid)),
            (Attribute::Name, Value::new_iname("test_resource_server")),
            (
                Attribute::DisplayName,
                Value::new_utf8s("test_resource_server")
            ),
            (
                Attribute::OAuth2RsOriginLanding,
                Value::new_url_s("https://demo.example.com").unwrap()
            ),
            // System admins
            (
                Attribute::OAuth2RsScopeMap,
                Value::new_oauthscopemap(
                    UUID_IDM_ALL_ACCOUNTS,
                    btreeset![OAUTH2_SCOPE_OPENID.to_string()]
                )
                .expect("invalid oauthscope")
            )
        );

        let ce = CreateEvent::new_internal(vec![e1, e2]);
        assert!(server_txn.create(&ce).is_ok());

        // Create a fake session and oauth2 session.

        let session_id = Uuid::new_v4();
        let pv_session_id = PartialValue::Refer(session_id);

        let parent_id = Uuid::new_v4();
        let pv_parent_id = PartialValue::Refer(parent_id);
        let issued_at = curtime_odt;
        let issued_by = IdentityId::User(tuuid);
        let scope = SessionScope::ReadOnly;

        // Mod the user
        let modlist = modlist!([
            Modify::Present(
                Attribute::OAuth2Session,
                Value::Oauth2Session(
                    session_id,
                    Oauth2Session {
                        parent: Some(parent_id),
                        // Note we set the exp to None so we are not removing based on exp
                        state: SessionState::NeverExpires,
                        issued_at,
                        rs_uuid,
                    },
                )
            ),
            Modify::Present(
                Attribute::UserAuthTokenSession,
                Value::Session(
                    parent_id,
                    Session {
                        label: "label".to_string(),
                        // Note we set the exp to None so we are not removing based on removal of the parent.
                        state: SessionState::NeverExpires,
                        // Need the other inner bits?
                        // for the gracewindow.
                        issued_at,
                        // Who actually created this?
                        issued_by,
                        cred_id,
                        // What is the access scope of this session? This is
                        // for auditing purposes.
                        scope,
                        type_: AuthType::Passkey,
                        ext_metadata: Default::default(),
                    },
                )
            ),
        ]);

        server_txn
            .internal_modify(
                &filter!(f_eq(Attribute::Uuid, PartialValue::Uuid(tuuid))),
                &modlist,
            )
            .expect("Failed to modify user");

        // Still there

        let entry = server_txn.internal_search_uuid(tuuid).expect("failed");
        assert!(entry.attribute_equality(Attribute::UserAuthTokenSession, &pv_parent_id));
        assert!(entry.attribute_equality(Attribute::OAuth2Session, &pv_session_id));

        // Delete the oauth2 resource server.
        assert!(server_txn.internal_delete_uuid(rs_uuid).is_ok());

        // Oauth2 Session gone.
        let entry = server_txn.internal_search_uuid(tuuid).expect("failed");

        // Note the uat is present still.
        let session = entry
            .get_ava_as_session_map(Attribute::UserAuthTokenSession)
            .and_then(|sessions| sessions.get(&parent_id))
            .expect("No session map found");
        assert!(matches!(session.state, SessionState::NeverExpires));

        // The oauth2 session is revoked.
        let session = entry
            .get_ava_as_oauth2session_map(Attribute::OAuth2Session)
            .and_then(|sessions| sessions.get(&session_id))
            .expect("No session map found");
        assert!(matches!(session.state, SessionState::RevokedAt(_)));

        assert!(server_txn.commit().is_ok());
    }

    #[qs_test]
    async fn test_ignore_references_for_regen(server: &QueryServer) {
        // Test that we ignore certain reference types that are specifically
        // regenerated in the code paths that *follow* refint. We have to have
        // refint before memberof just due to the nature of how it works. But
        // we still want to ignore invalid memberOf values and certain invalid
        // member sets from dyngroups to allow them to self-heal at run time.
        let curtime = duration_from_epoch_now();
        let mut server_txn = server.write(curtime).await.unwrap();

        let tgroup_uuid = Uuid::new_v4();
        let dyn_uuid = Uuid::new_v4();
        let inv_mo_uuid = Uuid::new_v4();
        let inv_mb_uuid = Uuid::new_v4();

        let e_dyn = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Group.to_value()),
            (Attribute::Class, EntryClass::DynGroup.to_value()),
            (Attribute::Uuid, Value::Uuid(dyn_uuid)),
            (Attribute::Name, Value::new_iname("test_dyngroup")),
            (Attribute::DynMember, Value::Refer(inv_mb_uuid)),
            (
                Attribute::DynGroupFilter,
                Value::JsonFilt(ProtoFilter::Eq(
                    Attribute::Name.to_string(),
                    "testgroup".to_string()
                ))
            )
        );

        let e_group: Entry<EntryInit, EntryNew> = entry_init!(
            (Attribute::Class, EntryClass::Group.to_value()),
            (Attribute::Class, EntryClass::MemberOf.to_value()),
            (Attribute::Name, Value::new_iname("testgroup")),
            (Attribute::Uuid, Value::Uuid(tgroup_uuid)),
            (Attribute::MemberOf, Value::Refer(inv_mo_uuid))
        );

        let ce = CreateEvent::new_internal(vec![e_dyn, e_group]);
        assert!(server_txn.create(&ce).is_ok());

        let dyna = server_txn
            .internal_search_uuid(dyn_uuid)
            .expect("Failed to access dyn group");

        let dyn_member = dyna
            .get_ava_refer(Attribute::DynMember)
            .expect("Failed to get dyn member attribute");
        assert_eq!(dyn_member.len(), 1);
        assert!(dyn_member.contains(&tgroup_uuid));

        let group = server_txn
            .internal_search_uuid(tgroup_uuid)
            .expect("Failed to access mo group");

        let grp_member = group
            .get_ava_refer(Attribute::MemberOf)
            .expect("Failed to get memberof attribute");
        assert_eq!(grp_member.len(), 1);
        assert!(grp_member.contains(&dyn_uuid));

        assert!(server_txn.commit().is_ok());
    }

    #[qs_test]
    async fn test_entry_managed_by_references(server: &QueryServer) {
        let curtime = duration_from_epoch_now();
        let mut server_txn = server.write(curtime).await.unwrap();

        let manages_uuid = Uuid::new_v4();
        let e_manages: Entry<EntryInit, EntryNew> = entry_init!(
            (Attribute::Class, EntryClass::Group.to_value()),
            (Attribute::Name, Value::new_iname("entry_manages")),
            (Attribute::Uuid, Value::Uuid(manages_uuid))
        );

        let group_uuid = Uuid::new_v4();
        let e_group: Entry<EntryInit, EntryNew> = entry_init!(
            (Attribute::Class, EntryClass::Group.to_value()),
            (Attribute::Name, Value::new_iname("entry_managed_by")),
            (Attribute::Uuid, Value::Uuid(group_uuid)),
            (Attribute::EntryManagedBy, Value::Refer(manages_uuid))
        );

        let ce = CreateEvent::new_internal(vec![e_manages, e_group]);
        assert!(server_txn.create(&ce).is_ok());

        let group = server_txn
            .internal_search_uuid(group_uuid)
            .expect("Failed to access group");

        let entry_managed_by = group
            .get_ava_single_refer(Attribute::EntryManagedBy)
            .expect("No entry managed by");

        assert_eq!(entry_managed_by, manages_uuid);

        // It's valid to delete this, since entryManagedBy is may not must.
        assert!(server_txn.internal_delete_uuid(manages_uuid).is_ok());

        let group = server_txn
            .internal_search_uuid(group_uuid)
            .expect("Failed to access group");

        assert!(group.get_ava_refer(Attribute::EntryManagedBy).is_none());

        assert!(server_txn.commit().is_ok());
    }

    #[test]
    fn test_delete_remove_reference_oauth2_claim_map() {
        let ea: Entry<EntryInit, EntryNew> = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Account.to_value()),
            (
                Attribute::Class,
                EntryClass::OAuth2ResourceServer.to_value()
            ),
            (
                Attribute::Class,
                EntryClass::OAuth2ResourceServerPublic.to_value()
            ),
            (Attribute::Name, Value::new_iname("test_resource_server")),
            (
                Attribute::DisplayName,
                Value::new_utf8s("test_resource_server")
            ),
            (
                Attribute::OAuth2RsOriginLanding,
                Value::new_url_s("https://demo.example.com").unwrap()
            ),
            (
                Attribute::OAuth2RsClaimMap,
                Value::OauthClaimMap(
                    "custom_a".to_string(),
                    OauthClaimMapJoin::CommaSeparatedValue,
                )
            ),
            (
                Attribute::OAuth2RsClaimMap,
                Value::OauthClaimValue(
                    "custom_a".to_string(),
                    Uuid::parse_str(TEST_TESTGROUP_B_UUID).unwrap(),
                    btreeset!["value_a".to_string()],
                )
            )
        );

        let eb: Entry<EntryInit, EntryNew> = entry_init!(
            (Attribute::Class, EntryClass::Group.to_value()),
            (Attribute::Name, Value::new_iname("testgroup")),
            (
                Attribute::Uuid,
                Value::Uuid(Uuid::parse_str(TEST_TESTGROUP_B_UUID).unwrap())
            ),
            (Attribute::Description, Value::new_utf8s("testgroup"))
        );

        let preload = vec![ea, eb];

        run_delete_test!(
            Ok(()),
            preload,
            filter!(f_eq(Attribute::Name, PartialValue::new_iname("testgroup"))),
            None,
            |qs: &mut QueryServerWriteTransaction| {
                let cands = qs
                    .internal_search(filter!(f_eq(
                        Attribute::Name,
                        PartialValue::new_iname("test_resource_server")
                    )))
                    .expect("Internal search failure");
                let ue = cands.first().expect("No entry");

                assert!(ue
                    .get_ava_set(Attribute::OAuth2RsClaimMap)
                    .and_then(|vs| vs.as_oauthclaim_map())
                    .is_none())
            }
        );
    }

    // =======================================================================
    // This section tests behaviour of reference *entries* rather than just
    // referential ID's. The reason this is different is because reference
    // entries similar to SQL are cascade deleted. That means we need to
    // handle this case cleanly when we delete entries that their
    // referencing entries are also deleted. Similar we need to ensure they
    // are also revived correctly.
    //
    // What is tricky here is the case when you delete a reference entry
    // intentionally, rather than just the parent entry. In this case you
    // don't want the manually deleted reference entry to be revived.
    //
    // Similar we also need to test when we delete an entry, that if we revive
    // something that references it, that the operation is rejected as the
    // reference would then be invalid.

    #[qs_test]
    async fn test_reference_entry_basic(server: &QueryServer) {
        // Create
        let curtime = duration_from_epoch_now();
        let mut server_txn = server.write(curtime).await.unwrap();

        let user_uuid = Uuid::new_v4();
        let ref_uuid = Uuid::new_v4();
        let cert_data = Box::new(
            Certificate::from_pem(TEST_X509_CERT_DATA)
                .expect("Unable to parse test X509 cert data"),
        );

        let user_entry = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Account.to_value()),
            (Attribute::Class, EntryClass::Person.to_value()),
            (Attribute::Name, Value::new_iname("testperson1")),
            (Attribute::Uuid, Value::Uuid(user_uuid)),
            (Attribute::Description, Value::new_utf8s("testperson1")),
            (Attribute::DisplayName, Value::new_utf8s("testperson1"))
        );

        let ref_entry = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::ClientCertificate.to_value()),
            (Attribute::Uuid, Value::Uuid(ref_uuid)),
            (Attribute::Refers, Value::Refer(user_uuid)),
            (
                Attribute::Certificate,
                Value::Certificate(cert_data.clone())
            )
        );

        assert!(server_txn
            .internal_create(vec![user_entry, ref_entry])
            .is_ok());

        // Delete
        assert!(server_txn.internal_delete_uuid(user_uuid).is_ok());

        // Assert the referenced cert is gone.
        assert!(!server_txn
            .internal_exists_uuid(ref_uuid)
            .expect("Unable to check if entry exists"));

        assert!(server_txn.commit().is_ok());
        // =========== new txn
        let mut server_txn = server.write(curtime).await.unwrap();

        // You can't revive just the cert.
        assert!(matches!(
            server_txn.internal_revive_uuid(ref_uuid).unwrap_err(),
            OperationError::Plugin(PluginError::ReferentialIntegrity(_))
        ));

        // Roll back
        drop(server_txn);

        // Revive
        // Assert both the user and the ref are back
        let mut server_txn = server.write(curtime).await.unwrap();

        assert!(server_txn.internal_revive_uuid(user_uuid).is_ok());

        assert!(server_txn
            .internal_exists_uuid(user_uuid)
            .expect("Unable to check if entry exists"));

        assert!(server_txn
            .internal_exists_uuid(ref_uuid)
            .expect("Unable to check if entry exists"));

        assert!(server_txn.commit().is_ok());

        // ===========================================
        // Now test when you delete the cert separately to the user,
        // that when you revive the user the cert stays deleted.

        let mut server_txn = server.write(curtime).await.unwrap();

        assert!(server_txn.internal_delete_uuid(ref_uuid).is_ok());

        assert!(server_txn
            .internal_exists_uuid(user_uuid)
            .expect("Unable to check if entry exists"));

        assert!(!server_txn
            .internal_exists_uuid(ref_uuid)
            .expect("Unable to check if entry exists"));

        assert!(server_txn.internal_delete_uuid(user_uuid).is_ok());

        assert!(server_txn.commit().is_ok());
        // =========== new txn
        let mut server_txn = server.write(curtime).await.unwrap();

        // You can't revive just the cert.
        assert!(server_txn.internal_revive_uuid(ref_uuid).is_err());

        // Roll back
        drop(server_txn);
        // =========== new txn
        let mut server_txn = server.write(curtime).await.unwrap();
        assert!(server_txn.internal_revive_uuid(user_uuid).is_ok());

        assert!(server_txn
            .internal_exists_uuid(user_uuid)
            .expect("Unable to check if entry exists"));

        // But the cert was NOT revived at the same time!!!
        assert!(!server_txn
            .internal_exists_uuid(ref_uuid)
            .expect("Unable to check if entry exists"));

        assert!(server_txn.commit().is_ok());
    }

    // Add in a test to assert a refers can't refers to another refers. No bad ouroboros
    #[qs_test]
    async fn test_reference_ouroboros_denied(server: &QueryServer) {
        // Create
        let curtime = duration_from_epoch_now();
        let mut server_txn = server.write(curtime).await.unwrap();

        let user_uuid = Uuid::new_v4();
        let ref_uuid = Uuid::new_v4();
        let ref_ouroboros_uuid = Uuid::new_v4();
        let cert_data = Box::new(
            Certificate::from_pem(TEST_X509_CERT_DATA)
                .expect("Unable to parse test X509 cert data"),
        );

        let user_entry = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Account.to_value()),
            (Attribute::Class, EntryClass::Person.to_value()),
            (Attribute::Name, Value::new_iname("testperson1")),
            (Attribute::Uuid, Value::Uuid(user_uuid)),
            (Attribute::Description, Value::new_utf8s("testperson1")),
            (Attribute::DisplayName, Value::new_utf8s("testperson1"))
        );

        let ref_entry = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::ClientCertificate.to_value()),
            (Attribute::Uuid, Value::Uuid(ref_uuid)),
            (Attribute::Refers, Value::Refer(user_uuid)),
            (
                Attribute::Certificate,
                Value::Certificate(cert_data.clone())
            )
        );

        assert!(server_txn
            .internal_create(vec![user_entry, ref_entry])
            .is_ok());

        assert!(server_txn.commit().is_ok());

        // =========== new txn
        let mut server_txn = server.write(curtime).await.unwrap();

        // May not create a reference to a reference.
        // This is a naughty entry.
        let ref_entry = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::ClientCertificate.to_value()),
            (Attribute::Uuid, Value::Uuid(ref_ouroboros_uuid)),
            (Attribute::Refers, Value::Refer(ref_uuid)),
            (
                Attribute::Certificate,
                Value::Certificate(cert_data.clone())
            )
        );

        assert!(server_txn.internal_create(vec![ref_entry]).is_err());

        // Roll back
        drop(server_txn);

        // =========== new txn
        let mut server_txn = server.write(curtime).await.unwrap();

        // May not create a reference to a reference.
        // This is a naughty entry.
        let ref_entry = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::ClientCertificate.to_value()),
            (Attribute::Uuid, Value::Uuid(ref_ouroboros_uuid)),
            // Start by referencing the person.
            (Attribute::Refers, Value::Refer(user_uuid)),
            (
                Attribute::Certificate,
                Value::Certificate(cert_data.clone())
            )
        );

        assert!(server_txn.internal_create(vec![ref_entry]).is_ok());

        // Now, modify to make it point at the other reference.
        let modlist = modlist!([
            Modify::Purged(Attribute::Refers),
            Modify::Present(Attribute::Refers, Value::Refer(ref_uuid)),
        ]);

        assert!(server_txn
            .internal_modify_uuid(ref_ouroboros_uuid, &modlist)
            .is_err());

        // Roll back
        drop(server_txn);
    }

    // Test with replication that on a conflict that the refers is deleted too?

    // Ensure that the refers are all removed when conflict occurs.
}
