use super::proto::*;
use crate::{
    plugins::Plugins,
    prelude::*,
    server::{ChangeFlag, ServerPhase},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

impl QueryServerWriteTransaction<'_> {
    // Apply the state changes if they are valid.

    fn consumer_incremental_apply_entries(
        &mut self,
        ctx_entries: Vec<ReplIncrementalEntryV1>,
    ) -> Result<bool, OperationError> {
        // trace!(?ctx_entries);

        // No action needed for this if the entries are empty.
        if ctx_entries.is_empty() {
            debug!("No entries to act upon");
            return Ok(false);
        }

        /*
         *  Incremental is very similar to modify in how we have to treat the entries
         *  with a pre and post state. However we need an incremental prepare so that
         *  when new entries are provided to us we can merge to a stub and then commit
         *  it correctly. This takes an extra backend interface that prepares the
         *  entry stubs for us.
         */

        // I think we need to rehydrate all the repl content to a partial
        // entry. This way all the types are consistent and ready.
        let ctx_entries: Vec<_> = ctx_entries.into_iter().map(
            EntryIncrementalNew::rehydrate
        )
        .collect::<Result<Vec<_>, _>>()
        .inspect_err(|err| {
            error!(?err, "Unable to process replication incremental entries to valid entry states for replication");
        })?;

        trace!(?ctx_entries);

        let db_entries = self
            .be_txn
            .incremental_prepare(&ctx_entries)
            .inspect_err(|err| {
                error!(?err, "Failed to access entries from db");
            })?;

        trace!(?db_entries);

        // Need to probably handle conflicts here in this phase. I think they
        // need to be pushed to a separate list where they are then "created"
        // as a conflict.

        // First find if entries are in a conflict state. Remember, these conflicts are purely
        // UUID creation conflicts at this phase in the process.

        let (conflicts, proceed): (Vec<_>, Vec<_>) = ctx_entries
            .iter()
            .zip(db_entries)
            .partition(|(ctx_ent, db_ent)| ctx_ent.is_add_conflict(db_ent.as_ref()));

        debug!(conflicts = %conflicts.len(), proceed = %proceed.len());

        // Now we have a set of conflicts and a set of entries to proceed.
        //
        //    /- entries that need to be created as conflicts.
        //    |                /- entries that survive and need update to the db in place.
        //    v                v
        let (conflict_create, conflict_update): (
            Vec<Option<EntrySealedNew>>,
            Vec<(EntryIncrementalCommitted, Arc<EntrySealedCommitted>)>,
        ) = conflicts
            .into_iter()
            .map(
                |(ctx_ent, db_ent): (&EntryIncrementalNew, Arc<EntrySealedCommitted>)| {
                    let (opt_create, ent) =
                        ctx_ent.resolve_add_conflict(self.get_cid(), db_ent.as_ref());
                    (opt_create, (ent, db_ent))
                },
            )
            .unzip();

        // ⚠️  If we end up with plugins triggering other entries to conflicts, we DON'T need to
        // add them to this list. This is just for uuid conflicts, not higher level ones!
        //
        // ⚠️  We need to collect this from conflict_update since we may NOT be the originator
        // server for some conflicts, but we still need to know the UUID is IN the conflict
        // state for plugins. We also need to do this here before the conflict_update
        // set is consumed by later steps.
        //
        // ⚠️  When we upgrade between two nodes, migrations will often create *new* system
        // entries on both nodes. Until both nodes upgrade they can't replicate. This creates
        // a situation where both nodes have identical entry content for system entries, but
        // the entries that were created now are conflicts. Normally this is okay, because the
        // first node to upgrade will have it's entries persisted, and the other nodes duplicate
        // entries will be removed. However, just through the nature of being in the conflict
        // state, these entries are then added to the conflict_uuid set. This conflict_uuid set
        // is used by referential integrity to remove uuids from references so that group
        // memberships don't accidentally leak to recipients that were not intended.
        //
        // To avoid this, we remove any system entries from this conflict set, so that they are
        // exempt from this conflict handling which allows upgrades to work.
        let mut conflict_uuids: BTreeSet<_> = conflict_update
            .iter()
            .filter_map(|(_, e)| {
                let u = e.get_uuid();
                if u >= DYNAMIC_RANGE_MINIMUM_UUID {
                    // It is a user created node, process the conflict within plugins
                    Some(u)
                } else {
                    // It is in a system range, do not process this entry
                    None
                }
            })
            .collect();

        // Filter out None from conflict_create
        let conflict_create: Vec<EntrySealedNew> = conflict_create.into_iter().flatten().collect();

        let proceed_update: Vec<(EntryIncrementalCommitted, Arc<EntrySealedCommitted>)> = proceed
            .into_iter()
            .map(|(ctx_ent, db_ent)| {
                // This now is the set of entries that are able to be updated. Merge
                // their attribute sets/states per the change state rules.

                // This must create an EntryInvalidCommitted
                let merge_ent = ctx_ent.merge_state(db_ent.as_ref(), &self.schema, self.trim_cid());
                (merge_ent, db_ent)
            })
            .collect();

        // We now merge the conflict updates and the updates that can proceed. This is correct
        // since if an entry was conflicting by uuid then there is nothing for it to merge with
        // so as a result we can just by pass that step. We now have all_updates which is
        // the set of live entries to write back.
        let mut all_updates = conflict_update
            .into_iter()
            .chain(proceed_update)
            .collect::<Vec<_>>();

        // ⚠️  This hook is probably not what you want to use for checking entries are consistent.
        //
        // The main issue is that at this point we have a set of entries that need to be
        // created / marked into conflicts, and until that occurs it's hard to proceed with validations
        // like attr unique because then we would need to walk the various sets to find cases where
        // an attribute may not be unique "currently" but *would* be unique once the various entries
        // have then been conflicted and updated.
        //
        // Instead we treat this like refint - we allow the database to "temporarily" become
        // inconsistent, then we fix it immediately. This hook remains for cases in future
        // where we may wish to have session cleanup performed for example.
        Plugins::run_pre_repl_incremental(self, all_updates.as_mut_slice()).map_err(|e| {
            admin_error!("Operation failed (pre_repl_incremental plugin), {:?}", e);
            e
        })?;

        // Now we have to schema check our entries. Remember, here because this is
        // using into_iter it's possible that entries may be conflicted due to becoming
        // schema invalid during the merge process.
        let all_updates_valid = all_updates
            .into_iter()
            .map(|(ctx_ent, db_ent)| {
                // Check the schema
                //
                // In these cases when an entry fails schema, we mark it to
                // a conflict state and then retain it in the update process.
                //
                // The marking is done INSIDE this function!
                let sealed_ent = ctx_ent.validate_repl(&self.schema).seal(&self.schema);
                (sealed_ent, db_ent)
            })
            .collect::<Vec<_>>();

        // We now have two sets!
        //
        // * conflict_create - entries to be created that are conflicted via add statements (duplicate uuid)
        //                     these are only created on the entry origin node!
        // * all_updates_valid - this has two types of entries
        //   * entries that have survived a uuid conflict and need inplace write. Unlikely to become invalid.
        //   * entries that were merged and are schema valid.
        //   * entries that were merged and their attribute state has now become invalid and are conflicts.
        //
        // incremental_apply here handles both the creations and the update processes to ensure that
        // everything is updated in a single consistent operation.
        self.be_txn
            .incremental_apply(&all_updates_valid, conflict_create)
            .map_err(|e| {
                admin_error!("betxn create failure {:?}", e);
                e
            })?;

        Plugins::run_post_repl_incremental_conflict(
            self,
            all_updates_valid.as_slice(),
            &mut conflict_uuids,
        )
        .map_err(|e| {
            error!(
                "Operation failed (post_repl_incremental_conflict plugin), {:?}",
                e
            );
            e
        })?;

        // Plugins need these unzipped
        //
        let (cand, pre_cand): (Vec<_>, Vec<_>) = all_updates_valid
            .into_iter()
            // We previously excluded this to avoid doing unnecessary work on entries that
            // were moving to a conflict state, and the survivor was staying "as is" on this
            // node. However, this gets messy with dyngroups and memberof, where on a conflict
            // the memberships are deleted across the replication boundary. In these cases
            // we need dyngroups to see the valid entries, even if they are "identical to before"
            // to re-assert all their memberships are valid.
            /*
            .filter(|(cand, _)| {
                // Exclude anything that is conflicted as a result of the conflict plugins.
                !conflict_uuids.contains(&cand.get_uuid())
            })
            */
            .unzip();

        // We don't need to process conflict_creates here, since they are all conflicting
        // uuids which means that the conflict_uuids are all *here* so they will trigger anything
        // that requires processing anyway. As well conflict_creates may not be the full
        // set of conflict entries as we may not be the origin node! Conflict_creates is always
        // a subset of the conflicts.
        Plugins::run_post_repl_incremental(
            self,
            pre_cand.as_slice(),
            cand.as_slice(),
            &conflict_uuids,
        )
        .map_err(|e| {
            error!("Operation failed (post_repl_incremental plugin), {:?}", e);
            e
        })?;

        self.changed_uuid.extend(cand.iter().map(|e| e.get_uuid()));

        if !self.changed_flags.contains(ChangeFlag::ACP)
            && cand
                .iter()
                .chain(pre_cand.iter().map(|e| e.as_ref()))
                .any(|e| {
                    e.attribute_equality(Attribute::Class, &EntryClass::AccessControlProfile.into())
                })
        {
            self.changed_flags.insert(ChangeFlag::ACP)
        }

        if !self.changed_flags.contains(ChangeFlag::OAUTH2)
            && cand
                .iter()
                .chain(pre_cand.iter().map(|e| e.as_ref()))
                .any(|e| {
                    e.attribute_equality(Attribute::Class, &EntryClass::OAuth2ResourceServer.into())
                })
        {
            self.changed_flags.insert(ChangeFlag::OAUTH2)
        }

        if !self.changed_flags.contains(ChangeFlag::OAUTH2_CLIENT)
            && cand
                .iter()
                .chain(pre_cand.iter().map(|e| e.as_ref()))
                .any(|e| e.attribute_equality(Attribute::Class, &EntryClass::OAuth2Client.into()))
        {
            self.changed_flags.insert(ChangeFlag::OAUTH2_CLIENT)
        }

        if !self.changed_flags.contains(ChangeFlag::FEATURE)
            && cand
                .iter()
                .chain(pre_cand.iter().map(|e| e.as_ref()))
                .any(|e| e.attribute_equality(Attribute::Class, &EntryClass::Feature.into()))
        {
            self.changed_flags.insert(ChangeFlag::FEATURE)
        }

        if !self.changed_flags.contains(ChangeFlag::APPLICATION)
            && cand
                .iter()
                .chain(pre_cand.iter().map(|e| e.as_ref()))
                .any(|e| e.attribute_equality(Attribute::Class, &EntryClass::Application.into()))
        {
            self.changed_flags.insert(ChangeFlag::APPLICATION)
        }

        if !self.changed_flags.contains(ChangeFlag::SYNC_AGREEMENT)
            && cand
                .iter()
                .chain(pre_cand.iter().map(|e| e.as_ref()))
                .any(|e| e.attribute_equality(Attribute::Class, &EntryClass::SyncAccount.into()))
        {
            self.changed_flags.insert(ChangeFlag::SYNC_AGREEMENT)
        }

        if !self.changed_flags.contains(ChangeFlag::KEY_MATERIAL)
            && cand
                .iter()
                .chain(pre_cand.iter().map(|e| e.as_ref()))
                .any(|e| {
                    e.attribute_equality(Attribute::Class, &EntryClass::KeyProvider.into())
                        || e.attribute_equality(Attribute::Class, &EntryClass::KeyObject.into())
                })
        {
            self.changed_flags.insert(ChangeFlag::KEY_MATERIAL)
        }

        trace!(
            changed = ?self.changed_flags.iter_names().collect::<Vec<_>>(),
        );

        Ok(true)
    }

    pub fn consumer_apply_changes(
        &mut self,
        ctx: ReplIncrementalContext,
    ) -> Result<ConsumerState, OperationError> {
        match ctx {
            ReplIncrementalContext::DomainMismatch => {
                error!("Unable to proceed with consumer incremental - the supplier has indicated that our domain_uuid's are not equivalent. This can occur when adding a new consumer to an existing topology.");
                error!("This server's content must be refreshed to proceed. If you have configured automatic refresh, this will occur shortly.");
                Ok(ConsumerState::RefreshRequired)
            }
            ReplIncrementalContext::NoChangesAvailable => {
                debug!("no changes are available");
                Ok(ConsumerState::Ok)
            }
            ReplIncrementalContext::RefreshRequired => {
                error!("Unable to proceed with consumer incremental - the supplier has indicated that our RUV is outdated, and replication would introduce data corruption.");
                error!("This server's content must be refreshed to proceed. If you have configured automatic refresh, this will occur shortly.");
                Ok(ConsumerState::RefreshRequired)
            }
            ReplIncrementalContext::UnwillingToSupply => {
                warn!("Unable to proceed with consumer incremental - the supplier has indicated that our RUV is ahead, and replication would introduce data corruption.");
                error!("This supplier's content must be refreshed to proceed. If you have configured automatic refresh, this will occur shortly.");
                Ok(ConsumerState::Ok)
            }
            ReplIncrementalContext::V1 {
                domain_version,
                domain_patch_level,
                domain_uuid,
                ranges,
                schema_entries,
                meta_entries,
                entries,
            } => self.consumer_apply_changes_v1(
                domain_version,
                domain_patch_level,
                domain_uuid,
                &ranges,
                schema_entries,
                meta_entries,
                entries,
            ),
        }
    }

    #[instrument(level = "debug", skip_all)]
    fn consumer_apply_changes_v1(
        &mut self,
        ctx_domain_version: DomainVersion,
        ctx_domain_patch_level: u32,
        ctx_domain_uuid: Uuid,
        ctx_ranges: &BTreeMap<Uuid, ReplAnchoredCidRange>,
        ctx_schema_entries: Vec<ReplIncrementalEntryV1>,
        ctx_meta_entries: Vec<ReplIncrementalEntryV1>,
        ctx_entries: Vec<ReplIncrementalEntryV1>,
    ) -> Result<ConsumerState, OperationError> {
        if ctx_domain_version < DOMAIN_MINIMUM_REPLICATION_LEVEL {
            error!("Unable to proceed with consumer incremental - incoming domain level is lower than our minimum supported level. {} < {}", ctx_domain_version, DOMAIN_MINIMUM_REPLICATION_LEVEL);
            return Err(OperationError::ReplDomainLevelUnsatisfiable);
        } else if ctx_domain_version > DOMAIN_MAXIMUM_REPLICATION_LEVEL {
            error!("Unable to proceed with consumer incremental - incoming domain level is greater than our maximum supported level. {} > {}", ctx_domain_version, DOMAIN_MAXIMUM_REPLICATION_LEVEL);
            return Err(OperationError::ReplDomainLevelUnsatisfiable);
        };

        let domain_patch_level = if self.get_domain_development_taint() {
            u32::MAX
        } else {
            self.get_domain_patch_level()
        };

        if ctx_domain_patch_level != domain_patch_level {
            error!("Unable to proceed with consumer incremental - incoming domain patch level is not equal to our patch level. {} != {}", ctx_domain_patch_level, domain_patch_level);
            return Err(OperationError::ReplDomainLevelUnsatisfiable);
        };

        // Assert that the d_uuid matches the repl domain uuid.
        let db_uuid = self.be_txn.get_db_d_uuid()?;

        if db_uuid != ctx_domain_uuid {
            error!("Unable to proceed with consumer incremental - incoming domain uuid does not match our database uuid. You must investigate this situation. {:?} != {:?}", db_uuid, ctx_domain_uuid);
            return Err(OperationError::ReplDomainUuidMismatch);
        }

        // Preflight checks of the incoming RUV to ensure it's in a good state.
        let txn_cid = *self.get_cid();
        let ruv = self.be_txn.get_ruv_write();

        let change_count = ctx_schema_entries.len() + ctx_meta_entries.len() + ctx_entries.len();

        ruv.incremental_preflight_validate_ruv(ctx_ranges, &txn_cid)
            .inspect_err(|err| {
                error!(
                    ?err,
                    "Incoming RUV failed preflight checks, unable to proceed."
                );
            })?;

        // == ⚠️  Below this point we begin to make changes! ==
        debug!(
            "Proceeding to apply incremental with {change_count} changes from domain {ctx_domain_uuid:?} at level {ctx_domain_version}"
        );

        debug!(?ctx_ranges);

        if ctx_domain_version < DOMAIN_LEVEL_1_11 {
            // Schema is an in memory property attached to domain level from 1_11, and so the meta entries
            // will trigger the schema to reload if required.
            debug!("Applying {} schema entries", ctx_schema_entries.len());
            // Apply the schema entries first.
            let schema_changed = self
                .consumer_incremental_apply_entries(ctx_schema_entries)
                .inspect_err(|err| {
                    error!(?err, "Failed to apply incremental schema entries");
                })?;

            if schema_changed {
                // We need to reload schema now!
                self.reload_schema().inspect_err(|err| {
                    error!(?err, "Failed to reload schema");
                })?;
            }
        } else {
            self.reload_schema().inspect_err(|err| {
                error!(?err, "Failed to reload schema");
            })?;
        }

        debug!("Applying {} meta entries", ctx_meta_entries.len());
        // Apply meta entries now.
        let meta_changed = self
            .consumer_incremental_apply_entries(ctx_meta_entries)
            .inspect_err(|err| {
                error!(?err, "Failed to apply incremental meta entries");
            })?;

        // This is re-loaded in case the domain name changed on the remote
        if meta_changed {
            self.reload_domain_info().inspect_err(|err| {
                error!(?err, "Failed to reload domain info");
            })?;
            self.reload_system_config().inspect_err(|err| {
                error!(?err, "Failed to reload system configuration");
            })?;
        }

        debug!("Applying {} context entries", ctx_entries.len());
        // Update all other entries now.
        self.consumer_incremental_apply_entries(ctx_entries)
            .inspect_err(|err| {
                error!(?err, "Failed to apply incremental meta entries");
            })?;

        // Reload the domain version, doing any needed migrations.
        //
        // While it seems odd that we do the migrations after we receive the entries,
        // this is because the supplier will already be sending us everything that
        // was just migrated. As a result, we only need to apply the migrations to entries
        // that were not on the supplier, and therefore need updates here.
        if meta_changed {
            self.reload_domain_info_version().inspect_err(|err| {
                error!(?err, "Failed to reload domain info version");
            })?;
        }

        // Finally, confirm that the ranges that we have added match the ranges from our
        // context. Note that we get this in a writeable form!
        let ruv = self.be_txn.get_ruv_write();

        ruv.refresh_validate_ruv(ctx_ranges).inspect_err(|err| {
            error!(?err, "RUV ranges were not rebuilt correctly.");
        })?;

        ruv.refresh_update_ruv(ctx_ranges).inspect_err(|err| {
            error!(?err, "Unable to update RUV with supplier ranges.");
        })?;

        Ok(ConsumerState::Ok)
    }

    pub fn consumer_apply_refresh(
        &mut self,
        ctx: ReplRefreshContext,
    ) -> Result<(), OperationError> {
        match ctx {
            ReplRefreshContext::V1 {
                domain_version,
                domain_devel,
                domain_uuid,
                ranges,
                schema_entries,
                meta_entries,
                entries,
            } => self.consumer_apply_refresh_v1(
                domain_version,
                domain_devel,
                domain_uuid,
                &ranges,
                schema_entries,
                meta_entries,
                entries,
            ),
        }
    }

    fn consumer_refresh_create_entries(
        &mut self,
        ctx_entries: Vec<ReplEntryV1>,
    ) -> Result<(), OperationError> {
        let candidates = ctx_entries
            .into_iter()
            .map(EntryRefreshNew::from_repl_entry_v1)
            .collect::<Result<Vec<EntryRefreshNew>, _>>()
            .inspect_err(|err| {
                error!(?err, "Failed to convert entries from supplier");
            })?;

        Plugins::run_pre_repl_refresh(self, candidates.as_slice()).map_err(|e| {
            admin_error!(
                "Refresh operation failed (pre_repl_refresh plugin), {:?}",
                e
            );
            e
        })?;

        // No need to assign CID's since this is a repl import.
        let norm_cand = candidates
            .into_iter()
            .map(|e| {
                e.validate(&self.schema)
                    .map_err(|e| {
                        admin_error!("Schema Violation in refresh validate {:?}", e);
                        OperationError::SchemaViolation(e)
                    })
                    .map(|e| {
                        // Then seal the changes?
                        e.seal(&self.schema)
                    })
            })
            .collect::<Result<Vec<EntrySealedNew>, _>>()?;

        let commit_cand = self.be_txn.refresh(norm_cand).map_err(|e| {
            admin_error!("betxn create failure {:?}", e);
            e
        })?;

        Plugins::run_post_repl_refresh(self, &commit_cand).map_err(|e| {
            admin_error!(
                "Refresh operation failed (post_repl_refresh plugin), {:?}",
                e
            );
            e
        })?;

        self.changed_uuid
            .extend(commit_cand.iter().map(|e| e.get_uuid()));

        Ok(())
    }

    #[instrument(level = "info", skip_all)]
    fn consumer_apply_refresh_v1(
        &mut self,
        ctx_domain_version: DomainVersion,
        ctx_domain_devel: bool,
        ctx_domain_uuid: Uuid,
        ctx_ranges: &BTreeMap<Uuid, ReplAnchoredCidRange>,
        ctx_schema_entries: Vec<ReplEntryV1>,
        ctx_meta_entries: Vec<ReplEntryV1>,
        ctx_entries: Vec<ReplEntryV1>,
    ) -> Result<(), OperationError> {
        // Can we apply the domain version validly?
        // if domain_version >= min_support ...
        let current_devel_flag = option_env!("KANIDM_PRE_RELEASE").is_some();

        if ctx_domain_version < DOMAIN_MINIMUM_REPLICATION_LEVEL {
            error!("Unable to proceed with consumer refresh - incoming domain level is lower than our minimum supported level. {} < {}", ctx_domain_version, DOMAIN_MINIMUM_REPLICATION_LEVEL);
            return Err(OperationError::ReplDomainLevelUnsatisfiable);
        } else if ctx_domain_version > DOMAIN_MAXIMUM_REPLICATION_LEVEL {
            error!("Unable to proceed with consumer refresh - incoming domain level is greater than our maximum supported level. {} > {}", ctx_domain_version, DOMAIN_MAXIMUM_REPLICATION_LEVEL);
            return Err(OperationError::ReplDomainLevelUnsatisfiable);
        } else if ctx_domain_devel && !current_devel_flag {
            error!("Unable to proceed with consumer refresh - incoming domain is from a development version while this server is a stable release.");
            return Err(OperationError::ReplDomainLevelUnsatisfiable);
        } else if !ctx_domain_devel && current_devel_flag {
            error!("Unable to proceed with consumer refresh - incoming domain is from a stable version while this server is a development release.");
            return Err(OperationError::ReplDomainLevelUnsatisfiable);
        } else {
            debug!(
                "Proceeding to refresh from domain at level {}",
                ctx_domain_version
            );
        };

        // == ⚠️  Below this point we begin to make changes! ==
        self.set_phase_bootstrap();

        // Update the d_uuid. This is what defines us as being part of this repl topology!
        self.be_txn
            .set_db_d_uuid(ctx_domain_uuid)
            .inspect_err(|err| {
                error!(?err, "Failed to reset domain uuid");
            })?;

        // We need to reset our server uuid now. This is so that any other servers
        // which had our former server_uuid in their RUV, is able to start to age it
        // out and trim it.
        self.reset_server_uuid()?;

        // Delete all entries - *proper delete, not just tombstone!*
        self.be_txn
            .danger_delete_all_db_content()
            .inspect_err(|err| {
                error!(?err, "Failed to clear existing server database content");
            })?;

        // Reset this transactions schema to a completely clean slate.

        // Schema is an in memory property attached to domain level from 1_11, and so we don't actually
        // need to apply these meta entries.
        if ctx_domain_version < DOMAIN_LEVEL_1_11 {
            self.schema.generate_in_memory().inspect_err(|err| {
                error!(?err, "Failed to reset in memory schema to clean state");
            })?;

            // Reindex now to force some basic indexes to exist
            self.reindex(false).inspect_err(|err| {
                error!(?err, "Failed to reload schema");
            })?;

            // Apply the schema entries first. This is the foundation that everything
            // else will build upon!
            self.consumer_refresh_create_entries(ctx_schema_entries)
                .inspect_err(|err| {
                    error!(?err, "Failed to refresh schema entries");
                })?;
        }

        // We need to reload schema now! From 1.11 and above, this is what actually
        // generates the in memory schema.
        self.reload_schema().inspect_err(|err| {
            error!(?err, "Failed to reload schema");
        })?;

        // Schema is now ready
        self.set_phase(ServerPhase::SchemaReady);

        // We have to reindex to force all the existing indexes to be dumped
        // and recreated before we start to import.
        self.reindex(false).inspect_err(|err| {
            error!(?err, "Failed to reload schema");
        })?;

        // Apply the domain info entry / system info / system config entry?
        self.consumer_refresh_create_entries(ctx_meta_entries)
            .inspect_err(|err| {
                error!(?err, "Failed to refresh meta entries");
            })?;

        // NOTE: The domain info we receive here will have the domain version populated!
        // That's okay though, because all the incoming data is already at the right
        // version!
        self.reload_domain_info().inspect_err(|err| {
            error!(?err, "Failed to reload domain info");
        })?;

        // Mark that everything changed so that post commit hooks function as expected.
        self.changed_flags.insert(
            ChangeFlag::SCHEMA
                | ChangeFlag::ACP
                | ChangeFlag::OAUTH2
                | ChangeFlag::OAUTH2_CLIENT
                | ChangeFlag::FEATURE
                | ChangeFlag::DOMAIN
                | ChangeFlag::APPLICATION
                | ChangeFlag::SYSTEM_CONFIG
                | ChangeFlag::SYNC_AGREEMENT
                | ChangeFlag::KEY_MATERIAL,
        );

        // Domain info is now ready.
        self.set_phase(ServerPhase::DomainInfoReady);

        // ==== That's it! We are GOOD to go! ====

        // Create all the entries. Note we don't hit plugins here beside post repl plugs.
        self.consumer_refresh_create_entries(ctx_entries)
            .inspect_err(|err| {
                error!(?err, "Failed to refresh main db entries");
            })?;

        // Finally, confirm that the ranges that we have recreated match the ranges from our
        // context. Note that we get this in a writeable form!
        let ruv = self.be_txn.get_ruv_write();

        ruv.refresh_validate_ruv(ctx_ranges).inspect_err(|err| {
            error!(?err, "RUV ranges were not rebuilt correctly.");
        })?;

        ruv.refresh_update_ruv(ctx_ranges).inspect_err(|err| {
            error!(?err, "Unable to update RUV with supplier ranges.");
        })?;

        // Refresh complete
        self.set_phase(ServerPhase::Running);

        Ok(())
    }
}
