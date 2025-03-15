//! Access Control Profiles
//!
//! This is a pretty important and security sensitive part of the code - it's
//! responsible for making sure that who is allowed to do what is enforced, as
//! well as who is *not* allowed to do what.
//!
//! A detailed design can be found in access-profiles-and-security.
//!
//! This component of the server really has a few parts
//! - the ability to parse access profile structures into real ACP structs
//! - the ability to apply sets of ACP's to entries for coarse actions (IE
//!   search.
//! - the ability to turn an entry into a partial-entry for results send
//!   requirements (also search).

use hashbrown::HashMap;
use std::cell::Cell;
use std::collections::BTreeSet;
use std::ops::DerefMut;
use std::sync::Arc;

use concread::arcache::ARCacheBuilder;
use concread::cowcell::*;
use uuid::Uuid;

use crate::entry::{Entry, EntryInit, EntryNew};
use crate::event::{CreateEvent, DeleteEvent, ModifyEvent, SearchEvent};
use crate::filter::{Filter, FilterValid, ResolveFilterCache, ResolveFilterCacheReadTxn};
use crate::modify::Modify;
use crate::prelude::*;

use self::profiles::{
    AccessControlCreate, AccessControlCreateResolved, AccessControlDelete,
    AccessControlDeleteResolved, AccessControlModify, AccessControlModifyResolved,
    AccessControlReceiver, AccessControlReceiverCondition, AccessControlSearch,
    AccessControlSearchResolved, AccessControlTarget, AccessControlTargetCondition,
};

use kanidm_proto::scim_v1::server::ScimAttributeEffectiveAccess;

use self::create::{apply_create_access, CreateResult};
use self::delete::{apply_delete_access, DeleteResult};
use self::modify::{apply_modify_access, ModifyResult};
use self::search::{apply_search_access, SearchResult};

const ACP_RESOLVE_FILTER_CACHE_MAX: usize = 256;
const ACP_RESOLVE_FILTER_CACHE_LOCAL: usize = 0;

mod create;
mod delete;
mod modify;
pub mod profiles;
mod protected;
mod search;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Access {
    Grant,
    Denied,
    Allow(BTreeSet<Attribute>),
}

impl From<&Access> for ScimAttributeEffectiveAccess {
    fn from(value: &Access) -> Self {
        match value {
            Access::Grant => Self::Grant,
            Access::Denied => Self::Denied,
            Access::Allow(set) => Self::Allow(set.clone()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccessClass {
    Grant,
    Denied,
    Allow(BTreeSet<AttrString>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessEffectivePermission {
    /// Who the access applies to
    pub ident: Uuid,
    /// The target the access affects
    pub target: Uuid,
    pub delete: bool,
    pub search: Access,
    pub modify_pres: Access,
    pub modify_rem: Access,
    pub modify_pres_class: AccessClass,
    pub modify_rem_class: AccessClass,
}

pub enum AccessBasicResult {
    // Deny this operation unconditionally.
    Denied,
    // Unbounded allow, provided no deny state exists.
    Grant,
    // This module makes no decisions about this entry.
    Ignore,
}

pub enum AccessSrchResult {
    // Deny this operation unconditionally.
    Denied,
    // Unbounded allow, provided no deny state exists.
    Grant,
    // This module makes no decisions about this entry.
    Ignore,
    // Limit the allowed attr set to this - this doesn't
    // allow anything, it constrains what might be allowed
    // by a later module.
    /*
    Constrain {
        attr: BTreeSet<Attribute>,
    },
    */
    Allow { attr: BTreeSet<Attribute> },
}

pub enum AccessModResult<'a> {
    // Deny this operation unconditionally.
    Denied,
    // Unbounded allow, provided no deny state exists.
    // Grant,
    // This module makes no decisions about this entry.
    Ignore,
    // Limit the allowed attr set to this - this doesn't
    // allow anything, it constrains what might be allowed
    // by a later module.
    Constrain {
        pres_attr: BTreeSet<Attribute>,
        rem_attr: BTreeSet<Attribute>,
        pres_cls: Option<BTreeSet<&'a str>>,
        rem_cls: Option<BTreeSet<&'a str>>,
    },
    // Allow these modifications within constraints.
    Allow {
        pres_attr: BTreeSet<Attribute>,
        rem_attr: BTreeSet<Attribute>,
        pres_class: BTreeSet<&'a str>,
        rem_class: BTreeSet<&'a str>,
    },
}

// =========================================================================
// ACP transactions and management for server bits.
// =========================================================================

#[derive(Clone)]
struct AccessControlsInner {
    acps_search: Vec<AccessControlSearch>,
    acps_create: Vec<AccessControlCreate>,
    acps_modify: Vec<AccessControlModify>,
    acps_delete: Vec<AccessControlDelete>,
    sync_agreements: HashMap<Uuid, BTreeSet<Attribute>>,
    // Oauth2
    // Sync prov
}

pub struct AccessControls {
    inner: CowCell<AccessControlsInner>,
    // acp_related_search_cache: ARCache<Uuid, Vec<Uuid>>,
    acp_resolve_filter_cache: ResolveFilterCache,
}

fn resolve_access_conditions(
    ident: &Identity,
    ident_memberof: Option<&BTreeSet<Uuid>>,
    receiver: &AccessControlReceiver,
    target: &AccessControlTarget,
    acp_resolve_filter_cache: &mut ResolveFilterCacheReadTxn<'_>,
) -> Option<(AccessControlReceiverCondition, AccessControlTargetCondition)> {
    let receiver_condition = match receiver {
        AccessControlReceiver::Group(groups) => {
            let group_check = ident_memberof
                // Have at least one group allowed.
                .map(|imo| {
                    trace!(?imo, ?groups);
                    imo.intersection(groups).next().is_some()
                })
                .unwrap_or_default();

            if group_check {
                AccessControlReceiverCondition::GroupChecked
            } else {
                // AccessControlReceiverCondition::None
                return None;
            }
        }
        AccessControlReceiver::EntryManager => AccessControlReceiverCondition::EntryManager,
        AccessControlReceiver::None => return None,
        // AccessControlReceiverCondition::None,
    };

    let target_condition = match &target {
        AccessControlTarget::Scope(filter) => filter
            .resolve(ident, None, Some(acp_resolve_filter_cache))
            .map_err(|e| {
                admin_error!(?e, "A internal filter/event was passed for resolution!?!?");
                e
            })
            .ok()
            .map(AccessControlTargetCondition::Scope)?,
        AccessControlTarget::None => return None,
    };

    Some((receiver_condition, target_condition))
}

pub trait AccessControlsTransaction<'a> {
    fn get_search(&self) -> &Vec<AccessControlSearch>;
    fn get_create(&self) -> &Vec<AccessControlCreate>;
    fn get_modify(&self) -> &Vec<AccessControlModify>;
    fn get_delete(&self) -> &Vec<AccessControlDelete>;
    fn get_sync_agreements(&self) -> &HashMap<Uuid, BTreeSet<Attribute>>;

    #[allow(clippy::mut_from_ref)]
    fn get_acp_resolve_filter_cache(&self) -> &mut ResolveFilterCacheReadTxn<'a>;

    #[instrument(level = "trace", name = "access::search_related_acp", skip_all)]
    fn search_related_acp<'b>(
        &'b self,
        ident: &Identity,
        attrs: Option<&BTreeSet<Attribute>>,
    ) -> Vec<AccessControlSearchResolved<'b>> {
        let search_state = self.get_search();
        let acp_resolve_filter_cache = self.get_acp_resolve_filter_cache();

        // ⚠️  WARNING ⚠️  -- Why is this cache commented out?
        //
        // The reason for this is that to determine what acps relate, we need to be
        // aware of session claims - since these can change session to session, we
        // would need the cache to be structured to handle this. It's much better
        // in a search to just lean on the filter resolve cache because of this
        // dynamic behaviour.
        //
        // It may be possible to do per-operation caching when we know that we will
        // perform the reduce step, but it may not be worth it. It's probably better
        // to make entry_match_no_index faster.

        /*
        if let Some(acs_uuids) = acp_related_search_cache.get(rec_entry.get_uuid()) {
            lperf_trace_segment!( "access::search_related_acp<cached>", || {
                // If we have a cache, we should look here first for all the uuids that match

                // could this be a better algo?
                search_state
                    .iter()
                    .filter(|acs| acs_uuids.binary_search(&acs.acp.uuid).is_ok())
                    .collect()
            })
        } else {
        */
        // else, we calculate this, and then stash/cache the uuids.

        let ident_memberof = ident.get_memberof();

        // let related_acp: Vec<(&AccessControlSearch, Filter<FilterValidResolved>)> =
        let related_acp: Vec<AccessControlSearchResolved<'b>> = search_state
            .iter()
            .filter_map(|acs| {
                // Now resolve the receiver filter
                // Okay, so in filter resolution, the primary error case
                // is that we have a non-user in the event. We have already
                // checked for this above BUT we should still check here
                // properly just in case.
                //
                // In this case, we assume that if the event is internal
                // that the receiver can NOT match because it has no selfuuid
                // and can as a result, never return true. This leads to this
                // acp not being considered in that case ... which should never
                // happen because we already bypassed internal ops above!
                //
                // A possible solution is to change the filter resolve function
                // such that it takes an entry, rather than an event, but that
                // would create issues in search.
                let (receiver_condition, target_condition) = resolve_access_conditions(
                    ident,
                    ident_memberof,
                    &acs.acp.receiver,
                    &acs.acp.target,
                    acp_resolve_filter_cache,
                )?;

                Some(AccessControlSearchResolved {
                    acp: acs,
                    receiver_condition,
                    target_condition,
                })
            })
            .collect();

        // Trim any search rule that doesn't provide attributes related to the request.
        let related_acp = if let Some(r_attrs) = attrs.as_ref() {
            related_acp
                .into_iter()
                .filter(|acs| !acs.acp.attrs.is_disjoint(r_attrs))
                .collect()
        } else {
            // None here means all attrs requested.
            related_acp
        };

        related_acp
    }

    #[instrument(level = "debug", name = "access::filter_entries", skip_all)]
    fn filter_entries(
        &self,
        ident: &Identity,
        filter_orig: &Filter<FilterValid>,
        entries: Vec<Arc<EntrySealedCommitted>>,
    ) -> Result<Vec<Arc<EntrySealedCommitted>>, OperationError> {
        // Prepare some shared resources.

        // Get the set of attributes requested by this se filter. This is what we are
        // going to access check.
        let requested_attrs: BTreeSet<Attribute> = filter_orig.get_attr_set();

        // First get the set of acps that apply to this receiver
        let related_acp = self.search_related_acp(ident, None);

        // For each entry.
        let entries_is_empty = entries.is_empty();
        let allowed_entries: Vec<_> = entries
            .into_iter()
            .filter(|e| {
                match apply_search_access(ident, related_acp.as_slice(), e) {
                    SearchResult::Denied => false,
                    SearchResult::Grant => true,
                    SearchResult::Allow(allowed_attrs) => {
                        // The allow set constrained.
                        let decision = requested_attrs.is_subset(&allowed_attrs);
                        security_debug!(
                            ?decision,
                            allowed = ?allowed_attrs,
                            requested = ?requested_attrs,
                            "search attribute decision",
                        );
                        decision
                    }
                }
            })
            .collect();

        if allowed_entries.is_empty() {
            if !entries_is_empty {
                security_access!("denied ❌ - no entries were released");
            }
        } else {
            debug!("allowed search of {} entries ✅", allowed_entries.len());
        }

        Ok(allowed_entries)
    }

    // Contains all the way to eval acps to entries
    #[inline(always)]
    fn search_filter_entries(
        &self,
        se: &SearchEvent,
        entries: Vec<Arc<EntrySealedCommitted>>,
    ) -> Result<Vec<Arc<EntrySealedCommitted>>, OperationError> {
        self.filter_entries(&se.ident, &se.filter_orig, entries)
    }

    #[instrument(
        level = "debug",
        name = "access::search_filter_entry_attributes",
        skip_all
    )]
    fn search_filter_entry_attributes<'b>(
        &'b self,
        se: &SearchEvent,
        entries: Vec<Arc<EntrySealedCommitted>>,
    ) -> Result<Vec<EntryReducedCommitted>, OperationError> {
        struct DoEffectiveCheck<'b> {
            modify_related_acp: Vec<AccessControlModifyResolved<'b>>,
            delete_related_acp: Vec<AccessControlDeleteResolved<'b>>,
            sync_agmts: &'b HashMap<Uuid, BTreeSet<Attribute>>,
        }

        let ident_uuid = match &se.ident.origin {
            IdentType::Internal => {
                // In production we can't risk leaking data here, so we return
                // empty sets.
                security_critical!("IMPOSSIBLE STATE: Internal search in external interface?! Returning empty for safety.");
                // No need to check ACS
                return Err(OperationError::InvalidState);
            }
            IdentType::Synch(_) => {
                security_critical!("Blocking sync check");
                return Err(OperationError::InvalidState);
            }
            IdentType::User(u) => u.entry.get_uuid(),
        };

        // Build a reference set from the req_attrs. This is what we test against
        // to see if the attribute is something we currently want.

        let do_effective_check = se.effective_access_check.then(|| {
            debug!("effective permission check requested during reduction phase");

            // == modify ==
            let modify_related_acp = self.modify_related_acp(&se.ident);
            // == delete ==
            let delete_related_acp = self.delete_related_acp(&se.ident);

            let sync_agmts = self.get_sync_agreements();

            DoEffectiveCheck {
                modify_related_acp,
                delete_related_acp,
                sync_agmts,
            }
        });

        // Get the relevant acps for this receiver.
        let search_related_acp = self.search_related_acp(&se.ident, se.attrs.as_ref());

        // For each entry.
        let entries_is_empty = entries.is_empty();
        let allowed_entries: Vec<_> = entries
            .into_iter()
            .filter_map(|entry| {
                match apply_search_access(&se.ident, &search_related_acp, &entry) {
                    SearchResult::Denied => {
                        None
                    }
                    SearchResult::Grant => {
                        // No properly written access module should allow
                        // unbounded attribute read!
                        error!("An access module allowed full read, this is a BUG! Denying read to prevent data leaks.");
                        None
                    }
                    SearchResult::Allow(allowed_attrs) => {
                        // The allow set constrained.
                        debug!(
                            requested = ?se.attrs,
                            allowed = ?allowed_attrs,
                            "reduction",
                        );

                        // Reduce requested by allowed.
                        let reduced_attrs = if let Some(requested) = se.attrs.as_ref() {
                            requested & &allowed_attrs
                        } else {
                            allowed_attrs
                        };

                        let effective_permissions = do_effective_check.as_ref().map(|do_check| {
                            self.entry_effective_permission_check(
                                &se.ident,
                                ident_uuid,
                                &entry,
                                &search_related_acp,
                                &do_check.modify_related_acp,
                                &do_check.delete_related_acp,
                                do_check.sync_agmts,
                            )
                        })
                        .map(Box::new);

                        Some(entry.reduce_attributes(&reduced_attrs, effective_permissions))
                    }
                }

                // End filter
            })
            .collect();

        if allowed_entries.is_empty() {
            if !entries_is_empty {
                security_access!("reduced to empty set on all entries ❌");
            }
        } else {
            debug!(
                "attribute set reduced on {} entries ✅",
                allowed_entries.len()
            );
        }

        Ok(allowed_entries)
    }

    #[instrument(level = "trace", name = "access::modify_related_acp", skip_all)]
    fn modify_related_acp<'b>(&'b self, ident: &Identity) -> Vec<AccessControlModifyResolved<'b>> {
        // Some useful references we'll use for the remainder of the operation
        let modify_state = self.get_modify();
        let acp_resolve_filter_cache = self.get_acp_resolve_filter_cache();

        let ident_memberof = ident.get_memberof();

        // Find the acps that relate to the caller, and compile their related
        // target filters.
        let related_acp: Vec<_> = modify_state
            .iter()
            .filter_map(|acs| {
                trace!(acs_name = ?acs.acp.name);
                let (receiver_condition, target_condition) = resolve_access_conditions(
                    ident,
                    ident_memberof,
                    &acs.acp.receiver,
                    &acs.acp.target,
                    acp_resolve_filter_cache,
                )?;

                Some(AccessControlModifyResolved {
                    acp: acs,
                    receiver_condition,
                    target_condition,
                })
            })
            .collect();

        related_acp
    }

    #[instrument(level = "debug", name = "access::modify_allow_operation", skip_all)]
    fn modify_allow_operation(
        &self,
        me: &ModifyEvent,
        entries: &[Arc<EntrySealedCommitted>],
    ) -> Result<bool, OperationError> {
        // Pre-check if the no-no purge class is present
        let disallow = me
            .modlist
            .iter()
            .any(|m| matches!(m, Modify::Purged(a) if a == Attribute::Class.as_ref()));

        if disallow {
            security_access!("Disallowing purge {} in modification", Attribute::Class);
            return Ok(false);
        }

        // Find the acps that relate to the caller, and compile their related
        // target filters.
        let related_acp: Vec<_> = self.modify_related_acp(&me.ident);

        // build two sets of "requested pres" and "requested rem"
        let requested_pres: BTreeSet<Attribute> = me
            .modlist
            .iter()
            .filter_map(|m| match m {
                Modify::Present(a, _) | Modify::Set(a, _) => Some(a.clone()),
                Modify::Removed(..) | Modify::Assert(..) | Modify::Purged(_) => None,
            })
            .collect();

        let requested_rem: BTreeSet<Attribute> = me
            .modlist
            .iter()
            .filter_map(|m| match m {
                Modify::Set(a, _) | Modify::Removed(a, _) | Modify::Purged(a) => Some(a.clone()),
                Modify::Present(..) | Modify::Assert(..) => None,
            })
            .collect();

        // Build the set of classes that we to work on, only in terms of "addition". To remove
        // I think we have no limit, but ... william of the future may find a problem with this
        // policy.
        let mut requested_pres_classes: BTreeSet<&str> = Default::default();
        let mut requested_rem_classes: BTreeSet<&str> = Default::default();

        for modify in me.modlist.iter() {
            match modify {
                Modify::Present(a, v) => {
                    if a == Attribute::Class.as_ref() {
                        // Here we have an option<&str> which could mean there is a risk of
                        // a malicious entity attempting to trick us by masking class mods
                        // in non-iutf8 types. However, the server first won't respect their
                        // existence, and second, we would have failed the mod at schema checking
                        // earlier in the process as these were not correctly type. As a result
                        // we can trust these to be correct here and not to be "None".
                        requested_pres_classes.extend(v.to_str())
                    }
                }
                Modify::Removed(a, v) => {
                    if a == Attribute::Class.as_ref() {
                        requested_rem_classes.extend(v.to_str())
                    }
                }
                Modify::Set(a, v) => {
                    if a == Attribute::Class.as_ref() {
                        // This is a reasonably complex case - we actually have to contemplate
                        // the difference between what exists and what doesn't, but that's per-entry.
                        //
                        // for now, we treat this as both pres and rem, but I think that ultimately
                        // to fix this we need to make all modifies apply in terms of "batch mod"
                        requested_pres_classes.extend(v.as_iutf8_iter().into_iter().flatten());
                        requested_rem_classes.extend(v.as_iutf8_iter().into_iter().flatten());
                    }
                }
                _ => {}
            }
        }

        debug!(?requested_pres, "Requested present attribute set");
        debug!(?requested_rem, "Requested remove attribute set");
        debug!(?requested_pres_classes, "Requested present class set");
        debug!(?requested_rem_classes, "Requested remove class set");

        let sync_agmts = self.get_sync_agreements();

        let r = entries.iter().all(|e| {
            debug!(entry_id = %e.get_display_id());

            match apply_modify_access(&me.ident, related_acp.as_slice(), sync_agmts, e) {
                ModifyResult::Denied => false,
                ModifyResult::Grant => true,
                ModifyResult::Allow {
                    pres,
                    rem,
                    pres_cls,
                    rem_cls,
                } => {
                    let mut decision = true;

                    if !requested_pres.is_subset(&pres) {
                        security_error!("requested_pres is not a subset of allowed");
                        security_error!(
                            "requested_pres: {:?} !⊆ allowed: {:?}",
                            requested_pres,
                            pres
                        );
                        decision = false
                    };

                    if !requested_rem.is_subset(&rem) {
                        security_error!("requested_rem is not a subset of allowed");
                        security_error!("requested_rem: {:?} !⊆ allowed: {:?}", requested_rem, rem);
                        decision = false;
                    };

                    if !requested_pres_classes.is_subset(&pres_cls) {
                        security_error!("requested_pres_classes is not a subset of allowed");
                        security_error!(
                            "requested_pres_classes: {:?} !⊆ allowed: {:?}",
                            requested_pres_classes,
                            pres_cls
                        );
                        decision = false;
                    };

                    if !requested_rem_classes.is_subset(&rem_cls) {
                        security_error!("requested_rem_classes is not a subset of allowed");
                        security_error!(
                            "requested_rem_classes: {:?} !⊆ allowed: {:?}",
                            requested_rem_classes,
                            rem_cls
                        );
                        decision = false;
                    }

                    if decision {
                        debug!("passed pres, rem, classes check.");
                    }

                    // Yield the result
                    decision
                }
            }
        });

        if r {
            debug!("allowed modify of {} entries ✅", entries.len());
        } else {
            security_access!("denied ❌ - modify may not proceed");
        }
        Ok(r)
    }

    #[instrument(
        level = "debug",
        name = "access::batch_modify_allow_operation",
        skip_all
    )]
    fn batch_modify_allow_operation(
        &self,
        me: &BatchModifyEvent,
        entries: &[Arc<EntrySealedCommitted>],
    ) -> Result<bool, OperationError> {
        // Find the acps that relate to the caller, and compile their related
        // target filters.
        let related_acp = self.modify_related_acp(&me.ident);

        let r = entries.iter().all(|e| {
            // Due to how batch mod works, we have to check the modlist *per entry* rather
            // than as a whole.

            let Some(modlist) = me.modset.get(&e.get_uuid()) else {
                security_access!(
                    "modlist not present for {}, failing operation.",
                    e.get_uuid()
                );
                return false;
            };

            let disallow = modlist
                .iter()
                .any(|m| matches!(m, Modify::Purged(a) if a == Attribute::Class.as_ref()));

            if disallow {
                security_access!("Disallowing purge in modification");
                return false;
            }

            // build two sets of "requested pres" and "requested rem"
            let requested_pres: BTreeSet<Attribute> = modlist
                .iter()
                .filter_map(|m| match m {
                    Modify::Present(a, _) => Some(a.clone()),
                    _ => None,
                })
                .collect();

            let requested_rem: BTreeSet<Attribute> = modlist
                .iter()
                .filter_map(|m| match m {
                    Modify::Removed(a, _) => Some(a.clone()),
                    Modify::Purged(a) => Some(a.clone()),
                    _ => None,
                })
                .collect();

            let mut requested_pres_classes: BTreeSet<&str> = Default::default();
            let mut requested_rem_classes: BTreeSet<&str> = Default::default();

            for modify in modlist.iter() {
                match modify {
                    Modify::Present(a, v) => {
                        if a == Attribute::Class.as_ref() {
                            requested_pres_classes.extend(v.to_str())
                        }
                    }
                    Modify::Removed(a, v) => {
                        if a == Attribute::Class.as_ref() {
                            requested_rem_classes.extend(v.to_str())
                        }
                    }
                    Modify::Set(a, v) => {
                        if a == Attribute::Class.as_ref() {
                            // This is a reasonably complex case - we actually have to contemplate
                            // the difference between what exists and what doesn't, but that's per-entry.
                            //
                            // for now, we treat this as both pres and rem, but I think that ultimately
                            // to fix this we need to make all modifies apply in terms of "batch mod"
                            requested_pres_classes.extend(v.as_iutf8_iter().into_iter().flatten());
                            requested_rem_classes.extend(v.as_iutf8_iter().into_iter().flatten());
                        }
                    }
                    _ => {}
                }
            }

            debug!(?requested_pres, "Requested present set");
            debug!(?requested_rem, "Requested remove set");
            debug!(?requested_pres_classes, "Requested present class set");
            debug!(?requested_rem_classes, "Requested remove class set");
            debug!(entry_id = %e.get_display_id());

            let sync_agmts = self.get_sync_agreements();

            match apply_modify_access(&me.ident, related_acp.as_slice(), sync_agmts, e) {
                ModifyResult::Denied => false,
                ModifyResult::Grant => true,
                ModifyResult::Allow {
                    pres,
                    rem,
                    pres_cls,
                    rem_cls,
                } => {
                    let mut decision = true;

                    if !requested_pres.is_subset(&pres) {
                        security_error!("requested_pres is not a subset of allowed");
                        security_error!(
                            "requested_pres: {:?} !⊆ allowed: {:?}",
                            requested_pres,
                            pres
                        );
                        decision = false
                    };

                    if !requested_rem.is_subset(&rem) {
                        security_error!("requested_rem is not a subset of allowed");
                        security_error!("requested_rem: {:?} !⊆ allowed: {:?}", requested_rem, rem);
                        decision = false;
                    };

                    if !requested_pres_classes.is_subset(&pres_cls) {
                        security_error!("requested_pres_classes is not a subset of allowed");
                        security_error!(
                            "requested_classes: {:?} !⊆ allowed: {:?}",
                            requested_pres_classes,
                            pres_cls
                        );
                        decision = false;
                    };

                    if !requested_rem_classes.is_subset(&rem_cls) {
                        security_error!("requested_rem_classes is not a subset of allowed");
                        security_error!(
                            "requested_classes: {:?} !⊆ allowed: {:?}",
                            requested_rem_classes,
                            rem_cls
                        );
                        decision = false;
                    }

                    if decision {
                        debug!("passed pres, rem, classes check.");
                    }

                    // Yield the result
                    decision
                }
            }
        });

        if r {
            debug!("allowed modify of {} entries ✅", entries.len());
        } else {
            security_access!("denied ❌ - modifications may not proceed");
        }
        Ok(r)
    }

    #[instrument(level = "debug", name = "access::create_allow_operation", skip_all)]
    fn create_allow_operation(
        &self,
        ce: &CreateEvent,
        entries: &[Entry<EntryInit, EntryNew>],
    ) -> Result<bool, OperationError> {
        // Some useful references we'll use for the remainder of the operation
        let create_state = self.get_create();
        let acp_resolve_filter_cache = self.get_acp_resolve_filter_cache();

        let ident_memberof = ce.ident.get_memberof();

        // Find the acps that relate to the caller.
        let related_acp: Vec<_> = create_state
            .iter()
            .filter_map(|acs| {
                let (receiver_condition, target_condition) = resolve_access_conditions(
                    &ce.ident,
                    ident_memberof,
                    &acs.acp.receiver,
                    &acs.acp.target,
                    acp_resolve_filter_cache,
                )?;

                Some(AccessControlCreateResolved {
                    acp: acs,
                    receiver_condition,
                    target_condition,
                })
            })
            .collect();

        // For each entry
        let r = entries.iter().all(|e| {
            match apply_create_access(&ce.ident, related_acp.as_slice(), e) {
                CreateResult::Denied => false,
                CreateResult::Grant => true,
            }
        });

        if r {
            debug!("allowed create of {} entries ✅", entries.len());
        } else {
            security_access!("denied ❌ - create may not proceed");
        }

        Ok(r)
    }

    #[instrument(level = "trace", name = "access::delete_related_acp", skip_all)]
    fn delete_related_acp<'b>(&'b self, ident: &Identity) -> Vec<AccessControlDeleteResolved<'b>> {
        // Some useful references we'll use for the remainder of the operation
        let delete_state = self.get_delete();
        let acp_resolve_filter_cache = self.get_acp_resolve_filter_cache();

        let ident_memberof = ident.get_memberof();

        let related_acp: Vec<_> = delete_state
            .iter()
            .filter_map(|acs| {
                let (receiver_condition, target_condition) = resolve_access_conditions(
                    ident,
                    ident_memberof,
                    &acs.acp.receiver,
                    &acs.acp.target,
                    acp_resolve_filter_cache,
                )?;

                Some(AccessControlDeleteResolved {
                    acp: acs,
                    receiver_condition,
                    target_condition,
                })
            })
            .collect();

        related_acp
    }

    #[instrument(level = "debug", name = "access::delete_allow_operation", skip_all)]
    fn delete_allow_operation(
        &self,
        de: &DeleteEvent,
        entries: &[Arc<EntrySealedCommitted>],
    ) -> Result<bool, OperationError> {
        // Find the acps that relate to the caller.
        let related_acp = self.delete_related_acp(&de.ident);

        // For each entry
        let r = entries.iter().all(|e| {
            match apply_delete_access(&de.ident, related_acp.as_slice(), e) {
                DeleteResult::Denied => false,
                DeleteResult::Grant => true,
            }
        });
        if r {
            debug!("allowed delete of {} entries ✅", entries.len());
        } else {
            security_access!("denied ❌ - delete may not proceed");
        }
        Ok(r)
    }

    #[instrument(level = "debug", name = "access::effective_permission_check", skip_all)]
    fn effective_permission_check(
        &self,
        ident: &Identity,
        attrs: Option<BTreeSet<Attribute>>,
        entries: &[Arc<EntrySealedCommitted>],
    ) -> Result<Vec<AccessEffectivePermission>, OperationError> {
        // I think we need a structure like " CheckResult, which is in the order of the
        // entries, but also stashes the uuid. Then it has search, mod, create, delete,
        // as separate attrs to describe what is capable.

        // Does create make sense here? I don't think it does. Create requires you to
        // have an entry template. I think james was right about the create being
        // a template copy op ...

        let ident_uuid = match &ident.origin {
            IdentType::Internal => {
                // In production we can't risk leaking data here, so we return
                // empty sets.
                security_critical!("IMPOSSIBLE STATE: Internal search in external interface?! Returning empty for safety.");
                // No need to check ACS
                return Err(OperationError::InvalidState);
            }
            IdentType::Synch(_) => {
                security_critical!("Blocking sync check");
                return Err(OperationError::InvalidState);
            }
            IdentType::User(u) => u.entry.get_uuid(),
        };

        trace!(ident = %ident, "Effective permission check");
        // I think we separate this to multiple checks ...?

        // == search ==
        // Get the relevant acps for this receiver.
        let search_related_acp = self.search_related_acp(ident, attrs.as_ref());
        // == modify ==
        let modify_related_acp = self.modify_related_acp(ident);
        // == delete ==
        let delete_related_acp = self.delete_related_acp(ident);

        let sync_agmts = self.get_sync_agreements();

        let effective_permissions: Vec<_> = entries
            .iter()
            .map(|entry| {
                self.entry_effective_permission_check(
                    ident,
                    ident_uuid,
                    entry,
                    &search_related_acp,
                    &modify_related_acp,
                    &delete_related_acp,
                    sync_agmts,
                )
            })
            .collect();

        effective_permissions.iter().for_each(|ep| {
            trace!(?ep);
        });

        Ok(effective_permissions)
    }

    fn entry_effective_permission_check<'b>(
        &'b self,
        ident: &Identity,
        ident_uuid: Uuid,
        entry: &Arc<EntrySealedCommitted>,
        search_related_acp: &[AccessControlSearchResolved<'b>],
        modify_related_acp: &[AccessControlModifyResolved<'b>],
        delete_related_acp: &[AccessControlDeleteResolved<'b>],
        sync_agmts: &HashMap<Uuid, BTreeSet<Attribute>>,
    ) -> AccessEffectivePermission {
        // == search ==
        let search_effective = match apply_search_access(ident, search_related_acp, entry) {
            SearchResult::Denied => Access::Denied,
            SearchResult::Grant => Access::Grant,
            SearchResult::Allow(allowed_attrs) => {
                // Bound by requested attrs?
                Access::Allow(allowed_attrs.into_iter().collect())
            }
        };

        // == modify ==
        let (modify_pres, modify_rem, modify_pres_class, modify_rem_class) =
            match apply_modify_access(ident, modify_related_acp, sync_agmts, entry) {
                ModifyResult::Denied => (
                    Access::Denied,
                    Access::Denied,
                    AccessClass::Denied,
                    AccessClass::Denied,
                ),
                ModifyResult::Grant => (
                    Access::Grant,
                    Access::Grant,
                    AccessClass::Grant,
                    AccessClass::Grant,
                ),
                ModifyResult::Allow {
                    pres,
                    rem,
                    pres_cls,
                    rem_cls,
                } => (
                    Access::Allow(pres.into_iter().collect()),
                    Access::Allow(rem.into_iter().collect()),
                    AccessClass::Allow(pres_cls.into_iter().map(|s| s.into()).collect()),
                    AccessClass::Allow(rem_cls.into_iter().map(|s| s.into()).collect()),
                ),
            };

        // == delete ==
        let delete_status = apply_delete_access(ident, delete_related_acp, entry);

        let delete = match delete_status {
            DeleteResult::Denied => false,
            DeleteResult::Grant => true,
        };

        AccessEffectivePermission {
            ident: ident_uuid,
            target: entry.get_uuid(),
            delete,
            search: search_effective,
            modify_pres,
            modify_rem,
            modify_pres_class,
            modify_rem_class,
        }
    }
}

pub struct AccessControlsWriteTransaction<'a> {
    inner: CowCellWriteTxn<'a, AccessControlsInner>,
    acp_resolve_filter_cache: Cell<ResolveFilterCacheReadTxn<'a>>,
}

impl AccessControlsWriteTransaction<'_> {
    // We have a method to update each set, so that if an error
    // occurs we KNOW it's an error, rather than using errors as
    // part of the logic (IE try-parse-fail method).
    pub fn update_search(
        &mut self,
        mut acps: Vec<AccessControlSearch>,
    ) -> Result<(), OperationError> {
        std::mem::swap(&mut acps, &mut self.inner.deref_mut().acps_search);
        Ok(())
    }

    pub fn update_create(
        &mut self,
        mut acps: Vec<AccessControlCreate>,
    ) -> Result<(), OperationError> {
        std::mem::swap(&mut acps, &mut self.inner.deref_mut().acps_create);
        Ok(())
    }

    pub fn update_modify(
        &mut self,
        mut acps: Vec<AccessControlModify>,
    ) -> Result<(), OperationError> {
        std::mem::swap(&mut acps, &mut self.inner.deref_mut().acps_modify);
        Ok(())
    }

    pub fn update_delete(
        &mut self,
        mut acps: Vec<AccessControlDelete>,
    ) -> Result<(), OperationError> {
        std::mem::swap(&mut acps, &mut self.inner.deref_mut().acps_delete);
        Ok(())
    }

    pub fn update_sync_agreements(
        &mut self,
        mut sync_agreements: HashMap<Uuid, BTreeSet<Attribute>>,
    ) {
        std::mem::swap(
            &mut sync_agreements,
            &mut self.inner.deref_mut().sync_agreements,
        );
    }

    pub fn commit(self) -> Result<(), OperationError> {
        self.inner.commit();

        Ok(())
    }
}

impl<'a> AccessControlsTransaction<'a> for AccessControlsWriteTransaction<'a> {
    fn get_search(&self) -> &Vec<AccessControlSearch> {
        &self.inner.acps_search
    }

    fn get_create(&self) -> &Vec<AccessControlCreate> {
        &self.inner.acps_create
    }

    fn get_modify(&self) -> &Vec<AccessControlModify> {
        &self.inner.acps_modify
    }

    fn get_delete(&self) -> &Vec<AccessControlDelete> {
        &self.inner.acps_delete
    }

    fn get_sync_agreements(&self) -> &HashMap<Uuid, BTreeSet<Attribute>> {
        &self.inner.sync_agreements
    }

    fn get_acp_resolve_filter_cache(&self) -> &mut ResolveFilterCacheReadTxn<'a> {
        unsafe {
            let mptr = self.acp_resolve_filter_cache.as_ptr();
            &mut (*mptr) as &mut ResolveFilterCacheReadTxn<'a>
        }
    }
}

// =========================================================================
// ACP operations (Should this actually be on the ACP's themself?
// =========================================================================

pub struct AccessControlsReadTransaction<'a> {
    inner: CowCellReadTxn<AccessControlsInner>,
    // acp_related_search_cache: Cell<ARCacheReadTxn<'a, Uuid, Vec<Uuid>>>,
    acp_resolve_filter_cache: Cell<ResolveFilterCacheReadTxn<'a>>,
}

unsafe impl Sync for AccessControlsReadTransaction<'_> {}

unsafe impl Send for AccessControlsReadTransaction<'_> {}

impl<'a> AccessControlsTransaction<'a> for AccessControlsReadTransaction<'a> {
    fn get_search(&self) -> &Vec<AccessControlSearch> {
        &self.inner.acps_search
    }

    fn get_create(&self) -> &Vec<AccessControlCreate> {
        &self.inner.acps_create
    }

    fn get_modify(&self) -> &Vec<AccessControlModify> {
        &self.inner.acps_modify
    }

    fn get_delete(&self) -> &Vec<AccessControlDelete> {
        &self.inner.acps_delete
    }

    fn get_sync_agreements(&self) -> &HashMap<Uuid, BTreeSet<Attribute>> {
        &self.inner.sync_agreements
    }

    fn get_acp_resolve_filter_cache(&self) -> &mut ResolveFilterCacheReadTxn<'a> {
        unsafe {
            let mptr = self.acp_resolve_filter_cache.as_ptr();
            &mut (*mptr) as &mut ResolveFilterCacheReadTxn<'a>
        }
    }
}

// =========================================================================
// ACP transaction operations
// =========================================================================

impl Default for AccessControls {
    #![allow(clippy::expect_used)]
    fn default() -> Self {
        AccessControls {
            inner: CowCell::new(AccessControlsInner {
                acps_search: Vec::with_capacity(0),
                acps_create: Vec::with_capacity(0),
                acps_modify: Vec::with_capacity(0),
                acps_delete: Vec::with_capacity(0),
                sync_agreements: HashMap::default(),
            }),
            // Allow the expect, if this fails it represents a programming/development
            // failure.
            acp_resolve_filter_cache: ARCacheBuilder::new()
                .set_size(ACP_RESOLVE_FILTER_CACHE_MAX, ACP_RESOLVE_FILTER_CACHE_LOCAL)
                .set_reader_quiesce(true)
                .build()
                .expect("Failed to construct acp_resolve_filter_cache"),
        }
    }
}

impl AccessControls {
    pub fn try_quiesce(&self) {
        self.acp_resolve_filter_cache.try_quiesce();
    }

    pub fn read(&self) -> AccessControlsReadTransaction {
        AccessControlsReadTransaction {
            inner: self.inner.read(),
            // acp_related_search_cache: Cell::new(self.acp_related_search_cache.read()),
            acp_resolve_filter_cache: Cell::new(self.acp_resolve_filter_cache.read()),
        }
    }

    pub fn write(&self) -> AccessControlsWriteTransaction {
        AccessControlsWriteTransaction {
            inner: self.inner.write(),
            // acp_related_search_cache_wr: self.acp_related_search_cache.write(),
            // acp_related_search_cache: Cell::new(self.acp_related_search_cache.read()),
            acp_resolve_filter_cache: Cell::new(self.acp_resolve_filter_cache.read()),
        }
    }
}

#[cfg(test)]
mod tests {
    use hashbrown::HashMap;
    use std::collections::BTreeSet;
    use std::sync::Arc;

    use uuid::uuid;

    use super::{
        profiles::{
            AccessControlCreate, AccessControlDelete, AccessControlModify, AccessControlProfile,
            AccessControlSearch, AccessControlTarget,
        },
        Access, AccessClass, AccessControls, AccessControlsTransaction, AccessEffectivePermission,
    };
    use crate::migration_data::BUILTIN_ACCOUNT_ANONYMOUS;
    use crate::prelude::*;
    use crate::valueset::ValueSetIname;

    const UUID_TEST_ACCOUNT_1: Uuid = uuid::uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930");
    const UUID_TEST_ACCOUNT_2: Uuid = uuid::uuid!("cec0852a-abdf-4ea6-9dae-d3157cb33d3a");
    const UUID_TEST_GROUP_1: Uuid = uuid::uuid!("81ec1640-3637-4a2f-8a52-874fa3c3c92f");
    const UUID_TEST_GROUP_2: Uuid = uuid::uuid!("acae81d6-5ea7-4bd8-8f7f-fcec4c0dd647");

    lazy_static! {
        pub static ref E_TEST_ACCOUNT_1: Arc<EntrySealedCommitted> = Arc::new(
            entry_init!(
                (Attribute::Class, EntryClass::Object.to_value()),
                (Attribute::Name, Value::new_iname("test_account_1")),
                (Attribute::Uuid, Value::Uuid(UUID_TEST_ACCOUNT_1)),
                (Attribute::MemberOf, Value::Refer(UUID_TEST_GROUP_1))
            )
            .into_sealed_committed()
        );
        pub static ref E_TEST_ACCOUNT_2: Arc<EntrySealedCommitted> = Arc::new(
            entry_init!(
                (Attribute::Class, EntryClass::Object.to_value()),
                (Attribute::Name, Value::new_iname("test_account_1")),
                (Attribute::Uuid, Value::Uuid(UUID_TEST_ACCOUNT_2)),
                (Attribute::MemberOf, Value::Refer(UUID_TEST_GROUP_2))
            )
            .into_sealed_committed()
        );
    }

    macro_rules! acp_from_entry_err {
        (
            $qs:expr,
            $e:expr,
            $type:ty
        ) => {{
            let ev1 = $e.into_sealed_committed();

            let r1 = <$type>::try_from($qs, &ev1);
            error!(?r1);
            assert!(r1.is_err());
        }};
    }

    macro_rules! acp_from_entry_ok {
        (
            $qs:expr,
            $e:expr,
            $type:ty
        ) => {{
            let ev1 = $e.into_sealed_committed();

            let r1 = <$type>::try_from($qs, &ev1);
            assert!(r1.is_ok());
            r1.unwrap()
        }};
    }

    #[qs_test]
    async fn test_access_acp_parser(qs: &QueryServer) {
        // Test parsing entries to acp. There so no point testing schema violations
        // because the schema system is well tested an robust. Instead we target
        // entry misconfigurations, such as missing classes required.

        // Generally, we are testing the *positive* cases here, because schema
        // really protects us *a lot* here, but it's nice to have defence and
        // layers of validation.

        let mut qs_write = qs.write(duration_from_epoch_now()).await.unwrap();

        acp_from_entry_err!(
            &mut qs_write,
            entry_init!(
                (Attribute::Class, EntryClass::Object.to_value()),
                (Attribute::Name, Value::new_iname("acp_invalid")),
                (
                    Attribute::Uuid,
                    Value::Uuid(uuid::uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"))
                )
            ),
            AccessControlProfile
        );

        acp_from_entry_err!(
            &mut qs_write,
            entry_init!(
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
                (Attribute::Name, Value::new_iname("acp_invalid")),
                (
                    Attribute::Uuid,
                    Value::Uuid(uuid::uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"))
                )
            ),
            AccessControlProfile
        );

        acp_from_entry_err!(
            &mut qs_write,
            entry_init!(
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
                (Attribute::Name, Value::new_iname("acp_invalid")),
                (
                    Attribute::Uuid,
                    Value::Uuid(uuid::uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"))
                ),
                (Attribute::AcpReceiverGroup, Value::Bool(true)),
                (Attribute::AcpTargetScope, Value::Bool(true))
            ),
            AccessControlProfile
        );

        // "\"Self\""
        acp_from_entry_ok!(
            &mut qs_write,
            entry_init!(
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
                (Attribute::Name, Value::new_iname("acp_valid")),
                (
                    Attribute::Uuid,
                    Value::Uuid(uuid::uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"))
                ),
                (
                    Attribute::AcpReceiverGroup,
                    Value::Refer(uuid::uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"))
                ),
                (
                    Attribute::AcpTargetScope,
                    Value::new_json_filter_s("{\"eq\":[\"name\",\"a\"]}").expect("filter")
                )
            ),
            AccessControlProfile
        );
    }

    #[qs_test]
    async fn test_access_acp_delete_parser(qs: &QueryServer) {
        let mut qs_write = qs.write(duration_from_epoch_now()).await.unwrap();

        acp_from_entry_err!(
            &mut qs_write,
            entry_init!(
                (Attribute::Class, EntryClass::Object.to_value()),
                (
                    Attribute::Class,
                    EntryClass::AccessControlProfile.to_value()
                ),
                (Attribute::Name, Value::new_iname("acp_valid")),
                (
                    Attribute::Uuid,
                    Value::Uuid(uuid::uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"))
                ),
                (
                    Attribute::AcpReceiverGroup,
                    Value::Refer(uuid::uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"))
                ),
                (
                    Attribute::AcpTargetScope,
                    Value::new_json_filter_s("{\"eq\":[\"name\",\"a\"]}").expect("filter")
                )
            ),
            AccessControlDelete
        );

        acp_from_entry_ok!(
            &mut qs_write,
            entry_init!(
                (Attribute::Class, EntryClass::Object.to_value()),
                (
                    Attribute::Class,
                    EntryClass::AccessControlProfile.to_value()
                ),
                (Attribute::Class, EntryClass::AccessControlDelete.to_value()),
                (Attribute::Name, Value::new_iname("acp_valid")),
                (
                    Attribute::Uuid,
                    Value::Uuid(uuid::uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"))
                ),
                (
                    Attribute::AcpReceiverGroup,
                    Value::Refer(uuid::uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"))
                ),
                (
                    Attribute::AcpTargetScope,
                    Value::new_json_filter_s("{\"eq\":[\"name\",\"a\"]}").expect("filter")
                )
            ),
            AccessControlDelete
        );
    }

    #[qs_test]
    async fn test_access_acp_search_parser(qs: &QueryServer) {
        // Test that parsing search access controls works.
        let mut qs_write = qs.write(duration_from_epoch_now()).await.unwrap();

        // Missing class acp
        acp_from_entry_err!(
            &mut qs_write,
            entry_init!(
                (Attribute::Class, EntryClass::Object.to_value()),
                (Attribute::Class, EntryClass::AccessControlSearch.to_value()),
                (Attribute::Name, Value::new_iname("acp_valid")),
                (
                    Attribute::Uuid,
                    Value::Uuid(uuid::uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"))
                ),
                (
                    Attribute::AcpReceiverGroup,
                    Value::Refer(uuid::uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"))
                ),
                (
                    Attribute::AcpTargetScope,
                    Value::new_json_filter_s("{\"eq\":[\"name\",\"a\"]}").expect("filter")
                ),
                (Attribute::AcpSearchAttr, Value::from(Attribute::Name)),
                (Attribute::AcpSearchAttr, Value::new_iutf8("class"))
            ),
            AccessControlSearch
        );

        // Missing class acs
        acp_from_entry_err!(
            &mut qs_write,
            entry_init!(
                (Attribute::Class, EntryClass::Object.to_value()),
                (
                    Attribute::Class,
                    EntryClass::AccessControlProfile.to_value()
                ),
                (Attribute::Name, Value::new_iname("acp_valid")),
                (
                    Attribute::Uuid,
                    Value::Uuid(uuid::uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"))
                ),
                (
                    Attribute::AcpReceiverGroup,
                    Value::Refer(uuid::uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"))
                ),
                (
                    Attribute::AcpTargetScope,
                    Value::new_json_filter_s("{\"eq\":[\"name\",\"a\"]}").expect("filter")
                ),
                (Attribute::AcpSearchAttr, Value::from(Attribute::Name)),
                (Attribute::AcpSearchAttr, Value::new_iutf8("class"))
            ),
            AccessControlSearch
        );

        // Missing attr acp_search_attr
        acp_from_entry_err!(
            &mut qs_write,
            entry_init!(
                (Attribute::Class, EntryClass::Object.to_value()),
                (
                    Attribute::Class,
                    EntryClass::AccessControlProfile.to_value()
                ),
                (Attribute::Class, EntryClass::AccessControlSearch.to_value()),
                (Attribute::Name, Value::new_iname("acp_valid")),
                (
                    Attribute::Uuid,
                    Value::Uuid(uuid::uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"))
                ),
                (
                    Attribute::AcpReceiverGroup,
                    Value::Refer(uuid::uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"))
                ),
                (
                    Attribute::AcpTargetScope,
                    Value::new_json_filter_s("{\"eq\":[\"name\",\"a\"]}").expect("filter")
                )
            ),
            AccessControlSearch
        );

        // All good!
        acp_from_entry_ok!(
            &mut qs_write,
            entry_init!(
                (Attribute::Class, EntryClass::Object.to_value()),
                (
                    Attribute::Class,
                    EntryClass::AccessControlProfile.to_value()
                ),
                (Attribute::Class, EntryClass::AccessControlSearch.to_value()),
                (Attribute::Name, Value::new_iname("acp_valid")),
                (
                    Attribute::Uuid,
                    Value::Uuid(uuid::uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"))
                ),
                (
                    Attribute::AcpReceiverGroup,
                    Value::Refer(uuid::uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"))
                ),
                (
                    Attribute::AcpTargetScope,
                    Value::new_json_filter_s("{\"eq\":[\"name\",\"a\"]}").expect("filter")
                ),
                (Attribute::AcpSearchAttr, Value::from(Attribute::Name)),
                (Attribute::AcpSearchAttr, Value::new_iutf8("class"))
            ),
            AccessControlSearch
        );
    }

    #[qs_test]
    async fn test_access_acp_modify_parser(qs: &QueryServer) {
        // Test that parsing modify access controls works.
        let mut qs_write = qs.write(duration_from_epoch_now()).await.unwrap();

        acp_from_entry_err!(
            &mut qs_write,
            entry_init!(
                (Attribute::Class, EntryClass::Object.to_value()),
                (
                    Attribute::Class,
                    EntryClass::AccessControlProfile.to_value()
                ),
                (Attribute::Name, Value::new_iname("acp_invalid")),
                (
                    Attribute::Uuid,
                    Value::Uuid(uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"))
                ),
                (
                    Attribute::AcpReceiverGroup,
                    Value::Refer(uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"))
                ),
                (
                    Attribute::AcpTargetScope,
                    Value::new_json_filter_s("{\"eq\":[\"name\",\"a\"]}").expect("filter")
                )
            ),
            AccessControlModify
        );

        acp_from_entry_ok!(
            &mut qs_write,
            entry_init!(
                (Attribute::Class, EntryClass::Object.to_value()),
                (
                    Attribute::Class,
                    EntryClass::AccessControlProfile.to_value()
                ),
                (Attribute::Class, EntryClass::AccessControlModify.to_value()),
                (Attribute::Name, Value::new_iname("acp_valid")),
                (
                    Attribute::Uuid,
                    Value::Uuid(uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"))
                ),
                (
                    Attribute::AcpReceiverGroup,
                    Value::Refer(uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"))
                ),
                (
                    Attribute::AcpTargetScope,
                    Value::new_json_filter_s("{\"eq\":[\"name\",\"a\"]}").expect("filter")
                )
            ),
            AccessControlModify
        );

        acp_from_entry_ok!(
            &mut qs_write,
            entry_init!(
                (Attribute::Class, EntryClass::Object.to_value()),
                (
                    Attribute::Class,
                    EntryClass::AccessControlProfile.to_value()
                ),
                (Attribute::Class, EntryClass::AccessControlModify.to_value()),
                (Attribute::Name, Value::new_iname("acp_valid")),
                (
                    Attribute::Uuid,
                    Value::Uuid(uuid::uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"))
                ),
                (
                    Attribute::AcpReceiverGroup,
                    Value::Refer(uuid::uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"))
                ),
                (
                    Attribute::AcpTargetScope,
                    Value::new_json_filter_s("{\"eq\":[\"name\",\"a\"]}").expect("filter")
                ),
                (
                    Attribute::AcpModifyRemovedAttr,
                    Value::from(Attribute::Name)
                ),
                (
                    Attribute::AcpModifyPresentAttr,
                    Value::from(Attribute::Name)
                ),
                (Attribute::AcpModifyClass, EntryClass::Object.to_value())
            ),
            AccessControlModify
        );
    }

    #[qs_test]
    async fn test_access_acp_create_parser(qs: &QueryServer) {
        // Test that parsing create access controls works.
        let mut qs_write = qs.write(duration_from_epoch_now()).await.unwrap();

        acp_from_entry_err!(
            &mut qs_write,
            entry_init!(
                (Attribute::Class, EntryClass::Object.to_value()),
                (
                    Attribute::Class,
                    EntryClass::AccessControlProfile.to_value()
                ),
                (Attribute::Name, Value::new_iname("acp_invalid")),
                (
                    Attribute::Uuid,
                    Value::Uuid(uuid::uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"))
                ),
                (
                    Attribute::AcpReceiverGroup,
                    Value::Refer(uuid::uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"))
                ),
                (
                    Attribute::AcpTargetScope,
                    Value::new_json_filter_s("{\"eq\":[\"name\",\"a\"]}").expect("filter")
                ),
                (Attribute::AcpCreateAttr, Value::from(Attribute::Name)),
                (Attribute::AcpCreateClass, EntryClass::Object.to_value())
            ),
            AccessControlCreate
        );

        acp_from_entry_ok!(
            &mut qs_write,
            entry_init!(
                (Attribute::Class, EntryClass::Object.to_value()),
                (
                    Attribute::Class,
                    EntryClass::AccessControlProfile.to_value()
                ),
                (Attribute::Class, EntryClass::AccessControlCreate.to_value()),
                (Attribute::Name, Value::new_iname("acp_valid")),
                (
                    Attribute::Uuid,
                    Value::Uuid(uuid::uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"))
                ),
                (
                    Attribute::AcpReceiverGroup,
                    Value::Refer(uuid::uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"))
                ),
                (
                    Attribute::AcpTargetScope,
                    Value::new_json_filter_s("{\"eq\":[\"name\",\"a\"]}").expect("filter")
                )
            ),
            AccessControlCreate
        );

        acp_from_entry_ok!(
            &mut qs_write,
            entry_init!(
                (Attribute::Class, EntryClass::Object.to_value()),
                (
                    Attribute::Class,
                    EntryClass::AccessControlProfile.to_value()
                ),
                (Attribute::Class, EntryClass::AccessControlCreate.to_value()),
                (Attribute::Name, Value::new_iname("acp_valid")),
                (
                    Attribute::Uuid,
                    Value::Uuid(uuid::uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"))
                ),
                (
                    Attribute::AcpReceiverGroup,
                    Value::Refer(uuid::uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"))
                ),
                (
                    Attribute::AcpTargetScope,
                    Value::new_json_filter_s("{\"eq\":[\"name\",\"a\"]}").expect("filter")
                ),
                (Attribute::AcpCreateAttr, Value::from(Attribute::Name)),
                (Attribute::AcpCreateClass, EntryClass::Object.to_value())
            ),
            AccessControlCreate
        );
    }

    #[qs_test]
    async fn test_access_acp_compound_parser(qs: &QueryServer) {
        // Test that parsing compound access controls works. This means that
        // given a single &str, we can evaluate all types from a single record.
        // This is valid, and could exist, IE a rule to allow create, search and modify
        // over a single scope.
        let mut qs_write = qs.write(duration_from_epoch_now()).await.unwrap();

        let e = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (
                Attribute::Class,
                EntryClass::AccessControlProfile.to_value()
            ),
            (Attribute::Class, EntryClass::AccessControlCreate.to_value()),
            (Attribute::Class, EntryClass::AccessControlDelete.to_value()),
            (Attribute::Class, EntryClass::AccessControlModify.to_value()),
            (Attribute::Class, EntryClass::AccessControlSearch.to_value()),
            (Attribute::Name, Value::new_iname("acp_valid")),
            (
                Attribute::Uuid,
                Value::Uuid(uuid::uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"))
            ),
            (
                Attribute::AcpReceiverGroup,
                Value::Refer(uuid::uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"))
            ),
            (
                Attribute::AcpTargetScope,
                Value::new_json_filter_s("{\"eq\":[\"name\",\"a\"]}").expect("filter")
            ),
            (Attribute::AcpSearchAttr, Value::from(Attribute::Name)),
            (Attribute::AcpCreateClass, EntryClass::Class.to_value()),
            (Attribute::AcpCreateAttr, Value::from(Attribute::Name)),
            (
                Attribute::AcpModifyRemovedAttr,
                Value::from(Attribute::Name)
            ),
            (
                Attribute::AcpModifyPresentAttr,
                Value::from(Attribute::Name)
            ),
            (Attribute::AcpModifyClass, EntryClass::Object.to_value())
        );

        acp_from_entry_ok!(&mut qs_write, e.clone(), AccessControlCreate);
        acp_from_entry_ok!(&mut qs_write, e.clone(), AccessControlDelete);
        acp_from_entry_ok!(&mut qs_write, e.clone(), AccessControlModify);
        acp_from_entry_ok!(&mut qs_write, e, AccessControlSearch);
    }

    macro_rules! test_acp_search {
        (
            $se:expr,
            $controls:expr,
            $entries:expr,
            $expect:expr
        ) => {{
            let ac = AccessControls::default();
            let mut acw = ac.write();
            acw.update_search($controls).expect("Failed to update");
            let acw = acw;

            let res = acw
                .search_filter_entries(&mut $se, $entries)
                .expect("op failed");
            debug!("result --> {:?}", res);
            debug!("expect --> {:?}", $expect);
            // should be ok, and same as expect.
            assert_eq!(res, $expect);
        }};
    }

    macro_rules! test_acp_search_reduce {
        (
            $se:expr,
            $controls:expr,
            $entries:expr,
            $expect:expr
        ) => {{
            let ac = AccessControls::default();
            let mut acw = ac.write();
            acw.update_search($controls).expect("Failed to update");
            let acw = acw;

            // We still have to reduce the entries to be sure that we are good.
            let res = acw
                .search_filter_entries(&mut $se, $entries)
                .expect("operation failed");
            // Now on the reduced entries, reduce the entries attrs.
            let reduced = acw
                .search_filter_entry_attributes(&mut $se, res)
                .expect("operation failed");

            // Help the type checker for the expect set.
            let expect_set: Vec<Entry<EntryReduced, EntryCommitted>> =
                $expect.into_iter().map(|e| e.into_reduced()).collect();

            debug!("expect --> {:?}", expect_set);
            debug!("result --> {:?}", reduced);
            // should be ok, and same as expect.
            assert_eq!(reduced, expect_set);
        }};
    }

    #[test]
    fn test_access_internal_search() {
        // Test that an internal search bypasses ACS
        let se = SearchEvent::new_internal_invalid(filter!(f_pres(Attribute::Class)));

        let expect = vec![E_TEST_ACCOUNT_1.clone()];
        let entries = vec![E_TEST_ACCOUNT_1.clone()];

        // This acp basically is "allow access to stuff, but not this".
        test_acp_search!(
            &se,
            vec![AccessControlSearch::from_raw(
                "test_acp",
                Uuid::new_v4(),
                UUID_TEST_GROUP_1,
                filter_valid!(f_pres(Attribute::NonExist)), // apply to none - ie no allowed results
                Attribute::Name.as_ref(), // allow to this attr, but we don't eval this.
            )],
            entries,
            expect
        );
    }

    #[test]
    fn test_access_enforce_search() {
        // Test that entries from a search are reduced by acps
        let ev1 = E_TESTPERSON_1.clone().into_sealed_committed();
        let ev2 = E_TESTPERSON_2.clone().into_sealed_committed();

        let r_set = vec![Arc::new(ev1.clone()), Arc::new(ev2)];

        let se_a = SearchEvent::new_impersonate_entry(
            E_TEST_ACCOUNT_1.clone(),
            filter_all!(f_pres(Attribute::Name)),
        );
        let ex_a = vec![Arc::new(ev1)];

        let se_b = SearchEvent::new_impersonate_entry(
            E_TEST_ACCOUNT_2.clone(),
            filter_all!(f_pres(Attribute::Name)),
        );
        let ex_b = vec![];

        let acp = AccessControlSearch::from_raw(
            "test_acp",
            Uuid::new_v4(),
            // apply to admin only
            UUID_TEST_GROUP_1,
            // Allow admin to read only testperson1
            filter_valid!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson1")
            )),
            // In that read, admin may only view the "name" attribute, or query on
            // the name attribute. Any other query (should be) rejected.
            Attribute::Name.as_ref(),
        );

        // Check the admin search event
        test_acp_search!(&se_a, vec![acp.clone()], r_set.clone(), ex_a);

        // Check the anonymous
        test_acp_search!(&se_b, vec![acp], r_set, ex_b);
    }

    #[test]
    fn test_access_enforce_scope_search() {
        sketching::test_init();
        // Test that identities are bound by their access scope.
        let ev1 = E_TESTPERSON_1.clone().into_sealed_committed();

        let ex_some = vec![Arc::new(ev1.clone())];

        let r_set = vec![Arc::new(ev1)];

        let se_ro = SearchEvent::new_impersonate_identity(
            Identity::from_impersonate_entry_readonly(E_TEST_ACCOUNT_1.clone()),
            filter_all!(f_pres(Attribute::Name)),
        );

        let se_rw = SearchEvent::new_impersonate_identity(
            Identity::from_impersonate_entry_readwrite(E_TEST_ACCOUNT_1.clone()),
            filter_all!(f_pres(Attribute::Name)),
        );

        let acp = AccessControlSearch::from_raw(
            "test_acp",
            Uuid::new_v4(),
            // apply to admin only
            UUID_TEST_GROUP_1,
            // Allow admin to read only testperson1
            filter_valid!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson1")
            )),
            // In that read, admin may only view the "name" attribute, or query on
            // the name attribute. Any other query (should be) rejected.
            Attribute::Name.as_ref(),
        );

        // Check the admin search event
        test_acp_search!(&se_ro, vec![acp.clone()], r_set.clone(), ex_some);

        test_acp_search!(&se_rw, vec![acp], r_set, ex_some);
    }

    #[test]
    fn test_access_enforce_scope_search_attrs() {
        // Test that in ident only mode that all attrs are always denied. The op should already have
        // "nothing to do" based on search_filter_entries, but we do the "right thing" anyway.

        let ev1 = E_TESTPERSON_1.clone().into_sealed_committed();
        let r_set = vec![Arc::new(ev1)];

        let exv1 = E_TESTPERSON_1_REDUCED.clone().into_sealed_committed();

        let ex_anon_some = vec![exv1];

        let se_anon_ro = SearchEvent::new_impersonate_identity(
            Identity::from_impersonate_entry_readonly(E_TEST_ACCOUNT_1.clone()),
            filter_all!(f_pres(Attribute::Name)),
        );

        let acp = AccessControlSearch::from_raw(
            "test_acp",
            Uuid::new_v4(),
            // apply to all accounts.
            UUID_TEST_GROUP_1,
            // Allow anonymous to read only testperson1
            filter_valid!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson1")
            )),
            // In that read, admin may only view the "name" attribute, or query on
            // the name attribute. Any other query (should be) rejected.
            Attribute::Name.as_ref(),
        );

        // Finally test it!
        test_acp_search_reduce!(&se_anon_ro, vec![acp], r_set, ex_anon_some);
    }

    lazy_static! {
        pub static ref E_TESTPERSON_1_REDUCED: EntryInitNew =
            entry_init!((Attribute::Name, Value::new_iname("testperson1")));
    }

    #[test]
    fn test_access_enforce_search_attrs() {
        // Test that attributes are correctly limited.
        // In this case, we test that a user can only see "name" despite the
        // class and uuid being present.
        let ev1 = E_TESTPERSON_1.clone().into_sealed_committed();
        let r_set = vec![Arc::new(ev1)];

        let exv1 = E_TESTPERSON_1_REDUCED.clone().into_sealed_committed();
        let ex_anon = vec![exv1];

        let se_anon = SearchEvent::new_impersonate_entry(
            E_TEST_ACCOUNT_1.clone(),
            filter_all!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson1")
            )),
        );

        let acp = AccessControlSearch::from_raw(
            "test_acp",
            Uuid::new_v4(),
            // apply to anonymous only
            UUID_TEST_GROUP_1,
            // Allow anonymous to read only testperson1
            filter_valid!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson1")
            )),
            // In that read, admin may only view the "name" attribute, or query on
            // the name attribute. Any other query (should be) rejected.
            Attribute::Name.as_ref(),
        );

        // Finally test it!
        test_acp_search_reduce!(&se_anon, vec![acp], r_set, ex_anon);
    }

    #[test]
    fn test_access_enforce_search_attrs_req() {
        // Test that attributes are correctly limited by the request.
        // In this case, we test that a user can only see "name" despite the
        // class and uuid being present.
        let ev1 = E_TESTPERSON_1.clone().into_sealed_committed();

        let r_set = vec![Arc::new(ev1)];

        let exv1 = E_TESTPERSON_1_REDUCED.clone().into_sealed_committed();
        let ex_anon = vec![exv1];

        let mut se_anon = SearchEvent::new_impersonate_entry(
            E_TEST_ACCOUNT_1.clone(),
            filter_all!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson1")
            )),
        );
        // the requested attrs here.
        se_anon.attrs = Some(btreeset![Attribute::Name]);

        let acp = AccessControlSearch::from_raw(
            "test_acp",
            Uuid::new_v4(),
            // apply to anonymous only
            UUID_TEST_GROUP_1,
            // Allow anonymous to read only testperson1
            filter_valid!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson1")
            )),
            // In that read, admin may only view the "name" attribute, or query on
            // the name attribute. Any other query (should be) rejected.
            "name uuid",
        );

        // Finally test it!
        test_acp_search_reduce!(&se_anon, vec![acp], r_set, ex_anon);
    }

    macro_rules! test_acp_modify {
        (
            $me:expr,
            $controls:expr,
            $entries:expr,
            $expect:expr
        ) => {{
            let ac = AccessControls::default();
            let mut acw = ac.write();
            acw.update_modify($controls).expect("Failed to update");
            let acw = acw;

            let res = acw
                .modify_allow_operation(&mut $me, $entries)
                .expect("op failed");

            debug!("result --> {:?}", res);
            debug!("expect --> {:?}", $expect);
            // should be ok, and same as expect.
            assert_eq!($expect, res);
        }};
        (
            $me:expr,
            $controls:expr,
            $sync_uuid:expr,
            $sync_yield_attr:expr,
            $entries:expr,
            $expect:expr
        ) => {{
            let ac = AccessControls::default();
            let mut acw = ac.write();
            acw.update_modify($controls).expect("Failed to update");
            let mut sync_agmt = HashMap::new();
            let mut set = BTreeSet::new();
            set.insert($sync_yield_attr);
            sync_agmt.insert($sync_uuid, set);
            acw.update_sync_agreements(sync_agmt);
            let acw = acw;

            let res = acw
                .modify_allow_operation(&mut $me, $entries)
                .expect("op failed");

            debug!("result --> {:?}", res);
            debug!("expect --> {:?}", $expect);
            // should be ok, and same as expect.
            assert_eq!($expect, res);
        }};
    }

    #[test]
    fn test_access_enforce_modify() {
        sketching::test_init();

        let ev1 = E_TESTPERSON_1.clone().into_sealed_committed();
        let r_set = vec![Arc::new(ev1)];

        // Name present
        let me_pres = ModifyEvent::new_impersonate_entry(
            E_TEST_ACCOUNT_1.clone(),
            filter_all!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson1")
            )),
            modlist!([m_pres(Attribute::Name, &Value::new_iname("value"))]),
        );
        // Name rem
        let me_rem = ModifyEvent::new_impersonate_entry(
            E_TEST_ACCOUNT_1.clone(),
            filter_all!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson1")
            )),
            modlist!([m_remove(Attribute::Name, &PartialValue::new_iname("value"))]),
        );
        // Name purge
        let me_purge = ModifyEvent::new_impersonate_entry(
            E_TEST_ACCOUNT_1.clone(),
            filter_all!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson1")
            )),
            modlist!([m_purge(Attribute::Name)]),
        );

        // Name Set
        let me_set = ModifyEvent::new_impersonate_entry(
            E_TEST_ACCOUNT_1.clone(),
            filter_all!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson1")
            )),
            modlist!([Modify::Set(Attribute::Name, ValueSetIname::new("value"))]),
        );

        // Class account pres
        let me_pres_class = ModifyEvent::new_impersonate_entry(
            E_TEST_ACCOUNT_1.clone(),
            filter_all!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson1")
            )),
            modlist!([m_pres(Attribute::Class, &EntryClass::Account.to_value())]),
        );
        // Class account rem
        let me_rem_class = ModifyEvent::new_impersonate_entry(
            E_TEST_ACCOUNT_1.clone(),
            filter_all!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson1")
            )),
            modlist!([m_remove(
                Attribute::Class,
                &EntryClass::Account.to_partialvalue()
            )]),
        );
        // Class purge
        let me_purge_class = ModifyEvent::new_impersonate_entry(
            E_TEST_ACCOUNT_1.clone(),
            filter_all!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson1")
            )),
            modlist!([m_purge(Attribute::Class)]),
        );

        // Set Class
        let me_set_class = ModifyEvent::new_impersonate_entry(
            E_TEST_ACCOUNT_1.clone(),
            filter_all!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson1")
            )),
            modlist!([Modify::Set(
                Attribute::Class,
                EntryClass::Account.to_valueset()
            )]),
        );

        // Allow name and class, class is account
        let acp_allow = AccessControlModify::from_raw(
            "test_modify_allow",
            Uuid::new_v4(),
            // Apply to admin
            UUID_TEST_GROUP_1,
            // To modify testperson
            filter_valid!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson1")
            )),
            // Allow pres name and class
            "name class",
            // Allow rem name and class
            "name class",
            // And the class allowed is account
            EntryClass::Account.into(),
            // And the class allowed is account
            EntryClass::Account.into(),
        );
        // Allow member, class is group. IE not account
        let acp_deny = AccessControlModify::from_raw(
            "test_modify_deny",
            Uuid::new_v4(),
            // Apply to admin
            UUID_TEST_GROUP_1,
            // To modify testperson
            filter_valid!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson1")
            )),
            // Allow pres name and class
            "member class",
            // Allow rem name and class
            "member class",
            "group",
            "group",
        );
        // Does not have a pres or rem class in attrs
        let acp_no_class = AccessControlModify::from_raw(
            "test_modify_no_class",
            Uuid::new_v4(),
            // Apply to admin
            UUID_TEST_GROUP_1,
            // To modify testperson
            filter_valid!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson1")
            )),
            // Allow pres name and class
            "name class",
            // Allow rem name and class
            "name class",
            // And the class allowed is NOT an account ...
            "group",
            "group",
        );

        // Test allowed pres
        test_acp_modify!(&me_pres, vec![acp_allow.clone()], &r_set, true);
        // test allowed rem
        test_acp_modify!(&me_rem, vec![acp_allow.clone()], &r_set, true);
        // test allowed purge
        test_acp_modify!(&me_purge, vec![acp_allow.clone()], &r_set, true);
        // test allowed set
        test_acp_modify!(&me_set, vec![acp_allow.clone()], &r_set, true);

        // Test rejected pres
        test_acp_modify!(&me_pres, vec![acp_deny.clone()], &r_set, false);
        // Test rejected rem
        test_acp_modify!(&me_rem, vec![acp_deny.clone()], &r_set, false);
        // Test rejected purge
        test_acp_modify!(&me_purge, vec![acp_deny.clone()], &r_set, false);
        // Test rejected set
        test_acp_modify!(&me_set, vec![acp_deny.clone()], &r_set, false);

        // test allowed pres class
        test_acp_modify!(&me_pres_class, vec![acp_allow.clone()], &r_set, true);
        // test allowed rem class
        test_acp_modify!(&me_rem_class, vec![acp_allow.clone()], &r_set, true);
        // test reject purge-class even if class present in allowed remattrs
        test_acp_modify!(&me_purge_class, vec![acp_allow.clone()], &r_set, false);
        // test allowed set class
        test_acp_modify!(&me_set_class, vec![acp_allow], &r_set, true);

        // Test reject pres class, but class not in classes
        test_acp_modify!(&me_pres_class, vec![acp_no_class.clone()], &r_set, false);
        // Test reject pres class, class in classes but not in pres attrs
        test_acp_modify!(&me_pres_class, vec![acp_deny.clone()], &r_set, false);
        // test reject rem class, but class not in classes
        test_acp_modify!(&me_rem_class, vec![acp_no_class.clone()], &r_set, false);
        // test reject rem class, class in classes but not in pres attrs
        test_acp_modify!(&me_rem_class, vec![acp_deny.clone()], &r_set, false);

        // Test reject set class, but class not in classes
        test_acp_modify!(&me_set_class, vec![acp_no_class], &r_set, false);
        // Test reject set class, class in classes but not in pres attrs
        test_acp_modify!(&me_set_class, vec![acp_deny], &r_set, false);
    }

    #[test]
    fn test_access_enforce_scope_modify() {
        let ev1 = E_TESTPERSON_1.clone().into_sealed_committed();
        let r_set = vec![Arc::new(ev1)];

        // Name present
        let me_pres_ro = ModifyEvent::new_impersonate_identity(
            Identity::from_impersonate_entry_readonly(E_TEST_ACCOUNT_1.clone()),
            filter_all!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson1")
            )),
            modlist!([m_pres(Attribute::Name, &Value::new_iname("value"))]),
        );

        // Name present
        let me_pres_rw = ModifyEvent::new_impersonate_identity(
            Identity::from_impersonate_entry_readwrite(E_TEST_ACCOUNT_1.clone()),
            filter_all!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson1")
            )),
            modlist!([m_pres(Attribute::Name, &Value::new_iname("value"))]),
        );

        let acp_allow = AccessControlModify::from_raw(
            "test_modify_allow",
            Uuid::new_v4(),
            // apply to admin only
            UUID_TEST_GROUP_1,
            // To modify testperson
            filter_valid!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson1")
            )),
            // Allow pres name and class
            "name class",
            // Allow rem name and class
            "name class",
            // And the class allowed is account
            EntryClass::Account.into(),
            EntryClass::Account.into(),
        );

        test_acp_modify!(&me_pres_ro, vec![acp_allow.clone()], &r_set, false);

        test_acp_modify!(&me_pres_rw, vec![acp_allow], &r_set, true);
    }

    macro_rules! test_acp_create {
        (
            $ce:expr,
            $controls:expr,
            $entries:expr,
            $expect:expr
        ) => {{
            let ac = AccessControls::default();
            let mut acw = ac.write();
            acw.update_create($controls).expect("Failed to update");
            let acw = acw;

            let res = acw
                .create_allow_operation(&mut $ce, $entries)
                .expect("op failed");

            debug!("result --> {:?}", res);
            debug!("expect --> {:?}", $expect);
            // should be ok, and same as expect.
            assert_eq!(res, $expect);
        }};
    }

    #[test]
    fn test_access_enforce_create() {
        let ev1 = entry_init!(
            (Attribute::Class, EntryClass::Account.to_value()),
            (Attribute::Name, Value::new_iname("testperson1")),
            (Attribute::Uuid, Value::Uuid(UUID_TEST_ACCOUNT_1))
        );
        let r1_set = vec![ev1];

        let ev2 = entry_init!(
            (Attribute::Class, EntryClass::Account.to_value()),
            (Attribute::TestNotAllowed, Value::new_class("notallowed")),
            (Attribute::Name, Value::new_iname("testperson1")),
            (Attribute::Uuid, Value::Uuid(UUID_TEST_ACCOUNT_1))
        );

        let r2_set = vec![ev2];

        let ev3 = entry_init!(
            (Attribute::Class, EntryClass::Account.to_value()),
            (Attribute::Class, Value::new_class("notallowed")),
            (Attribute::Name, Value::new_iname("testperson1")),
            (Attribute::Uuid, Value::Uuid(UUID_TEST_ACCOUNT_1))
        );
        let r3_set = vec![ev3];

        let ev4 = entry_init!(
            (Attribute::Class, EntryClass::Account.to_value()),
            (Attribute::Class, EntryClass::Group.to_value()),
            (Attribute::Name, Value::new_iname("testperson1")),
            (Attribute::Uuid, Value::Uuid(UUID_TEST_ACCOUNT_1))
        );
        let r4_set = vec![ev4];

        // In this case, we can make the create event with an empty entry
        // set because we only reference the entries in r_set in the test.
        //
        // In the server code, the entry set is derived from and checked
        // against the create event, so we have some level of trust in it.

        let ce_admin = CreateEvent::new_impersonate_identity(
            Identity::from_impersonate_entry_readwrite(E_TEST_ACCOUNT_1.clone()),
            vec![],
        );

        let acp = AccessControlCreate::from_raw(
            "test_create",
            Uuid::new_v4(),
            // Apply to admin
            UUID_TEST_GROUP_1,
            // To create matching filter testperson
            // Can this be empty?
            filter_valid!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson1")
            )),
            // classes
            EntryClass::Account.into(),
            // attrs
            "class name uuid",
        );

        let acp2 = AccessControlCreate::from_raw(
            "test_create_2",
            Uuid::new_v4(),
            // Apply to admin
            UUID_TEST_GROUP_1,
            // To create matching filter testperson
            filter_valid!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson1")
            )),
            // classes
            EntryClass::Group.into(),
            // attrs
            "class name uuid",
        );

        // Test allowed to create
        test_acp_create!(&ce_admin, vec![acp.clone()], &r1_set, true);
        // Test reject create (not allowed attr)
        test_acp_create!(&ce_admin, vec![acp.clone()], &r2_set, false);
        // Test reject create (not allowed class)
        test_acp_create!(&ce_admin, vec![acp.clone()], &r3_set, false);
        // Test reject create (hybrid u + g entry w_ u & g create allow)
        test_acp_create!(&ce_admin, vec![acp, acp2], &r4_set, false);
    }

    #[test]
    fn test_access_enforce_scope_create() {
        let ev1 = entry_init!(
            (Attribute::Class, EntryClass::Account.to_value()),
            (Attribute::Name, Value::new_iname("testperson1")),
            (Attribute::Uuid, Value::Uuid(UUID_TEST_ACCOUNT_1))
        );
        let r1_set = vec![ev1];

        let admin = E_TEST_ACCOUNT_1.clone();

        let ce_admin_ro = CreateEvent::new_impersonate_identity(
            Identity::from_impersonate_entry_readonly(admin.clone()),
            vec![],
        );

        let ce_admin_rw = CreateEvent::new_impersonate_identity(
            Identity::from_impersonate_entry_readwrite(admin),
            vec![],
        );

        let acp = AccessControlCreate::from_raw(
            "test_create",
            Uuid::new_v4(),
            // Apply to admin
            UUID_TEST_GROUP_1,
            // To create matching filter testperson
            // Can this be empty?
            filter_valid!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson1")
            )),
            // classes
            EntryClass::Account.into(),
            // attrs
            "class name uuid",
        );

        test_acp_create!(&ce_admin_ro, vec![acp.clone()], &r1_set, false);

        test_acp_create!(&ce_admin_rw, vec![acp], &r1_set, true);
    }

    macro_rules! test_acp_delete {
        (
            $de:expr,
            $controls:expr,
            $entries:expr,
            $expect:expr
        ) => {{
            let ac = AccessControls::default();
            let mut acw = ac.write();
            acw.update_delete($controls).expect("Failed to update");
            let acw = acw;

            let res = acw
                .delete_allow_operation($de, $entries)
                .expect("op failed");

            debug!("result --> {:?}", res);
            debug!("expect --> {:?}", $expect);
            // should be ok, and same as expect.
            assert_eq!(res, $expect);
        }};
    }

    #[test]
    fn test_access_enforce_delete() {
        let ev1 = E_TESTPERSON_1.clone().into_sealed_committed();
        let r_set = vec![Arc::new(ev1)];

        let de_admin = DeleteEvent::new_impersonate_entry(
            E_TEST_ACCOUNT_1.clone(),
            filter_all!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson1")
            )),
        );

        let de_anon = DeleteEvent::new_impersonate_entry(
            E_TEST_ACCOUNT_2.clone(),
            filter_all!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson1")
            )),
        );

        let acp = AccessControlDelete::from_raw(
            "test_delete",
            Uuid::new_v4(),
            // Apply to admin
            UUID_TEST_GROUP_1,
            // To delete testperson
            filter_valid!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson1")
            )),
        );

        // Test allowed to delete
        test_acp_delete!(&de_admin, vec![acp.clone()], &r_set, true);
        // Test reject delete
        test_acp_delete!(&de_anon, vec![acp], &r_set, false);
    }

    #[test]
    fn test_access_enforce_scope_delete() {
        sketching::test_init();
        let ev1 = E_TESTPERSON_1.clone().into_sealed_committed();
        let r_set = vec![Arc::new(ev1)];

        let admin = E_TEST_ACCOUNT_1.clone();

        let de_admin_ro = DeleteEvent::new_impersonate_identity(
            Identity::from_impersonate_entry_readonly(admin.clone()),
            filter_all!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson1")
            )),
        );

        let de_admin_rw = DeleteEvent::new_impersonate_identity(
            Identity::from_impersonate_entry_readwrite(admin),
            filter_all!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson1")
            )),
        );

        let acp = AccessControlDelete::from_raw(
            "test_delete",
            Uuid::new_v4(),
            // Apply to admin
            UUID_TEST_GROUP_1,
            // To delete testperson
            filter_valid!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson1")
            )),
        );

        test_acp_delete!(&de_admin_ro, vec![acp.clone()], &r_set, false);

        test_acp_delete!(&de_admin_rw, vec![acp], &r_set, true);
    }

    macro_rules! test_acp_effective_permissions {
        (
            $ident:expr,
            $attrs:expr,
            $search_controls:expr,
            $modify_controls:expr,
            $entries:expr,
            $expect:expr
        ) => {{
            let ac = AccessControls::default();
            let mut acw = ac.write();
            acw.update_search($search_controls)
                .expect("Failed to update");
            acw.update_modify($modify_controls)
                .expect("Failed to update");
            let acw = acw;

            let res = acw
                .effective_permission_check($ident, $attrs, $entries)
                .expect("Failed to apply effective_permission_check");

            debug!("result --> {:?}", res);
            debug!("expect --> {:?}", $expect);
            // should be ok, and same as expect.
            assert_eq!(res, $expect);
        }};
    }

    #[test]
    fn test_access_effective_permission_check_1() {
        sketching::test_init();

        let admin = Identity::from_impersonate_entry_readwrite(E_TEST_ACCOUNT_1.clone());

        let ev1 = E_TESTPERSON_1.clone().into_sealed_committed();

        let r_set = vec![Arc::new(ev1)];

        test_acp_effective_permissions!(
            &admin,
            None,
            vec![AccessControlSearch::from_raw(
                "test_acp",
                Uuid::new_v4(),
                // apply to admin only
                UUID_TEST_GROUP_1,
                // Allow admin to read only testperson1
                filter_valid!(f_eq(
                    Attribute::Name,
                    PartialValue::new_iname("testperson1")
                )),
                // They can read "name".
                Attribute::Name.as_ref(),
            )],
            vec![],
            &r_set,
            vec![AccessEffectivePermission {
                ident: UUID_TEST_ACCOUNT_1,
                delete: false,
                target: uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"),
                search: Access::Allow(btreeset![Attribute::Name]),
                modify_pres: Access::Allow(BTreeSet::new()),
                modify_rem: Access::Allow(BTreeSet::new()),
                modify_pres_class: AccessClass::Allow(BTreeSet::new()),
                modify_rem_class: AccessClass::Allow(BTreeSet::new()),
            }]
        )
    }

    #[test]
    fn test_access_effective_permission_check_2() {
        sketching::test_init();

        let admin = Identity::from_impersonate_entry_readwrite(E_TEST_ACCOUNT_1.clone());

        let ev1 = E_TESTPERSON_1.clone().into_sealed_committed();

        let r_set = vec![Arc::new(ev1)];

        test_acp_effective_permissions!(
            &admin,
            None,
            vec![],
            vec![AccessControlModify::from_raw(
                "test_acp",
                Uuid::new_v4(),
                // apply to admin only
                UUID_TEST_GROUP_1,
                // Allow admin to read only testperson1
                filter_valid!(f_eq(
                    Attribute::Name,
                    PartialValue::new_iname("testperson1")
                )),
                // They can read "name".
                Attribute::Name.as_ref(),
                Attribute::Name.as_ref(),
                EntryClass::Object.into(),
                EntryClass::Object.into(),
            )],
            &r_set,
            vec![AccessEffectivePermission {
                ident: UUID_TEST_ACCOUNT_1,
                delete: false,
                target: uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"),
                search: Access::Allow(BTreeSet::new()),
                modify_pres: Access::Allow(btreeset![Attribute::Name]),
                modify_rem: Access::Allow(btreeset![Attribute::Name]),
                modify_pres_class: AccessClass::Allow(btreeset![EntryClass::Object.into()]),
                modify_rem_class: AccessClass::Allow(btreeset![EntryClass::Object.into()]),
            }]
        )
    }

    #[test]
    fn test_access_sync_authority_create() {
        sketching::test_init();

        let ce_admin = CreateEvent::new_impersonate_identity(
            Identity::from_impersonate_entry_readwrite(E_TEST_ACCOUNT_1.clone()),
            vec![],
        );

        // We can create without a sync class.
        let ev1 = entry_init!(
            (Attribute::Class, EntryClass::Account.to_value()),
            (Attribute::Name, Value::new_iname("testperson1")),
            (Attribute::Uuid, Value::Uuid(UUID_TEST_ACCOUNT_1))
        );
        let r1_set = vec![ev1];

        let ev2 = entry_init!(
            (Attribute::Class, EntryClass::Account.to_value()),
            (Attribute::Class, EntryClass::SyncObject.to_value()),
            (Attribute::Name, Value::new_iname("testperson1")),
            (Attribute::Uuid, Value::Uuid(UUID_TEST_ACCOUNT_1))
        );
        let r2_set = vec![ev2];

        let acp = AccessControlCreate::from_raw(
            "test_create",
            Uuid::new_v4(),
            // Apply to admin
            UUID_TEST_GROUP_1,
            // To create matching filter testperson
            // Can this be empty?
            filter_valid!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson1")
            )),
            // classes
            "account sync_object",
            // attrs
            "class name uuid",
        );

        // Test allowed to create
        test_acp_create!(&ce_admin, vec![acp.clone()], &r1_set, true);
        // Test Fails due to protected from sync object
        test_acp_create!(&ce_admin, vec![acp], &r2_set, false);
    }

    #[test]
    fn test_access_sync_authority_delete() {
        sketching::test_init();

        let ev1 = entry_init!(
            (Attribute::Class, EntryClass::Account.to_value()),
            (Attribute::Name, Value::new_iname("testperson1")),
            (Attribute::Uuid, Value::Uuid(UUID_TEST_ACCOUNT_1))
        )
        .into_sealed_committed();
        let r1_set = vec![Arc::new(ev1)];

        let ev2 = entry_init!(
            (Attribute::Class, EntryClass::Account.to_value()),
            (Attribute::Class, EntryClass::SyncObject.to_value()),
            (Attribute::Name, Value::new_iname("testperson1")),
            (Attribute::Uuid, Value::Uuid(UUID_TEST_ACCOUNT_1))
        )
        .into_sealed_committed();
        let r2_set = vec![Arc::new(ev2)];

        let de_admin = DeleteEvent::new_impersonate_entry(
            E_TEST_ACCOUNT_1.clone(),
            filter_all!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson1")
            )),
        );

        let acp = AccessControlDelete::from_raw(
            "test_delete",
            Uuid::new_v4(),
            // Apply to admin
            UUID_TEST_GROUP_1,
            // To delete testperson
            filter_valid!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson1")
            )),
        );

        // Test allowed to delete
        test_acp_delete!(&de_admin, vec![acp.clone()], &r1_set, true);
        // Test reject delete
        test_acp_delete!(&de_admin, vec![acp], &r2_set, false);
    }

    #[test]
    fn test_access_sync_authority_modify() {
        sketching::test_init();

        let ev1 = entry_init!(
            (Attribute::Class, EntryClass::Account.to_value()),
            (Attribute::Name, Value::new_iname("testperson1")),
            (Attribute::Uuid, Value::Uuid(UUID_TEST_ACCOUNT_1))
        )
        .into_sealed_committed();
        let r1_set = vec![Arc::new(ev1)];

        let sync_uuid = Uuid::new_v4();
        let ev2 = entry_init!(
            (Attribute::Class, EntryClass::Account.to_value()),
            (Attribute::Class, EntryClass::SyncObject.to_value()),
            (Attribute::SyncParentUuid, Value::Refer(sync_uuid)),
            (Attribute::Name, Value::new_iname("testperson1")),
            (Attribute::Uuid, Value::Uuid(UUID_TEST_ACCOUNT_1))
        )
        .into_sealed_committed();
        let r2_set = vec![Arc::new(ev2)];

        // Allow name and class, class is account
        let acp_allow = AccessControlModify::from_raw(
            "test_modify_allow",
            Uuid::new_v4(),
            // Apply to admin
            UUID_TEST_GROUP_1,
            // To modify testperson
            filter_valid!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson1")
            )),
            // Allow pres user_auth_token_session
            &format!("{} {}", Attribute::UserAuthTokenSession, Attribute::Name),
            // Allow user_auth_token_session
            &format!("{} {}", Attribute::UserAuthTokenSession, Attribute::Name),
            // And the class allowed is account, we don't use it though.
            EntryClass::Account.into(),
            EntryClass::Account.into(),
        );

        // NOTE! Syntax doesn't matter here, we just need to assert if the attr exists
        // and is being modified.
        // Name present
        let me_pres = ModifyEvent::new_impersonate_entry(
            E_TEST_ACCOUNT_1.clone(),
            filter_all!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson1")
            )),
            modlist!([m_pres(
                Attribute::UserAuthTokenSession,
                &Value::new_iname("value")
            )]),
        );
        // Name rem
        let me_rem = ModifyEvent::new_impersonate_entry(
            E_TEST_ACCOUNT_1.clone(),
            filter_all!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson1")
            )),
            modlist!([m_remove(
                Attribute::UserAuthTokenSession,
                &PartialValue::new_iname("value")
            )]),
        );
        // Name purge
        let me_purge = ModifyEvent::new_impersonate_entry(
            E_TEST_ACCOUNT_1.clone(),
            filter_all!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson1")
            )),
            modlist!([m_purge(Attribute::UserAuthTokenSession)]),
        );

        // Test allowed pres
        test_acp_modify!(&me_pres, vec![acp_allow.clone()], &r1_set, true);
        // test allowed rem
        test_acp_modify!(&me_rem, vec![acp_allow.clone()], &r1_set, true);
        // test allowed purge
        test_acp_modify!(&me_purge, vec![acp_allow.clone()], &r1_set, true);

        // Test allow pres
        test_acp_modify!(&me_pres, vec![acp_allow.clone()], &r2_set, true);
        // Test allow rem
        test_acp_modify!(&me_rem, vec![acp_allow.clone()], &r2_set, true);
        // Test allow purge
        test_acp_modify!(&me_purge, vec![acp_allow.clone()], &r2_set, true);

        // But other attrs are blocked.
        let me_pres = ModifyEvent::new_impersonate_entry(
            E_TEST_ACCOUNT_1.clone(),
            filter_all!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson1")
            )),
            modlist!([m_pres(Attribute::Name, &Value::new_iname("value"))]),
        );
        // Name rem
        let me_rem = ModifyEvent::new_impersonate_entry(
            E_TEST_ACCOUNT_1.clone(),
            filter_all!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson1")
            )),
            modlist!([m_remove(Attribute::Name, &PartialValue::new_iname("value"))]),
        );
        // Name purge
        let me_purge = ModifyEvent::new_impersonate_entry(
            E_TEST_ACCOUNT_1.clone(),
            filter_all!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson1")
            )),
            modlist!([m_purge(Attribute::Name)]),
        );

        // Test reject pres
        test_acp_modify!(&me_pres, vec![acp_allow.clone()], &r2_set, false);
        // Test reject rem
        test_acp_modify!(&me_rem, vec![acp_allow.clone()], &r2_set, false);
        // Test reject purge
        test_acp_modify!(&me_purge, vec![acp_allow.clone()], &r2_set, false);

        // Test that when an attribute is in the sync_yield state that it can be
        // modified by a user.

        // Test allow pres
        test_acp_modify!(
            &me_pres,
            vec![acp_allow.clone()],
            sync_uuid,
            Attribute::Name,
            &r2_set,
            true
        );
        // Test allow rem
        test_acp_modify!(
            &me_rem,
            vec![acp_allow.clone()],
            sync_uuid,
            Attribute::Name,
            &r2_set,
            true
        );
        // Test allow purge
        test_acp_modify!(
            &me_purge,
            vec![acp_allow],
            sync_uuid,
            Attribute::Name,
            &r2_set,
            true
        );
    }

    #[test]
    fn test_access_oauth2_dyn_search() {
        sketching::test_init();
        // Test that an account that is granted a scope to an oauth2 rs is granted
        // the ability to search that rs.
        let rs_uuid = Uuid::new_v4();
        let ev1 = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (
                Attribute::Class,
                EntryClass::OAuth2ResourceServer.to_value()
            ),
            (
                Attribute::Class,
                EntryClass::OAuth2ResourceServerBasic.to_value()
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
            (
                Attribute::OAuth2RsOrigin,
                Value::new_url_s("app://hidden").unwrap()
            ),
            (
                Attribute::OAuth2RsScopeMap,
                Value::new_oauthscopemap(UUID_TEST_GROUP_1, btreeset!["groups".to_string()])
                    .expect("invalid oauthscope")
            ),
            (
                Attribute::OAuth2RsSupScopeMap,
                Value::new_oauthscopemap(UUID_TEST_GROUP_1, btreeset!["supplement".to_string()])
                    .expect("invalid oauthscope")
            ),
            (
                Attribute::OAuth2AllowInsecureClientDisablePkce,
                Value::new_bool(true)
            ),
            (
                Attribute::OAuth2JwtLegacyCryptoEnable,
                Value::new_bool(false)
            ),
            (Attribute::OAuth2PreferShortUsername, Value::new_bool(false))
        )
        .into_sealed_committed();

        let ev1_reduced = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (
                Attribute::Class,
                EntryClass::OAuth2ResourceServer.to_value()
            ),
            (
                Attribute::Class,
                EntryClass::OAuth2ResourceServerBasic.to_value()
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
            )
        )
        .into_sealed_committed();

        let ev2 = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (
                Attribute::Class,
                EntryClass::OAuth2ResourceServer.to_value()
            ),
            (
                Attribute::Class,
                EntryClass::OAuth2ResourceServerBasic.to_value()
            ),
            (Attribute::Uuid, Value::Uuid(Uuid::new_v4())),
            (Attribute::Name, Value::new_iname("second_resource_server")),
            (
                Attribute::DisplayName,
                Value::new_utf8s("second_resource_server")
            ),
            (
                Attribute::OAuth2RsOriginLanding,
                Value::new_url_s("https://noaccess.example.com").unwrap()
            ),
            (
                Attribute::OAuth2RsOrigin,
                Value::new_url_s("app://hidden").unwrap()
            ),
            (
                Attribute::OAuth2RsScopeMap,
                Value::new_oauthscopemap(UUID_SYSTEM_ADMINS, btreeset!["groups".to_string()])
                    .expect("invalid oauthscope")
            ),
            (
                Attribute::OAuth2RsSupScopeMap,
                Value::new_oauthscopemap(
                    // This is NOT the scope map that is access checked!
                    UUID_TEST_GROUP_1,
                    btreeset!["supplement".to_string()]
                )
                .expect("invalid oauthscope")
            ),
            (
                Attribute::OAuth2AllowInsecureClientDisablePkce,
                Value::new_bool(true)
            ),
            (
                Attribute::OAuth2JwtLegacyCryptoEnable,
                Value::new_bool(false)
            ),
            (Attribute::OAuth2PreferShortUsername, Value::new_bool(false))
        )
        .into_sealed_committed();

        let r_set = vec![Arc::new(ev1.clone()), Arc::new(ev2)];

        // Check the authorisation search event, and that it reduces correctly.
        let se_a = SearchEvent::new_impersonate_entry(
            E_TEST_ACCOUNT_1.clone(),
            filter_all!(f_pres(Attribute::Name)),
        );
        let ex_a = vec![Arc::new(ev1)];
        let ex_a_reduced = vec![ev1_reduced];

        test_acp_search!(&se_a, vec![], r_set.clone(), ex_a);
        test_acp_search_reduce!(&se_a, vec![], r_set.clone(), ex_a_reduced);

        // Check that anonymous is denied even though it's a member of the group.
        let anon: EntryInitNew = BUILTIN_ACCOUNT_ANONYMOUS.clone().into();
        let mut anon = anon.into_invalid_new();
        anon.set_ava_set(&Attribute::MemberOf, ValueSetRefer::new(UUID_TEST_GROUP_1));

        let anon = Arc::new(anon.into_sealed_committed());

        let se_anon =
            SearchEvent::new_impersonate_entry(anon, filter_all!(f_pres(Attribute::Name)));
        let ex_anon = vec![];
        test_acp_search!(&se_anon, vec![], r_set.clone(), ex_anon);

        // Check the deny case.
        let se_b = SearchEvent::new_impersonate_entry(
            E_TEST_ACCOUNT_2.clone(),
            filter_all!(f_pres(Attribute::Name)),
        );
        let ex_b = vec![];

        test_acp_search!(&se_b, vec![], r_set, ex_b);
    }

    #[test]
    fn test_access_sync_account_dyn_search() {
        sketching::test_init();
        // Test that an account that has been synchronised from external
        // sources is able to read the sync providers credential portal
        // url.

        let sync_uuid = Uuid::new_v4();
        let portal_url = Url::parse("https://localhost/portal").unwrap();

        let ev1 = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::SyncAccount.to_value()),
            (Attribute::Uuid, Value::Uuid(sync_uuid)),
            (Attribute::Name, Value::new_iname("test_sync_account")),
            (
                Attribute::SyncCredentialPortal,
                Value::Url(portal_url.clone())
            )
        )
        .into_sealed_committed();

        let ev1_reduced = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::SyncAccount.to_value()),
            (Attribute::Uuid, Value::Uuid(sync_uuid)),
            (
                Attribute::SyncCredentialPortal,
                Value::Url(portal_url.clone())
            )
        )
        .into_sealed_committed();

        let ev2 = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::SyncAccount.to_value()),
            (Attribute::Uuid, Value::Uuid(Uuid::new_v4())),
            (Attribute::Name, Value::new_iname("test_sync_account")),
            (
                Attribute::SyncCredentialPortal,
                Value::Url(portal_url.clone())
            )
        )
        .into_sealed_committed();

        let sync_test_account: Arc<EntrySealedCommitted> = Arc::new(
            entry_init!(
                (Attribute::Class, EntryClass::Object.to_value()),
                (Attribute::Class, EntryClass::Account.to_value()),
                (Attribute::Class, EntryClass::SyncObject.to_value()),
                (Attribute::Name, Value::new_iname("test_account_1")),
                (Attribute::Uuid, Value::Uuid(UUID_TEST_ACCOUNT_1)),
                (Attribute::MemberOf, Value::Refer(UUID_TEST_GROUP_1)),
                (Attribute::SyncParentUuid, Value::Refer(sync_uuid))
            )
            .into_sealed_committed(),
        );

        // Check the authorised search event, and that it reduces correctly.
        let r_set = vec![Arc::new(ev1.clone()), Arc::new(ev2)];

        let se_a = SearchEvent::new_impersonate_entry(
            sync_test_account,
            filter_all!(f_pres(Attribute::SyncCredentialPortal)),
        );
        let ex_a = vec![Arc::new(ev1)];
        let ex_a_reduced = vec![ev1_reduced];

        test_acp_search!(&se_a, vec![], r_set.clone(), ex_a);
        test_acp_search_reduce!(&se_a, vec![], r_set.clone(), ex_a_reduced);

        // Test a non-synced account aka the deny case
        let se_b = SearchEvent::new_impersonate_entry(
            E_TEST_ACCOUNT_2.clone(),
            filter_all!(f_pres(Attribute::SyncCredentialPortal)),
        );
        let ex_b = vec![];

        test_acp_search!(&se_b, vec![], r_set, ex_b);
    }

    #[test]
    fn test_access_entry_managed_by_search() {
        sketching::test_init();

        let test_entry = Arc::new(
            entry_init!(
                (Attribute::Class, EntryClass::Object.to_value()),
                (Attribute::Name, Value::new_iname("testperson1")),
                (Attribute::Uuid, Value::Uuid(UUID_TEST_ACCOUNT_1)),
                (Attribute::EntryManagedBy, Value::Refer(UUID_TEST_GROUP_1))
            )
            .into_sealed_committed(),
        );

        let data_set = vec![test_entry.clone()];

        let se_a = SearchEvent::new_impersonate_entry(
            E_TEST_ACCOUNT_1.clone(),
            filter_all!(f_pres(Attribute::Name)),
        );
        let expect_a = vec![test_entry];

        let se_b = SearchEvent::new_impersonate_entry(
            E_TEST_ACCOUNT_2.clone(),
            filter_all!(f_pres(Attribute::Name)),
        );
        let expect_b = vec![];

        let acp = AccessControlSearch::from_managed_by(
            "test_acp",
            Uuid::new_v4(),
            // Allow admin to read only testperson1
            AccessControlTarget::Scope(filter_valid!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson1")
            ))),
            // In that read, admin may only view the "name" attribute, or query on
            // the name attribute. Any other query (should be) rejected.
            Attribute::Name.as_ref(),
        );

        // Check where allowed
        test_acp_search!(&se_a, vec![acp.clone()], data_set.clone(), expect_a);

        // And where not
        test_acp_search!(&se_b, vec![acp], data_set, expect_b);
    }

    #[test]
    fn test_access_entry_managed_by_create() {
        sketching::test_init();

        let test_entry = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Name, Value::new_iname("testperson1")),
            (Attribute::Uuid, Value::Uuid(UUID_TEST_ACCOUNT_1)),
            (Attribute::EntryManagedBy, Value::Refer(UUID_TEST_GROUP_1))
        );

        let data_set = vec![test_entry];

        let ce = CreateEvent::new_impersonate_identity(
            Identity::from_impersonate_entry_readwrite(E_TEST_ACCOUNT_1.clone()),
            vec![],
        );

        let acp = AccessControlCreate::from_managed_by(
            "test_create",
            Uuid::new_v4(),
            AccessControlTarget::Scope(filter_valid!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson1")
            ))),
            // classes
            EntryClass::Account.into(),
            // attrs
            "class name uuid",
        );

        // Test reject create (not allowed attr). This is because entry
        // managed by is non-sensical with creates!
        test_acp_create!(&ce, vec![acp.clone()], &data_set, false);
    }

    #[test]
    fn test_access_entry_managed_by_modify() {
        let test_entry = Arc::new(
            entry_init!(
                (Attribute::Class, EntryClass::Object.to_value()),
                (Attribute::Name, Value::new_iname("testperson1")),
                (Attribute::Uuid, Value::Uuid(UUID_TEST_ACCOUNT_1)),
                (Attribute::EntryManagedBy, Value::Refer(UUID_TEST_GROUP_1))
            )
            .into_sealed_committed(),
        );

        let data_set = vec![test_entry];

        // Name present
        let me_pres = ModifyEvent::new_impersonate_entry(
            E_TEST_ACCOUNT_1.clone(),
            filter_all!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson1")
            )),
            modlist!([m_pres(Attribute::Name, &Value::new_iname("value"))]),
        );
        // Name rem
        let me_rem = ModifyEvent::new_impersonate_entry(
            E_TEST_ACCOUNT_1.clone(),
            filter_all!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson1")
            )),
            modlist!([m_remove(Attribute::Name, &PartialValue::new_iname("value"))]),
        );
        // Name purge
        let me_purge = ModifyEvent::new_impersonate_entry(
            E_TEST_ACCOUNT_1.clone(),
            filter_all!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson1")
            )),
            modlist!([m_purge(Attribute::Name)]),
        );

        let acp_allow = AccessControlModify::from_managed_by(
            "test_modify_allow",
            Uuid::new_v4(),
            // To modify testperson
            AccessControlTarget::Scope(filter_valid!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson1")
            ))),
            // Allow pres name and class
            "name class",
            // Allow rem name and class
            "name class",
            // And the class allowed is account
            EntryClass::Account.into(),
            EntryClass::Account.into(),
        );

        // Test allowed pres
        test_acp_modify!(&me_pres, vec![acp_allow.clone()], &data_set, true);
        // test allowed rem
        test_acp_modify!(&me_rem, vec![acp_allow.clone()], &data_set, true);
        // test allowed purge
        test_acp_modify!(&me_purge, vec![acp_allow.clone()], &data_set, true);
    }

    #[test]
    fn test_access_entry_managed_by_delete() {
        let test_entry = Arc::new(
            entry_init!(
                (Attribute::Class, EntryClass::Object.to_value()),
                (Attribute::Name, Value::new_iname("testperson1")),
                (Attribute::Uuid, Value::Uuid(UUID_TEST_ACCOUNT_1)),
                (Attribute::EntryManagedBy, Value::Refer(UUID_TEST_GROUP_1))
            )
            .into_sealed_committed(),
        );

        let data_set = vec![test_entry];

        let de_a = DeleteEvent::new_impersonate_entry(
            E_TEST_ACCOUNT_1.clone(),
            filter_all!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson1")
            )),
        );

        let de_b = DeleteEvent::new_impersonate_entry(
            E_TEST_ACCOUNT_2.clone(),
            filter_all!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson1")
            )),
        );

        let acp = AccessControlDelete::from_managed_by(
            "test_delete",
            Uuid::new_v4(),
            // To delete testperson
            AccessControlTarget::Scope(filter_valid!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson1")
            ))),
        );

        // Test allowed to delete
        test_acp_delete!(&de_a, vec![acp.clone()], &data_set, true);
        // Test reject delete
        test_acp_delete!(&de_b, vec![acp], &data_set, false);
    }

    #[test]
    fn test_access_delete_protect_system_ranges() {
        let ev1: EntryInitNew = BUILTIN_ACCOUNT_ANONYMOUS.clone().into();
        let ev1 = ev1.into_sealed_committed();
        let r_set = vec![Arc::new(ev1)];

        let de_account = DeleteEvent::new_impersonate_entry(
            E_TEST_ACCOUNT_1.clone(),
            filter_all!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson1")
            )),
        );

        let acp = AccessControlDelete::from_raw(
            "test_delete",
            Uuid::new_v4(),
            UUID_TEST_GROUP_1,
            // To delete testperson
            filter_valid!(f_eq(Attribute::Name, PartialValue::new_iname("anonymous"))),
        );

        // Test reject delete, can not delete due to system protection
        test_acp_delete!(&de_account, vec![acp], &r_set, false);
    }

    #[test]
    fn test_access_sync_memberof_implies_directmemberof() {
        sketching::test_init();

        let ev1 = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Name, Value::new_iname("test_account_1")),
            (Attribute::Uuid, Value::Uuid(UUID_TEST_ACCOUNT_1)),
            (Attribute::MemberOf, Value::Refer(UUID_TEST_GROUP_1)),
            (Attribute::DirectMemberOf, Value::Refer(UUID_TEST_GROUP_1))
        )
        .into_sealed_committed();
        let r_set = vec![Arc::new(ev1)];

        let exv1 = entry_init!(
            (Attribute::Name, Value::new_iname("test_account_1")),
            (Attribute::MemberOf, Value::Refer(UUID_TEST_GROUP_1)),
            (Attribute::DirectMemberOf, Value::Refer(UUID_TEST_GROUP_1))
        )
        .into_sealed_committed();

        let ex_anon_some = vec![exv1];

        let se_anon_ro = SearchEvent::new_impersonate_identity(
            Identity::from_impersonate_entry_readonly(E_TEST_ACCOUNT_1.clone()),
            filter_all!(f_pres(Attribute::Name)),
        );

        let acp = AccessControlSearch::from_raw(
            "test_acp",
            Uuid::new_v4(),
            // apply to all accounts.
            UUID_TEST_GROUP_1,
            // Allow anonymous to read only testperson1
            filter_valid!(f_eq(
                Attribute::Uuid,
                PartialValue::Uuid(UUID_TEST_ACCOUNT_1)
            )),
            // May query on name, and see memberof. MemberOf implies direct
            // memberof.
            format!("{} {}", Attribute::Name, Attribute::MemberOf).as_str(),
        );

        // Finally test it!
        test_acp_search_reduce!(&se_anon_ro, vec![acp], r_set, ex_anon_some);
    }

    #[test]
    fn test_access_protected_deny_create() {
        sketching::test_init();

        let ev1 = entry_init!(
            (Attribute::Class, EntryClass::Account.to_value()),
            (Attribute::Name, Value::new_iname("testperson1")),
            (Attribute::Uuid, Value::Uuid(UUID_TEST_ACCOUNT_1))
        );
        let r1_set = vec![ev1];

        let ev2 = entry_init!(
            (Attribute::Class, EntryClass::Account.to_value()),
            (Attribute::Class, EntryClass::System.to_value()),
            (Attribute::Name, Value::new_iname("testperson1")),
            (Attribute::Uuid, Value::Uuid(UUID_TEST_ACCOUNT_1))
        );

        let r2_set = vec![ev2];

        let ce_admin = CreateEvent::new_impersonate_identity(
            Identity::from_impersonate_entry_readwrite(E_TEST_ACCOUNT_1.clone()),
            vec![],
        );

        let acp = AccessControlCreate::from_raw(
            "test_create",
            Uuid::new_v4(),
            // Apply to admin
            UUID_TEST_GROUP_1,
            // To create matching filter testperson
            // Can this be empty?
            filter_valid!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson1")
            )),
            // classes
            EntryClass::Account.into(),
            // attrs
            "class name uuid",
        );

        // Test allowed to create
        test_acp_create!(&ce_admin, vec![acp.clone()], &r1_set, true);
        // Test reject create (not allowed attr)
        test_acp_create!(&ce_admin, vec![acp.clone()], &r2_set, false);
    }

    #[test]
    fn test_access_protected_deny_delete() {
        sketching::test_init();

        let ev1 = entry_init!(
            (Attribute::Class, EntryClass::Account.to_value()),
            (Attribute::Name, Value::new_iname("testperson1")),
            (Attribute::Uuid, Value::Uuid(UUID_TEST_ACCOUNT_1))
        )
        .into_sealed_committed();
        let r1_set = vec![Arc::new(ev1)];

        let ev2 = entry_init!(
            (Attribute::Class, EntryClass::Account.to_value()),
            (Attribute::Class, EntryClass::System.to_value()),
            (Attribute::Name, Value::new_iname("testperson1")),
            (Attribute::Uuid, Value::Uuid(UUID_TEST_ACCOUNT_1))
        )
        .into_sealed_committed();

        let r2_set = vec![Arc::new(ev2)];

        let de = DeleteEvent::new_impersonate_entry(
            E_TEST_ACCOUNT_1.clone(),
            filter_all!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson1")
            )),
        );

        let acp = AccessControlDelete::from_raw(
            "test_delete",
            Uuid::new_v4(),
            // Apply to admin
            UUID_TEST_GROUP_1,
            // To delete testperson
            filter_valid!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson1")
            )),
        );

        // Test allowed to delete
        test_acp_delete!(&de, vec![acp.clone()], &r1_set, true);
        // Test not allowed to delete
        test_acp_delete!(&de, vec![acp.clone()], &r2_set, false);
    }

    #[test]
    fn test_access_protected_deny_modify() {
        sketching::test_init();

        let ev1 = entry_init!(
            (Attribute::Class, EntryClass::Account.to_value()),
            (Attribute::Name, Value::new_iname("testperson1")),
            (Attribute::Uuid, Value::Uuid(UUID_TEST_ACCOUNT_1))
        )
        .into_sealed_committed();
        let r1_set = vec![Arc::new(ev1)];

        let ev2 = entry_init!(
            (Attribute::Class, EntryClass::Account.to_value()),
            (Attribute::Class, EntryClass::System.to_value()),
            (Attribute::Name, Value::new_iname("testperson1")),
            (Attribute::Uuid, Value::Uuid(UUID_TEST_ACCOUNT_1))
        )
        .into_sealed_committed();

        let r2_set = vec![Arc::new(ev2)];

        // Allow name and class, class is account
        let acp_allow = AccessControlModify::from_raw(
            "test_modify_allow",
            Uuid::new_v4(),
            // Apply to admin
            UUID_TEST_GROUP_1,
            // To modify testperson
            filter_valid!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson1")
            )),
            // Allow pres disp name and class
            "displayname class",
            // Allow rem disp name and class
            "displayname class",
            // And the class allowed is system
            EntryClass::System.into(),
            // And the class allowed is system
            EntryClass::System.into(),
        );

        let me_pres = ModifyEvent::new_impersonate_entry(
            E_TEST_ACCOUNT_1.clone(),
            filter_all!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("testperson1")
            )),
            modlist!([m_pres(Attribute::DisplayName, &Value::new_utf8s("value"))]),
        );

        // Test allowed pres
        test_acp_modify!(&me_pres, vec![acp_allow.clone()], &r1_set, true);

        // Test not allowed pres (due to system class)
        test_acp_modify!(&me_pres, vec![acp_allow.clone()], &r2_set, false);
    }
}
