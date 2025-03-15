use super::profiles::{
    AccessControlModify, AccessControlModifyResolved, AccessControlReceiverCondition,
    AccessControlTargetCondition,
};
use super::protected::{LOCKED_ENTRY_CLASSES, PROTECTED_MOD_ENTRY_CLASSES};
use super::{AccessResult, AccessResultClass};
use crate::prelude::*;
use hashbrown::HashMap;
use std::collections::BTreeSet;
use std::sync::Arc;

pub(super) enum ModifyResult<'a> {
    Denied,
    Grant,
    Allow {
        pres: BTreeSet<Attribute>,
        rem: BTreeSet<Attribute>,
        cls: BTreeSet<&'a str>,
    },
}

pub(super) fn apply_modify_access<'a>(
    ident: &Identity,
    related_acp: &'a [AccessControlModifyResolved],
    sync_agreements: &HashMap<Uuid, BTreeSet<Attribute>>,
    entry: &Arc<EntrySealedCommitted>,
) -> ModifyResult<'a> {
    let mut denied = false;
    let mut grant = false;

    let mut constrain_pres = BTreeSet::default();
    let mut allow_pres = BTreeSet::default();
    let mut constrain_rem = BTreeSet::default();
    let mut allow_rem = BTreeSet::default();
    let mut constrain_cls = BTreeSet::default();
    let mut allow_cls = BTreeSet::default();

    // Some useful references.
    //  - needed for checking entry manager conditions.
    let ident_memberof = ident.get_memberof();
    let ident_uuid = ident.get_uuid();

    // run each module. These have to be broken down further due to modify
    // kind of being three operations all in one.

    match modify_ident_test(ident) {
        AccessResult::Denied => denied = true,
        AccessResult::Grant => grant = true,
        AccessResult::Ignore => {}
        AccessResult::Constrain(mut set) => constrain_pres.append(&mut set),
        AccessResult::Allow(mut set) => allow_pres.append(&mut set),
    }

    // Check with protected if we should proceed.
    match modify_protected_attrs(ident, entry) {
        AccessResult::Denied => denied = true,
        AccessResult::Constrain(mut set) => {
            constrain_rem.extend(set.iter().cloned());
            constrain_pres.append(&mut set)
        }
        // Can't grant.
        AccessResult::Grant |
        // Can't allow
        AccessResult::Allow(_) |
        AccessResult::Ignore => {}
    }

    if !grant && !denied {
        // If it's a sync entry, constrain it.
        match modify_sync_constrain(ident, entry, sync_agreements) {
            AccessResult::Denied => denied = true,
            AccessResult::Constrain(mut set) => {
                constrain_rem.extend(set.iter().cloned());
                constrain_pres.append(&mut set)
            }
            // Can't grant.
            AccessResult::Grant |
            // Can't allow
            AccessResult::Allow(_) |
            AccessResult::Ignore => {}
        }

        // Setup the acp's here
        let scoped_acp: Vec<&AccessControlModify> = related_acp
            .iter()
            .filter_map(|acm| {
                match &acm.receiver_condition {
                    AccessControlReceiverCondition::GroupChecked => {
                        // The groups were already checked during filter resolution. Trust
                        // that result, and continue.
                    }
                    AccessControlReceiverCondition::EntryManager => {
                        // This condition relies on the entry we are looking at to have a back-ref
                        // to our uuid or a group we are in as an entry manager.

                        // Note, while schema has this as single value, we currently
                        // fetch it as a multivalue btreeset for future incase we allow
                        // multiple entry manager by in future.
                        if let Some(entry_manager_uuids) =
                            entry.get_ava_refer(Attribute::EntryManagedBy)
                        {
                            let group_check = ident_memberof
                                // Have at least one group allowed.
                                .map(|imo| imo.intersection(entry_manager_uuids).next().is_some())
                                .unwrap_or_default();

                            let user_check = ident_uuid
                                .map(|u| entry_manager_uuids.contains(&u))
                                .unwrap_or_default();

                            if !(group_check || user_check) {
                                // Not the entry manager
                                return None;
                            }
                        } else {
                            // Can not satisfy.
                            return None;
                        }
                    }
                };

                match &acm.target_condition {
                    AccessControlTargetCondition::Scope(f_res) => {
                        if !entry.entry_match_no_index(f_res) {
                            debug!(entry = ?entry.get_display_id(), acm = %acm.acp.acp.name, "entry DOES NOT match acs");
                            return None;
                        }
                    }
                };

                debug!(entry = ?entry.get_display_id(), acs = %acm.acp.acp.name, "acs applied to entry");

                Some(acm.acp)
            })
            .collect();

        match modify_pres_test(scoped_acp.as_slice()) {
            AccessResult::Denied => denied = true,
            // Can never return a unilateral grant.
            AccessResult::Grant => {}
            AccessResult::Ignore => {}
            AccessResult::Constrain(mut set) => constrain_pres.append(&mut set),
            AccessResult::Allow(mut set) => allow_pres.append(&mut set),
        }

        match modify_rem_test(scoped_acp.as_slice()) {
            AccessResult::Denied => denied = true,
            // Can never return a unilateral grant.
            AccessResult::Grant => {}
            AccessResult::Ignore => {}
            AccessResult::Constrain(mut set) => constrain_rem.append(&mut set),
            AccessResult::Allow(mut set) => allow_rem.append(&mut set),
        }

        match modify_cls_test(scoped_acp.as_slice()) {
            AccessResultClass::Denied => denied = true,
            // Can never return a unilateral grant.
            AccessResultClass::Grant => {}
            AccessResultClass::Ignore => {}
            AccessResultClass::Constrain(mut set) => constrain_cls.append(&mut set),
            AccessResultClass::Allow(mut set) => allow_cls.append(&mut set),
        }
    }

    if denied {
        ModifyResult::Denied
    } else if grant {
        ModifyResult::Grant
    } else {
        let allowed_pres = if !constrain_pres.is_empty() {
            // bit_and
            &constrain_pres & &allow_pres
        } else {
            allow_pres
        };

        let allowed_rem = if !constrain_rem.is_empty() {
            // bit_and
            &constrain_rem & &allow_rem
        } else {
            allow_rem
        };

        let mut allowed_cls = if !constrain_cls.is_empty() {
            // bit_and
            &constrain_cls & &allow_cls
        } else {
            allow_cls
        };

        // Deny these classes from being part of any addition or removal to an entry
        for protected_cls in PROTECTED_MOD_ENTRY_CLASSES.iter() {
            allowed_cls.remove(protected_cls.as_str());
        }

        ModifyResult::Allow {
            pres: allowed_pres,
            rem: allowed_rem,
            cls: allowed_cls,
        }
    }
}

fn modify_ident_test(ident: &Identity) -> AccessResult {
    match &ident.origin {
        IdentType::Internal => {
            trace!("Internal operation, bypassing access check");
            // No need to check ACS
            return AccessResult::Grant;
        }
        IdentType::Synch(_) => {
            security_critical!("Blocking sync check");
            return AccessResult::Denied;
        }
        IdentType::User(_) => {}
    };
    debug!(event = %ident, "Access check for modify event");

    match ident.access_scope() {
        AccessScope::ReadOnly | AccessScope::Synchronise => {
            security_access!("denied ❌ - identity access scope is not permitted to modify");
            return AccessResult::Denied;
        }
        AccessScope::ReadWrite => {
            // As you were
        }
    };

    AccessResult::Ignore
}

fn modify_pres_test(scoped_acp: &[&AccessControlModify]) -> AccessResult {
    let allowed_pres: BTreeSet<Attribute> = scoped_acp
        .iter()
        .flat_map(|acp| acp.presattrs.iter().cloned())
        .collect();
    AccessResult::Allow(allowed_pres)
}

fn modify_rem_test(scoped_acp: &[&AccessControlModify]) -> AccessResult {
    let allowed_rem: BTreeSet<Attribute> = scoped_acp
        .iter()
        .flat_map(|acp| acp.remattrs.iter().cloned())
        .collect();
    AccessResult::Allow(allowed_rem)
}

// TODO: Should this be reverted to the Str borrow method? Or do we try to change
// to EntryClass?
fn modify_cls_test<'a>(scoped_acp: &[&'a AccessControlModify]) -> AccessResultClass<'a> {
    let allowed_classes: BTreeSet<&'a str> = scoped_acp
        .iter()
        .flat_map(|acp| acp.classes.iter().map(|s| s.as_str()))
        .collect();
    AccessResultClass::Allow(allowed_classes)
}

fn modify_sync_constrain(
    ident: &Identity,
    entry: &Arc<EntrySealedCommitted>,
    sync_agreements: &HashMap<Uuid, BTreeSet<Attribute>>,
) -> AccessResult {
    match &ident.origin {
        IdentType::Internal => AccessResult::Ignore,
        IdentType::Synch(_) => {
            // Allowed to mod sync objects. Later we'll probably need to check the limits of what
            // it can do if we go that way.
            AccessResult::Ignore
        }
        IdentType::User(_) => {
            // We need to meet these conditions.
            // * We are a sync object
            // * We have a sync_parent_uuid
            let is_sync = entry
                .get_ava_set(Attribute::Class)
                .map(|classes| classes.contains(&EntryClass::SyncObject.into()))
                .unwrap_or(false);

            if !is_sync {
                return AccessResult::Ignore;
            }

            if let Some(sync_uuid) = entry.get_ava_single_refer(Attribute::SyncParentUuid) {
                let mut set = btreeset![
                    Attribute::UserAuthTokenSession,
                    Attribute::OAuth2Session,
                    Attribute::OAuth2ConsentScopeMap,
                    Attribute::CredentialUpdateIntentToken
                ];

                if let Some(sync_yield_authority) = sync_agreements.get(&sync_uuid) {
                    set.extend(sync_yield_authority.iter().cloned())
                }

                AccessResult::Constrain(set)
            } else {
                warn!(entry = ?entry.get_uuid(), "sync_parent_uuid not found on sync object, preventing all access");
                AccessResult::Denied
            }
        }
    }
}

/// Verify if the modification runs into limits that are defined by our protection rules.
fn modify_protected_attrs(ident: &Identity, entry: &Arc<EntrySealedCommitted>) -> AccessResult {
    match &ident.origin {
        IdentType::Internal | IdentType::Synch(_) => {
            // We don't constraint or influence these.
            AccessResult::Ignore
        }
        IdentType::User(_) => {
            if let Some(classes) = entry.get_ava_as_iutf8(Attribute::Class) {
                if classes.is_disjoint(&PROTECTED_MOD_ENTRY_CLASSES) {
                    // Not protected, go ahead
                    AccessResult::Ignore
                } else {
                    // Okay, the entry is protected, apply the full ruleset.
                    modify_protected_entry_attrs(classes)
                }
            } else {
                // Nothing to check - this entry will fail to modify anyway because it has
                // no classes
                AccessResult::Ignore
            }
        }
    }
}

fn modify_protected_entry_attrs(classes: &BTreeSet<String>) -> AccessResult {
    // This is where the majority of the logic is - this contains the modification
    // rules as they apply.

    // First check for the hard-deny rules.
    if !classes.is_disjoint(&LOCKED_ENTRY_CLASSES) {
        // Hard deny attribute modifications to these types.
        return AccessResult::Denied;
    }

    let mut constrain_attrs = BTreeSet::default();

    // Allows removal of the recycled class specifically on recycled entries.
    if classes.contains(EntryClass::Recycled.into()) {
        constrain_attrs.extend([Attribute::Class]);
    }

    if classes.contains(EntryClass::ClassType.into()) {
        constrain_attrs.extend([Attribute::May, Attribute::Must]);
    }

    if classes.contains(EntryClass::SystemConfig.into()) {
        constrain_attrs.extend([Attribute::BadlistPassword]);
    }

    // Allow domain settings.
    if classes.contains(EntryClass::DomainInfo.into()) {
        constrain_attrs.extend([
            Attribute::DomainSsid,
            Attribute::DomainLdapBasedn,
            Attribute::LdapMaxQueryableAttrs,
            Attribute::LdapAllowUnixPwBind,
            Attribute::FernetPrivateKeyStr,
            Attribute::Es256PrivateKeyDer,
            Attribute::KeyActionRevoke,
            Attribute::KeyActionRotate,
            Attribute::IdVerificationEcKey,
            Attribute::DeniedName,
            Attribute::DomainDisplayName,
            Attribute::Image,
        ]);
    }

    // Allow account policy related attributes to be changed on dyngroup
    if classes.contains(EntryClass::DynGroup.into()) {
        constrain_attrs.extend([
            Attribute::AuthSessionExpiry,
            Attribute::AuthPasswordMinimumLength,
            Attribute::CredentialTypeMinimum,
            Attribute::PrivilegeExpiry,
            Attribute::WebauthnAttestationCaList,
            Attribute::LimitSearchMaxResults,
            Attribute::LimitSearchMaxFilterTest,
            Attribute::AllowPrimaryCredFallback,
        ]);
    }

    // If we don't constrain the attributes at all, we have to deny the change
    // from proceeding.
    if constrain_attrs.is_empty() {
        AccessResult::Denied
    } else {
        AccessResult::Constrain(constrain_attrs)
    }
}
