use super::profiles::{
    AccessControlModify, AccessControlModifyResolved, AccessControlReceiverCondition,
    AccessControlTargetCondition,
};
use super::protected::{
    LOCKED_ENTRY_CLASSES, PROTECTED_MOD_ENTRY_CLASSES, PROTECTED_MOD_PRES_ENTRY_CLASSES,
    PROTECTED_MOD_REM_ENTRY_CLASSES,
};
use super::{AccessBasicResult, AccessModResult};
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
        pres_cls: BTreeSet<&'a str>,
        rem_cls: BTreeSet<&'a str>,
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

    let mut constrain_pres_cls = BTreeSet::default();
    let mut allow_pres_cls = BTreeSet::default();

    let mut constrain_rem_cls = BTreeSet::default();
    let mut allow_rem_cls = BTreeSet::default();

    // Some useful references.
    //  - needed for checking entry manager conditions.
    let ident_memberof = ident.get_memberof();
    let ident_uuid = ident.get_uuid();

    // run each module. These have to be broken down further due to modify
    // kind of being three operations all in one.

    match modify_ident_test(ident) {
        AccessBasicResult::Denied => denied = true,
        AccessBasicResult::Grant => grant = true,
        AccessBasicResult::Ignore => {}
    }

    // Check with protected if we should proceed.
    match modify_protected_attrs(ident, entry) {
        AccessModResult::Denied => denied = true,
        AccessModResult::Constrain {
            mut pres_attr,
            mut rem_attr,
            pres_cls,
            rem_cls,
        } => {
            constrain_rem.append(&mut rem_attr);
            constrain_pres.append(&mut pres_attr);

            if let Some(mut pres_cls) = pres_cls {
                constrain_pres_cls.append(&mut pres_cls);
            }

            if let Some(mut rem_cls) = rem_cls {
                constrain_rem_cls.append(&mut rem_cls);
            }
        }
        // Can't grant.
        // AccessModResult::Grant |
        // Can't allow
        AccessModResult::Allow { .. } | AccessModResult::Ignore => {}
    }

    if !grant && !denied {
        // If it's a sync entry, constrain it.
        match modify_sync_constrain(ident, entry, sync_agreements) {
            AccessModResult::Denied => denied = true,
            AccessModResult::Constrain {
                mut pres_attr,
                mut rem_attr,
                ..
            } => {
                constrain_rem.append(&mut rem_attr);
                constrain_pres.append(&mut pres_attr);
            }
            // Can't grant.
            // AccessModResult::Grant |
            // Can't allow
            AccessModResult::Allow { .. } | AccessModResult::Ignore => {}
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
            AccessModResult::Denied => denied = true,
            // Can never return a unilateral grant.
            // AccessModResult::Grant => {}
            AccessModResult::Ignore => {}
            AccessModResult::Constrain { .. } => {}
            AccessModResult::Allow {
                mut pres_attr,
                mut rem_attr,
                mut pres_class,
                mut rem_class,
            } => {
                allow_pres.append(&mut pres_attr);
                allow_rem.append(&mut rem_attr);
                allow_pres_cls.append(&mut pres_class);
                allow_rem_cls.append(&mut rem_class);
            }
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

        let mut allowed_pres_cls = if !constrain_pres_cls.is_empty() {
            // bit_and
            &constrain_pres_cls & &allow_pres_cls
        } else {
            allow_pres_cls
        };

        let mut allowed_rem_cls = if !constrain_rem_cls.is_empty() {
            // bit_and
            &constrain_rem_cls & &allow_rem_cls
        } else {
            allow_rem_cls
        };

        // Deny these classes from being part of any addition or removal to an entry
        for protected_cls in PROTECTED_MOD_PRES_ENTRY_CLASSES.iter() {
            allowed_pres_cls.remove(protected_cls.as_str());
        }

        for protected_cls in PROTECTED_MOD_REM_ENTRY_CLASSES.iter() {
            allowed_rem_cls.remove(protected_cls.as_str());
        }

        ModifyResult::Allow {
            pres: allowed_pres,
            rem: allowed_rem,
            pres_cls: allowed_pres_cls,
            rem_cls: allowed_rem_cls,
        }
    }
}

fn modify_ident_test(ident: &Identity) -> AccessBasicResult {
    match &ident.origin {
        IdentType::Internal => {
            trace!("Internal operation, bypassing access check");
            // No need to check ACS
            return AccessBasicResult::Grant;
        }
        IdentType::Synch(_) => {
            security_critical!("Blocking sync check");
            return AccessBasicResult::Denied;
        }
        IdentType::User(_) => {}
    };
    debug!(event = %ident, "Access check for modify event");

    match ident.access_scope() {
        AccessScope::ReadOnly | AccessScope::Synchronise => {
            security_access!("denied ❌ - identity access scope is not permitted to modify");
            return AccessBasicResult::Denied;
        }
        AccessScope::ReadWrite => {
            // As you were
        }
    };

    AccessBasicResult::Ignore
}

fn modify_pres_test<'a>(scoped_acp: &[&'a AccessControlModify]) -> AccessModResult<'a> {
    let pres_attr: BTreeSet<Attribute> = scoped_acp
        .iter()
        .flat_map(|acp| acp.presattrs.iter().cloned())
        .collect();

    let rem_attr: BTreeSet<Attribute> = scoped_acp
        .iter()
        .flat_map(|acp| acp.remattrs.iter().cloned())
        .collect();

    let pres_class: BTreeSet<&'a str> = scoped_acp
        .iter()
        .flat_map(|acp| acp.pres_classes.iter().map(|s| s.as_str()))
        .collect();

    let rem_class: BTreeSet<&'a str> = scoped_acp
        .iter()
        .flat_map(|acp| acp.rem_classes.iter().map(|s| s.as_str()))
        .collect();

    AccessModResult::Allow {
        pres_attr,
        rem_attr,
        pres_class,
        rem_class,
    }
}

fn modify_sync_constrain<'a>(
    ident: &Identity,
    entry: &Arc<EntrySealedCommitted>,
    sync_agreements: &HashMap<Uuid, BTreeSet<Attribute>>,
) -> AccessModResult<'a> {
    match &ident.origin {
        IdentType::Internal => AccessModResult::Ignore,
        IdentType::Synch(_) => {
            // Allowed to mod sync objects. Later we'll probably need to check the limits of what
            // it can do if we go that way.
            AccessModResult::Ignore
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
                return AccessModResult::Ignore;
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

                AccessModResult::Constrain {
                    pres_attr: set.clone(),
                    rem_attr: set,
                    pres_cls: None,
                    rem_cls: None,
                }
            } else {
                warn!(entry = ?entry.get_uuid(), "sync_parent_uuid not found on sync object, preventing all access");
                AccessModResult::Denied
            }
        }
    }
}

/// Verify if the modification runs into limits that are defined by our protection rules.
fn modify_protected_attrs<'a>(
    ident: &Identity,
    entry: &Arc<EntrySealedCommitted>,
) -> AccessModResult<'a> {
    match &ident.origin {
        IdentType::Internal | IdentType::Synch(_) => {
            // We don't constraint or influence these.
            AccessModResult::Ignore
        }
        IdentType::User(_) => {
            if let Some(classes) = entry.get_ava_as_iutf8(Attribute::Class) {
                if classes.is_disjoint(&PROTECTED_MOD_ENTRY_CLASSES) {
                    // Not protected, go ahead
                    AccessModResult::Ignore
                } else {
                    // Okay, the entry is protected, apply the full ruleset.
                    modify_protected_entry_attrs(classes)
                }
            } else {
                // Nothing to check - this entry will fail to modify anyway because it has
                // no classes
                AccessModResult::Ignore
            }
        }
    }
}

fn modify_protected_entry_attrs<'a>(classes: &BTreeSet<String>) -> AccessModResult<'a> {
    // This is where the majority of the logic is - this contains the modification
    // rules as they apply.

    // First check for the hard-deny rules.
    if !classes.is_disjoint(&LOCKED_ENTRY_CLASSES) {
        // Hard deny attribute modifications to these types.
        return AccessModResult::Denied;
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
        AccessModResult::Denied
    } else {
        AccessModResult::Constrain {
            pres_attr: constrain_attrs.clone(),
            rem_attr: constrain_attrs,
            pres_cls: None,
            rem_cls: None,
        }
    }
}
