use super::profiles::{
    AccessControlDeleteResolved, AccessControlReceiverCondition, AccessControlTargetCondition,
};
use super::protected::PROTECTED_ENTRY_CLASSES;
use crate::prelude::*;
use std::sync::Arc;

pub(super) enum DeleteResult {
    Denied,
    Grant,
}

enum IResult {
    Denied,
    Grant,
    Ignore,
}

pub(super) fn apply_delete_access<'a>(
    ident: &Identity,
    related_acp: &'a [AccessControlDeleteResolved],
    entry: &'a Arc<EntrySealedCommitted>,
) -> DeleteResult {
    let mut denied = false;
    let mut grant = false;

    match protected_filter_entry(ident, entry) {
        IResult::Denied => denied = true,
        IResult::Grant | IResult::Ignore => {}
    }

    match delete_filter_entry(ident, related_acp, entry) {
        IResult::Denied => denied = true,
        IResult::Grant => grant = true,
        IResult::Ignore => {}
    }

    if denied {
        // Something explicitly said no.
        DeleteResult::Denied
    } else if grant {
        // Something said yes
        DeleteResult::Grant
    } else {
        // Nothing said yes.
        DeleteResult::Denied
    }
}

fn delete_filter_entry<'a>(
    ident: &Identity,
    related_acp: &'a [AccessControlDeleteResolved],
    entry: &'a Arc<EntrySealedCommitted>,
) -> IResult {
    match &ident.origin {
        IdentType::Internal => {
            trace!("Internal operation, bypassing access check");
            // No need to check ACS
            return IResult::Grant;
        }
        IdentType::Synch(_) => {
            security_critical!("Blocking sync check");
            return IResult::Denied;
        }
        IdentType::User(_) => {}
    };
    debug!(event = %ident, "Access check for delete event");

    match ident.access_scope() {
        AccessScope::ReadOnly | AccessScope::Synchronise => {
            security_access!("denied ❌ - identity access scope is not permitted to delete");
            return IResult::Denied;
        }
        AccessScope::ReadWrite => {
            // As you were
        }
    };

    let ident_memberof = ident.get_memberof();
    let ident_uuid = ident.get_uuid();

    let allow = related_acp.iter().any(|acd| {
        // Assert that the receiver condition applies.
        match &acd.receiver_condition {
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
                if let Some(entry_manager_uuids) = entry.get_ava_refer(Attribute::EntryManagedBy) {
                    let group_check = ident_memberof
                        // Have at least one group allowed.
                        .map(|imo| imo.intersection(entry_manager_uuids).next().is_some())
                        .unwrap_or_default();

                    let user_check = ident_uuid
                        .map(|u| entry_manager_uuids.contains(&u))
                        .unwrap_or_default();

                    if !(group_check || user_check) {
                        // Not the entry manager
                        return false;
                    }
                } else {
                    // Can not satisfy.
                    return false;
                }
            }
        };

        match &acd.target_condition {
            AccessControlTargetCondition::Scope(f_res) => {
                if !entry.entry_match_no_index(f_res) {
                    trace!(
                        "entry {:?} DOES NOT match acs {}",
                        entry.get_uuid(),
                        acd.acp.acp.name
                    );
                    // Does not match, fail.
                    return false;
                }
            }
        };

        let entry_name = entry.get_display_id();
        security_access!(
            %entry_name,
            acs = %acd.acp.acp.name,
            "entry matches acs"
        );

        true
    }); // any related_acp

    if allow {
        IResult::Grant
    } else {
        IResult::Ignore
    }
}

fn protected_filter_entry(ident: &Identity, entry: &Arc<EntrySealedCommitted>) -> IResult {
    match &ident.origin {
        IdentType::Internal => {
            trace!("Internal operation, protected rules do not apply.");
            IResult::Ignore
        }
        IdentType::Synch(_) => {
            security_access!("sync agreements may not directly delete entities");
            IResult::Denied
        }
        IdentType::User(_) => {
            // Prevent deletion of entries that exist in the system controlled entry range.
            if entry.get_uuid() <= UUID_ANONYMOUS {
                security_access!("attempt to delete system builtin entry");
                return IResult::Denied;
            }

            // Prevent deleting some protected types.
            if let Some(classes) = entry.get_ava_as_iutf8(Attribute::Class) {
                if classes.is_disjoint(&PROTECTED_ENTRY_CLASSES) {
                    // It's different, go ahead
                    IResult::Ignore
                } else {
                    // Block the mod, something is present
                    security_access!("attempt to create with protected class type");
                    IResult::Denied
                }
            } else {
                // Nothing to check - this entry will fail to create anyway because it has
                // no classes
                IResult::Ignore
            }
        }
    }
}
