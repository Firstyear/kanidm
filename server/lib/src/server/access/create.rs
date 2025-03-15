use super::profiles::{
    AccessControlCreateResolved, AccessControlReceiverCondition, AccessControlTargetCondition,
};
use super::protected::PROTECTED_ENTRY_CLASSES;
use crate::prelude::*;
use std::collections::BTreeSet;

pub(super) enum CreateResult {
    Denied,
    Grant,
}

enum IResult {
    Denied,
    Grant,
    Ignore,
}

pub(super) fn apply_create_access<'a>(
    ident: &Identity,
    related_acp: &'a [AccessControlCreateResolved],
    entry: &'a Entry<EntryInit, EntryNew>,
) -> CreateResult {
    let mut denied = false;
    let mut grant = false;

    // This module can never yield a grant.
    match protected_filter_entry(ident, entry) {
        IResult::Denied => denied = true,
        IResult::Grant | IResult::Ignore => {}
    }

    match create_filter_entry(ident, related_acp, entry) {
        IResult::Denied => denied = true,
        IResult::Grant => grant = true,
        IResult::Ignore => {}
    }

    if denied {
        // Something explicitly said no.
        CreateResult::Denied
    } else if grant {
        // Something said yes
        CreateResult::Grant
    } else {
        // Nothing said yes.
        CreateResult::Denied
    }
}

fn create_filter_entry<'a>(
    ident: &Identity,
    related_acp: &'a [AccessControlCreateResolved],
    entry: &'a Entry<EntryInit, EntryNew>,
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
    debug!(event = %ident, "Access check for create event");

    match ident.access_scope() {
        AccessScope::ReadOnly | AccessScope::Synchronise => {
            security_access!("denied ❌ - identity access scope is not permitted to create");
            return IResult::Denied;
        }
        AccessScope::ReadWrite => {
            // As you were
        }
    };

    // Build the set of requested classes and attrs here.
    let create_attrs: BTreeSet<&str> = entry.get_ava_names().collect();
    // If this is empty, we make an empty set, which is fine because
    // the empty class set despite matching is_subset, will have the
    // following effect:
    // * there is no class on entry, so schema will fail
    // * plugin-base will add object to give a class, but excess
    //   attrs will cause fail (could this be a weakness?)
    // * class is a "may", so this could be empty in the rules, so
    //   if the accr is empty this would not be a true subset,
    //   so this would "fail", but any content in the accr would
    //   have to be validated.
    //
    // I still think if this is None, we should just fail here ...
    // because it shouldn't be possible to match.

    let create_classes: BTreeSet<&str> = match entry.get_ava_iter_iutf8(Attribute::Class) {
        Some(s) => s.collect(),
        None => {
            admin_error!("Class set failed to build - corrupted entry?");
            return IResult::Denied;
        }
    };

    //      Find the set of related acps for this entry.
    //
    //      For each "created" entry.
    //          If the created entry is 100% allowed by this acp
    //          IE: all attrs to be created AND classes match classes
    //              allow
    //          if no acp allows, fail operation.
    let allow = related_acp.iter().any(|accr| {
        // Assert that the receiver condition applies.
        match &accr.receiver_condition {
            AccessControlReceiverCondition::GroupChecked => {
                // The groups were already checked during filter resolution. Trust
                // that result, and continue.
            }
            AccessControlReceiverCondition::EntryManager => {
                // Currently, this is unsatisfiable for creates.
                return false;
            }
        };

        match &accr.target_condition {
            AccessControlTargetCondition::Scope(f_res) => {
                if !entry.entry_match_no_index(f_res) {
                    trace!(?entry, acs = %accr.acp.acp.name, "entry DOES NOT match acs");
                    // Does not match, fail this rule.
                    return false;
                }
            }
        };

        // -- Conditions pass -- now verify the attributes.

        let entry_name = entry.get_display_id();
        security_access!(%entry_name, acs = ?accr.acp.acp.name, "entry matches acs");
        // It matches, so now we have to check attrs and classes.
        // Remember, we have to match ALL requested attrs
        // and classes to pass!
        let allowed_attrs: BTreeSet<&str> = accr.acp.attrs.iter().map(|s| s.as_str()).collect();
        let allowed_classes: BTreeSet<&str> = accr.acp.classes.iter().map(|s| s.as_str()).collect();

        if !create_attrs.is_subset(&allowed_attrs) {
            security_error!("create_attrs is not a subset of allowed");
            security_error!("create: {:?} !⊆ allowed: {:?}", create_attrs, allowed_attrs);
            false
        } else if !create_classes.is_subset(&allowed_classes) {
            security_error!("create_classes is not a subset of allowed");
            security_error!(
                "create: {:?} !⊆ allowed: {:?}",
                create_classes,
                allowed_classes
            );
            false
        } else {
            // All attribute conditions are now met.
            true
        }
    });

    if allow {
        IResult::Grant
    } else {
        IResult::Ignore
    }
}

fn protected_filter_entry(ident: &Identity, entry: &Entry<EntryInit, EntryNew>) -> IResult {
    match &ident.origin {
        IdentType::Internal => {
            trace!("Internal operation, protected rules do not apply.");
            IResult::Ignore
        }
        IdentType::Synch(_) => {
            security_access!("sync agreements may not directly create entities");
            IResult::Denied
        }
        IdentType::User(_) => {
            // Now check things ...
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
