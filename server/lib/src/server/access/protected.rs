
use std::collections::BTreeSet;
use crate::prelude::{EntryClass};


lazy_static! {
    /// These entry classes may not be created or deleted, and may invoke some protection rules
    /// if on an entry.
    pub static ref PROTECTED_ENTRY_CLASSES: BTreeSet<String> = {
        let classes = vec![
            EntryClass::System,
            EntryClass::DomainInfo,
            EntryClass::SystemInfo,
            EntryClass::SystemConfig,
            EntryClass::DynGroup,
            EntryClass::SyncObject,
            EntryClass::Tombstone,
            EntryClass::Recycled,
        ];

        BTreeSet::from_iter(classes.into_iter()
            .map(|ec| ec.into()))
    };

    /// Entries with these classes are protected from modifications - not that
    /// sync object is not present here as there are separate rules for that in
    /// the modification access module.
    ///
    /// Recycled is also not protected here as it needs to be able to be removed
    /// by a recycle bin admin.
    pub static ref PROTECTED_MOD_ENTRY_CLASSES: BTreeSet<String> = {
        let classes = vec![
            EntryClass::System,
            EntryClass::DomainInfo,
            EntryClass::SystemInfo,
            EntryClass::SystemConfig,
            EntryClass::DynGroup,
            // EntryClass::SyncObject,
            EntryClass::Tombstone,
            // EntryClass::Recycled,
        ];

        BTreeSet::from_iter(classes.into_iter()
            .map(|ec| ec.into()))
    };

    /// Entries with these classes may not be modified under any circumstance.
    pub static ref LOCKED_ENTRY_CLASSES: BTreeSet<String> = {
        let classes = vec![
            EntryClass::Tombstone,
            // EntryClass::Recycled,
        ];

        BTreeSet::from_iter(classes.into_iter()
            .map(|ec| ec.into()))
    };
}


