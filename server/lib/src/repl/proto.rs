use super::{
    cid::Cid,
    entry::{EntryChangeState, State},
};
use crate::{
    be::dbvalue::DbValueSetV2,
    entry::Eattrs,
    prelude::*,
    schema::{SchemaReadTransaction, SchemaTransaction},
    valueset,
};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fmt};

pub enum ConsumerState {
    Ok,
    RefreshRequired,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct ReplCidV1 {
    #[serde(rename = "t")]
    pub ts: Duration,
    #[serde(rename = "s")]
    pub s_uuid: Uuid,
}

// From / Into CID
impl From<&Cid> for ReplCidV1 {
    fn from(cid: &Cid) -> Self {
        ReplCidV1 {
            ts: cid.ts,
            s_uuid: cid.s_uuid,
        }
    }
}

impl From<ReplCidV1> for Cid {
    fn from(cid: ReplCidV1) -> Self {
        Cid {
            ts: cid.ts,
            s_uuid: cid.s_uuid,
        }
    }
}

impl From<&ReplCidV1> for Cid {
    fn from(cid: &ReplCidV1) -> Self {
        Cid {
            ts: cid.ts,
            s_uuid: cid.s_uuid,
        }
    }
}

/// An anchored CID range. This contains a minimum and maximum range of CID times for a server,
/// and also includes the list of all CIDs that occur between those two points. This allows these
/// extra change "anchors" to be injected into the consumer RUV during an incremental. Once
/// inserted, these anchors prevent RUV trimming from creating "jumps" due to idle servers.
#[derive(Serialize, Deserialize, PartialEq, Eq)]
pub struct ReplAnchoredCidRange {
    #[serde(rename = "m")]
    pub ts_min: Duration,
    #[serde(rename = "a", default)]
    pub anchors: Vec<Duration>,
    #[serde(rename = "x")]
    pub ts_max: Duration,
}

impl fmt::Debug for ReplAnchoredCidRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:032} --{}-> {:032}",
            self.ts_min.as_nanos(),
            self.anchors.len(),
            self.ts_max.as_nanos()
        )
    }
}

/// A CID range. This contains the minimum and maximum values of a range. This is used for
/// querying the RUV to select all elements in this range.
#[derive(Serialize, Deserialize, PartialEq, Eq)]
pub struct ReplCidRange {
    #[serde(rename = "m")]
    pub ts_min: Duration,
    #[serde(rename = "x")]
    pub ts_max: Duration,
}

impl fmt::Debug for ReplCidRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:032} -> {:032}",
            self.ts_min.as_nanos(),
            self.ts_max.as_nanos()
        )
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub enum ReplRuvRange {
    V1 {
        domain_uuid: Uuid,
        ranges: BTreeMap<Uuid, ReplCidRange>,
    },
}

impl ReplRuvRange {
    pub fn is_empty(&self) -> bool {
        match self {
            ReplRuvRange::V1 { ranges, .. } => ranges.is_empty(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct ReplAttrStateV1 {
    cid: ReplCidV1,
    attr: Option<DbValueSetV2>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub enum ReplStateV1 {
    Live {
        at: ReplCidV1,
        // Also add AT here for breaking entry origin on conflict.
        attrs: BTreeMap<Attribute, ReplAttrStateV1>,
    },
    Tombstone {
        at: ReplCidV1,
    },
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
// I think partial entries should be separate? This clearly implies a refresh.
pub struct ReplEntryV1 {
    uuid: Uuid,
    // Change State
    st: ReplStateV1,
}

impl ReplEntryV1 {
    pub fn new(entry: &EntrySealedCommitted, schema: &SchemaReadTransaction) -> ReplEntryV1 {
        let cs = entry.get_changestate();
        let uuid = entry.get_uuid();

        let st = match cs.current() {
            State::Live { at, changes } => {
                let live_attrs = entry.get_ava();

                let attrs = changes
                    .iter()
                    .filter_map(|(attr_name, cid)| {
                        if schema.is_replicated(attr_name) {
                            let live_attr = live_attrs.get(attr_name);

                            let cid = cid.into();
                            let attr = live_attr.and_then(|maybe|
                                // There is a quirk in the way we currently handle certain
                                // types of adds/deletes that it may be possible to have an
                                // empty value set still in memory on a supplier. In the future
                                // we may make it so in memory valuesets can be empty and sent
                                // but for now, if it's an empty set in any capacity, we map
                                // to None and just send the Cid since they have the same result
                                // on how the entry/attr state looks at each end.
                                if maybe.is_empty() {
                                    None
                                } else {
                                    Some(maybe.to_db_valueset_v2())
                                }
                            );

                            Some((attr_name.clone(), ReplAttrStateV1 { cid, attr }))
                        } else {
                            None
                        }
                    })
                    .collect();

                ReplStateV1::Live {
                    at: at.into(),
                    attrs,
                }
            }
            State::Tombstone { at } => ReplStateV1::Tombstone { at: at.into() },
        };

        ReplEntryV1 { uuid, st }
    }

    pub fn rehydrate(self) -> Result<(EntryChangeState, Eattrs), OperationError> {
        match self.st {
            ReplStateV1::Live { at, attrs } => {
                trace!("{:?} {:#?}", at, attrs);
                // We need to build two sets, one for the Entry Change States, and one for the
                // Eattrs.
                let mut changes = BTreeMap::default();
                let mut eattrs = Eattrs::default();

                for (attr_name, ReplAttrStateV1 { cid, attr }) in attrs.into_iter() {
                    let cid: Cid = cid.into();

                    if let Some(attr_value) = attr {
                        let v = valueset::from_db_valueset_v2(attr_value).inspect_err(|err| {
                            error!(?err, "Unable to restore valueset for {}", attr_name);
                        })?;
                        if eattrs.insert(attr_name.clone(), v).is_some() {
                            error!(
                                "Impossible eattrs state, attribute {} appears to be duplicated!",
                                attr_name
                            );
                            return Err(OperationError::InvalidEntryState);
                        }
                    }

                    if changes.insert(attr_name.clone(), cid).is_some() {
                        error!(
                            "Impossible changes state, attribute {} appears to be duplicated!",
                            attr_name
                        );
                        return Err(OperationError::InvalidEntryState);
                    }
                }

                let at: Cid = at.into();

                let ecstate = EntryChangeState {
                    st: State::Live { at, changes },
                };
                Ok((ecstate, eattrs))
            }
            ReplStateV1::Tombstone { at } => {
                let at: Cid = at.into();

                let mut eattrs = Eattrs::default();

                let class_ava = vs_iutf8n![EntryClass::Object.into(), EntryClass::Tombstone.into()];
                let last_mod_ava = vs_cid![at];

                eattrs.insert(Attribute::Uuid, vs_uuid![self.uuid]);
                eattrs.insert(Attribute::Class, class_ava);
                eattrs.insert(Attribute::LastModifiedCid, last_mod_ava);

                let ecstate = EntryChangeState {
                    st: State::Tombstone { at },
                };

                Ok((ecstate, eattrs))
            }
        }
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
// I think partial entries should be separate? This clearly implies a refresh.
pub struct ReplIncrementalEntryV1 {
    pub(crate) uuid: Uuid,
    // Change State
    pub(crate) st: ReplStateV1,
}

impl ReplIncrementalEntryV1 {
    pub fn new(
        entry: &EntrySealedCommitted,
        schema: &SchemaReadTransaction,
        ctx_range: &BTreeMap<Uuid, ReplCidRange>,
    ) -> ReplIncrementalEntryV1 {
        let cs = entry.get_changestate();
        let uuid = entry.get_uuid();

        let st = match cs.current() {
            State::Live { at, changes } => {
                // Only put attributes into the change state that were changed within the range that was
                // requested.
                let live_attrs = entry.get_ava();

                let attrs = changes
                    .iter()
                    .filter_map(|(attr_name, cid)| {
                        // If the cid is within the ctx range
                        let within = schema.is_replicated(attr_name)
                            && ctx_range
                                .get(&cid.s_uuid)
                                .map(|repl_range| {
                                    // Supply anything up to and including.
                                    cid.ts <= repl_range.ts_max &&
                                    // ts_min is always what the consumer already has.
                                    cid.ts > repl_range.ts_min
                                })
                                // If not present in the range, assume it's not needed.
                                .unwrap_or(false);

                        // Then setup to supply it.
                        if within {
                            let live_attr = live_attrs.get(attr_name);
                            let cid = cid.into();
                            let attr = live_attr.and_then(|maybe| {
                                if maybe.is_empty() {
                                    None
                                } else {
                                    Some(maybe.to_db_valueset_v2())
                                }
                            });

                            Some((attr_name.clone(), ReplAttrStateV1 { cid, attr }))
                        } else {
                            None
                        }
                    })
                    .collect();

                ReplStateV1::Live {
                    at: at.into(),
                    attrs,
                }
            }
            // Don't care what the at is - send the tombstone.
            State::Tombstone { at } => ReplStateV1::Tombstone { at: at.into() },
        };

        ReplIncrementalEntryV1 { uuid, st }
    }

    pub fn rehydrate(self) -> Result<(Uuid, EntryChangeState, Eattrs), OperationError> {
        match self.st {
            ReplStateV1::Live { at, attrs } => {
                trace!("{:?} {:#?}", at, attrs);
                let mut changes = BTreeMap::default();
                let mut eattrs = Eattrs::default();

                for (attr_name, ReplAttrStateV1 { cid, attr }) in attrs.into_iter() {
                    let cid: Cid = cid.into();

                    if let Some(attr_value) = attr {
                        let v = valueset::from_db_valueset_v2(attr_value).inspect_err(|err| {
                            error!(?err, "Unable to restore valueset for {}", attr_name);
                        })?;
                        if eattrs.insert(attr_name.clone(), v).is_some() {
                            error!(
                                "Impossible eattrs state, attribute {} appears to be duplicated!",
                                attr_name
                            );
                            return Err(OperationError::InvalidEntryState);
                        }
                    }

                    if changes.insert(attr_name.clone(), cid).is_some() {
                        error!(
                            "Impossible changes state, attribute {} appears to be duplicated!",
                            attr_name
                        );
                        return Err(OperationError::InvalidEntryState);
                    }
                }

                let at: Cid = at.into();

                let ecstate = EntryChangeState {
                    st: State::Live { at, changes },
                };
                Ok((self.uuid, ecstate, eattrs))
            }
            ReplStateV1::Tombstone { at } => {
                let at: Cid = at.into();
                let eattrs = Eattrs::default();
                let ecstate = EntryChangeState {
                    st: State::Tombstone { at },
                };
                Ok((self.uuid, ecstate, eattrs))
            }
        }
    }
}

// From / Into Entry

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ReplRefreshContext {
    V1 {
        domain_version: DomainVersion,
        domain_devel: bool,
        domain_uuid: Uuid,
        // We need to send the current state of the ranges to populate into
        // the ranges so that lookups and ranges work properly.
        ranges: BTreeMap<Uuid, ReplAnchoredCidRange>,
        schema_entries: Vec<ReplEntryV1>,
        meta_entries: Vec<ReplEntryV1>,
        entries: Vec<ReplEntryV1>,
    },
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ReplIncrementalContext {
    DomainMismatch,
    NoChangesAvailable,
    RefreshRequired,
    UnwillingToSupply,
    V1 {
        domain_version: DomainVersion,
        #[serde(default)]
        domain_patch_level: u32,
        domain_uuid: Uuid,
        // We need to send the current state of the ranges to populate into
        // the ranges so that lookups and ranges work properly, and the
        // consumer ends with the same state as we have (or at least merges)
        // it with this.
        ranges: BTreeMap<Uuid, ReplAnchoredCidRange>,
        schema_entries: Vec<ReplIncrementalEntryV1>,
        meta_entries: Vec<ReplIncrementalEntryV1>,
        entries: Vec<ReplIncrementalEntryV1>,
    },
}
