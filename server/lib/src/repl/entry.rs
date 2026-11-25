use super::cid::Cid;
use crate::{
    be::{dbrepl::DbEntryChangeState, dbvalue::DbCidV1},
    entry::Eattrs,
    prelude::*,
    schema::SchemaTransaction,
};

use std::collections::BTreeMap;

#[derive(Debug, Clone)]
pub enum State {
    Live {
        at: Cid,
        changes: BTreeMap<Attribute, Cid>,
    },
    Tombstone {
        at: Cid,
    },
}

#[derive(Debug, Clone)]
pub struct EntryChangeState {
    pub(super) st: State,
}

impl EntryChangeState {
    pub fn new(cid: &Cid, attrs: &Eattrs, _schema: &dyn SchemaTransaction) -> Self {
        let changes = attrs.keys().cloned().map(|attr| (attr, *cid)).collect();

        let st = State::Live { at: *cid, changes };

        EntryChangeState { st }
    }

    pub fn new_without_schema(cid: &Cid, attrs: &Eattrs) -> Self {
        let class = attrs.get(&Attribute::Class);
        let st = if class
            .as_ref()
            .map(|c| c.contains(&EntryClass::Tombstone.to_partialvalue()))
            .unwrap_or(false)
        {
            State::Tombstone { at: *cid }
        } else {
            let changes = attrs.keys().cloned().map(|attr| (attr, *cid)).collect();

            State::Live { at: *cid, changes }
        };

        EntryChangeState { st }
    }

    pub(crate) fn to_db_changestate(&self) -> DbEntryChangeState {
        match &self.st {
            State::Live { at, changes } => {
                let at = DbCidV1 {
                    server_id: at.s_uuid,
                    timestamp: at.ts,
                };

                let changes = changes
                    .iter()
                    .map(|(attr, cid)| {
                        (
                            attr.clone(),
                            DbCidV1 {
                                server_id: cid.s_uuid,
                                timestamp: cid.ts,
                            },
                        )
                    })
                    .collect();

                DbEntryChangeState::V1Live { at, changes }
            }
            State::Tombstone { at } => {
                let at = DbCidV1 {
                    server_id: at.s_uuid,
                    timestamp: at.ts,
                };

                DbEntryChangeState::V1Tombstone { at }
            }
        }
    }

    pub(crate) fn from_db_changestate(db_ecstate: DbEntryChangeState) -> Self {
        match db_ecstate {
            DbEntryChangeState::V1Live { at, changes } => {
                let at = Cid {
                    s_uuid: at.server_id,
                    ts: at.timestamp,
                };

                let changes = changes
                    .iter()
                    .map(|(attr, cid)| {
                        (
                            attr.clone(),
                            Cid {
                                s_uuid: cid.server_id,
                                ts: cid.timestamp,
                            },
                        )
                    })
                    .collect();

                EntryChangeState {
                    st: State::Live { at, changes },
                }
            }
            DbEntryChangeState::V1Tombstone { at } => EntryChangeState {
                st: State::Tombstone {
                    at: Cid {
                        s_uuid: at.server_id,
                        ts: at.timestamp,
                    },
                },
            },
        }
    }

    pub(crate) fn build(st: State) -> Self {
        EntryChangeState { st }
    }

    pub fn current(&self) -> &State {
        &self.st
    }

    pub fn at(&self) -> &Cid {
        match &self.st {
            State::Live { at, .. } => at,
            State::Tombstone { at } => at,
        }
    }

    pub(crate) fn stub(&self) -> Self {
        let st = match &self.st {
            State::Live { at, changes: _ } => State::Live {
                at: *at,
                changes: Default::default(),
            },
            State::Tombstone { at } => State::Tombstone { at: *at },
        };
        EntryChangeState { st }
    }

    pub fn change_ava(&mut self, cid: &Cid, attr: &Attribute) {
        match &mut self.st {
            State::Live {
                at: _,
                ref mut changes,
            } => {
                if let Some(change) = changes.get_mut(attr) {
                    // Update the cid.
                    if change != cid {
                        *change = *cid
                    }
                } else {
                    changes.insert(attr.clone(), *cid);
                }
            }
            State::Tombstone { .. } => {
                unreachable!();
            }
        }
    }

    pub fn tombstone(&mut self, cid: &Cid) {
        match &mut self.st {
            State::Live { at: _, changes: _ } => self.st = State::Tombstone { at: *cid },
            State::Tombstone { .. } => {} // no-op
        };
    }

    pub fn can_delete(&self, cid: &Cid) -> bool {
        match &self.st {
            State::Live { .. } => false,
            State::Tombstone { at } => at < cid,
        }
    }

    pub fn is_live(&self) -> bool {
        match &self.st {
            State::Live { .. } => true,
            State::Tombstone { .. } => false,
        }
    }

    pub fn contains_tail_cid(&self, cid: &Cid) -> bool {
        // This is slow? Is it needed?
        match &self.st {
            State::Live { at: _, changes } => changes.values().any(|change| change == cid),
            State::Tombstone { at } => at == cid,
        }
    }

    pub(crate) fn get_max_cid(&self) -> &Cid {
        match &self.st {
            State::Live { at, changes } => changes.values().max().unwrap_or(at),
            State::Tombstone { at } => at,
        }
    }

    #[cfg(test)]
    pub(crate) fn get_attr_cid(&self, attr: &Attribute) -> Option<&Cid> {
        match &self.st {
            State::Live { at: _, changes } => changes.get(attr),
            State::Tombstone { at: _ } => None,
        }
    }

    pub(crate) fn cid_iter(&self) -> Vec<&Cid> {
        match &self.st {
            State::Live { at: _, changes } => {
                let mut v: Vec<_> = changes.values().collect();
                v.sort_unstable();
                v.dedup();
                v
            }
            State::Tombstone { at } => vec![at],
        }
    }

    pub fn retain<F>(&mut self, f: F)
    where
        F: FnMut(&Attribute, &mut Cid) -> bool,
    {
        match &mut self.st {
            State::Live { at: _, changes } => changes.retain(f),
            State::Tombstone { .. } => {}
        }
    }

    #[instrument(level = "trace", name = "verify", skip_all)]
    pub fn verify(
        &self,
        schema: &dyn SchemaTransaction,
        expected_attrs: &Eattrs,
        entry_id: u64,
        results: &mut Vec<Result<(), ConsistencyError>>,
    ) {
        let class = expected_attrs.get(&Attribute::Class);
        let is_ts = class
            .as_ref()
            .map(|c| c.contains(&EntryClass::Tombstone.to_partialvalue()))
            .unwrap_or(false);

        match (&self.st, is_ts) {
            (State::Live { at, changes }, false) => {
                // Every change must be after at.

                // Check that all attrs from expected, have a value in our changes.
                let inconsistent: Vec<_> = expected_attrs
                    .keys()
                    .filter(|attr| {
                        /*
                         * If the attribute is a replicated attribute, and it is NOT present
                         * in the change state then we are in a desync state.
                         *
                         * However, we don't check the inverse - if an entry is in the change state
                         * but is NOT replicated by schema. This is because there is is a way to
                         * delete an attribute in schema which will then prevent future replications
                         * of that value. However the value, while not being updated, will retain
                         * a state entry in the change state.
                         *
                         * For the entry to then be replicated once more, it would require it's schema
                         * attributes to be re-added and then the replication will resume from whatever
                         * receives the changes first. Generally there are lots of desync and edge
                         * cases here, which is why we pretty much don't allow schema to be deleted
                         * but we have to handle it here due to a test case that simulates this.
                         */
                        let change_cid_present = if let Some(change_cid) = changes.get(*attr) {
                        if change_cid < at {
                            warn!("changestate has a change that occurs before entry was created! {attr:?} {change_cid:?} {at:?}");
                            results.push(Err(ConsistencyError::ChangeStateDesynchronised(entry_id)));
                        }
                           true
                        } else {
                           false
                        };

                        // Only assert this when we actually have replication requirements.
                        let desync = schema.is_replicated(attr) && !change_cid_present;
                        if desync {
                            debug!(%entry_id, %attr, %desync);
                        }
                        desync
                    })
                    .collect();

                if inconsistent.is_empty() {
                    trace!("changestate is synchronised");
                } else {
                    warn!("changestate has desynchronised! Missing state attrs {inconsistent:?}");
                    results.push(Err(ConsistencyError::ChangeStateDesynchronised(entry_id)));
                }
            }
            (State::Tombstone { .. }, true) => {
                trace!("changestate is synchronised");
            }
            (State::Live { .. }, true) => {
                warn!("changestate has desynchronised! State Live when tombstone is true");
                results.push(Err(ConsistencyError::ChangeStateDesynchronised(entry_id)));
            }
            (State::Tombstone { .. }, false) => {
                warn!("changestate has desynchronised! State Tombstone when tombstone is false");
                results.push(Err(ConsistencyError::ChangeStateDesynchronised(entry_id)));
            }
        }
    }
}

impl PartialEq for EntryChangeState {
    fn eq(&self, rhs: &Self) -> bool {
        match (&self.st, &rhs.st) {
            (
                State::Live {
                    at: at_left,
                    changes: changes_left,
                },
                State::Live {
                    at: at_right,
                    changes: changes_right,
                },
            ) => at_left.eq(at_right) && changes_left.eq(changes_right),
            (State::Tombstone { at: at_left }, State::Tombstone { at: at_right }) => {
                at_left.eq(at_right)
            }
            (_, _) => false,
        }
    }
}
