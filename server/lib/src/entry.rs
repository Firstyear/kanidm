//! Entries are the base unit of object storage in the server. This is one of the three foundational
//! concepts along with [`filter`]s and [`schema`] that everything else builds upon.
//!
//! An [`Entry`] is a collection of attribute-value sets. There are sometimes called attribute value
//! assertions, or AVAs. The attribute is a "key" and it holds 1 to infinite associated values
//! with no ordering. An entry has many AVAs. A pseudo example, minus schema and typing:
//!
//! ```text
//! Entry {
//!   "name": ["william"],
//!   "uuid": ["..."],
//!   "mail": ["maila@example.com", "mailb@example.com"],
//! };
//! ```
//!
//! There are three rules for entries:
//! * Must have an AVA for UUID containing a single value.
//! * Any AVA with zero values will be removed.
//! * AVAs are stored with no sorting.
//!
//! For more, see the [`Entry`] type.
//!
//! [`Entry`]: struct.Entry.html
//! [`filter`]: ../filter/index.html
//! [`schema`]: ../schema/index.html

use crate::be::dbentry::{DbEntry, DbEntryVers};
use crate::be::dbvalue::DbValueSetV2;
use crate::be::{IdxKey, IdxSlope};
use crate::credential::apppwd::ApplicationPassword;
use crate::credential::Credential;
use crate::filter::{Filter, FilterInvalid, FilterResolved, FilterValidResolved};
use crate::idm::ldap::ldap_vattr_map;
use crate::modify::{Modify, ModifyInvalid, ModifyList, ModifyValid};
use crate::prelude::*;
use crate::repl::cid::Cid;
use crate::repl::entry::EntryChangeState;
use crate::repl::proto::{ReplEntryV1, ReplIncrementalEntryV1};
use crate::schema::{SchemaAttribute, SchemaClass, SchemaTransaction};
use crate::server::access::AccessEffectivePermission;
use crate::value::{
    ApiToken, CredentialType, IndexType, IntentTokenState, Oauth2Session, PartialValue, Session,
    SyntaxType, Value,
};
use crate::valueset::{self, ScimResolveStatus, ValueSet, ValueSetSpn};
use compact_jwt::JwsEs256Signer;
use crypto_glue::s256::Sha256Output;
use hashbrown::{HashMap, HashSet};
use kanidm_proto::internal::ImageValue;
use kanidm_proto::internal::{
    ConsistencyError, Filter as ProtoFilter, OperationError, SchemaError, UiHint,
};
use kanidm_proto::scim_v1::server::ScimEffectiveAccess;
use kanidm_proto::v1::Entry as ProtoEntry;
use ldap3_proto::simple::{LdapPartialAttribute, LdapSearchResultEntry};
use openssl::ec::EcKey;
use openssl::pkey::{Private, Public};
use std::cmp::Ordering;
pub use std::collections::BTreeSet as Set;
use std::collections::{BTreeMap as Map, BTreeMap, BTreeSet};
use std::sync::Arc;
use time::OffsetDateTime;
use tracing::trace;
use uuid::Uuid;
use webauthn_rs::prelude::{
    AttestationCaList, AttestedPasskey as AttestedPasskeyV4, Passkey as PasskeyV4,
};

pub type EntryInitNew = Entry<EntryInit, EntryNew>;
pub type EntryInvalidNew = Entry<EntryInvalid, EntryNew>;
pub type EntryRefreshNew = Entry<EntryRefresh, EntryNew>;
pub type EntrySealedNew = Entry<EntrySealed, EntryNew>;
pub type EntryValidCommitted = Entry<EntryValid, EntryCommitted>;
pub type EntrySealedCommitted = Entry<EntrySealed, EntryCommitted>;
pub type EntryInvalidCommitted = Entry<EntryInvalid, EntryCommitted>;
pub type EntryReducedCommitted = Entry<EntryReduced, EntryCommitted>;
pub type EntryTuple = (Arc<EntrySealedCommitted>, EntryInvalidCommitted);

pub type EntryIncrementalNew = Entry<EntryIncremental, EntryNew>;
pub type EntryIncrementalCommitted = Entry<EntryIncremental, EntryCommitted>;

// Entry should have a lifecycle of types. This is Raw (modifiable) and Entry (verified).
// This way, we can move between them, but only certain actions are possible on either
// This means modifications happen on Raw, but to move to Entry, you schema normalise.
// Vice versa, you can for free, move to Raw, but you lose the validation.

// Because this is type system it's "free" in the end, and means we force validation
// at the correct and required points of the entries life.

// This is specifically important for the commit to the backend, as we only want to
// commit validated types.

// Has never been in the DB, so doesn't have an ID.
#[derive(Clone, Debug)]
pub struct EntryNew; // new

// It's been in the DB, so it has an id
#[derive(Clone, Debug)]
pub struct EntryCommitted {
    id: u64,
}

#[derive(Clone, Debug)]
pub struct EntryInit;

/*  |
 *  | Init comes from a proto entry, it's new.
 *  | We add the current Cid before we allow mods.
 *  V
 */

#[derive(Clone, Debug)]
pub struct EntryInvalid {
    cid: Cid,
    ecstate: EntryChangeState,
}

// Alternate path - this entry came from a full refresh, and already has an entry change state.
#[derive(Clone, Debug)]
pub struct EntryRefresh {
    ecstate: EntryChangeState,
}

// Alternate path - this entry came from an incremental replication.
#[derive(Clone, Debug)]
pub struct EntryIncremental {
    // Must have a uuid, else we can't proceed at all.
    uuid: Uuid,
    ecstate: EntryChangeState,
}

/*  |
 *  | The changes made within this entry are validated by the schema.
 *  V
 */

#[derive(Clone, Debug)]
pub struct EntryValid {
    // Asserted with schema, so we know it has a UUID now ...
    uuid: Uuid,
    ecstate: EntryChangeState,
}

/*  |
 *  | The changes are extracted into the changelog as needed, creating a
 *  | stable database entry.
 *  V
 */

#[derive(Clone, Debug)]
pub struct EntrySealed {
    uuid: Uuid,
    ecstate: EntryChangeState,
}

/*  |
 *  | The entry has access controls applied to reduce what is yielded to a client
 *  V
 */

#[derive(Clone, Debug)]
pub struct EntryReduced {
    uuid: Uuid,
    effective_access: Option<Box<AccessEffectivePermission>>,
}

// One day this is going to be Map<Attribute, ValueSet> - @yaleman
// Today is that day - @firstyear
pub type Eattrs = Map<Attribute, ValueSet>;

pub trait GetUuid {
    fn get_uuid(&self) -> Uuid;
}

pub trait Committed {}

impl Committed for EntrySealed {}
impl Committed for EntryReduced {}

pub(crate) fn compare_attrs(left: &Eattrs, right: &Eattrs) -> bool {
    // We can't shortcut based on len because cid mod may not be present.
    // Build the set of all keys between both.
    let allkeys: Set<&Attribute> = left
        .keys()
        .chain(right.keys())
        .filter(|k| *k != &Attribute::LastModifiedCid && *k != &Attribute::CreatedAtCid)
        .collect();

    allkeys.into_iter().all(|k| {
        // Both must be Some, and both must have the same interiors.
        let left_vs = left.get(k);
        let right_vs = right.get(k);
        let r = match (left_vs, right_vs) {
            (Some(l), Some(r)) => l.eq(r),
            _ => false,
        };
        if !r {
            trace!(?k, ?left_vs, ?right_vs, "compare_attrs_allkeys");
        }
        r
    })
}

/// Entry is the core data storage type of the server. Almost every aspect of the server is
/// designed to read, handle and manipulate entries.
///
/// Entries store attribute value assertions, or AVA. These are sets of key-values.
///
/// Entries have a lifecycle within a single operation, and as part of replication.
/// The lifecycle for operations is defined through state and valid types. Each entry has a pair
/// Of these types at anytime. The first is the AVA [`schema`] and [`access`] control assertion
/// state. This is represented by the type `VALID` as one of `EntryValid`, `EntryInvalid` or
/// `EntryReduced`. Every entry starts as `EntryInvalid`, and when checked by the schema for
/// correctness, transitions to `EntryValid`. While an entry is `EntryValid` it can not be
/// altered - you must invalidate it to `EntryInvalid`, then modify, then check again.
/// An entry that has had access controls applied moves from `EntryValid` to `EntryReduced`,
/// to show that the AVAs have reduced to the valid read set of the current [`event`] user.
///
/// The second type of `STATE` represents the database commit state and internal db ID's. A
/// new entry that has never been committed is `EntryNew`, but an entry that has been retrieved
/// from the database is `EntryCommitted`. This affects the operations you can apply IE modify
/// or delete.
///
/// These types exist to prevent at compile time, mishandling of Entries, to ensure they are always
/// handled with the correct lifecycles and processes.
///
/// [`schema`]: ../schema/index.html
/// [`access`]: ../access/index.html
/// [`event`]: ../event/index.html
pub struct Entry<VALID, STATE> {
    valid: VALID,
    state: STATE,
    // We may need to change this to Set to allow borrow of Value -> PartialValue for lookups.
    attrs: Eattrs,
}

impl<VALID, STATE> std::fmt::Debug for Entry<VALID, STATE>
where
    STATE: std::fmt::Debug,
    VALID: std::fmt::Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("Entry<EntrySealed, _>")
            .field("state", &self.state)
            .field("valid", &self.valid)
            .field("attrs", &self.attrs)
            .finish()
    }
}

impl<STATE> std::fmt::Display for Entry<EntrySealed, STATE>
where
    STATE: Clone,
{
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.get_uuid())
    }
}

impl<STATE> std::fmt::Display for Entry<EntryInit, STATE>
where
    STATE: Clone,
{
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Entry in initial state")
    }
}

impl<STATE> Entry<EntryInit, STATE>
where
    STATE: Clone,
{
    /// Get the uuid of this entry.
    pub fn get_uuid(&self) -> Option<Uuid> {
        self.attrs
            .get(&Attribute::Uuid)
            .and_then(|vs| vs.to_uuid_single())
    }
}

impl Default for Entry<EntryInit, EntryNew> {
    fn default() -> Self {
        Self::new()
    }
}

impl FromIterator<(Attribute, ValueSet)> for EntryInitNew {
    fn from_iter<I: IntoIterator<Item = (Attribute, ValueSet)>>(iter: I) -> Self {
        let attrs = Eattrs::from_iter(iter);

        Entry {
            valid: EntryInit,
            state: EntryNew,
            attrs,
        }
    }
}

impl Entry<EntryInit, EntryNew> {
    pub fn new() -> Self {
        Entry {
            // This means NEVER COMMITTED
            valid: EntryInit,
            state: EntryNew,
            attrs: Map::new(),
        }
    }

    /// Consume a Protocol Entry from JSON, and validate and process the data into an internal
    /// [`Entry`] type.
    pub fn from_proto_entry(
        e: &ProtoEntry,
        qs: &mut QueryServerWriteTransaction,
    ) -> Result<Self, OperationError> {
        trace!("from_proto_entry");
        // Why not the trait? In the future we may want to extend
        // this with server aware functions for changes of the
        // incoming data.

        // Somehow we need to take the tree of e attrs, and convert
        // all ref types to our types ...
        let map2: Result<Eattrs, OperationError> = e
            .attrs
            .iter()
            .filter(|(_, v)| !v.is_empty())
            .map(|(k, v)| {
                trace!(?k, ?v, "attribute");
                let attr_nk = Attribute::from(k.as_str());
                let nv = valueset::from_result_value_iter(
                    v.iter().map(|vr| qs.clone_value(&attr_nk, vr)),
                );
                trace!(?nv, "new valueset transform");
                match nv {
                    Ok(nvi) => Ok((attr_nk, nvi)),
                    Err(e) => Err(e),
                }
            })
            .collect();

        let x = map2?;

        Ok(Entry {
            state: EntryNew,
            valid: EntryInit,
            attrs: x,
        })
    }

    /// Given a proto entry in JSON formed as a serialised string, processed that string
    /// into an Entry.
    #[instrument(level = "debug", skip_all)]
    pub fn from_proto_entry_str(
        es: &str,
        qs: &mut QueryServerWriteTransaction,
    ) -> Result<Self, OperationError> {
        if cfg!(test) {
            if es.len() > 256 {
                let (dsp_es, _) = es.split_at(255);
                trace!("Parsing -> {}...", dsp_es);
            } else {
                trace!("Parsing -> {}", es);
            }
        }
        // str -> Proto entry
        let pe: ProtoEntry = serde_json::from_str(es).map_err(|e| {
            // We probably shouldn't print ES here because that would allow users
            // to inject content into our logs :)
            admin_error!(?e, "SerdeJson Failure");
            OperationError::SerdeJsonError
        })?;
        // now call from_proto_entry
        Self::from_proto_entry(&pe, qs)
    }

    /// Assign the Change Identifier to this Entry, allowing it to be modified and then
    /// written to the `Backend`
    pub fn assign_cid(
        mut self,
        cid: Cid,
        schema: &dyn SchemaTransaction,
    ) -> Entry<EntryInvalid, EntryNew> {
        /*
         * Create the change log. This must be the last thing BEFORE we return!
         * This is because we need to capture the set_last_changed attribute in
         * the create transition.
         */
        let ecstate = EntryChangeState::new(&cid, &self.attrs, schema);

        // Since the entry is now created, and modified here, we set the initial CID
        // values.
        let cv = vs_cid![cid.clone()];
        let _ = self.attrs.insert(Attribute::LastModifiedCid, cv);
        let cv = vs_cid![cid.clone()];
        let _ = self.attrs.insert(Attribute::CreatedAtCid, cv);

        Entry {
            valid: EntryInvalid { cid, ecstate },
            state: EntryNew,
            attrs: self.attrs,
        }
    }

    /// Compare this entry to another.
    pub fn compare(&self, rhs: &Entry<EntrySealed, EntryCommitted>) -> bool {
        compare_attrs(&self.attrs, &rhs.attrs)
    }

    /// ⚠️  This function bypasses the db commit and creates invalid replication metadata.
    /// The entry it creates can never be replicated.
    /// This is a TEST ONLY method and will never be exposed in production.
    #[cfg(test)]
    pub fn into_invalid_new(mut self) -> Entry<EntryInvalid, EntryNew> {
        let cid = Cid::new_zero();
        self.set_last_changed(cid.clone());

        let ecstate = EntryChangeState::new_without_schema(&cid, &self.attrs);

        Entry {
            valid: EntryInvalid { cid, ecstate },
            state: EntryNew,
            attrs: self.attrs,
        }
    }

    /// ⚠️  This function bypasses the db commit and creates invalid replication metadata.
    /// The entry it creates can never be replicated.
    /// This is a TEST ONLY method and will never be exposed in production.
    #[cfg(test)]
    pub fn into_valid_new(mut self) -> Entry<EntryValid, EntryNew> {
        let cid = Cid::new_zero();
        self.set_last_changed(cid.clone());
        let ecstate = EntryChangeState::new_without_schema(&cid, &self.attrs);

        Entry {
            valid: EntryValid {
                ecstate,
                uuid: self.get_uuid().expect("Invalid uuid"),
            },
            state: EntryNew,
            attrs: self.attrs,
        }
    }

    /// ⚠️  This function bypasses the db commit, assigns fake db ids, and invalid replication metadata.
    /// The entry it creates can never be committed safely or replicated.
    /// This is a TEST ONLY method and will never be exposed in production.
    #[cfg(test)]
    pub fn into_sealed_committed(mut self) -> Entry<EntrySealed, EntryCommitted> {
        let cid = Cid::new_zero();
        self.set_last_changed(cid.clone());
        let ecstate = EntryChangeState::new_without_schema(&cid, &self.attrs);
        let uuid = self.get_uuid().unwrap_or_else(Uuid::new_v4);
        Entry {
            valid: EntrySealed { uuid, ecstate },
            state: EntryCommitted { id: 0 },
            attrs: self.attrs,
        }
    }

    /// ⚠️  This function bypasses the db commit and creates invalid replication metadata.
    /// The entry it creates can never be replicated.
    /// This is a TEST ONLY method and will never be exposed in production.
    #[cfg(test)]
    pub fn into_sealed_new(mut self) -> Entry<EntrySealed, EntryNew> {
        let cid = Cid::new_zero();
        self.set_last_changed(cid.clone());
        let ecstate = EntryChangeState::new_without_schema(&cid, &self.attrs);

        Entry {
            valid: EntrySealed {
                uuid: self.get_uuid().expect("Invalid uuid"),
                ecstate,
            },
            state: EntryNew,
            attrs: self.attrs,
        }
    }

    //              ⚠️   replication safety  ⚠️
    // These functions are SAFE because they occur in the EntryInit
    // state, which precedes the generation of the initial Create
    // event for the attribute.
    /// Add an attribute-value-assertion to this Entry.
    pub fn add_ava(&mut self, attr: Attribute, value: Value) {
        self.add_ava_int(attr, value);
    }

    pub fn pop_ava<A: AsRef<Attribute>>(&mut self, attr: A) -> Option<ValueSet> {
        self.attrs.remove(attr.as_ref())
    }

    pub fn remove_ava<A: AsRef<Attribute>>(&mut self, attr: A) {
        self.pop_ava(attr);
    }

    /// Set the content of this ava with this valueset, ignoring the previous data.
    pub fn set_ava_set(&mut self, attr: &Attribute, vs: ValueSet) {
        self.attrs.insert(attr.clone(), vs);
    }

    /// Replace the existing content of an attribute set of this Entry, with a new set of Values.
    pub fn set_ava<T>(&mut self, attr: Attribute, iter: T)
    where
        T: IntoIterator<Item = Value>,
    {
        self.set_ava_iter_int(attr, iter);
    }

    pub fn get_ava_mut<A: AsRef<Attribute>>(&mut self, attr: A) -> Option<&mut ValueSet> {
        self.attrs.get_mut(attr.as_ref())
    }
}

impl From<SchemaAttribute> for EntryInitNew {
    fn from(value: SchemaAttribute) -> Self {
        EntryInitNew::from(&value)
    }
}

impl From<&SchemaAttribute> for EntryInitNew {
    fn from(s: &SchemaAttribute) -> Self {
        // Build the Map of the attributes
        let mut attrs = Eattrs::new();
        attrs.insert(Attribute::AttributeName, vs_iutf8![s.name.as_str()]);
        attrs.insert(Attribute::Description, vs_utf8![s.description.to_owned()]);
        attrs.insert(Attribute::Uuid, vs_uuid![s.uuid]);
        attrs.insert(Attribute::MultiValue, vs_bool![s.multivalue]);
        attrs.insert(Attribute::Phantom, vs_bool![s.phantom]);
        attrs.insert(Attribute::SyncAllowed, vs_bool![s.sync_allowed]);
        attrs.insert(Attribute::Replicated, vs_bool![s.replicated.into()]);
        attrs.insert(Attribute::Unique, vs_bool![s.unique]);
        attrs.insert(Attribute::Indexed, vs_bool![s.indexed]);
        attrs.insert(Attribute::Syntax, vs_syntax![s.syntax]);
        attrs.insert(
            Attribute::Class,
            vs_iutf8![
                EntryClass::Object.into(),
                EntryClass::System.into(),
                EntryClass::AttributeType.into()
            ],
        );

        // Insert stuff.

        Entry {
            valid: EntryInit,
            state: EntryNew,
            attrs,
        }
    }
}

impl From<SchemaClass> for EntryInitNew {
    fn from(value: SchemaClass) -> Self {
        EntryInitNew::from(&value)
    }
}

impl From<&SchemaClass> for EntryInitNew {
    fn from(s: &SchemaClass) -> Self {
        let mut attrs = Eattrs::new();
        attrs.insert(Attribute::ClassName, vs_iutf8![s.name.as_str()]);
        attrs.insert(Attribute::Description, vs_utf8![s.description.to_owned()]);
        attrs.insert(Attribute::SyncAllowed, vs_bool![s.sync_allowed]);
        attrs.insert(Attribute::Uuid, vs_uuid![s.uuid]);
        attrs.insert(
            Attribute::Class,
            vs_iutf8![
                EntryClass::Object.into(),
                EntryClass::System.into(),
                EntryClass::ClassType.into()
            ],
        );

        let vs_systemmay = ValueSetIutf8::from_iter(s.systemmay.iter().map(|sm| sm.as_str()));
        if let Some(vs) = vs_systemmay {
            attrs.insert(Attribute::SystemMay, vs);
        }

        let vs_systemmust = ValueSetIutf8::from_iter(s.systemmust.iter().map(|sm| sm.as_str()));
        if let Some(vs) = vs_systemmust {
            attrs.insert(Attribute::SystemMust, vs);
        }

        let vs_systemexcludes =
            ValueSetIutf8::from_iter(s.systemexcludes.iter().map(|sm| sm.as_str()));
        if let Some(vs) = vs_systemexcludes {
            attrs.insert(Attribute::SystemExcludes, vs);
        }

        let vs_systemsupplements =
            ValueSetIutf8::from_iter(s.systemsupplements.iter().map(|sm| sm.as_str()));
        if let Some(vs) = vs_systemsupplements {
            attrs.insert(Attribute::SystemSupplements, vs);
        }

        Entry {
            valid: EntryInit,
            state: EntryNew,
            attrs,
        }
    }
}

impl Entry<EntryRefresh, EntryNew> {
    pub fn from_repl_entry_v1(repl_entry: ReplEntryV1) -> Result<Self, OperationError> {
        // From the entry, we have to rebuild the ecstate and the attrs.
        let (ecstate, mut attrs) = repl_entry.rehydrate()?;

        // During seal, these values will be re-written, but we need them present for
        // schema validation.
        let last_mod_cid = ecstate.get_max_cid();
        let cv = vs_cid![last_mod_cid.clone()];
        let _ = attrs.insert(Attribute::LastModifiedCid, cv);

        let create_at_cid = ecstate.at();
        let cv = vs_cid![create_at_cid.clone()];
        let _ = attrs.insert(Attribute::CreatedAtCid, cv);

        Ok(Entry {
            valid: EntryRefresh { ecstate },
            state: EntryNew,
            attrs,
        })
    }
}

impl<STATE> Entry<EntryRefresh, STATE> {
    pub fn validate(
        self,
        schema: &dyn SchemaTransaction,
    ) -> Result<Entry<EntryValid, STATE>, SchemaError> {
        let uuid: Uuid = self
            .attrs
            .get(&Attribute::Uuid)
            .ok_or_else(|| SchemaError::MissingMustAttribute(vec![Attribute::Uuid]))
            .and_then(|vs| {
                vs.to_uuid_single()
                    .ok_or_else(|| SchemaError::MissingMustAttribute(vec![Attribute::Uuid]))
            })?;

        // Build the new valid entry ...
        let ne = Entry {
            valid: EntryValid {
                uuid,
                ecstate: self.valid.ecstate,
            },
            state: self.state,
            attrs: self.attrs,
        };

        ne.validate(schema).map(|()| ne)
    }
}

impl<STATE> Entry<EntryIncremental, STATE> {
    pub fn get_uuid(&self) -> Uuid {
        self.valid.uuid
    }
}

impl Entry<EntryIncremental, EntryNew> {
    fn stub_ecstate(&self) -> EntryChangeState {
        self.valid.ecstate.stub()
    }

    pub fn rehydrate(repl_inc_entry: ReplIncrementalEntryV1) -> Result<Self, OperationError> {
        let (uuid, ecstate, attrs) = repl_inc_entry.rehydrate()?;

        Ok(Entry {
            valid: EntryIncremental { uuid, ecstate },
            state: EntryNew,
            attrs,
        })
    }

    pub(crate) fn is_add_conflict(&self, db_entry: &EntrySealedCommitted) -> bool {
        use crate::repl::entry::State;
        debug_assert_eq!(self.valid.uuid, db_entry.valid.uuid);
        // This is a conflict if the state 'at' is not identical
        let self_cs = &self.valid.ecstate;
        let db_cs = db_entry.get_changestate();

        // Can only add conflict on live entries.
        match (self_cs.current(), db_cs.current()) {
            (State::Live { at: at_left, .. }, State::Live { at: at_right, .. }) => {
                at_left != at_right
            }
            // Tombstone will always overwrite.
            _ => false,
        }
    }

    pub(crate) fn resolve_add_conflict(
        &self,
        cid: &Cid,
        db_ent: &EntrySealedCommitted,
    ) -> (Option<EntrySealedNew>, EntryIncrementalCommitted) {
        use crate::repl::entry::State;
        debug_assert_eq!(self.valid.uuid, db_ent.valid.uuid);
        let self_cs = &self.valid.ecstate;
        let db_cs = db_ent.get_changestate();

        match (self_cs.current(), db_cs.current()) {
            (
                State::Live {
                    at: at_left,
                    changes: _changes_left,
                },
                State::Live {
                    at: at_right,
                    changes: _changes_right,
                },
            ) => {
                debug_assert!(at_left != at_right);
                // Determine which of the entries must become the conflict
                // and which will now persist. There are three possible cases.
                //
                // 1. The incoming ReplIncremental is after DBentry. This means RI is the
                //    conflicting node. We take no action and just return the db_ent
                //    as the valid state.
                //
                //    Since we are returning the existing database entry, we already have
                //    locally applies the needed LastModifiedCid and CreatedAtCid. We
                //    can proceed with no other changes.
                if at_left > at_right {
                    trace!("RI > DE, return DE");
                    (
                        None,
                        Entry {
                            valid: EntryIncremental {
                                uuid: db_ent.valid.uuid,
                                ecstate: db_cs.clone(),
                            },
                            state: EntryCommitted {
                                id: db_ent.state.id,
                            },
                            attrs: db_ent.attrs.clone(),
                        },
                    )
                }
                //
                // 2. The incoming ReplIncremental is before DBentry. This means our
                //    DE is the conflicting note. There are now two choices:
                //    a.  We are the origin of the DE, and thus must create the conflict
                //        entry for replication (to guarantee single create)
                //    b.  We are not the origin of the DE and so do not create a conflict
                //        entry.
                //    In both cases we update the DE with the state of RI after we have
                //    followed the above logic.
                else {
                    trace!("RI < DE, return RI");
                    // Are we the origin?
                    let conflict = if at_right.s_uuid == cid.s_uuid {
                        trace!("Origin process conflict entry");
                        // We are making a new entry!

                        let mut cnf_ent = Entry {
                            valid: EntryInvalid {
                                cid: cid.clone(),
                                ecstate: db_cs.clone(),
                            },
                            state: EntryNew,
                            attrs: db_ent.attrs.clone(),
                        };

                        // Move the current uuid to source_uuid
                        cnf_ent.add_ava(Attribute::SourceUuid, Value::Uuid(db_ent.valid.uuid));

                        // We need to make a random uuid in the conflict gen process.
                        let new_uuid = Uuid::new_v4();
                        cnf_ent.purge_ava(Attribute::Uuid);
                        cnf_ent.add_ava(Attribute::Uuid, Value::Uuid(new_uuid));
                        cnf_ent.add_ava(Attribute::Class, EntryClass::Recycled.into());
                        cnf_ent.add_ava(Attribute::Class, EntryClass::Conflict.into());

                        // Bypass add_ava here so that we don't update the ecstate with the
                        // metadata of these attrs.
                        // Setup the last changed to now.
                        let cv = vs_cid![cid.clone()];
                        let _ = cnf_ent.attrs.insert(Attribute::LastModifiedCid, cv);
                        // Set the created_at to now, since we are creating a new conflict entry here.
                        let cv = vs_cid![cid.clone()];
                        let _ = cnf_ent.attrs.insert(Attribute::CreatedAtCid, cv);

                        // Now we have to internally bypass some states.
                        // This is okay because conflict entries aren't subject
                        // to schema anyway.
                        let Entry {
                            valid: EntryInvalid { cid: _, ecstate },
                            state,
                            attrs,
                        } = cnf_ent;

                        let cnf_ent = Entry {
                            valid: EntrySealed {
                                uuid: new_uuid,
                                ecstate,
                            },
                            state,
                            attrs,
                        };

                        Some(cnf_ent)
                    } else {
                        None
                    };

                    // Since we are going to make the incoming node, we need to now
                    // populate it's last-mod and created attributes.

                    let mut attrs = self.attrs.clone();
                    let ecstate = self_cs.clone();

                    let last_mod_cid = ecstate.get_max_cid();
                    let cv = vs_cid![last_mod_cid.clone()];
                    let _ = attrs.insert(Attribute::LastModifiedCid, cv);

                    let create_at_cid = ecstate.at();
                    let cv = vs_cid![create_at_cid.clone()];
                    let _ = attrs.insert(Attribute::CreatedAtCid, cv);

                    (
                        conflict,
                        Entry {
                            valid: EntryIncremental {
                                uuid: self.valid.uuid,
                                ecstate,
                            },
                            state: EntryCommitted {
                                id: db_ent.state.id,
                            },
                            attrs,
                        },
                    )
                }
            }
            // Can never get here due to is_add_conflict above. This is because
            // a tombstone state on either branch will trigger is_add_conflict
            // causing this to be impossible to reach.
            _ => unreachable!(),
        }
    }

    pub(crate) fn merge_state(
        &self,
        db_ent: &EntrySealedCommitted,
        schema: &dyn SchemaTransaction,
        trim_cid: &Cid,
    ) -> EntryIncrementalCommitted {
        use crate::repl::entry::State;

        // Paranoid check.
        debug_assert_eq!(self.valid.uuid, db_ent.valid.uuid);

        // First, determine if either side is a tombstone. This is needed so that only
        // when both sides are live
        let self_cs = &self.valid.ecstate;
        let db_cs = db_ent.get_changestate();

        match (self_cs.current(), db_cs.current()) {
            (
                State::Live {
                    at: at_left,
                    changes: changes_left,
                },
                State::Live {
                    at: at_right,
                    changes: changes_right,
                },
            ) => {
                debug_assert_eq!(at_left, at_right);
                // Given the current db entry, compare and merge our attributes to
                // form a resultant entry attr and ecstate
                //
                // To shortcut this we dedup the attr set and then iterate.
                let mut attr_set: Vec<_> =
                    changes_left.keys().chain(changes_right.keys()).collect();
                attr_set.shrink_to_fit();
                attr_set.sort_unstable();
                attr_set.dedup();

                // Make a new ecstate and attrs set.
                let mut changes = BTreeMap::default();
                let mut eattrs = Eattrs::default();

                // Now we have the set of attrs from both sides. Lets see what state they are in!
                for attr_name in attr_set.into_iter() {
                    match (changes_left.get(attr_name), changes_right.get(attr_name)) {
                        (Some(cid_left), Some(cid_right)) => {
                            // This is the normal / usual and most "fun" case. Here we need to determine
                            // which side is latest and then do a valueset merge. This is also
                            // needing schema awareness depending on the attribute!
                            //
                            // The behaviour is very dependent on the state of the attributes and
                            // if they exist.
                            let take_left = cid_left > cid_right;

                            match (self.attrs.get(attr_name), db_ent.attrs.get(attr_name)) {
                                (Some(vs_left), Some(vs_right)) if take_left => {
                                    changes.insert(attr_name.clone(), cid_left.clone());
                                    #[allow(clippy::todo)]
                                    if let Some(merged_attr_state) =
                                        vs_left.repl_merge_valueset(vs_right, trim_cid)
                                    {
                                        // NOTE: This is for special attr types that need to merge
                                        // rather than choose content.
                                        eattrs.insert(attr_name.clone(), merged_attr_state);
                                    } else {
                                        eattrs.insert(attr_name.clone(), vs_left.clone());
                                    }
                                }
                                (Some(vs_left), Some(vs_right)) => {
                                    changes.insert(attr_name.clone(), cid_right.clone());
                                    #[allow(clippy::todo)]
                                    if let Some(merged_attr_state) =
                                        vs_right.repl_merge_valueset(vs_left, trim_cid)
                                    {
                                        // NOTE: This is for special attr types that need to merge
                                        // rather than choose content.
                                        eattrs.insert(attr_name.clone(), merged_attr_state);
                                    } else {
                                        eattrs.insert(attr_name.clone(), vs_right.clone());
                                    }
                                }
                                (Some(vs_left), None) if take_left => {
                                    changes.insert(attr_name.clone(), cid_left.clone());
                                    eattrs.insert(attr_name.clone(), vs_left.clone());
                                }
                                (Some(_vs_left), None) => {
                                    changes.insert(attr_name.clone(), cid_right.clone());
                                    // Taking right, nothing to do due to no attr.
                                }
                                (None, Some(_vs_right)) if take_left => {
                                    changes.insert(attr_name.clone(), cid_left.clone());
                                    // Taking left, nothing to do due to no attr.
                                }
                                (None, Some(vs_right)) => {
                                    changes.insert(attr_name.clone(), cid_right.clone());
                                    eattrs.insert(attr_name.clone(), vs_right.clone());
                                }
                                (None, None) if take_left => {
                                    changes.insert(attr_name.clone(), cid_left.clone());
                                    // Taking left, nothing to do due to no attr.
                                }
                                (None, None) => {
                                    changes.insert(attr_name.clone(), cid_right.clone());
                                    // Taking right, nothing to do due to no attr.
                                }
                            }
                            // End attr merging
                        }
                        (Some(cid_left), None) => {
                            // Keep the value on the left.
                            changes.insert(attr_name.clone(), cid_left.clone());
                            if let Some(valueset) = self.attrs.get(attr_name) {
                                eattrs.insert(attr_name.clone(), valueset.clone());
                            }
                        }
                        (None, Some(cid_right)) => {
                            // Keep the value on the right.
                            changes.insert(attr_name.clone(), cid_right.clone());
                            if let Some(valueset) = db_ent.attrs.get(attr_name) {
                                eattrs.insert(attr_name.clone(), valueset.clone());
                            }
                        }
                        (None, None) => {
                            // Should be impossible! At least one side or the other must have a change.
                            debug_assert!(false);
                        }
                    }
                }

                let mut ecstate = EntryChangeState::build(State::Live {
                    at: at_left.clone(),
                    changes,
                });

                // Similar to the process of "seal", remove anything that isn't
                // replicated from the ecstate (should be a no-op), and then update
                // the created/mod cid's.
                ecstate.retain(|k, _| schema.is_replicated(k));

                let cv = vs_cid![ecstate.get_max_cid().clone()];
                let _ = eattrs.insert(Attribute::LastModifiedCid, cv);

                let cv = vs_cid![ecstate.at().clone()];
                let _ = eattrs.insert(Attribute::CreatedAtCid, cv);

                Entry {
                    valid: EntryIncremental {
                        uuid: self.valid.uuid,
                        ecstate,
                    },
                    state: EntryCommitted {
                        id: db_ent.state.id,
                    },
                    attrs: eattrs,
                }
            }
            (State::Tombstone { at: left_at }, State::Live { .. }) => {
                // We have to generate the attrs here, since on replication
                // we just send the tombstone ecstate rather than attrs. Our
                // db stub also lacks these attributes too.
                let mut attrs_new: Eattrs = Map::new();
                let class_ava = vs_iutf8![EntryClass::Object.into(), EntryClass::Tombstone.into()];
                let last_mod_ava = vs_cid![left_at.clone()];
                let created_ava = vs_cid![left_at.clone()];

                attrs_new.insert(Attribute::Uuid, vs_uuid![self.valid.uuid]);
                attrs_new.insert(Attribute::Class, class_ava);
                attrs_new.insert(Attribute::LastModifiedCid, last_mod_ava);
                attrs_new.insert(Attribute::CreatedAtCid, created_ava);

                Entry {
                    valid: EntryIncremental {
                        uuid: self.valid.uuid,
                        ecstate: self.valid.ecstate.clone(),
                    },
                    state: EntryCommitted {
                        id: db_ent.state.id,
                    },
                    attrs: attrs_new,
                }
            }
            (State::Live { .. }, State::Tombstone { .. }) => {
                // Our current DB entry is a tombstone - ignore the incoming live
                // entry and just retain our DB tombstone.
                //
                // Note we don't need to gen the attrs here since if a stub was made then
                // we'd be live:live. To be in live:ts, then our db entry MUST exist and
                // must be a ts.

                Entry {
                    valid: EntryIncremental {
                        uuid: db_ent.valid.uuid,
                        ecstate: db_ent.valid.ecstate.clone(),
                    },
                    state: EntryCommitted {
                        id: db_ent.state.id,
                    },
                    attrs: db_ent.attrs.clone(),
                }
            }
            (State::Tombstone { at: left_at }, State::Tombstone { at: right_at }) => {
                // WARNING - this differs from the other tombstone check cases
                // lower of the two AT values. This way replicas always have the
                // earliest TS value. It's a rare case but needs handling.

                let (at, ecstate) = if left_at < right_at {
                    (left_at, self.valid.ecstate.clone())
                } else {
                    (right_at, db_ent.valid.ecstate.clone())
                };

                let mut attrs_new: Eattrs = Map::new();
                let class_ava = vs_iutf8![EntryClass::Object.into(), EntryClass::Tombstone.into()];
                let last_mod_ava = vs_cid![at.clone()];
                let created_ava = vs_cid![at.clone()];

                attrs_new.insert(Attribute::Uuid, vs_uuid![db_ent.valid.uuid]);
                attrs_new.insert(Attribute::Class, class_ava);
                attrs_new.insert(Attribute::LastModifiedCid, last_mod_ava);
                attrs_new.insert(Attribute::CreatedAtCid, created_ava);

                Entry {
                    valid: EntryIncremental {
                        uuid: db_ent.valid.uuid,
                        ecstate,
                    },
                    state: EntryCommitted {
                        id: db_ent.state.id,
                    },
                    attrs: attrs_new,
                }
            }
        }
    }
}

impl Entry<EntryIncremental, EntryCommitted> {
    pub(crate) fn validate_repl(self, schema: &dyn SchemaTransaction) -> EntryValidCommitted {
        // Unlike the other method of schema validation, we can't return an error
        // here when schema fails - we need to in-place move the entry to a
        // conflict state so that the replication can proceed.

        let mut ne = Entry {
            valid: EntryValid {
                uuid: self.valid.uuid,
                ecstate: self.valid.ecstate,
            },
            state: self.state,
            attrs: self.attrs,
        };

        if let Err(e) = ne.validate(schema) {
            warn!(uuid = ?self.valid.uuid, err = ?e, "Entry failed schema check, moving to a conflict state");
            ne.add_ava_int(Attribute::Class, EntryClass::Recycled.into());
            ne.add_ava_int(Attribute::Class, EntryClass::Conflict.into());
            ne.add_ava_int(Attribute::SourceUuid, Value::Uuid(self.valid.uuid));
        }
        ne
    }
}

impl<STATE> Entry<EntryInvalid, STATE> {
    pub(crate) fn get_uuid(&self) -> Option<Uuid> {
        self.attrs
            .get(&Attribute::Uuid)
            .and_then(|vs| vs.to_uuid_single())
    }

    /// Validate that this entry and its attribute-value sets are conformant to the system's'
    /// schema and the relevant syntaxes.
    pub fn validate(
        self,
        schema: &dyn SchemaTransaction,
    ) -> Result<Entry<EntryValid, STATE>, SchemaError> {
        let uuid: Uuid = self
            .attrs
            .get(&Attribute::Uuid)
            .ok_or_else(|| SchemaError::MissingMustAttribute(vec![Attribute::Uuid]))
            .and_then(|vs| {
                vs.to_uuid_single()
                    .ok_or_else(|| SchemaError::MissingMustAttribute(vec![Attribute::Uuid]))
            })?;

        // Build the new valid entry ...
        let ne = Entry {
            valid: EntryValid {
                uuid,
                ecstate: self.valid.ecstate,
            },
            state: self.state,
            attrs: self.attrs,
        };

        ne.validate(schema).map(|()| ne)
    }

    /// Access a reference set in a directly mutable form. This is "safe" because
    /// referential integrity will check the values added are valid, and because
    /// this is strongly typed it can't violate syntax.
    pub(crate) fn get_ava_refer_mut<A: AsRef<Attribute>>(
        &mut self,
        attr: A,
    ) -> Option<&mut BTreeSet<Uuid>> {
        self.get_ava_mut(attr).and_then(|vs| vs.as_refer_set_mut())
    }

    pub(crate) fn get_ava_mut<A: AsRef<Attribute>>(&mut self, attr: A) -> Option<&mut ValueSet> {
        let attr_ref = attr.as_ref();
        self.valid.ecstate.change_ava(&self.valid.cid, attr_ref);
        self.attrs.get_mut(attr.as_ref())
    }
}

impl<VALID, STATE> Clone for Entry<VALID, STATE>
where
    VALID: Clone,
    STATE: Clone,
{
    // Dirty modifiable state. Works on any other state to dirty them.
    fn clone(&self) -> Entry<VALID, STATE> {
        Entry {
            valid: self.valid.clone(),
            state: self.state.clone(),
            attrs: self.attrs.clone(),
        }
    }
}

impl Entry<EntryInvalid, EntryCommitted> {
    /// ⚠️  This function bypasses the schema validation and can panic if uuid is not found.
    /// The entry it creates can never be committed safely or replicated.
    /// This is a TEST ONLY method and will never be exposed in production.
    #[cfg(test)]
    pub fn into_valid_new(self) -> Entry<EntryValid, EntryNew> {
        let uuid = self.get_uuid().expect("Invalid uuid");
        Entry {
            valid: EntryValid {
                uuid,
                ecstate: self.valid.ecstate,
            },
            state: EntryNew,
            attrs: self.attrs,
        }
    }

    /// Convert this entry into a recycled entry, that is "in the recycle bin".
    pub fn to_recycled(mut self) -> Self {
        // This will put the modify ahead of the recycle transition.
        self.add_ava(Attribute::Class, EntryClass::Recycled.into());

        // Change state repl doesn't need this flag
        // self.valid.ecstate.recycled(&self.valid.cid);

        Entry {
            valid: self.valid,
            state: self.state,
            attrs: self.attrs,
        }
    }

    /// Convert this entry into a conflict, declaring what entries it conflicted against.
    pub fn to_conflict<T>(&mut self, iter: T)
    where
        T: IntoIterator<Item = Uuid>,
    {
        self.add_ava(Attribute::Class, EntryClass::Recycled.into());
        self.add_ava(Attribute::Class, EntryClass::Conflict.into());
        // Add all the source uuids we conflicted against.
        for source_uuid in iter {
            self.add_ava(Attribute::SourceUuid, Value::Uuid(source_uuid));
        }
    }

    /// Extract this entry from the recycle bin into a live state.
    pub fn to_revived(mut self) -> Self {
        // This will put the modify ahead of the revive transition.
        self.remove_ava(Attribute::Class, &EntryClass::Recycled.into());
        self.remove_ava(Attribute::Class, &EntryClass::Conflict.into());

        self.purge_ava(Attribute::CascadeDeleted);
        self.purge_ava(Attribute::SourceUuid);
        self.purge_ava(Attribute::RecycledDirectMemberOf);

        // Change state repl doesn't need this flag
        // self.valid.ecstate.revive(&self.valid.cid);

        Entry {
            valid: self.valid,
            state: self.state,
            attrs: self.attrs,
        }
    }
}
// Both invalid states can be reached from "entry -> invalidate"

impl Entry<EntryInvalid, EntryNew> {
    /// This function steps back from EntryInvalid to EntryInit.
    /// This is a TEST ONLY method and will never be exposed in production.
    #[cfg(test)]
    pub fn into_init_new(self) -> Entry<EntryInit, EntryNew> {
        Entry {
            valid: EntryInit,
            state: EntryNew,
            attrs: self.attrs,
        }
    }

    /// ⚠️  This function bypasses the schema validation and can panic if uuid is not found.
    /// The entry it creates can never be committed safely or replicated.
    /// This is a TEST ONLY method and will never be exposed in production.
    #[cfg(test)]
    pub fn into_valid_new(self) -> Entry<EntryValid, EntryNew> {
        let uuid = self.get_uuid().expect("Invalid uuid");
        Entry {
            valid: EntryValid {
                uuid,
                ecstate: self.valid.ecstate,
            },
            state: EntryNew,
            attrs: self.attrs,
        }
    }

    /// ⚠️  This function bypasses the db commit, assigns fake db ids, and assigns an invalid uuid.
    /// The entry it creates can never be committed safely or replicated.
    /// This is a TEST ONLY method and will never be exposed in production.
    #[cfg(test)]
    pub fn into_sealed_committed(self) -> Entry<EntrySealed, EntryCommitted> {
        let uuid = self.get_uuid().unwrap_or_else(Uuid::new_v4);
        Entry {
            valid: EntrySealed {
                uuid,
                ecstate: self.valid.ecstate,
            },
            state: EntryCommitted { id: 0 },
            attrs: self.attrs,
        }
    }

    /// ⚠️  This function bypasses the schema validation and assigns a fake uuid.
    /// The entry it creates can never be committed safely or replicated.
    /// This is a TEST ONLY method and will never be exposed in production.
    #[cfg(test)]
    pub fn into_valid_committed(self) -> Entry<EntryValid, EntryCommitted> {
        let uuid = self.get_uuid().unwrap_or_else(Uuid::new_v4);
        Entry {
            valid: EntryValid {
                uuid,
                ecstate: self.valid.ecstate,
            },
            state: EntryCommitted { id: 0 },
            attrs: self.attrs,
        }
    }
}

impl Entry<EntryInvalid, EntryCommitted> {
    /// ⚠️  This function bypasses the schema validation and assigns a fake uuid.
    /// The entry it creates can never be committed safely or replicated.
    /// This is a TEST ONLY method and will never be exposed in production.
    #[cfg(test)]
    pub fn into_sealed_committed(self) -> Entry<EntrySealed, EntryCommitted> {
        let uuid = self.get_uuid().unwrap_or_else(Uuid::new_v4);
        Entry {
            valid: EntrySealed {
                uuid,
                ecstate: self.valid.ecstate,
            },
            state: self.state,
            attrs: self.attrs,
        }
    }
}

impl Entry<EntrySealed, EntryNew> {
    /// ⚠️  This function bypasses schema validation and assigns an invalid uuid.
    /// The entry it creates can never be committed safely or replicated.
    /// This is a TEST ONLY method and will never be exposed in production.
    #[cfg(test)]
    pub fn into_sealed_committed(self) -> Entry<EntrySealed, EntryCommitted> {
        Entry {
            valid: self.valid,
            state: EntryCommitted { id: 0 },
            attrs: self.attrs,
        }
    }

    /// Given this validated and sealed entry, process it with a `Backend` ID number so that it
    /// can be then serialised to the database.
    pub fn into_sealed_committed_id(self, id: u64) -> Entry<EntrySealed, EntryCommitted> {
        Entry {
            valid: self.valid,
            state: EntryCommitted { id },
            attrs: self.attrs,
        }
    }

    pub fn compare(&self, rhs: &Entry<EntrySealed, EntryNew>) -> bool {
        compare_attrs(&self.attrs, &rhs.attrs)
    }
}

type IdxDiff<'a> =
    Vec<Result<(&'a Attribute, IndexType, String), (&'a Attribute, IndexType, String)>>;

impl<VALID> Entry<VALID, EntryCommitted> {
    /// If this entry has ever been committed to disk, retrieve its database id number.
    pub fn get_id(&self) -> u64 {
        self.state.id
    }
}

impl<STATE> Entry<EntrySealed, STATE> {
    pub fn into_init(self) -> Entry<EntryInit, STATE> {
        Entry {
            valid: EntryInit,
            state: self.state,
            attrs: self.attrs,
        }
    }
}

impl Entry<EntrySealed, EntryCommitted> {
    #[cfg(test)]
    pub(crate) fn get_last_changed(&self) -> Cid {
        self.valid.ecstate.get_max_cid().clone()
    }

    /// State transititon to allow self to self for certain test macros.
    #[cfg(test)]
    pub fn into_sealed_committed(self) -> Entry<EntrySealed, EntryCommitted> {
        // NO-OP to satisfy macros.
        self
    }

    pub(crate) fn stub_sealed_committed_id(
        id: u64,
        ctx_ent: &EntryIncrementalNew,
    ) -> EntrySealedCommitted {
        let uuid = ctx_ent.get_uuid();
        let ecstate = ctx_ent.stub_ecstate();

        Entry {
            valid: EntrySealed { uuid, ecstate },
            state: EntryCommitted { id },
            attrs: Default::default(),
        }
    }

    /// Insert a claim to this entry. This claim can NOT be persisted to disk, this is only
    /// used during a single Event session.
    pub fn insert_claim(&mut self, value: &str) {
        self.add_ava_int(Attribute::Claim, Value::new_iutf8(value));
    }

    pub fn compare(&self, rhs: &Entry<EntrySealed, EntryCommitted>) -> bool {
        compare_attrs(&self.attrs, &rhs.attrs)
    }

    /// Serialise this entry to its Database format ready for storage.
    pub fn to_dbentry(&self) -> DbEntry {
        // In the future this will do extra work to process uuid
        // into "attributes" suitable for dbentry storage.
        DbEntry {
            ent: DbEntryVers::V3 {
                changestate: self.valid.ecstate.to_db_changestate(),
                attrs: self
                    .attrs
                    .iter()
                    .map(|(k, vs)| {
                        let dbvs: DbValueSetV2 = vs.to_db_valueset_v2();
                        (k.clone(), dbvs)
                    })
                    .collect(),
            },
        }
    }

    #[inline]
    /// Given this entry, extract the set of strings that can uniquely identify this for authentication
    /// purposes. These strings are then indexed.
    fn get_name2uuid_cands(&self) -> Set<String> {
        // The cands are:
        // * spn
        // * name
        // * gidnumber

        let cands = [Attribute::Spn, Attribute::Name, Attribute::GidNumber];
        cands
            .iter()
            .filter_map(|cand| {
                self.attrs
                    .get(cand)
                    .map(|vs| vs.to_proto_string_clone_iter())
            })
            .flatten()
            .collect()
    }

    #[inline]
    /// Given this entry, extract the set of strings that can externally identify this
    /// entry for sync purposes. These strings are then indexed.
    fn get_externalid2uuid(&self) -> Option<String> {
        self.attrs
            .get(&Attribute::SyncExternalId)
            .and_then(|vs| vs.to_proto_string_single())
    }

    #[inline]
    /// Given this entry, extract its primary security principal name, or if not present
    /// extract its name, and if that's not present, extract its uuid.
    pub(crate) fn get_uuid2spn(&self) -> Value {
        self.attrs
            .get(&Attribute::Spn)
            .and_then(|vs| vs.to_value_single())
            .or_else(|| {
                self.attrs
                    .get(&Attribute::Name)
                    .and_then(|vs| vs.to_value_single())
            })
            .unwrap_or_else(|| Value::Uuid(self.get_uuid()))
    }

    #[inline]
    /// Given this entry, determine its relative distinguished named for LDAP compatibility.
    ///
    /// See also - `get_display_id`
    pub(crate) fn get_uuid2rdn(&self) -> String {
        self.attrs
            .get(&Attribute::Spn)
            .and_then(|vs| vs.to_proto_string_single().map(|v| format!("spn={v}")))
            .or_else(|| {
                self.attrs
                    .get(&Attribute::Name)
                    .and_then(|vs| vs.to_proto_string_single().map(|v| format!("name={v}")))
            })
            .unwrap_or_else(|| format!("uuid={}", self.get_uuid().as_hyphenated()))
    }

    /// Generate the required values for a name2uuid index. IE this is
    /// ALL possible names this entry COULD be known uniquely by!
    pub(crate) fn idx_name2uuid_diff(
        pre: Option<&Self>,
        post: Option<&Self>,
    ) -> (
        // Add
        Option<Set<String>>,
        // Remove
        Option<Set<String>>,
    ) {
        // needs to return gid for posix conversion
        match (pre, post) {
            (None, None) => {
                // No action required
                (None, None)
            }
            (None, Some(b)) => {
                // We are adding this entry (or restoring it),
                // so we need to add the values.
                (Some(b.get_name2uuid_cands()), None)
            }
            (Some(a), None) => {
                // Removing the entry, remove all values.
                (None, Some(a.get_name2uuid_cands()))
            }
            (Some(a), Some(b)) => {
                let pre_set = a.get_name2uuid_cands();
                let post_set = b.get_name2uuid_cands();

                // what is in post, but not pre (added)
                let add_set: Set<_> = post_set.difference(&pre_set).cloned().collect();
                // what is in pre, but not post (removed)
                let rem_set: Set<_> = pre_set.difference(&post_set).cloned().collect();
                (Some(add_set), Some(rem_set))
            }
        }
    }

    /// Generate the required values for externalid2uuid.
    pub(crate) fn idx_externalid2uuid_diff(
        pre: Option<&Self>,
        post: Option<&Self>,
    ) -> (Option<String>, Option<String>) {
        match (pre, post) {
            (None, None) => {
                // no action
                (None, None)
            }
            (None, Some(b)) => {
                // add
                (b.get_externalid2uuid(), None)
            }
            (Some(a), None) => {
                // remove
                (None, a.get_externalid2uuid())
            }
            (Some(a), Some(b)) => {
                let ia = a.get_externalid2uuid();
                let ib = b.get_externalid2uuid();
                if ia != ib {
                    // Note, we swap these since ib is the new post state
                    // we want to add, and ia is what we remove.
                    (ib, ia)
                } else {
                    // no action
                    (None, None)
                }
            }
        }
    }

    /// Generate a differential between a previous and current entry state, and what changes this
    /// means for the current set of spn's for this uuid.
    pub(crate) fn idx_uuid2spn_diff(
        pre: Option<&Self>,
        post: Option<&Self>,
    ) -> Option<Result<Value, ()>> {
        match (pre, post) {
            (None, None) => {
                // no action
                None
            }
            (None, Some(b)) => {
                // add
                Some(Ok(b.get_uuid2spn()))
            }
            (Some(_a), None) => {
                // remove
                Some(Err(()))
            }
            (Some(a), Some(b)) => {
                let ia = a.get_uuid2spn();
                let ib = b.get_uuid2spn();
                if ia != ib {
                    // Add (acts as replace)
                    Some(Ok(ib))
                } else {
                    // no action
                    None
                }
            }
        }
    }

    /// Generate a differential between a previous and current entry state, and what changes this
    /// means for the current set of LDAP relative distinguished names.
    pub(crate) fn idx_uuid2rdn_diff(
        pre: Option<&Self>,
        post: Option<&Self>,
    ) -> Option<Result<String, ()>> {
        match (pre, post) {
            (None, None) => {
                // no action
                None
            }
            (None, Some(b)) => {
                // add
                Some(Ok(b.get_uuid2rdn()))
            }
            (Some(_a), None) => {
                // remove
                Some(Err(()))
            }
            (Some(a), Some(b)) => {
                let ia = a.get_uuid2rdn();
                let ib = b.get_uuid2rdn();
                if ia != ib {
                    // Add (acts as replace)
                    Some(Ok(ib))
                } else {
                    // no action
                    None
                }
            }
        }
    }

    /// Given the previous and current state of this entry, determine the indexing differential
    /// that needs to be applied. i.e. what indexes must be created, modified and removed.
    pub(crate) fn idx_diff<'a>(
        idxmeta: &'a HashMap<IdxKey, IdxSlope>,
        pre: Option<&Self>,
        post: Option<&Self>,
    ) -> IdxDiff<'a> {
        // We yield a list of Result, where Ok() means "add",
        // and Err() means "remove".
        // the value inside the result, is a tuple of attr, itype, idx_key

        match (pre, post) {
            (None, None) => {
                // if both are none, yield empty list.
                Vec::with_capacity(0)
            }
            (Some(pre_e), None) => {
                // If we are none (?), yield our pre-state as removals.
                idxmeta
                    .keys()
                    .flat_map(|ikey| {
                        match pre_e.get_ava_set(&ikey.attr) {
                            None => Vec::with_capacity(0),
                            Some(vs) => {
                                let changes: Vec<Result<_, _>> = match ikey.itype {
                                    IndexType::Equality => {
                                        // We generate these keys out of the valueset now.
                                        vs.generate_idx_eq_keys()
                                            .into_iter()
                                            .map(|idx_key| Err((&ikey.attr, ikey.itype, idx_key)))
                                            .collect()
                                    }
                                    IndexType::Presence => {
                                        vec![Err((&ikey.attr, ikey.itype, "_".to_string()))]
                                    }
                                    IndexType::SubString => vs
                                        .generate_idx_sub_keys()
                                        .into_iter()
                                        .map(|idx_key| Err((&ikey.attr, ikey.itype, idx_key)))
                                        .collect(),
                                    IndexType::Ordering => vs
                                        .generate_idx_ord_keys()
                                        .into_iter()
                                        .map(|idx_key| Err((&ikey.attr, ikey.itype, idx_key)))
                                        .collect(),
                                };
                                changes
                            }
                        }
                    })
                    .collect()
            }
            (None, Some(post_e)) => {
                // If the pre-state is none, yield our additions.
                idxmeta
                    .keys()
                    .flat_map(|ikey| {
                        match post_e.get_ava_set(&ikey.attr) {
                            None => Vec::with_capacity(0),
                            Some(vs) => {
                                let changes: Vec<Result<_, _>> = match ikey.itype {
                                    IndexType::Equality => vs
                                        .generate_idx_eq_keys()
                                        .into_iter()
                                        .map(|idx_key| Ok((&ikey.attr, ikey.itype, idx_key)))
                                        .collect(),
                                    IndexType::Presence => {
                                        vec![Ok((&ikey.attr, ikey.itype, "_".to_string()))]
                                    }
                                    IndexType::SubString => vs
                                        .generate_idx_sub_keys()
                                        .into_iter()
                                        .map(|idx_key| Ok((&ikey.attr, ikey.itype, idx_key)))
                                        .collect(),
                                    IndexType::Ordering => vs
                                        .generate_idx_ord_keys()
                                        .into_iter()
                                        .map(|idx_key| Ok((&ikey.attr, ikey.itype, idx_key)))
                                        .collect(),
                                };
                                // For each value
                                //
                                changes
                            }
                        }
                    })
                    .collect()
            }
            (Some(pre_e), Some(post_e)) => {
                assert_eq!(pre_e.state.id, post_e.state.id);
                idxmeta
                    .keys()
                    .flat_map(|ikey| {
                        match (
                            pre_e.get_ava_set(&ikey.attr),
                            post_e.get_ava_set(&ikey.attr),
                        ) {
                            (None, None) => {
                                // Neither have it, do nothing.
                                Vec::with_capacity(0)
                            }
                            (Some(pre_vs), None) => {
                                // It existed before, but not anymore
                                let changes: Vec<Result<_, _>> = match ikey.itype {
                                    IndexType::Equality => {
                                        // Turn each idx_key to the tuple of
                                        // changes.
                                        pre_vs
                                            .generate_idx_eq_keys()
                                            .into_iter()
                                            .map(|idx_key| Err((&ikey.attr, ikey.itype, idx_key)))
                                            .collect()
                                    }
                                    IndexType::Presence => {
                                        vec![Err((&ikey.attr, ikey.itype, "_".to_string()))]
                                    }
                                    IndexType::SubString => pre_vs
                                        .generate_idx_sub_keys()
                                        .into_iter()
                                        .map(|idx_key| Err((&ikey.attr, ikey.itype, idx_key)))
                                        .collect(),
                                    IndexType::Ordering => pre_vs
                                        .generate_idx_ord_keys()
                                        .into_iter()
                                        .map(|idx_key| Err((&ikey.attr, ikey.itype, idx_key)))
                                        .collect(),
                                };
                                changes
                            }
                            (None, Some(post_vs)) => {
                                // It was added now.
                                let changes: Vec<Result<_, _>> = match ikey.itype {
                                    IndexType::Equality => {
                                        // Turn each idx_key to the tuple of
                                        // changes.
                                        post_vs
                                            .generate_idx_eq_keys()
                                            .into_iter()
                                            .map(|idx_key| Ok((&ikey.attr, ikey.itype, idx_key)))
                                            .collect()
                                    }
                                    IndexType::Presence => {
                                        vec![Ok((&ikey.attr, ikey.itype, "_".to_string()))]
                                    }
                                    IndexType::SubString => post_vs
                                        .generate_idx_sub_keys()
                                        .into_iter()
                                        .map(|idx_key| Ok((&ikey.attr, ikey.itype, idx_key)))
                                        .collect(),
                                    IndexType::Ordering => post_vs
                                        .generate_idx_ord_keys()
                                        .into_iter()
                                        .map(|idx_key| Ok((&ikey.attr, ikey.itype, idx_key)))
                                        .collect(),
                                };
                                changes
                            }
                            (Some(pre_vs), Some(post_vs)) => {
                                // it exists in both, we need to work out the difference within the attr.
                                let (mut pre_idx_keys, mut post_idx_keys) = match ikey.itype {
                                    IndexType::Equality => (
                                        pre_vs.generate_idx_eq_keys(),
                                        post_vs.generate_idx_eq_keys(),
                                    ),
                                    IndexType::Presence => {
                                        // No action - we still are "present", so nothing to do!
                                        (Vec::with_capacity(0), Vec::with_capacity(0))
                                    }
                                    IndexType::SubString => (
                                        pre_vs.generate_idx_sub_keys(),
                                        post_vs.generate_idx_sub_keys(),
                                    ),
                                    IndexType::Ordering => (
                                        pre_vs.generate_idx_ord_keys(),
                                        post_vs.generate_idx_ord_keys(),
                                    ),
                                };

                                let sz = if pre_idx_keys.len() > post_idx_keys.len() {
                                    pre_idx_keys.len()
                                } else {
                                    post_idx_keys.len()
                                };

                                let mut added_vs = Vec::with_capacity(sz);
                                let mut removed_vs = Vec::with_capacity(sz);

                                if sz > 0 {
                                    pre_idx_keys.sort_unstable();
                                    post_idx_keys.sort_unstable();

                                    let mut pre_iter = pre_idx_keys.iter();
                                    let mut post_iter = post_idx_keys.iter();

                                    let mut pre = pre_iter.next();
                                    let mut post = post_iter.next();

                                    loop {
                                        match (pre, post) {
                                            (Some(a), Some(b)) => {
                                                match a.cmp(b) {
                                                    Ordering::Less => {
                                                        removed_vs.push(a.clone());
                                                        pre = pre_iter.next();
                                                    }
                                                    Ordering::Equal => {
                                                        // In both - no action needed.
                                                        pre = pre_iter.next();
                                                        post = post_iter.next();
                                                    }
                                                    Ordering::Greater => {
                                                        added_vs.push(b.clone());
                                                        post = post_iter.next();
                                                    }
                                                }
                                            }
                                            (Some(a), None) => {
                                                removed_vs.push(a.clone());
                                                pre = pre_iter.next();
                                            }
                                            (None, Some(b)) => {
                                                added_vs.push(b.clone());
                                                post = post_iter.next();
                                            }
                                            (None, None) => {
                                                break;
                                            }
                                        }
                                    }
                                } // end sz > 0

                                let mut diff =
                                    Vec::with_capacity(removed_vs.len() + added_vs.len());

                                match ikey.itype {
                                    IndexType::SubString
                                    | IndexType::Ordering
                                    | IndexType::Equality => {
                                        removed_vs
                                            .into_iter()
                                            .map(|idx_key| Err((&ikey.attr, ikey.itype, idx_key)))
                                            .for_each(|v| diff.push(v));
                                        added_vs
                                            .into_iter()
                                            .map(|idx_key| Ok((&ikey.attr, ikey.itype, idx_key)))
                                            .for_each(|v| diff.push(v));
                                    }
                                    IndexType::Presence => {
                                        // No action - we still are "present", so nothing to do!
                                    }
                                };
                                // Return the diff
                                diff
                            }
                        }
                    })
                    .collect()
                // End diff of the entries
            }
        }
    }

    pub fn from_dbentry(db_e: DbEntry, id: u64) -> Option<Self> {
        // Convert attrs from db format to value

        let (attrs, ecstate) = match db_e.ent {
            DbEntryVers::V3 { changestate, attrs } => {
                let ecstate = EntryChangeState::from_db_changestate(changestate);

                let r_attrs = attrs
                    .into_iter()
                    // Skip anything empty as new VS can't deal with it.
                    .filter(|(_k, vs)| !vs.is_empty())
                    .map(|(k, dbvs)| {
                        valueset::from_db_valueset_v2(dbvs)
                            .map(|vs: ValueSet| (k, vs))
                            .map_err(|e| {
                                error!(?e, "from_dbentry failed");
                            })
                    })
                    .collect::<Result<Eattrs, ()>>()
                    .ok()?;

                (r_attrs, ecstate)
            }
        };

        let uuid = attrs
            .get(&Attribute::Uuid)
            .and_then(|vs| vs.to_uuid_single())?;

        Some(Entry {
            valid: EntrySealed { uuid, ecstate },
            state: EntryCommitted { id },
            attrs,
        })
    }

    /// ⚠️  This function bypasses the access control validation logic and should NOT
    /// be used without special care and attention to ensure that no private data
    /// is leaked incorrectly to clients. Generally this is ONLY used inside of
    /// the access control processing functions which correctly applies the reduction
    /// steps.
    ///
    /// This is a TEST ONLY method and will never be exposed in production.
    #[cfg(test)]
    pub(crate) fn into_reduced(self) -> Entry<EntryReduced, EntryCommitted> {
        Entry {
            valid: EntryReduced {
                uuid: self.valid.uuid,
                effective_access: None,
            },
            state: self.state,
            attrs: self.attrs,
        }
    }

    /// Given a set of attributes that are allowed to be seen on this entry, process and remove
    /// all other values that are NOT allowed in this query.
    pub fn reduce_attributes(
        &self,
        allowed_attrs: &BTreeSet<Attribute>,
        effective_access: Option<Box<AccessEffectivePermission>>,
    ) -> Entry<EntryReduced, EntryCommitted> {
        // Remove all attrs from our tree that are NOT in the allowed set.
        let f_attrs: Map<_, _> = self
            .attrs
            .iter()
            .filter_map(|(k, v)| {
                if allowed_attrs.contains(k) {
                    Some((k.clone(), v.clone()))
                } else {
                    None
                }
            })
            .collect();

        let valid = EntryReduced {
            uuid: self.valid.uuid,
            effective_access,
        };
        let state = self.state.clone();

        Entry {
            valid,
            state,
            attrs: f_attrs,
        }
    }

    /// Convert this recycled entry, into a tombstone ready for reaping.
    pub fn to_tombstone(&self, cid: Cid) -> Entry<EntryInvalid, EntryCommitted> {
        let mut ecstate = self.valid.ecstate.clone();
        // Duplicate this to a tombstone entry
        let mut attrs_new: Eattrs = Map::new();

        let class_ava = vs_iutf8![EntryClass::Object.into(), EntryClass::Tombstone.into()];
        let last_mod_ava = vs_cid![cid.clone()];
        let created_ava = vs_cid![cid.clone()];

        attrs_new.insert(Attribute::Uuid, vs_uuid![self.get_uuid()]);
        attrs_new.insert(Attribute::Class, class_ava);
        attrs_new.insert(Attribute::LastModifiedCid, last_mod_ava);
        attrs_new.insert(Attribute::CreatedAtCid, created_ava);

        // ⚠️  No return from this point!
        ecstate.tombstone(&cid);

        Entry {
            valid: EntryInvalid { cid, ecstate },
            state: self.state.clone(),
            attrs: attrs_new,
        }
    }

    /// Given a current transaction change identifier, mark this entry as valid and committed.
    pub fn into_valid(self, ecstate: EntryChangeState) -> Entry<EntryValid, EntryCommitted> {
        Entry {
            valid: EntryValid {
                uuid: self.valid.uuid,
                ecstate,
            },
            state: self.state,
            attrs: self.attrs,
        }
    }

    pub fn verify(
        &self,
        schema: &dyn SchemaTransaction,
        results: &mut Vec<Result<(), ConsistencyError>>,
    ) {
        self.valid
            .ecstate
            .verify(schema, &self.attrs, self.state.id, results);
    }
}

impl<STATE> Entry<EntryValid, STATE> {
    fn validate(&self, schema: &dyn SchemaTransaction) -> Result<(), SchemaError> {
        let schema_classes = schema.get_classes();
        let schema_attributes = schema.get_attributes();

        // Now validate it!
        trace!(?self.attrs, "Entry::validate -> target");

        // First, check we have class on the object ....
        if !self.attribute_pres(Attribute::Class) {
            // lrequest_error!("Missing attribute class");
            return Err(SchemaError::NoClassFound);
        }

        if self.attribute_equality(Attribute::Class, &EntryClass::Conflict.into()) {
            // Conflict entries are exempt from schema enforcement. Return true.
            trace!("Skipping schema validation on conflict entry");
            return Ok(());
        };

        // Are we in the recycle bin? We soften some checks if we are.
        let recycled = self.attribute_equality(Attribute::Class, &EntryClass::Recycled.into());

        // Do we have extensible? We still validate syntax of attrs but don't
        // check for valid object structures.
        let extensible =
            self.attribute_equality(Attribute::Class, &EntryClass::ExtensibleObject.into());

        let entry_classes = self.get_ava_set(Attribute::Class).ok_or_else(|| {
            admin_debug!("Attribute '{}' missing from entry", Attribute::Class);
            SchemaError::NoClassFound
        })?;
        let mut invalid_classes = Vec::with_capacity(0);

        let mut classes: Vec<&SchemaClass> = Vec::with_capacity(entry_classes.len());

        // We need to keep the btreeset of entry classes here so we can check the
        // requires and excludes.
        let entry_classes = if let Some(ec) = entry_classes.as_iutf8_set() {
            ec.iter()
                .for_each(|s| match schema_classes.get(s.as_str()) {
                    Some(x) => classes.push(x),
                    None => {
                        admin_debug!("invalid class: {:?}", s);
                        invalid_classes.push(s.to_string())
                    }
                });
            ec
        } else {
            admin_debug!("corrupt class attribute");
            return Err(SchemaError::NoClassFound);
        };

        if !invalid_classes.is_empty() {
            return Err(SchemaError::InvalidClass(invalid_classes));
        };

        // Now determine the set of excludes and requires we have, and then
        // assert we don't violate them.

        let supplements_classes: Vec<_> = classes
            .iter()
            .flat_map(|cls| cls.systemsupplements.iter().chain(cls.supplements.iter()))
            .collect();

        // So long as one supplement is present we can continue.
        let valid_supplements = if supplements_classes.is_empty() {
            // No need to check.
            true
        } else {
            supplements_classes
                .iter()
                .any(|class| entry_classes.contains(class.as_str()))
        };

        if !valid_supplements {
            warn!(
                "Validation error, the following possible supplement classes are missing - {:?}",
                supplements_classes
            );
            let supplements_classes = supplements_classes.iter().map(|s| s.to_string()).collect();
            return Err(SchemaError::SupplementsNotSatisfied(supplements_classes));
        }

        let excludes_classes: Vec<_> = classes
            .iter()
            .flat_map(|cls| cls.systemexcludes.iter().chain(cls.excludes.iter()))
            .collect();

        let mut invalid_excludes = Vec::with_capacity(0);

        excludes_classes.iter().for_each(|class| {
            if entry_classes.contains(class.as_str()) {
                invalid_excludes.push(class.to_string())
            }
        });

        if !invalid_excludes.is_empty() {
            admin_warn!(
                "Validation error, the following excluded classes are present - {:?}",
                invalid_excludes
            );
            return Err(SchemaError::ExcludesNotSatisfied(invalid_excludes));
        }

        // What this is really doing is taking a set of classes, and building an
        // "overall" class that describes this exact object for checking. IE we
        // build a super must/may set from the small class must/may sets.

        //   for each class
        //      add systemmust/must and systemmay/may to their lists
        //      add anything from must also into may

        // Now from the set of valid classes make a list of must/may
        //
        // NOTE: We still need this on extensible, because we still need to satisfy
        // our other must conditions as well!
        let must: Result<Vec<&SchemaAttribute>, _> = classes
            .iter()
            // Join our class systemmmust + must into one iter
            .flat_map(|cls| cls.systemmust.iter().chain(cls.must.iter()))
            .map(|s| {
                // This should NOT fail - if it does, it means our schema is
                // in an invalid state!
                schema_attributes.get(s).ok_or(SchemaError::Corrupted)
            })
            .collect();

        let must = must?;

        // Check that all must are inplace
        //   for each attr in must, check it's present on our ent
        let mut missing_must = Vec::with_capacity(0);
        for attr in must.iter() {
            let avas = self.get_ava_set(&attr.name);
            if avas.is_none() {
                missing_must.push(attr.name.clone());
            }
        }

        if !missing_must.is_empty() {
            admin_warn!(
                "Validation error, the following required ({}) (must) attributes are missing - {:?}",
                self.get_display_id(), missing_must
            );
            // We if are in the recycle bin, we don't hard error here. This can occur when
            // a migration occurs and we delete an acp, and then the related group. Because
            // this would trigger refint which purges the acp_receiver_group, then this
            // must value becomes unsatisfiable. So here we soften the check for recycled
            // entries because they are in a "nebulous" state anyway.
            if !recycled {
                return Err(SchemaError::MissingMustAttribute(missing_must));
            }
        }

        if extensible {
            self.attrs.iter().try_for_each(|(attr_name, avas)| {
                    match schema_attributes.get(attr_name) {
                        Some(a_schema) => {
                            // Now, for each type we do a *full* check of the syntax
                            // and validity of the ava.
                            if a_schema.phantom {
                                admin_warn!(
                                    "Rejecting attempt to add phantom attribute to extensible object: {}",
                                    attr_name
                                );
                                Err(SchemaError::PhantomAttribute(attr_name.to_string()))
                            } else {
                                a_schema.validate_ava(attr_name, avas)
                                // .map_err(|e| lrequest_error!("Failed to validate: {}", attr_name);)
                            }
                        }
                        None => {
                            admin_error!(
                                "Invalid Attribute {}, undefined in schema_attributes",
                                attr_name.to_string()
                            );
                            Err(SchemaError::InvalidAttribute(
                                attr_name.to_string()
                            ))
                        }
                    }
                })?;
        } else {
            // Note - we do NOT need to check phantom attributes here because they are
            // not allowed to exist in the class, which means a phantom attribute can't
            // be in the may/must set, and would FAIL our normal checks anyway.

            // The set of "may" is a combination of may and must, since we have already
            // asserted that all must requirements are fulfilled. This allows us to
            // perform extended attribute checking in a single pass.
            let may: Result<Map<&Attribute, &SchemaAttribute>, _> = classes
                .iter()
                // Join our class systemmmust + must + systemmay + may into one.
                .flat_map(|cls| {
                    trace!(?cls);
                    cls.systemmust
                        .iter()
                        .chain(cls.must.iter())
                        .chain(cls.systemmay.iter())
                        .chain(cls.may.iter())
                })
                .map(|s| {
                    // This should NOT fail - if it does, it means our schema is
                    // in an invalid state!
                    Ok((s, schema_attributes.get(s).ok_or(SchemaError::Corrupted)?))
                })
                .collect();

            let may = may?;

            // TODO #70: Error needs to say what is missing
            // We need to return *all* missing attributes, not just the first error
            // we find. This will probably take a rewrite of the function definition
            // to return a result<_, vec<schemaerror>> and for the schema errors to take
            // information about what is invalid. It's pretty nontrivial.

            // Check that any other attributes are in may
            //   for each attr on the object, check it's in the may+must set
            self.attrs.iter().try_for_each(|(attr_name, avas)| {
                    match may.get(attr_name) {
                        Some(a_schema) => {
                            // Now, for each type we do a *full* check of the syntax
                            // and validity of the ava.
                            a_schema.validate_ava(attr_name, avas)
                            // .map_err(|e| lrequest_error!("Failed to validate: {}", attr_name);
                        }
                        None => {
                            admin_error!(
                                "{} {} - not found in the list of valid attributes for this set of classes {:?} - valid attributes are {:?}",

                                attr_name.as_str(),
                                self.get_display_id(),
                                entry_classes.iter().collect::<Vec<_>>(),
                                may.keys().collect::<Vec<_>>()
                            );
                            Err(SchemaError::AttributeNotValidForClass(
                                attr_name.to_string()
                            ))
                        }
                    }
                })?;
        }

        // Well, we got here, so okay!
        Ok(())
    }

    pub fn seal(mut self, schema: &dyn SchemaTransaction) -> Entry<EntrySealed, STATE> {
        let EntryValid { uuid, mut ecstate } = self.valid;

        // Remove anything from the ecstate that is not a replicated attribute in the schema.
        // This is to allow ecstate equality to work, but also to just prevent ruv updates and
        // replicating things that only touched or changed phantom attrs.
        ecstate.retain(|k, _| schema.is_replicated(k));

        // Update the last changed time.
        let last_mod_cid = ecstate.get_max_cid();
        let cv = vs_cid![last_mod_cid.clone()];
        let _ = self.attrs.insert(Attribute::LastModifiedCid, cv);

        // Update created-at time. This is needed for migrations currently. It could
        // be alternately in the entry create path, but it makes more sense here as
        // we get the create_at time from the replication metadata
        let create_at_cid = ecstate.at();
        let cv = vs_cid![create_at_cid.clone()];
        let _ = self.attrs.insert(Attribute::CreatedAtCid, cv);

        Entry {
            valid: EntrySealed { uuid, ecstate },
            state: self.state,
            attrs: self.attrs,
        }
    }

    pub fn get_uuid(&self) -> Uuid {
        self.valid.uuid
    }
}

impl<STATE> GetUuid for Entry<EntrySealed, STATE>
where
    STATE: Clone,
{
    fn get_uuid(&self) -> Uuid {
        self.valid.uuid
    }
}

impl<STATE> Entry<EntrySealed, STATE>
where
    STATE: Clone,
{
    pub fn invalidate(mut self, cid: Cid, trim_cid: &Cid) -> Entry<EntryInvalid, STATE> {
        // Trim attributes that require it. For most this is a no-op.
        for vs in self.attrs.values_mut() {
            vs.trim(trim_cid);
        }

        // During migration to the new modified/created cid system, we need to account
        // for entries that don't have this yet. Normally we would apply this in seal()
        // to the current CID. At this point we enter in the expected value from the
        // entry. Note, we don't set last mod to cid yet, we leave that to seal() so that
        // if this entry is excluded later in the change, we haven't tainted anything, or
        // so that if the change only applies to non-replicated attrs we haven't mucked
        // up the value.
        let last_mod_cid = self.valid.ecstate.get_max_cid();
        let cv = vs_cid![last_mod_cid.clone()];
        let _ = self.attrs.insert(Attribute::LastModifiedCid, cv);

        let create_at_cid = self.valid.ecstate.at();
        let cv = vs_cid![create_at_cid.clone()];
        let _ = self.attrs.insert(Attribute::CreatedAtCid, cv);

        Entry {
            valid: EntryInvalid {
                cid,
                ecstate: self.valid.ecstate,
            },
            state: self.state,
            attrs: self.attrs,
        }
    }

    pub fn get_uuid(&self) -> Uuid {
        self.valid.uuid
    }

    pub fn get_changestate(&self) -> &EntryChangeState {
        &self.valid.ecstate
    }

    /// Determine if any attribute of this entry changed excluding the attribute named.
    /// This allows for detection of entry changes unless the change was to a specific
    /// attribute.
    pub(crate) fn entry_changed_excluding_attribute<A: AsRef<Attribute>>(
        &self,
        attr: A,
        cid: &Cid,
    ) -> bool {
        let attr_ref = attr.as_ref();

        use crate::repl::entry::State;

        match self.get_changestate().current() {
            State::Live { at: _, changes } => {
                changes.iter().any(|(change_attr, change_id)| {
                    change_id >= cid &&
                    *change_attr != *attr_ref &&
                    // This always changes, and could throw off other detections.
                    *change_attr != Attribute::LastModifiedCid
                })
            }
            State::Tombstone { at } => at == cid,
        }
    }

    /// ⚠️  - Invalidate an entry by resetting it's change state to time-zero. This entry
    /// can never be replicated after this.
    /// This is a TEST ONLY method and will never be exposed in production.
    #[cfg(test)]
    pub(crate) fn into_invalid(mut self) -> Entry<EntryInvalid, STATE> {
        let cid = Cid::new_zero();
        self.set_last_changed(cid.clone());

        let ecstate = EntryChangeState::new_without_schema(&cid, &self.attrs);

        Entry {
            valid: EntryInvalid { cid, ecstate },
            state: self.state,
            attrs: self.attrs,
        }
    }
}

impl GetUuid for Entry<EntryReduced, EntryCommitted> {
    fn get_uuid(&self) -> Uuid {
        self.valid.uuid
    }
}

impl Entry<EntryReduced, EntryCommitted> {
    pub fn get_uuid(&self) -> Uuid {
        self.valid.uuid
    }

    /// Transform this reduced entry into a JSON protocol form that can be sent to clients.
    pub fn to_pe(&self, qs: &mut QueryServerReadTransaction) -> Result<ProtoEntry, OperationError> {
        // Turn values -> Strings.
        let attrs: Result<_, _> = self
            .attrs
            .iter()
            .map(|(k, vs)| qs.resolve_valueset(vs).map(|pvs| (k.to_string(), pvs)))
            .collect();
        Ok(ProtoEntry { attrs: attrs? })
    }

    pub fn to_scim_kanidm<'a, TXN>(
        &self,
        read_txn: &mut TXN,
    ) -> Result<ScimEntryKanidm, OperationError>
    where
        TXN: QueryServerTransaction<'a>,
    {
        let result: Result<BTreeMap<Attribute, ScimValueKanidm>, OperationError> = self
            .attrs
            .iter()
            // We want to skip some attributes as they are already in the header.
            .filter(|(k, _vs)| **k != Attribute::Uuid)
            .filter_map(|(k, vs)| {
                let opt_resolve_status = vs.to_scim_value();
                let res_opt_scim_value = match opt_resolve_status {
                    None => Ok(None),
                    Some(ScimResolveStatus::Resolved(scim_value_kani)) => Ok(Some(scim_value_kani)),
                    Some(ScimResolveStatus::NeedsResolution(scim_value_interim)) => {
                        read_txn.resolve_scim_interim(scim_value_interim)
                    }
                };
                res_opt_scim_value
                    .transpose()
                    .map(|scim_res| scim_res.map(|scim_value| (k.clone(), scim_value)))
            })
            .collect();

        let attrs = result?;

        let ext_access_check = self.valid.effective_access.as_ref().map(|eff_acc| {
            let ident = eff_acc.ident;
            let delete = eff_acc.delete;
            let search = (&eff_acc.search).into();
            let modify_present = (&eff_acc.modify_pres).into();
            let modify_remove = (&eff_acc.modify_rem).into();

            ScimEffectiveAccess {
                ident,
                delete,
                search,
                modify_present,
                modify_remove,
            }
        });

        let id = self.get_uuid();

        // Not sure how I want to handle this yet, I think we need some schema changes
        // to achieve this.
        let schemas = Vec::with_capacity(0);

        Ok(ScimEntryKanidm {
            header: ScimEntryHeader {
                schemas,
                id,
                // TODO: Should be spn / name or uuid.
                external_id: None,
                // TODO - this one will be useful in future, but we need to change
                // entry to store some extra metadata.
                meta: None,
            },
            ext_access_check,
            attrs,
        })
    }

    /// Transform this reduced entry into an LDAP form that can be sent to clients.
    pub fn to_ldap(
        &self,
        qs: &mut QueryServerReadTransaction,
        basedn: &str,
        // Did the client request all attributes?
        all_attrs: bool,
        // Did the ldap client request any sperific attribute names? If so,
        // we need to remap everything to match.
        l_attrs: &[String],
    ) -> Result<LdapSearchResultEntry, OperationError> {
        let rdn = qs.uuid_to_rdn(self.get_uuid())?;

        let dn = format!("{rdn},{basedn}");

        // Everything in our attrs set is "what was requested". So we can transform that now
        // so they are all in "ldap forms" which makes our next stage a bit easier.

        // Stage 1 - transform our results to a map of kani attr -> ldap value.
        let attr_map: Result<Map<&str, Vec<Vec<u8>>>, _> = self
            .attrs
            .iter()
            .map(|(k, vs)| {
                qs.resolve_valueset_ldap(vs, basedn)
                    .map(|pvs| (k.as_str(), pvs))
            })
            .collect();
        let attr_map = attr_map?;

        // Stage 2 - transform and get all our attr - names out that we need to return.
        //                  ldap a, kani a
        let attr_names: Vec<(&str, &str)> = if all_attrs {
            // Join the set of attr keys, and our requested attrs.
            self.attrs
                .keys()
                .map(|k| (k.as_str(), k.as_str()))
                .chain(
                    l_attrs
                        .iter()
                        .map(|k| (k.as_str(), ldap_vattr_map(k.as_str()).unwrap_or(k.as_str()))),
                )
                .collect()
        } else {
            // Just get the requested ones.
            l_attrs
                .iter()
                .map(|k| (k.as_str(), ldap_vattr_map(k.as_str()).unwrap_or(k.as_str())))
                .collect()
        };

        // Stage 3 - given our map, generate the final result.
        let attributes: Vec<_> = attr_names
            .into_iter()
            .filter_map(|(ldap_a, kani_a)| {
                // In some special cases, we may need to transform or rewrite the values.
                match ldap_a {
                    LDAP_ATTR_DN => Some(LdapPartialAttribute {
                        atype: LDAP_ATTR_DN.to_string(),
                        vals: vec![dn.as_bytes().to_vec()],
                    }),
                    LDAP_ATTR_ENTRYDN => Some(LdapPartialAttribute {
                        atype: LDAP_ATTR_ENTRYDN.to_string(),
                        vals: vec![dn.as_bytes().to_vec()],
                    }),
                    LDAP_ATTR_MAIL_PRIMARY | LDAP_ATTR_EMAIL_PRIMARY => {
                        attr_map.get(kani_a).map(|pvs| LdapPartialAttribute {
                            atype: ldap_a.to_string(),
                            vals: pvs
                                .first()
                                .map(|first| vec![first.clone()])
                                .unwrap_or_default(),
                        })
                    }
                    LDAP_ATTR_MAIL_ALTERNATIVE | LDAP_ATTR_EMAIL_ALTERNATIVE => {
                        attr_map.get(kani_a).map(|pvs| LdapPartialAttribute {
                            atype: ldap_a.to_string(),
                            vals: pvs
                                .split_first()
                                .map(|(_, rest)| rest.to_vec())
                                .unwrap_or_default(),
                        })
                    }
                    ATTR_HOME_DIRECTORY => Some(LdapPartialAttribute {
                        atype: ATTR_HOME_DIRECTORY.to_string(),
                        vals: vec![format!("/home/{}", self.get_uuid()).into_bytes()],
                    }),
                    _ => attr_map.get(kani_a).map(|pvs| LdapPartialAttribute {
                        atype: ldap_a.to_string(),
                        vals: pvs.clone(),
                    }),
                }
            })
            .collect();

        Ok(LdapSearchResultEntry { dn, attributes })
    }
}

impl<VALID, STATE> Entry<VALID, STATE> {
    /// This internally adds an AVA to the entry. If the entry was newly added, then true is returned.
    /// If the value already existed, or was unable to be added, false is returned. Alternately,
    /// you can think of this boolean as "if a write occurred to the structure", true indicating that
    /// a change occurred.
    fn add_ava_int(&mut self, attr: Attribute, value: Value) -> bool {
        if let Some(vs) = self.attrs.get_mut(&attr) {
            let r = vs.insert_checked(value);
            debug_assert!(r.is_ok());
            // Default to the value not being present if wrong typed.
            r.unwrap_or(false)
        } else {
            #[allow(clippy::expect_used)]
            let vs = valueset::from_value_iter(std::iter::once(value))
                .expect("Unable to fail - non-zero iter, and single value type!");
            self.attrs.insert(attr, vs);
            // The attribute did not exist before.
            true
        }
        // Doesn't matter if it already exists, equality will replace.
    }

    /// Overwrite the current set of values for an attribute, with this new set.
    fn set_ava_iter_int<T>(&mut self, attr: Attribute, iter: T)
    where
        T: IntoIterator<Item = Value>,
    {
        let Ok(vs) = valueset::from_value_iter(iter.into_iter()) else {
            trace!("set_ava_iter_int - empty from_value_iter, skipping");
            return;
        };

        if let Some(existing_vs) = self.attrs.get_mut(&attr) {
            // This is the suboptimal path. This can only exist in rare cases.
            let _ = existing_vs.merge(&vs);
        } else {
            // Normally this is what's taken.
            self.attrs.insert(attr, vs);
        }
    }

    /// Update the last_changed flag of this entry to the given change identifier.
    #[cfg(test)]
    fn set_last_changed(&mut self, cid: Cid) {
        let cv = vs_cid![cid.clone()];
        let _ = self.attrs.insert(Attribute::LastModifiedCid, cv);
        let cv = vs_cid![cid];
        let _ = self.attrs.insert(Attribute::CreatedAtCid, cv);
    }

    pub(crate) fn get_display_id(&self) -> String {
        self.attrs
            .get(&Attribute::Spn)
            .and_then(|vs| vs.to_value_single())
            .or_else(|| {
                self.attrs
                    .get(&Attribute::Name)
                    .and_then(|vs| vs.to_value_single())
            })
            .or_else(|| {
                self.attrs
                    .get(&Attribute::Uuid)
                    .and_then(|vs| vs.to_value_single())
            })
            .map(|value| value.to_proto_string_clone())
            .unwrap_or_else(|| "no entry id available".to_string())
    }

    pub fn has_class(&self, class: &EntryClass) -> bool {
        self.get_ava_set(Attribute::Class)
            .and_then(|vs| vs.as_iutf8_set())
            .map(|set| {
                let class_name: &str = class.into();
                set.contains(class_name)
            })
            .unwrap_or_default()
    }

    pub fn attr_keys(&self) -> impl Iterator<Item = &Attribute> {
        self.attrs.keys()
    }

    /// Get an iterator over the current set of attribute names that this entry contains.
    pub fn get_ava_names(&self) -> impl Iterator<Item = &str> {
        // Get the set of all attribute names in the entry
        self.attrs.keys().map(|a| a.as_str())
    }

    /// Get an iterator over the current set of values for an attribute name.
    pub fn get_ava(&self) -> &Eattrs {
        &self.attrs
    }

    pub fn get_ava_iter(&self) -> impl Iterator<Item = (&Attribute, &ValueSet)> {
        self.attrs.iter()
    }

    /// Return a reference to the current set of values that are associated to this attribute.
    pub fn get_ava_set<A: AsRef<Attribute>>(&self, attr: A) -> Option<&ValueSet> {
        self.attrs.get(attr.as_ref())
    }

    pub fn get_ava_refer<A: AsRef<Attribute>>(&self, attr: A) -> Option<&BTreeSet<Uuid>> {
        self.get_ava_set(attr).and_then(|vs| vs.as_refer_set())
    }

    pub fn get_ava_as_iutf8_iter<A: AsRef<Attribute>>(
        &self,
        attr: A,
    ) -> Option<impl Iterator<Item = &str>> {
        self.get_ava_set(attr).and_then(|vs| vs.as_iutf8_iter())
    }

    pub fn get_ava_as_iutf8<A: AsRef<Attribute>>(&self, attr: A) -> Option<&BTreeSet<String>> {
        self.get_ava_set(attr).and_then(|vs| vs.as_iutf8_set())
    }

    pub fn get_ava_as_image<A: AsRef<Attribute>>(&self, attr: A) -> Option<&HashSet<ImageValue>> {
        self.get_ava_set(attr).and_then(|vs| vs.as_imageset())
    }

    pub fn get_ava_single_image<A: AsRef<Attribute>>(&self, attr: A) -> Option<ImageValue> {
        let images = self.get_ava_set(attr).and_then(|vs| vs.as_imageset())?;
        images.iter().next().cloned()
    }

    pub fn get_ava_single_credential_type<A: AsRef<Attribute>>(
        &self,
        attr: A,
    ) -> Option<CredentialType> {
        self.get_ava_set(attr)
            .and_then(|vs| vs.to_credentialtype_single())
    }

    pub fn get_ava_as_oauthscopes<A: AsRef<Attribute>>(
        &self,
        attr: A,
    ) -> Option<impl Iterator<Item = &str>> {
        self.get_ava_set(attr)
            .and_then(|vs| vs.as_oauthscope_iter())
    }

    pub fn get_ava_as_oauthscopemaps<A: AsRef<Attribute>>(
        &self,
        attr: A,
    ) -> Option<&std::collections::BTreeMap<Uuid, std::collections::BTreeSet<String>>> {
        self.get_ava_set(attr).and_then(|vs| vs.as_oauthscopemap())
    }

    pub fn get_ava_as_intenttokens<A: AsRef<Attribute>>(
        &self,
        attr: A,
    ) -> Option<&std::collections::BTreeMap<String, IntentTokenState>> {
        self.get_ava_set(attr)
            .and_then(|vs| vs.as_intenttoken_map())
    }

    pub fn get_ava_as_session_map<A: AsRef<Attribute>>(
        &self,
        attr: A,
    ) -> Option<&std::collections::BTreeMap<Uuid, Session>> {
        self.get_ava_set(attr).and_then(|vs| vs.as_session_map())
    }

    pub fn get_ava_as_apitoken_map<A: AsRef<Attribute>>(
        &self,
        attr: A,
    ) -> Option<&std::collections::BTreeMap<Uuid, ApiToken>> {
        self.get_ava_set(attr).and_then(|vs| vs.as_apitoken_map())
    }

    pub fn get_ava_as_oauth2session_map<A: AsRef<Attribute>>(
        &self,
        attr: A,
    ) -> Option<&std::collections::BTreeMap<Uuid, Oauth2Session>> {
        self.get_ava_set(attr)
            .and_then(|vs| vs.as_oauth2session_map())
    }

    pub fn get_ava_as_s256_set<A: AsRef<Attribute>>(
        &self,
        attr: A,
    ) -> Option<&std::collections::BTreeSet<Sha256Output>> {
        self.get_ava_set(attr).and_then(|vs| vs.as_s256_set())
    }

    /// If possible, return an iterator over the set of values transformed into a `&str`.
    pub fn get_ava_iter_iname<A: AsRef<Attribute>>(
        &self,
        attr: A,
    ) -> Option<impl Iterator<Item = &str>> {
        self.get_ava_set(attr).and_then(|vs| vs.as_iname_iter())
    }

    /// If possible, return an iterator over the set of values transformed into a `&str`.
    pub fn get_ava_iter_iutf8<A: AsRef<Attribute>>(
        &self,
        attr: A,
    ) -> Option<impl Iterator<Item = &str>> {
        self.get_ava_set(attr).and_then(|vs| vs.as_iutf8_iter())
    }

    /// If possible, return an iterator over the set of values transformed into a `Uuid`.
    pub fn get_ava_as_refuuid<A: AsRef<Attribute>>(
        &self,
        attr: A,
    ) -> Option<Box<dyn Iterator<Item = Uuid> + '_>> {
        // If any value is NOT a reference, it's filtered out.
        self.get_ava_set(attr).and_then(|vs| vs.as_ref_uuid_iter())
    }

    /// If possible, return an iterator over the set of ssh key values transformed into a `&str`.
    pub fn get_ava_iter_sshpubkeys<A: AsRef<Attribute>>(
        &self,
        attr: A,
    ) -> Option<impl Iterator<Item = String> + '_> {
        self.get_ava_set(attr)
            .and_then(|vs| vs.as_sshpubkey_string_iter())
    }

    // These are special types to allow returning typed values from
    // an entry, if we "know" what we expect to receive.

    /// Return a single value of this attributes name, or `None` if it is NOT present, or
    /// there are multiple values present (ambiguous).
    pub fn get_ava_single<A: AsRef<Attribute>>(&self, attr: A) -> Option<Value> {
        self.get_ava_set(attr).and_then(|vs| vs.to_value_single())
    }

    pub fn get_ava_single_proto_string<A: AsRef<Attribute>>(&self, attr: A) -> Option<String> {
        self.get_ava_set(attr)
            .and_then(|vs| vs.to_proto_string_single())
    }

    /// Return a single bool, if valid to transform this value into a boolean.
    pub fn get_ava_single_bool<A: AsRef<Attribute>>(&self, attr: A) -> Option<bool> {
        self.get_ava_set(attr).and_then(|vs| vs.to_bool_single())
    }

    /// Return a single uint32, if valid to transform this value.
    pub fn get_ava_single_uint32<A: AsRef<Attribute>>(&self, attr: A) -> Option<u32> {
        self.get_ava_set(attr).and_then(|vs| vs.to_uint32_single())
    }

    /// Return a single syntax type, if valid to transform this value.
    pub fn get_ava_single_syntax<A: AsRef<Attribute>>(&self, attr: A) -> Option<SyntaxType> {
        self.get_ava_set(attr)
            .and_then(|vs| vs.to_syntaxtype_single())
    }

    /// Return a single credential, if valid to transform this value.
    pub fn get_ava_single_credential<A: AsRef<Attribute>>(&self, attr: A) -> Option<&Credential> {
        self.get_ava_set(attr)
            .and_then(|vs| vs.to_credential_single())
    }

    /// Get the set of passkeys on this account, if any are present.
    pub fn get_ava_passkeys<A: AsRef<Attribute>>(
        &self,
        attr: A,
    ) -> Option<&BTreeMap<Uuid, (String, PasskeyV4)>> {
        self.get_ava_set(attr).and_then(|vs| vs.as_passkey_map())
    }

    /// Get the set of devicekeys on this account, if any are present.
    pub fn get_ava_attestedpasskeys<A: AsRef<Attribute>>(
        &self,
        attr: A,
    ) -> Option<&BTreeMap<Uuid, (String, AttestedPasskeyV4)>> {
        self.get_ava_set(attr)
            .and_then(|vs| vs.as_attestedpasskey_map())
    }

    /// Get the set of uihints on this account, if any are present.
    pub fn get_ava_uihint<A: AsRef<Attribute>>(&self, attr: A) -> Option<&BTreeSet<UiHint>> {
        self.get_ava_set(attr).and_then(|vs| vs.as_uihint_set())
    }

    /// Return a single secret value, if valid to transform this value.
    pub fn get_ava_single_secret<A: AsRef<Attribute>>(&self, attr: A) -> Option<&str> {
        self.get_ava_set(attr).and_then(|vs| vs.to_secret_single())
    }

    /// Return a single datetime, if valid to transform this value.
    pub fn get_ava_single_datetime<A: AsRef<Attribute>>(&self, attr: A) -> Option<OffsetDateTime> {
        self.get_ava_set(attr)
            .and_then(|vs| vs.to_datetime_single())
    }

    /// Return a single `&str`, if valid to transform this value.
    pub(crate) fn get_ava_single_utf8<A: AsRef<Attribute>>(&self, attr: A) -> Option<&str> {
        self.get_ava_set(attr).and_then(|vs| vs.to_utf8_single())
    }

    /// Return a single `&str`, if valid to transform this value.
    pub(crate) fn get_ava_single_iutf8<A: AsRef<Attribute>>(&self, attr: A) -> Option<&str> {
        self.get_ava_set(attr).and_then(|vs| vs.to_iutf8_single())
    }

    /// Return a single `&str`, if valid to transform this value.
    pub(crate) fn get_ava_single_iname<A: AsRef<Attribute>>(&self, attr: A) -> Option<&str> {
        self.get_ava_set(attr).and_then(|vs| vs.to_iname_single())
    }

    /// Return a single `&Url`, if valid to transform this value.
    pub fn get_ava_single_url<A: AsRef<Attribute>>(&self, attr: A) -> Option<&Url> {
        self.get_ava_set(attr).and_then(|vs| vs.to_url_single())
    }

    pub fn get_ava_single_uuid<A: AsRef<Attribute>>(&self, attr: A) -> Option<Uuid> {
        self.get_ava_set(attr).and_then(|vs| vs.to_uuid_single())
    }

    pub fn get_ava_single_refer<A: AsRef<Attribute>>(&self, attr: A) -> Option<Uuid> {
        self.get_ava_set(attr).and_then(|vs| vs.to_refer_single())
    }

    pub fn get_ava_mail_primary<A: AsRef<Attribute>>(&self, attr: A) -> Option<&str> {
        self.get_ava_set(attr)
            .and_then(|vs| vs.to_email_address_primary_str())
    }

    pub fn get_ava_iter_mail<A: AsRef<Attribute>>(
        &self,
        attr: A,
    ) -> Option<impl Iterator<Item = &str>> {
        self.get_ava_set(attr).and_then(|vs| vs.as_email_str_iter())
    }

    /// Return a single protocol filter, if valid to transform this value.
    pub fn get_ava_single_protofilter<A: AsRef<Attribute>>(&self, attr: A) -> Option<&ProtoFilter> {
        self.get_ava_set(attr)
            .and_then(|vs| vs.to_json_filter_single())
    }

    pub fn get_ava_single_private_binary<A: AsRef<Attribute>>(&self, attr: A) -> Option<&[u8]> {
        self.get_ava_set(attr)
            .and_then(|vs| vs.to_private_binary_single())
    }

    pub fn get_ava_single_jws_key_es256<A: AsRef<Attribute>>(
        &self,
        attr: A,
    ) -> Option<&JwsEs256Signer> {
        self.get_ava_set(attr)
            .and_then(|vs| vs.to_jws_key_es256_single())
    }

    pub fn get_ava_single_eckey_private<A: AsRef<Attribute>>(
        &self,
        attr: A,
    ) -> Option<&EcKey<Private>> {
        self.get_ava_set(attr)
            .and_then(|vs| vs.to_eckey_private_single())
    }

    pub fn get_ava_single_eckey_public<A: AsRef<Attribute>>(
        &self,
        attr: A,
    ) -> Option<&EcKey<Public>> {
        self.get_ava_set(attr)
            .and_then(|vs| vs.to_eckey_public_single())
    }

    pub fn get_ava_webauthn_attestation_ca_list<A: AsRef<Attribute>>(
        &self,
        attr: A,
    ) -> Option<&AttestationCaList> {
        self.get_ava_set(attr)
            .and_then(|vs| vs.as_webauthn_attestation_ca_list())
    }

    pub fn get_ava_application_password<A: AsRef<Attribute>>(
        &self,
        attr: A,
    ) -> Option<&BTreeMap<Uuid, Vec<ApplicationPassword>>> {
        self.get_ava_set(attr)
            .and_then(|vs| vs.as_application_password_map())
    }

    /// Return a single security principle name, if valid to transform this value.
    pub(crate) fn generate_spn(&self, domain_name: &str) -> Option<ValueSet> {
        if let Some(name) = self.get_ava_single_iname(Attribute::Name) {
            // There is a name attribute, lets return it.
            return Some(ValueSetSpn::new((name.into(), domain_name.into())));
        }

        // Some entries may not have a name. There are now three paths.
        let spn_set = self.get_ava_set(Attribute::Spn)?;

        if spn_set.syntax() == SyntaxType::SecurityPrincipalName {
            // - we already have a valid spn
            Some(spn_set.clone())
        } else if let Some(name) = spn_set.to_iname_single() {
            // - we have an iname stashed into the spn attr for generation.
            Some(ValueSetSpn::new((name.into(), domain_name.into())))
        } else {
            // - We have no way to proceed
            None
        }
    }

    /// Assert if an attribute of this name is present on this entry.
    pub fn attribute_pres<A: AsRef<Attribute>>(&self, attr: A) -> bool {
        self.attrs.contains_key(attr.as_ref())
    }

    /// Assert if an attribute of this name is present, and one of its values contains
    /// an exact match of this partial value.
    pub fn attribute_equality<A: AsRef<Attribute>>(&self, attr: A, value: &PartialValue) -> bool {
        // we assume based on schema normalisation on the way in
        // that the equality here of the raw values MUST be correct.
        // We also normalise filters, to ensure that their values are
        // syntax valid and will correctly match here with our indexes.
        match self.attrs.get(attr.as_ref()) {
            Some(v_list) => v_list.contains(value),
            None => false,
        }
    }

    /// Assert if an attribute of this name is present, and one of it's values contains
    /// the following substring, if possible to perform the substring comparison.
    pub fn attribute_substring<A: AsRef<Attribute>>(
        &self,
        attr: A,
        subvalue: &PartialValue,
    ) -> bool {
        self.get_ava_set(attr)
            .map(|vset| vset.substring(subvalue))
            .unwrap_or(false)
    }

    /// Assert if an attribute of this name is present, and one of its values startswith
    /// the following string, if possible to perform the comparison.
    pub fn attribute_startswith<A: AsRef<Attribute>>(
        &self,
        attr: A,
        subvalue: &PartialValue,
    ) -> bool {
        self.get_ava_set(attr)
            .map(|vset| vset.startswith(subvalue))
            .unwrap_or(false)
    }

    /// Assert if an attribute of this name is present, and one of its values startswith
    /// the following string, if possible to perform the comparison.
    pub fn attribute_endswith<A: AsRef<Attribute>>(
        &self,
        attr: A,
        subvalue: &PartialValue,
    ) -> bool {
        self.get_ava_set(attr)
            .map(|vset| vset.endswith(subvalue))
            .unwrap_or(false)
    }

    /// Assert if an attribute of this name is present, and one of its values is less than
    /// the following partial value
    pub fn attribute_lessthan<A: AsRef<Attribute>>(
        &self,
        attr: A,
        subvalue: &PartialValue,
    ) -> bool {
        self.get_ava_set(attr)
            .map(|vset| vset.lessthan(subvalue))
            .unwrap_or(false)
    }

    // Since EntryValid/Invalid is just about class adherence, not Value correctness, we
    // can now apply filters to invalid entries - why? Because even if they aren't class
    // valid, we still have strict typing checks between the filter -> entry to guarantee
    // they should be functional. We'll never match something that isn't syntactically valid.
    #[inline(always)]
    #[instrument(level = "trace", name = "entry::entry_match_no_index", skip(self))]
    /// Test if the following filter applies to and matches this entry.
    pub fn entry_match_no_index(&self, filter: &Filter<FilterValidResolved>) -> bool {
        self.entry_match_no_index_inner(filter.to_inner())
    }

    // This is private, but exists on all types, so that valid and normal can then
    // expose the simpler wrapper for entry_match_no_index only.
    // Assert if this filter matches the entry (no index)
    fn entry_match_no_index_inner(&self, filter: &FilterResolved) -> bool {
        // Go through the filter components and check them in the entry.
        // This is recursive!!!!
        match filter {
            FilterResolved::Eq(attr, value, _) => self.attribute_equality(attr, value),
            FilterResolved::Cnt(attr, subvalue, _) => self.attribute_substring(attr, subvalue),
            FilterResolved::Stw(attr, subvalue, _) => self.attribute_startswith(attr, subvalue),
            FilterResolved::Enw(attr, subvalue, _) => self.attribute_endswith(attr, subvalue),
            FilterResolved::Pres(attr, _) => self.attribute_pres(attr),
            FilterResolved::LessThan(attr, subvalue, _) => self.attribute_lessthan(attr, subvalue),
            // Check with ftweedal about or filter zero len correctness.
            FilterResolved::Or(l, _) => l.iter().any(|f| self.entry_match_no_index_inner(f)),
            // Check with ftweedal about and filter zero len correctness.
            FilterResolved::And(l, _) => l.iter().all(|f| self.entry_match_no_index_inner(f)),
            FilterResolved::Inclusion(_, _) => {
                // An inclusion doesn't make sense on an entry in isolation!
                // Inclusions are part of exists queries, on search they mean
                // nothing!
                false
            }
            FilterResolved::AndNot(f, _) => !self.entry_match_no_index_inner(f),
            FilterResolved::Invalid(_) => false,
        }
    }

    /// Given this entry, generate a filter containing the requested attributes strings as
    /// equality components.
    pub fn filter_from_attrs(&self, attrs: &[Attribute]) -> Option<Filter<FilterInvalid>> {
        // Because we are a valid entry, a filter we create still may not
        // be valid because the internal server entry templates are still
        // created by humans! Plus double checking something already valid
        // is not bad ...
        //
        // Generate a filter from the attributes requested and defined.
        // Basically, this is a series of nested and's (which will be
        // optimised down later: but if someone wants to solve flatten() ...)

        // Take name: (a, b), name: (c, d) -> (name, a), (name, b), (name, c), (name, d)

        let mut pairs: Vec<(Attribute, PartialValue)> = Vec::with_capacity(0);

        for attr in attrs {
            match self.attrs.get(attr) {
                Some(values) => values
                    .to_partialvalue_iter()
                    .for_each(|pv| pairs.push((attr.clone(), pv))),
                None => return None,
            }
        }

        let res: Vec<FC> = pairs
            .into_iter()
            .map(|(attr, pv)| FC::Eq(attr, pv))
            .collect();
        Some(filter_all!(f_and(res)))
    }

    /// Given this entry, generate a modification list that would "assert"
    /// another entry is in the same/identical attribute state.
    pub fn gen_modlist_assert(
        &self,
        schema: &dyn SchemaTransaction,
    ) -> Result<ModifyList<ModifyInvalid>, SchemaError> {
        // Create a modlist from this entry. We make this assuming we want the entry
        // to have this one as a subset of values. This means if we have single
        // values, we'll replace, if they are multivalue, we present them.
        let mut mods = ModifyList::new();

        for (k, vs) in self.attrs.iter() {
            // WHY?! We skip uuid here because it is INVALID for a UUID
            // to be in a modlist, and the base.rs plugin will fail if it
            // is there. This actually doesn't matter, because to apply the
            // modlist in these situations we already know the entry MUST
            // exist with that UUID, we only need to conform it's other
            // attributes into the same state.
            //
            // In the future, if we make uuid a real entry type, then this
            // check can "go away" because uuid will never exist as an ava.
            //
            // NOTE: Remove this check when uuid becomes a real attribute.
            // UUID is now a real attribute, but it also has an ava for db_entry
            // conversion - so what do? If we remove it here, we could have CSN issue with
            // repl on uuid conflict, but it probably shouldn't be an ava either ...
            // as a result, I think we need to keep this continue line to not cause issues.
            if *k == Attribute::Uuid {
                continue;
            }
            // Get the schema attribute type out.
            match schema.is_multivalue(k) {
                Ok(r) => {
                    // As this is single value, purge then present to maintain this
                    // invariant.
                    if !r ||
                        // we need to be able to express REMOVAL of attributes, so we
                        // purge here for migrations of certain system attributes.
                        *k == Attribute::AcpReceiverGroup ||
                        *k == Attribute::AcpCreateAttr ||
                        *k == Attribute::AcpCreateClass ||
                        *k == Attribute::AcpModifyPresentAttr ||
                        *k == Attribute::AcpModifyRemovedAttr ||
                        *k == Attribute::AcpModifyClass ||
                        *k == Attribute::SystemMust ||
                        *k == Attribute::SystemMay
                    {
                        mods.push_mod(Modify::Purged(k.clone()));
                    }
                }
                // A schema error happened, fail the whole operation.
                Err(e) => return Err(e),
            }
            for v in vs.to_value_iter() {
                mods.push_mod(Modify::Present(k.clone(), v.clone()));
            }
        }

        Ok(mods)
    }

    /// Determine if this entry is recycled or a tombstone, and map that to "None". This allows
    /// filter_map to effectively remove entries that should not be considered as "alive".
    pub fn mask_recycled_ts(&self) -> Option<&Self> {
        // Only when cls has ts/rc then None, else always Some(self).
        match self.attrs.get(&Attribute::Class) {
            Some(cls) => {
                if cls.contains(&EntryClass::Tombstone.to_partialvalue())
                    || cls.contains(&EntryClass::Recycled.to_partialvalue())
                {
                    None
                } else {
                    Some(self)
                }
            }
            None => Some(self),
        }
    }

    /// Determine if this entry is recycled, and map that to "None". This allows
    /// filter_map to effectively remove entries that are recycled in some cases.
    pub fn mask_recycled(&self) -> Option<&Self> {
        // Only when cls has ts/rc then None, else lways Some(self).
        match self.attrs.get(&Attribute::Class) {
            Some(cls) => {
                if cls.contains(&EntryClass::Recycled.to_partialvalue()) {
                    None
                } else {
                    Some(self)
                }
            }
            None => Some(self),
        }
    }

    /// Determine if this entry is a tombstone, and map that to "None". This allows
    /// filter_map to effectively remove entries that are tombstones in some cases.
    pub fn mask_tombstone(&self) -> Option<&Self> {
        // Only when cls has ts/rc then None, else lways Some(self).
        match self.attrs.get(&Attribute::Class) {
            Some(cls) => {
                if cls.contains(&EntryClass::Tombstone.to_partialvalue()) {
                    None
                } else {
                    Some(self)
                }
            }
            None => Some(self),
        }
    }
}

impl<STATE> Entry<EntryInvalid, STATE>
where
    STATE: Clone,
{
    // This should always work? It's only on validate that we'll build
    // a list of syntax violations ...
    // If this already exists, we silently drop the event. This is because
    // we need this to be *state* based where we assert presence.
    pub fn add_ava(&mut self, attr: Attribute, value: Value) {
        self.valid.ecstate.change_ava(&self.valid.cid, &attr);
        self.add_ava_int(attr, value);
    }

    pub fn add_ava_if_not_exist<A: AsRef<Attribute>>(&mut self, attr: A, value: Value) {
        let attr_ref = attr.as_ref();
        // This returns true if the value WAS changed! See add_ava_int.
        if self.add_ava_int(attr_ref.clone(), value) {
            // In this case, we ONLY update the changestate if the value was already present!
            self.valid.ecstate.change_ava(&self.valid.cid, attr_ref);
        }
    }

    fn assert_ava<A: AsRef<Attribute>>(
        &mut self,
        attr: A,
        value: &PartialValue,
    ) -> Result<(), OperationError> {
        self.valid
            .ecstate
            .change_ava(&self.valid.cid, attr.as_ref());

        if self.attribute_equality(attr, value) {
            Ok(())
        } else {
            Err(OperationError::ModifyAssertionFailed)
        }
    }

    /// Remove an attribute-value pair from this entry. If the ava doesn't exist, we
    /// don't do anything else since we are asserting the absence of a value.
    pub(crate) fn remove_ava<A: AsRef<Attribute>>(&mut self, attr: A, value: &PartialValue) {
        let attr_ref = attr.as_ref();
        self.valid.ecstate.change_ava(&self.valid.cid, attr_ref);

        let rm = if let Some(vs) = self.attrs.get_mut(attr_ref) {
            vs.remove(value, &self.valid.cid);
            vs.is_empty()
        } else {
            false
        };
        if rm {
            self.attrs.remove(attr_ref);
        };
    }

    pub(crate) fn remove_avas<A: AsRef<Attribute>>(
        &mut self,
        attr: A,
        values: &BTreeSet<PartialValue>,
    ) {
        let attr_ref = attr.as_ref();
        self.valid.ecstate.change_ava(&self.valid.cid, attr_ref);

        let rm = if let Some(vs) = self.attrs.get_mut(attr_ref) {
            values.iter().for_each(|k| {
                vs.remove(k, &self.valid.cid);
            });
            vs.is_empty()
        } else {
            false
        };
        if rm {
            self.attrs.remove(attr_ref);
        };
    }

    /// Remove all values of this attribute from the entry. If it doesn't exist, this
    /// asserts that no content of that attribute exist.
    pub(crate) fn purge_ava<A: AsRef<Attribute>>(&mut self, attr: A) {
        let attr_ref = attr.as_ref();
        self.valid.ecstate.change_ava(&self.valid.cid, attr_ref);
        // self.valid.eclog.purge_ava(&self.valid.cid, attr);

        let can_remove = self
            .attrs
            .get_mut(attr_ref)
            .map(|vs| vs.purge(&self.valid.cid))
            // Default to false since a missing attr can't be removed!
            .unwrap_or_default();
        if can_remove {
            self.attrs.remove(attr_ref);
        }
    }

    /// Remove this value set from the entry, returning the value set at the time of removal.
    pub fn pop_ava<A: AsRef<Attribute>>(&mut self, attr: A) -> Option<ValueSet> {
        let attr_ref = attr.as_ref();
        self.valid.ecstate.change_ava(&self.valid.cid, attr_ref);

        let mut vs = self.attrs.remove(attr_ref)?;
        if vs.purge(&self.valid.cid) {
            // Can return as is.
            Some(vs)
        } else {
            // This type may need special handling. Clone and reinsert.
            let r_vs = vs.clone();
            self.attrs.insert(attr_ref.clone(), vs);
            Some(r_vs)
        }
    }

    /// Unlike pop or purge, this does NOT respect the attributes purge settings, meaning
    /// that this can break replication by force clearing the state of an attribute. It's
    /// useful for things like "session" to test the grace window by removing the revoked
    /// sessions from the value set that you otherwise, could not.
    #[cfg(test)]
    pub(crate) fn force_trim_ava<A: AsRef<Attribute>>(&mut self, attr: A) -> Option<ValueSet> {
        self.valid
            .ecstate
            .change_ava(&self.valid.cid, attr.as_ref());
        self.attrs.remove(attr.as_ref())
    }

    /// Replace the content of this attribute with the values from this
    /// iterator. If the iterator is empty, the attribute is purged.
    pub fn set_ava<T>(&mut self, attr: &Attribute, iter: T)
    where
        T: Clone + IntoIterator<Item = Value>,
    {
        self.purge_ava(attr);
        self.set_ava_iter_int(attr.clone(), iter)
    }

    /// Replace the content of this attribute with a new value set. Effectively this is
    /// a a "purge and set".
    pub fn set_ava_set(&mut self, attr: &Attribute, vs: ValueSet) {
        self.purge_ava(attr);
        if let Some(existing_vs) = self.attrs.get_mut(attr) {
            let _ = existing_vs.merge(&vs);
        } else {
            self.attrs.insert(attr.clone(), vs);
        }
    }

    /// Merge the content from the new ValueSet into the existing ValueSet. If no existing
    /// ValueSet is present, then these data are inserted.
    pub fn merge_ava_set(&mut self, attr: &Attribute, vs: ValueSet) -> Result<(), OperationError> {
        self.valid.ecstate.change_ava(&self.valid.cid, attr);
        if let Some(existing_vs) = self.attrs.get_mut(attr) {
            existing_vs.merge(&vs)
        } else {
            self.attrs.insert(attr.clone(), vs);
            Ok(())
        }
    }

    /// Apply the content of this modlist to this entry, enforcing the expressed state.
    pub fn apply_modlist(
        &mut self,
        modlist: &ModifyList<ModifyValid>,
    ) -> Result<(), OperationError> {
        for modify in modlist {
            match modify {
                Modify::Present(attr, value) => {
                    self.add_ava(attr.clone(), value.clone());
                }
                Modify::Removed(attr, value) => {
                    self.remove_ava(attr, value);
                }
                Modify::Purged(attr) => {
                    self.purge_ava(attr);
                }
                Modify::Assert(attr, value) => {
                    self.assert_ava(attr, value).inspect_err(|_e| {
                        error!("Modification assertion was not met. {} {:?}", attr, value);
                    })?;
                }
                Modify::Set(attr, valueset) => self.set_ava_set(attr, valueset.clone()),
            }
        }
        Ok(())
    }
}

impl<VALID, STATE> PartialEq for Entry<VALID, STATE> {
    fn eq(&self, rhs: &Entry<VALID, STATE>) -> bool {
        // This may look naive - but it is correct. This is because
        // all items that end up in an item MUST have passed through
        // schema validation and normalisation so we can assume that
        // all rules were applied correctly. Thus we can just simply
        // do a char-compare like this.
        //
        // Of course, this is only true on the "Valid" types ... the others
        // are not guaranteed to support this ... but more likely that will
        // just end in eager false-results. We'll never say something is true
        // that should NOT be.
        compare_attrs(&self.attrs, &rhs.attrs)
    }
}

/// This is a helper function to create an entry from an iterator of attribute-value pairs. This is a replacement for the old `entry_init!`` macro
pub(crate) fn entry_init_fn<T>(args: T) -> EntryInitNew
where
    T: IntoIterator<Item = (Attribute, Value)>,
{
    let mut entry: EntryInitNew = Entry::new();
    args.into_iter().for_each(|(k, v)| entry.add_ava(k, v));
    entry
}

#[cfg(test)]
mod tests {
    use crate::prelude::*;
    use std::collections::BTreeSet as Set;

    use hashbrown::HashMap;

    use crate::be::{IdxKey, IdxSlope};
    use crate::entry::{Entry, EntryInit, EntryInvalid, EntryNew};
    use crate::modify::{Modify, ModifyList};
    use crate::value::{IndexType, PartialValue, Value};

    #[test]
    fn test_entry_basic() {
        let mut e: Entry<EntryInit, EntryNew> = Entry::new();

        e.add_ava(Attribute::UserId, Value::from("william"));
    }

    #[test]
    fn test_entry_dup_value() {
        // Schema doesn't matter here because we are duplicating a value
        // it should fail!

        // We still probably need schema here anyway to validate what we
        // are adding ... Or do we validate after the changes are made in
        // total?
        let mut e: Entry<EntryInit, EntryNew> = Entry::new();
        e.add_ava(Attribute::UserId, Value::from("william"));
        e.add_ava(Attribute::UserId, Value::from("william"));

        let values = e.get_ava_set(Attribute::UserId).expect("Failed to get ava");
        // Should only be one value!
        assert_eq!(values.len(), 1)
    }

    #[test]
    fn test_entry_pres() {
        let mut e: Entry<EntryInit, EntryNew> = Entry::new();
        e.add_ava(Attribute::UserId, Value::from("william"));

        assert!(e.attribute_pres(Attribute::UserId));
        assert!(!e.attribute_pres(Attribute::Name));
    }

    #[test]
    fn test_entry_equality() {
        let mut e: Entry<EntryInit, EntryNew> = Entry::new();

        e.add_ava(Attribute::UserId, Value::from("william"));

        assert!(e.attribute_equality(Attribute::UserId, &PartialValue::new_utf8s("william")));
        assert!(!e.attribute_equality(Attribute::UserId, &PartialValue::new_utf8s("test")));
        assert!(!e.attribute_equality(Attribute::NonExist, &PartialValue::new_utf8s("william")));
        // Also test non-matching attr syntax
        assert!(!e.attribute_equality(Attribute::UserId, &PartialValue::new_iutf8("william")));
    }

    #[test]
    fn test_entry_substring() {
        let mut e: Entry<EntryInit, EntryNew> = Entry::new();

        e.add_ava(Attribute::UserId, Value::from("william"));

        assert!(e.attribute_substring(Attribute::UserId, &PartialValue::new_utf8s("william")));
        assert!(e.attribute_substring(Attribute::UserId, &PartialValue::new_utf8s("will")));
        assert!(e.attribute_substring(Attribute::UserId, &PartialValue::new_utf8s("liam")));
        assert!(e.attribute_substring(Attribute::UserId, &PartialValue::new_utf8s("lli")));
        assert!(!e.attribute_substring(Attribute::UserId, &PartialValue::new_utf8s("llim")));
        assert!(!e.attribute_substring(Attribute::UserId, &PartialValue::new_utf8s("bob")));
        assert!(!e.attribute_substring(Attribute::UserId, &PartialValue::new_utf8s("wl")));

        assert!(e.attribute_startswith(Attribute::UserId, &PartialValue::new_utf8s("will")));
        assert!(!e.attribute_startswith(Attribute::UserId, &PartialValue::new_utf8s("liam")));
        assert!(!e.attribute_startswith(Attribute::UserId, &PartialValue::new_utf8s("lli")));
        assert!(!e.attribute_startswith(Attribute::UserId, &PartialValue::new_utf8s("llim")));
        assert!(!e.attribute_startswith(Attribute::UserId, &PartialValue::new_utf8s("bob")));
        assert!(!e.attribute_startswith(Attribute::UserId, &PartialValue::new_utf8s("wl")));

        assert!(e.attribute_endswith(Attribute::UserId, &PartialValue::new_utf8s("liam")));
        assert!(!e.attribute_endswith(Attribute::UserId, &PartialValue::new_utf8s("will")));
        assert!(!e.attribute_endswith(Attribute::UserId, &PartialValue::new_utf8s("lli")));
        assert!(!e.attribute_endswith(Attribute::UserId, &PartialValue::new_utf8s("llim")));
        assert!(!e.attribute_endswith(Attribute::UserId, &PartialValue::new_utf8s("bob")));
        assert!(!e.attribute_endswith(Attribute::UserId, &PartialValue::new_utf8s("wl")));
    }

    #[test]
    fn test_entry_lessthan() {
        let mut e1: Entry<EntryInit, EntryNew> = Entry::new();

        let pv2 = PartialValue::new_uint32(2);
        let pv8 = PartialValue::new_uint32(8);
        let pv10 = PartialValue::new_uint32(10);
        let pv15 = PartialValue::new_uint32(15);

        e1.add_ava(Attribute::TestAttr, Value::new_uint32(10));

        assert!(!e1.attribute_lessthan(Attribute::TestAttr, &pv2));
        assert!(!e1.attribute_lessthan(Attribute::TestAttr, &pv8));
        assert!(!e1.attribute_lessthan(Attribute::TestAttr, &pv10));
        assert!(e1.attribute_lessthan(Attribute::TestAttr, &pv15));

        e1.add_ava(Attribute::TestAttr, Value::new_uint32(8));

        assert!(!e1.attribute_lessthan(Attribute::TestAttr, &pv2));
        assert!(!e1.attribute_lessthan(Attribute::TestAttr, &pv8));
        assert!(e1.attribute_lessthan(Attribute::TestAttr, &pv10));
        assert!(e1.attribute_lessthan(Attribute::TestAttr, &pv15));
    }

    #[test]
    fn test_entry_apply_modlist() {
        // Test application of changes to an entry.
        let mut e: Entry<EntryInvalid, EntryNew> = Entry::new().into_invalid_new();

        e.add_ava(Attribute::UserId, Value::from("william"));

        let present_single_mods = ModifyList::new_valid_list(vec![Modify::Present(
            Attribute::Attr,
            Value::new_iutf8("value"),
        )]);

        assert!(e.apply_modlist(&present_single_mods).is_ok());

        // Assert the changes are there
        assert!(e.attribute_equality(Attribute::UserId, &PartialValue::new_utf8s("william")));
        assert!(e.attribute_equality(Attribute::Attr, &PartialValue::new_iutf8("value")));

        // Assert present for multivalue
        let present_multivalue_mods = ModifyList::new_valid_list(vec![
            Modify::Present(Attribute::Class, Value::new_iutf8("test")),
            Modify::Present(Attribute::Class, Value::new_iutf8("multi_test")),
        ]);

        assert!(e.apply_modlist(&present_multivalue_mods).is_ok());

        assert!(e.attribute_equality(Attribute::Class, &PartialValue::new_iutf8("test")));
        assert!(e.attribute_equality(Attribute::Class, &PartialValue::new_iutf8("multi_test")));

        // Assert purge on single/multi/empty value
        let purge_single_mods = ModifyList::new_valid_list(vec![Modify::Purged(Attribute::Attr)]);

        assert!(e.apply_modlist(&purge_single_mods).is_ok());

        assert!(!e.attribute_pres(Attribute::Attr));

        let purge_multi_mods = ModifyList::new_valid_list(vec![Modify::Purged(Attribute::Class)]);

        assert!(e.apply_modlist(&purge_multi_mods).is_ok());

        assert!(!e.attribute_pres(Attribute::Class));

        let purge_empty_mods = purge_single_mods;

        assert!(e.apply_modlist(&purge_empty_mods).is_ok());

        // Assert removed on value that exists and doesn't exist
        let remove_mods = ModifyList::new_valid_list(vec![Modify::Removed(
            Attribute::Attr,
            PartialValue::new_iutf8("value"),
        )]);

        assert!(e.apply_modlist(&present_single_mods).is_ok());
        assert!(e.attribute_equality(Attribute::Attr, &PartialValue::new_iutf8("value")));
        assert!(e.apply_modlist(&remove_mods).is_ok());
        assert!(!e.attrs.contains_key(&Attribute::Attr));

        let remove_empty_mods = remove_mods;

        assert!(e.apply_modlist(&remove_empty_mods).is_ok());

        assert!(!e.attrs.contains_key(&Attribute::Attr));
    }

    #[test]
    fn test_entry_idx_diff() {
        let mut e1: Entry<EntryInit, EntryNew> = Entry::new();
        e1.add_ava(Attribute::UserId, Value::from("william"));
        let mut e1_mod = e1.clone();
        e1_mod.add_ava(Attribute::Extra, Value::from("test"));

        let e1 = e1.into_sealed_committed();
        let e1_mod = e1_mod.into_sealed_committed();

        let mut e2: Entry<EntryInit, EntryNew> = Entry::new();
        e2.add_ava(Attribute::UserId, Value::from("claire"));
        let e2 = e2.into_sealed_committed();

        let mut idxmeta = HashMap::with_capacity(8);
        idxmeta.insert(
            IdxKey {
                attr: Attribute::UserId,
                itype: IndexType::Equality,
            },
            IdxSlope::MAX,
        );
        idxmeta.insert(
            IdxKey {
                attr: Attribute::UserId,
                itype: IndexType::Presence,
            },
            IdxSlope::MAX,
        );
        idxmeta.insert(
            IdxKey {
                attr: Attribute::Extra,
                itype: IndexType::Equality,
            },
            IdxSlope::MAX,
        );

        // When we do None, None, we get nothing back.
        let r1 = Entry::idx_diff(&idxmeta, None, None);
        eprintln!("{r1:?}");
        assert_eq!(r1, Vec::with_capacity(0));

        // Check generating a delete diff
        let mut del_r = Entry::idx_diff(&idxmeta, Some(&e1), None);
        del_r.sort_unstable();
        eprintln!("del_r {del_r:?}");
        assert!(
            del_r[0]
                == Err((
                    &Attribute::UserId,
                    IndexType::Equality,
                    "william".to_string()
                ))
        );
        assert!(del_r[1] == Err((&Attribute::UserId, IndexType::Presence, "_".to_string())));

        // Check generating an add diff
        let mut add_r = Entry::idx_diff(&idxmeta, None, Some(&e1));
        add_r.sort_unstable();
        eprintln!("{add_r:?}");
        assert!(
            add_r[0]
                == Ok((
                    &Attribute::UserId,
                    IndexType::Equality,
                    "william".to_string()
                ))
        );
        assert!(add_r[1] == Ok((&Attribute::UserId, IndexType::Presence, "_".to_string())));

        // Check the mod cases now

        // Check no changes
        let no_r = Entry::idx_diff(&idxmeta, Some(&e1), Some(&e1));
        assert!(no_r.is_empty());

        // Check "adding" an attribute.
        let add_a_r = Entry::idx_diff(&idxmeta, Some(&e1), Some(&e1_mod));
        assert!(add_a_r[0] == Ok((&Attribute::Extra, IndexType::Equality, "test".to_string())));

        // Check "removing" an attribute.
        let del_a_r = Entry::idx_diff(&idxmeta, Some(&e1_mod), Some(&e1));
        assert!(del_a_r[0] == Err((&Attribute::Extra, IndexType::Equality, "test".to_string())));

        // Change an attribute.
        let mut chg_r = Entry::idx_diff(&idxmeta, Some(&e1), Some(&e2));
        chg_r.sort_unstable();
        eprintln!("{chg_r:?}");
        assert!(
            chg_r[1]
                == Err((
                    &Attribute::UserId,
                    IndexType::Equality,
                    "william".to_string()
                ))
        );

        assert!(
            chg_r[0]
                == Ok((
                    &Attribute::UserId,
                    IndexType::Equality,
                    "claire".to_string()
                ))
        );
    }

    #[test]
    fn test_entry_mask_recycled_ts() {
        let mut e1: Entry<EntryInit, EntryNew> = Entry::new();
        e1.add_ava(Attribute::Class, EntryClass::Person.to_value());
        let e1 = e1.into_sealed_committed();
        assert!(e1.mask_recycled_ts().is_some());

        let mut e2: Entry<EntryInit, EntryNew> = Entry::new();
        e2.add_ava(Attribute::Class, EntryClass::Person.to_value());
        e2.add_ava(Attribute::Class, EntryClass::Recycled.into());
        let e2 = e2.into_sealed_committed();
        assert!(e2.mask_recycled_ts().is_none());

        let mut e3: Entry<EntryInit, EntryNew> = Entry::new();
        e3.add_ava(Attribute::Class, EntryClass::Tombstone.into());
        let e3 = e3.into_sealed_committed();
        assert!(e3.mask_recycled_ts().is_none());
    }

    #[test]
    fn test_entry_idx_name2uuid_diff() {
        // none, none,
        let r = Entry::idx_name2uuid_diff(None, None);
        assert_eq!(r, (None, None));

        // none, some - test adding an entry gives back add sets
        {
            let mut e: Entry<EntryInit, EntryNew> = Entry::new();
            e.add_ava(Attribute::Class, EntryClass::Person.to_value());
            let e = e.into_sealed_committed();

            assert!(Entry::idx_name2uuid_diff(None, Some(&e)) == (Some(Set::new()), None));
        }

        {
            let mut e: Entry<EntryInit, EntryNew> = Entry::new();
            e.add_ava(Attribute::Class, EntryClass::Person.to_value());
            e.add_ava(Attribute::GidNumber, Value::new_uint32(1300));
            e.add_ava(Attribute::Name, Value::new_iname("testperson"));
            e.add_ava(
                Attribute::Spn,
                Value::new_spn_str("testperson", "example.com"),
            );
            e.add_ava(
                Attribute::Uuid,
                Value::Uuid(uuid!("9fec0398-c46c-4df4-9df5-b0016f7d563f")),
            );
            let e = e.into_sealed_committed();

            // Note the uuid isn't present!
            assert!(
                Entry::idx_name2uuid_diff(None, Some(&e))
                    == (
                        Some(btreeset![
                            "1300".to_string(),
                            "testperson".to_string(),
                            "testperson@example.com".to_string()
                        ]),
                        None
                    )
            );
            // some, none,
            // Check delete, swap the order of args
            assert!(
                Entry::idx_name2uuid_diff(Some(&e), None)
                    == (
                        None,
                        Some(btreeset![
                            "1300".to_string(),
                            "testperson".to_string(),
                            "testperson@example.com".to_string()
                        ])
                    )
            );

            // some, some (same), should be empty changes.
            assert!(
                Entry::idx_name2uuid_diff(Some(&e), Some(&e))
                    == (Some(Set::new()), Some(Set::new()))
            );
        }
        // some, some (diff)

        {
            let mut e1: Entry<EntryInit, EntryNew> = Entry::new();
            e1.add_ava(Attribute::Class, EntryClass::Person.to_value());
            e1.add_ava(
                Attribute::Spn,
                Value::new_spn_str("testperson", "example.com"),
            );
            let e1 = e1.into_sealed_committed();

            let mut e2: Entry<EntryInit, EntryNew> = Entry::new();
            e2.add_ava(Attribute::Class, EntryClass::Person.to_value());
            e2.add_ava(Attribute::Name, Value::new_iname("testperson"));
            e2.add_ava(
                Attribute::Spn,
                Value::new_spn_str("testperson", "example.com"),
            );
            let e2 = e2.into_sealed_committed();

            // One attr added
            assert!(
                Entry::idx_name2uuid_diff(Some(&e1), Some(&e2))
                    == (Some(btreeset!["testperson".to_string()]), Some(Set::new()))
            );

            // One removed
            assert!(
                Entry::idx_name2uuid_diff(Some(&e2), Some(&e1))
                    == (Some(Set::new()), Some(btreeset!["testperson".to_string()]))
            );
        }

        // Value changed, remove old, add new.
        {
            let mut e1: Entry<EntryInit, EntryNew> = Entry::new();
            e1.add_ava(Attribute::Class, EntryClass::Person.to_value());
            e1.add_ava(
                Attribute::Spn,
                Value::new_spn_str("testperson", "example.com"),
            );
            let e1 = e1.into_sealed_committed();

            let mut e2: Entry<EntryInit, EntryNew> = Entry::new();
            e2.add_ava(Attribute::Class, EntryClass::Person.to_value());
            e2.add_ava(
                Attribute::Spn,
                Value::new_spn_str("renameperson", "example.com"),
            );
            let e2 = e2.into_sealed_committed();

            assert!(
                Entry::idx_name2uuid_diff(Some(&e1), Some(&e2))
                    == (
                        Some(btreeset!["renameperson@example.com".to_string()]),
                        Some(btreeset!["testperson@example.com".to_string()])
                    )
            );
        }
    }

    #[test]
    fn test_entry_idx_uuid2spn_diff() {
        assert!(Entry::idx_uuid2spn_diff(None, None).is_none());

        let mut e1: Entry<EntryInit, EntryNew> = Entry::new();
        e1.add_ava(
            Attribute::Spn,
            Value::new_spn_str("testperson", "example.com"),
        );
        let e1 = e1.into_sealed_committed();

        let mut e2: Entry<EntryInit, EntryNew> = Entry::new();
        e2.add_ava(
            Attribute::Spn,
            Value::new_spn_str("renameperson", "example.com"),
        );
        let e2 = e2.into_sealed_committed();

        assert!(
            Entry::idx_uuid2spn_diff(None, Some(&e1))
                == Some(Ok(Value::new_spn_str("testperson", "example.com")))
        );
        assert!(Entry::idx_uuid2spn_diff(Some(&e1), None) == Some(Err(())));
        assert!(Entry::idx_uuid2spn_diff(Some(&e1), Some(&e1)).is_none());
        assert!(
            Entry::idx_uuid2spn_diff(Some(&e1), Some(&e2))
                == Some(Ok(Value::new_spn_str("renameperson", "example.com")))
        );
    }

    #[test]
    fn test_entry_idx_uuid2rdn_diff() {
        assert!(Entry::idx_uuid2rdn_diff(None, None).is_none());

        let mut e1: Entry<EntryInit, EntryNew> = Entry::new();
        e1.add_ava(
            Attribute::Spn,
            Value::new_spn_str("testperson", "example.com"),
        );
        let e1 = e1.into_sealed_committed();

        let mut e2: Entry<EntryInit, EntryNew> = Entry::new();
        e2.add_ava(
            Attribute::Spn,
            Value::new_spn_str("renameperson", "example.com"),
        );
        let e2 = e2.into_sealed_committed();

        assert!(
            Entry::idx_uuid2rdn_diff(None, Some(&e1))
                == Some(Ok("spn=testperson@example.com".to_string()))
        );
        assert!(Entry::idx_uuid2rdn_diff(Some(&e1), None) == Some(Err(())));
        assert!(Entry::idx_uuid2rdn_diff(Some(&e1), Some(&e1)).is_none());
        assert!(
            Entry::idx_uuid2rdn_diff(Some(&e1), Some(&e2))
                == Some(Ok("spn=renameperson@example.com".to_string()))
        );
    }
}
