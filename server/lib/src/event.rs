//! An `event` is a self contained module of data, that contains all of the
//! required information for any operation to proceed. While there are many
//! types of potential events, they all eventually lower to one of:
//!
//! * AuthEvent
//! * SearchEvent
//! * ExistsEvent
//! * ModifyEvent
//! * CreateEvent
//! * DeleteEvent
//!
//! An "event" is generally then passed to the `QueryServer` for processing.
//! By making these fully self contained units, it means that we can assert
//! at event creation time we have all the correct data required to proceed
//! with the operation, and a clear path to know how to transform events between
//! various types.

use std::collections::BTreeSet;
#[cfg(test)]
use std::sync::Arc;

use kanidm_proto::{
    internal::{
        CreateRequest, DeleteRequest, ModifyList as ProtoModifyList, ModifyRequest, OperationError,
        SearchRequest, SearchResponse,
    },
    v1::{Entry as ProtoEntry, WhoamiResponse},
};
use ldap3_proto::simple::LdapFilter;
use uuid::Uuid;

use crate::{
    entry::{Entry, EntryCommitted, EntryInit, EntryNew, EntryReduced},
    filter::{Filter, FilterInvalid, FilterValid},
    modify::{ModifyInvalid, ModifyList, ModifyValid},
    prelude::*,
    schema::SchemaTransaction,
    value::PartialValue,
};

#[derive(Debug)]
pub struct SearchResult {
    entries: Vec<ProtoEntry>,
}

impl SearchResult {
    pub fn new(
        qs: &mut QueryServerReadTransaction,
        entries: &[Entry<EntryReduced, EntryCommitted>],
    ) -> Result<Self, OperationError> {
        let entries: Result<_, _> = entries
            .iter()
            .map(|e| {
                // All the needed transforms for this result are done
                // in search_ext. This is just an entry -> protoentry
                // step.
                e.to_pe(qs)
            })
            .collect();
        Ok(SearchResult { entries: entries? })
    }

    // Consume self into a search response
    pub fn response(self) -> SearchResponse {
        SearchResponse {
            entries: self.entries,
        }
    }

    // Consume into the array of entries, used in the json proto
    pub fn into_proto_array(self) -> Vec<ProtoEntry> {
        self.entries
    }
}

#[derive(Debug)]
pub struct SearchEvent {
    pub ident: Identity,
    // This is the filter as we apply and process it.
    pub filter: Filter<FilterValid>,
    // This is the original filter, for the purpose of ACI checking.
    pub filter_orig: Filter<FilterValid>,
    pub attrs: Option<BTreeSet<Attribute>>,
    pub effective_access_check: bool,
}

impl SearchEvent {
    pub fn from_message(
        ident: Identity,
        req: &SearchRequest,
        qs: &mut QueryServerReadTransaction,
    ) -> Result<Self, OperationError> {
        let f = Filter::from_ro(&ident, &req.filter, qs)?;
        // We do need to do this twice to account for the ignore_hidden
        // changes.
        let filter_orig = f
            .validate(qs.get_schema())
            .map_err(OperationError::SchemaViolation)?;
        let filter = filter_orig.clone().into_ignore_hidden();
        Ok(SearchEvent {
            ident,
            filter,
            filter_orig,
            // We can't get this from the SearchMessage because it's annoying with the
            // current macro design.
            attrs: None,
            effective_access_check: false,
        })
    }

    pub fn from_internal_message(
        ident: Identity,
        filter: &Filter<FilterInvalid>,
        attrs: Option<&[String]>,
        qs: &mut QueryServerReadTransaction,
    ) -> Result<Self, OperationError> {
        let r_attrs: Option<BTreeSet<Attribute>> = attrs.map(|vs| {
            vs.iter()
                .filter_map(|a| qs.get_schema().normalise_attr_if_exists(a.as_str()))
                .collect()
        });

        if let Some(s) = &r_attrs {
            if s.is_empty() {
                request_error!("EmptyRequest for attributes");
                return Err(OperationError::EmptyRequest);
            }
        }

        let filter_orig = filter.validate(qs.get_schema()).map_err(|e| {
            request_error!(?e, "filter schema violation");
            OperationError::SchemaViolation(e)
        })?;
        let filter = filter_orig.clone().into_ignore_hidden();

        Ok(SearchEvent {
            ident,
            filter,
            filter_orig,
            attrs: r_attrs,
            effective_access_check: false,
        })
    }

    pub fn from_internal_recycle_message(
        ident: Identity,
        filter: &Filter<FilterInvalid>,
        attrs: Option<&[String]>,
        qs: &QueryServerReadTransaction,
    ) -> Result<Self, OperationError> {
        let r_attrs: Option<BTreeSet<Attribute>> = attrs.map(|vs| {
            vs.iter()
                .filter_map(|a| {
                    qs.get_schema()
                        .normalise_attr_if_exists(a.as_str())
                        .map(|a_str| Attribute::from(a_str.as_str()))
                })
                .collect()
        });

        if let Some(s) = &r_attrs {
            if s.is_empty() {
                return Err(OperationError::EmptyRequest);
            }
        }

        let filter_orig = filter
            .validate(qs.get_schema())
            .map(|f| f.into_recycled())
            .map_err(OperationError::SchemaViolation)?;
        let filter = filter_orig.clone();

        Ok(SearchEvent {
            ident,
            filter,
            filter_orig,
            attrs: r_attrs,
            effective_access_check: false,
        })
    }

    pub fn from_whoami_request(
        ident: Identity,
        qs: &QueryServerReadTransaction,
    ) -> Result<Self, OperationError> {
        let filter_orig = filter_all!(f_self())
            .validate(qs.get_schema())
            .map_err(OperationError::SchemaViolation)?;
        let filter = filter_orig.clone().into_ignore_hidden();

        Ok(SearchEvent {
            ident,
            filter,
            filter_orig,
            attrs: None,
            effective_access_check: false,
        })
    }

    pub fn from_target_uuid_request(
        ident: Identity,
        target_uuid: Uuid,
        qs: &QueryServerReadTransaction,
    ) -> Result<Self, OperationError> {
        let filter_orig = filter_all!(f_eq(Attribute::Uuid, PartialValue::Uuid(target_uuid)))
            .validate(qs.get_schema())
            .map_err(OperationError::SchemaViolation)?;
        let filter = filter_orig.clone().into_ignore_hidden();
        Ok(SearchEvent {
            ident,
            filter,
            filter_orig,
            attrs: None,
            effective_access_check: false,
        })
    }

    /// ⚠️  - Bypass the schema state machine and force the filter to be considered valid.
    /// This is a TEST ONLY method and will never be exposed in production.
    #[cfg(test)]
    pub fn new_impersonate_entry(
        e: Arc<Entry<EntrySealed, EntryCommitted>>,
        filter: Filter<FilterInvalid>,
    ) -> Self {
        SearchEvent {
            ident: Identity::from_impersonate_entry_readonly(e),
            filter: filter.clone().into_valid(),
            filter_orig: filter.into_valid(),
            attrs: None,
            effective_access_check: false,
        }
    }

    /// ⚠️  - Bypass the schema state machine and force the filter to be considered valid.
    /// This is a TEST ONLY method and will never be exposed in production.
    #[cfg(test)]
    pub fn new_impersonate_identity(ident: Identity, filter: Filter<FilterInvalid>) -> Self {
        SearchEvent {
            ident,
            filter: filter.clone().into_valid(),
            filter_orig: filter.into_valid(),
            attrs: None,
            effective_access_check: false,
        }
    }

    pub fn new_impersonate(
        ident: &Identity,
        filter: Filter<FilterValid>,
        filter_orig: Filter<FilterValid>,
    ) -> Self {
        SearchEvent {
            ident: Identity::from_impersonate(ident),
            filter,
            filter_orig,
            attrs: None,
            effective_access_check: false,
        }
    }

    /// ⚠️  - Bypass the schema state machine and force the filter to be considered valid.
    /// This is a TEST ONLY method and will never be exposed in production.
    #[cfg(test)]
    pub fn new_rec_impersonate_entry(
        e: Arc<Entry<EntrySealed, EntryCommitted>>,
        filter: Filter<FilterInvalid>,
    ) -> Self {
        /* Impersonate a request for recycled objects */
        let filter_orig = filter.into_valid();
        let filter = filter_orig.clone().into_recycled();
        SearchEvent {
            ident: Identity::from_impersonate_entry_readonly(e),
            filter,
            filter_orig,
            attrs: None,
            effective_access_check: false,
        }
    }

    /// ⚠️  - Bypass the schema state machine and force the filter to be considered valid.
    /// This is a TEST ONLY method and will never be exposed in production.
    #[cfg(test)]
    pub fn new_ext_impersonate_entry(
        e: Arc<Entry<EntrySealed, EntryCommitted>>,
        filter: Filter<FilterInvalid>,
    ) -> Self {
        /* Impersonate an external request AKA filter ts + recycle */
        SearchEvent {
            ident: Identity::from_impersonate_entry_readonly(e),
            filter: filter.clone().into_valid().into_ignore_hidden(),
            filter_orig: filter.into_valid(),
            attrs: None,
            effective_access_check: false,
        }
    }

    pub(crate) fn new_ext_impersonate_uuid(
        qs: &mut QueryServerReadTransaction,
        ident: Identity,
        lf: &LdapFilter,
        attrs: Option<BTreeSet<Attribute>>,
    ) -> Result<Self, OperationError> {
        // Kanidm Filter from LdapFilter
        let f = Filter::from_ldap_ro(&ident, lf, qs)?;
        let filter_orig = f
            .validate(qs.get_schema())
            .map_err(OperationError::SchemaViolation)?;
        let filter = filter_orig.clone().into_ignore_hidden();
        Ok(SearchEvent {
            ident,
            filter,
            filter_orig,
            attrs,
            effective_access_check: false,
        })
    }

    /// ⚠️  - Bypass the schema state machine and force the filter to be considered valid.
    /// This is a TEST ONLY method and will never be exposed in production.
    #[cfg(test)]
    pub fn new_internal_invalid(filter: Filter<FilterInvalid>) -> Self {
        SearchEvent {
            ident: Identity::from_internal(),
            filter: filter.clone().into_valid(),
            filter_orig: filter.into_valid(),
            attrs: None,
            effective_access_check: false,
        }
    }

    pub(crate) fn new_internal(filter: Filter<FilterValid>) -> Self {
        SearchEvent {
            ident: Identity::from_internal(),
            filter: filter.clone(),
            filter_orig: filter,
            attrs: None,
            effective_access_check: false,
        }
    }
}

// Represents the decoded entries from the protocol -> internal entry representation
// including information about the identity performing the request, and if the
// request is internal or not.
#[derive(Debug)]
pub struct CreateEvent {
    pub ident: Identity,
    // This may still actually change to handle the *raw* nature of the
    // input that we plan to parse.
    pub entries: Vec<Entry<EntryInit, EntryNew>>,
    // Is the CreateEvent from an internal or external source?
    // This may affect which plugins are run ...
    /// If true, the list of created entry UUID's will be returned.
    pub return_created_uuids: bool,
}

impl CreateEvent {
    pub fn from_message(
        ident: Identity,
        req: &CreateRequest,
        qs: &mut QueryServerWriteTransaction,
    ) -> Result<Self, OperationError> {
        let rentries: Result<Vec<_>, _> = req
            .entries
            .iter()
            .map(|e| Entry::from_proto_entry(e, qs))
            .collect();
        // From ProtoEntry -> Entry
        // What is the correct consuming iterator here? Can we
        // even do that?
        match rentries {
            Ok(entries) => Ok(CreateEvent {
                ident,
                entries,
                return_created_uuids: false,
            }),
            Err(e) => Err(e),
        }
    }

    pub fn new_impersonate_identity(
        ident: Identity,
        entries: Vec<Entry<EntryInit, EntryNew>>,
    ) -> Self {
        CreateEvent {
            ident,
            entries,
            return_created_uuids: false,
        }
    }

    pub fn new_internal(entries: Vec<Entry<EntryInit, EntryNew>>) -> Self {
        CreateEvent {
            ident: Identity::from_internal(),
            entries,
            return_created_uuids: false,
        }
    }
}

#[derive(Debug)]
pub struct ExistsEvent {
    pub ident: Identity,
    // This is the filter, as it will be processed.
    pub filter: Filter<FilterValid>,
    // This is the original filter, for the purpose of ACI checking.
    pub filter_orig: Filter<FilterValid>,
}

impl ExistsEvent {
    pub fn new_internal(filter: Filter<FilterValid>) -> Self {
        ExistsEvent {
            ident: Identity::from_internal(),
            filter: filter.clone(),
            filter_orig: filter,
        }
    }

    /// ⚠️  - Bypass the schema state machine and force the filter to be considered valid.
    /// This is a TEST ONLY method and will never be exposed in production.
    #[cfg(test)]
    pub fn new_internal_invalid(filter: Filter<FilterInvalid>) -> Self {
        ExistsEvent {
            ident: Identity::from_internal(),
            filter: filter.clone().into_valid(),
            filter_orig: filter.into_valid(),
        }
    }
}

#[derive(Debug)]
pub struct DeleteEvent {
    pub ident: Identity,
    // This is the filter, as it will be processed.
    pub filter: Filter<FilterValid>,
    // This is the original filter, for the purpose of ACI checking.
    pub filter_orig: Filter<FilterValid>,
}

impl DeleteEvent {
    pub fn from_message(
        ident: Identity,
        req: &DeleteRequest,
        qs: &mut QueryServerWriteTransaction,
    ) -> Result<Self, OperationError> {
        let f = Filter::from_rw(&ident, &req.filter, qs)?;
        let filter_orig = f
            .validate(qs.get_schema())
            .map_err(OperationError::SchemaViolation)?;
        let filter = filter_orig.clone().into_ignore_hidden();
        Ok(DeleteEvent {
            ident,
            filter,
            filter_orig,
        })
    }

    pub fn from_parts(
        ident: Identity,
        f: &Filter<FilterInvalid>,
        qs: &mut QueryServerWriteTransaction,
    ) -> Result<Self, OperationError> {
        let filter_orig = f
            .validate(qs.get_schema())
            .map_err(OperationError::SchemaViolation)?;
        let filter = filter_orig.clone().into_ignore_hidden();
        Ok(DeleteEvent {
            ident,
            filter,
            filter_orig,
        })
    }

    /// ⚠️  - Bypass the schema state machine and force the filter to be considered valid.
    /// This is a TEST ONLY method and will never be exposed in production.
    #[cfg(test)]
    pub fn new_impersonate_entry(
        e: Arc<Entry<EntrySealed, EntryCommitted>>,
        filter: Filter<FilterInvalid>,
    ) -> Self {
        DeleteEvent {
            ident: Identity::from_impersonate_entry_readwrite(e),
            filter: filter.clone().into_valid(),
            filter_orig: filter.into_valid(),
        }
    }

    /// ⚠️  - Bypass the schema state machine, allowing an invalid filter to be used in an impersonate request.
    /// This is a TEST ONLY method and will never be exposed in production.
    #[cfg(test)]
    pub fn new_impersonate_identity(ident: Identity, filter: Filter<FilterInvalid>) -> Self {
        DeleteEvent {
            ident,
            filter: filter.clone().into_valid(),
            filter_orig: filter.into_valid(),
        }
    }

    /// ⚠️  - Bypass the schema state machine and force the filter to be considered valid.
    /// This is a TEST ONLY method and will never be exposed in production.
    #[cfg(test)]
    pub fn new_internal_invalid(filter: Filter<FilterInvalid>) -> Self {
        DeleteEvent {
            ident: Identity::from_internal(),
            filter: filter.clone().into_valid(),
            filter_orig: filter.into_valid(),
        }
    }

    pub fn new_internal(filter: Filter<FilterValid>) -> Self {
        DeleteEvent {
            ident: Identity::from_internal(),
            filter: filter.clone(),
            filter_orig: filter,
        }
    }
}

#[derive(Debug)]
pub struct ModifyEvent {
    pub ident: Identity,
    // This is the filter, as it will be processed.
    pub filter: Filter<FilterValid>,
    // This is the original filter, for the purpose of ACI checking.
    pub filter_orig: Filter<FilterValid>,
    pub modlist: ModifyList<ModifyValid>,
}

impl ModifyEvent {
    pub fn from_message(
        ident: Identity,
        req: &ModifyRequest,
        qs: &mut QueryServerWriteTransaction,
    ) -> Result<Self, OperationError> {
        let f = Filter::from_rw(&ident, &req.filter, qs)?;
        let m = ModifyList::from(&req.modlist, qs)?;
        let filter_orig = f
            .validate(qs.get_schema())
            .map_err(OperationError::SchemaViolation)?;
        let filter = filter_orig.clone().into_ignore_hidden();
        let modlist = m
            .validate(qs.get_schema())
            .map_err(OperationError::SchemaViolation)?;
        Ok(ModifyEvent {
            ident,
            filter,
            filter_orig,
            modlist,
        })
    }

    pub fn from_parts(
        ident: Identity,
        target_uuid: Uuid,
        proto_ml: &ProtoModifyList,
        filter: Filter<FilterInvalid>,
        qs: &mut QueryServerWriteTransaction,
    ) -> Result<Self, OperationError> {
        let f_uuid = filter_all!(f_eq(Attribute::Uuid, PartialValue::Uuid(target_uuid)));
        // Add any supplemental conditions we have.
        let f = Filter::join_parts_and(f_uuid, filter);

        let m = ModifyList::from(proto_ml, qs)?;
        let filter_orig = f
            .validate(qs.get_schema())
            .map_err(OperationError::SchemaViolation)?;
        let filter = filter_orig.clone().into_ignore_hidden();
        let modlist = m
            .validate(qs.get_schema())
            .map_err(OperationError::SchemaViolation)?;

        Ok(ModifyEvent {
            ident,
            filter,
            filter_orig,
            modlist,
        })
    }

    pub fn from_internal_parts(
        ident: Identity,
        ml: &ModifyList<ModifyInvalid>,
        filter: &Filter<FilterInvalid>,
        qs: &QueryServerWriteTransaction,
    ) -> Result<Self, OperationError> {
        let filter_orig = filter
            .validate(qs.get_schema())
            .map_err(OperationError::SchemaViolation)?;
        let filter = filter_orig.clone().into_ignore_hidden();
        let modlist = ml
            .validate(qs.get_schema())
            .map_err(OperationError::SchemaViolation)?;

        Ok(ModifyEvent {
            ident,
            filter,
            filter_orig,
            modlist,
        })
    }

    pub fn from_target_uuid_attr_purge(
        ident: Identity,
        target_uuid: Uuid,
        attr: Attribute,
        filter: Filter<FilterInvalid>,
        qs: &QueryServerWriteTransaction,
    ) -> Result<Self, OperationError> {
        let ml = ModifyList::new_purge(attr);
        let f_uuid = filter_all!(f_eq(Attribute::Uuid, PartialValue::Uuid(target_uuid)));
        // Add any supplemental conditions we have.
        let f = Filter::join_parts_and(f_uuid, filter);

        let filter_orig = f
            .validate(qs.get_schema())
            .map_err(OperationError::SchemaViolation)?;
        let filter = filter_orig.clone().into_ignore_hidden();
        let modlist = ml
            .validate(qs.get_schema())
            .map_err(OperationError::SchemaViolation)?;
        Ok(ModifyEvent {
            ident,
            filter,
            filter_orig,
            modlist,
        })
    }

    pub fn new_internal(filter: Filter<FilterValid>, modlist: ModifyList<ModifyValid>) -> Self {
        ModifyEvent {
            ident: Identity::from_internal(),
            filter: filter.clone(),
            filter_orig: filter,
            modlist,
        }
    }

    /// ⚠️  - Bypass the schema state machine and force the filter to be considered valid.
    /// This is a TEST ONLY method and will never be exposed in production.
    #[cfg(test)]
    pub fn new_internal_invalid(
        filter: Filter<FilterInvalid>,
        modlist: ModifyList<ModifyInvalid>,
    ) -> Self {
        ModifyEvent {
            ident: Identity::from_internal(),
            filter: filter.clone().into_valid(),
            filter_orig: filter.into_valid(),
            modlist: modlist.into_valid(),
        }
    }

    /// ⚠️  - Bypass the schema state machine and force the filter to be considered valid.
    /// This is a TEST ONLY method and will never be exposed in production.
    #[cfg(test)]
    pub fn new_impersonate_identity(
        ident: Identity,
        filter: Filter<FilterInvalid>,
        modlist: ModifyList<ModifyInvalid>,
    ) -> Self {
        ModifyEvent {
            ident,
            filter: filter.clone().into_valid(),
            filter_orig: filter.into_valid(),
            modlist: modlist.into_valid(),
        }
    }

    /// ⚠️  - Bypass the schema state machine and force the filter to be considered valid.
    /// This is a TEST ONLY method and will never be exposed in production.
    #[cfg(test)]
    pub fn new_impersonate_entry(
        e: Arc<Entry<EntrySealed, EntryCommitted>>,
        filter: Filter<FilterInvalid>,
        modlist: ModifyList<ModifyInvalid>,
    ) -> Self {
        ModifyEvent {
            ident: Identity::from_impersonate_entry_readwrite(e),
            filter: filter.clone().into_valid(),
            filter_orig: filter.into_valid(),
            modlist: modlist.into_valid(),
        }
    }

    pub fn new_impersonate(
        ident: &Identity,
        filter: Filter<FilterValid>,
        filter_orig: Filter<FilterValid>,
        modlist: ModifyList<ModifyValid>,
    ) -> Self {
        ModifyEvent {
            ident: Identity::from_impersonate(ident),
            filter,
            filter_orig,
            modlist,
        }
    }
}

pub struct WhoamiResult {
    youare: ProtoEntry,
}

impl WhoamiResult {
    pub fn new(
        qs: &mut QueryServerReadTransaction,
        e: &Entry<EntryReduced, EntryCommitted>,
    ) -> Result<Self, OperationError> {
        Ok(WhoamiResult {
            youare: e.to_pe(qs)?,
        })
    }

    pub fn response(self) -> WhoamiResponse {
        WhoamiResponse {
            youare: self.youare,
        }
    }
}

#[derive(Debug)]
pub struct PurgeTombstoneEvent {
    pub ident: Identity,
    pub eventid: Uuid,
}

impl Default for PurgeTombstoneEvent {
    fn default() -> Self {
        Self::new()
    }
}

impl PurgeTombstoneEvent {
    pub fn new() -> Self {
        PurgeTombstoneEvent {
            ident: Identity::from_internal(),
            eventid: Uuid::new_v4(),
        }
    }
}

#[derive(Debug)]
pub struct PurgeRecycledEvent {
    pub ident: Identity,
    pub eventid: Uuid,
}

impl Default for PurgeRecycledEvent {
    fn default() -> Self {
        Self::new()
    }
}

impl PurgeRecycledEvent {
    pub fn new() -> Self {
        PurgeRecycledEvent {
            ident: Identity::from_internal(),
            eventid: Uuid::new_v4(),
        }
    }
}

#[derive(Debug)]
pub struct PurgeDeleteAfterEvent {
    pub ident: Identity,
    pub eventid: Uuid,
}

impl Default for PurgeDeleteAfterEvent {
    fn default() -> Self {
        Self::new()
    }
}

impl PurgeDeleteAfterEvent {
    pub fn new() -> Self {
        PurgeDeleteAfterEvent {
            ident: Identity::from_internal(),
            eventid: Uuid::new_v4(),
        }
    }
}

#[derive(Debug)]
pub struct OnlineBackupEvent {
    pub ident: Identity,
    pub eventid: Uuid,
}

impl Default for OnlineBackupEvent {
    fn default() -> Self {
        Self::new()
    }
}

impl OnlineBackupEvent {
    pub fn new() -> Self {
        OnlineBackupEvent {
            ident: Identity::from_internal(),
            eventid: Uuid::new_v4(),
        }
    }
}

#[derive(Debug)]
pub struct ReviveRecycledEvent {
    pub ident: Identity,
    // This is the filter, as it will be processed.
    pub filter: Filter<FilterValid>,
    // Unlike the others, because of how this works, we don't need the orig filter
    // to be retained, because the filter is the orig filter for this check.
    //
    // It will be duplicated into the modify ident as it exists.
}

impl ReviveRecycledEvent {
    pub fn from_parts(
        ident: Identity,
        filter: &Filter<FilterInvalid>,
        qs: &QueryServerWriteTransaction,
    ) -> Result<Self, OperationError> {
        let filter = filter
            .validate(qs.get_schema())
            .map(|f| f.into_recycled())
            .map_err(OperationError::SchemaViolation)?;
        Ok(ReviveRecycledEvent { ident, filter })
    }

    /// ⚠️  - Bypass the schema state machine and force the filter to be considered valid.
    /// This is a TEST ONLY method and will never be exposed in production.
    #[cfg(test)]
    pub fn new_impersonate_entry(
        e: Arc<Entry<EntrySealed, EntryCommitted>>,
        filter: Filter<FilterInvalid>,
    ) -> Self {
        ReviveRecycledEvent {
            ident: Identity::from_impersonate_entry_readwrite(e),
            filter: filter.into_valid(),
        }
    }

    #[cfg(test)]
    pub(crate) fn new_internal(filter: Filter<FilterValid>) -> Self {
        ReviveRecycledEvent {
            ident: Identity::from_internal(),
            filter,
        }
    }
}
