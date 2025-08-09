//! The Kanidmd server library. This implements all of the internal components of the server
//! which is used to process authentication, store identities and enforce access controls.

// #![deny(warnings)]
#![deny(deprecated)]
#![recursion_limit = "512"]
#![warn(unused_extern_crates)]
// Enable some groups of clippy lints.
#![deny(clippy::suspicious)]
#![deny(clippy::perf)]
// Specific lints to enforce.
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::needless_pass_by_value)]
#![deny(clippy::trivially_copy_pass_by_ref)]
#![deny(clippy::disallowed_types)]
#![deny(clippy::manual_let_else)]
#![allow(clippy::unreachable)]

#[cfg(all(test, not(any(feature = "dhat-heap", target_os = "illumos"))))]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[cfg(all(test, feature = "dhat-heap"))]
#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

#[macro_use]
extern crate rusqlite;

#[macro_use]
extern crate tracing;
#[macro_use]
extern crate lazy_static;

// #[macro_use]
// extern crate sketching;

// This has to be before 'be' so the import order works
#[macro_use]
pub mod macros;

pub mod be;
pub mod constants;
pub mod credential;
pub mod entry;
pub mod event;
pub mod filter;

// If this module is ever made public outside of this crate, firstyear will be extremely sad.
// This is *purely migration data*. Don't even think about using it in test cases for anything
// else.
pub(crate) mod migration_data;

pub mod modify;
pub mod time;
pub(crate) mod utils;
pub mod value;
pub mod valueset;
#[macro_use]
mod plugins;
pub mod idm;
pub mod repl;
pub mod schema;
pub mod server;
pub mod status;
pub mod testkit;

/// A prelude of imports that should be imported by all other Kanidm modules to
/// help make imports cleaner.
pub mod prelude {
    pub use kanidm_proto::attribute::{AttrString, Attribute};
    pub use kanidm_proto::constants::*;
    pub use kanidm_proto::internal::{ConsistencyError, OperationError, PluginError, SchemaError};
    pub use sketching::{
        admin_debug, admin_error, admin_info, admin_warn, filter_error, filter_info, filter_trace,
        filter_warn, perf_trace, request_error, request_info, request_trace, request_warn,
        security_access, security_critical, security_debug, security_error, security_info,
        tagged_event, EventTag,
    };
    pub use std::time::Duration;
    pub use url::Url;
    pub use uuid::{uuid, Uuid};

    pub use crate::constants::*;
    pub use crate::entry::{
        Entry, EntryCommitted, EntryIncrementalCommitted, EntryIncrementalNew, EntryInit,
        EntryInitNew, EntryInvalid, EntryInvalidCommitted, EntryInvalidNew, EntryNew, EntryReduced,
        EntryReducedCommitted, EntryRefresh, EntryRefreshNew, EntrySealed, EntrySealedCommitted,
        EntrySealedNew, EntryTuple, EntryValid,
    };
    pub use crate::event::{CreateEvent, DeleteEvent, ExistsEvent, ModifyEvent, SearchEvent};
    pub use crate::filter::{
        f_and, f_andnot, f_eq, f_id, f_inc, f_invalid, f_lt, f_or, f_pres, f_self, f_spn_name,
        f_sub, Filter, FilterInvalid, FilterValid, FC,
    };
    pub use crate::idm::server::{IdmServer, IdmServerAudit, IdmServerDelayed};
    pub use crate::idm::{ClientAuthInfo, ClientCertInfo};
    pub use crate::modify::{
        m_assert, m_pres, m_purge, m_remove, Modify, ModifyInvalid, ModifyList, ModifyValid,
    };
    pub use crate::repl::cid::Cid;
    pub use crate::server::access::AccessControlsTransaction;
    pub use crate::server::batch_modify::BatchModifyEvent;
    pub use crate::server::identity::{
        AccessScope, IdentType, IdentUser, Identity, IdentityId, Source,
    };
    pub use crate::server::{
        QueryServer, QueryServerReadTransaction, QueryServerTransaction,
        QueryServerWriteTransaction,
    };
    pub use crate::time::duration_from_epoch_now;
    pub use crate::value::{
        ApiTokenScope, IndexType, PartialValue, SessionScope, SyntaxType, Value,
    };

    pub use time::format_description::well_known::Rfc3339;

    #[cfg(test)]
    pub use kanidmd_lib_macros::*;

    pub(crate) use crate::valueset::{
        ValueSet, ValueSetBool, ValueSetCid, ValueSetIutf8, ValueSetRefer, ValueSetSyntax,
        ValueSetT, ValueSetUtf8, ValueSetUuid,
    };

    pub(crate) use kanidm_proto::scim_v1::{
        server::{ScimEntryKanidm, ScimValueKanidm},
        ScimEntryHeader,
    };

    pub(crate) use crate::be::Limits;
}
