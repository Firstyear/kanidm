//! The Kanidmd server library. This implements all of the internal components of the server
//! which is used to process authentication, store identities and enforce access controls.

#![deny(warnings)]
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
#![deny(clippy::indexing_slicing)]
#![allow(clippy::unreachable)]

#[cfg(all(test, feature = "dhat-heap"))]
#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

#[macro_use]
extern crate rusqlite;

#[macro_use]
extern crate tracing;

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
// Clippy is wrong, these are used. Hush little clippy.
#[allow(unused_imports)]
pub mod prelude {
    pub(crate) use crate::server::sealed::QueryServerTransactionPrivate;
    pub(crate) use crate::{
        be::Limits,
        constants::uuids::*,
        entry::{
            entry_init_fn, Entry, EntryCommitted, EntryIncrementalCommitted, EntryIncrementalNew,
            EntryInit, EntryInitNew, EntryInvalid, EntryInvalidCommitted, EntryInvalidNew,
            EntryNew, EntryReduced, EntryReducedCommitted, EntryRefresh, EntryRefreshNew,
            EntrySealed, EntrySealedCommitted, EntrySealedNew, EntryTuple, EntryValid,
        },
        valueset::{
            ValueSet, ValueSetBool, ValueSetCid, ValueSetDateTime, ValueSetEmailAddress,
            ValueSetIname, ValueSetInameN, ValueSetIutf8, ValueSetIutf8N, ValueSetRefer,
            ValueSetReferN, ValueSetSha256, ValueSetSshKey, ValueSetSyntax, ValueSetT,
            ValueSetTotpSecret, ValueSetUint32, ValueSetUrl, ValueSetUrlN, ValueSetUtf8,
            ValueSetUuid, ValueSetUuidN,
        },
    };
    pub use crate::{
        constants::*,
        event::{CreateEvent, DeleteEvent, ExistsEvent, ModifyEvent, SearchEvent},
        filter::{
            f_and, f_andnot, f_eq, f_gt, f_id, f_inc, f_invalid, f_lt, f_or, f_pres, f_self,
            f_spn_name, f_sub, Filter, FilterInvalid, FilterValid, FC,
        },
        idm::{
            authentication::{ClientAuthInfo, ClientCertInfo},
            server::{IdmServer, IdmServerAudit, IdmServerDelayed},
        },
        modify::{
            m_assert, m_pres, m_purge, m_remove, Modify, ModifyInvalid, ModifyList, ModifyValid,
        },
        repl::cid::Cid,
        schema::{SchemaAttribute, SchemaClass},
        server::{
            access::AccessControlsTransaction,
            batch_modify::BatchModifyEvent,
            identity::{
                AccessScope, IdentType, IdentUser, Identity, IdentityId, InternalRole, Source,
            },
            QueryServer, QueryServerReadTransaction, QueryServerTransaction,
            QueryServerTransactionPublic, QueryServerWriteTransaction,
        },
        time::duration_from_epoch_now,
        value::{ApiTokenScope, IndexType, PartialValue, SessionScope, SyntaxType, Value},
    };
    pub(crate) use kanidm_proto::scim_v1::{
        server::{ScimEntryKanidm, ScimValueKanidm},
        ScimEntryHeader,
    };
    pub use kanidm_proto::{
        attribute::{AttrString, Attribute},
        constants::*,
        internal::{
            ConsistencyError, Filter as ProtoFilter, OperationError, PluginError, SchemaError,
        },
        scim_v1::JsonValue,
    };
    #[cfg(test)]
    pub use kanidmd_lib_macros::*;
    pub use sketching::{
        admin_debug, admin_error, admin_info, admin_warn, filter_error, filter_info, filter_trace,
        filter_warn, perf_trace, request_error, request_info, request_trace, request_warn,
        security_access, security_critical, security_debug, security_error, security_info,
        tagged_event, EventTag,
    };
    pub(crate) use std::sync::LazyLock;
    pub use std::time::Duration;
    pub use time::format_description::well_known::Rfc3339;
    pub use url::Url;
    pub use uuid::{uuid, Uuid};
}
