//! `server` contains the query server, which is the main high level construction
//! to coordinate queries and operations in the server.

use self::{
    access::{
        profiles::{
            AccessControlCreate, AccessControlDelete, AccessControlModify, AccessControlSearch,
        },
        AccessControls, AccessControlsReadTransaction, AccessControlsTransaction,
        AccessControlsWriteTransaction,
    },
    keys::{
        KeyObject, KeyProvider, KeyProviders, KeyProvidersReadTransaction, KeyProvidersTransaction,
        KeyProvidersWriteTransaction,
    },
};
use crate::{
    be::{Backend, BackendReadTransaction, BackendTransaction, BackendWriteTransaction},
    filter::{
        Filter, FilterInvalid, FilterValid, FilterValidResolved, ResolveFilterCache,
        ResolveFilterCacheReadTxn,
    },
    plugins::{
        self,
        dyngroup::{DynGroup, DynGroupCache},
        Plugins,
    },
    prelude::*,
    repl::{cid::Cid, proto::ReplRuvRange, ruv::ReplicationUpdateVectorTransaction},
    schema::{
        Schema, SchemaAttribute, SchemaClass, SchemaReadTransaction, SchemaTransaction,
        SchemaWriteTransaction,
    },
    value::{CredentialType, EXTRACT_VAL_DN},
    valueset::*,
};
use concread::{
    arcache::{ARCacheBuilder, ARCacheReadTxn, ARCacheWriteTxn},
    cowcell::*,
};
use crypto_glue::{hmac_s256::HmacSha256Key, s256::Sha256Output};
use hashbrown::{HashMap, HashSet};
use kanidm_proto::{
    internal::{DomainInfo as ProtoDomainInfo, ImageValue, UiHint},
    scim_v1::{
        server::{ScimListResponse, ScimOAuth2ClaimMap, ScimOAuth2ScopeMap, ScimReference},
        JsonValue, ScimEntryGetQuery, ScimFilter,
    },
};
use std::{
    collections::{BTreeMap, BTreeSet},
    num::NonZeroU64,
    str::FromStr,
    sync::Arc,
};
use time::OffsetDateTime;
use tokio::sync::{Semaphore, SemaphorePermit};
use tracing::trace;

pub(crate) mod access;
pub mod assert;
pub mod batch_modify;
pub mod create;
pub mod delete;
pub mod identity;
pub(crate) mod keys;
pub(crate) mod migrations;
pub mod modify;
pub(crate) mod recycle;
pub mod scim;
pub(crate) mod utils;

const RESOLVE_FILTER_CACHE_MAX: usize = 256;
const RESOLVE_FILTER_CACHE_LOCAL: usize = 8;

#[derive(Debug, Clone, Copy, PartialOrd, PartialEq, Eq)]
pub(crate) enum ServerPhase {
    Bootstrap,
    SchemaReady,
    DomainInfoReady,
    Running,
}

/// Domain Information. This should not contain sensitive information, the data within
/// this structure may be used for public presentation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainInfo {
    pub(crate) d_uuid: Uuid,
    pub(crate) d_name: String,
    pub(crate) d_display: String,
    pub(crate) d_vers: DomainVersion,
    pub(crate) d_patch_level: u32,
    pub(crate) d_devel_taint: bool,
    pub(crate) d_ldap_allow_unix_pw_bind: bool,
    pub(crate) d_allow_easter_eggs: bool,
    pub(crate) d_allow_account_recovery: bool,
    // In future this should be image reference instead of the image itself.
    d_image: Option<ImageValue>,

    // Needs to be part of the domain structure so we can expose this to the UI.
    feature_config: FeatureConfig,
}

impl DomainInfo {
    pub fn name(&self) -> &str {
        self.d_name.as_str()
    }

    pub fn display_name(&self) -> &str {
        self.d_display.as_str()
    }

    pub fn devel_taint(&self) -> bool {
        self.d_devel_taint
    }

    pub fn image(&self) -> Option<&ImageValue> {
        self.d_image.as_ref()
    }

    pub fn has_custom_image(&self) -> bool {
        self.d_image.is_some()
    }

    pub fn allow_easter_eggs(&self) -> bool {
        self.d_allow_easter_eggs
    }

    pub fn allow_account_recovery(&self) -> bool {
        self.d_allow_account_recovery
    }

    pub fn allow_account_signup(&self) -> bool {
        self.feature_config.account_signup.enabled
    }

    #[cfg(feature = "test")]
    pub fn new_test() -> CowCell<Self> {
        concread::cowcell::CowCell::new(Self {
            d_uuid: Uuid::new_v4(),
            d_name: "test domain".to_string(),
            d_display: "Test Domain".to_string(),
            d_vers: 1,
            d_patch_level: 0,
            d_devel_taint: false,
            d_ldap_allow_unix_pw_bind: false,
            d_allow_easter_eggs: false,
            d_allow_account_recovery: false,
            d_image: None,
            feature_config: FeatureConfig::default(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SystemConfig {
    pub(crate) denied_names: HashSet<String>,
    pub(crate) pw_badlist: HashSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HmacNameHistoryConfig {
    pub(crate) enabled: bool,
    pub(crate) key: HmacSha256Key,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AccountSignupConfig {
    pub(crate) enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FeatureConfig {
    pub(crate) hmac_name_history: HmacNameHistoryConfig,
    pub(crate) account_signup: AccountSignupConfig,
}

#[derive(Clone)]
pub struct QueryServer {
    phase: Arc<CowCell<ServerPhase>>,
    pub(crate) d_info: Arc<CowCell<DomainInfo>>,
    system_config: Arc<CowCell<SystemConfig>>,
    be: Backend,
    schema: Arc<Schema>,
    accesscontrols: Arc<AccessControls>,
    db_tickets: Arc<Semaphore>,
    read_tickets: Arc<Semaphore>,
    write_ticket: Arc<Semaphore>,
    resolve_filter_cache: Arc<ResolveFilterCache>,
    dyngroup_cache: Arc<CowCell<DynGroupCache>>,
    cid_max: Arc<CowCell<Cid>>,
    key_providers: Arc<KeyProviders>,
}

pub struct QueryServerReadTransaction<'a> {
    be_txn: BackendReadTransaction<'a>,
    // Anything else? In the future, we'll need to have a schema transaction
    // type, maybe others?
    pub(crate) d_info: CowCellReadTxn<DomainInfo>,
    system_config: CowCellReadTxn<SystemConfig>,
    schema: SchemaReadTransaction,
    accesscontrols: AccessControlsReadTransaction<'a>,
    key_providers: KeyProvidersReadTransaction,
    _db_ticket: SemaphorePermit<'a>,
    _read_ticket: SemaphorePermit<'a>,
    resolve_filter_cache: ResolveFilterCacheReadTxn<'a>,
    // Future we may need this.
    // cid_max: CowCellReadTxn<Cid>,
    trim_cid: Cid,
    txn_name_to_uuid: BTreeMap<String, Uuid>,
}

unsafe impl Sync for QueryServerReadTransaction<'_> {}

unsafe impl Send for QueryServerReadTransaction<'_> {}

bitflags::bitflags! {
    #[derive(Copy, Clone, Debug)]
    pub struct ChangeFlag: u64 {
        const SCHEMA =                      0b0000_0000_0000_0001;
        const ACP =                         0b0000_0000_0000_0010;
        const OAUTH2 =                      0b0000_0000_0000_0100;
        const DOMAIN =                      0b0000_0000_0000_1000;
        const SYSTEM_CONFIG =               0b0000_0000_0001_0000;
        const SYNC_AGREEMENT =              0b0000_0000_0010_0000;
        const KEY_MATERIAL   =              0b0000_0000_0100_0000;
        const APPLICATION    =              0b0000_0000_1000_0000;
        const OAUTH2_CLIENT            =    0b0000_0001_0000_0000;
        const FEATURE                  =    0b0000_0010_0000_0000;
    }
}

pub struct QueryServerWriteTransaction<'a> {
    committed: bool,
    phase: CowCellWriteTxn<'a, ServerPhase>,
    d_info: CowCellWriteTxn<'a, DomainInfo>,
    system_config: CowCellWriteTxn<'a, SystemConfig>,
    curtime: Duration,
    cid: CowCellWriteTxn<'a, Cid>,
    trim_cid: Cid,
    pub(crate) be_txn: BackendWriteTransaction<'a>,
    pub(crate) schema: SchemaWriteTransaction<'a>,
    accesscontrols: AccessControlsWriteTransaction<'a>,
    key_providers: KeyProvidersWriteTransaction<'a>,
    // We store a set of flags that indicate we need a reload of
    // schema or acp, which is tested by checking the classes of the
    // changing content.
    pub(super) changed_flags: ChangeFlag,

    // Store the list of changed uuids for other invalidation needs?
    pub(super) changed_uuid: HashSet<Uuid>,
    _db_ticket: SemaphorePermit<'a>,
    _write_ticket: SemaphorePermit<'a>,
    resolve_filter_cache_clear: bool,
    resolve_filter_cache_write: ARCacheWriteTxn<
        'a,
        (IdentityId, Arc<Filter<FilterValid>>),
        Arc<Filter<FilterValidResolved>>,
        (),
    >,
    resolve_filter_cache: ARCacheReadTxn<
        'a,
        (IdentityId, Arc<Filter<FilterValid>>),
        Arc<Filter<FilterValidResolved>>,
        (),
    >,
    dyngroup_cache: CowCellWriteTxn<'a, DynGroupCache>,
    txn_name_to_uuid: BTreeMap<String, Uuid>,
}

impl QueryServerWriteTransaction<'_> {
    pub(crate) fn trim_cid(&self) -> &Cid {
        &self.trim_cid
    }
}

/// The `QueryServerTransaction` trait provides a set of common read only operations to be
/// shared between [`QueryServerReadTransaction`] and [`QueryServerWriteTransaction`]s.
///
/// These operations tend to be high level constructions, generally different types of searches
/// that are capable of taking different types of parameters and applying access controls or not,
/// impersonating accounts, or bypassing these via internal searches.
///
/// [`QueryServerReadTransaction`]: struct.QueryServerReadTransaction.html
/// [`QueryServerWriteTransaction`]: struct.QueryServerWriteTransaction.html
pub trait QueryServerTransactionPublic<'a> {
    type BackendTransactionType: BackendTransaction;
    fn get_be_txn(&mut self) -> &mut Self::BackendTransactionType;

    type SchemaTransactionType: SchemaTransaction;
    fn get_schema<'b>(&self) -> &'b Self::SchemaTransactionType;

    type AccessControlsTransactionType: AccessControlsTransaction<'a>;
    fn get_accesscontrols(&self) -> &Self::AccessControlsTransactionType;

    type KeyProvidersTransactionType: KeyProvidersTransaction;
    fn get_key_providers(&self) -> &Self::KeyProvidersTransactionType;

    fn pw_badlist(&self) -> &HashSet<String>;

    fn denied_names(&self) -> &HashSet<String>;

    fn domain_info(&self) -> &DomainInfo;

    fn get_domain_version(&self) -> DomainVersion;

    fn get_domain_patch_level(&self) -> u32;

    fn get_domain_development_taint(&self) -> bool;

    fn get_domain_uuid(&self) -> Uuid;

    fn get_domain_name(&self) -> &str;

    fn get_domain_display_name(&self) -> &str;

    fn get_domain_image_value(&self) -> Option<ImageValue>;

    fn get_resolve_filter_cache(&mut self) -> Option<&mut ResolveFilterCacheReadTxn<'a>>;

    fn get_feature_hmac_name_history_config(&self) -> &HmacNameHistoryConfig;

    fn get_feature_account_signup_config(&self) -> &AccountSignupConfig;

    fn txn_name_to_uuid(&mut self) -> &mut BTreeMap<String, Uuid>;

    // Because of how borrowck in rust works, if we need to get two inner types we have to get them
    // in a single fn.

    fn get_resolve_filter_cache_and_be_txn(
        &mut self,
    ) -> (
        &mut Self::BackendTransactionType,
        Option<&mut ResolveFilterCacheReadTxn<'a>>,
    );

    /// Conduct a search and apply access controls to yield a set of entries that
    /// have been reduced to the set of user visible avas. Note that if you provide
    /// a `SearchEvent` for the internal user, this query will fail. It is invalid for
    /// the [`access`] module to attempt to reduce avas for internal searches, and you
    /// should use [`fn search`] instead.
    ///
    /// [`SearchEvent`]: ../event/struct.SearchEvent.html
    /// [`access`]: ../access/index.html
    /// [`fn search`]: trait.QueryServerTransaction.html#method.search
    #[instrument(level = "debug", skip_all)]
    fn search_ext(
        &mut self,
        se: &SearchEvent,
    ) -> Result<Vec<EntryReducedCommitted>, OperationError> {
        /*
         * This just wraps search, but it's for the external interface
         * so as a result it also reduces the entry set's attributes at
         * the end.
         */
        let entries = self.search(se)?;

        let access = self.get_accesscontrols();
        access
            .search_filter_entry_attributes(se, entries)
            .map_err(|e| {
                // Log and fail if something went wrong.
                admin_error!(?e, "Failed to filter entry attributes");
                e
            })
        // This now returns the reduced vec.
    }

    #[instrument(level = "debug", skip_all)]
    fn search(
        &mut self,
        se: &SearchEvent,
    ) -> Result<Vec<Arc<EntrySealedCommitted>>, OperationError> {
        if se.ident.is_internal() {
            trace!(internal_filter = ?se.filter, "search");
        } else {
            security_info!(initiator = %se.ident, "search");
            admin_debug!(external_filter = ?se.filter, "search");
        }

        // This is an important security step because it prevents us from
        // performing un-indexed searches on attr's that don't exist in the
        // server. This is why ExtensibleObject can only take schema that
        // exists in the server, not arbitrary attr names.
        //
        // This normalises and validates in a single step.
        //
        // NOTE: Filters are validated in event conversion.

        let (be_txn, resolve_filter_cache) = self.get_resolve_filter_cache_and_be_txn();

        let idxmeta = be_txn.get_idxmeta_ref();

        trace!(resolve_filter_cache = %resolve_filter_cache.is_some());

        // Now resolve all references and indexes.
        let vfr = se
            .filter
            .resolve(&se.ident, Some(idxmeta), resolve_filter_cache)
            .map_err(|e| {
                admin_error!(?e, "search filter resolve failure");
                e
            })?;

        let lims = se.ident.limits();

        // NOTE: We currently can't build search plugins due to the inability to hand
        // the QS wr/ro to the plugin trait. However, there shouldn't be a need for search
        // plugins, because all data transforms should be in the write path.

        let res = self.get_be_txn().search(lims, &vfr).map_err(|e| {
            admin_error!(?e, "backend failure");
            OperationError::Backend
        })?;

        // Apply ACP before we let the plugins "have at it".
        // WARNING; for external searches this is NOT the only
        // ACP application. There is a second application to reduce the
        // attribute set on the entries!
        //
        let access = self.get_accesscontrols();
        access.search_filter_entries(se, res).map_err(|e| {
            admin_error!(?e, "Unable to access filter entries");
            e
        })
    }

    #[instrument(level = "debug", skip_all)]
    fn exists(&mut self, ee: &ExistsEvent) -> Result<bool, OperationError> {
        let (be_txn, resolve_filter_cache) = self.get_resolve_filter_cache_and_be_txn();
        let idxmeta = be_txn.get_idxmeta_ref();

        let vfr = ee
            .filter
            .resolve(&ee.ident, Some(idxmeta), resolve_filter_cache)
            .map_err(|e| {
                admin_error!(?e, "Failed to resolve filter");
                e
            })?;

        let lims = ee.ident.limits();

        if ee.ident.is_internal() {
            // We take a fast-path on internal because we can skip loading entries
            // at all in this case.
            be_txn.exists(lims, &vfr).map_err(|e| {
                admin_error!(?e, "backend failure");
                OperationError::Backend
            })
        } else {
            // For external idents, we need to load the entries else we can't apply
            // access controls to them.
            let res = self.get_be_txn().search(lims, &vfr).map_err(|e| {
                admin_error!(?e, "backend failure");
                OperationError::Backend
            })?;

            // ⚠️  Compare / Exists is annoying security wise. It has the
            // capability to easily leak information based on comparisons
            // that have been made. In the external account case, we need
            // to filter entries as a result.

            // Apply ACP before we return the bool state.
            let access = self.get_accesscontrols();
            access
                .filter_entries(&ee.ident, &ee.filter_orig, res)
                .map_err(|e| {
                    admin_error!(?e, "Unable to access filter entries");
                    e
                })
                .map(|entries| !entries.is_empty())
        }
    }

    fn name_to_uuid(&mut self, name: &str) -> Result<Uuid, OperationError> {
        // There are some contexts where we will be passed an rdn or dn. We need
        // to remove these elements if they exist.
        //
        // Why is it okay to ignore the attr and dn here? In Kani spn and name are
        // always unique and absolutes, so even if the dn/rdn are not expected, there
        // is only a single correct answer that *can* match these values. This also
        // hugely simplifies the process of matching when we have app based searches
        // in future too.
        let work = EXTRACT_VAL_DN
            .captures(name)
            .and_then(|caps| caps.name("val"))
            .map(|v| v.as_str().to_lowercase())
            .ok_or(OperationError::InvalidValueState)?;

        // Is it just a uuid?
        if let Ok(uuid) = Uuid::parse_str(&work) {
            return Ok(uuid);
        }

        if let Some(uuid) = self.get_be_txn().name2uuid(&work)? {
            return Ok(uuid);
        }

        if let Some(uuid) = self.txn_name_to_uuid().get(name) {
            Ok(*uuid)
        } else {
            Err(OperationError::NoMatchingEntries)
        }
    }

    // Similar to name, but where we lookup from external_id instead.
    fn sync_external_id_to_uuid(
        &mut self,
        external_id: &str,
    ) -> Result<Option<Uuid>, OperationError> {
        // Is it just a uuid?
        Uuid::parse_str(external_id).map(Some).or_else(|_| {
            let lname = external_id.to_lowercase();
            self.get_be_txn().externalid2uuid(lname.as_str())
        })
    }

    fn uuid_to_spn(&mut self, uuid: Uuid) -> Result<Option<Value>, OperationError> {
        let r = self.get_be_txn().uuid2spn(uuid)?;

        if let Some(ref n) = r {
            // Shouldn't we be doing more graceful error handling here?
            // Or, if we know it will always be true, we should remove this.
            debug_assert!(n.is_spn() || n.is_iname());
        }

        Ok(r)
    }

    fn uuid_to_rdn(&mut self, uuid: Uuid) -> Result<String, OperationError> {
        // If we have a some, pass it on, else unwrap into a default.
        self.get_be_txn()
            .uuid2rdn(uuid)
            .map(|v| v.unwrap_or_else(|| format!("uuid={}", uuid.as_hyphenated())))
    }

    #[instrument(level = "debug", skip_all)]
    fn impersonate_search_valid(
        &mut self,
        f_valid: Filter<FilterValid>,
        f_intent_valid: Filter<FilterValid>,
        event: &Identity,
    ) -> Result<Vec<Arc<EntrySealedCommitted>>, OperationError> {
        let se = SearchEvent::new_impersonate(event, f_valid, f_intent_valid);
        self.search(&se)
    }

    /// Applies ACP to filter result entries.
    fn impersonate_search_ext_valid(
        &mut self,
        f_valid: Filter<FilterValid>,
        f_intent_valid: Filter<FilterValid>,
        event: &Identity,
    ) -> Result<Vec<Entry<EntryReduced, EntryCommitted>>, OperationError> {
        let se = SearchEvent::new_impersonate(event, f_valid, f_intent_valid);
        self.search_ext(&se)
    }

    fn ident_search(
        &mut self,
        ident: &Identity,
        filter: Filter<FilterInvalid>,
    ) -> Result<Vec<Arc<EntrySealedCommitted>>, OperationError> {
        let f_intent_valid = filter
            .validate(self.get_schema())
            .map_err(OperationError::SchemaViolation)?;

        let f_valid = f_intent_valid.clone().into_ignore_hidden();

        let se = SearchEvent::new_impersonate(ident, f_valid, f_intent_valid);
        self.search(&se)
    }

    fn ident_search_single(
        &mut self,
        ident: &Identity,
        filter: Filter<FilterInvalid>,
    ) -> Result<Arc<EntrySealedCommitted>, OperationError> {
        let mut vs = self.ident_search(ident, filter)?;
        match vs.pop() {
            Some(entry) if vs.is_empty() => Ok(entry),
            _ => Err(OperationError::NoMatchingEntries),
        }
    }

    // Who they are will go here
    fn impersonate_search(
        &mut self,
        filter: Filter<FilterInvalid>,
        filter_intent: Filter<FilterInvalid>,
        event: &Identity,
    ) -> Result<Vec<Arc<EntrySealedCommitted>>, OperationError> {
        let f_valid = filter
            .validate(self.get_schema())
            .map_err(OperationError::SchemaViolation)?;
        let f_intent_valid = filter_intent
            .validate(self.get_schema())
            .map_err(OperationError::SchemaViolation)?;
        self.impersonate_search_valid(f_valid, f_intent_valid, event)
    }

    #[instrument(level = "debug", skip_all)]
    fn impersonate_search_ext(
        &mut self,
        filter: Filter<FilterInvalid>,
        filter_intent: Filter<FilterInvalid>,
        event: &Identity,
    ) -> Result<Vec<Entry<EntryReduced, EntryCommitted>>, OperationError> {
        let f_valid = filter
            .validate(self.get_schema())
            .map_err(OperationError::SchemaViolation)?;
        let f_intent_valid = filter_intent
            .validate(self.get_schema())
            .map_err(OperationError::SchemaViolation)?;
        self.impersonate_search_ext_valid(f_valid, f_intent_valid, event)
    }

    #[instrument(level = "debug", skip_all)]
    fn impersonate_search_ext_uuid(
        &mut self,
        uuid: Uuid,
        event: &Identity,
    ) -> Result<Entry<EntryReduced, EntryCommitted>, OperationError> {
        let filter_intent = filter_all!(f_eq(Attribute::Uuid, PartialValue::Uuid(uuid)));
        let filter = filter!(f_eq(Attribute::Uuid, PartialValue::Uuid(uuid)));

        let mut vs = self.impersonate_search_ext(filter, filter_intent, event)?;
        match vs.pop() {
            Some(entry) if vs.is_empty() => Ok(entry),
            _ => {
                if vs.is_empty() {
                    Err(OperationError::NoMatchingEntries)
                } else {
                    // Multiple entries matched, should not be possible!
                    Err(OperationError::UniqueConstraintViolation)
                }
            }
        }
    }

    #[instrument(level = "debug", skip_all)]
    fn consumer_get_state(&mut self) -> Result<ReplRuvRange, OperationError> {
        // Get the current state of "where we are up to"
        //
        // There are two approaches we can use here. We can either store a cookie
        // related to the supplier we are fetching from, or we can use our RUV state.
        //
        // Initially I'm using RUV state, because it lets us select exactly what has
        // changed, where the cookie approach is more coarse grained. The cookie also
        // requires some more knowledge about what supplier we are communicating too
        // where the RUV approach doesn't since the supplier calcs the diff.
        //
        // We need the RUV as a state of
        //
        // [ s_uuid, cid_min, cid_max ]
        // [ s_uuid, cid_min, cid_max ]
        // [ s_uuid, cid_min, cid_max ]
        // ...
        //
        // This way the remote can diff against it's knowledge and work out:
        //
        // [ s_uuid, from_cid, to_cid ]
        // [ s_uuid, from_cid, to_cid ]
        //
        // ...

        let domain_uuid = self.get_domain_uuid();

        // Which then the supplier will use to actually retrieve the set of entries.
        // and the needed attributes we need.
        let ruv_snapshot = self.get_be_txn().get_ruv();

        // What's the current set of ranges?
        ruv_snapshot
            .current_ruv_range()
            .map(|ranges| ReplRuvRange::V1 {
                domain_uuid,
                ranges,
            })
    }
}

pub trait QueryServerTransaction<'a>:
    sealed::QueryServerTransactionPrivate<'a> + QueryServerTransactionPublic<'a>
{
}

pub(crate) mod sealed {
    use super::*;

    pub trait QueryServerTransactionPrivate<'a>: QueryServerTransactionPublic<'a> {
        /// From internal, generate an "exists" event and dispatch
        #[instrument(level = "debug", skip_all)]
        fn internal_exists(
            &mut self,
            filter: &Filter<FilterInvalid>,
        ) -> Result<bool, OperationError> {
            // Check the filter
            let f_valid = filter
                .validate(self.get_schema())
                .map_err(OperationError::SchemaViolation)?;
            // Build an exists event
            let ee = ExistsEvent::new_internal(f_valid);
            // Submit it
            self.exists(&ee)
        }

        #[instrument(level = "debug", skip_all)]
        fn internal_exists_uuid(&mut self, uuid: Uuid) -> Result<bool, OperationError> {
            let filter = filter!(f_eq(Attribute::Uuid, PartialValue::Uuid(uuid)));
            self.internal_exists(&filter)
        }

        #[instrument(level = "debug", skip_all)]
        fn internal_search(
            &mut self,
            filter: Filter<FilterInvalid>,
        ) -> Result<Vec<Arc<EntrySealedCommitted>>, OperationError> {
            let f_valid = filter
                .validate(self.get_schema())
                .map_err(OperationError::SchemaViolation)?;
            let se = SearchEvent::new_internal(f_valid);
            self.search(&se)
        }

        #[instrument(level = "debug", skip_all)]
        fn impersonate_search_uuid(
            &mut self,
            uuid: Uuid,
            event: &Identity,
        ) -> Result<Arc<EntrySealedCommitted>, OperationError> {
            let filter_intent = filter_all!(f_eq(Attribute::Uuid, PartialValue::Uuid(uuid)));
            let filter = filter!(f_eq(Attribute::Uuid, PartialValue::Uuid(uuid)));

            let mut vs = self.impersonate_search(filter, filter_intent, event)?;
            match vs.pop() {
                Some(entry) if vs.is_empty() => Ok(entry),
                _ => Err(OperationError::NoMatchingEntries),
            }
        }

        /// Get a single entry by its UUID. This is used heavily for internal
        /// server operations, especially in login and ACP checks.
        #[instrument(level = "debug", skip_all)]
        fn internal_search_uuid(
            &mut self,
            uuid: Uuid,
        ) -> Result<Arc<EntrySealedCommitted>, OperationError> {
            let filter = filter!(f_eq(Attribute::Uuid, PartialValue::Uuid(uuid)));
            let f_valid = filter.validate(self.get_schema()).map_err(|e| {
                error!(?e, "Filter Validate - SchemaViolation");
                OperationError::SchemaViolation(e)
            })?;
            let se = SearchEvent::new_internal(f_valid);

            let mut vs = self.search(&se)?;
            match vs.pop() {
                Some(entry) if vs.is_empty() => Ok(entry),
                _ => Err(OperationError::NoMatchingEntries),
            }
        }

        /// Get a single entry by its UUID, even if the entry in question
        /// is in a masked state (recycled, tombstoned).
        #[instrument(level = "debug", skip_all)]
        fn internal_search_all_uuid(
            &mut self,
            uuid: Uuid,
        ) -> Result<Arc<EntrySealedCommitted>, OperationError> {
            let filter = filter_all!(f_eq(Attribute::Uuid, PartialValue::Uuid(uuid)));
            let f_valid = filter.validate(self.get_schema()).map_err(|e| {
                error!(?e, "Filter Validate - SchemaViolation");
                OperationError::SchemaViolation(e)
            })?;
            let se = SearchEvent::new_internal(f_valid);

            let mut vs = self.search(&se)?;
            match vs.pop() {
                Some(entry) if vs.is_empty() => Ok(entry),
                _ => Err(OperationError::NoMatchingEntries),
            }
        }

        /// Get all conflict entries that originated from a source uuid.
        #[instrument(level = "debug", skip_all)]
        fn internal_search_conflict_uuid(
            &mut self,
            uuid: Uuid,
        ) -> Result<Vec<Arc<EntrySealedCommitted>>, OperationError> {
            let filter = filter_all!(f_and(vec![
                f_eq(Attribute::SourceUuid, PartialValue::Uuid(uuid)),
                f_eq(Attribute::Class, EntryClass::Conflict.into())
            ]));
            let f_valid = filter.validate(self.get_schema()).map_err(|e| {
                error!(?e, "Filter Validate - SchemaViolation");
                OperationError::SchemaViolation(e)
            })?;
            let se = SearchEvent::new_internal(f_valid);

            self.search(&se)
        }

        /// Given an entries UUID, return an impersonation session for that account. This
        /// should be used with care, as it allows you to perform actions internally on
        /// behalf of a another user, without checking the permissions of the original
        /// user.
        fn impersonate_uuid_as_readwrite_identity(
            &mut self,
            uuid: Uuid,
        ) -> Result<Identity, OperationError> {
            self.internal_search_uuid(uuid)
                .map(Identity::from_impersonate_entry_readwrite)
        }

        /// Do a schema aware conversion from a String:String to String:Value for modification
        /// present.
        fn clone_value(&mut self, attr: &Attribute, value: &str) -> Result<Value, OperationError> {
            let schema = self.get_schema();

            // Should this actually be a fn of Value - no - I think that introduces issues with the
            // monomorphisation of the trait for transactions, so we should have this here.

            // Lookup the attr
            match schema.get_attributes().get(attr) {
                Some(schema_a) => {
                    match schema_a.syntax {
                    SyntaxType::Utf8String => Ok(Value::new_utf8(value.to_string())),
                    SyntaxType::Utf8StringInsensitiveN => Ok(Value::new_iutf8n(value)),
                    SyntaxType::Utf8StringInsensitive => Ok(Value::new_iutf8(value)),
                    SyntaxType::Utf8StringInameN => Ok(Value::new_inamen(value)),
                    SyntaxType::Utf8StringIname => Ok(Value::new_iname(value)),
                    SyntaxType::Boolean => Value::new_bools(value)
                        .ok_or_else(|| OperationError::InvalidAttribute("Invalid boolean syntax".to_string())),
                    SyntaxType::SyntaxId => Value::new_syntaxs(value)
                        .ok_or_else(|| OperationError::InvalidAttribute("Invalid Syntax syntax".to_string())),
                    SyntaxType::IndexId => Value::new_indexes(value)
                        .ok_or_else(|| OperationError::InvalidAttribute("Invalid Index syntax".to_string())),
                    SyntaxType::CredentialType => CredentialType::try_from(value)
                        .map(Value::CredentialType)
                        .map_err(|()| OperationError::InvalidAttribute("Invalid CredentialType syntax".to_string())),
                    SyntaxType::Uuid => {
                        // Attempt to resolve this name to a uuid. If it's already a uuid, then
                        // name to uuid will "do the right thing" and give us the Uuid back.
                        let un = self
                            .name_to_uuid(value)
                            .unwrap_or(UUID_DOES_NOT_EXIST);
                        Ok(Value::Uuid(un))
                    }
                    SyntaxType::ReferenceUuidN
                    => {
                        let un = self
                            .name_to_uuid(value)
                            .unwrap_or(UUID_DOES_NOT_EXIST);
                        Ok(Value::ReferN(un))
                    }
                    SyntaxType::ReferenceUuid
                    => {
                        let un = self
                            .name_to_uuid(value)
                            .unwrap_or(UUID_DOES_NOT_EXIST);
                        Ok(Value::Refer(un))
                    }
                    SyntaxType::JsonFilter => Value::new_json_filter_s(value)
                        .ok_or_else(|| OperationError::InvalidAttribute("Invalid Filter syntax".to_string())),
                    SyntaxType::Image => Value::new_image(value),

                    SyntaxType::Credential => Err(OperationError::InvalidAttribute("Credentials can not be supplied through modification - please use the IDM api".to_string())),
                    SyntaxType::SecretUtf8String => Err(OperationError::InvalidAttribute("Radius secrets can not be supplied through modification - please use the IDM api".to_string())),
                    SyntaxType::SshKey => Err(OperationError::InvalidAttribute("SSH public keys can not be supplied through modification - please use the IDM api".to_string())),
                    SyntaxType::SecurityPrincipalName => Err(OperationError::InvalidAttribute("SPNs are generated and not able to be set.".to_string())),
                    SyntaxType::Uint32 => Value::new_uint32_str(value)
                        .ok_or_else(|| OperationError::InvalidAttribute("Invalid uint32 syntax".to_string())),
                    SyntaxType::Int64 => Value::new_int64_str(value)
                        .ok_or_else(|| OperationError::InvalidAttribute("Invalid int64 syntax".to_string())),
                    SyntaxType::Uint64 => Value::new_uint64_str(value)
                        .ok_or_else(|| OperationError::InvalidAttribute("Invalid uint64 syntax".to_string())),
                    SyntaxType::Cid => Err(OperationError::InvalidAttribute("CIDs are generated and not able to be set.".to_string())),
                    SyntaxType::NsUniqueId => Value::new_nsuniqueid_s(value)
                        .ok_or_else(|| OperationError::InvalidAttribute("Invalid NsUniqueId syntax".to_string())),
                    SyntaxType::DateTime => Value::new_datetime_s(value)
                        .ok_or_else(|| OperationError::InvalidAttribute("Invalid DateTime (rfc3339) syntax".to_string())),
                    SyntaxType::EmailAddress => Value::new_email_address_s(value)
                        .ok_or_else(|| OperationError::InvalidAttribute("Invalid Email Address syntax".to_string())),

                    SyntaxType::UrlN => Value::new_urln_s(value)
                        .ok_or_else(|| OperationError::InvalidAttribute("Invalid Url (whatwg/url) syntax".to_string())),
                    SyntaxType::Url => Value::new_url_s(value)
                        .ok_or_else(|| OperationError::InvalidAttribute("Invalid Url (whatwg/url) syntax".to_string())),
                    SyntaxType::OauthScope => Value::new_oauthscope(value)
                        .ok_or_else(|| OperationError::InvalidAttribute("Invalid Oauth Scope syntax".to_string())),
                    SyntaxType::WebauthnAttestationCaList => Value::new_webauthn_attestation_ca_list(value)
                        .ok_or_else(|| OperationError::InvalidAttribute("Invalid Webauthn Attestation CA List".to_string())),
                    SyntaxType::OauthScopeMap => Err(OperationError::InvalidAttribute("Oauth Scope Maps can not be supplied through modification - please use the IDM api".to_string())),
                    SyntaxType::OauthClaimMap => Err(OperationError::InvalidAttribute("Oauth Claim Maps can not be supplied through modification - please use the IDM api".to_string())),
                    SyntaxType::PrivateBinary => Err(OperationError::InvalidAttribute("Private Binary Values can not be supplied through modification".to_string())),
                    SyntaxType::IntentToken => Err(OperationError::InvalidAttribute("Intent Token Values can not be supplied through modification".to_string())),
                    SyntaxType::Passkey => Err(OperationError::InvalidAttribute("Passkey Values can not be supplied through modification".to_string())),
                    SyntaxType::AttestedPasskey => Err(OperationError::InvalidAttribute("AttestedPasskey Values can not be supplied through modification".to_string())),
                    SyntaxType::Session => Err(OperationError::InvalidAttribute("Session Values can not be supplied through modification".to_string())),
                    SyntaxType::ApiToken => Err(OperationError::InvalidAttribute("ApiToken Values can not be supplied through modification".to_string())),
                    SyntaxType::JwsKeyEs256 => Err(OperationError::InvalidAttribute("JwsKeyEs256 Values can not be supplied through modification".to_string())),
                    SyntaxType::JwsKeyRs256 => Err(OperationError::InvalidAttribute("JwsKeyRs256 Values can not be supplied through modification".to_string())),
                    SyntaxType::Oauth2Session => Err(OperationError::InvalidAttribute("Oauth2Session Values can not be supplied through modification".to_string())),
                    SyntaxType::UiHint => UiHint::from_str(value)
                        .map(Value::UiHint)
                        .map_err(|()| OperationError::InvalidAttribute("Invalid uihint syntax".to_string())),
                    SyntaxType::TotpSecret => Err(OperationError::InvalidAttribute("TotpSecret Values can not be supplied through modification".to_string())),
                    SyntaxType::AuditLogString => Err(OperationError::InvalidAttribute("Audit logs are generated and not able to be set.".to_string())),
                    SyntaxType::EcKeyPrivate => Err(OperationError::InvalidAttribute("Ec keys are generated and not able to be set.".to_string())),
                    SyntaxType::KeyInternal => Err(OperationError::InvalidAttribute("Internal keys are generated and not able to be set.".to_string())),
                    SyntaxType::HexString => Value::new_hex_string_s(value)
                        .ok_or_else(|| OperationError::InvalidAttribute("Invalid hex string syntax".to_string())),
                    SyntaxType::Certificate => Value::new_certificate_s(value)
                        .ok_or_else(|| OperationError::InvalidAttribute("Invalid x509 certificate syntax".to_string())),
                    SyntaxType::ApplicationPassword => Err(OperationError::InvalidAttribute("ApplicationPassword values can not be supplied through modification".to_string())),
                    SyntaxType::Json => Err(OperationError::InvalidAttribute("Json values can not be supplied through modification".to_string())),
                    SyntaxType::Sha256 => Err(OperationError::InvalidAttribute("SHA256 values can not be supplied through modification".to_string())),
                    SyntaxType::Message => Err(OperationError::InvalidAttribute("Message values can not be supplied through modification".to_string())),
                    SyntaxType::UuidN => Err(OperationError::InvalidAttribute("Uuid-Set values can not be supplied through modification".to_string())),
                }
                }
                None => {
                    // No attribute of this name exists - fail fast, there is no point to
                    // proceed, as nothing can be satisfied.
                    Err(OperationError::InvalidAttributeName(attr.to_string()))
                }
            }
        }

        fn clone_partialvalue(
            &mut self,
            attr: &Attribute,
            value: &str,
        ) -> Result<PartialValue, OperationError> {
            let schema = self.get_schema();

            // Lookup the attr
            match schema.get_attributes().get(attr) {
                Some(schema_a) => {
                    match schema_a.syntax {
                        SyntaxType::Utf8String | SyntaxType::TotpSecret => {
                            Ok(PartialValue::new_utf8(value.to_string()))
                        }
                        SyntaxType::Utf8StringInsensitive
                        | SyntaxType::Utf8StringInsensitiveN
                        | SyntaxType::JwsKeyEs256
                        | SyntaxType::JwsKeyRs256 => Ok(PartialValue::new_iutf8(value)),
                        SyntaxType::Utf8StringInameN | SyntaxType::Utf8StringIname => {
                            Ok(PartialValue::new_iname(value))
                        }
                        SyntaxType::Boolean => PartialValue::new_bools(value).ok_or_else(|| {
                            OperationError::InvalidAttribute("Invalid boolean syntax".to_string())
                        }),
                        SyntaxType::SyntaxId => PartialValue::new_syntaxs(value).ok_or_else(|| {
                            OperationError::InvalidAttribute("Invalid Syntax syntax".to_string())
                        }),
                        SyntaxType::IndexId => PartialValue::new_indexes(value).ok_or_else(|| {
                            OperationError::InvalidAttribute("Invalid Index syntax".to_string())
                        }),
                        SyntaxType::CredentialType => CredentialType::try_from(value)
                            .map(PartialValue::CredentialType)
                            .map_err(|()| {
                                OperationError::InvalidAttribute(
                                    "Invalid credentialtype syntax".to_string(),
                                )
                            }),
                        SyntaxType::Uuid | SyntaxType::UuidN => {
                            let un = self.name_to_uuid(value).unwrap_or(UUID_DOES_NOT_EXIST);
                            Ok(PartialValue::Uuid(un))
                        }
                        // ⚠️   Any types here need to also be added to update_attributes in
                        // schema.rs for reference type / cache awareness during referential
                        // integrity processing. Exceptions are self-contained value types!
                        SyntaxType::ReferenceUuid
                        | SyntaxType::ReferenceUuidN
                        | SyntaxType::OauthScopeMap
                        | SyntaxType::Session
                        | SyntaxType::ApiToken
                        | SyntaxType::Oauth2Session
                        | SyntaxType::ApplicationPassword => {
                            let un = self.name_to_uuid(value).unwrap_or(UUID_DOES_NOT_EXIST);
                            Ok(PartialValue::Refer(un))
                        }
                        SyntaxType::OauthClaimMap => self
                            .name_to_uuid(value)
                            .map(PartialValue::Refer)
                            .or_else(|_| Ok(PartialValue::new_iutf8(value))),

                        SyntaxType::JsonFilter => PartialValue::new_json_filter_s(value)
                            .ok_or_else(|| {
                                OperationError::InvalidAttribute(
                                    "Invalid Filter syntax".to_string(),
                                )
                            }),
                        SyntaxType::Credential => Ok(PartialValue::new_credential_tag(value)),
                        SyntaxType::SecretUtf8String => Ok(PartialValue::new_secret_str()),
                        SyntaxType::SshKey => Ok(PartialValue::new_sshkey_tag_s(value)),
                        SyntaxType::SecurityPrincipalName => PartialValue::new_spn_s(value)
                            .ok_or_else(|| {
                                OperationError::InvalidAttribute("Invalid spn syntax".to_string())
                            }),
                        SyntaxType::Uint32 => {
                            PartialValue::new_uint32_str(value).ok_or_else(|| {
                                OperationError::InvalidAttribute(
                                    "Invalid uint32 syntax".to_string(),
                                )
                            })
                        }
                        SyntaxType::Uint64 => {
                            PartialValue::new_uint64_str(value).ok_or_else(|| {
                                OperationError::InvalidAttribute(
                                    "Invalid uint64 syntax".to_string(),
                                )
                            })
                        }
                        SyntaxType::Int64 => PartialValue::new_int64_str(value).ok_or_else(|| {
                            OperationError::InvalidAttribute("Invalid int64 syntax".to_string())
                        }),
                        SyntaxType::Cid => PartialValue::new_cid_s(value).ok_or_else(|| {
                            OperationError::InvalidAttribute("Invalid cid syntax".to_string())
                        }),
                        SyntaxType::NsUniqueId => Ok(PartialValue::new_nsuniqueid_s(value)),
                        SyntaxType::DateTime => {
                            PartialValue::new_datetime_s(value).ok_or_else(|| {
                                OperationError::InvalidAttribute(
                                    "Invalid DateTime (rfc3339) syntax".to_string(),
                                )
                            })
                        }
                        SyntaxType::EmailAddress => Ok(PartialValue::new_email_address_s(value)),
                        SyntaxType::UrlN | SyntaxType::Url => PartialValue::new_url_s(value)
                            .ok_or_else(|| {
                                OperationError::InvalidAttribute(
                                    "Invalid Url (whatwg/url) syntax".to_string(),
                                )
                            }),
                        SyntaxType::OauthScope => Ok(PartialValue::new_oauthscope(value)),
                        SyntaxType::PrivateBinary => Ok(PartialValue::PrivateBinary),
                        SyntaxType::IntentToken => {
                            PartialValue::new_intenttoken_s(value.to_string()).ok_or_else(|| {
                                OperationError::InvalidAttribute(
                                    "Invalid Intent Token ID (uuid) syntax".to_string(),
                                )
                            })
                        }
                        SyntaxType::Passkey => {
                            PartialValue::new_passkey_s(value).ok_or_else(|| {
                                OperationError::InvalidAttribute(
                                    "Invalid Passkey UUID syntax".to_string(),
                                )
                            })
                        }
                        SyntaxType::AttestedPasskey => PartialValue::new_attested_passkey_s(value)
                            .ok_or_else(|| {
                                OperationError::InvalidAttribute(
                                    "Invalid AttestedPasskey UUID syntax".to_string(),
                                )
                            }),
                        SyntaxType::UiHint => UiHint::from_str(value)
                            .map(PartialValue::UiHint)
                            .map_err(|()| {
                                OperationError::InvalidAttribute(
                                    "Invalid uihint syntax".to_string(),
                                )
                            }),
                        SyntaxType::AuditLogString => Ok(PartialValue::new_utf8s(value)),
                        SyntaxType::EcKeyPrivate => Ok(PartialValue::SecretValue),
                        SyntaxType::Image => Ok(PartialValue::new_utf8s(value)),
                        SyntaxType::WebauthnAttestationCaList => {
                            Err(OperationError::InvalidAttribute(
                                "Invalid - unable to query attestation CA list".to_string(),
                            ))
                        }
                        SyntaxType::HexString
                        | SyntaxType::KeyInternal
                        | SyntaxType::Certificate => PartialValue::new_hex_string_s(value)
                            .ok_or_else(|| {
                                OperationError::InvalidAttribute(
                                    "Invalid syntax, expected hex string".to_string(),
                                )
                            }),
                        SyntaxType::Sha256 => {
                            let mut sha256bytes = Sha256Output::default();
                            if hex::decode_to_slice(value, &mut sha256bytes).is_ok() {
                                Ok(PartialValue::Sha256(sha256bytes))
                            } else {
                                Err(OperationError::InvalidAttribute(
                                "Invalid syntax, expected sha256 hex string containing 64 characters".to_string(),
                            ))
                            }
                        }
                        SyntaxType::Json => Err(OperationError::InvalidAttribute(
                            "Json values can not be validated by this interface".to_string(),
                        )),
                        SyntaxType::Message => Err(OperationError::InvalidAttribute(
                            "Message values can not be validated by this interface".to_string(),
                        )),
                    }
                }
                None => {
                    // No attribute of this name exists - fail fast, there is no point to
                    // proceed, as nothing can be satisfied.
                    Err(OperationError::InvalidAttributeName(attr.to_string()))
                }
            }
        }

        fn resolve_scim_interim(
            &mut self,
            scim_value_intermediate: ScimValueIntermediate,
        ) -> Result<Option<ScimValueKanidm>, OperationError> {
            match scim_value_intermediate {
                ScimValueIntermediate::Reference(uuid) => {
                    let scim_reference = self
                        .uuid_to_spn(uuid)
                        .and_then(|maybe_value| {
                            maybe_value.ok_or(OperationError::InvalidValueState)
                        })
                        .map(|value| ScimReference {
                            uuid,
                            value: value.to_proto_string_clone(),
                        })?;
                    Ok(Some(ScimValueKanidm::EntryReference(scim_reference)))
                }

                ScimValueIntermediate::References(uuids) => {
                    let scim_references = uuids
                        .into_iter()
                        .map(|uuid| {
                            self.uuid_to_spn(uuid)
                                .and_then(|maybe_value| {
                                    maybe_value.ok_or(OperationError::InvalidValueState)
                                })
                                .map(|value| ScimReference {
                                    uuid,
                                    value: value.to_proto_string_clone(),
                                })
                        })
                        .collect::<Result<Vec<_>, _>>()?;
                    Ok(Some(ScimValueKanidm::EntryReferences(scim_references)))
                }
                ScimValueIntermediate::Oauth2ClaimMap(unresolved_maps) => {
                    let scim_claim_maps = unresolved_maps
                        .into_iter()
                        .map(
                            |UnresolvedScimValueOauth2ClaimMap {
                                 group_uuid,
                                 claim,
                                 join_char,
                                 values,
                             }| {
                                self.uuid_to_spn(group_uuid)
                                    .and_then(|maybe_value| {
                                        maybe_value.ok_or(OperationError::InvalidValueState)
                                    })
                                    .map(|value| ScimOAuth2ClaimMap {
                                        group: value.to_proto_string_clone(),
                                        group_uuid,
                                        claim,
                                        join_char,
                                        values,
                                    })
                            },
                        )
                        .collect::<Result<Vec<_>, _>>()?;

                    Ok(Some(ScimValueKanidm::OAuth2ClaimMap(scim_claim_maps)))
                }

                ScimValueIntermediate::Oauth2ScopeMap(unresolved_maps) => {
                    let scim_claim_maps = unresolved_maps
                        .into_iter()
                        .map(|UnresolvedScimValueOauth2ScopeMap { group_uuid, scopes }| {
                            self.uuid_to_spn(group_uuid)
                                .and_then(|maybe_value| {
                                    maybe_value.ok_or(OperationError::InvalidValueState)
                                })
                                .map(|value| ScimOAuth2ScopeMap {
                                    group: value.to_proto_string_clone(),
                                    group_uuid,
                                    scopes,
                                })
                        })
                        .collect::<Result<Vec<_>, _>>()?;

                    Ok(Some(ScimValueKanidm::OAuth2ScopeMap(scim_claim_maps)))
                }
            }
        }

        fn resolve_scim_json_get(
            &mut self,
            attr: &Attribute,
            value: &JsonValue,
        ) -> Result<PartialValue, OperationError> {
            let schema = self.get_schema();
            // Lookup the attr
            let Some(schema_a) = schema.get_attributes().get(attr) else {
                // No attribute of this name exists - fail fast, there is no point to
                // proceed, as nothing can be satisfied.
                return Err(OperationError::InvalidAttributeName(attr.to_string()));
            };

            debug!(schema_syntax = ?schema_a.syntax, ?value);

            match schema_a.syntax {
                SyntaxType::Utf8String => {
                    let JsonValue::String(value) = value else {
                        return Err(OperationError::InvalidAttribute(attr.to_string()));
                    };
                    Ok(PartialValue::Utf8(value.to_string()))
                }
                SyntaxType::Utf8StringInsensitive | SyntaxType::Utf8StringInsensitiveN => {
                    let JsonValue::String(value) = value else {
                        return Err(OperationError::InvalidAttribute(attr.to_string()));
                    };
                    Ok(PartialValue::new_iutf8(value))
                }
                SyntaxType::Utf8StringIname | SyntaxType::Utf8StringInameN => {
                    let JsonValue::String(value) = value else {
                        return Err(OperationError::InvalidAttribute(attr.to_string()));
                    };
                    Ok(PartialValue::new_iname(value))
                }
                SyntaxType::Uuid | SyntaxType::UuidN => {
                    let JsonValue::String(value) = value else {
                        return Err(OperationError::InvalidAttribute(attr.to_string()));
                    };

                    let un = self.name_to_uuid(value).unwrap_or(UUID_DOES_NOT_EXIST);
                    Ok(PartialValue::Uuid(un))
                }
                SyntaxType::Boolean => {
                    let JsonValue::Bool(value) = value else {
                        return Err(OperationError::InvalidAttribute(attr.to_string()));
                    };
                    Ok(PartialValue::Bool(*value))
                }
                SyntaxType::SyntaxId => {
                    let JsonValue::String(value) = value else {
                        return Err(OperationError::InvalidAttribute(attr.to_string()));
                    };
                    let Ok(value) = SyntaxType::try_from(value.as_str()) else {
                        return Err(OperationError::InvalidAttribute(attr.to_string()));
                    };
                    Ok(PartialValue::Syntax(value))
                }
                SyntaxType::ReferenceUuid
                | SyntaxType::ReferenceUuidN
                | SyntaxType::OauthScopeMap
                | SyntaxType::Session
                | SyntaxType::ApiToken
                | SyntaxType::Oauth2Session
                | SyntaxType::ApplicationPassword => {
                    let JsonValue::String(value) = value else {
                        return Err(OperationError::InvalidAttribute(attr.to_string()));
                    };

                    let un = self.name_to_uuid(value).unwrap_or(UUID_DOES_NOT_EXIST);
                    Ok(PartialValue::Refer(un))
                }

                syntax => {
                    debug!(?attr, ?syntax, "resolve_scim_json_get not implemented");
                    Err(OperationError::InvalidAttribute(attr.to_string()))
                }
            }
        }

        fn resolve_valueset_intermediate(
            &mut self,
            vs_inter: ValueSetIntermediate,
        ) -> Result<ValueSet, OperationError> {
            match vs_inter {
                ValueSetIntermediate::Reference(reference) => {
                    let resolved = match reference {
                            UnresolvedReferenceState::Uuid(uuid) => uuid,
                            UnresolvedReferenceState::Value(value) => {
                                self.name_to_uuid(value.as_str()).unwrap_or_else(|_| {
                                    warn!(
                                        ?value,
                                        "Value can not be resolved to a uuid - assuming it does not exist."
                                    );
                                    UUID_DOES_NOT_EXIST
                                })
                            }
                            UnresolvedReferenceState::Complete {
                                uuid, value
                            } => {
                                self.name_to_uuid(value.as_str())
                                    .inspect(|r_uuid| if *r_uuid != uuid {
                                        warn!(?r_uuid, ?uuid, "Resolved uuid does not match provided uuid for value - this will become an error in future.");
                                    })
                                .unwrap_or_else(|_| {
                                    warn!(
                                        ?value,
                                        "Value can not be resolved to a uuid - assuming it does not exist."
                                    );
                                    uuid
                                })
                            }
                        };

                    let vs = ValueSetRefer::new(resolved);
                    Ok(vs)
                }

                ValueSetIntermediate::References { unresolved } => {
                    let resolved = unresolved.into_iter()
                    .map(|value| {

                        match value {
                            UnresolvedReferenceState::Uuid(uuid) => uuid,
                            UnresolvedReferenceState::Value(value) => {
                                self.name_to_uuid(value.as_str()).unwrap_or_else(|_| {
                                    warn!(
                                        ?value,
                                        "Value can not be resolved to a uuid - assuming it does not exist."
                                    );
                                    UUID_DOES_NOT_EXIST
                                })
                            }
                            UnresolvedReferenceState::Complete {
                                uuid, value
                            } => {
                                self.name_to_uuid(value.as_str())
                                    .inspect(|r_uuid| if *r_uuid != uuid {
                                        warn!(?r_uuid, ?uuid, "Resolved uuid does not match provided uuid for value - this will become an error in future.");
                                    })
                                .unwrap_or_else(|_| {
                                    warn!(
                                        ?value,
                                        "Value can not be resolved to a uuid - assuming it does not exist."
                                    );
                                    uuid
                                })
                            }
                        }
                    })
                    .collect();

                    let vs = ValueSetReferN::from_set(resolved);
                    Ok(vs)
                }

                ValueSetIntermediate::Oauth2ClaimMap {
                    mut resolved,
                    unresolved,
                } => {
                    resolved.extend(unresolved.into_iter().map(
                        |UnresolvedValueSetOauth2ClaimMap {
                             group_name,
                             claim,
                             join_char,
                             claim_values,
                         }| {
                            let group_uuid =
                                self.name_to_uuid(group_name.as_str()).unwrap_or_else(|_| {
                                    warn!(
                            ?group_name,
                            "Value can not be resolved to a uuid - assuming it does not exist."
                        );
                                    UUID_DOES_NOT_EXIST
                                });

                            ResolvedValueSetOauth2ClaimMap {
                                group_uuid,
                                claim,
                                join_char,
                                claim_values,
                            }
                        },
                    ));

                    let vs = ValueSetOauthClaimMap::from_set(resolved);
                    Ok(vs)
                }

                ValueSetIntermediate::Oauth2ScopeMap {
                    mut resolved,
                    unresolved,
                } => {
                    resolved.extend(unresolved.into_iter().map(
                        |UnresolvedValueSetOauth2ScopeMap { group_name, scopes }| {
                            let group_uuid =
                                self.name_to_uuid(group_name.as_str()).unwrap_or_else(|_| {
                                    warn!(
                            ?group_name,
                            "Value can not be resolved to a uuid - assuming it does not exist."
                        );
                                    UUID_DOES_NOT_EXIST
                                });

                            ResolvedValueSetOauth2ScopeMap { group_uuid, scopes }
                        },
                    ));

                    let vs = ValueSetOauthScopeMap::from_set(resolved);
                    Ok(vs)
                }
            }
        }

        // In the opposite direction, we can resolve values for presentation
        fn resolve_valueset(&mut self, value: &ValueSet) -> Result<Vec<String>, OperationError> {
            if let Some(r_set) = value.as_refer_set() {
                let v: Result<Vec<_>, _> = r_set
                    .iter()
                    .copied()
                    .map(|ur| {
                        let nv = self.uuid_to_spn(ur)?;
                        match nv {
                            Some(v) => Ok(v.to_proto_string_clone()),
                            None => Ok(uuid_to_proto_string(ur)),
                        }
                    })
                    .collect();
                v
            } else if let Some(r_map) = value.as_oauthscopemap() {
                let v: Result<Vec<_>, _> = r_map
                    .iter()
                    .map(|(u, m)| {
                        let nv = self.uuid_to_spn(*u)?;
                        let u = match nv {
                            Some(v) => v.to_proto_string_clone(),
                            None => uuid_to_proto_string(*u),
                        };
                        Ok(format!("{u}: {m:?}"))
                    })
                    .collect();
                v
            } else if let Some(r_map) = value.as_oauthclaim_map() {
                let mut v = Vec::with_capacity(0);
                for (claim_name, mapping) in r_map.iter() {
                    for (group_ref, claims) in mapping.values() {
                        let join_char = mapping.join().to_str();

                        let nv = self.uuid_to_spn(*group_ref)?;
                        let resolved_id = match nv {
                            Some(v) => v.to_proto_string_clone(),
                            None => uuid_to_proto_string(*group_ref),
                        };

                        let joined = str_concat!(claims, ",");

                        v.push(format!("{claim_name}:{resolved_id}:{join_char}:{joined:?}"))
                    }
                }
                Ok(v)
            } else {
                let v: Vec<_> = value.to_proto_string_clone_iter().collect();
                Ok(v)
            }
        }

        fn resolve_valueset_ldap(
            &mut self,
            value: &ValueSet,
            basedn: &str,
        ) -> Result<Vec<Vec<u8>>, OperationError> {
            if let Some(r_set) = value.as_refer_set() {
                let v: Result<Vec<_>, _> = r_set
                    .iter()
                    .copied()
                    .map(|ur| {
                        let rdn = self.uuid_to_rdn(ur)?;
                        Ok(format!("{rdn},{basedn}").into_bytes())
                    })
                    .collect();
                v
            // We have to special case ssh keys here as the proto form isn't valid for
            // sss_ssh_authorized_keys to consume.
            } else if let Some(key_iter) = value.as_sshpubkey_string_iter() {
                let v: Vec<_> = key_iter.map(|s| s.into_bytes()).collect();
                Ok(v)
            } else {
                let v: Vec<_> = value
                    .to_proto_string_clone_iter()
                    .map(|s| s.into_bytes())
                    .collect();
                Ok(v)
            }
        }

        fn get_db_domain(&mut self) -> Result<Arc<EntrySealedCommitted>, OperationError> {
            self.internal_search_uuid(UUID_DOMAIN_INFO)
        }

        fn get_domain_key_object_handle(&self) -> Result<Arc<KeyObject>, OperationError> {
            self.get_key_providers()
                .get_key_object_handle(UUID_DOMAIN_INFO)
                .ok_or(OperationError::KP0031KeyObjectNotFound)
        }

        fn get_domain_ldap_allow_unix_pw_bind(&mut self) -> Result<bool, OperationError> {
            self.internal_search_uuid(UUID_DOMAIN_INFO).map(|entry| {
                entry
                    .get_ava_single_bool(Attribute::LdapAllowUnixPwBind)
                    .unwrap_or(true)
            })
        }

        /// Get the password badlist from the system config. You should not call this directly
        /// as this value is cached in the system_config() value.
        fn get_sc_password_badlist(&mut self) -> Result<HashSet<String>, OperationError> {
            self.internal_search_uuid(UUID_SYSTEM_CONFIG)
                .map(|e| match e.get_ava_iter_iutf8(Attribute::BadlistPassword) {
                    Some(vs_str_iter) => vs_str_iter.map(str::to_string).collect::<HashSet<_>>(),
                    None => HashSet::default(),
                })
                .map_err(|e| {
                    error!(
                        ?e,
                        "Failed to retrieve password badlist from system configuration"
                    );
                    e
                })
        }

        /// Get the denied name set from the system config. You should not call this directly
        /// as this value is cached in the system_config() value.
        fn get_sc_denied_names(&mut self) -> Result<HashSet<String>, OperationError> {
            self.internal_search_uuid(UUID_SYSTEM_CONFIG)
                .map(|e| match e.get_ava_iter_iname(Attribute::DeniedName) {
                    Some(vs_str_iter) => vs_str_iter.map(str::to_string).collect::<HashSet<_>>(),
                    None => HashSet::default(),
                })
                .map_err(|e| {
                    error!(
                        ?e,
                        "Failed to retrieve denied names from system configuration"
                    );
                    e
                })
        }

        fn get_oauth2rs_set(&mut self) -> Result<Vec<Arc<EntrySealedCommitted>>, OperationError> {
            self.internal_search(filter!(f_eq(
                Attribute::Class,
                EntryClass::OAuth2ResourceServer.into(),
            )))
        }

        fn get_applications_set(
            &mut self,
        ) -> Result<Vec<Arc<EntrySealedCommitted>>, OperationError> {
            self.internal_search(filter!(f_eq(
                Attribute::Class,
                EntryClass::Application.into(),
            )))
        }
    }
}

// Actually conduct a search request
// This is the core of the server, as it processes the entire event
// applies all parts required in order and more.
impl<'a> QueryServerTransactionPublic<'a> for QueryServerReadTransaction<'a> {
    type AccessControlsTransactionType = AccessControlsReadTransaction<'a>;
    type BackendTransactionType = BackendReadTransaction<'a>;
    type SchemaTransactionType = SchemaReadTransaction;
    type KeyProvidersTransactionType = KeyProvidersReadTransaction;

    fn get_be_txn(&mut self) -> &mut BackendReadTransaction<'a> {
        &mut self.be_txn
    }

    fn get_schema<'b>(&self) -> &'b SchemaReadTransaction {
        // Strip the lifetime here. Schema is a sub-component of the transaction and is
        // *never* changed excepting in a write TXN, so we want to allow the schema to
        // be borrowed while the rest of the read txn is under a mut.
        unsafe {
            let s = (&self.schema) as *const _;
            &*s
        }
    }

    fn get_accesscontrols(&self) -> &AccessControlsReadTransaction<'a> {
        &self.accesscontrols
    }

    fn get_key_providers(&self) -> &KeyProvidersReadTransaction {
        &self.key_providers
    }

    fn get_resolve_filter_cache(&mut self) -> Option<&mut ResolveFilterCacheReadTxn<'a>> {
        Some(&mut self.resolve_filter_cache)
    }

    fn get_feature_hmac_name_history_config(&self) -> &HmacNameHistoryConfig {
        &self.d_info.feature_config.hmac_name_history
    }

    fn get_feature_account_signup_config(&self) -> &AccountSignupConfig {
        &self.d_info.feature_config.account_signup
    }

    fn txn_name_to_uuid(&mut self) -> &mut BTreeMap<String, Uuid> {
        &mut self.txn_name_to_uuid
    }

    fn get_resolve_filter_cache_and_be_txn(
        &mut self,
    ) -> (
        &mut BackendReadTransaction<'a>,
        Option<&mut ResolveFilterCacheReadTxn<'a>>,
    ) {
        (&mut self.be_txn, Some(&mut self.resolve_filter_cache))
    }

    fn pw_badlist(&self) -> &HashSet<String> {
        &self.system_config.pw_badlist
    }

    fn denied_names(&self) -> &HashSet<String> {
        &self.system_config.denied_names
    }

    fn domain_info(&self) -> &DomainInfo {
        &self.d_info
    }

    fn get_domain_version(&self) -> DomainVersion {
        self.d_info.d_vers
    }

    fn get_domain_patch_level(&self) -> u32 {
        self.d_info.d_patch_level
    }

    fn get_domain_development_taint(&self) -> bool {
        self.d_info.d_devel_taint
    }

    fn get_domain_uuid(&self) -> Uuid {
        self.d_info.d_uuid
    }

    fn get_domain_name(&self) -> &str {
        &self.d_info.d_name
    }

    fn get_domain_display_name(&self) -> &str {
        &self.d_info.d_display
    }

    fn get_domain_image_value(&self) -> Option<ImageValue> {
        self.d_info.d_image.clone()
    }
}

impl<'a> sealed::QueryServerTransactionPrivate<'a> for QueryServerReadTransaction<'a> {}

impl<'a> QueryServerTransaction<'a> for QueryServerReadTransaction<'a> {}

impl QueryServerReadTransaction<'_> {
    pub(crate) fn trim_cid(&self) -> &Cid {
        &self.trim_cid
    }

    /// Retrieve the domain info of this server
    pub fn public_domain_info(&mut self) -> Result<ProtoDomainInfo, OperationError> {
        let d_info = &self.d_info;

        Ok(ProtoDomainInfo {
            name: d_info.d_name.clone(),
            displayname: d_info.d_display.clone(),
            uuid: d_info.d_uuid,
            level: d_info.d_vers,
        })
    }

    /// Verify the data content of the server is as expected. This will probably
    /// call various functions for validation, including possibly plugin
    /// verifications.
    pub(crate) fn verify(&mut self) -> Vec<Result<(), ConsistencyError>> {
        // If we fail after backend, we need to return NOW because we can't
        // assert any other faith in the DB states.
        //  * backend
        let be_errs = self.get_be_txn().verify();

        if !be_errs.is_empty() {
            return be_errs;
        }

        //  * in memory schema consistency.
        let sc_errs = self.get_schema().validate();

        if !sc_errs.is_empty() {
            return sc_errs;
        }

        // The schema is now valid, so we load this up

        //  * Indexing (req be + sch )
        let idx_errs = self.get_be_txn().verify_indexes();

        if !idx_errs.is_empty() {
            return idx_errs;
        }

        // If anything error to this point we can't trust the verifications below. From
        // here we can just amass results.
        let mut results = Vec::with_capacity(0);

        // Verify all our entries. Weird flex I know, but it's needed for verifying
        // the entry changelogs are consistent to their entries.
        let schema = self.get_schema();

        let filt_all = filter!(f_pres(Attribute::Class));
        let all_entries = match self.internal_search(filt_all) {
            Ok(a) => a,
            Err(_e) => return vec![Err(ConsistencyError::QueryServerSearchFailure)],
        };

        for e in all_entries {
            e.verify(schema, &mut results)
        }

        // Verify the RUV to the entry changelogs now.
        self.get_be_txn().verify_ruv(&mut results);

        // Ok entries passed, lets move on to the content.
        // Most of our checks are in the plugins, so we let them
        // do their job.

        // Now, call the plugins verification system.
        Plugins::run_verify(self, &mut results);
        // Finished

        results
    }

    #[instrument(level = "debug", skip_all)]
    pub fn scim_entry_id_get_ext(
        &mut self,
        uuid: Uuid,
        class: EntryClass,
        query: ScimEntryGetQuery,
        ident: Identity,
    ) -> Result<ScimEntryKanidm, OperationError> {
        let filter_intent = filter!(f_and!([
            f_eq(Attribute::Uuid, PartialValue::Uuid(uuid)),
            f_eq(Attribute::Class, class.into())
        ]));

        let f_intent_valid = filter_intent
            .validate(self.get_schema())
            .map_err(OperationError::SchemaViolation)?;

        let f_valid = f_intent_valid.clone().into_ignore_hidden();

        let r_attrs = query
            .attributes
            .map(|attr_set| attr_set.into_iter().collect());

        let se = SearchEvent {
            ident,
            filter: f_valid,
            filter_orig: f_intent_valid,
            attrs: r_attrs,
            effective_access_check: query.ext_access_check,
        };

        let mut vs = self.search_ext(&se)?;
        match vs.pop() {
            Some(entry) if vs.is_empty() => entry.to_scim_kanidm(self),
            _ => {
                if vs.is_empty() {
                    Err(OperationError::NoMatchingEntries)
                } else {
                    // Multiple entries matched, should not be possible!
                    Err(OperationError::UniqueConstraintViolation)
                }
            }
        }
    }

    #[instrument(level = "debug", skip_all)]
    pub fn scim_search_ext(
        &mut self,
        ident: Identity,
        filter: ScimFilter,
        query: ScimEntryGetQuery,
    ) -> Result<ScimListResponse, OperationError> {
        let filter = if let Some(ref user_filter) = query.filter {
            ScimFilter::And(Box::new(filter), Box::new(user_filter.clone()))
        } else {
            filter
        };

        let filter_intent = Filter::from_scim_ro(&ident, &filter, self)
            .inspect_err(|err| error!(?err, "Unable to resolve scim filter"))?;

        self.scim_search_filter_ext(ident, &filter_intent, query)
    }

    pub fn scim_search_filter_ext(
        &mut self,
        ident: Identity,
        filter_intent: &Filter<FilterInvalid>,
        query: ScimEntryGetQuery,
    ) -> Result<ScimListResponse, OperationError> {
        let f_intent_valid = filter_intent
            .validate(self.get_schema())
            .map_err(OperationError::SchemaViolation)?;

        let f_valid = f_intent_valid.clone().into_ignore_hidden();

        let r_attrs = query
            .attributes
            .map(|attr_set| attr_set.into_iter().collect());

        let se = SearchEvent {
            ident,
            filter: f_valid,
            filter_orig: f_intent_valid,
            attrs: r_attrs,
            effective_access_check: query.ext_access_check,
        };

        let mut result_set = self.search_ext(&se)?;

        // We need to know total_results before we paginate.
        let total_results = result_set.len() as u64;

        // These are STUPID ways to do this, but they demonstrate that the feature
        // works and it's viable on small datasets. We will make this use indexes
        // in the future!

        // First, sort if any.
        if let Some(sort_attr) = query.sort_by {
            result_set.sort_unstable_by(|entry_left, entry_right| {
                let left = entry_left.get_ava_set(&sort_attr);
                let right = entry_right.get_ava_set(&sort_attr);
                match (left, right) {
                    (Some(left), Some(right)) => left.cmp(right),
                    (Some(_), None) => std::cmp::Ordering::Less,
                    (None, Some(_)) => std::cmp::Ordering::Greater,
                    (None, None) => std::cmp::Ordering::Equal,
                }
            });
        }

        // Paginate, if any.
        let (items_per_page, start_index, paginated_result_set) = if let Some(count) = query.count {
            let count: u64 = count.get();
            // User wants pagination. Count is how many elements they want.

            let start_index: u64 = query
                .start_index
                .map(|non_zero_index|
                    // SCIM pagination is 1 indexed, not 0.
                    non_zero_index.get() - 1)
                .unwrap_or_default();

            // First, check that our start_index is valid.
            if start_index as usize > result_set.len() {
                // SCIM rfc doesn't define what happens if start index
                // is OOB of the result set.
                return Err(OperationError::SC0029PaginationOutOfBounds);
            }

            let mut result_set = result_set.split_off(start_index as usize);
            result_set.truncate(count as usize);

            (
                NonZeroU64::new(count),
                NonZeroU64::new(start_index + 1),
                result_set,
            )
        } else {
            // Unchanged
            (None, None, result_set)
        };

        let resources = paginated_result_set
            .into_iter()
            .map(|entry| entry.to_scim_kanidm(self))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(ScimListResponse {
            // Requires other schema changes in future.
            schemas: Vec::with_capacity(0),
            total_results,
            items_per_page,
            start_index,
            resources,
        })
    }

    #[instrument(level = "debug", skip_all)]
    pub fn scim_search_message_ready_ext(
        &mut self,
        ident: Identity,
        curtime: Duration,
    ) -> Result<ScimListResponse, OperationError> {
        let curtime_odt = OffsetDateTime::UNIX_EPOCH + curtime;

        let filter_intent = filter_all!(f_and(vec![
            f_eq(Attribute::Class, EntryClass::OutboundMessage.into()),
            f_lt(Attribute::SendAfter, PartialValue::DateTime(curtime_odt)),
            f_andnot(f_pres(Attribute::SentAt))
        ]));

        let query = ScimEntryGetQuery::default();

        self.scim_search_filter_ext(ident, &filter_intent, query)
    }
}

impl<'a> QueryServerTransactionPublic<'a> for QueryServerWriteTransaction<'a> {
    type AccessControlsTransactionType = AccessControlsWriteTransaction<'a>;
    type BackendTransactionType = BackendWriteTransaction<'a>;
    type SchemaTransactionType = SchemaWriteTransaction<'a>;
    type KeyProvidersTransactionType = KeyProvidersWriteTransaction<'a>;

    fn get_be_txn(&mut self) -> &mut BackendWriteTransaction<'a> {
        &mut self.be_txn
    }

    fn get_schema<'b>(&self) -> &'b SchemaWriteTransaction<'a> {
        // Strip the lifetime here. Schema is a sub-component of the transaction and is
        // *never* changed excepting in a write TXN, so we want to allow the schema to
        // be borrowed while the rest of the read txn is under a mut.
        unsafe {
            let s = (&self.schema) as *const _;
            &*s
        }
    }

    fn get_accesscontrols(&self) -> &AccessControlsWriteTransaction<'a> {
        &self.accesscontrols
    }

    fn get_key_providers(&self) -> &KeyProvidersWriteTransaction<'a> {
        &self.key_providers
    }

    fn get_resolve_filter_cache(&mut self) -> Option<&mut ResolveFilterCacheReadTxn<'a>> {
        if self.resolve_filter_cache_clear || *self.phase < ServerPhase::SchemaReady {
            None
        } else {
            Some(&mut self.resolve_filter_cache)
        }
    }

    fn get_feature_hmac_name_history_config(&self) -> &HmacNameHistoryConfig {
        &self.d_info.feature_config.hmac_name_history
    }

    fn get_feature_account_signup_config(&self) -> &AccountSignupConfig {
        &self.d_info.feature_config.account_signup
    }

    fn txn_name_to_uuid(&mut self) -> &mut BTreeMap<String, Uuid> {
        &mut self.txn_name_to_uuid
    }

    fn get_resolve_filter_cache_and_be_txn(
        &mut self,
    ) -> (
        &mut BackendWriteTransaction<'a>,
        Option<&mut ResolveFilterCacheReadTxn<'a>>,
    ) {
        if self.resolve_filter_cache_clear || *self.phase < ServerPhase::SchemaReady {
            (&mut self.be_txn, None)
        } else {
            (&mut self.be_txn, Some(&mut self.resolve_filter_cache))
        }
    }

    fn pw_badlist(&self) -> &HashSet<String> {
        &self.system_config.pw_badlist
    }

    fn denied_names(&self) -> &HashSet<String> {
        &self.system_config.denied_names
    }

    fn domain_info(&self) -> &DomainInfo {
        &self.d_info
    }

    fn get_domain_version(&self) -> DomainVersion {
        self.d_info.d_vers
    }

    fn get_domain_patch_level(&self) -> u32 {
        self.d_info.d_patch_level
    }

    fn get_domain_development_taint(&self) -> bool {
        self.d_info.d_devel_taint
    }

    fn get_domain_uuid(&self) -> Uuid {
        self.d_info.d_uuid
    }

    /// Gets the in-memory domain_name element
    fn get_domain_name(&self) -> &str {
        &self.d_info.d_name
    }

    fn get_domain_display_name(&self) -> &str {
        &self.d_info.d_display
    }

    fn get_domain_image_value(&self) -> Option<ImageValue> {
        self.d_info.d_image.clone()
    }
}

impl<'a> sealed::QueryServerTransactionPrivate<'a> for QueryServerWriteTransaction<'a> {}

impl<'a> QueryServerTransaction<'a> for QueryServerWriteTransaction<'a> {}

impl QueryServer {
    pub fn new(
        be: Backend,
        schema: Schema,
        domain_name: String,
        curtime: Duration,
    ) -> Result<Self, OperationError> {
        let (s_uuid, d_uuid, ts_max) = {
            let mut wr = be.write()?;
            let s_uuid = wr.get_db_s_uuid()?;
            let d_uuid = wr.get_db_d_uuid()?;
            let ts_max = wr.get_db_ts_max(curtime)?;
            wr.commit()?;
            (s_uuid, d_uuid, ts_max)
        };

        let pool_size = be.get_pool_size();

        debug!("Server UUID -> {:?}", s_uuid);
        debug!("Domain UUID -> {:?}", d_uuid);
        debug!("Domain Name -> {:?}", domain_name);

        let d_info = Arc::new(CowCell::new(DomainInfo {
            d_uuid,
            // Start with our level as zero.
            // This will be reloaded from the DB shortly :)
            d_vers: DOMAIN_LEVEL_0,
            d_patch_level: 0,
            d_name: domain_name.clone(),
            // we set the domain_display_name to the configuration file's domain_name
            // here because the database is not started, so we cannot pull it from there.
            d_display: domain_name,
            // Automatically derive our current taint mode based on the PRERELEASE setting.
            d_devel_taint: option_env!("KANIDM_PRE_RELEASE").is_some(),
            d_ldap_allow_unix_pw_bind: false,
            d_allow_easter_eggs: false,
            d_allow_account_recovery: false,
            d_image: None,
            feature_config: FeatureConfig::default(),
        }));

        let cid = Cid::new_lamport(s_uuid, curtime, &ts_max);
        let cid_max = Arc::new(CowCell::new(cid));

        // These default to empty, but they'll be populated shortly.
        let system_config = Arc::new(CowCell::new(SystemConfig::default()));

        let dyngroup_cache = Arc::new(CowCell::new(DynGroupCache::default()));

        let phase = Arc::new(CowCell::new(ServerPhase::Bootstrap));

        let resolve_filter_cache = Arc::new(
            ARCacheBuilder::new()
                .set_size(RESOLVE_FILTER_CACHE_MAX, RESOLVE_FILTER_CACHE_LOCAL)
                .set_reader_quiesce(true)
                .build()
                .ok_or_else(|| {
                    error!("Failed to build filter resolve cache");
                    OperationError::DB0003FilterResolveCacheBuild
                })?,
        );

        let key_providers = Arc::new(KeyProviders::default());

        // These needs to be pool_size minus one to always leave a DB ticket
        // for a writer. But it also needs to be at least one :)
        debug_assert!(pool_size > 0);
        let read_ticket_pool = std::cmp::max(pool_size - 1, 1);

        Ok(QueryServer {
            phase,
            d_info,
            system_config,
            be,
            schema: Arc::new(schema),
            accesscontrols: Arc::new(AccessControls::default()),
            db_tickets: Arc::new(Semaphore::new(pool_size as usize)),
            read_tickets: Arc::new(Semaphore::new(read_ticket_pool as usize)),
            write_ticket: Arc::new(Semaphore::new(1)),
            resolve_filter_cache,
            dyngroup_cache,
            cid_max,
            key_providers,
        })
    }

    pub fn try_quiesce(&self) {
        self.be.try_quiesce();
        self.accesscontrols.try_quiesce();
        self.resolve_filter_cache.try_quiesce();
    }

    #[instrument(level = "debug", skip_all)]
    async fn read_acquire_ticket(&self) -> Option<(SemaphorePermit<'_>, SemaphorePermit<'_>)> {
        // Get a read ticket. Basically this forces us to queue with other readers, while preventing
        // us from competing with writers on the db tickets. This tilts us to write prioritising
        // on db operations by always making sure a writer can get a db ticket.
        let read_ticket = if cfg!(test) {
            self.read_tickets
                .try_acquire()
                .inspect_err(|err| {
                    error!(?err, "Unable to acquire read ticket!");
                })
                .ok()?
        } else {
            let fut = tokio::time::timeout(
                Duration::from_millis(DB_LOCK_ACQUIRE_TIMEOUT_MILLIS),
                self.read_tickets.acquire(),
            );

            match fut.await {
                Ok(Ok(ticket)) => ticket,
                Ok(Err(_)) => {
                    error!("Failed to acquire read ticket, may be poisoned.");
                    return None;
                }
                Err(_) => {
                    error!("Failed to acquire read ticket, server is overloaded.");
                    return None;
                }
            }
        };

        // We need to ensure a db conn will be available. At this point either a db ticket
        // *must* be available because pool_size >= 2 and the only other holders are write
        // and read ticket holders, OR pool_size == 1, and we are waiting on the writer to now
        // complete.
        let db_ticket = if cfg!(test) {
            self.db_tickets
                .try_acquire()
                .inspect_err(|err| {
                    error!(?err, "Unable to acquire database ticket!");
                })
                .ok()?
        } else {
            self.db_tickets
                .acquire()
                .await
                .inspect_err(|err| {
                    error!(?err, "Unable to acquire database ticket!");
                })
                .ok()?
        };

        Some((read_ticket, db_ticket))
    }

    pub async fn read(&self) -> Result<QueryServerReadTransaction<'_>, OperationError> {
        let (read_ticket, db_ticket) = self
            .read_acquire_ticket()
            .await
            .ok_or(OperationError::DatabaseLockAcquisitionTimeout)?;
        // Point of no return - we now have a DB thread AND the read ticket, we MUST complete
        // as soon as possible! The following locks and elements below are SYNCHRONOUS but
        // will never be contented at this point, and will always progress.
        let schema = self.schema.read();

        let cid_max = self.cid_max.read();
        let trim_cid = cid_max.sub_secs(CHANGELOG_MAX_AGE)?;

        let be_txn = self.be.read()?;

        Ok(QueryServerReadTransaction {
            be_txn,
            schema,
            d_info: self.d_info.read(),
            system_config: self.system_config.read(),
            accesscontrols: self.accesscontrols.read(),
            key_providers: self.key_providers.read(),
            _db_ticket: db_ticket,
            _read_ticket: read_ticket,
            resolve_filter_cache: self.resolve_filter_cache.read(),
            trim_cid,
            txn_name_to_uuid: Default::default(),
        })
    }

    #[instrument(level = "debug", skip_all)]
    async fn write_acquire_ticket(&self) -> Option<(SemaphorePermit<'_>, SemaphorePermit<'_>)> {
        // Guarantee we are the only writer on the thread pool
        let write_ticket = if cfg!(test) {
            self.write_ticket
                .try_acquire()
                .inspect_err(|err| {
                    error!(?err, "Unable to acquire write ticket!");
                })
                .ok()?
        } else {
            let fut = tokio::time::timeout(
                Duration::from_millis(DB_LOCK_ACQUIRE_TIMEOUT_MILLIS),
                self.write_ticket.acquire(),
            );

            match fut.await {
                Ok(Ok(ticket)) => ticket,
                Ok(Err(_)) => {
                    error!("Failed to acquire write ticket, may be poisoned.");
                    return None;
                }
                Err(_) => {
                    error!("Failed to acquire write ticket, server is overloaded.");
                    return None;
                }
            }
        };

        // We need to ensure a db conn will be available. At this point either a db ticket
        // *must* be available because pool_size >= 2 and the only other are readers, or
        // pool_size == 1 and we are waiting on a single reader to now complete
        let db_ticket = if cfg!(test) {
            self.db_tickets
                .try_acquire()
                .inspect_err(|err| {
                    error!(?err, "Unable to acquire write db_ticket!");
                })
                .ok()?
        } else {
            self.db_tickets
                .acquire()
                .await
                .inspect_err(|err| {
                    error!(?err, "Unable to acquire write db_ticket!");
                })
                .ok()?
        };

        Some((write_ticket, db_ticket))
    }

    pub async fn write(
        &self,
        curtime: Duration,
    ) -> Result<QueryServerWriteTransaction<'_>, OperationError> {
        let (write_ticket, db_ticket) = self
            .write_acquire_ticket()
            .await
            .ok_or(OperationError::DatabaseLockAcquisitionTimeout)?;

        // Point of no return - we now have a DB thread AND the write ticket, we MUST complete
        // as soon as possible! The following locks and elements below are SYNCHRONOUS but
        // will never be contented at this point, and will always progress.

        let be_txn = self.be.write()?;

        let schema_write = self.schema.write();
        let d_info = self.d_info.write();
        let system_config = self.system_config.write();
        let phase = self.phase.write();

        let mut cid = self.cid_max.write();
        // Update the cid now.
        *cid = Cid::new_lamport(cid.s_uuid, curtime, &cid.ts);

        let trim_cid = cid.sub_secs(CHANGELOG_MAX_AGE)?;

        Ok(QueryServerWriteTransaction {
            // I think this is *not* needed, because commit is mut self which should
            // take ownership of the value, and cause the commit to "only be run
            // once".
            //
            // The committed flag is however used for abort-specific code in drop
            // which today I don't think we have ... yet.
            committed: false,
            phase,
            d_info,
            system_config,
            curtime,
            cid,
            trim_cid,
            be_txn,
            schema: schema_write,
            accesscontrols: self.accesscontrols.write(),
            changed_flags: ChangeFlag::empty(),
            changed_uuid: HashSet::new(),
            _db_ticket: db_ticket,
            _write_ticket: write_ticket,
            resolve_filter_cache: self.resolve_filter_cache.read(),
            resolve_filter_cache_clear: false,
            resolve_filter_cache_write: self.resolve_filter_cache.write(),
            dyngroup_cache: self.dyngroup_cache.write(),
            key_providers: self.key_providers.write(),
            txn_name_to_uuid: Default::default(),
        })
    }

    #[cfg(any(test, debug_assertions))]
    pub async fn clear_cache(&self) -> Result<(), OperationError> {
        let ct = duration_from_epoch_now();
        let mut w_txn = self.write(ct).await?;
        w_txn.clear_cache()?;
        w_txn.commit()
    }

    pub async fn verify(&self) -> Vec<Result<(), ConsistencyError>> {
        let current_time = duration_from_epoch_now();
        // Before we can proceed, command the QS to load schema in full.
        // IMPORTANT: While we take a write txn, this does no writes to the
        // actual db, it's only so we can write to the in memory schema
        // structures.
        if self
            .write(current_time)
            .await
            .and_then(|mut txn| {
                txn.force_schema_reload();
                txn.commit()
            })
            .is_err()
        {
            return vec![Err(ConsistencyError::Unknown)];
        };

        match self.read().await {
            Ok(mut r_txn) => r_txn.verify(),
            Err(_) => vec![Err(ConsistencyError::Unknown)],
        }
    }
}

impl<'a> QueryServerWriteTransaction<'a> {
    pub(crate) fn get_server_uuid(&self) -> Uuid {
        // Cid has our server id within
        self.cid.s_uuid
    }

    pub(crate) fn reset_server_uuid(&mut self) -> Result<(), OperationError> {
        let s_uuid = self.be_txn.reset_db_s_uuid().map_err(|err| {
            error!(?err, "Failed to reset server replication uuid");
            err
        })?;

        debug!(?s_uuid, "reset server replication uuid");

        self.cid.s_uuid = s_uuid;

        Ok(())
    }

    pub(crate) fn get_curtime(&self) -> Duration {
        self.curtime
    }

    pub(crate) fn get_curtime_odt(&self) -> OffsetDateTime {
        OffsetDateTime::UNIX_EPOCH + self.curtime
    }

    pub(crate) fn get_cid(&self) -> &Cid {
        &self.cid
    }

    pub(crate) fn get_key_providers_mut(&mut self) -> &mut KeyProvidersWriteTransaction<'a> {
        &mut self.key_providers
    }

    pub(crate) fn get_dyngroup_cache(&mut self) -> &mut DynGroupCache {
        &mut self.dyngroup_cache
    }

    pub fn domain_raise(&mut self, level: u32) -> Result<(), OperationError> {
        if level > DOMAIN_MAX_LEVEL {
            return Err(OperationError::MG0002RaiseDomainLevelExceedsMaximum);
        }

        let modl = ModifyList::new_purge_and_set(Attribute::Version, Value::Uint32(level));
        let udi = PVUUID_DOMAIN_INFO.clone();
        let filt = filter_all!(f_eq(Attribute::Uuid, udi));
        self.internal_modify(&filt, &modl)
    }

    pub fn domain_remigrate(&mut self, level: u32) -> Result<(), OperationError> {
        let mut_d_info = self.d_info.get_mut();

        // NOTE: See reload_domain_info_version which asserts that we are not attempting
        // an unsupported remigration. This check is just a smoke check to no-op if we
        // are not requesting any meaningful action.
        if level > mut_d_info.d_vers {
            // Nothing to do.
            return Ok(());
        };

        info!(
            "Preparing to re-migrate from {} -> {}",
            level, mut_d_info.d_vers
        );
        mut_d_info.d_vers = level;
        self.changed_flags.insert(ChangeFlag::DOMAIN);

        Ok(())
    }

    #[instrument(level = "debug", skip_all)]
    pub(crate) fn reload_schema(&mut self) -> Result<(), OperationError> {
        match self.get_domain_version() {
            /*
            0 => {
                // server is being brought up, so the schema was already set by a caller.
            }
            */
            level if level < DOMAIN_LEVEL_1_11 => {
                // supply entries to the writable schema to reload from.
                // find all attributes.
                let filt = filter!(f_eq(Attribute::Class, EntryClass::AttributeType.into()));
                let res = self.internal_search(filt).map_err(|e| {
                    error!("reload schema internal search failed {:?}", e);
                    e
                })?;
                // load them.
                let attributetypes: Result<Vec<_>, _> =
                    res.iter().map(|e| SchemaAttribute::try_from(e)).collect();

                let attributetypes = attributetypes.map_err(|e| {
                    error!("reload schema attributetypes {:?}", e);
                    e
                })?;

                // IMPORTANT: If attribute types is empty, it's because we are in "in memory schema"
                // mode only. This is a horrid hack but it's needed for backwards compat for now.
                //
                // The reason it's needed is that at this phase in bootstrap, domain_version is 0
                // but the on-disk schema mode relies on that to trigger a read from the DB. We can't
                // gate on version == 0 because that breaks the older versions. But if we DONT do
                // anything then this call will nuke the in memory schema that we just setup causing
                // the server to fail.
                if attributetypes.is_empty() {
                    debug!("DB attributes are empty - we are probably in DL_1_11 memory only schema mode.");
                } else {
                    self.schema
                        .update_attributes(attributetypes.into_iter())
                        .map_err(|e| {
                            error!("reload schema update attributetypes {:?}", e);
                            e
                        })?;

                    // find all classes
                    let filt = filter!(f_eq(Attribute::Class, EntryClass::ClassType.into()));
                    let res = self.internal_search(filt).map_err(|e| {
                        error!("reload schema internal search failed {:?}", e);
                        e
                    })?;
                    // load them.
                    let classtypes: Result<Vec<_>, _> =
                        res.iter().map(|e| SchemaClass::try_from(e)).collect();
                    let classtypes = classtypes.map_err(|e| {
                        error!("reload schema classtypes {:?}", e);
                        e
                    })?;

                    self.schema
                        .update_classes(classtypes.into_iter())
                        .map_err(|e| {
                            error!("reload schema update classtypes {:?}", e);
                            e
                        })?;

                    // validate.
                    let valid_r = self.schema.validate();

                    // Translate the result.
                    if !valid_r.is_empty() {
                        // Log the failures
                        error!("Schema reload failed -> {:?}", valid_r);
                        return Err(OperationError::ConsistencyError(
                            valid_r.into_iter().filter_map(|v| v.err()).collect(),
                        ));
                    };
                }
            }
            DOMAIN_LEVEL_1_11 => self.migrate_schema_1_11()?,
            DOMAIN_LEVEL_1_12 => self.migrate_schema_1_12()?,
            DOMAIN_LEVEL_1_13 => self.migrate_schema_1_13()?,
            _ => {
                debug_assert!(false, "domain level was not configured in reload_schema");
                return Err(OperationError::MG0001InvalidReMigrationLevel);
            }
        }

        // Now use this to reload the backend idxmeta
        trace!("Reloading idxmeta ...");
        self.be_txn
            .update_idxmeta(self.schema.reload_idxmeta())
            .inspect_err(|err| {
                error!(?err, "reload schema update idxmeta");
            })?;

        // Since we reloaded the schema, we need to reload the filter cache since it
        // may have incorrect or outdated information about indexes now.
        self.resolve_filter_cache_clear = true;

        // Trigger reloads on services that require post-schema reloads.
        // Mainly this is plugins.
        DynGroup::reload(self)?;

        Ok(())
    }

    #[instrument(level = "debug", skip_all)]
    fn reload_accesscontrols(&mut self) -> Result<(), OperationError> {
        // supply entries to the writable access controls to reload from.
        // This has to be done in FOUR passes - one for each type!
        //
        // Note, we have to do the search, parse, then submit here, because of the
        // requirement to have the write query server reference in the parse stage - this
        // would cause a rust double-borrow if we had AccessControls to try to handle
        // the entry lists themself.
        trace!("ACP reload started ...");

        // Update the set of sync agreements

        let filt = filter!(f_eq(Attribute::Class, EntryClass::SyncAccount.into()));

        let res = self.internal_search(filt).map_err(|e| {
            admin_error!(
                err = ?e,
                "reload accesscontrols internal search failed",
            );
            e
        })?;

        let sync_agreement_map: HashMap<Uuid, BTreeSet<Attribute>> = res
            .iter()
            .filter_map(|e| {
                e.get_ava_as_iutf8(Attribute::SyncYieldAuthority)
                    .map(|set| {
                        let set: BTreeSet<_> =
                            set.iter().map(|s| Attribute::from(s.as_str())).collect();
                        (e.get_uuid(), set)
                    })
            })
            .collect();

        self.accesscontrols
            .update_sync_agreements(sync_agreement_map);

        // Update search
        let filt = filter!(f_and!([
            f_eq(Attribute::Class, EntryClass::AccessControlProfile.into()),
            f_eq(Attribute::Class, EntryClass::AccessControlSearch.into()),
            f_andnot(f_eq(Attribute::AcpEnable, PV_FALSE.clone())),
        ]));

        let res = self.internal_search(filt).map_err(|e| {
            admin_error!(
                err = ?e,
                "reload accesscontrols internal search failed",
            );
            e
        })?;
        let search_acps: Result<Vec<_>, _> = res
            .iter()
            .map(|e| AccessControlSearch::try_from(self, e))
            .collect();

        let search_acps = search_acps.map_err(|e| {
            admin_error!(err = ?e, "Unable to parse search accesscontrols");
            e
        })?;

        self.accesscontrols
            .update_search(search_acps)
            .map_err(|e| {
                admin_error!(err = ?e, "Failed to update search accesscontrols");
                e
            })?;
        // Update create
        let filt = filter!(f_and!([
            f_eq(Attribute::Class, EntryClass::AccessControlProfile.into()),
            f_eq(Attribute::Class, EntryClass::AccessControlCreate.into()),
            f_andnot(f_eq(Attribute::AcpEnable, PV_FALSE.clone())),
        ]));

        let res = self.internal_search(filt).map_err(|e| {
            admin_error!(
                err = ?e,
                "reload accesscontrols internal search failed"
            );
            e
        })?;
        let create_acps: Result<Vec<_>, _> = res
            .iter()
            .map(|e| AccessControlCreate::try_from(self, e))
            .collect();

        let create_acps = create_acps.map_err(|e| {
            admin_error!(err = ?e, "Unable to parse create accesscontrols");
            e
        })?;

        self.accesscontrols
            .update_create(create_acps)
            .map_err(|e| {
                admin_error!(err = ?e, "Failed to update create accesscontrols");
                e
            })?;
        // Update modify
        let filt = filter!(f_and!([
            f_eq(Attribute::Class, EntryClass::AccessControlProfile.into()),
            f_eq(Attribute::Class, EntryClass::AccessControlModify.into()),
            f_andnot(f_eq(Attribute::AcpEnable, PV_FALSE.clone())),
        ]));

        let res = self.internal_search(filt).map_err(|e| {
            admin_error!("reload accesscontrols internal search failed {:?}", e);
            e
        })?;
        let modify_acps: Result<Vec<_>, _> = res
            .iter()
            .map(|e| AccessControlModify::try_from(self, e))
            .collect();

        let modify_acps = modify_acps.map_err(|e| {
            admin_error!("Unable to parse modify accesscontrols {:?}", e);
            e
        })?;

        self.accesscontrols
            .update_modify(modify_acps)
            .map_err(|e| {
                admin_error!("Failed to update modify accesscontrols {:?}", e);
                e
            })?;
        // Update delete
        let filt = filter!(f_and!([
            f_eq(Attribute::Class, EntryClass::AccessControlProfile.into()),
            f_eq(Attribute::Class, EntryClass::AccessControlDelete.into()),
            f_andnot(f_eq(Attribute::AcpEnable, PV_FALSE.clone())),
        ]));

        let res = self.internal_search(filt).map_err(|e| {
            admin_error!("reload accesscontrols internal search failed {:?}", e);
            e
        })?;
        let delete_acps: Result<Vec<_>, _> = res
            .iter()
            .map(|e| AccessControlDelete::try_from(self, e))
            .collect();

        let delete_acps = delete_acps.map_err(|e| {
            admin_error!("Unable to parse delete accesscontrols {:?}", e);
            e
        })?;

        self.accesscontrols.update_delete(delete_acps).map_err(|e| {
            admin_error!("Failed to update delete accesscontrols {:?}", e);
            e
        })
    }

    #[instrument(level = "debug", skip_all)]
    pub(crate) fn reload_key_material(&mut self) -> Result<(), OperationError> {
        let filt = filter!(f_eq(Attribute::Class, EntryClass::KeyProvider.into()));

        let res = self.internal_search(filt).map_err(|e| {
            admin_error!(
                err = ?e,
                "reload key providers internal search failed",
            );
            e
        })?;

        // FUTURE: During this reload we may need to access the PIN or other data
        // to access the provider.
        let providers = res
            .iter()
            .map(|e| KeyProvider::try_from(e).and_then(|kp| kp.test().map(|()| kp)))
            .collect::<Result<Vec<_>, _>>()?;

        self.key_providers.update_providers(providers)?;

        let filt = filter!(f_eq(Attribute::Class, EntryClass::KeyObject.into()));

        let res = self.internal_search(filt).map_err(|e| {
            admin_error!(
                err = ?e,
                "reload key objects internal search failed",
            );
            e
        })?;

        res.iter()
            .try_for_each(|entry| self.key_providers.load_key_object(entry.as_ref()))
    }

    #[instrument(level = "debug", skip_all)]
    pub(crate) fn reload_system_config(&mut self) -> Result<(), OperationError> {
        let denied_names = self.get_sc_denied_names()?;
        let pw_badlist = self.get_sc_password_badlist()?;

        let mut_system_config = self.system_config.get_mut();
        mut_system_config.denied_names = denied_names;
        mut_system_config.pw_badlist = pw_badlist;
        Ok(())
    }

    /// Pulls the domain name from the database and updates the DomainInfo data in memory
    #[instrument(level = "debug", skip_all)]
    pub(crate) fn reload_domain_info_version(&mut self) -> Result<(), OperationError> {
        let domain_info = self.internal_search_uuid(UUID_DOMAIN_INFO).map_err(|err| {
            error!(?err, "Error getting domain info");
            err
        })?;

        let domain_info_version = domain_info
            .get_ava_single_uint32(Attribute::Version)
            .ok_or_else(|| {
                error!("domain info missing attribute version");
                OperationError::InvalidEntryState
            })?;

        let domain_info_patch_level = domain_info
            .get_ava_single_uint32(Attribute::PatchLevel)
            .unwrap_or(0);

        // If we have moved from stable to dev, this triggers the taint. If we
        // are moving from dev to stable, the db will be true triggering the
        // taint flag. If we are stable to stable this will be false.
        let current_devel_flag = option_env!("KANIDM_PRE_RELEASE").is_some();
        let domain_info_devel_taint = current_devel_flag
            || domain_info
                .get_ava_single_bool(Attribute::DomainDevelopmentTaint)
                .unwrap_or_default();

        let domain_allow_easter_eggs = domain_info
            .get_ava_single_bool(Attribute::DomainAllowEasterEggs)
            // This defaults to false for release versions, and true in development
            .unwrap_or(option_env!("KANIDM_PRE_RELEASE").is_some());

        let domain_allow_account_recovery = domain_info
            .get_ava_single_bool(Attribute::DomainAllowAccountRecovery)
            .unwrap_or_default();

        // We have to set the domain version here so that features which check for it
        // will now see it's been increased. This also prevents recursion during reloads
        // inside of a domain migration.
        let mut_d_info = self.d_info.get_mut();
        debug!(?mut_d_info);
        // This is the value that is set as part of re-migrate.
        let previous_version = mut_d_info.d_vers;
        let previous_patch_level = mut_d_info.d_patch_level;
        mut_d_info.d_vers = domain_info_version;
        mut_d_info.d_patch_level = domain_info_patch_level;
        mut_d_info.d_devel_taint = domain_info_devel_taint;
        mut_d_info.d_allow_easter_eggs = domain_allow_easter_eggs;
        mut_d_info.d_allow_account_recovery = domain_allow_account_recovery;

        debug!(?mut_d_info);

        // We must both be at the correct domain version *and* the correct patch level. If we are
        // not, then we only proceed to migrate *if* our server boot phase is correct.
        if (previous_version == domain_info_version
            && previous_patch_level == domain_info_patch_level)
            || *self.phase < ServerPhase::DomainInfoReady
        {
            return Ok(());
        }

        debug!(domain_previous_version = ?previous_version, domain_target_version = ?domain_info_version);
        debug!(domain_previous_patch_level = ?previous_patch_level, domain_target_patch_level = ?domain_info_patch_level);

        // We have to check for DL0 since that's the initialisation level. If we are at DL0 then
        // the server was just brought up and there are no other actions to take since we are
        // now at TGT level.
        if previous_version == DOMAIN_LEVEL_0 {
            debug!(
                "Server was just brought up, skipping migrations as we are already at target level"
            );
            return Ok(());
        }

        if previous_version < DOMAIN_MIN_REMIGRATION_LEVEL {
            let valid_levels: Vec<_> =
                (DOMAIN_MIN_REMIGRATION_LEVEL..DOMAIN_PREVIOUS_TGT_LEVEL).collect();
            error!("UNABLE TO PROCEED. You have requested an initial migration level which is lower than supported.");
            error!("For more see: https://kanidm.github.io/kanidm/stable/support.html#upgrade-policy and https://kanidm.github.io/kanidm/stable/server_updates.html");
            error!(domain_previous_version = ?previous_version, domain_target_version = ?domain_info_version);
            error!(domain_previous_patch_level = ?previous_patch_level, domain_target_patch_level = ?domain_info_patch_level);
            error!(?valid_levels);

            debug_assert!(false);

            return Err(OperationError::MG0001InvalidReMigrationLevel);
        }

        // Commented as an example of patch application
        /*
        if previous_patch_level < PATCH_LEVEL_2
            && domain_info_patch_level >= PATCH_LEVEL_2
            && domain_info_version == DOMAIN_LEVEL_9
        {
            self.migrate_domain_patch_level_2()?;
        }
        */

        // This is to catch during development if we incorrectly move MIN_REMIGRATION but
        // without actually updating these values correctly.
        const { assert!(DOMAIN_MIN_REMIGRATION_LEVEL <= DOMAIN_PREVIOUS_TGT_LEVEL) };
        const { assert!(DOMAIN_MIN_REMIGRATION_LEVEL >= DOMAIN_MIN_CREATION_LEVEL) };

        const { assert!(DOMAIN_MIN_CREATION_LEVEL >= DOMAIN_LEVEL_12) };

        //                     /--- This needs to be the minimum creation level.
        //                     |                                          /-- This is the minlevel we can remigrate from
        //                     v                                          v
        if previous_version <= DOMAIN_LEVEL_11 && domain_info_version >= DOMAIN_LEVEL_12 {
            // 1.7 -> 1.8
            self.migrate_domain_11_to_12()?;
        }

        if previous_version <= DOMAIN_LEVEL_12 && domain_info_version >= DOMAIN_LEVEL_13 {
            // 1.8 -> 1.9
            self.migrate_domain_12_to_13()?;
        }

        if previous_version <= DOMAIN_LEVEL_13 && domain_info_version >= DOMAIN_LEVEL_14 {
            // 1.9 -> 1.10
            self.migrate_domain_13_to_14()?;
        }

        if previous_version <= DOMAIN_LEVEL_14 && domain_info_version >= DOMAIN_LEVEL_1_11 {
            // 1.10 -> 1.11
            self.migrate_domain_1_10_to_1_11()?;
        }

        if previous_version <= DOMAIN_LEVEL_1_11 && domain_info_version >= DOMAIN_LEVEL_1_12 {
            // 1.11 -> 1.12
            self.migrate_domain_1_11_to_1_12()?;
        }

        if previous_version <= DOMAIN_LEVEL_1_12 && domain_info_version >= DOMAIN_LEVEL_1_13 {
            // 1.12 -> 1.13
            self.migrate_domain_1_12_to_1_13()?;
        }

        if previous_version <= DOMAIN_LEVEL_1_13 && domain_info_version >= DOMAIN_LEVEL_1_14 {
            // 1.13 -> 1.14
            self.migrate_domain_1_13_to_1_14()?;
        }

        // This is here to catch when we increase domain levels but didn't create the migration
        // hooks. If this fails it probably means you need to add another migration hook
        // in the above.
        const { assert!(DOMAIN_MAX_LEVEL == DOMAIN_LEVEL_1_14) };
        debug_assert!(domain_info_version <= DOMAIN_MAX_LEVEL);

        Ok(())
    }

    /// Pulls the domain name from the database and updates the DomainInfo data in memory
    #[instrument(level = "debug", skip_all)]
    pub(crate) fn reload_domain_info(&mut self) -> Result<(), OperationError> {
        let domain_entry = self.get_db_domain()?;

        let domain_name = domain_entry
            .get_ava_single_iname(Attribute::DomainName)
            .map(str::to_string)
            .ok_or(OperationError::InvalidEntryState)?;

        let display_name = domain_entry
            .get_ava_single_utf8(Attribute::DomainDisplayName)
            .map(str::to_string)
            .unwrap_or_else(|| format!("Kanidm {domain_name}"));

        let domain_ldap_allow_unix_pw_bind = domain_entry
            .get_ava_single_bool(Attribute::LdapAllowUnixPwBind)
            .unwrap_or(true);

        let domain_image = domain_entry.get_ava_single_image(Attribute::Image);

        let domain_uuid = self.be_txn.get_db_d_uuid()?;

        let mut_d_info = self.d_info.get_mut();
        mut_d_info.d_ldap_allow_unix_pw_bind = domain_ldap_allow_unix_pw_bind;
        if mut_d_info.d_uuid != domain_uuid {
            admin_warn!(
                "Using domain uuid from the database {} - was {} in memory",
                domain_name,
                mut_d_info.d_name,
            );
            mut_d_info.d_uuid = domain_uuid;
        }
        if mut_d_info.d_name != domain_name {
            admin_warn!(
                "Using domain name from the database {} - was {} in memory",
                domain_name,
                mut_d_info.d_name,
            );
            admin_warn!(
                    "If you think this is an error, see https://kanidm.github.io/kanidm/master/domain_rename.html"
                );
            mut_d_info.d_name = domain_name;
        }
        mut_d_info.d_display = display_name;
        mut_d_info.d_image = domain_image;
        Ok(())
    }

    /// Reloads feature configurations if they have changed in this operation
    #[instrument(level = "debug", skip_all)]
    pub(crate) fn reload_feature_config(&mut self) -> Result<(), OperationError> {
        let filt = filter!(f_eq(Attribute::Class, EntryClass::Feature.into()));

        let feature_configs = self.internal_search(filt).inspect_err(|err| {
            error!(?err, "reload feature configuration internal search failed",)
        })?;

        let current_time = self.get_curtime();
        let domain_level = self.get_domain_version();

        let mut hmac_name_history_fixup = false;

        // TODO: How to handle disabling on a delete? Needs thought ... but also
        // should be impossible for someone TO delete a feature config entry?

        for feature_entry in feature_configs {
            match feature_entry.get_uuid() {
                UUID_HMAC_NAME_FEATURE => {
                    if domain_level < DOMAIN_LEVEL_12 {
                        trace!("Skipping hmac name history config");
                        continue;
                    }

                    let key_object = self
                        .get_key_providers()
                        .get_key_object_handle(UUID_HMAC_NAME_FEATURE)
                        .ok_or(OperationError::KP0079KeyObjectNotFound)?;

                    let mut key = HmacSha256Key::default();
                    key_object.hkdf_s256_expand(
                        UUID_HMAC_NAME_FEATURE.as_bytes(),
                        key.as_mut_slice(),
                        current_time,
                    )?;

                    drop(key_object);

                    let new_feature_enabled_state = feature_entry
                        .get_ava_single_bool(Attribute::Enabled)
                        .unwrap_or_default();

                    let feature_config_txn = &mut self.d_info.get_mut().feature_config;

                    hmac_name_history_fixup =
                        !feature_config_txn.hmac_name_history.enabled && new_feature_enabled_state;

                    feature_config_txn.hmac_name_history.enabled = new_feature_enabled_state;

                    std::mem::swap(&mut key, &mut feature_config_txn.hmac_name_history.key);
                }

                UUID_ACCOUNT_SIGNUP_FEATURE => {
                    if domain_level < DOMAIN_LEVEL_1_12 {
                        trace!("Skipping account signup config");
                        continue;
                    }

                    let new_feature_enabled_state = feature_entry
                        .get_ava_single_bool(Attribute::Enabled)
                        .unwrap_or_default();

                    let feature_config_txn = &mut self.d_info.get_mut().feature_config;

                    feature_config_txn.account_signup.enabled = new_feature_enabled_state;

                    // Probably will add flags here soon?
                }
                feature_uuid => {
                    error!(
                        ?feature_uuid,
                        "Unrecognised feature uuid, unable to proceed"
                    );
                    return Err(OperationError::KG004UnknownFeatureUuid);
                }
            }
        }

        if hmac_name_history_fixup {
            plugins::hmac_name_unique::HmacNameUnique::fixup(self)?;
        }

        Ok(())
    }

    /// Initiate a domain display name change process. This isn't particularly scary
    /// because it's just a wibbly human-facing thing, not used for secure
    /// activities (yet)
    pub fn set_domain_display_name(&mut self, new_domain_name: &str) -> Result<(), OperationError> {
        let modl = ModifyList::new_purge_and_set(
            Attribute::DomainDisplayName,
            Value::new_utf8(new_domain_name.to_string()),
        );
        let udi = PVUUID_DOMAIN_INFO.clone();
        let filt = filter_all!(f_eq(Attribute::Uuid, udi));
        self.internal_modify(&filt, &modl)
    }

    /// Initiate a domain rename process. This is generally an internal function but it's
    /// exposed to the cli for admins to be able to initiate the process.
    ///
    /// # Safety
    /// This is UNSAFE because while it may change the domain name, it doesn't update
    /// the running configured version of the domain name that is resident to the
    /// query server.
    ///
    /// Currently it's only used to test what happens if we rename the domain and how
    /// that impacts spns, but in the future we may need to reconsider how this is
    /// approached, especially if we have a domain re-name replicated to us. It could
    /// be that we end up needing to have this as a cow cell or similar?
    pub fn danger_domain_rename(&mut self, new_domain_name: &str) -> Result<(), OperationError> {
        let modl =
            ModifyList::new_purge_and_set(Attribute::DomainName, Value::new_iname(new_domain_name));
        let udi = PVUUID_DOMAIN_INFO.clone();
        let filt = filter_all!(f_eq(Attribute::Uuid, udi));
        self.internal_modify(&filt, &modl)
    }

    pub fn reindex(&mut self, immediate: bool) -> Result<(), OperationError> {
        // initiate a be reindex here. This could have been from first run checking
        // the versions, or it could just be from the cli where an admin needs to do an
        // indexing.
        self.be_txn.reindex(immediate)
    }

    fn force_schema_reload(&mut self) {
        self.changed_flags.insert(ChangeFlag::SCHEMA);
    }

    fn force_domain_reload(&mut self) {
        self.changed_flags.insert(ChangeFlag::DOMAIN);
    }

    pub(crate) fn upgrade_reindex(&mut self, v: i64) -> Result<(), OperationError> {
        self.be_txn.upgrade_reindex(v)
    }

    #[inline]
    pub(crate) fn get_changed_app(&self) -> bool {
        self.changed_flags.contains(ChangeFlag::APPLICATION)
    }

    #[inline]
    pub(crate) fn get_changed_oauth2(&self) -> bool {
        self.changed_flags.contains(ChangeFlag::OAUTH2)
    }

    #[inline]
    pub(crate) fn clear_changed_oauth2(&mut self) {
        self.changed_flags.remove(ChangeFlag::OAUTH2)
    }

    #[inline]
    pub(crate) fn get_changed_oauth2_client(&self) -> bool {
        self.changed_flags.contains(ChangeFlag::OAUTH2_CLIENT)
    }

    /// Indicate that we are about to re-bootstrap this server. You should ONLY
    /// call this during a replication refresh!!!
    pub(crate) fn set_phase_bootstrap(&mut self) {
        *self.phase = ServerPhase::Bootstrap;
    }

    /// Raise the currently running server phase.
    pub(crate) fn set_phase(&mut self, phase: ServerPhase) {
        // Phase changes are one way
        if phase > *self.phase {
            *self.phase = phase
        }
    }

    pub(crate) fn get_phase(&mut self) -> ServerPhase {
        *self.phase
    }

    pub(crate) fn reload(&mut self) -> Result<(), OperationError> {
        // First, check if the domain version has changed. This can trigger
        // changes to schema, access controls and more.
        if self.changed_flags.intersects(ChangeFlag::DOMAIN) {
            self.reload_domain_info_version()?;
        }

        // This could be faster if we cache the set of classes changed
        // in an operation so we can check if we need to do the reload or not
        //
        // Reload the schema from qs.
        if self.changed_flags.intersects(ChangeFlag::SCHEMA) {
            self.reload_schema()?;

            // If the server is in a late phase of start up or is
            // operational, then a reindex may be required. After the reindex, the schema
            // must also be reloaded so that slope optimisation indexes are loaded correctly.
            if *self.phase >= ServerPhase::Running {
                self.reindex(false)?;
                self.reload_schema()?;
            }
        }

        // We need to reload cryptographic providers before anything else so that
        // sync agreements and the domain can access their key material.
        if self
            .changed_flags
            .intersects(ChangeFlag::SCHEMA | ChangeFlag::KEY_MATERIAL)
        {
            self.reload_key_material()?;
        }

        // Determine if we need to update access control profiles
        // based on any modifications that have occurred.
        // IF SCHEMA CHANGED WE MUST ALSO RELOAD!!! IE if schema had an attr removed
        // that we rely on we MUST fail this here!!
        //
        // Also note that changing sync agreements triggers an acp reload since
        // access controls need to be aware of these agreements.
        if self
            .changed_flags
            .intersects(ChangeFlag::SCHEMA | ChangeFlag::ACP | ChangeFlag::SYNC_AGREEMENT)
        {
            self.reload_accesscontrols()?;
        } else {
            // On a reload the cache is dropped, otherwise we tell accesscontrols
            // to drop anything related that was changed.
            // self.accesscontrols
            //    .invalidate_related_cache(self.changed_uuid.into_inner().as_slice())
        }

        if self.changed_flags.intersects(ChangeFlag::SYSTEM_CONFIG) {
            self.reload_system_config()?;
        }

        if self.changed_flags.intersects(ChangeFlag::DOMAIN) {
            self.reload_domain_info()?;
        }

        if self
            .changed_flags
            .intersects(ChangeFlag::FEATURE | ChangeFlag::KEY_MATERIAL)
        {
            self.reload_feature_config()?;
        }

        // Clear flags
        self.changed_flags.remove(
            ChangeFlag::DOMAIN
                | ChangeFlag::SCHEMA
                | ChangeFlag::FEATURE
                | ChangeFlag::SYSTEM_CONFIG
                | ChangeFlag::ACP
                | ChangeFlag::SYNC_AGREEMENT
                | ChangeFlag::KEY_MATERIAL,
        );

        Ok(())
    }

    #[cfg(any(test, debug_assertions))]
    #[instrument(level = "debug", skip_all)]
    pub fn clear_cache(&mut self) -> Result<(), OperationError> {
        self.be_txn.clear_cache()
    }

    #[instrument(level = "debug", name="qswt_commit" skip_all)]
    pub fn commit(mut self) -> Result<(), OperationError> {
        self.reload()?;

        // Now destructure the transaction ready to reset it.
        let QueryServerWriteTransaction {
            committed,
            phase,
            d_info,
            system_config,
            mut be_txn,
            schema,
            accesscontrols,
            cid,
            dyngroup_cache,
            key_providers,
            // Hold these for a bit more ...
            _db_ticket,
            _write_ticket,
            // Ignore values that don't need a commit.
            curtime: _,
            trim_cid: _,
            changed_flags,
            changed_uuid: _,
            resolve_filter_cache: _,
            resolve_filter_cache_clear,
            mut resolve_filter_cache_write,
            txn_name_to_uuid: _,
        } = self;
        debug_assert!(!committed);

        // Should have been cleared by any reloads.
        trace!(
            changed = ?changed_flags.iter_names().collect::<Vec<_>>(),
        );

        // Write the cid to the db. If this fails, we can't assume replication
        // will be stable, so return if it fails.
        be_txn.set_db_ts_max(cid.ts)?;
        cid.commit();

        // We don't care if this passes/fails, committing this is fine.
        if resolve_filter_cache_clear {
            resolve_filter_cache_write.clear();
        }
        resolve_filter_cache_write.commit();

        // Point of no return - everything has been validated and reloaded.
        //
        // = Lets commit =
        schema
            .commit()
            .map(|_| d_info.commit())
            .map(|_| system_config.commit())
            .map(|_| phase.commit())
            .map(|_| dyngroup_cache.commit())
            .and_then(|_| key_providers.commit())
            .and_then(|_| accesscontrols.commit())
            .and_then(|_| be_txn.commit())
    }

    pub(crate) fn get_txn_cid(&self) -> &Cid {
        &self.cid
    }
}

#[cfg(test)]
mod tests {
    use crate::prelude::*;
    use kanidm_proto::scim_v1::{
        server::{ScimListResponse, ScimReference},
        JsonValue, ScimEntryGetQuery, ScimFilter,
    };
    use std::num::NonZeroU64;

    #[qs_test]
    async fn test_name_to_uuid(server: &QueryServer) {
        let mut server_txn = server.write(duration_from_epoch_now()).await.unwrap();

        let t_uuid = Uuid::new_v4();
        assert!(server_txn
            .internal_create(vec![entry_init!(
                (Attribute::Class, EntryClass::Object.to_value()),
                (Attribute::Class, EntryClass::Account.to_value()),
                (Attribute::Class, EntryClass::Person.to_value()),
                (Attribute::Name, Value::new_iname("testperson1")),
                (Attribute::Uuid, Value::Uuid(t_uuid)),
                (Attribute::Description, Value::new_utf8s("testperson1")),
                (Attribute::DisplayName, Value::new_utf8s("testperson1"))
            ),])
            .is_ok());

        // Name doesn't exist
        let r1 = server_txn.name_to_uuid("testpers");
        assert!(r1.is_err());
        // Name doesn't exist (not syntax normalised)
        let r2 = server_txn.name_to_uuid("tEsTpErS");
        assert!(r2.is_err());
        // Name does exist
        let r3 = server_txn.name_to_uuid("testperson1");
        assert_eq!(r3, Ok(t_uuid));
        // Name is not syntax normalised (but exists)
        let r4 = server_txn.name_to_uuid("tEsTpErSoN1");
        assert_eq!(r4, Ok(t_uuid));
        // Name is an rdn
        let r5 = server_txn.name_to_uuid("name=testperson1");
        assert_eq!(r5, Ok(t_uuid));
        // Name is a dn
        let r6 = server_txn.name_to_uuid("name=testperson1,o=example");
        assert_eq!(r6, Ok(t_uuid));
    }

    #[qs_test]
    async fn test_external_id_to_uuid(server: &QueryServer) {
        let mut server_txn = server.write(duration_from_epoch_now()).await.unwrap();

        let t_uuid = Uuid::new_v4();
        assert!(server_txn
            .internal_create(vec![entry_init!(
                (Attribute::Class, EntryClass::Object.to_value()),
                (Attribute::Class, EntryClass::ExtensibleObject.to_value()),
                (Attribute::Uuid, Value::Uuid(t_uuid)),
                (
                    Attribute::SyncExternalId,
                    Value::new_iutf8("uid=testperson")
                )
            ),])
            .is_ok());

        // Name doesn't exist
        let r1 = server_txn.sync_external_id_to_uuid("tobias");
        assert_eq!(r1, Ok(None));
        // Name doesn't exist (not syntax normalised)
        let r2 = server_txn.sync_external_id_to_uuid("tObIAs");
        assert_eq!(r2, Ok(None));
        // Name does exist
        let r3 = server_txn.sync_external_id_to_uuid("uid=testperson");
        assert_eq!(r3, Ok(Some(t_uuid)));
        // Name is not syntax normalised (but exists)
        let r4 = server_txn.sync_external_id_to_uuid("uId=TeStPeRsOn");
        assert_eq!(r4, Ok(Some(t_uuid)));
    }

    #[qs_test]
    async fn test_uuid_to_spn(server: &QueryServer) {
        let mut server_txn = server.write(duration_from_epoch_now()).await.unwrap();

        let e1 = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Person.to_value()),
            (Attribute::Class, EntryClass::Account.to_value()),
            (Attribute::Name, Value::new_iname("testperson1")),
            (
                Attribute::Uuid,
                Value::Uuid(uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"))
            ),
            (Attribute::Description, Value::new_utf8s("testperson1")),
            (Attribute::DisplayName, Value::new_utf8s("testperson1"))
        );
        let ce = CreateEvent::new_internal(vec![e1]);
        let cr = server_txn.create(&ce);
        assert!(cr.is_ok());

        // Name doesn't exist
        let r1 = server_txn.uuid_to_spn(uuid!("bae3f507-e6c3-44ba-ad01-f8ff1083534a"));
        // There is nothing.
        assert_eq!(r1, Ok(None));
        // Name does exist
        let r3 = server_txn.uuid_to_spn(uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"));
        println!("{r3:?}");
        assert_eq!(
            r3.unwrap().unwrap(),
            Value::new_spn_str("testperson1", "example.com")
        );
        // Name is not syntax normalised (but exists)
        let r4 = server_txn.uuid_to_spn(uuid!("CC8E95B4-C24F-4D68-BA54-8BED76F63930"));
        assert_eq!(
            r4.unwrap().unwrap(),
            Value::new_spn_str("testperson1", "example.com")
        );
    }

    #[qs_test]
    async fn test_uuid_to_rdn(server: &QueryServer) {
        let mut server_txn = server.write(duration_from_epoch_now()).await.unwrap();

        let e1 = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Person.to_value()),
            (Attribute::Class, EntryClass::Account.to_value()),
            (Attribute::Name, Value::new_iname("testperson1")),
            (
                Attribute::Uuid,
                Value::Uuid(uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"))
            ),
            (Attribute::Description, Value::new_utf8s("testperson")),
            (Attribute::DisplayName, Value::new_utf8s("testperson1"))
        );
        let ce = CreateEvent::new_internal(vec![e1]);
        let cr = server_txn.create(&ce);
        assert!(cr.is_ok());

        // Name doesn't exist
        let r1 = server_txn.uuid_to_rdn(uuid!("bae3f507-e6c3-44ba-ad01-f8ff1083534a"));
        // There is nothing.
        assert_eq!(r1.unwrap(), "uuid=bae3f507-e6c3-44ba-ad01-f8ff1083534a");
        // Name does exist
        let r3 = server_txn.uuid_to_rdn(uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"));
        println!("{r3:?}");
        assert_eq!(r3.unwrap(), "spn=testperson1@example.com");
        // Uuid is not syntax normalised (but exists)
        let r4 = server_txn.uuid_to_rdn(uuid!("CC8E95B4-C24F-4D68-BA54-8BED76F63930"));
        assert_eq!(r4.unwrap(), "spn=testperson1@example.com");
    }

    #[qs_test]
    async fn test_clone_value(server: &QueryServer) {
        let mut server_txn = server.write(duration_from_epoch_now()).await.unwrap();
        let e1 = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Account.to_value()),
            (Attribute::Class, EntryClass::Person.to_value()),
            (Attribute::Name, Value::new_iname("testperson1")),
            (
                Attribute::Uuid,
                Value::Uuid(uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"))
            ),
            (Attribute::Description, Value::new_utf8s("testperson1")),
            (Attribute::DisplayName, Value::new_utf8s("testperson1"))
        );
        let ce = CreateEvent::new_internal(vec![e1]);
        let cr = server_txn.create(&ce);
        assert!(cr.is_ok());

        // test attr not exist
        let r1 = server_txn.clone_value(&Attribute::from("tausau"), "naoeutnhaou");

        assert!(r1.is_err());

        // test attr not-normalised (error)
        // test attr not-reference
        let r2 = server_txn.clone_value(&Attribute::Custom("NaMe".into()), "NaMe");

        assert!(r2.is_err());

        // test attr reference
        let r3 = server_txn.clone_value(&Attribute::from("member"), "testperson1");

        assert_eq!(
            r3,
            Ok(Value::ReferN(uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930")))
        );

        // test attr reference already resolved.
        let r4 = server_txn.clone_value(
            &Attribute::from("member"),
            "cc8e95b4-c24f-4d68-ba54-8bed76f63930",
        );

        debug!("{:?}", r4);
        assert_eq!(
            r4,
            Ok(Value::ReferN(uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930")))
        );
    }

    #[qs_test(domain_level=DOMAIN_LEVEL_13)]
    async fn test_dynamic_schema_class(server: &QueryServer) {
        let e1 = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::TestClass.to_value()),
            (Attribute::Name, Value::new_iname("testobj1")),
            (
                Attribute::Uuid,
                Value::Uuid(uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"))
            )
        );

        // Class definition
        let e_cd = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::ClassType.to_value()),
            (
                Attribute::ClassName,
                Value::new_iutf8(EntryClass::TestClass.as_str())
            ),
            (
                Attribute::Uuid,
                Value::Uuid(uuid!("cfcae205-31c3-484b-8ced-667d1709c5e3"))
            ),
            (Attribute::Description, Value::new_utf8s("Test Class")),
            (Attribute::May, Value::new_iutf8n(Attribute::Name.as_str()))
        );
        let mut server_txn = server.write(duration_from_epoch_now()).await.unwrap();
        // Add a new class.
        let ce_class = CreateEvent::new_internal(vec![e_cd.clone()]);
        assert!(server_txn.create(&ce_class).is_ok());
        // Trying to add it now should fail.
        let ce_fail = CreateEvent::new_internal(vec![e1.clone()]);
        assert!(server_txn.create(&ce_fail).is_err());

        // Commit
        server_txn.commit().expect("should not fail");

        // Start a new write
        let mut server_txn = server.write(duration_from_epoch_now()).await.unwrap();
        // Add the class to an object
        // should work
        let ce_work = CreateEvent::new_internal(vec![e1.clone()]);
        assert!(server_txn.create(&ce_work).is_ok());

        // Commit
        server_txn.commit().expect("should not fail");

        // Start a new write
        let mut server_txn = server.write(duration_from_epoch_now()).await.unwrap();
        // delete the class
        let de_class = DeleteEvent::new_internal_invalid(filter!(f_eq(
            Attribute::ClassName,
            EntryClass::TestClass.into()
        )));
        assert!(server_txn.delete(&de_class).is_ok());
        // Commit
        server_txn.commit().expect("should not fail");

        // Start a new write
        let mut server_txn = server.write(duration_from_epoch_now()).await.unwrap();
        // Trying to add now should fail
        let ce_fail = CreateEvent::new_internal(vec![e1.clone()]);
        assert!(server_txn.create(&ce_fail).is_err());
        // Search our entry
        let testobj1 = server_txn
            .internal_search_uuid(uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"))
            .expect("failed");
        assert!(testobj1.attribute_equality(Attribute::Class, &EntryClass::TestClass.into()));

        // Should still be good
        server_txn.commit().expect("should not fail");
        // Commit.
    }

    #[qs_test(domain_level=DOMAIN_LEVEL_13)]
    async fn test_dynamic_schema_attr(server: &QueryServer) {
        let e1 = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::ExtensibleObject.to_value()),
            (Attribute::Name, Value::new_iname("testobj1")),
            (
                Attribute::Uuid,
                Value::Uuid(uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"))
            ),
            (Attribute::TestAttr, Value::new_utf8s("test"))
        );

        // Attribute definition
        let e_ad = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::AttributeType.to_value()),
            (
                Attribute::Uuid,
                Value::Uuid(uuid!("cfcae205-31c3-484b-8ced-667d1709c5e3"))
            ),
            (
                Attribute::AttributeName,
                Value::new_iutf8(Attribute::TestAttr.as_str())
            ),
            (Attribute::Description, Value::new_utf8s("Test Attribute")),
            (Attribute::MultiValue, Value::new_bool(false)),
            (Attribute::Unique, Value::new_bool(false)),
            (
                Attribute::Syntax,
                Value::new_syntaxs("UTF8STRING").expect("syntax")
            )
        );

        let mut server_txn = server.write(duration_from_epoch_now()).await.unwrap();
        // Add a new attribute.
        let ce_attr = CreateEvent::new_internal(vec![e_ad.clone()]);
        assert!(server_txn.create(&ce_attr).is_ok());
        // Trying to add it now should fail. (use extensible object)
        let ce_fail = CreateEvent::new_internal(vec![e1.clone()]);
        assert!(server_txn.create(&ce_fail).is_err());

        // Commit
        server_txn.commit().expect("should not fail");

        // Start a new write
        let mut server_txn = server.write(duration_from_epoch_now()).await.unwrap();
        // Add the attr to an object
        // should work
        let ce_work = CreateEvent::new_internal(vec![e1.clone()]);
        assert!(server_txn.create(&ce_work).is_ok());

        // Commit
        server_txn.commit().expect("should not fail");

        // Start a new write
        let mut server_txn = server.write(duration_from_epoch_now()).await.unwrap();
        // delete the attr
        let de_attr = DeleteEvent::new_internal_invalid(filter!(f_eq(
            Attribute::AttributeName,
            PartialValue::from(Attribute::TestAttr)
        )));
        assert!(server_txn.delete(&de_attr).is_ok());
        // Commit
        server_txn.commit().expect("should not fail");

        // Start a new write
        let mut server_txn = server.write(duration_from_epoch_now()).await.unwrap();
        // Trying to add now should fail
        let ce_fail = CreateEvent::new_internal(vec![e1.clone()]);
        assert!(server_txn.create(&ce_fail).is_err());
        // Search our attribute - should FAIL
        let filt = filter!(f_eq(Attribute::TestAttr, PartialValue::new_utf8s("test")));
        assert!(server_txn.internal_search(filt).is_err());
        // Search the entry - the attribute will still be present
        // even if we can't search on it.
        let testobj1 = server_txn
            .internal_search_uuid(uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"))
            .expect("failed");
        assert!(testobj1.attribute_equality(Attribute::TestAttr, &PartialValue::new_utf8s("test")));

        server_txn.commit().expect("should not fail");
        // Commit.
    }

    #[qs_test]
    async fn test_scim_entry_structure(server: &QueryServer) {
        let mut read_txn = server.read().await.unwrap();

        // Query entry (A builtin one ?)
        let entry = read_txn
            .internal_search_uuid(UUID_IDM_PEOPLE_SELF_NAME_WRITE)
            .unwrap();

        // Convert entry into scim
        let reduced = entry.as_ref().clone().into_reduced();
        let scim_entry = reduced.to_scim_kanidm(&mut read_txn).unwrap();

        // Assert scim entry attributes are as expected
        assert_eq!(scim_entry.header.id, UUID_IDM_PEOPLE_SELF_NAME_WRITE);
        let name_scim = scim_entry.attrs.get(&Attribute::Name).unwrap();
        match name_scim {
            ScimValueKanidm::String(name) => {
                assert_eq!(name.clone(), "idm_people_self_name_write")
            }
            _ => {
                panic!("expected String, actual {name_scim:?}");
            }
        }

        // such as returning a new struct type for `members` attributes or `managed_by`
        let entry_managed_by_scim = scim_entry.attrs.get(&Attribute::EntryManagedBy).unwrap();
        match entry_managed_by_scim {
            ScimValueKanidm::EntryReference(managed_by) => {
                assert_eq!(
                    managed_by.clone(),
                    ScimReference {
                        uuid: UUID_IDM_ADMINS,
                        value: "idm_admins@example.com".to_string()
                    }
                )
            }
            _ => {
                panic!("expected EntryReference, actual {entry_managed_by_scim:?}");
            }
        }

        let members_scim = scim_entry.attrs.get(&Attribute::Member).unwrap();
        match members_scim {
            ScimValueKanidm::EntryReferences(members) => {
                assert_eq!(
                    members.first().unwrap().clone(),
                    ScimReference {
                        uuid: UUID_IDM_ALL_PERSONS,
                        value: "idm_all_persons@example.com".to_string()
                    }
                )
            }
            _ => {
                panic!("expected EntryReferences, actual {members_scim:?}");
            }
        }
    }

    #[qs_test]
    async fn test_scim_effective_access_query(server: &QueryServer) {
        let mut server_txn = server.write(duration_from_epoch_now()).await.unwrap();

        let group_uuid = Uuid::new_v4();
        let e1 = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Group.to_value()),
            (Attribute::Name, Value::new_iname("testgroup")),
            (Attribute::Uuid, Value::Uuid(group_uuid))
        );

        assert!(server_txn.internal_create(vec![e1]).is_ok());
        assert!(server_txn.commit().is_ok());

        // Now read that entry.

        let mut server_txn = server.read().await.unwrap();

        let idm_admin_entry = server_txn.internal_search_uuid(UUID_IDM_ADMIN).unwrap();
        let idm_admin_ident = Identity::from_impersonate_entry_readwrite(idm_admin_entry);

        let query = ScimEntryGetQuery {
            ext_access_check: true,
            ..Default::default()
        };

        let scim_entry = server_txn
            .scim_entry_id_get_ext(group_uuid, EntryClass::Group, query, idm_admin_ident)
            .unwrap();

        let ext_access_check = scim_entry.ext_access_check.unwrap();

        trace!(?ext_access_check);

        assert!(ext_access_check.delete);
        assert!(ext_access_check.search.check(&Attribute::DirectMemberOf));
        assert!(ext_access_check.search.check(&Attribute::MemberOf));
        assert!(ext_access_check.search.check(&Attribute::Name));
        assert!(ext_access_check.modify_present.check(&Attribute::Name));
        assert!(ext_access_check.modify_remove.check(&Attribute::Name));
    }

    #[qs_test]
    async fn test_scim_basic_search_ext_query(server: &QueryServer) {
        let mut server_txn = server.write(duration_from_epoch_now()).await.unwrap();

        let group_uuid = Uuid::new_v4();
        let e1 = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Group.to_value()),
            (Attribute::Name, Value::new_iname("testgroup")),
            (Attribute::Uuid, Value::Uuid(group_uuid))
        );

        assert!(server_txn.internal_create(vec![e1]).is_ok());
        assert!(server_txn.commit().is_ok());

        // Now read that entry.
        let mut server_txn = server.read().await.unwrap();

        let idm_admin_entry = server_txn.internal_search_uuid(UUID_IDM_ADMIN).unwrap();
        let idm_admin_ident = Identity::from_impersonate_entry_readwrite(idm_admin_entry);

        let filter = ScimFilter::And(
            Box::new(ScimFilter::Equal(
                Attribute::Class.into(),
                EntryClass::Group.into(),
            )),
            Box::new(ScimFilter::Equal(
                Attribute::Uuid.into(),
                JsonValue::String(group_uuid.to_string()),
            )),
        );

        let base: ScimListResponse = server_txn
            .scim_search_ext(idm_admin_ident, filter, ScimEntryGetQuery::default())
            .unwrap();

        assert_eq!(base.resources.len(), 1);
        assert_eq!(base.total_results, 1);
        // Pagination not requested,
        assert_eq!(base.items_per_page, None);
        assert_eq!(base.start_index, None);
        assert_eq!(base.resources[0].header.id, group_uuid);
    }

    #[qs_test]
    async fn test_scim_basic_search_ext_query_with_sort(server: &QueryServer) {
        let mut server_txn = server.write(duration_from_epoch_now()).await.unwrap();

        for i in (1..4).rev() {
            let e1 = entry_init!(
                (Attribute::Class, EntryClass::Object.to_value()),
                (Attribute::Class, EntryClass::Group.to_value()),
                (
                    Attribute::Name,
                    Value::new_iname(format!("testgroup{i}").as_str())
                )
            );
            assert!(server_txn.internal_create(vec![e1]).is_ok());
        }

        assert!(server_txn.commit().is_ok());

        // Now read that entry.
        let mut server_txn = server.read().await.unwrap();

        let idm_admin_entry = server_txn.internal_search_uuid(UUID_IDM_ADMIN).unwrap();
        let idm_admin_ident = Identity::from_impersonate_entry_readwrite(idm_admin_entry);

        let filter = ScimFilter::And(
            Box::new(ScimFilter::Equal(
                Attribute::Class.into(),
                EntryClass::Group.into(),
            )),
            Box::new(ScimFilter::StartsWith(
                Attribute::Name.into(),
                JsonValue::String("testgroup".into()),
            )),
        );

        let base: ScimListResponse = server_txn
            .scim_search_ext(
                idm_admin_ident.clone(),
                filter.clone(),
                ScimEntryGetQuery {
                    sort_by: Some(Attribute::Name),
                    ..Default::default()
                },
            )
            .unwrap();

        assert_eq!(base.resources.len(), 3);
        assert_eq!(base.total_results, 3);
        // Pagination not requested,
        assert_eq!(base.items_per_page, None);
        assert_eq!(base.start_index, None);

        let Some(ScimValueKanidm::String(testgroup_name_0)) =
            base.resources[0].attrs.get(&Attribute::Name)
        else {
            panic!("Invalid data in attribute.");
        };
        let Some(ScimValueKanidm::String(testgroup_name_1)) =
            base.resources[1].attrs.get(&Attribute::Name)
        else {
            panic!("Invalid data in attribute.");
        };
        let Some(ScimValueKanidm::String(testgroup_name_2)) =
            base.resources[2].attrs.get(&Attribute::Name)
        else {
            panic!("Invalid data in attribute.");
        };

        assert!(testgroup_name_0 < testgroup_name_1);
        assert!(testgroup_name_0 < testgroup_name_2);
        assert!(testgroup_name_1 < testgroup_name_2);

        // ================
        // Test pagination.
        let base: ScimListResponse = server_txn
            .scim_search_ext(
                idm_admin_ident.clone(),
                filter.clone(),
                ScimEntryGetQuery {
                    count: NonZeroU64::new(1),
                    ..Default::default()
                },
            )
            .unwrap();

        assert_eq!(base.resources.len(), 1);
        assert_eq!(base.total_results, 3);
        // Pagination not requested,
        assert_eq!(base.items_per_page, NonZeroU64::new(1));
        assert_eq!(base.start_index, NonZeroU64::new(1));

        let Some(ScimValueKanidm::String(testgroup_name_0)) =
            base.resources[0].attrs.get(&Attribute::Name)
        else {
            panic!("Invalid data in attribute.");
        };
        // DB has reverse order
        assert_eq!(testgroup_name_0, "testgroup3");

        // ================
        // Test pagination + sort
        let base: ScimListResponse = server_txn
            .scim_search_ext(
                idm_admin_ident,
                filter.clone(),
                ScimEntryGetQuery {
                    sort_by: Some(Attribute::Name),
                    count: NonZeroU64::new(2),
                    start_index: NonZeroU64::new(2),
                    ..Default::default()
                },
            )
            .unwrap();

        assert_eq!(base.resources.len(), 2);
        assert_eq!(base.total_results, 3);
        assert_eq!(base.items_per_page, NonZeroU64::new(2));
        assert_eq!(base.start_index, NonZeroU64::new(2));

        let Some(ScimValueKanidm::String(testgroup_name_0)) =
            base.resources[0].attrs.get(&Attribute::Name)
        else {
            panic!("Invalid data in attribute.");
        };
        let Some(ScimValueKanidm::String(testgroup_name_1)) =
            base.resources[1].attrs.get(&Attribute::Name)
        else {
            panic!("Invalid data in attribute.");
        };
        // Sorted, note we skipped entry "testgroup 1" using pagination.
        assert_eq!(testgroup_name_0, "testgroup2");
        assert_eq!(testgroup_name_1, "testgroup3");
    }
}
