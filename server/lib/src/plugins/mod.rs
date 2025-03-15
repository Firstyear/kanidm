//! Plugins allow an `Event` to be inspected and transformed during the write
//! paths of the server. This allows richer expression of some concepts and
//! helps to ensure that data is always in specific known states within the
//! `QueryServer`

use std::collections::BTreeSet;
use std::sync::Arc;

use crate::entry::{Entry, EntryCommitted, EntryInvalid, EntryNew, EntrySealed};
use crate::event::{CreateEvent, DeleteEvent, ModifyEvent};
use crate::prelude::*;

mod attrunique;
mod base;
mod cred_import;
mod default_values;
mod domain;
pub(crate) mod dyngroup;
mod eckeygen;
pub(crate) mod gidnumber;
mod jwskeygen;
mod keyobject;
mod memberof;
mod namehistory;
mod refint;
mod session;
mod spn;
mod valuedeny;

trait Plugin {
    fn id() -> &'static str;

    fn pre_create_transform(
        _qs: &mut QueryServerWriteTransaction,
        _cand: &mut Vec<EntryInvalidNew>,
        _ce: &CreateEvent,
    ) -> Result<(), OperationError> {
        admin_error!(
            "plugin {} has an unimplemented pre_create_transform!",
            Self::id()
        );
        debug_assert!(false);
        Err(OperationError::InvalidState)
    }

    #[allow(dead_code)]
    fn pre_create(
        _qs: &mut QueryServerWriteTransaction,
        // List of what we will commit that is valid?
        _cand: &[EntrySealedNew],
        _ce: &CreateEvent,
    ) -> Result<(), OperationError> {
        admin_error!("plugin {} has an unimplemented pre_create!", Self::id());
        debug_assert!(false);
        Err(OperationError::InvalidState)
    }

    fn post_create(
        _qs: &mut QueryServerWriteTransaction,
        // List of what we committed that was valid?
        _cand: &[EntrySealedCommitted],
        _ce: &CreateEvent,
    ) -> Result<(), OperationError> {
        admin_error!("plugin {} has an unimplemented post_create!", Self::id());
        debug_assert!(false);
        Err(OperationError::InvalidState)
    }

    fn pre_modify(
        _qs: &mut QueryServerWriteTransaction,
        _pre_cand: &[Arc<EntrySealedCommitted>],
        _cand: &mut Vec<EntryInvalidCommitted>,
        _me: &ModifyEvent,
    ) -> Result<(), OperationError> {
        admin_error!("plugin {} has an unimplemented pre_modify!", Self::id());
        debug_assert!(false);
        Err(OperationError::InvalidState)
    }

    fn post_modify(
        _qs: &mut QueryServerWriteTransaction,
        // List of what we modified that was valid?
        _pre_cand: &[Arc<EntrySealedCommitted>],
        _cand: &[EntrySealedCommitted],
        _ce: &ModifyEvent,
    ) -> Result<(), OperationError> {
        admin_error!("plugin {} has an unimplemented post_modify!", Self::id());
        debug_assert!(false);
        Err(OperationError::InvalidState)
    }

    fn pre_batch_modify(
        _qs: &mut QueryServerWriteTransaction,
        _pre_cand: &[Arc<EntrySealedCommitted>],
        _cand: &mut Vec<EntryInvalidCommitted>,
        _me: &BatchModifyEvent,
    ) -> Result<(), OperationError> {
        admin_error!(
            "plugin {} has an unimplemented pre_batch_modify!",
            Self::id()
        );
        debug_assert!(false);
        Err(OperationError::InvalidState)
    }

    fn post_batch_modify(
        _qs: &mut QueryServerWriteTransaction,
        // List of what we modified that was valid?
        _pre_cand: &[Arc<EntrySealedCommitted>],
        _cand: &[EntrySealedCommitted],
        _me: &BatchModifyEvent,
    ) -> Result<(), OperationError> {
        admin_error!(
            "plugin {} has an unimplemented post_batch_modify!",
            Self::id()
        );
        debug_assert!(false);
        Err(OperationError::InvalidState)
    }

    fn pre_delete(
        _qs: &mut QueryServerWriteTransaction,
        _cand: &mut Vec<EntryInvalidCommitted>,
        _de: &DeleteEvent,
    ) -> Result<(), OperationError> {
        admin_error!("plugin {} has an unimplemented pre_delete!", Self::id());
        debug_assert!(false);
        Err(OperationError::InvalidState)
    }

    fn post_delete(
        _qs: &mut QueryServerWriteTransaction,
        // List of what we delete that was valid?
        _cand: &[EntrySealedCommitted],
        _ce: &DeleteEvent,
    ) -> Result<(), OperationError> {
        admin_error!("plugin {} has an unimplemented post_delete!", Self::id());
        debug_assert!(false);
        Err(OperationError::InvalidState)
    }

    fn pre_repl_refresh(
        _qs: &mut QueryServerWriteTransaction,
        _cand: &[EntryRefreshNew],
    ) -> Result<(), OperationError> {
        admin_error!(
            "plugin {} has an unimplemented pre_repl_refresh!",
            Self::id()
        );
        debug_assert!(false);
        Err(OperationError::InvalidState)
    }

    fn post_repl_refresh(
        _qs: &mut QueryServerWriteTransaction,
        _cand: &[EntrySealedCommitted],
    ) -> Result<(), OperationError> {
        admin_error!(
            "plugin {} has an unimplemented post_repl_refresh!",
            Self::id()
        );
        debug_assert!(false);
        Err(OperationError::InvalidState)
    }

    // fn pre_repl_incremental(
    //     _qs: &mut QueryServerWriteTransaction,
    //     _cand: &mut [(EntryIncrementalCommitted, Arc<EntrySealedCommitted>)],
    // ) -> Result<(), OperationError> {
    //     admin_error!(
    //         "plugin {} has an unimplemented pre_repl_incremental!",
    //         Self::id()
    //     );
    //     debug_assert!(false);
    //     Err(OperationError::InvalidState)
    // }

    fn post_repl_incremental_conflict(
        _qs: &mut QueryServerWriteTransaction,
        _cand: &[(EntrySealedCommitted, Arc<EntrySealedCommitted>)],
        _conflict_uuids: &mut BTreeSet<Uuid>,
    ) -> Result<(), OperationError> {
        admin_error!(
            "plugin {} has an unimplemented post_repl_incremental_conflict!",
            Self::id()
        );
        debug_assert!(false);
        Err(OperationError::InvalidState)
    }

    fn post_repl_incremental(
        _qs: &mut QueryServerWriteTransaction,
        _pre_cand: &[Arc<EntrySealedCommitted>],
        _cand: &[EntrySealedCommitted],
        _conflict_uuids: &BTreeSet<Uuid>,
    ) -> Result<(), OperationError> {
        admin_error!(
            "plugin {} has an unimplemented post_repl_incremental!",
            Self::id()
        );
        debug_assert!(false);
        Err(OperationError::InvalidState)
    }

    fn verify(_qs: &mut QueryServerReadTransaction) -> Vec<Result<(), ConsistencyError>> {
        admin_error!("plugin {} has an unimplemented verify!", Self::id());
        vec![Err(ConsistencyError::Unknown)]
    }
}

pub struct Plugins {}

macro_rules! run_verify_plugin {
    (
        $qs:ident,
        $results:expr,
        $target_plugin:ty
    ) => {{
        let mut r = <$target_plugin>::verify($qs);
        $results.append(&mut r);
    }};
}

impl Plugins {
    #[instrument(level = "debug", name = "plugins::run_pre_create_transform", skip_all)]
    pub fn run_pre_create_transform(
        qs: &mut QueryServerWriteTransaction,
        cand: &mut Vec<Entry<EntryInvalid, EntryNew>>,
        ce: &CreateEvent,
    ) -> Result<(), OperationError> {
        base::Base::pre_create_transform(qs, cand, ce)?;
        valuedeny::ValueDeny::pre_create_transform(qs, cand, ce)?;
        cred_import::CredImport::pre_create_transform(qs, cand, ce)?;
        keyobject::KeyObjectManagement::pre_create_transform(qs, cand, ce)?;
        jwskeygen::JwsKeygen::pre_create_transform(qs, cand, ce)?;
        gidnumber::GidNumber::pre_create_transform(qs, cand, ce)?;
        domain::Domain::pre_create_transform(qs, cand, ce)?;
        spn::Spn::pre_create_transform(qs, cand, ce)?;
        default_values::DefaultValues::pre_create_transform(qs, cand, ce)?;
        namehistory::NameHistory::pre_create_transform(qs, cand, ce)?;
        eckeygen::EcdhKeyGen::pre_create_transform(qs, cand, ce)?;
        // Should always be last
        attrunique::AttrUnique::pre_create_transform(qs, cand, ce)
    }

    #[instrument(level = "trace", name = "plugins::run_pre_create", skip_all)]
    pub fn run_pre_create(
        _qs: &mut QueryServerWriteTransaction,
        _cand: &[Entry<EntrySealed, EntryNew>],
        _ce: &CreateEvent,
    ) -> Result<(), OperationError> {
        // protected::Protected::pre_create(qs, cand, ce)
        Ok(())
    }

    #[instrument(level = "debug", name = "plugins::run_post_create", skip_all)]
    pub fn run_post_create(
        qs: &mut QueryServerWriteTransaction,
        cand: &[Entry<EntrySealed, EntryCommitted>],
        ce: &CreateEvent,
    ) -> Result<(), OperationError> {
        refint::ReferentialIntegrity::post_create(qs, cand, ce)?;
        memberof::MemberOf::post_create(qs, cand, ce)
    }

    #[instrument(level = "debug", name = "plugins::run_pre_modify", skip_all)]
    pub fn run_pre_modify(
        qs: &mut QueryServerWriteTransaction,
        pre_cand: &[Arc<EntrySealedCommitted>],
        cand: &mut Vec<Entry<EntryInvalid, EntryCommitted>>,
        me: &ModifyEvent,
    ) -> Result<(), OperationError> {
        // protected::Protected::pre_modify(qs, pre_cand, cand, me)?;
        base::Base::pre_modify(qs, pre_cand, cand, me)?;
        valuedeny::ValueDeny::pre_modify(qs, pre_cand, cand, me)?;
        cred_import::CredImport::pre_modify(qs, pre_cand, cand, me)?;
        jwskeygen::JwsKeygen::pre_modify(qs, pre_cand, cand, me)?;
        keyobject::KeyObjectManagement::pre_modify(qs, pre_cand, cand, me)?;
        gidnumber::GidNumber::pre_modify(qs, pre_cand, cand, me)?;
        domain::Domain::pre_modify(qs, pre_cand, cand, me)?;
        spn::Spn::pre_modify(qs, pre_cand, cand, me)?;
        session::SessionConsistency::pre_modify(qs, pre_cand, cand, me)?;
        default_values::DefaultValues::pre_modify(qs, pre_cand, cand, me)?;
        namehistory::NameHistory::pre_modify(qs, pre_cand, cand, me)?;
        eckeygen::EcdhKeyGen::pre_modify(qs, pre_cand, cand, me)?;
        // attr unique should always be last
        attrunique::AttrUnique::pre_modify(qs, pre_cand, cand, me)
    }

    #[instrument(level = "debug", name = "plugins::run_post_modify", skip_all)]
    pub fn run_post_modify(
        qs: &mut QueryServerWriteTransaction,
        pre_cand: &[Arc<Entry<EntrySealed, EntryCommitted>>],
        cand: &[Entry<EntrySealed, EntryCommitted>],
        me: &ModifyEvent,
    ) -> Result<(), OperationError> {
        refint::ReferentialIntegrity::post_modify(qs, pre_cand, cand, me)?;
        spn::Spn::post_modify(qs, pre_cand, cand, me)?;
        memberof::MemberOf::post_modify(qs, pre_cand, cand, me)
    }

    #[instrument(level = "debug", name = "plugins::run_pre_batch_modify", skip_all)]
    pub fn run_pre_batch_modify(
        qs: &mut QueryServerWriteTransaction,
        pre_cand: &[Arc<EntrySealedCommitted>],
        cand: &mut Vec<Entry<EntryInvalid, EntryCommitted>>,
        me: &BatchModifyEvent,
    ) -> Result<(), OperationError> {
        // protected::Protected::pre_batch_modify(qs, pre_cand, cand, me)?;
        base::Base::pre_batch_modify(qs, pre_cand, cand, me)?;
        valuedeny::ValueDeny::pre_batch_modify(qs, pre_cand, cand, me)?;
        cred_import::CredImport::pre_batch_modify(qs, pre_cand, cand, me)?;
        jwskeygen::JwsKeygen::pre_batch_modify(qs, pre_cand, cand, me)?;
        keyobject::KeyObjectManagement::pre_batch_modify(qs, pre_cand, cand, me)?;
        gidnumber::GidNumber::pre_batch_modify(qs, pre_cand, cand, me)?;
        domain::Domain::pre_batch_modify(qs, pre_cand, cand, me)?;
        spn::Spn::pre_batch_modify(qs, pre_cand, cand, me)?;
        session::SessionConsistency::pre_batch_modify(qs, pre_cand, cand, me)?;
        default_values::DefaultValues::pre_batch_modify(qs, pre_cand, cand, me)?;
        namehistory::NameHistory::pre_batch_modify(qs, pre_cand, cand, me)?;
        eckeygen::EcdhKeyGen::pre_batch_modify(qs, pre_cand, cand, me)?;
        // attr unique should always be last
        attrunique::AttrUnique::pre_batch_modify(qs, pre_cand, cand, me)
    }

    #[instrument(level = "debug", name = "plugins::run_post_batch_modify", skip_all)]
    pub fn run_post_batch_modify(
        qs: &mut QueryServerWriteTransaction,
        pre_cand: &[Arc<Entry<EntrySealed, EntryCommitted>>],
        cand: &[Entry<EntrySealed, EntryCommitted>],
        me: &BatchModifyEvent,
    ) -> Result<(), OperationError> {
        refint::ReferentialIntegrity::post_batch_modify(qs, pre_cand, cand, me)?;
        spn::Spn::post_batch_modify(qs, pre_cand, cand, me)?;
        memberof::MemberOf::post_batch_modify(qs, pre_cand, cand, me)
    }

    #[instrument(level = "debug", name = "plugins::run_pre_delete", skip_all)]
    pub fn run_pre_delete(
        qs: &mut QueryServerWriteTransaction,
        cand: &mut Vec<Entry<EntryInvalid, EntryCommitted>>,
        de: &DeleteEvent,
    ) -> Result<(), OperationError> {
        // protected::Protected::pre_delete(qs, cand, de)?;
        memberof::MemberOf::pre_delete(qs, cand, de)
    }

    #[instrument(level = "debug", name = "plugins::run_post_delete", skip_all)]
    pub fn run_post_delete(
        qs: &mut QueryServerWriteTransaction,
        cand: &[Entry<EntrySealed, EntryCommitted>],
        de: &DeleteEvent,
    ) -> Result<(), OperationError> {
        refint::ReferentialIntegrity::post_delete(qs, cand, de)?;
        memberof::MemberOf::post_delete(qs, cand, de)
    }

    #[instrument(level = "debug", name = "plugins::run_pre_repl_refresh", skip_all)]
    pub fn run_pre_repl_refresh(
        qs: &mut QueryServerWriteTransaction,
        cand: &[EntryRefreshNew],
    ) -> Result<(), OperationError> {
        attrunique::AttrUnique::pre_repl_refresh(qs, cand)
    }

    #[instrument(level = "debug", name = "plugins::run_post_repl_refresh", skip_all)]
    pub fn run_post_repl_refresh(
        qs: &mut QueryServerWriteTransaction,
        cand: &[EntrySealedCommitted],
    ) -> Result<(), OperationError> {
        refint::ReferentialIntegrity::post_repl_refresh(qs, cand)?;
        memberof::MemberOf::post_repl_refresh(qs, cand)
    }

    #[instrument(level = "debug", name = "plugins::run_pre_repl_incremental", skip_all)]
    pub fn run_pre_repl_incremental(
        _qs: &mut QueryServerWriteTransaction,
        _cand: &mut [(EntryIncrementalCommitted, Arc<EntrySealedCommitted>)],
    ) -> Result<(), OperationError> {
        // Cleanup sessions on incoming replication? May not actually
        // be needed since each node will be session checking and replicating
        // those cleanups as needed.
        // session::SessionConsistency::pre_repl_incremental(qs, cand)?;
        Ok(())
    }

    #[instrument(
        level = "debug",
        name = "plugins::run_post_repl_incremental_conflict",
        skip_all
    )]
    pub fn run_post_repl_incremental_conflict(
        qs: &mut QueryServerWriteTransaction,
        cand: &[(EntrySealedCommitted, Arc<EntrySealedCommitted>)],
        conflict_uuids: &mut BTreeSet<Uuid>,
    ) -> Result<(), OperationError> {
        // Attr unique MUST BE FIRST.
        attrunique::AttrUnique::post_repl_incremental_conflict(qs, cand, conflict_uuids)
    }

    #[instrument(level = "debug", name = "plugins::run_post_repl_incremental", skip_all)]
    pub fn run_post_repl_incremental(
        qs: &mut QueryServerWriteTransaction,
        pre_cand: &[Arc<EntrySealedCommitted>],
        cand: &[EntrySealedCommitted],
        conflict_uuids: &BTreeSet<Uuid>,
    ) -> Result<(), OperationError> {
        // Nothing to do yet.
        // domain::Domain::post_repl_incremental(qs, pre_cand, cand, conflict_uuids)?;
        spn::Spn::post_repl_incremental(qs, pre_cand, cand, conflict_uuids)?;
        // refint MUST proceed memberof.
        refint::ReferentialIntegrity::post_repl_incremental(qs, pre_cand, cand, conflict_uuids)?;
        // Memberof MUST BE LAST.
        memberof::MemberOf::post_repl_incremental(qs, pre_cand, cand, conflict_uuids)
    }

    #[instrument(level = "debug", name = "plugins::run_verify", skip_all)]
    pub fn run_verify(
        qs: &mut QueryServerReadTransaction,
        results: &mut Vec<Result<(), ConsistencyError>>,
    ) {
        run_verify_plugin!(qs, results, base::Base);
        run_verify_plugin!(qs, results, valuedeny::ValueDeny);
        run_verify_plugin!(qs, results, attrunique::AttrUnique);
        run_verify_plugin!(qs, results, refint::ReferentialIntegrity);
        run_verify_plugin!(qs, results, keyobject::KeyObjectManagement);
        run_verify_plugin!(qs, results, dyngroup::DynGroup);
        run_verify_plugin!(qs, results, memberof::MemberOf);
        run_verify_plugin!(qs, results, spn::Spn);
    }
}
