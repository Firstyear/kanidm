use crate::be::BackendTransaction;
use crate::credential::Credential;
use crate::prelude::*;
use crate::repl::entry::State;
use crate::repl::proto::ConsumerState;
use crate::repl::proto::ReplIncrementalContext;
use crate::repl::ruv::ReplicationUpdateVectorTransaction;
use crate::repl::ruv::{RangeDiffStatus, ReplicationUpdateVector};
use crate::value::{AuthType, Session, SessionState};
use kanidm_lib_crypto::x509_cert::{der::DecodePem, Certificate};
use kanidm_lib_crypto::CryptoPolicy;
use std::collections::BTreeMap;
use time::OffsetDateTime;

fn repl_initialise(
    from: &mut QueryServerReadTransaction<'_>,
    to: &mut QueryServerWriteTransaction<'_>,
) -> Result<(), OperationError> {
    // First, build the refresh context.
    let refresh_context = from.supplier_provide_refresh()?;

    // Apply it to the server
    to.consumer_apply_refresh(refresh_context)?;

    // Need same d_uuid
    assert_eq!(from.get_domain_uuid(), to.get_domain_uuid());

    // Ruvs are the same now
    let a_ruv_range = from
        .get_be_txn()
        .get_ruv()
        .current_ruv_range()
        .expect("Failed to get RUV range A");
    let b_ruv_range = to
        .get_be_txn()
        .get_ruv()
        .current_ruv_range()
        .expect("Failed to get RUV range B");

    trace!(?a_ruv_range);
    trace!(?b_ruv_range);
    assert_eq!(a_ruv_range, b_ruv_range);

    Ok(())
}

fn repl_incremental(
    from: &mut QueryServerReadTransaction<'_>,
    to: &mut QueryServerWriteTransaction<'_>,
) {
    let a_ruv_range = to
        .get_be_txn()
        .get_ruv()
        .current_ruv_range()
        .expect("Failed to get RUV range from");
    let b_ruv_range = from
        .get_be_txn()
        .get_ruv()
        .current_ruv_range()
        .expect("Failed to get RUV range to");

    trace!(?a_ruv_range);
    trace!(?b_ruv_range);
    assert!(a_ruv_range != b_ruv_range);

    // Now setup the consumer state for the next incremental replication.
    let a_ruv_range = to.consumer_get_state().expect("Unable to access RUV range");

    // Incremental.
    // Should now be on the other partner.

    // Get the changes.
    let changes = from
        .supplier_provide_changes(a_ruv_range)
        .expect("Unable to generate supplier changes");

    trace!(?changes, "supplying changes");

    // Check the changes = should be empty.
    to.consumer_apply_changes(changes)
        .expect("Unable to apply changes to consumer.");

    // RUV should be consistent again.
    let a_ruv_range = to
        .get_be_txn()
        .get_ruv()
        .current_ruv_range()
        .expect("Failed to get RUV range A");
    let b_ruv_range = from
        .get_be_txn()
        .get_ruv()
        .current_ruv_range()
        .expect("Failed to get RUV range B");

    trace!(?a_ruv_range);
    trace!(?b_ruv_range);

    // May need to be "is subset" for future when we are testing
    // some more complex scenarios.
    let valid = match ReplicationUpdateVector::range_diff(&a_ruv_range, &b_ruv_range) {
        RangeDiffStatus::Ok(require) => require.is_empty(),
        _ => false,
    };
    assert!(valid);
}

#[qs_pair_test]
async fn test_repl_refresh_basic(server_a: &QueryServer, server_b: &QueryServer) {
    // Rebuild / refresh the content of server a with the content from b.

    // To ensure we have a spectrum of content, we do some setup here such as creating
    // tombstones.

    let mut server_a_txn = server_a.write(duration_from_epoch_now()).await.unwrap();

    let mut server_b_txn = server_b.read().await.unwrap();

    assert!(repl_initialise(&mut server_b_txn, &mut server_a_txn)
        .and_then(|_| server_a_txn.commit())
        .is_ok());

    // Verify the content of server_a and server_b are identical.
    let mut server_a_txn = server_a.read().await.unwrap();

    let domain_entry_a = server_a_txn
        .internal_search_uuid(UUID_DOMAIN_INFO)
        .expect("Failed to access domain info");

    let domain_entry_b = server_b_txn
        .internal_search_uuid(UUID_DOMAIN_INFO)
        .expect("Failed to access domain info");

    // Same d_vers / domain info.
    assert_eq!(domain_entry_a, domain_entry_b);

    trace!(
        "domain_changestate a {:#?}",
        domain_entry_a.get_changestate()
    );
    trace!(
        "domain_changestate b {:#?}",
        domain_entry_b.get_changestate()
    );

    // Compare that their change states are identical too.
    assert_eq!(
        domain_entry_a.get_changestate(),
        domain_entry_b.get_changestate()
    );

    // There is some metadata here we should also consider testing such as key
    // reloads? These are done at the IDM level, but this is QS level, so do we need to change
    // these tests? Or should they be separate repl tests later?
    assert_eq!(*server_a_txn.d_info, *server_b_txn.d_info);

    // Now assert everything else in the db matches.

    let entries_a = server_a_txn
        .internal_search(filter_all!(f_pres(Attribute::Class)))
        .map(|ents| {
            ents.into_iter()
                .map(|e| (e.get_uuid(), e))
                .collect::<BTreeMap<_, _>>()
        })
        .expect("Failed to access all entries");

    let entries_b = server_a_txn
        .internal_search(filter_all!(f_pres(Attribute::Class)))
        .map(|ents| {
            ents.into_iter()
                .map(|e| (e.get_uuid(), e))
                .collect::<BTreeMap<_, _>>()
        })
        .expect("Failed to access all entries");

    // Basically do a select * then put into btreemaps and compare them all.

    // Need to have the same length!
    assert_eq!(entries_a.len(), entries_b.len());

    // We don't use the uuid-keys here since these are compared internally, they are
    // just to sort the two sets.
    std::iter::zip(entries_a.values(), entries_b.values()).for_each(|(ent_a, ent_b)| {
        assert_eq!(ent_a, ent_b);
        assert_eq!(ent_a.get_changestate(), ent_b.get_changestate());
    });

    // Done! The entry content are identical as are their replication metadata. We are good
    // to go!

    // Both servers will be post-test validated.
}

// Test that adding an entry to one side replicates correctly.
#[qs_pair_test]
async fn test_repl_increment_basic_entry_add(server_a: &QueryServer, server_b: &QueryServer) {
    let mut server_a_txn = server_a.write(duration_from_epoch_now()).await.unwrap();

    let mut server_b_txn = server_b.read().await.unwrap();

    assert!(repl_initialise(&mut server_b_txn, &mut server_a_txn)
        .and_then(|_| server_a_txn.commit())
        .is_ok());

    //  - incremental - no changes should be present
    let mut server_a_txn = server_a.read().await.unwrap();
    let a_ruv_range = server_a_txn
        .consumer_get_state()
        .expect("Unable to access RUV range");
    // End the read.
    drop(server_a_txn);

    // Get the changes.
    let changes = server_b_txn
        .supplier_provide_changes(a_ruv_range)
        .expect("Unable to generate supplier changes");

    // Check the changes = should be empty.
    let mut server_a_txn = server_a.write(duration_from_epoch_now()).await.unwrap();

    server_a_txn
        .consumer_apply_changes(changes)
        .expect("Unable to apply changes to consumer.");

    // Do a ruv check - should still be the same.
    let a_ruv_range = server_a_txn
        .get_be_txn()
        .get_ruv()
        .current_ruv_range()
        .expect("Failed to get RUV range A");
    let b_ruv_range = server_b_txn
        .get_be_txn()
        .get_ruv()
        .current_ruv_range()
        .expect("Failed to get RUV range B");

    trace!(?a_ruv_range);
    trace!(?b_ruv_range);
    assert_eq!(a_ruv_range, b_ruv_range);

    server_a_txn.commit().expect("Failed to commit");

    drop(server_b_txn);

    // Add an entry.
    let mut server_b_txn = server_b.write(duration_from_epoch_now()).await.unwrap();
    let t_uuid = Uuid::new_v4();
    assert!(server_b_txn
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
    server_b_txn.commit().expect("Failed to commit");

    // let mut server_a_txn = server_a.write(duration_from_epoch_now()).await.unwrap();
    let mut server_a_txn = server_a.read().await.unwrap();
    let mut server_b_txn = server_b.read().await.unwrap();

    // Assert the entry is not on A.
    assert_eq!(
        server_a_txn.internal_search_uuid(t_uuid),
        Err(OperationError::NoMatchingEntries)
    );

    let a_ruv_range = server_a_txn
        .get_be_txn()
        .get_ruv()
        .current_ruv_range()
        .expect("Failed to get RUV range A");
    let b_ruv_range = server_b_txn
        .get_be_txn()
        .get_ruv()
        .current_ruv_range()
        .expect("Failed to get RUV range B");

    trace!(?a_ruv_range);
    trace!(?b_ruv_range);
    assert!(a_ruv_range != b_ruv_range);

    // Now setup the consumer state for the next incremental replication.
    let a_ruv_range = server_a_txn
        .consumer_get_state()
        .expect("Unable to access RUV range");
    // End the read.
    drop(server_a_txn);

    // Incremental.
    // Should now be on the other partner.

    // Get the changes.
    let changes = server_b_txn
        .supplier_provide_changes(a_ruv_range)
        .expect("Unable to generate supplier changes");

    // Check the changes = should be empty.
    let mut server_a_txn = server_a.write(duration_from_epoch_now()).await.unwrap();

    server_a_txn
        .consumer_apply_changes(changes)
        .expect("Unable to apply changes to consumer.");

    // RUV should be consistent again.
    let a_ruv_range = server_a_txn
        .get_be_txn()
        .get_ruv()
        .current_ruv_range()
        .expect("Failed to get RUV range A");
    let b_ruv_range = server_b_txn
        .get_be_txn()
        .get_ruv()
        .current_ruv_range()
        .expect("Failed to get RUV range B");

    trace!(?a_ruv_range);
    trace!(?b_ruv_range);
    assert_eq!(a_ruv_range, b_ruv_range);

    // Assert the entry is now present, and the same on both sides
    let e1 = server_a_txn
        .internal_search_uuid(t_uuid)
        .expect("Unable to access new entry.");
    let e2 = server_b_txn
        .internal_search_uuid(t_uuid)
        .expect("Unable to access entry.");

    assert_eq!(e1, e2);

    server_a_txn.commit().expect("Failed to commit");
    drop(server_b_txn);
}

// Test that adding an entry to one side, then recycling it replicates correctly.
#[qs_pair_test]
async fn test_repl_increment_basic_entry_recycle(server_a: &QueryServer, server_b: &QueryServer) {
    let mut server_a_txn = server_a.write(duration_from_epoch_now()).await.unwrap();
    let mut server_b_txn = server_b.read().await.unwrap();

    assert!(repl_initialise(&mut server_b_txn, &mut server_a_txn)
        .and_then(|_| server_a_txn.commit())
        .is_ok());
    drop(server_b_txn);

    // Add an entry.
    let mut server_b_txn = server_b.write(duration_from_epoch_now()).await.unwrap();
    let t_uuid = Uuid::new_v4();
    assert!(server_b_txn
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

    // Now recycle it.
    assert!(server_b_txn.internal_delete_uuid(t_uuid).is_ok());

    server_b_txn.commit().expect("Failed to commit");

    // Assert the entry is not on A.

    let mut server_a_txn = server_a.write(duration_from_epoch_now()).await.unwrap();
    let mut server_b_txn = server_b.read().await.unwrap();

    assert_eq!(
        server_a_txn.internal_search_uuid(t_uuid),
        Err(OperationError::NoMatchingEntries)
    );

    repl_incremental(&mut server_b_txn, &mut server_a_txn);

    let e1 = server_a_txn
        .internal_search_all_uuid(t_uuid)
        .expect("Unable to access new entry.");
    let e2 = server_b_txn
        .internal_search_all_uuid(t_uuid)
        .expect("Unable to access entry.");

    assert_eq!(e1, e2);

    server_a_txn.commit().expect("Failed to commit");
    drop(server_b_txn);
}

// Test that adding an entry to one side, then recycling it, and tombstoning it
// replicates correctly.
#[qs_pair_test]
async fn test_repl_increment_basic_entry_tombstone(server_a: &QueryServer, server_b: &QueryServer) {
    let ct = duration_from_epoch_now();

    let mut server_a_txn = server_a.write(ct).await.unwrap();
    let mut server_b_txn = server_b.read().await.unwrap();

    assert!(repl_initialise(&mut server_b_txn, &mut server_a_txn)
        .and_then(|_| server_a_txn.commit())
        .is_ok());
    drop(server_b_txn);

    // Add an entry.
    let mut server_b_txn = server_b.write(ct).await.unwrap();
    let t_uuid = Uuid::new_v4();
    assert!(server_b_txn
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

    // Now recycle it.
    assert!(server_b_txn.internal_delete_uuid(t_uuid).is_ok());
    server_b_txn.commit().expect("Failed to commit");

    // Now move past the recyclebin time.
    let ct = ct + Duration::from_secs(RECYCLEBIN_MAX_AGE + 1);

    let mut server_b_txn = server_b.write(ct).await.unwrap();
    // Clean out the recycle bin.
    assert!(server_b_txn.purge_recycled().is_ok());
    server_b_txn.commit().expect("Failed to commit");

    // Assert the entry is not on A.

    let mut server_a_txn = server_a.write(ct).await.unwrap();
    let mut server_b_txn = server_b.read().await.unwrap();

    assert_eq!(
        server_a_txn.internal_search_uuid(t_uuid),
        Err(OperationError::NoMatchingEntries)
    );

    repl_incremental(&mut server_b_txn, &mut server_a_txn);

    let e1 = server_a_txn
        .internal_search_all_uuid(t_uuid)
        .expect("Unable to access new entry.");
    let e2 = server_b_txn
        .internal_search_all_uuid(t_uuid)
        .expect("Unable to access entry.");

    assert!(e1.attribute_equality(Attribute::Class, &EntryClass::Tombstone.into()));

    assert_eq!(e1, e2);

    server_a_txn.commit().expect("Failed to commit");
    drop(server_b_txn);
}

// Test that adding an entry -> tombstone then the tombstone is trimmed raises
// a replication error.
#[qs_pair_test]
async fn test_repl_increment_consumer_lagging_tombstone(
    server_a: &QueryServer,
    server_b: &QueryServer,
) {
    let ct = duration_from_epoch_now();

    let mut server_a_txn = server_a.write(ct).await.unwrap();
    let mut server_b_txn = server_b.read().await.unwrap();

    assert!(repl_initialise(&mut server_b_txn, &mut server_a_txn)
        .and_then(|_| server_a_txn.commit())
        .is_ok());
    drop(server_b_txn);

    // Add an entry.
    let mut server_b_txn = server_b.write(ct).await.unwrap();
    let t_uuid = Uuid::new_v4();
    assert!(server_b_txn
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

    // Now recycle it.
    assert!(server_b_txn.internal_delete_uuid(t_uuid).is_ok());
    server_b_txn.commit().expect("Failed to commit");

    // Now move past the recyclebin time.
    let ct = ct + Duration::from_secs(RECYCLEBIN_MAX_AGE + 1);

    let mut server_b_txn = server_b.write(ct).await.unwrap();
    // Clean out the recycle bin.
    assert!(server_b_txn.purge_recycled().is_ok());
    server_b_txn.commit().expect("Failed to commit");

    // Now move past the tombstone trim time.
    let ct = ct + Duration::from_secs(CHANGELOG_MAX_AGE + 1);

    let mut server_b_txn = server_b.write(ct).await.unwrap();
    // Clean out the recycle bin.
    assert!(server_b_txn.purge_tombstones().is_ok());
    server_b_txn.commit().expect("Failed to commit");

    // Assert the entry is not on A *or* B.

    let mut server_a_txn = server_a.write(ct).await.unwrap();
    let mut server_b_txn = server_b.read().await.unwrap();

    assert_eq!(
        server_a_txn.internal_search_uuid(t_uuid),
        Err(OperationError::NoMatchingEntries)
    );
    assert_eq!(
        server_b_txn.internal_search_uuid(t_uuid),
        Err(OperationError::NoMatchingEntries)
    );

    // The ruvs must be different
    let a_ruv_range = server_a_txn
        .get_be_txn()
        .get_ruv()
        .current_ruv_range()
        .expect("Failed to get RUV range A");
    let b_ruv_range = server_b_txn
        .get_be_txn()
        .get_ruv()
        .current_ruv_range()
        .expect("Failed to get RUV range B");

    trace!(?a_ruv_range);
    trace!(?b_ruv_range);
    assert!(a_ruv_range != b_ruv_range);

    let a_ruv_range = server_a_txn
        .consumer_get_state()
        .expect("Unable to access RUV range");

    let changes = server_b_txn
        .supplier_provide_changes(a_ruv_range)
        .expect("Unable to generate supplier changes");

    assert!(matches!(changes, ReplIncrementalContext::RefreshRequired));

    let result = server_a_txn
        .consumer_apply_changes(changes)
        .expect("Unable to apply changes to consumer.");

    assert!(matches!(result, ConsumerState::RefreshRequired));

    drop(server_a_txn);
    drop(server_b_txn);
}

// Write state cases.

// Create Entry an B -> A
// Write to A
// A -> B becomes consistent.

#[qs_pair_test]
async fn test_repl_increment_basic_bidirectional_write(
    server_a: &QueryServer,
    server_b: &QueryServer,
) {
    let mut server_a_txn = server_a.write(duration_from_epoch_now()).await.unwrap();
    let mut server_b_txn = server_b.read().await.unwrap();

    assert!(repl_initialise(&mut server_b_txn, &mut server_a_txn)
        .and_then(|_| server_a_txn.commit())
        .is_ok());
    drop(server_b_txn);

    // Add an entry.
    let mut server_b_txn = server_b.write(duration_from_epoch_now()).await.unwrap();
    let t_uuid = Uuid::new_v4();
    assert!(server_b_txn
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
    server_b_txn.commit().expect("Failed to commit");

    // Assert the entry is not on A.
    let mut server_a_txn = server_a.write(duration_from_epoch_now()).await.unwrap();
    let mut server_b_txn = server_b.read().await.unwrap();

    assert_eq!(
        server_a_txn.internal_search_uuid(t_uuid),
        Err(OperationError::NoMatchingEntries)
    );

    //               from               to
    repl_incremental(&mut server_b_txn, &mut server_a_txn);

    let e1 = server_a_txn
        .internal_search_all_uuid(t_uuid)
        .expect("Unable to access new entry.");
    let e2 = server_b_txn
        .internal_search_all_uuid(t_uuid)
        .expect("Unable to access entry.");

    assert_eq!(e1, e2);

    // Now perform a write on A
    assert!(server_a_txn
        .internal_modify_uuid(t_uuid, &ModifyList::new_purge(Attribute::Description))
        .is_ok());

    server_a_txn.commit().expect("Failed to commit");
    drop(server_b_txn);

    // Incremental repl in the reverse direction.
    let mut server_a_txn = server_a.read().await.unwrap();
    let mut server_b_txn = server_b.write(duration_from_epoch_now()).await.unwrap();

    //               from               to
    repl_incremental(&mut server_a_txn, &mut server_b_txn);

    let e1 = server_a_txn
        .internal_search_all_uuid(t_uuid)
        .expect("Unable to access new entry.");
    let e2 = server_b_txn
        .internal_search_all_uuid(t_uuid)
        .expect("Unable to access entry.");

    // They are consistent again.
    assert_eq!(e1, e2);
    assert!(e1.get_ava_set(Attribute::Description).is_none());

    server_b_txn.commit().expect("Failed to commit");
    drop(server_a_txn);
}

// Create Entry on A
// Delete an attr of the entry on A
// Should send the empty attr + changestate state to B

#[qs_pair_test]
async fn test_repl_increment_basic_deleted_attr(server_a: &QueryServer, server_b: &QueryServer) {
    let mut server_a_txn = server_a.write(duration_from_epoch_now()).await.unwrap();
    let mut server_b_txn = server_b.read().await.unwrap();

    assert!(repl_initialise(&mut server_b_txn, &mut server_a_txn)
        .and_then(|_| server_a_txn.commit())
        .is_ok());
    drop(server_b_txn);

    // Add an entry.
    let mut server_a_txn = server_a.write(duration_from_epoch_now()).await.unwrap();
    let t_uuid = Uuid::new_v4();
    assert!(server_a_txn
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
    server_a_txn.commit().expect("Failed to commit");

    // Delete an attribute so that the changestate doesn't reflect it's
    // presence
    let mut server_a_txn = server_a.write(duration_from_epoch_now()).await.unwrap();
    assert!(server_a_txn
        .internal_modify_uuid(t_uuid, &ModifyList::new_purge(Attribute::Description))
        .is_ok());
    server_a_txn.commit().expect("Failed to commit");

    // Incremental repl in the reverse direction.
    let mut server_a_txn = server_a.read().await.unwrap();
    let mut server_b_txn = server_b.write(duration_from_epoch_now()).await.unwrap();

    //               from               to
    repl_incremental(&mut server_a_txn, &mut server_b_txn);

    let e1 = server_a_txn
        .internal_search_all_uuid(t_uuid)
        .expect("Unable to access new entry.");
    let e2 = server_b_txn
        .internal_search_all_uuid(t_uuid)
        .expect("Unable to access entry.");

    // They are consistent again.
    assert!(e1.get_ava_set(Attribute::Description).is_none());
    assert_eq!(e1, e2);

    let e1_cs = e1.get_changestate();
    let e2_cs = e2.get_changestate();
    assert_eq!(e1_cs, e2_cs);
    assert!(e1_cs.get_attr_cid(&Attribute::Description).is_some());

    server_b_txn.commit().expect("Failed to commit");
    drop(server_a_txn);
}

// Create Entry on A -> B
// Write to both
// B -> A and A -> B become consistent.

#[qs_pair_test]
async fn test_repl_increment_simultaneous_bidirectional_write(
    server_a: &QueryServer,
    server_b: &QueryServer,
) {
    let mut server_a_txn = server_a.write(duration_from_epoch_now()).await.unwrap();
    let mut server_b_txn = server_b.read().await.unwrap();

    assert!(repl_initialise(&mut server_b_txn, &mut server_a_txn)
        .and_then(|_| server_a_txn.commit())
        .is_ok());
    drop(server_b_txn);

    // Add an entry.
    let mut server_b_txn = server_b.write(duration_from_epoch_now()).await.unwrap();
    let t_uuid = Uuid::new_v4();
    assert!(server_b_txn
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
    server_b_txn.commit().expect("Failed to commit");

    // Assert the entry is not on A.
    let mut server_a_txn = server_a.write(duration_from_epoch_now()).await.unwrap();
    let mut server_b_txn = server_b.read().await.unwrap();

    assert_eq!(
        server_a_txn.internal_search_uuid(t_uuid),
        Err(OperationError::NoMatchingEntries)
    );

    //               from               to
    repl_incremental(&mut server_b_txn, &mut server_a_txn);

    let e1 = server_a_txn
        .internal_search_all_uuid(t_uuid)
        .expect("Unable to access new entry.");
    let e2 = server_b_txn
        .internal_search_all_uuid(t_uuid)
        .expect("Unable to access entry.");

    assert_eq!(e1, e2);

    // Now perform a write on A
    assert!(server_a_txn
        .internal_modify_uuid(
            t_uuid,
            &ModifyList::new_purge_and_set(Attribute::Description, Value::new_utf8s("repl_test"))
        )
        .is_ok());

    server_a_txn.commit().expect("Failed to commit");
    drop(server_b_txn);

    // Also write to B.
    let mut server_b_txn = server_b.write(duration_from_epoch_now()).await.unwrap();
    assert!(server_b_txn
        .internal_modify_uuid(
            t_uuid,
            &ModifyList::new_purge_and_set(Attribute::DisplayName, Value::new_utf8s("repl_test"))
        )
        .is_ok());

    server_b_txn.commit().expect("Failed to commit");

    // Incremental repl in the both directions.
    let mut server_a_txn = server_a.read().await.unwrap();
    let mut server_b_txn = server_b.write(duration_from_epoch_now()).await.unwrap();
    //               from               to
    repl_incremental(&mut server_a_txn, &mut server_b_txn);
    server_b_txn.commit().expect("Failed to commit");
    drop(server_a_txn);

    let mut server_a_txn = server_a.write(duration_from_epoch_now()).await.unwrap();
    let mut server_b_txn = server_b.read().await.unwrap();
    //               from               to
    repl_incremental(&mut server_b_txn, &mut server_a_txn);
    server_a_txn.commit().expect("Failed to commit");
    drop(server_b_txn);

    // Validate they are the same again.
    let mut server_a_txn = server_a.read().await.unwrap();
    let mut server_b_txn = server_b.read().await.unwrap();

    let e1 = server_a_txn
        .internal_search_all_uuid(t_uuid)
        .expect("Unable to access new entry.");
    let e2 = server_b_txn
        .internal_search_all_uuid(t_uuid)
        .expect("Unable to access entry.");

    // They are consistent again.
    assert_eq!(e1, e2);
    assert_eq!(
        e1.get_ava_single_utf8(Attribute::Description),
        Some("repl_test")
    );
    assert_eq!(
        e1.get_ava_single_utf8(Attribute::DisplayName),
        Some("repl_test")
    );
}

// Create entry on A -> B
// Recycle
// Recycle propagates from A -> B
// TS on B
// B -> A TS

#[qs_pair_test]
async fn test_repl_increment_basic_bidirectional_lifecycle(
    server_a: &QueryServer,
    server_b: &QueryServer,
) {
    let ct = duration_from_epoch_now();

    let mut server_a_txn = server_a.write(ct).await.unwrap();
    let mut server_b_txn = server_b.read().await.unwrap();

    assert!(repl_initialise(&mut server_b_txn, &mut server_a_txn)
        .and_then(|_| server_a_txn.commit())
        .is_ok());
    drop(server_b_txn);

    // Add an entry.
    let mut server_b_txn = server_b.write(ct).await.unwrap();
    let t_uuid = Uuid::new_v4();
    assert!(server_b_txn
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
    server_b_txn.commit().expect("Failed to commit");

    // Assert the entry is not on A.
    let mut server_a_txn = server_a.write(ct).await.unwrap();
    let mut server_b_txn = server_b.read().await.unwrap();

    assert_eq!(
        server_a_txn.internal_search_uuid(t_uuid),
        Err(OperationError::NoMatchingEntries)
    );

    //               from               to
    repl_incremental(&mut server_b_txn, &mut server_a_txn);

    let e1 = server_a_txn
        .internal_search_all_uuid(t_uuid)
        .expect("Unable to access new entry.");
    let e2 = server_b_txn
        .internal_search_all_uuid(t_uuid)
        .expect("Unable to access entry.");

    assert_eq!(e1, e2);

    server_a_txn.commit().expect("Failed to commit");
    drop(server_b_txn);

    // Delete on A
    let mut server_a_txn = server_a.write(ct).await.unwrap();
    assert!(server_a_txn.internal_delete_uuid(t_uuid).is_ok());
    server_a_txn.commit().expect("Failed to commit");

    // Repl A -> B
    let mut server_a_txn = server_a.read().await.unwrap();
    let mut server_b_txn = server_b.write(ct).await.unwrap();

    repl_incremental(&mut server_a_txn, &mut server_b_txn);

    let e1 = server_a_txn
        .internal_search_all_uuid(t_uuid)
        .expect("Unable to access new entry.");
    let e2 = server_b_txn
        .internal_search_all_uuid(t_uuid)
        .expect("Unable to access entry.");

    // They are consistent again.
    assert_eq!(e1, e2);
    assert!(e1.attribute_equality(Attribute::Class, &EntryClass::Recycled.into()));

    server_b_txn.commit().expect("Failed to commit");
    drop(server_a_txn);

    // At an earlier time make a change on A.
    let mut server_a_txn = server_a.write(ct).await.unwrap();
    assert!(server_a_txn.internal_revive_uuid(t_uuid).is_ok());
    server_a_txn.commit().expect("Failed to commit");

    // Now move past the recyclebin time.
    let ct = ct + Duration::from_secs(RECYCLEBIN_MAX_AGE + 1);

    // Now TS on B.
    let mut server_b_txn = server_b.write(ct).await.unwrap();
    assert!(server_b_txn.purge_recycled().is_ok());
    server_b_txn.commit().expect("Failed to commit");

    // Repl A -> B - B will silently reject the update due to the TS state on B.
    let mut server_a_txn = server_a.read().await.unwrap();
    let mut server_b_txn = server_b.write(ct).await.unwrap();

    repl_incremental(&mut server_a_txn, &mut server_b_txn);

    let e1 = server_a_txn
        .internal_search_all_uuid(t_uuid)
        .expect("Unable to access new entry.");
    let e2 = server_b_txn
        .internal_search_all_uuid(t_uuid)
        .expect("Unable to access entry.");

    // They are NOT consistent.
    assert!(e1 != e2);
    // E1 from A is NOT a tombstone ... yet.
    assert!(!e1.attribute_equality(Attribute::Class, &EntryClass::Tombstone.into()));
    // E2 from B is a tombstone!
    assert!(e2.attribute_equality(Attribute::Class, &EntryClass::Tombstone.into()));

    server_b_txn.commit().expect("Failed to commit");
    drop(server_a_txn);

    // Repl B -> A - will have a TS at the end.
    let mut server_a_txn = server_a.write(ct).await.unwrap();
    let mut server_b_txn = server_b.read().await.unwrap();

    repl_incremental(&mut server_b_txn, &mut server_a_txn);

    let e1 = server_a_txn
        .internal_search_all_uuid(t_uuid)
        .expect("Unable to access new entry.");
    let e2 = server_b_txn
        .internal_search_all_uuid(t_uuid)
        .expect("Unable to access entry.");

    // Ts on both.
    assert!(e1.attribute_equality(Attribute::Class, &EntryClass::Tombstone.into()));
    assert_eq!(e1, e2);

    server_a_txn.commit().expect("Failed to commit");
    drop(server_b_txn);
}

// Create entry on A -> B
// Recycle on Both A/B
// Recycle propagates from A -> B, B -> A, keep latest.
// We already know the recycle -> ts state is good from other tests.

#[qs_pair_test]
async fn test_repl_increment_basic_bidirectional_recycle(
    server_a: &QueryServer,
    server_b: &QueryServer,
) {
    let ct = duration_from_epoch_now();

    let mut server_a_txn = server_a.write(ct).await.unwrap();
    let mut server_b_txn = server_b.read().await.unwrap();

    assert!(repl_initialise(&mut server_b_txn, &mut server_a_txn)
        .and_then(|_| server_a_txn.commit())
        .is_ok());
    drop(server_b_txn);

    // Add an entry.
    let mut server_b_txn = server_b.write(ct).await.unwrap();
    let t_uuid = Uuid::new_v4();
    assert!(server_b_txn
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
    server_b_txn.commit().expect("Failed to commit");

    // Assert the entry is not on A.
    let mut server_a_txn = server_a.write(ct).await.unwrap();
    let mut server_b_txn = server_b.read().await.unwrap();

    //               from               to
    repl_incremental(&mut server_b_txn, &mut server_a_txn);

    let e1 = server_a_txn
        .internal_search_all_uuid(t_uuid)
        .expect("Unable to access new entry.");
    let e2 = server_b_txn
        .internal_search_all_uuid(t_uuid)
        .expect("Unable to access entry.");

    assert_eq!(e1, e2);

    server_a_txn.commit().expect("Failed to commit");
    drop(server_b_txn);

    // On both servers, at separate timestamps, run the recycle.
    let ct = ct + Duration::from_secs(1);
    let mut server_a_txn = server_a.write(ct).await.unwrap();
    assert!(server_a_txn.internal_delete_uuid(t_uuid).is_ok());
    server_a_txn.commit().expect("Failed to commit");

    let ct = ct + Duration::from_secs(2);
    let mut server_b_txn = server_b.write(ct).await.unwrap();
    assert!(server_b_txn.internal_delete_uuid(t_uuid).is_ok());
    server_b_txn.commit().expect("Failed to commit");

    // Send server a -> b - ignored.
    let mut server_a_txn = server_a.read().await.unwrap();
    let mut server_b_txn = server_b.write(ct).await.unwrap();

    repl_incremental(&mut server_a_txn, &mut server_b_txn);

    let e1 = server_a_txn
        .internal_search_all_uuid(t_uuid)
        .expect("Unable to access new entry.");
    let e2 = server_b_txn
        .internal_search_all_uuid(t_uuid)
        .expect("Unable to access entry.");

    server_b_txn.commit().expect("Failed to commit");
    drop(server_a_txn);

    // They are equal, but their CL states are not. e2 should have been
    // retained due to being the latest!
    assert_eq!(e1, e2);
    assert!(e1.attribute_equality(Attribute::Class, &EntryClass::Recycled.into()));

    // Remember entry comparison doesn't compare last_mod_cid.
    assert!(e1.get_last_changed() < e2.get_last_changed());

    let e1_cs = e1.get_changestate();
    let e2_cs = e2.get_changestate();

    let valid = match (e1_cs.current(), e2_cs.current()) {
        (
            State::Live {
                at: _,
                changes: changes_left,
            },
            State::Live {
                at: _,
                changes: changes_right,
            },
        ) => match (
            changes_left.get(&Attribute::Class),
            changes_right.get(&Attribute::Class),
        ) {
            (Some(cid_left), Some(cid_right)) => cid_left < cid_right,
            _ => false,
        },
        _ => false,
    };
    assert!(valid);

    // Now go the other way. They'll be equal again.
    let mut server_a_txn = server_a.write(ct).await.unwrap();
    let mut server_b_txn = server_b.read().await.unwrap();

    repl_incremental(&mut server_b_txn, &mut server_a_txn);

    let e1 = server_a_txn
        .internal_search_all_uuid(t_uuid)
        .expect("Unable to access new entry.");
    let e2 = server_b_txn
        .internal_search_all_uuid(t_uuid)
        .expect("Unable to access entry.");

    assert_eq!(e1, e2);

    let e1_cs = e1.get_changestate();
    let e2_cs = e2.get_changestate();
    assert_eq!(e1_cs, e2_cs);

    server_a_txn.commit().expect("Failed to commit");
    drop(server_b_txn);
}

// Create + recycle entry on B -> A
// TS on Both,
// TS resolves to lowest AT.

#[qs_pair_test]
async fn test_repl_increment_basic_bidirectional_tombstone(
    server_a: &QueryServer,
    server_b: &QueryServer,
) {
    let ct = duration_from_epoch_now();

    let mut server_b_txn = server_b.write(ct).await.unwrap();
    let t_uuid = Uuid::new_v4();
    assert!(server_b_txn
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
    // And then recycle it.
    assert!(server_b_txn.internal_delete_uuid(t_uuid).is_ok());
    server_b_txn.commit().expect("Failed to commit");

    // Now setup repl
    let mut server_a_txn = server_a.write(ct).await.unwrap();
    let mut server_b_txn = server_b.read().await.unwrap();

    assert!(repl_initialise(&mut server_b_txn, &mut server_a_txn).is_ok());

    let e1 = server_a_txn
        .internal_search_all_uuid(t_uuid)
        .expect("Unable to access new entry.");
    let e2 = server_b_txn
        .internal_search_all_uuid(t_uuid)
        .expect("Unable to access entry.");

    assert_eq!(e1, e2);

    server_a_txn.commit().expect("Failed to commit");
    drop(server_b_txn);

    // Now on both servers, perform a recycle -> ts at different times.
    let ct = ct + Duration::from_secs(RECYCLEBIN_MAX_AGE + 1);
    let mut server_a_txn = server_a.write(ct).await.unwrap();
    assert!(server_a_txn.purge_recycled().is_ok());
    server_a_txn.commit().expect("Failed to commit");

    let ct = ct + Duration::from_secs(1);
    let mut server_b_txn = server_b.write(ct).await.unwrap();
    assert!(server_b_txn.purge_recycled().is_ok());
    server_b_txn.commit().expect("Failed to commit");

    // Now do B -> A - no change on A as it's TS was earlier.
    let mut server_a_txn = server_a.write(ct).await.unwrap();
    let mut server_b_txn = server_b.read().await.unwrap();

    repl_incremental(&mut server_b_txn, &mut server_a_txn);

    let e1 = server_a_txn
        .internal_search_all_uuid(t_uuid)
        .expect("Unable to access new entry.");
    let e2 = server_b_txn
        .internal_search_all_uuid(t_uuid)
        .expect("Unable to access entry.");

    assert!(e1.attribute_equality(Attribute::Class, &EntryClass::Tombstone.into()));
    assert!(e2.attribute_equality(Attribute::Class, &EntryClass::Tombstone.into()));
    trace!("{:?}", e1.get_last_changed());
    trace!("{:?}", e2.get_last_changed());
    assert!(e1.get_last_changed() < e2.get_last_changed());

    server_a_txn.commit().expect("Failed to commit");
    drop(server_b_txn);

    // A -> B - B should now have the A TS time.
    let mut server_a_txn = server_a.read().await.unwrap();
    let mut server_b_txn = server_b.write(duration_from_epoch_now()).await.unwrap();

    repl_incremental(&mut server_a_txn, &mut server_b_txn);

    let e1 = server_a_txn
        .internal_search_all_uuid(t_uuid)
        .expect("Unable to access new entry.");
    let e2 = server_b_txn
        .internal_search_all_uuid(t_uuid)
        .expect("Unable to access entry.");

    assert!(e1.attribute_equality(Attribute::Class, &EntryClass::Tombstone.into()));
    assert!(e2.attribute_equality(Attribute::Class, &EntryClass::Tombstone.into()));
    assert_eq!(e1.get_last_changed(), e2.get_last_changed());

    server_b_txn.commit().expect("Failed to commit");
    drop(server_a_txn);
}

// conflict cases.

// both add entry with same uuid - only one can win!
#[qs_pair_test]
async fn test_repl_increment_creation_uuid_conflict(
    server_a: &QueryServer,
    server_b: &QueryServer,
) {
    let ct = duration_from_epoch_now();
    let mut server_a_txn = server_a.write(ct).await.unwrap();
    let mut server_b_txn = server_b.read().await.unwrap();

    assert!(repl_initialise(&mut server_b_txn, &mut server_a_txn).is_ok());

    server_a_txn.commit().expect("Failed to commit");
    drop(server_b_txn);

    // Now create the same entry on both servers.
    let t_uuid = Uuid::new_v4();
    let e_init = entry_init!(
        (Attribute::Class, EntryClass::Object.to_value()),
        (Attribute::Class, EntryClass::Account.to_value()),
        (Attribute::Class, EntryClass::Person.to_value()),
        (Attribute::Name, Value::new_iname("testperson1")),
        (Attribute::Uuid, Value::Uuid(t_uuid)),
        (Attribute::Description, Value::new_utf8s("testperson1")),
        (Attribute::DisplayName, Value::new_utf8s("testperson1"))
    );

    let mut server_b_txn = server_b.write(ct).await.unwrap();
    assert!(server_b_txn.internal_create(vec![e_init.clone(),]).is_ok());
    server_b_txn.commit().expect("Failed to commit");

    // Get a new time.
    let ct = duration_from_epoch_now();
    let mut server_a_txn = server_a.write(ct).await.unwrap();
    assert!(server_a_txn.internal_create(vec![e_init.clone(),]).is_ok());
    server_a_txn.commit().expect("Failed to commit");

    // Replicate A to B. B should ignore.
    let mut server_a_txn = server_a.read().await.unwrap();
    let mut server_b_txn = server_b.write(duration_from_epoch_now()).await.unwrap();

    trace!("========================================");
    repl_incremental(&mut server_a_txn, &mut server_b_txn);

    let e1 = server_a_txn
        .internal_search_all_uuid(t_uuid)
        .expect("Unable to access new entry.");
    let e2 = server_b_txn
        .internal_search_all_uuid(t_uuid)
        .expect("Unable to access entry.");

    let e1_acc = server_a_txn
        .internal_search_all_uuid(UUID_IDM_ALL_ACCOUNTS)
        .expect("Unable to access new entry.");
    let e2_acc = server_b_txn
        .internal_search_all_uuid(UUID_IDM_ALL_ACCOUNTS)
        .expect("Unable to access entry.");

    trace!("TESTMARKER 0");
    trace!(?e1);
    trace!(?e2);
    trace!(?e1_acc);
    trace!(?e2_acc);

    trace!("{:?}", e1.get_last_changed());
    trace!("{:?}", e2.get_last_changed());
    // e2 from b will be smaller as it's the older entry.
    assert!(e1.get_last_changed() > e2.get_last_changed());

    // Check that no conflict entries exist yet.
    let cnf_a = server_a_txn
        .internal_search_conflict_uuid(t_uuid)
        .expect("Unable to conflict entries.");
    assert!(cnf_a.is_empty());
    let cnf_b = server_b_txn
        .internal_search_conflict_uuid(t_uuid)
        .expect("Unable to conflict entries.");
    assert!(cnf_b.is_empty());

    server_b_txn.commit().expect("Failed to commit");
    drop(server_a_txn);

    // Replicate B to A. A should replace with B, and create the
    // conflict entry as it's the origin of the conflict.
    let mut server_a_txn = server_a.write(ct).await.unwrap();
    let mut server_b_txn = server_b.read().await.unwrap();

    trace!("========================================");
    repl_incremental(&mut server_b_txn, &mut server_a_txn);

    let e1 = server_a_txn
        .internal_search_all_uuid(t_uuid)
        .expect("Unable to access new entry.");
    let e2 = server_b_txn
        .internal_search_all_uuid(t_uuid)
        .expect("Unable to access entry.");

    let e1_acc = server_a_txn
        .internal_search_all_uuid(UUID_IDM_ALL_ACCOUNTS)
        .expect("Unable to access new entry.");
    let e2_acc = server_b_txn
        .internal_search_all_uuid(UUID_IDM_ALL_ACCOUNTS)
        .expect("Unable to access entry.");

    trace!("TESTMARKER 1");
    trace!(?e1);
    trace!(?e2);
    trace!(?e1_acc);
    trace!(?e2_acc);

    assert_eq!(e1.get_last_changed(), e2.get_last_changed());

    let cnf_a = server_a_txn
        .internal_search_conflict_uuid(t_uuid)
        .expect("Unable to conflict entries.")
        // Should be a vec.
        .pop()
        .expect("No conflict entries present");
    assert_eq!(
        cnf_a.get_ava_single_iname(Attribute::Name),
        Some("testperson1")
    );

    let cnf_b = server_b_txn
        .internal_search_conflict_uuid(t_uuid)
        .expect("Unable to conflict entries.");
    assert!(cnf_b.is_empty());

    trace!("TESTMARKER 2");
    trace!(?cnf_a);
    trace!(?cnf_b);

    server_a_txn.commit().expect("Failed to commit");
    drop(server_b_txn);

    // At this point server a now has the conflict entry, and we have to confirm
    // it can be sent to b.

    let mut server_a_txn = server_a.read().await.unwrap();
    let mut server_b_txn = server_b.write(duration_from_epoch_now()).await.unwrap();

    trace!("========================================");
    repl_incremental(&mut server_a_txn, &mut server_b_txn);

    // Now the repl should have caused the conflict to be on both sides.
    let cnf_a = server_a_txn
        .internal_search_conflict_uuid(t_uuid)
        .expect("Unable to conflict entries.")
        // Should be a vec.
        .pop()
        .expect("No conflict entries present");

    let cnf_b = server_b_txn
        .internal_search_conflict_uuid(t_uuid)
        .expect("Unable to conflict entries.")
        // Should be a vec.
        .pop()
        .expect("No conflict entries present");

    trace!("TESTMARKER 3");
    trace!(?cnf_a);
    trace!(?cnf_b);

    assert_eq!(cnf_a.get_last_changed(), cnf_b.get_last_changed());

    let e1 = server_a_txn
        .internal_search_all_uuid(t_uuid)
        .expect("Unable to access new entry.");
    let e2 = server_b_txn
        .internal_search_all_uuid(t_uuid)
        .expect("Unable to access entry.");

    let e1_acc = server_a_txn
        .internal_search_all_uuid(UUID_IDM_ALL_ACCOUNTS)
        .expect("Unable to access new entry.");
    let e2_acc = server_b_txn
        .internal_search_all_uuid(UUID_IDM_ALL_ACCOUNTS)
        .expect("Unable to access entry.");

    trace!("TESTMARKER 4");
    trace!(?e1);
    trace!(?e2);
    trace!(?e1_acc);
    trace!(?e2_acc);

    server_b_txn.commit().expect("Failed to commit");
    drop(server_a_txn);
}

// both add entry with same uuid, but one becomes ts - ts always wins.
#[qs_pair_test]
async fn test_repl_increment_create_tombstone_uuid_conflict(
    server_a: &QueryServer,
    server_b: &QueryServer,
) {
    let ct = duration_from_epoch_now();
    let mut server_a_txn = server_a.write(ct).await.unwrap();
    let mut server_b_txn = server_b.read().await.unwrap();

    assert!(repl_initialise(&mut server_b_txn, &mut server_a_txn).is_ok());

    server_a_txn.commit().expect("Failed to commit");
    drop(server_b_txn);

    // Now create the same entry on both servers.
    let t_uuid = Uuid::new_v4();
    let e_init = entry_init!(
        (Attribute::Class, EntryClass::Object.to_value()),
        (Attribute::Class, EntryClass::Account.to_value()),
        (Attribute::Class, EntryClass::Person.to_value()),
        (Attribute::Name, Value::new_iname("testperson1")),
        (Attribute::Uuid, Value::Uuid(t_uuid)),
        (Attribute::Description, Value::new_utf8s("testperson1")),
        (Attribute::DisplayName, Value::new_utf8s("testperson1"))
    );

    let mut server_b_txn = server_b.write(ct).await.unwrap();
    assert!(server_b_txn.internal_create(vec![e_init.clone(),]).is_ok());
    server_b_txn.commit().expect("Failed to commit");

    // Since A was added second, this should normal be the entry that loses in the
    // conflict resolve case, but here because it's tombstoned, we actually see it
    // persist

    // Get a new time.
    let ct = duration_from_epoch_now();
    let mut server_a_txn = server_a.write(ct).await.unwrap();
    assert!(server_a_txn.internal_create(vec![e_init.clone(),]).is_ok());
    // Immediately send it to the shadow realm
    assert!(server_a_txn.internal_delete_uuid(t_uuid).is_ok());
    server_a_txn.commit().expect("Failed to commit");

    // Tombstone the entry.
    let ct = ct + Duration::from_secs(RECYCLEBIN_MAX_AGE + 1);
    let mut server_a_txn = server_a.write(ct).await.unwrap();
    assert!(server_a_txn.purge_recycled().is_ok());
    server_a_txn.commit().expect("Failed to commit");

    // Do B -> A - no change on A. Normally this would create the conflict
    // on A since it's the origin, but here since it's a TS it now takes
    // precedence.
    let mut server_a_txn = server_a.write(ct).await.unwrap();
    let mut server_b_txn = server_b.read().await.unwrap();

    trace!("========================================");
    repl_incremental(&mut server_b_txn, &mut server_a_txn);

    let e1 = server_a_txn
        .internal_search_all_uuid(t_uuid)
        .expect("Unable to access new entry.");
    let e2 = server_b_txn
        .internal_search_all_uuid(t_uuid)
        .expect("Unable to access entry.");
    assert!(e1 != e2);
    // E1 from A is a ts
    assert!(e1.attribute_equality(Attribute::Class, &EntryClass::Tombstone.into()));
    // E2 from B is not a TS
    assert!(!e2.attribute_equality(Attribute::Class, &EntryClass::Tombstone.into()));

    server_a_txn.commit().expect("Failed to commit");
    drop(server_b_txn);

    // Now A -> B - this should cause B to become a TS even though it's AT is
    // earlier.
    let mut server_a_txn = server_a.read().await.unwrap();
    let mut server_b_txn = server_b.write(duration_from_epoch_now()).await.unwrap();

    trace!("========================================");
    repl_incremental(&mut server_a_txn, &mut server_b_txn);

    let e1 = server_a_txn
        .internal_search_all_uuid(t_uuid)
        .expect("Unable to access new entry.");
    let e2 = server_b_txn
        .internal_search_all_uuid(t_uuid)
        .expect("Unable to access entry.");
    assert_eq!(e1, e2);
    assert!(e1.attribute_equality(Attribute::Class, &EntryClass::Tombstone.into()));

    server_b_txn.commit().expect("Failed to commit");
    drop(server_a_txn);
}

// both add entry with same uuid, both become ts - merge, take lowest AT.
#[qs_pair_test]
async fn test_repl_increment_create_tombstone_conflict(
    server_a: &QueryServer,
    server_b: &QueryServer,
) {
    let ct = duration_from_epoch_now();
    let mut server_a_txn = server_a.write(ct).await.unwrap();
    let mut server_b_txn = server_b.read().await.unwrap();

    assert!(repl_initialise(&mut server_b_txn, &mut server_a_txn).is_ok());

    server_a_txn.commit().expect("Failed to commit");
    drop(server_b_txn);

    // Now create the same entry on both servers.
    let t_uuid = Uuid::new_v4();
    let e_init = entry_init!(
        (Attribute::Class, EntryClass::Object.to_value()),
        (Attribute::Class, EntryClass::Account.to_value()),
        (Attribute::Class, EntryClass::Person.to_value()),
        (Attribute::Name, Value::new_iname("testperson1")),
        (Attribute::Uuid, Value::Uuid(t_uuid)),
        (Attribute::Description, Value::new_utf8s("testperson1")),
        (Attribute::DisplayName, Value::new_utf8s("testperson1"))
    );

    let mut server_b_txn = server_b.write(ct).await.unwrap();
    assert!(server_b_txn.internal_create(vec![e_init.clone(),]).is_ok());
    // Immediately send it to the shadow realm
    assert!(server_b_txn.internal_delete_uuid(t_uuid).is_ok());
    server_b_txn.commit().expect("Failed to commit");

    // Get a new time.
    let ct = ct + Duration::from_secs(1);
    let mut server_a_txn = server_a.write(ct).await.unwrap();
    assert!(server_a_txn.internal_create(vec![e_init.clone(),]).is_ok());
    // Immediately send it to the shadow realm
    assert!(server_a_txn.internal_delete_uuid(t_uuid).is_ok());
    server_a_txn.commit().expect("Failed to commit");

    // Tombstone on both sides.
    let ct = ct + Duration::from_secs(RECYCLEBIN_MAX_AGE + 1);
    let mut server_b_txn = server_b.write(ct).await.unwrap();
    assert!(server_b_txn.purge_recycled().is_ok());
    server_b_txn.commit().expect("Failed to commit");

    let ct = ct + Duration::from_secs(1);
    let mut server_a_txn = server_a.write(ct).await.unwrap();
    assert!(server_a_txn.purge_recycled().is_ok());
    server_a_txn.commit().expect("Failed to commit");

    // Since B was tombstoned first, it is the tombstone that should persist.

    // This means A -> B - no change on B, it's the persisting tombstone.
    let ct = ct + Duration::from_secs(1);
    let mut server_a_txn = server_a.read().await.unwrap();
    let mut server_b_txn = server_b.write(ct).await.unwrap();

    trace!("========================================");
    repl_incremental(&mut server_a_txn, &mut server_b_txn);

    let e1 = server_a_txn
        .internal_search_all_uuid(t_uuid)
        .expect("Unable to access new entry.");
    let e2 = server_b_txn
        .internal_search_all_uuid(t_uuid)
        .expect("Unable to access entry.");

    assert!(e1.get_last_changed() > e2.get_last_changed());
    // Yet, they are both TS. Curious.
    assert!(e1.attribute_equality(Attribute::Class, &EntryClass::Tombstone.into()));
    assert!(e2.attribute_equality(Attribute::Class, &EntryClass::Tombstone.into()));

    server_b_txn.commit().expect("Failed to commit");
    drop(server_a_txn);

    // B -> A - A should now have the lower AT reflected.
    let mut server_a_txn = server_a.write(ct).await.unwrap();
    let mut server_b_txn = server_b.read().await.unwrap();

    trace!("========================================");
    repl_incremental(&mut server_b_txn, &mut server_a_txn);

    let e1 = server_a_txn
        .internal_search_all_uuid(t_uuid)
        .expect("Unable to access new entry.");
    let e2 = server_b_txn
        .internal_search_all_uuid(t_uuid)
        .expect("Unable to access entry.");

    assert_eq!(e1, e2);
    assert!(e1.attribute_equality(Attribute::Class, &EntryClass::Tombstone.into()));

    server_a_txn.commit().expect("Failed to commit");
    drop(server_b_txn);
}

// Test schema conflict state - add attr A on one side, and then remove the supporting
// class on the other. On repl both sides move to conflict.
#[qs_pair_test]
async fn test_repl_increment_schema_conflict(server_a: &QueryServer, server_b: &QueryServer) {
    let ct = duration_from_epoch_now();
    let mut server_a_txn = server_a.write(ct).await.unwrap();
    let mut server_b_txn = server_b.read().await.unwrap();

    assert!(repl_initialise(&mut server_b_txn, &mut server_a_txn).is_ok());

    server_a_txn.commit().expect("Failed to commit");
    drop(server_b_txn);

    // Setup the entry we plan to break.
    let mut server_b_txn = server_b.write(ct).await.unwrap();
    let t_uuid = Uuid::new_v4();
    assert!(server_b_txn
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
    server_b_txn.commit().expect("Failed to commit");

    let mut server_a_txn = server_a.write(ct).await.unwrap();
    let mut server_b_txn = server_b.read().await.unwrap();

    trace!("========================================");
    repl_incremental(&mut server_b_txn, &mut server_a_txn);

    let e1 = server_a_txn
        .internal_search_all_uuid(t_uuid)
        .expect("Unable to access new entry.");
    let e2 = server_b_txn
        .internal_search_all_uuid(t_uuid)
        .expect("Unable to access entry.");

    assert_eq!(e1, e2);

    server_a_txn.commit().expect("Failed to commit");
    drop(server_b_txn);

    // Now at this point we need to write to both sides. The order *does* matter
    // here because we need the displayname write to happen *after* the purge
    // on the B node.

    // This is a really rare/wild change to swap an object out to a group but it
    // works well for our test here.
    let ct = ct + Duration::from_secs(1);
    let mut server_b_txn = server_b.write(ct).await.unwrap();
    let modlist = ModifyList::new_list(vec![
        Modify::Removed(Attribute::Class, EntryClass::Person.into()),
        Modify::Removed(Attribute::Class, EntryClass::Account.into()),
        Modify::Present(Attribute::Class, EntryClass::Group.into()),
        Modify::Purged(Attribute::NameHistory),
        Modify::Purged(Attribute::DisplayName),
    ]);
    assert!(server_b_txn.internal_modify_uuid(t_uuid, &modlist).is_ok());
    server_b_txn.commit().expect("Failed to commit");

    // On A we'll change the displayname which is predicated on being a person still
    let ct = ct + Duration::from_secs(1);
    let mut server_a_txn = server_a.write(ct).await.unwrap();
    assert!(server_a_txn
        .internal_modify_uuid(
            t_uuid,
            &ModifyList::new_purge_and_set(
                Attribute::DisplayName,
                Value::Utf8("Updated displayname".to_string())
            )
        )
        .is_ok());
    server_a_txn.commit().expect("Failed to commit");

    // Now we have to replicate again. It shouldn't matter *which* direction we go first
    // because *both* should end in the conflict state.
    //
    // B -> A
    let mut server_a_txn = server_a.write(ct).await.unwrap();
    let mut server_b_txn = server_b.read().await.unwrap();

    trace!("========================================");
    repl_incremental(&mut server_b_txn, &mut server_a_txn);

    let e1 = server_a_txn
        .internal_search_all_uuid(t_uuid)
        .expect("Unable to access new entry.");

    trace!(?e1);

    assert!(e1.attribute_equality(Attribute::Class, &EntryClass::Conflict.into()));

    server_a_txn.commit().expect("Failed to commit");
    drop(server_b_txn);

    // A -> B
    let mut server_a_txn = server_a.read().await.unwrap();
    let mut server_b_txn = server_b.write(duration_from_epoch_now()).await.unwrap();

    trace!("========================================");
    repl_incremental(&mut server_a_txn, &mut server_b_txn);

    let e2 = server_b_txn
        .internal_search_all_uuid(t_uuid)
        .expect("Unable to access entry.");

    assert!(e2.attribute_equality(Attribute::Class, &EntryClass::Conflict.into()));

    server_b_txn.commit().expect("Failed to commit");
    drop(server_a_txn);
}

// Test RUV content when a server's changes have been trimmed out and are not present
// in a refresh. This is not about tombstones, this is about attribute state.
#[qs_pair_test]
async fn test_repl_increment_consumer_lagging_attributes(
    server_a: &QueryServer,
    server_b: &QueryServer,
) {
    let ct = duration_from_epoch_now();

    let mut server_a_txn = server_a.write(ct).await.unwrap();
    let mut server_b_txn = server_b.read().await.unwrap();

    assert!(repl_initialise(&mut server_b_txn, &mut server_a_txn)
        .and_then(|_| server_a_txn.commit())
        .is_ok());
    drop(server_b_txn);

    // Add an entry.
    let mut server_b_txn = server_b.write(ct).await.unwrap();
    let t_uuid = Uuid::new_v4();
    assert!(server_b_txn
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

    server_b_txn.commit().expect("Failed to commit");

    // Now setup bidirectional replication. We only need to trigger B -> A
    // here because that's all that has changes.
    let mut server_a_txn = server_a.write(ct).await.unwrap();
    let mut server_b_txn = server_b.read().await.unwrap();

    trace!("========================================");
    repl_incremental(&mut server_b_txn, &mut server_a_txn);

    let e1 = server_a_txn
        .internal_search_all_uuid(t_uuid)
        .expect("Unable to access entry.");
    let e2 = server_b_txn
        .internal_search_all_uuid(t_uuid)
        .expect("Unable to access entry.");

    assert_eq!(e1, e2);

    server_a_txn.commit().expect("Failed to commit");
    drop(server_b_txn);

    // Okay, now we do a change on B and then we'll push time ahead of changelog
    // ruv trim. This should mean that the indexes to find those changes are lost.
    let ct = ct + Duration::from_secs(1);
    let mut server_b_txn = server_b.write(ct).await.unwrap();
    assert!(server_b_txn
        .internal_modify_uuid(
            t_uuid,
            &ModifyList::new_purge_and_set(
                Attribute::DisplayName,
                Value::Utf8("Updated displayname".to_string())
            )
        )
        .is_ok());
    server_b_txn.commit().expect("Failed to commit");

    // Now we advance the time.
    let ct = ct + Duration::from_secs(CHANGELOG_MAX_AGE + 1);

    // And setup the ruv trim. This is triggered by purge/reap tombstones.
    let mut server_b_txn = server_b.write(ct).await.unwrap();
    assert!(server_b_txn.purge_tombstones().is_ok());
    server_b_txn.commit().expect("Failed to commit");

    // Okay, ready to go. When we do A -> B or B -> A we should get appropriate
    // errors regarding the delay state.
    let mut server_a_txn = server_a.write(ct).await.unwrap();
    let mut server_b_txn = server_b.read().await.unwrap();

    let a_ruv_range = server_a_txn
        .consumer_get_state()
        .expect("Unable to access RUV range");

    let changes = server_b_txn
        .supplier_provide_changes(a_ruv_range)
        .expect("Unable to generate supplier changes");

    assert!(matches!(changes, ReplIncrementalContext::RefreshRequired));

    let result = server_a_txn
        .consumer_apply_changes(changes)
        .expect("Unable to apply changes to consumer.");

    assert!(matches!(result, ConsumerState::RefreshRequired));

    drop(server_a_txn);
    drop(server_b_txn);

    // Reverse it!
    let mut server_a_txn = server_a.read().await.unwrap();
    let mut server_b_txn = server_b.write(ct).await.unwrap();

    let b_ruv_range = server_b_txn
        .consumer_get_state()
        .expect("Unable to access RUV range");

    let changes = server_a_txn
        .supplier_provide_changes(b_ruv_range)
        .expect("Unable to generate supplier changes");

    assert!(matches!(changes, ReplIncrementalContext::UnwillingToSupply));

    let result = server_b_txn
        .consumer_apply_changes(changes)
        .expect("Unable to apply changes to consumer.");

    assert!(matches!(result, ConsumerState::Ok));

    drop(server_a_txn);
    drop(server_b_txn);
}

// Test two synchronised nodes where no changes occurred in a TS/RUV window.
#[qs_pair_test]
async fn test_repl_increment_consumer_ruv_trim_past_valid(
    server_a: &QueryServer,
    server_b: &QueryServer,
) {
    let ct = duration_from_epoch_now();

    let mut server_a_txn = server_a.write(ct).await.unwrap();
    let mut server_b_txn = server_b.read().await.unwrap();

    assert!(repl_initialise(&mut server_b_txn, &mut server_a_txn)
        .and_then(|_| server_a_txn.commit())
        .is_ok());
    drop(server_b_txn);

    // Add an entry. We need at least one change on B, else it won't have anything
    // to ship in it's RUV to A.
    let ct = duration_from_epoch_now();
    let mut server_b_txn = server_b.write(ct).await.unwrap();
    let t_uuid = Uuid::new_v4();
    assert!(server_b_txn
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

    server_b_txn.commit().expect("Failed to commit");

    // Now setup bidirectional replication. We only need to trigger B -> A
    // here because that's all that has changes.
    let ct = duration_from_epoch_now();
    let mut server_a_txn = server_a.write(ct).await.unwrap();
    let mut server_b_txn = server_b.read().await.unwrap();

    trace!("========================================");
    repl_incremental(&mut server_b_txn, &mut server_a_txn);

    let e1 = server_a_txn
        .internal_search_all_uuid(t_uuid)
        .expect("Unable to access entry.");
    let e2 = server_b_txn
        .internal_search_all_uuid(t_uuid)
        .expect("Unable to access entry.");

    assert_eq!(e1, e2);

    server_a_txn.commit().expect("Failed to commit");
    drop(server_b_txn);

    // Everything is consistent!

    // Compare RUV's

    // Push time ahead past a changelog max age.
    let ct = ct + Duration::from_secs(CHANGELOG_MAX_AGE * 4);

    // And setup the ruv trim. This is triggered by purge/reap tombstones.
    // Apply this to both nodes so that they shift their RUV states.
    let mut server_a_txn = server_a.write(ct).await.unwrap();
    assert!(server_a_txn.purge_tombstones().is_ok());
    server_a_txn.commit().expect("Failed to commit");

    let mut server_b_txn = server_b.write(ct).await.unwrap();
    assert!(server_b_txn.purge_tombstones().is_ok());
    server_b_txn.commit().expect("Failed to commit");

    // At this point, purge_tombstones now writes an anchor cid to the RUV, which means
    // both servers will detect the deception and error.

    // Now check incremental in both directions. Should show *no* changes
    // needed (rather than an error/lagging).
    let mut server_a_txn = server_a.write(ct).await.unwrap();
    let mut server_b_txn = server_b.read().await.unwrap();

    let a_ruv_range = server_a_txn
        .consumer_get_state()
        .expect("Unable to access RUV range");

    trace!(?a_ruv_range);

    let changes = server_b_txn
        .supplier_provide_changes(a_ruv_range)
        .expect("Unable to generate supplier changes");

    trace!(?changes);

    assert!(matches!(changes, ReplIncrementalContext::UnwillingToSupply));

    let result = server_a_txn
        .consumer_apply_changes(changes)
        .expect("Unable to apply changes to consumer.");

    assert!(matches!(result, ConsumerState::Ok));

    drop(server_a_txn);
    drop(server_b_txn);

    // Reverse it!
    let mut server_a_txn = server_a.read().await.unwrap();
    let mut server_b_txn = server_b.write(ct).await.unwrap();

    let b_ruv_range = server_b_txn
        .consumer_get_state()
        .expect("Unable to access RUV range");

    trace!(?b_ruv_range);

    let changes = server_a_txn
        .supplier_provide_changes(b_ruv_range)
        .expect("Unable to generate supplier changes");

    trace!(?changes);

    assert!(matches!(changes, ReplIncrementalContext::UnwillingToSupply));

    let result = server_b_txn
        .consumer_apply_changes(changes)
        .expect("Unable to apply changes to consumer.");

    assert!(matches!(result, ConsumerState::Ok));

    drop(server_a_txn);
    drop(server_b_txn);
}

// Test two synchronised nodes where changes are not occurring - this situation would previously
// cause issues because when a change did occur, the ruv would "jump" ahead and cause desyncs.w
#[qs_pair_test]
async fn test_repl_increment_consumer_ruv_trim_idle_servers(
    server_a: &QueryServer,
    server_b: &QueryServer,
) {
    let ct = duration_from_epoch_now();
    let changelog_quarter_life = Duration::from_secs(CHANGELOG_MAX_AGE / 4);
    let one_second = Duration::from_secs(1);

    let mut server_a_txn = server_a.write(ct).await.unwrap();
    let mut server_b_txn = server_b.read().await.unwrap();

    assert!(repl_initialise(&mut server_b_txn, &mut server_a_txn)
        .and_then(|_| server_a_txn.commit())
        .is_ok());
    drop(server_b_txn);

    // Add an entry. We need at least one change on B, else it won't have anything
    // to ship in it's RUV to A.
    let ct = ct + one_second;
    let mut server_b_txn = server_b.write(ct).await.unwrap();
    let t_uuid = Uuid::new_v4();
    assert!(server_b_txn
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

    server_b_txn.commit().expect("Failed to commit");

    // Now setup bidirectional replication. We only need to trigger B -> A
    // here because that's all that has changes.
    let ct = ct + one_second;
    let mut server_a_txn = server_a.write(ct).await.unwrap();
    let mut server_b_txn = server_b.read().await.unwrap();

    trace!("========================================");
    repl_incremental(&mut server_b_txn, &mut server_a_txn);

    let e1 = server_a_txn
        .internal_search_all_uuid(t_uuid)
        .expect("Unable to access entry.");
    let e2 = server_b_txn
        .internal_search_all_uuid(t_uuid)
        .expect("Unable to access entry.");

    assert_eq!(e1, e2);

    server_a_txn.commit().expect("Failed to commit");
    drop(server_b_txn);

    // Everything is consistent!
    let mut ct = ct;

    // We now loop periodically, and everything should stay in sync.
    for i in 0..8 {
        trace!("========================================");
        trace!("repl iteration {}", i);
        // Purge tombstones.
        let mut server_a_txn = server_a.write(ct).await.unwrap();
        assert!(server_a_txn.purge_tombstones().is_ok());
        server_a_txn.commit().expect("Failed to commit");

        ct += one_second;

        let mut server_b_txn = server_b.write(ct).await.unwrap();
        assert!(server_b_txn.purge_tombstones().is_ok());
        server_b_txn.commit().expect("Failed to commit");

        ct += one_second;

        // Now check incremental in both directions. Should show *no* changes
        // needed (rather than an error/lagging).
        let mut server_a_txn = server_a.write(ct).await.unwrap();
        let mut server_b_txn = server_b.read().await.unwrap();

        let a_ruv_range = server_a_txn
            .consumer_get_state()
            .expect("Unable to access RUV range");

        trace!(?a_ruv_range);

        let changes = server_b_txn
            .supplier_provide_changes(a_ruv_range)
            .expect("Unable to generate supplier changes");

        assert!(matches!(changes, ReplIncrementalContext::V1 { .. }));

        let result = server_a_txn
            .consumer_apply_changes(changes)
            .expect("Unable to apply changes to consumer.");

        assert!(matches!(result, ConsumerState::Ok));

        server_a_txn.commit().expect("Failed to commit");
        drop(server_b_txn);

        ct += one_second;

        // Reverse it!
        let mut server_a_txn = server_a.read().await.unwrap();
        let mut server_b_txn = server_b.write(ct).await.unwrap();

        let b_ruv_range = server_b_txn
            .consumer_get_state()
            .expect("Unable to access RUV range");

        trace!(?b_ruv_range);

        let changes = server_a_txn
            .supplier_provide_changes(b_ruv_range)
            .expect("Unable to generate supplier changes");

        assert!(matches!(changes, ReplIncrementalContext::V1 { .. }));

        let result = server_b_txn
            .consumer_apply_changes(changes)
            .expect("Unable to apply changes to consumer.");

        assert!(matches!(result, ConsumerState::Ok));

        drop(server_a_txn);
        server_b_txn.commit().expect("Failed to commit");

        ct += changelog_quarter_life;
    }

    // Done!
}

// Test change of a domain name over incremental.
#[qs_pair_test]
async fn test_repl_increment_domain_rename(server_a: &QueryServer, server_b: &QueryServer) {
    let ct = duration_from_epoch_now();

    let mut server_a_txn = server_a.write(ct).await.unwrap();
    let mut server_b_txn = server_b.read().await.unwrap();

    assert!(repl_initialise(&mut server_b_txn, &mut server_a_txn)
        .and_then(|_| server_a_txn.commit())
        .is_ok());
    drop(server_b_txn);

    // Rename the domain. We do this on server_a.
    let mut server_a_txn = server_a.write(ct).await.unwrap();
    assert!(server_a_txn
        .danger_domain_rename("new.example.com")
        .and_then(|_| server_a_txn.commit())
        .is_ok());

    // Add an entry to server_b. This should have it's spn regenerated after
    // the domain rename is replicated.
    // - satisfies:
    // Test domain rename where the receiver of the rename has added entries, and
    // they need spn regen to stabilise.

    let mut server_b_txn = server_b.write(duration_from_epoch_now()).await.unwrap();
    let t_uuid = Uuid::new_v4();
    assert!(server_b_txn
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
    server_b_txn.commit().expect("Failed to commit");

    // Now replicate from a to b. This will be fun won't it.
    // This means A -> B - no change on B, it's the persisting tombstone.
    let mut server_a_txn = server_a.read().await.unwrap();
    let mut server_b_txn = server_b.write(duration_from_epoch_now()).await.unwrap();

    trace!("========================================");
    repl_incremental(&mut server_a_txn, &mut server_b_txn);

    let e1 = server_a_txn
        .internal_search_all_uuid(UUID_DOMAIN_INFO)
        .expect("Unable to access new entry.");
    let e2 = server_b_txn
        .internal_search_all_uuid(UUID_DOMAIN_INFO)
        .expect("Unable to access entry.");

    assert_eq!(e1, e2);

    let e1_cs = e1.get_changestate();
    let e2_cs = e2.get_changestate();
    assert_eq!(e1_cs, e2_cs);

    // Check that an existing user was updated properly.
    let e1 = server_a_txn
        .internal_search_all_uuid(UUID_ADMIN)
        .expect("Unable to access new entry.");
    let e2 = server_b_txn
        .internal_search_all_uuid(UUID_ADMIN)
        .expect("Unable to access entry.");

    let vx1 = e1.get_ava_single(Attribute::Spn).expect("spn not present");
    let ex1 = Value::new_spn_str("admin", "new.example.com");
    assert_eq!(vx1, ex1);

    trace!(?e1);
    trace!(?e2);
    assert_eq!(e1, e2);

    // Due to the domain rename, the spn regens on everything. This only occurs
    // once per-replica, and is not unlimited.
    let e1_cs = e1.get_changestate();
    let e2_cs = e2.get_changestate();

    trace!(?e1_cs);
    trace!(?e2_cs);
    assert!(e1_cs != e2_cs);

    // Check that the user on server_b had it's spn regenerated too.
    assert_eq!(
        server_a_txn.internal_search_uuid(t_uuid),
        Err(OperationError::NoMatchingEntries)
    );

    let e2 = server_b_txn
        .internal_search_all_uuid(t_uuid)
        .expect("Unable to access entry.");

    let vx2 = e2.get_ava_single(Attribute::Spn).expect("spn not present");
    let ex2 = Value::new_spn_str("testperson1", "new.example.com");
    assert_eq!(vx2, ex2);

    server_b_txn.commit().expect("Failed to commit");
    drop(server_a_txn);

    // Now we have to check a bunch of things are correct after the domain
    // rename has completed. Generally this is that the spn is now correct and
    // our other configs have reloaded.
    //
    // Possible to check the webauthn rp_id?

    let mut server_a_txn = server_a.write(duration_from_epoch_now()).await.unwrap();
    let mut server_b_txn = server_b.read().await.unwrap();

    trace!("========================================");
    //               from               to
    repl_incremental(&mut server_b_txn, &mut server_a_txn);

    // Check the admin is now in sync
    let e1 = server_a_txn
        .internal_search_all_uuid(UUID_ADMIN)
        .expect("Unable to access new entry.");
    let e2 = server_b_txn
        .internal_search_all_uuid(UUID_ADMIN)
        .expect("get_ava_single(spn).");

    let vx1 = e1.get_ava_single(Attribute::Spn).expect("spn not present");
    let ex1 = Value::new_spn_str("admin", "new.example.com");
    assert_eq!(vx1, ex1);
    assert_eq!(e1, e2);

    let e1_cs = e1.get_changestate();
    let e2_cs = e2.get_changestate();
    assert_eq!(e1_cs, e2_cs);

    // Check the test person is back over and now in sync.
    let e1 = server_a_txn
        .internal_search_all_uuid(t_uuid)
        .expect("Unable to access entry.");
    let e2 = server_b_txn
        .internal_search_all_uuid(t_uuid)
        .expect("Unable to access entry.");

    let vx2 = e2.get_ava_single(Attribute::Spn).expect("spn not present");
    let ex2 = Value::new_spn_str("testperson1", "new.example.com");
    assert_eq!(vx2, ex2);
    assert_eq!(e1, e2);

    let e1_cs = e1.get_changestate();
    let e2_cs = e2.get_changestate();
    assert_eq!(e1_cs, e2_cs);

    server_a_txn.commit().expect("Failed to commit");
    drop(server_b_txn);
}

// Test schema addition / change over incremental.
#[qs_pair_test]
async fn test_repl_increment_schema_dynamic(server_a: &QueryServer, server_b: &QueryServer) {
    let ct = duration_from_epoch_now();

    let mut server_a_txn = server_a.write(ct).await.unwrap();
    let mut server_b_txn = server_b.read().await.unwrap();

    assert!(repl_initialise(&mut server_b_txn, &mut server_a_txn)
        .and_then(|_| server_a_txn.commit())
        .is_ok());
    drop(server_b_txn);

    let mut server_a_txn = server_a.write(ct).await.unwrap();
    // Add a new schema entry/item.
    let s_uuid = Uuid::new_v4();
    assert!(server_a_txn
        .internal_create(vec![entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::ClassType.to_value()),
            (Attribute::ClassName, EntryClass::TestClass.to_value()),
            (Attribute::Uuid, Value::Uuid(s_uuid)),
            (Attribute::Description, Value::new_utf8s("Test Class")),
            (Attribute::May, Value::from(Attribute::Name))
        )])
        .is_ok());
    // Schema doesn't take effect til after a commit.
    server_a_txn.commit().expect("Failed to commit");

    // Now use the new schema in an entry.
    let mut server_a_txn = server_a.write(ct).await.unwrap();
    let t_uuid = Uuid::new_v4();
    assert!(server_a_txn
        .internal_create(vec![entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::TestClass.to_value()),
            (Attribute::Uuid, Value::Uuid(t_uuid))
        )])
        .is_ok());

    server_a_txn.commit().expect("Failed to commit");

    // Now replicate from A to B. B should not only get the new schema,
    // but should accept the entry that was created.

    let mut server_a_txn = server_a.read().await.unwrap();
    let mut server_b_txn = server_b.write(ct).await.unwrap();

    trace!("========================================");
    repl_incremental(&mut server_a_txn, &mut server_b_txn);

    let e1 = server_a_txn
        .internal_search_all_uuid(s_uuid)
        .expect("Unable to access new entry.");
    let e2 = server_b_txn
        .internal_search_all_uuid(s_uuid)
        .expect("Unable to access entry.");

    assert_eq!(e1, e2);

    let e1 = server_a_txn
        .internal_search_all_uuid(t_uuid)
        .expect("Unable to access new entry.");
    let e2 = server_b_txn
        .internal_search_all_uuid(t_uuid)
        .expect("Unable to access entry.");

    assert_eq!(e1, e2);

    server_b_txn.commit().expect("Failed to commit");
    drop(server_a_txn);
}

// Test memberof over replication boundaries.
#[qs_pair_test]
async fn test_repl_increment_memberof_basic(server_a: &QueryServer, server_b: &QueryServer) {
    let ct = duration_from_epoch_now();

    let mut server_a_txn = server_a.write(ct).await.unwrap();
    let mut server_b_txn = server_b.read().await.unwrap();

    assert!(repl_initialise(&mut server_b_txn, &mut server_a_txn)
        .and_then(|_| server_a_txn.commit())
        .is_ok());
    drop(server_b_txn);

    // Since memberof isn't replicated, we have to check that when a group with
    // a member is sent over, it's re-calced on the other side.

    let mut server_a_txn = server_a.write(duration_from_epoch_now()).await.unwrap();
    let t_uuid = Uuid::new_v4();
    assert!(server_a_txn
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

    let g_uuid = Uuid::new_v4();
    assert!(server_a_txn
        .internal_create(vec![entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Group.to_value()),
            (Attribute::Name, Value::new_iname("testgroup1")),
            (Attribute::Uuid, Value::Uuid(g_uuid)),
            (Attribute::Member, Value::Refer(t_uuid))
        ),])
        .is_ok());

    server_a_txn.commit().expect("Failed to commit");

    // Now replicated A -> B

    let mut server_a_txn = server_a.read().await.unwrap();
    let mut server_b_txn = server_b.write(ct).await.unwrap();

    trace!("========================================");
    repl_incremental(&mut server_a_txn, &mut server_b_txn);

    let e1 = server_a_txn
        .internal_search_all_uuid(g_uuid)
        .expect("Unable to access new entry.");
    let e2 = server_b_txn
        .internal_search_all_uuid(g_uuid)
        .expect("Unable to access entry.");

    assert_eq!(e1, e2);

    let e1 = server_a_txn
        .internal_search_all_uuid(t_uuid)
        .expect("Unable to access new entry.");
    let e2 = server_b_txn
        .internal_search_all_uuid(t_uuid)
        .expect("Unable to access entry.");

    assert_eq!(e1, e2);
    assert!(e1.attribute_equality(Attribute::MemberOf, &PartialValue::Refer(g_uuid)));
    // We should also check dyngroups too here :)
    assert!(e1.attribute_equality(
        Attribute::MemberOf,
        &PartialValue::Refer(UUID_IDM_ALL_ACCOUNTS)
    ));

    server_b_txn.commit().expect("Failed to commit");
    drop(server_a_txn);
}

// Test when a group has a member A, and then the group is conflicted, that when
// group is moved to conflict the memberShip of A is removed. The conflict must be
// a non group, or a group that doesn't have the member A.
#[qs_pair_test]
async fn test_repl_increment_memberof_conflict(server_a: &QueryServer, server_b: &QueryServer) {
    let ct = duration_from_epoch_now();

    let mut server_a_txn = server_a.write(ct).await.unwrap();
    let mut server_b_txn = server_b.read().await.unwrap();

    assert!(repl_initialise(&mut server_b_txn, &mut server_a_txn)
        .and_then(|_| server_a_txn.commit())
        .is_ok());
    drop(server_b_txn);

    // First, we need to create a group on b that will conflict. This needs to be
    // at a time point earlier than A.
    let mut server_b_txn = server_b.write(ct).await.unwrap();
    let g_uuid = Uuid::new_v4();

    assert!(server_b_txn
        .internal_create(vec![entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Group.to_value()),
            (Attribute::Name, Value::new_iname("testgroup_conflict")),
            (Attribute::Uuid, Value::Uuid(g_uuid))
        ),])
        .is_ok());

    server_b_txn.commit().expect("Failed to commit");

    // Advance the clock so that A's operation is later than B
    let ct = ct + Duration::from_secs(1);
    // Now on a, use the same uuid, make the user and a group as it's member.
    let mut server_a_txn = server_a.write(ct).await.unwrap();
    let t_uuid = Uuid::new_v4();
    assert!(server_a_txn
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

    assert!(server_a_txn
        .internal_create(vec![entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Group.to_value()),
            (Attribute::Name, Value::new_iname("testgroup1")),
            // This UUID is what will conflict
            (Attribute::Uuid, Value::Uuid(g_uuid)),
            (Attribute::Member, Value::Refer(t_uuid))
        ),])
        .is_ok());

    server_a_txn.commit().expect("Failed to commit");

    // Now do A -> B. B should show that the second group was a conflict and
    // the membership drops.
    let ct = ct + Duration::from_secs(1);
    let mut server_a_txn = server_a.read().await.unwrap();
    let mut server_b_txn = server_b.write(ct).await.unwrap();

    trace!("========================================");
    repl_incremental(&mut server_a_txn, &mut server_b_txn);

    let e = server_b_txn
        .internal_search_all_uuid(g_uuid)
        .expect("Unable to access entry.");
    assert!(!e.attribute_equality(Attribute::Member, &PartialValue::Refer(t_uuid)));
    assert!(e.attribute_equality(
        Attribute::Name,
        &PartialValue::new_iname("testgroup_conflict")
    ));

    let e = server_b_txn
        .internal_search_all_uuid(t_uuid)
        .expect("Unable to access entry.");
    assert!(!e.attribute_equality(Attribute::MemberOf, &PartialValue::Refer(g_uuid)));

    server_b_txn.commit().expect("Failed to commit");
    drop(server_a_txn);

    // Now B -> A. A will now reflect the conflict as well, causing the local group on A
    // to become a conflict, and the group from B will take over. This causes the membership
    // on test user to be dropped.
    let ct = ct + Duration::from_secs(1);
    let mut server_b_txn = server_b.read().await.unwrap();
    let mut server_a_txn = server_a.write(ct).await.unwrap();

    trace!("========================================");
    repl_incremental(&mut server_b_txn, &mut server_a_txn);

    let e1 = server_a_txn
        .internal_search_all_uuid(g_uuid)
        .expect("Unable to access entry.");
    let e2 = server_b_txn
        .internal_search_all_uuid(g_uuid)
        .expect("Unable to access entry.");

    assert_eq!(e1, e2);
    assert!(!e1.attribute_equality(Attribute::Member, &PartialValue::Refer(t_uuid)));
    assert!(e1.attribute_equality(
        Attribute::Name,
        &PartialValue::new_iname("testgroup_conflict")
    ));

    let e1 = server_a_txn
        .internal_search_all_uuid(t_uuid)
        .expect("Unable to access entry.");
    let e2 = server_b_txn
        .internal_search_all_uuid(t_uuid)
        .expect("Unable to access entry.");

    assert_eq!(e1, e2);
    assert!(!e1.attribute_equality(Attribute::MemberOf, &PartialValue::Refer(g_uuid)));

    server_a_txn.commit().expect("Failed to commit");
    drop(server_b_txn);
}

// Ref int deletes references when tombstone is replicated over. May need consumer
// to have some extra groups that need cleanup
#[qs_pair_test]
async fn test_repl_increment_refint_tombstone(server_a: &QueryServer, server_b: &QueryServer) {
    let ct = duration_from_epoch_now();

    let mut server_a_txn = server_a.write(ct).await.unwrap();
    let mut server_b_txn = server_b.read().await.unwrap();

    assert!(repl_initialise(&mut server_b_txn, &mut server_a_txn)
        .and_then(|_| server_a_txn.commit())
        .is_ok());
    drop(server_b_txn);

    // Create a person / group on a. Don't add membership yet.
    let mut server_a_txn = server_a.write(ct).await.unwrap();
    let t_uuid = Uuid::new_v4();
    assert!(server_a_txn
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

    let g_uuid = Uuid::new_v4();
    assert!(server_a_txn
        .internal_create(vec![entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Group.to_value()),
            (Attribute::Name, Value::new_iname("testgroup1")),
            (Attribute::Uuid, Value::Uuid(g_uuid)) // Don't add the membership yet!
                                                   // (Attribute::Member, Value::Refer(t_uuid))
        ),])
        .is_ok());

    server_a_txn.commit().expect("Failed to commit");

    // A -> B repl.
    let ct = duration_from_epoch_now();
    let mut server_a_txn = server_a.read().await.unwrap();
    let mut server_b_txn = server_b.write(ct).await.unwrap();

    trace!("========================================");
    repl_incremental(&mut server_a_txn, &mut server_b_txn);

    server_b_txn.commit().expect("Failed to commit");
    drop(server_a_txn);

    // On B, delete the person.
    let ct = duration_from_epoch_now();
    let mut server_b_txn = server_b.write(ct).await.unwrap();
    assert!(server_b_txn.internal_delete_uuid(t_uuid).is_ok());
    server_b_txn.commit().expect("Failed to commit");

    // On A, add person to group.
    let ct = duration_from_epoch_now();
    let mut server_a_txn = server_a.write(ct).await.unwrap();
    assert!(server_a_txn
        .internal_modify_uuid(
            g_uuid,
            &ModifyList::new_purge_and_set(Attribute::Member, Value::Refer(t_uuid))
        )
        .is_ok());
    server_a_txn.commit().expect("Failed to commit");

    // A -> B - B should remove the reference.
    let ct = duration_from_epoch_now();
    let mut server_a_txn = server_a.read().await.unwrap();
    let mut server_b_txn = server_b.write(ct).await.unwrap();

    trace!("========================================");
    repl_incremental(&mut server_a_txn, &mut server_b_txn);

    // Assert on B that Member is now gone.
    let e = server_b_txn
        .internal_search_all_uuid(g_uuid)
        .expect("Unable to access entry.");
    assert!(!e.attribute_equality(Attribute::Member, &PartialValue::Refer(t_uuid)));

    server_b_txn.commit().expect("Failed to commit");
    drop(server_a_txn);

    // B -> A - A should remove the reference, everything is consistent again.
    let ct = duration_from_epoch_now();
    let mut server_b_txn = server_b.read().await.unwrap();
    let mut server_a_txn = server_a.write(ct).await.unwrap();

    trace!("========================================");
    repl_incremental(&mut server_b_txn, &mut server_a_txn);

    let e1 = server_a_txn
        .internal_search_all_uuid(g_uuid)
        .expect("Unable to access entry.");
    let e2 = server_b_txn
        .internal_search_all_uuid(g_uuid)
        .expect("Unable to access entry.");

    let e1_cs = e1.get_changestate();
    let e2_cs = e2.get_changestate();

    assert_eq!(e1_cs, e2_cs);

    assert_eq!(e1, e2);
    assert!(!e1.attribute_equality(Attribute::Member, &PartialValue::Refer(t_uuid)));

    server_a_txn.commit().expect("Failed to commit");
    drop(server_b_txn);
}

#[qs_pair_test]
async fn test_repl_increment_refint_conflict(server_a: &QueryServer, server_b: &QueryServer) {
    let mut server_a_txn = server_a.write(duration_from_epoch_now()).await.unwrap();
    let mut server_b_txn = server_b.read().await.unwrap();

    assert!(repl_initialise(&mut server_b_txn, &mut server_a_txn)
        .and_then(|_| server_a_txn.commit())
        .is_ok());
    drop(server_b_txn);

    // On B, create a conflicting person.
    let mut server_b_txn = server_b.write(duration_from_epoch_now()).await.unwrap();
    let t_uuid = Uuid::new_v4();
    assert!(server_b_txn
        .internal_create(vec![entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Account.to_value()),
            (Attribute::Class, EntryClass::Person.to_value()),
            (Attribute::Name, Value::new_iname("testperson_conflict")),
            (Attribute::Uuid, Value::Uuid(t_uuid)),
            (Attribute::Description, Value::new_utf8s("testperson1")),
            (Attribute::DisplayName, Value::new_utf8s("testperson1"))
        ),])
        .is_ok());
    server_b_txn.commit().expect("Failed to commit");

    // Create a person / group on a. Add person to group.
    let mut server_a_txn = server_a.write(duration_from_epoch_now()).await.unwrap();
    assert!(server_a_txn
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

    let g_uuid = Uuid::new_v4();
    assert!(server_a_txn
        .internal_create(vec![entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Group.to_value()),
            (Attribute::Name, Value::new_iname("testgroup1")),
            (Attribute::Uuid, Value::Uuid(g_uuid)),
            (Attribute::Member, Value::Refer(t_uuid))
        ),])
        .is_ok());

    server_a_txn.commit().expect("Failed to commit");

    // A -> B - B should remove the reference.
    let mut server_a_txn = server_a.read().await.unwrap();
    let mut server_b_txn = server_b.write(duration_from_epoch_now()).await.unwrap();

    trace!("========================================");
    repl_incremental(&mut server_a_txn, &mut server_b_txn);

    // Note that in the case an entry conflicts we remove references to the entry that
    // had the collision. This is because we don't know if our references are reflecting
    // the true intent of the situation now.
    //
    // In this example, the users created on server A was intended to be a member of
    // the group, but the user on server B *was not* intended to be a member. Therefore
    // it's wrong that we retain the user from Server B *while* also the membership
    // that was intended for the user on A.
    let e = server_b_txn
        .internal_search_all_uuid(g_uuid)
        .expect("Unable to access entry.");
    assert!(!e.attribute_equality(Attribute::Member, &PartialValue::Refer(t_uuid)));

    server_b_txn.commit().expect("Failed to commit");
    drop(server_a_txn);

    // B -> A - A should remove the reference.
    let mut server_b_txn = server_b.read().await.unwrap();
    let mut server_a_txn = server_a.write(duration_from_epoch_now()).await.unwrap();

    trace!("========================================");
    repl_incremental(&mut server_b_txn, &mut server_a_txn);

    let e1 = server_a_txn
        .internal_search_all_uuid(g_uuid)
        .expect("Unable to access entry.");
    let e2 = server_b_txn
        .internal_search_all_uuid(g_uuid)
        .expect("Unable to access entry.");

    let e1_cs = e1.get_changestate();
    let e2_cs = e2.get_changestate();
    assert_eq!(e1_cs, e2_cs);

    assert_eq!(e1, e2);
    assert!(!e1.attribute_equality(Attribute::Member, &PartialValue::Refer(t_uuid)));

    server_a_txn.commit().expect("Failed to commit");
    drop(server_b_txn);
}

// Ref int when we transmit a delete over the boundary. This is the opposite order to
// a previous test, where the delete is sent to the member holder first.
#[qs_pair_test]
async fn test_repl_increment_refint_delete_to_member_holder(
    server_a: &QueryServer,
    server_b: &QueryServer,
) {
    let ct = duration_from_epoch_now();

    let mut server_a_txn = server_a.write(ct).await.unwrap();
    let mut server_b_txn = server_b.read().await.unwrap();

    assert!(repl_initialise(&mut server_b_txn, &mut server_a_txn)
        .and_then(|_| server_a_txn.commit())
        .is_ok());
    drop(server_b_txn);

    // Create a person / group on a. Don't add membership yet.
    let mut server_a_txn = server_a.write(ct).await.unwrap();
    let t_uuid = Uuid::new_v4();
    assert!(server_a_txn
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

    let g_uuid = Uuid::new_v4();
    assert!(server_a_txn
        .internal_create(vec![entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Group.to_value()),
            (Attribute::Name, Value::new_iname("testgroup1")),
            (Attribute::Uuid, Value::Uuid(g_uuid)) // Don't add the membership yet!
                                                   // (Attribute::Member, Value::Refer(t_uuid))
        ),])
        .is_ok());

    server_a_txn.commit().expect("Failed to commit");

    // A -> B repl.
    let ct = duration_from_epoch_now();
    let mut server_a_txn = server_a.read().await.unwrap();
    let mut server_b_txn = server_b.write(ct).await.unwrap();

    trace!("========================================");
    repl_incremental(&mut server_a_txn, &mut server_b_txn);

    server_b_txn.commit().expect("Failed to commit");
    drop(server_a_txn);

    // On A, add person to group.
    let ct = duration_from_epoch_now();
    let mut server_a_txn = server_a.write(ct).await.unwrap();
    assert!(server_a_txn
        .internal_modify_uuid(
            g_uuid,
            &ModifyList::new_purge_and_set(Attribute::Member, Value::Refer(t_uuid))
        )
        .is_ok());
    server_a_txn.commit().expect("Failed to commit");

    // On B, delete the person.
    let ct = duration_from_epoch_now();
    let mut server_b_txn = server_b.write(ct).await.unwrap();
    assert!(server_b_txn.internal_delete_uuid(t_uuid).is_ok());
    server_b_txn.commit().expect("Failed to commit");

    // B -> A - A should remove the reference, everything is consistent again.
    let ct = duration_from_epoch_now();
    let mut server_b_txn = server_b.read().await.unwrap();
    let mut server_a_txn = server_a.write(ct).await.unwrap();

    trace!("========================================");
    repl_incremental(&mut server_b_txn, &mut server_a_txn);

    let e = server_a_txn
        .internal_search_all_uuid(g_uuid)
        .expect("Unable to access entry.");
    assert!(!e.attribute_equality(Attribute::Member, &PartialValue::Refer(t_uuid)));

    server_a_txn.commit().expect("Failed to commit");
    drop(server_b_txn);

    // A -> B - Should just reflect what happened on A.
    let ct = duration_from_epoch_now();
    let mut server_a_txn = server_a.read().await.unwrap();
    let mut server_b_txn = server_b.write(ct).await.unwrap();

    trace!("========================================");
    repl_incremental(&mut server_a_txn, &mut server_b_txn);

    let e1 = server_a_txn
        .internal_search_all_uuid(g_uuid)
        .expect("Unable to access entry.");
    let e2 = server_b_txn
        .internal_search_all_uuid(g_uuid)
        .expect("Unable to access entry.");

    let e1_cs = e1.get_changestate();
    let e2_cs = e2.get_changestate();

    assert_eq!(e1_cs, e2_cs);
    assert_eq!(e1, e2);
    assert!(!e1.attribute_equality(Attribute::Member, &PartialValue::Refer(t_uuid)));

    server_b_txn.commit().expect("Failed to commit");
    drop(server_a_txn);
}

// Test attrunique conflicts
// Test ref-int when attrunique makes a conflict
// Test memberof when attrunique makes a conflict
#[qs_pair_test]
async fn test_repl_increment_attrunique_conflict_basic(
    server_a: &QueryServer,
    server_b: &QueryServer,
) {
    let ct = duration_from_epoch_now();

    let mut server_a_txn = server_a.write(ct).await.unwrap();
    let mut server_b_txn = server_b.read().await.unwrap();

    assert!(repl_initialise(&mut server_b_txn, &mut server_a_txn)
        .and_then(|_| server_a_txn.commit())
        .is_ok());
    drop(server_b_txn);

    let mut server_a_txn = server_a.write(duration_from_epoch_now()).await.unwrap();

    // To test memberof, we add a user who is MO A/B
    let t_uuid = Uuid::new_v4();
    assert!(server_a_txn
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

    let g_a_uuid = Uuid::new_v4();
    assert!(server_a_txn
        .internal_create(vec![entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Group.to_value()),
            (Attribute::Name, Value::new_iname("testgroup_a")),
            (Attribute::Uuid, Value::Uuid(g_a_uuid)),
            (Attribute::Member, Value::Refer(t_uuid))
        ),])
        .is_ok());

    let g_b_uuid = Uuid::new_v4();
    assert!(server_a_txn
        .internal_create(vec![entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Group.to_value()),
            (Attribute::Name, Value::new_iname("testgroup_b")),
            (Attribute::Uuid, Value::Uuid(g_b_uuid)),
            (Attribute::Member, Value::Refer(t_uuid))
        ),])
        .is_ok());

    // To test ref-int, we make a third group that has both a and b as members.
    let g_c_uuid = Uuid::new_v4();
    assert!(server_a_txn
        .internal_create(vec![entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Group.to_value()),
            (Attribute::Name, Value::new_iname("testgroup_c")),
            (Attribute::Uuid, Value::Uuid(g_c_uuid)),
            (Attribute::Member, Value::Refer(g_a_uuid)),
            (Attribute::Member, Value::Refer(g_b_uuid))
        ),])
        .is_ok());

    server_a_txn.commit().expect("Failed to commit");

    // Now replicated A -> B

    let mut server_a_txn = server_a.read().await.unwrap();
    let mut server_b_txn = server_b.write(duration_from_epoch_now()).await.unwrap();

    trace!("========================================");
    repl_incremental(&mut server_a_txn, &mut server_b_txn);

    let e1 = server_a_txn
        .internal_search_all_uuid(g_a_uuid)
        .expect("Unable to access new entry.");
    let e2 = server_b_txn
        .internal_search_all_uuid(g_a_uuid)
        .expect("Unable to access entry.");

    assert_eq!(e1, e2);

    let e1 = server_a_txn
        .internal_search_all_uuid(g_b_uuid)
        .expect("Unable to access new entry.");
    let e2 = server_b_txn
        .internal_search_all_uuid(g_b_uuid)
        .expect("Unable to access entry.");

    assert_eq!(e1, e2);
    server_b_txn.commit().expect("Failed to commit");
    drop(server_a_txn);

    // At this point both sides now have the groups. Now on each node we will rename them
    // so that they conflict.

    let mut server_a_txn = server_a.write(duration_from_epoch_now()).await.unwrap();
    assert!(server_a_txn
        .internal_modify_uuid(
            g_a_uuid,
            &ModifyList::new_purge_and_set(Attribute::Name, Value::new_iname("name_conflict"))
        )
        .is_ok());
    server_a_txn.commit().expect("Failed to commit");

    let mut server_b_txn = server_b.write(duration_from_epoch_now()).await.unwrap();
    assert!(server_b_txn
        .internal_modify_uuid(
            g_b_uuid,
            &ModifyList::new_purge_and_set(Attribute::Name, Value::new_iname("name_conflict"))
        )
        .is_ok());
    server_b_txn.commit().expect("Failed to commit");

    // Now each node has an entry, separate uuids, but a name that will violate attr
    // unique on the next replicate.
    //
    // Order of replication doesn't matter here! Which ever one see's it first will
    // conflict the entries. In this case, A will detect the attr unique violation
    // and create the conflicts.
    let mut server_b_txn = server_b.read().await.unwrap();
    let mut server_a_txn = server_a.write(duration_from_epoch_now()).await.unwrap();

    trace!("========================================");
    repl_incremental(&mut server_b_txn, &mut server_a_txn);

    // The conflict should now have occurred.
    // Check both groups are conflicts.
    let cnf_a = server_a_txn
        .internal_search_conflict_uuid(g_a_uuid)
        .expect("Unable to search conflict entries.")
        .pop()
        .expect("No conflict entries present");
    assert_eq!(
        cnf_a.get_ava_single_iname(Attribute::Name),
        Some("name_conflict")
    );

    let cnf_b = server_a_txn
        .internal_search_conflict_uuid(g_b_uuid)
        .expect("Unable to search conflict entries.")
        .pop()
        .expect("No conflict entries present");
    assert_eq!(
        cnf_b.get_ava_single_iname(Attribute::Name),
        Some("name_conflict")
    );

    // Check the person has MO A/B removed.
    let e = server_a_txn
        .internal_search_all_uuid(t_uuid)
        .expect("Unable to access entry.");
    assert!(!e.attribute_equality(Attribute::MemberOf, &PartialValue::Refer(g_a_uuid)));
    assert!(!e.attribute_equality(Attribute::MemberOf, &PartialValue::Refer(g_b_uuid)));

    // Check the group has M A/B removed.
    let e = server_a_txn
        .internal_search_all_uuid(g_c_uuid)
        .expect("Unable to access entry.");
    assert!(!e.attribute_equality(Attribute::Member, &PartialValue::Refer(g_a_uuid)));
    assert!(!e.attribute_equality(Attribute::Member, &PartialValue::Refer(g_b_uuid)));

    server_a_txn.commit().expect("Failed to commit");
    drop(server_b_txn);

    // Reverse it - The conflicts will now be sent back A -> B, meaning that
    // everything is consistent once more.
    let mut server_a_txn = server_a.read().await.unwrap();
    let mut server_b_txn = server_b.write(duration_from_epoch_now()).await.unwrap();

    trace!("========================================");
    repl_incremental(&mut server_a_txn, &mut server_b_txn);

    let cnf_a = server_b_txn
        .internal_search_conflict_uuid(g_a_uuid)
        .expect("Unable to search conflict entries.")
        .pop()
        .expect("No conflict entries present");
    assert_eq!(
        cnf_a.get_ava_single_iname(Attribute::Name),
        Some("name_conflict")
    );

    let cnf_b = server_b_txn
        .internal_search_conflict_uuid(g_b_uuid)
        .expect("Unable to search conflict entries.")
        .pop()
        .expect("No conflict entries present");
    assert_eq!(
        cnf_b.get_ava_single_iname(Attribute::Name),
        Some("name_conflict")
    );

    server_b_txn.commit().expect("Failed to commit");
    drop(server_a_txn);
}

// Test a complex attr unique situation when the attrunique conflict would occur normally but is
// skipped because the entry it is going to conflict against is actually a uuid conflict.

#[qs_pair_test]
async fn test_repl_increment_attrunique_conflict_complex(
    server_a: &QueryServer,
    server_b: &QueryServer,
) {
    let ct = duration_from_epoch_now();

    let mut server_a_txn = server_a.write(ct).await.unwrap();
    let mut server_b_txn = server_b.read().await.unwrap();

    assert!(repl_initialise(&mut server_b_txn, &mut server_a_txn)
        .and_then(|_| server_a_txn.commit())
        .is_ok());
    drop(server_b_txn);

    let mut server_a_txn = server_a.write(duration_from_epoch_now()).await.unwrap();

    // Create two entries on A - The entry that will be an attrunique conflict
    // and the entry that will UUID conflict to the second entry. The second entry
    // should not attrunique conflict within server_a

    let g_a_uuid = Uuid::new_v4();
    assert!(server_a_txn
        .internal_create(vec![entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Group.to_value()),
            (Attribute::Name, Value::new_iname("name_conflict")),
            (Attribute::Uuid, Value::Uuid(g_a_uuid))
        ),])
        .is_ok());

    let g_b_uuid = Uuid::new_v4();
    assert!(server_a_txn
        .internal_create(vec![entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Group.to_value()),
            (Attribute::Name, Value::new_iname("uuid_conflict")),
            (Attribute::Uuid, Value::Uuid(g_b_uuid))
        ),])
        .is_ok());

    server_a_txn.commit().expect("Failed to commit");

    let mut server_b_txn = server_b.write(duration_from_epoch_now()).await.unwrap();

    // Create an entry on B that is a uuid conflict to the second entry on A. This entry
    // should *also* have an attr conflict to name on the first entry from A.
    assert!(server_b_txn
        .internal_create(vec![entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Group.to_value()),
            // Conflicting name
            (Attribute::Name, Value::new_iname("name_conflict")),
            // Conflicting uuid
            (Attribute::Uuid, Value::Uuid(g_b_uuid))
        ),])
        .is_ok());

    server_b_txn.commit().expect("Failed to commit");

    // We have to replicate B -> A first. This is so that A will not load the conflict
    // entry, and the entries g_a_uuid and g_b_uuid stay present.
    let mut server_b_txn = server_b.read().await.unwrap();
    let mut server_a_txn = server_a.write(duration_from_epoch_now()).await.unwrap();

    trace!("========================================");
    repl_incremental(&mut server_b_txn, &mut server_a_txn);

    // Check these entries are still present and were NOT conflicted due to attrunique
    let e = server_a_txn
        .internal_search_all_uuid(g_a_uuid)
        .expect("Unable to access entry.");
    assert!(e.attribute_equality(Attribute::Name, &PartialValue::new_iname("name_conflict")));

    let e = server_a_txn
        .internal_search_all_uuid(g_b_uuid)
        .expect("Unable to access entry.");
    assert!(e.attribute_equality(Attribute::Name, &PartialValue::new_iname("uuid_conflict")));

    // The other entry will not be conflicted here, since A is not the origin node.

    server_a_txn.commit().expect("Failed to commit");
    drop(server_b_txn);

    // Replicate A -> B now. This will cause the entry to be persisted as a conflict
    // as this is the origin node. We should end up with the two entries from
    // server A remaining.
    let mut server_a_txn = server_a.read().await.unwrap();
    let mut server_b_txn = server_b.write(duration_from_epoch_now()).await.unwrap();

    trace!("========================================");
    repl_incremental(&mut server_a_txn, &mut server_b_txn);

    // Check these entries are still present and were NOT conflicted due to attrunique
    let e = server_b_txn
        .internal_search_all_uuid(g_a_uuid)
        .expect("Unable to access entry.");
    assert!(e.attribute_equality(Attribute::Name, &PartialValue::new_iname("name_conflict")));

    let e = server_b_txn
        .internal_search_all_uuid(g_b_uuid)
        .expect("Unable to access entry.");
    assert!(e.attribute_equality(Attribute::Name, &PartialValue::new_iname("uuid_conflict")));

    // Check the conflict was also now created.
    let cnf_a = server_b_txn
        .internal_search_conflict_uuid(g_b_uuid)
        .expect("Unable to search conflict entries.")
        .pop()
        .expect("No conflict entries present");
    assert_eq!(
        cnf_a.get_ava_single_iname(Attribute::Name),
        Some("name_conflict")
    );

    server_b_txn.commit().expect("Failed to commit");
    drop(server_a_txn);
}

// Test the behaviour of a "new server join". This will have the supplier and
// consumer mismatch on the domain_uuid, leading to the consumer with a
// refresh required message. This should then be refreshed and succeed

#[qs_pair_test]
async fn test_repl_initial_consumer_join(server_a: &QueryServer, server_b: &QueryServer) {
    let ct = duration_from_epoch_now();

    let mut server_a_txn = server_a.write(ct).await.unwrap();
    let mut server_b_txn = server_b.read().await.unwrap();

    let a_ruv_range = server_a_txn
        .consumer_get_state()
        .expect("Unable to access RUV range");

    let changes = server_b_txn
        .supplier_provide_changes(a_ruv_range)
        .expect("Unable to generate supplier changes");

    assert!(matches!(changes, ReplIncrementalContext::DomainMismatch));

    let result = server_a_txn
        .consumer_apply_changes(changes)
        .expect("Unable to apply changes to consumer.");

    assert!(matches!(result, ConsumerState::RefreshRequired));

    drop(server_a_txn);
    drop(server_b_txn);

    // Then a refresh resolves.
    let mut server_a_txn = server_a.write(ct).await.unwrap();
    let mut server_b_txn = server_b.read().await.unwrap();

    assert!(repl_initialise(&mut server_b_txn, &mut server_a_txn)
        .and_then(|_| server_a_txn.commit())
        .is_ok());
    drop(server_b_txn);
}

// Test handling of sessions over replication

#[qs_pair_test]
async fn test_repl_increment_session_new(server_a: &QueryServer, server_b: &QueryServer) {
    let ct = duration_from_epoch_now();

    // First create a user.

    let mut server_b_txn = server_b.write(ct).await.unwrap();

    let t_uuid = Uuid::new_v4();

    let p = CryptoPolicy::minimum();
    let cred = Credential::new_password_only(&p, "test_password", OffsetDateTime::UNIX_EPOCH + ct)
        .unwrap();
    let cred_id = cred.uuid;

    let e1 = entry_init!(
        (Attribute::Class, EntryClass::Object.to_value()),
        (Attribute::Class, EntryClass::Person.to_value()),
        (Attribute::Class, EntryClass::Account.to_value()),
        (Attribute::Name, Value::new_iname("testperson1")),
        (Attribute::Uuid, Value::Uuid(t_uuid)),
        (Attribute::Description, Value::new_utf8s("testperson1")),
        (Attribute::DisplayName, Value::new_utf8s("testperson1")),
        (
            Attribute::PrimaryCredential,
            Value::Cred("primary".to_string(), cred.clone())
        )
    );

    let ce = CreateEvent::new_internal(vec![e1]);
    assert!(server_b_txn.create(&ce).is_ok());

    server_b_txn.commit().expect("Failed to commit");

    let mut server_a_txn = server_a.write(ct).await.unwrap();
    let mut server_b_txn = server_b.read().await.unwrap();

    assert!(repl_initialise(&mut server_b_txn, &mut server_a_txn)
        .and_then(|_| server_a_txn.commit())
        .is_ok());
    drop(server_b_txn);

    // Update a session on A.

    let mut server_a_txn = server_a.write(ct).await.unwrap();

    let curtime_odt = OffsetDateTime::UNIX_EPOCH + ct;
    let exp_curtime = ct + Duration::from_secs(60);
    let exp_curtime_odt = OffsetDateTime::UNIX_EPOCH + exp_curtime;

    // Create a fake session.
    let session_id_a = Uuid::new_v4();
    let state = SessionState::ExpiresAt(exp_curtime_odt);
    let issued_at = curtime_odt;
    let issued_by = IdentityId::User(t_uuid);
    let scope = SessionScope::ReadOnly;
    let type_ = AuthType::Passkey;

    let session = Value::Session(
        session_id_a,
        Session {
            label: "label".to_string(),
            state,
            issued_at,
            issued_by,
            cred_id,
            scope,
            type_,
            ext_metadata: Default::default(),
        },
    );

    let modlist = ModifyList::new_append(Attribute::UserAuthTokenSession, session);

    server_a_txn
        .internal_modify(
            &filter!(f_eq(Attribute::Uuid, PartialValue::Uuid(t_uuid))),
            &modlist,
        )
        .expect("Failed to modify user");

    server_a_txn.commit().expect("Failed to commit");

    // And a session on B.

    let ct = duration_from_epoch_now();
    let mut server_b_txn = server_b.write(ct).await.unwrap();

    let curtime_odt = OffsetDateTime::UNIX_EPOCH + ct;
    let exp_curtime = ct + Duration::from_secs(60);
    let exp_curtime_odt = OffsetDateTime::UNIX_EPOCH + exp_curtime;

    // Create a fake session.
    let session_id_b = Uuid::new_v4();
    let state = SessionState::ExpiresAt(exp_curtime_odt);
    let issued_at = curtime_odt;
    let issued_by = IdentityId::User(t_uuid);
    let scope = SessionScope::ReadOnly;
    let type_ = AuthType::Passkey;

    let session = Value::Session(
        session_id_b,
        Session {
            label: "label".to_string(),
            state,
            issued_at,
            issued_by,
            cred_id,
            scope,
            type_,
            ext_metadata: Default::default(),
        },
    );

    let modlist = ModifyList::new_append(Attribute::UserAuthTokenSession, session);

    server_b_txn
        .internal_modify(
            &filter!(f_eq(Attribute::Uuid, PartialValue::Uuid(t_uuid))),
            &modlist,
        )
        .expect("Failed to modify user");

    server_b_txn.commit().expect("Failed to commit");

    // Now incremental in both directions.

    let ct = duration_from_epoch_now();
    let mut server_a_txn = server_a.read().await.unwrap();
    let mut server_b_txn = server_b.write(ct).await.unwrap();

    trace!("========================================");
    repl_incremental(&mut server_a_txn, &mut server_b_txn);

    let e1 = server_a_txn
        .internal_search_all_uuid(t_uuid)
        .expect("Unable to access entry.");
    let e2 = server_b_txn
        .internal_search_all_uuid(t_uuid)
        .expect("Unable to access entry.");

    // Here, A's session should have merged with B.
    let sessions_a = e1
        .get_ava_as_session_map(Attribute::UserAuthTokenSession)
        .unwrap();

    assert_eq!(sessions_a.len(), 1);
    assert!(sessions_a.get(&session_id_a).is_some());
    assert!(sessions_a.get(&session_id_b).is_none());

    let sessions_b = e2
        .get_ava_as_session_map(Attribute::UserAuthTokenSession)
        .unwrap();

    assert_eq!(sessions_b.len(), 2);
    assert!(sessions_b.get(&session_id_a).is_some());
    assert!(sessions_b.get(&session_id_b).is_some());

    server_b_txn.commit().expect("Failed to commit");
    drop(server_a_txn);

    let ct = duration_from_epoch_now();
    let mut server_b_txn = server_b.read().await.unwrap();
    let mut server_a_txn = server_a.write(ct).await.unwrap();

    trace!("========================================");
    repl_incremental(&mut server_b_txn, &mut server_a_txn);

    let e1 = server_a_txn
        .internal_search_all_uuid(t_uuid)
        .expect("Unable to access entry.");
    let e2 = server_b_txn
        .internal_search_all_uuid(t_uuid)
        .expect("Unable to access entry.");

    let e1_cs = e1.get_changestate();
    let e2_cs = e2.get_changestate();

    assert_eq!(e1_cs, e2_cs);
    trace!(?e1);
    trace!(?e2);
    assert_eq!(e1, e2);

    server_a_txn.commit().expect("Failed to commit");
    drop(server_b_txn);
}

/// Test the process of refreshing a consumer once it has entered a lag state.
///
/// It was noticed in a production instance that it was possible for a consumer
/// to enter an unrecoverable state where replication could no longer proceed.
///
/// We have server A and B. We will focus on A and it's RUV state.
///
/// - A accepts a change setting it's RUV to A: 1
/// - A replicates to B, setting B ruv to A: 1
/// - Now A begins to lag and exceeds the changelog max age.
/// - At this point incremental replication will cease to function.
/// - The correct response (and automatically occurs) is that A would be
///   refreshed from B. This then sets A ruv to A:1 - which is significantly
///   behind the changelog max age.
/// - Then A does a RUV trim. This set's it's RUV to A: X where X is > 1 + CL max.
/// - On next replication to B, the replication stops as now "B" appears to be
///   lagging since there is no overlap of it's RUV window to A.
///
/// The resolution in this case is two-fold.
/// On a server refresh, the server-replication-id must be reset and regenerated. This
/// ensures that any RUV state to a server is now fresh and unique
///
/// Second, to prevent tainting the RUV with outdated information, we need to stop it
/// propagating when consumed. At the end of each consumption, the RUV should be trimmed
/// if and only if entries exist in it that exceed the CL max. It is only trimmed conditionally
/// to prevent infinite replication loops since a trim implies the creation of a new anchor.

#[qs_pair_test]
async fn test_repl_increment_consumer_lagging_refresh(
    server_a: &QueryServer,
    server_b: &QueryServer,
) {
    let ct = duration_from_epoch_now();

    let mut server_a_txn = server_a.write(ct).await.unwrap();
    let mut server_b_txn = server_b.read().await.unwrap();

    assert!(repl_initialise(&mut server_b_txn, &mut server_a_txn)
        .and_then(|_| server_a_txn.commit())
        .is_ok());
    drop(server_b_txn);

    // - A accepts a change setting it's RUV to A: 1
    let mut server_a_txn = server_a.write(ct).await.unwrap();
    let t_uuid = Uuid::new_v4();
    assert!(server_a_txn
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

    // Take a copy of the CID here for it's s_uuid - this allows us to
    // validate later that the s_uuid is rotated, and trimmed from the
    // RUV.
    let server_a_initial_uuid = server_a_txn.get_server_uuid();

    server_a_txn.commit().expect("Failed to commit");

    // - A replicates to B, setting B ruv to A: 1
    let mut server_a_txn = server_a.read().await.unwrap();
    let mut server_b_txn = server_b.write(duration_from_epoch_now()).await.unwrap();

    repl_incremental(&mut server_a_txn, &mut server_b_txn);

    let e1 = server_a_txn
        .internal_search_all_uuid(t_uuid)
        .expect("Unable to access new entry.");
    let e2 = server_b_txn
        .internal_search_all_uuid(t_uuid)
        .expect("Unable to access entry.");

    assert_eq!(e1.get_last_changed(), e2.get_last_changed());

    server_b_txn.commit().expect("Failed to commit");
    drop(server_a_txn);

    // - B working properly, creates an update within the max win
    let ct_half = ct + Duration::from_secs(CHANGELOG_MAX_AGE / 2);

    let mut server_b_txn = server_b.write(ct_half).await.unwrap();
    assert!(server_b_txn.purge_tombstones().is_ok());
    server_b_txn.commit().expect("Failed to commit");

    // - Now A begins to lag and exceeds the changelog max age.
    let ct = ct + Duration::from_secs(CHANGELOG_MAX_AGE + 1);

    trace!("========================================");
    // Purge tombstones - this triggers a write anchor to be created
    // on both servers, and it will also trim the old values from the ruv.
    let mut server_a_txn = server_a.write(ct).await.unwrap();
    assert!(server_a_txn.purge_tombstones().is_ok());
    server_a_txn.commit().expect("Failed to commit");

    let mut server_b_txn = server_b.write(ct).await.unwrap();
    assert!(server_b_txn.purge_tombstones().is_ok());
    server_b_txn.commit().expect("Failed to commit");

    // - At this point incremental replication will cease to function in either
    //   direction.
    let ct = ct + Duration::from_secs(1);

    let mut server_a_txn = server_a.write(ct).await.unwrap();
    let mut server_b_txn = server_b.read().await.unwrap();

    // The ruvs must be different
    let a_ruv_range = server_a_txn
        .get_be_txn()
        .get_ruv()
        .current_ruv_range()
        .expect("Failed to get RUV range A");
    let b_ruv_range = server_b_txn
        .get_be_txn()
        .get_ruv()
        .current_ruv_range()
        .expect("Failed to get RUV range B");

    trace!(?a_ruv_range);
    trace!(?b_ruv_range);
    assert!(a_ruv_range != b_ruv_range);

    let a_ruv_range = server_a_txn
        .consumer_get_state()
        .expect("Unable to access RUV range");

    let changes = server_b_txn
        .supplier_provide_changes(a_ruv_range)
        .expect("Unable to generate supplier changes");

    trace!(?changes);
    assert!(matches!(changes, ReplIncrementalContext::UnwillingToSupply));

    drop(server_a_txn);
    drop(server_b_txn);

    // - The correct response (and automatically occurs) is that A would be
    //   refreshed from B. This then sets A ruv to A:1 - which is significantly
    //   behind the changelog max age.
    let ct = ct + Duration::from_secs(1);

    let mut server_a_txn = server_a.write(ct).await.unwrap();
    let mut server_b_txn = server_b.read().await.unwrap();

    // First, build the refresh context.
    let refresh_context = server_b_txn
        .supplier_provide_refresh()
        .expect("Unable to supply refresh");

    // Apply it to the server
    server_a_txn
        .consumer_apply_refresh(refresh_context)
        .expect("Unable to apply refresh");

    // Need same d_uuid
    assert_eq!(
        server_b_txn.get_domain_uuid(),
        server_a_txn.get_domain_uuid()
    );

    // Assert that the server's repl uuid was rotated as part of the refresh.
    let server_a_rotated_uuid = server_a_txn.get_server_uuid();
    assert_ne!(server_a_initial_uuid, server_a_rotated_uuid);

    // Ruvs are the same now
    let a_ruv_range = server_a_txn
        .get_be_txn()
        .get_ruv()
        .current_ruv_range()
        .expect("Failed to get RUV range A");
    let b_ruv_range = server_b_txn
        .get_be_txn()
        .get_ruv()
        .current_ruv_range()
        .expect("Failed to get RUV range B");

    trace!(?a_ruv_range);
    trace!(?b_ruv_range);

    assert!(server_a_txn.commit().is_ok());
    drop(server_b_txn);

    // - Then A does a RUV trim. This set's it's RUV to A: X where X is > 1 + CL max.

    let mut server_a_txn = server_a.write(ct).await.unwrap();
    assert!(server_a_txn.purge_tombstones().is_ok());

    let a_ruv_range = server_a_txn
        .get_be_txn()
        .get_ruv()
        .current_ruv_range()
        .expect("Failed to get RUV range A");
    trace!(?a_ruv_range);

    server_a_txn.commit().expect("Failed to commit");

    // ERROR CASE: On next replication to B, the replication stops as now "B"
    //             appears to be lagging since there is no overlap of it's RUV
    //             window to A.
    // EXPECTED: replication proceeds as usual as consumer was refreshed and should
    //           be in sync now!

    let ct = ct + Duration::from_secs(1);

    let mut server_a_txn = server_a.write(ct).await.unwrap();
    let mut server_b_txn = server_b.read().await.unwrap();

    repl_incremental(&mut server_b_txn, &mut server_a_txn);

    let e1 = server_a_txn
        .internal_search_all_uuid(t_uuid)
        .expect("Unable to access new entry.");
    let e2 = server_b_txn
        .internal_search_all_uuid(t_uuid)
        .expect("Unable to access entry.");

    assert_eq!(e1.get_last_changed(), e2.get_last_changed());

    server_a_txn.commit().expect("Failed to commit");
    drop(server_b_txn);

    let mut server_a_txn = server_a.read().await.unwrap();
    let mut server_b_txn = server_b.write(ct).await.unwrap();

    repl_incremental(&mut server_a_txn, &mut server_b_txn);

    let e1 = server_a_txn
        .internal_search_all_uuid(t_uuid)
        .expect("Unable to access new entry.");
    let e2 = server_b_txn
        .internal_search_all_uuid(t_uuid)
        .expect("Unable to access entry.");

    assert_eq!(e1.get_last_changed(), e2.get_last_changed());

    server_b_txn.commit().expect("Failed to commit");
    drop(server_a_txn);

    // Now we run the incremental replication in a loop to trim out the initial server uuid.

    let mut ct = ct;
    let changelog_quarter_life = Duration::from_secs(CHANGELOG_MAX_AGE / 4);
    let one_second = Duration::from_secs(1);

    for i in 0..8 {
        trace!("========================================");
        trace!("repl iteration {}", i);
        // Purge tombstones.
        let mut server_a_txn = server_a.write(ct).await.unwrap();
        assert!(server_a_txn.purge_tombstones().is_ok());
        server_a_txn.commit().expect("Failed to commit");

        ct += one_second;

        let mut server_b_txn = server_b.write(ct).await.unwrap();
        assert!(server_b_txn.purge_tombstones().is_ok());
        server_b_txn.commit().expect("Failed to commit");

        ct += one_second;

        // Now check incremental in both directions. Should show *no* changes
        // needed (rather than an error/lagging).
        let mut server_a_txn = server_a.write(ct).await.unwrap();
        let mut server_b_txn = server_b.read().await.unwrap();

        let a_ruv_range = server_a_txn
            .consumer_get_state()
            .expect("Unable to access RUV range");

        trace!(?a_ruv_range);

        let changes = server_b_txn
            .supplier_provide_changes(a_ruv_range)
            .expect("Unable to generate supplier changes");

        assert!(matches!(changes, ReplIncrementalContext::V1 { .. }));

        let result = server_a_txn
            .consumer_apply_changes(changes)
            .expect("Unable to apply changes to consumer.");

        assert!(matches!(result, ConsumerState::Ok));

        server_a_txn.commit().expect("Failed to commit");
        drop(server_b_txn);

        ct += one_second;

        // Reverse it!
        let mut server_a_txn = server_a.read().await.unwrap();
        let mut server_b_txn = server_b.write(ct).await.unwrap();

        let b_ruv_range = server_b_txn
            .consumer_get_state()
            .expect("Unable to access RUV range");

        trace!(?b_ruv_range);

        let changes = server_a_txn
            .supplier_provide_changes(b_ruv_range)
            .expect("Unable to generate supplier changes");

        assert!(matches!(changes, ReplIncrementalContext::V1 { .. }));

        let result = server_b_txn
            .consumer_apply_changes(changes)
            .expect("Unable to apply changes to consumer.");

        assert!(matches!(result, ConsumerState::Ok));

        drop(server_a_txn);
        server_b_txn.commit().expect("Failed to commit");

        ct += changelog_quarter_life;
    }

    // Finally, verify that the former server RUV has been trimmed out.
    let mut server_b_txn = server_b.read().await.unwrap();
    let mut server_a_txn = server_a.read().await.unwrap();

    assert_ne!(server_a_initial_uuid, server_a_rotated_uuid);

    // Ruvs are the same now
    let a_ruv_range = server_a_txn
        .get_be_txn()
        .get_ruv()
        .current_ruv_range()
        .expect("Failed to get RUV range A");

    let b_ruv_range = server_b_txn
        .get_be_txn()
        .get_ruv()
        .current_ruv_range()
        .expect("Failed to get RUV range B");

    trace!("TRACE MARKER");
    trace!(?server_a_initial_uuid, ?server_a_rotated_uuid);
    trace!(?a_ruv_range);
    trace!(?b_ruv_range);

    assert!(!a_ruv_range.contains_key(&server_a_initial_uuid));
    assert!(!b_ruv_range.contains_key(&server_a_initial_uuid));
}

// A challenge of reference entries is that we can't easily tell who they
// related to in a uuid conflict case. Thankfully, uuid conflicts are RARE
// but if they happen we need to go scortched earth and just delete anything
// that referenced a uuid in a conflict state.
#[qs_pair_test]
async fn test_repl_increment_reference_conflicts(server_a: &QueryServer, server_b: &QueryServer) {
    let ct = duration_from_epoch_now();
    let mut server_a_txn = server_a.write(ct).await.unwrap();
    let mut server_b_txn = server_b.read().await.unwrap();

    let cert_data = Box::new(
        Certificate::from_pem(TEST_X509_CERT_DATA).expect("Unable to parse test X509 cert data"),
    );

    assert!(repl_initialise(&mut server_b_txn, &mut server_a_txn).is_ok());

    server_a_txn.commit().expect("Failed to commit");
    drop(server_b_txn);

    // Now create the same entry on both servers.
    let t_uuid = Uuid::new_v4();
    let e_init = entry_init!(
        (Attribute::Class, EntryClass::Object.to_value()),
        (Attribute::Class, EntryClass::Account.to_value()),
        (Attribute::Class, EntryClass::Person.to_value()),
        (Attribute::Name, Value::new_iname("testperson1")),
        (Attribute::Uuid, Value::Uuid(t_uuid)),
        (Attribute::Description, Value::new_utf8s("testperson1")),
        (Attribute::DisplayName, Value::new_utf8s("testperson1"))
    );

    // Create a reference on both servers to show the difference in handling.
    let ref_uuid_a = Uuid::new_v4();
    let ref_entry_a = entry_init!(
        (Attribute::Class, EntryClass::Object.to_value()),
        (Attribute::Class, EntryClass::ClientCertificate.to_value()),
        (Attribute::Uuid, Value::Uuid(ref_uuid_a)),
        (Attribute::Refers, Value::Refer(t_uuid)),
        (
            Attribute::Certificate,
            Value::Certificate(cert_data.clone())
        )
    );

    let ref_uuid_b = Uuid::new_v4();
    let ref_entry_b = entry_init!(
        (Attribute::Class, EntryClass::Object.to_value()),
        (Attribute::Class, EntryClass::ClientCertificate.to_value()),
        (Attribute::Uuid, Value::Uuid(ref_uuid_b)),
        (Attribute::Refers, Value::Refer(t_uuid)),
        (
            Attribute::Certificate,
            Value::Certificate(cert_data.clone())
        )
    );

    // Create on B first
    let mut server_b_txn = server_b.write(ct).await.unwrap();
    assert!(server_b_txn
        .internal_create(vec![e_init.clone(), ref_entry_b.clone()])
        .is_ok());
    server_b_txn.commit().expect("Failed to commit");

    // Get a new time.
    let ct = duration_from_epoch_now();
    let mut server_a_txn = server_a.write(ct).await.unwrap();
    assert!(server_a_txn
        .internal_create(vec![e_init.clone(), ref_entry_a.clone()])
        .is_ok());
    server_a_txn.commit().expect("Failed to commit");

    trace!("========================================");
    let mut server_a_txn = server_a.read().await.unwrap();
    let mut server_b_txn = server_b.write(duration_from_epoch_now()).await.unwrap();

    repl_incremental(&mut server_a_txn, &mut server_b_txn);
    // Replicate A to B. B should ignore the incoming conflict entry, but it will
    // delete it's reference entry. It also needs to ignore the incoming reference.

    let e1 = server_a_txn
        .internal_search_all_uuid(t_uuid)
        .expect("Unable to access new entry.");
    let e2 = server_b_txn
        .internal_search_all_uuid(t_uuid)
        .expect("Unable to access entry.");

    // A is newer than B, so this is a basic assertion.
    assert!(e1.get_last_changed() > e2.get_last_changed());

    // Should not have been brought in.
    let ref_a_on_b = server_b_txn
        .internal_search_all_uuid(ref_uuid_a)
        .expect("Unable to access new entry.");

    // Must now be a conflict
    let cnf_ref_b_on_b = server_b_txn
        .internal_search_conflict_uuid(ref_uuid_b)
        .expect("Unable to conflict entries.")
        .pop()
        .expect("No conflict entries present");

    trace!(?ref_a_on_b);
    trace!(?cnf_ref_b_on_b);

    server_b_txn.commit().expect("Failed to commit");
    drop(server_a_txn);

    trace!("========================================");
    // Replicate B to A. A should replace with B, and create the
    // conflict entry as it's the origin of the conflict.
    //
    // Additionally, A should now also conflict it's reference entry too.

    let mut server_a_txn = server_a.write(duration_from_epoch_now()).await.unwrap();
    let mut server_b_txn = server_b.read().await.unwrap();

    repl_incremental(&mut server_b_txn, &mut server_a_txn);

    let e1 = server_a_txn
        .internal_search_all_uuid(t_uuid)
        .expect("Unable to access new entry.");
    let e2 = server_b_txn
        .internal_search_all_uuid(t_uuid)
        .expect("Unable to access entry.");

    // These are now the same entry.
    assert_eq!(e1.get_last_changed(), e2.get_last_changed());

    // A will now have created a conflict for the original entry.
    let cnf_user_on_a = server_a_txn
        .internal_search_conflict_uuid(t_uuid)
        .expect("Unable to conflict entries.")
        .pop()
        .expect("No conflict entries present");

    // A should now have the conflict of it's reference.
    let cnf_ref_a_on_a = server_a_txn
        .internal_search_conflict_uuid(ref_uuid_a)
        .expect("Unable to conflict entries.")
        .pop()
        .expect("No conflict entries present");

    // A will have replicated in the conflict reference from B.
    let cnf_ref_b_on_a = server_a_txn
        .internal_search_conflict_uuid(ref_uuid_b)
        .expect("Unable to conflict entries.")
        .pop()
        .expect("No conflict entries present");

    trace!(?cnf_user_on_a);
    trace!(?cnf_ref_a_on_a);
    trace!(?cnf_ref_b_on_a);

    server_a_txn.commit().expect("Failed to commit");
    drop(server_b_txn);

    trace!("========================================");
    // Assert all the conflict entries get replicated around as expected.
    let mut server_a_txn = server_a.read().await.unwrap();
    let mut server_b_txn = server_b.write(duration_from_epoch_now()).await.unwrap();

    repl_incremental(&mut server_a_txn, &mut server_b_txn);

    // B will now have recieve A's conflict for the original entry.
    let cnf_user_on_b = server_b_txn
        .internal_search_conflict_uuid(t_uuid)
        .expect("Unable to conflict entries.")
        .pop()
        .expect("No conflict entries present");

    // B should now have the conflict of A's reference.
    let cnf_ref_a_on_b = server_b_txn
        .internal_search_conflict_uuid(ref_uuid_a)
        .expect("Unable to conflict entries.")
        .pop()
        .expect("No conflict entries present");

    // And we still have conflict from B
    let cnf_ref_b_on_b = server_b_txn
        .internal_search_conflict_uuid(ref_uuid_b)
        .expect("Unable to conflict entries.")
        .pop()
        .expect("No conflict entries present");

    trace!(?cnf_user_on_b);
    trace!(?cnf_ref_a_on_b);
    trace!(?cnf_ref_b_on_b);

    server_b_txn.commit().expect("Failed to commit");
    drop(server_a_txn);
}

// Test change of domain version over incremental.
//
// todo when I have domain version migrations working.
