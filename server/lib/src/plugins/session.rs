//! This plugin maintains consistency of authenticated sessions on accounts.
//!
//! An example of this is that oauth2 sessions are child of user auth sessions,
//! such than when the user auth session is terminated, then the corresponding
//! oauth2 session should also be terminated.
//!
//! This plugin is also responsible for invaliding old sessions that are past
//! their expiry.

use crate::event::ModifyEvent;
use crate::plugins::Plugin;
use crate::prelude::*;
use crate::value::SessionState;
use std::collections::BTreeSet;
use std::sync::Arc;
use time::OffsetDateTime;

pub struct SessionConsistency {}

impl Plugin for SessionConsistency {
    fn id() -> &'static str {
        "plugin_session_consistency"
    }

    #[instrument(level = "debug", name = "session_consistency", skip_all)]
    fn pre_modify(
        qs: &mut QueryServerWriteTransaction,
        _pre_cand: &[Arc<EntrySealedCommitted>],
        cand: &mut Vec<Entry<EntryInvalid, EntryCommitted>>,
        _me: &ModifyEvent,
    ) -> Result<(), OperationError> {
        Self::modify_inner(qs, cand)
    }

    #[instrument(level = "debug", name = "session_consistency", skip_all)]
    fn pre_batch_modify(
        qs: &mut QueryServerWriteTransaction,
        _pre_cand: &[Arc<EntrySealedCommitted>],
        cand: &mut Vec<Entry<EntryInvalid, EntryCommitted>>,
        _me: &BatchModifyEvent,
    ) -> Result<(), OperationError> {
        Self::modify_inner(qs, cand)
    }
}

impl SessionConsistency {
    fn modify_inner<T: Clone + std::fmt::Debug>(
        qs: &mut QueryServerWriteTransaction,
        cand: &mut [Entry<EntryInvalid, T>],
    ) -> Result<(), OperationError> {
        let curtime = qs.get_curtime();
        let curtime_odt = OffsetDateTime::UNIX_EPOCH + curtime;
        trace!(%curtime_odt);

        // We need to assert a number of properties. We must do these *in order*.
        cand.iter_mut().try_for_each(|entry| {
            // * If the session's credential is no longer on the account, we remove the session.
            let cred_ids: BTreeSet<Uuid> =
                entry
                    .get_ava_single_credential(Attribute::PrimaryCredential)
                        .iter()
                        .map(|c| c.uuid)

                .chain(
                    entry.get_ava_passkeys(Attribute::PassKeys)
                        .iter()
                        .flat_map(|pks| pks.keys().copied())
                )
                .chain(
                    entry.get_ava_attestedpasskeys(Attribute::AttestedPasskeys)
                        .iter()
                        .flat_map(|pks| pks.keys().copied())
                )
                .chain(
                    entry.get_ava_single_uuid(Attribute::OAuth2AccountCredentialUuid)
                )
                .collect();

            let invalidate: Option<BTreeSet<_>> = entry.get_ava_as_session_map(Attribute::UserAuthTokenSession)
                .map(|sessions| {
                    sessions.iter().filter_map(|(session_id, session)| {
                        match &session.state {
                            SessionState::RevokedAt(_) => {
                                // Ignore, it's already revoked.
                                None
                            }
                            SessionState::ExpiresAt(_) |
                            SessionState::NeverExpires =>
                                if !cred_ids.contains(&session.cred_id) {
                                    info!(%session_id, "Revoking auth session whose issuing credential no longer exists");
                                    Some(PartialValue::Refer(*session_id))
                                } else {
                                    None
                                },
                        }
                    })
                    .collect()
                });

            if let Some(invalidate) = invalidate.as_ref() {
                entry.remove_avas(Attribute::UserAuthTokenSession, invalidate);
            }

            // * If a UAT is past its expiry, remove it.
            let expired: Option<BTreeSet<_>> = entry.get_ava_as_session_map(Attribute::UserAuthTokenSession)
                .map(|sessions| {
                    sessions.iter().filter_map(|(session_id, session)| {
                        trace!(?session_id, ?session);
                        match &session.state {
                            SessionState::ExpiresAt(exp) if exp <= &curtime_odt => {
                                info!(%session_id, "Removing expired auth session");
                                Some(PartialValue::Refer(*session_id))
                            }
                            _ => None,
                        }
                    })
                    .collect()
                });

            if let Some(expired) = expired.as_ref() {
                entry.remove_avas(Attribute::UserAuthTokenSession, expired);
            }

            // * If an oauth2 session is past it's expiry, remove it.
            // * If an oauth2 session is past the grace window, and no parent session exists, remove it.
            let oauth2_remove: Option<BTreeSet<_>> = entry.get_ava_as_oauth2session_map(Attribute::OAuth2Session).map(|oauth2_sessions| {
                // If we have oauth2 sessions, we need to be able to lookup if sessions exist in the uat.
                let sessions = entry.get_ava_as_session_map(Attribute::UserAuthTokenSession);

                oauth2_sessions.iter().filter_map(|(o2_session_id, session)| {
                    trace!(?o2_session_id, ?session);
                    match &session.state {
                        SessionState::ExpiresAt(exp) if exp <= &curtime_odt => {
                            info!(%o2_session_id, "Removing expired oauth2 session");
                            Some(PartialValue::Refer(*o2_session_id))
                        }
                        SessionState::RevokedAt(_) => {
                            // no-op, it's already revoked.
                            trace!("Skip already revoked session");
                            None
                        }
                        _ => {
                            // Okay, now check the issued / grace time for parent enforcement.
                                if sessions.map(|session_map| {
                                    if let Some(parent_session_id) = session.parent.as_ref() {
                                        // A parent session id exists - validate it exists in the account.
                                        if let Some(parent_session) = session_map.get(parent_session_id) {
                                            // Only match non-revoked sessions
                                            !matches!(parent_session.state, SessionState::RevokedAt(_))
                                        } else {
                                            // not found
                                            false
                                        }
                                    } else {
                                        // The session specifically has no parent session and so is
                                        // not bounded by it's presence.
                                        true
                                    }
                                }).unwrap_or(false) {
                                    // The parent exists and is still valid, go ahead
                                    debug!("Parent session remains valid.");
                                    None
                                } else {
                                    // Can't find the parent. Are we within grace window
                                    if session.issued_at + AUTH_TOKEN_GRACE_WINDOW <= curtime_odt {
                                        info!(%o2_session_id, parent_id = ?session.parent, "Removing orphaned oauth2 session");
                                        Some(PartialValue::Refer(*o2_session_id))
                                    } else {
                                        // Grace window is still in effect
                                        debug!("Not enforcing parent session consistency on session within grace window");
                                        None
                                    }

                                }
                        }
                    }

                })
                .collect()
            });

            if let Some(oauth2_remove) = oauth2_remove.as_ref() {
                entry.remove_avas(Attribute::OAuth2Session, oauth2_remove);
            }

            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::prelude::*;

    use crate::event::CreateEvent;
    use crate::value::{AuthType, Oauth2Session, Session, SessionState};
    use kanidm_proto::constants::OAUTH2_SCOPE_OPENID;
    use std::time::Duration;
    use time::OffsetDateTime;
    use uuid::uuid;

    use crate::credential::Credential;
    use kanidm_lib_crypto::CryptoPolicy;

    // Test expiry of old sessions

    #[qs_test]
    async fn test_session_consistency_expire_old_sessions(server: &QueryServer) {
        let curtime = duration_from_epoch_now();
        let curtime_odt = OffsetDateTime::UNIX_EPOCH + curtime;

        let p = CryptoPolicy::minimum();
        let cred = Credential::new_password_only(&p, "test_password", OffsetDateTime::UNIX_EPOCH).unwrap();
        let cred_id = cred.uuid;

        let exp_curtime = curtime + Duration::from_secs(60);
        let exp_curtime_odt = OffsetDateTime::UNIX_EPOCH + exp_curtime;

        // Create a user
        let mut server_txn = server.write(curtime).await.unwrap();

        let tuuid = uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930");

        let e1 = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Person.to_value()),
            (Attribute::Class, EntryClass::Account.to_value()),
            (Attribute::Name, Value::new_iname("testperson1")),
            (Attribute::Uuid, Value::Uuid(tuuid)),
            (Attribute::Description, Value::new_utf8s("testperson1")),
            (Attribute::DisplayName, Value::new_utf8s("testperson1")),
            (
                Attribute::PrimaryCredential,
                Value::Cred("primary".to_string(), cred.clone())
            )
        );

        let ce = CreateEvent::new_internal(vec![e1]);
        assert!(server_txn.create(&ce).is_ok());

        // Create a fake session.
        let session_id = Uuid::new_v4();
        let state = SessionState::ExpiresAt(exp_curtime_odt);
        let issued_at = curtime_odt;
        let issued_by = IdentityId::User(tuuid);
        let scope = SessionScope::ReadOnly;

        let session = Value::Session(
            session_id,
            Session {
                label: "label".to_string(),
                state,
                // Need the other inner bits?
                // for the gracewindow.
                issued_at,
                // Who actually created this?
                issued_by,
                cred_id,
                // What is the access scope of this session? This is
                // for auditing purposes.
                scope,
                type_: AuthType::Passkey,
                ext_metadata: Default::default(),
            },
        );

        // Mod the user
        let modlist = ModifyList::new_append(Attribute::UserAuthTokenSession, session);

        server_txn
            .internal_modify(
                &filter!(f_eq(Attribute::Uuid, PartialValue::Uuid(tuuid))),
                &modlist,
            )
            .expect("Failed to modify user");

        // Still there

        let entry = server_txn.internal_search_uuid(tuuid).expect("failed");

        let session = entry
            .get_ava_as_session_map(Attribute::UserAuthTokenSession)
            .and_then(|sessions| sessions.get(&session_id))
            .expect("No session map found");
        assert!(matches!(session.state, SessionState::ExpiresAt(_)));

        assert!(server_txn.commit().is_ok());
        let mut server_txn = server.write(exp_curtime).await.unwrap();

        // Mod again - anything will do.
        let modlist = ModifyList::new_purge_and_set(
            Attribute::Description,
            Value::new_utf8s("test person 1 change"),
        );

        server_txn
            .internal_modify(
                &filter!(f_eq(Attribute::Uuid, PartialValue::Uuid(tuuid))),
                &modlist,
            )
            .expect("Failed to modify user");

        // Session gone.
        let entry = server_txn.internal_search_uuid(tuuid).expect("failed");

        // We get the attribute and have to check it's now in a revoked state.
        let session = entry
            .get_ava_as_session_map(Attribute::UserAuthTokenSession)
            .and_then(|sessions| sessions.get(&session_id))
            .expect("No session map found");
        assert!(matches!(session.state, SessionState::RevokedAt(_)));

        assert!(server_txn.commit().is_ok());
    }

    // Test expiry of old oauth2 sessions
    #[qs_test]
    async fn test_session_consistency_oauth2_expiry_cleanup(server: &QueryServer) {
        let curtime = duration_from_epoch_now();
        let curtime_odt = OffsetDateTime::UNIX_EPOCH + curtime;

        let p = CryptoPolicy::minimum();
        let cred = Credential::new_password_only(&p, "test_password", OffsetDateTime::UNIX_EPOCH).unwrap();
        let cred_id = cred.uuid;

        // Set exp to gracewindow.
        let exp_curtime = curtime + AUTH_TOKEN_GRACE_WINDOW;
        let exp_curtime_odt = OffsetDateTime::UNIX_EPOCH + exp_curtime;

        // Create a user
        let mut server_txn = server.write(curtime).await.unwrap();

        let tuuid = uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930");
        let rs_uuid = Uuid::new_v4();

        let e1 = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Person.to_value()),
            (Attribute::Class, EntryClass::Account.to_value()),
            (Attribute::Name, Value::new_iname("testperson1")),
            (Attribute::Uuid, Value::Uuid(tuuid)),
            (Attribute::Description, Value::new_utf8s("testperson1")),
            (Attribute::DisplayName, Value::new_utf8s("testperson1")),
            (
                Attribute::PrimaryCredential,
                Value::Cred("primary".to_string(), cred.clone())
            )
        );

        let e2 = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Account.to_value()),
            (
                Attribute::Class,
                EntryClass::OAuth2ResourceServer.to_value()
            ),
            (
                Attribute::Class,
                EntryClass::OAuth2ResourceServerBasic.to_value()
            ),
            (Attribute::Uuid, Value::Uuid(rs_uuid)),
            (Attribute::Name, Value::new_iname("test_resource_server")),
            (
                Attribute::DisplayName,
                Value::new_utf8s("test_resource_server")
            ),
            (
                Attribute::OAuth2RsOriginLanding,
                Value::new_url_s("https://demo.example.com").unwrap()
            ),
            // System admins
            (
                Attribute::OAuth2RsScopeMap,
                Value::new_oauthscopemap(
                    UUID_IDM_ALL_ACCOUNTS,
                    btreeset![OAUTH2_SCOPE_OPENID.to_string()]
                )
                .expect("invalid oauthscope")
            )
        );

        let ce = CreateEvent::new_internal(vec![e1, e2]);
        assert!(server_txn.create(&ce).is_ok());

        // Create a fake session and oauth2 session.

        let session_id = Uuid::new_v4();
        let parent_id = Uuid::new_v4();
        let state = SessionState::ExpiresAt(exp_curtime_odt);
        let issued_at = curtime_odt;
        let issued_by = IdentityId::User(tuuid);
        let scope = SessionScope::ReadOnly;

        // Mod the user
        let modlist = modlist!([
            Modify::Present(
                "oauth2_session".into(),
                Value::Oauth2Session(
                    session_id,
                    Oauth2Session {
                        parent: Some(parent_id),
                        // Set to the exp window.
                        state,
                        issued_at,
                        rs_uuid,
                    },
                )
            ),
            Modify::Present(
                Attribute::UserAuthTokenSession,
                Value::Session(
                    parent_id,
                    Session {
                        label: "label".to_string(),
                        // Note we set the exp to None so we are not removing based on removal of the parent.
                        state: SessionState::NeverExpires,
                        // Need the other inner bits?
                        // for the gracewindow.
                        issued_at,
                        // Who actually created this?
                        issued_by,
                        cred_id,
                        // What is the access scope of this session? This is
                        // for auditing purposes.
                        scope,
                        type_: AuthType::Passkey,
                        ext_metadata: Default::default(),
                    },
                )
            ),
        ]);

        server_txn
            .internal_modify(
                &filter!(f_eq(Attribute::Uuid, PartialValue::Uuid(tuuid))),
                &modlist,
            )
            .expect("Failed to modify user");

        // Still there

        let entry = server_txn.internal_search_uuid(tuuid).expect("failed");

        let session = entry
            .get_ava_as_session_map(Attribute::UserAuthTokenSession)
            .and_then(|sessions| sessions.get(&parent_id))
            .expect("No session map found");
        assert!(matches!(session.state, SessionState::NeverExpires));

        let session = entry
            .get_ava_as_oauth2session_map(Attribute::OAuth2Session)
            .and_then(|sessions| sessions.get(&session_id))
            .expect("No session map found");
        assert!(matches!(session.state, SessionState::ExpiresAt(_)));

        assert!(server_txn.commit().is_ok());

        // Note as we are now past exp time, the oauth2 session will be removed, but the uat session
        // will remain.
        let mut server_txn = server.write(exp_curtime).await.unwrap();

        // Mod again - anything will do.
        let modlist = ModifyList::new_purge_and_set(
            Attribute::Description,
            Value::new_utf8s("test person 1 change"),
        );

        server_txn
            .internal_modify(
                &filter!(f_eq(Attribute::Uuid, PartialValue::Uuid(tuuid))),
                &modlist,
            )
            .expect("Failed to modify user");

        // Session gone.
        let entry = server_txn.internal_search_uuid(tuuid).expect("failed");

        // Note the uat is still present
        let session = entry
            .get_ava_as_session_map(Attribute::UserAuthTokenSession)
            .and_then(|sessions| sessions.get(&parent_id))
            .expect("No session map found");
        assert!(matches!(session.state, SessionState::NeverExpires));

        let session = entry
            .get_ava_as_oauth2session_map(Attribute::OAuth2Session)
            .and_then(|sessions| sessions.get(&session_id))
            .expect("No session map found");
        assert!(matches!(session.state, SessionState::RevokedAt(_)));

        assert!(server_txn.commit().is_ok());
    }

    // test removal of a session removes related oauth2 sessions.
    #[qs_test]
    async fn test_session_consistency_oauth2_removed_by_parent(server: &QueryServer) {
        let curtime = duration_from_epoch_now();
        let curtime_odt = OffsetDateTime::UNIX_EPOCH + curtime;
        let exp_curtime = curtime + AUTH_TOKEN_GRACE_WINDOW;

        let p = CryptoPolicy::minimum();
        let cred = Credential::new_password_only(&p, "test_password", OffsetDateTime::UNIX_EPOCH).unwrap();
        let cred_id = cred.uuid;

        // Create a user
        let mut server_txn = server.write(curtime).await.unwrap();

        let tuuid = uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930");
        let rs_uuid = Uuid::new_v4();

        let e1 = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Person.to_value()),
            (Attribute::Class, EntryClass::Account.to_value()),
            (Attribute::Name, Value::new_iname("testperson1")),
            (Attribute::Uuid, Value::Uuid(tuuid)),
            (Attribute::Description, Value::new_utf8s("testperson1")),
            (Attribute::DisplayName, Value::new_utf8s("testperson1")),
            (
                Attribute::PrimaryCredential,
                Value::Cred("primary".to_string(), cred.clone())
            )
        );

        let e2 = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Account.to_value()),
            (
                Attribute::Class,
                EntryClass::OAuth2ResourceServer.to_value()
            ),
            (
                Attribute::Class,
                EntryClass::OAuth2ResourceServerBasic.to_value()
            ),
            (Attribute::Uuid, Value::Uuid(rs_uuid)),
            (Attribute::Name, Value::new_iname("test_resource_server")),
            (
                Attribute::DisplayName,
                Value::new_utf8s("test_resource_server")
            ),
            (
                Attribute::OAuth2RsOriginLanding,
                Value::new_url_s("https://demo.example.com").unwrap()
            ),
            // System admins
            (
                Attribute::OAuth2RsScopeMap,
                Value::new_oauthscopemap(
                    UUID_IDM_ALL_ACCOUNTS,
                    btreeset![OAUTH2_SCOPE_OPENID.to_string()]
                )
                .expect("invalid oauthscope")
            )
        );

        let ce = CreateEvent::new_internal(vec![e1, e2]);
        assert!(server_txn.create(&ce).is_ok());

        // Create a fake session and oauth2 session.

        let session_id = Uuid::new_v4();
        let parent_id = Uuid::new_v4();
        let issued_at = curtime_odt;
        let issued_by = IdentityId::User(tuuid);
        let scope = SessionScope::ReadOnly;

        // Mod the user
        let modlist = modlist!([
            Modify::Present(
                "oauth2_session".into(),
                Value::Oauth2Session(
                    session_id,
                    Oauth2Session {
                        parent: Some(parent_id),
                        // Note we set the exp to None so we are not removing based on exp
                        state: SessionState::NeverExpires,
                        issued_at,
                        rs_uuid,
                    },
                )
            ),
            Modify::Present(
                Attribute::UserAuthTokenSession,
                Value::Session(
                    parent_id,
                    Session {
                        label: "label".to_string(),
                        // Note we set the exp to None so we are not removing based on removal of the parent.
                        state: SessionState::NeverExpires,
                        // Need the other inner bits?
                        // for the gracewindow.
                        issued_at,
                        // Who actually created this?
                        issued_by,
                        cred_id,
                        // What is the access scope of this session? This is
                        // for auditing purposes.
                        scope,
                        type_: AuthType::Passkey,
                        ext_metadata: Default::default(),
                    },
                )
            ),
        ]);

        server_txn
            .internal_modify(
                &filter!(f_eq(Attribute::Uuid, PartialValue::Uuid(tuuid))),
                &modlist,
            )
            .expect("Failed to modify user");

        // Still there

        let entry = server_txn.internal_search_uuid(tuuid).expect("failed");

        let session = entry
            .get_ava_as_session_map(Attribute::UserAuthTokenSession)
            .and_then(|sessions| sessions.get(&parent_id))
            .expect("No session map found");
        assert!(matches!(session.state, SessionState::NeverExpires));

        let session = entry
            .get_ava_as_oauth2session_map(Attribute::OAuth2Session)
            .and_then(|sessions| sessions.get(&session_id))
            .expect("No session map found");
        assert!(matches!(session.state, SessionState::NeverExpires));

        // We need the time to be past grace_window.
        assert!(server_txn.commit().is_ok());
        let mut server_txn = server.write(exp_curtime).await.unwrap();

        // Mod again - remove the parent session.
        let modlist = ModifyList::new_remove(
            Attribute::UserAuthTokenSession,
            PartialValue::Refer(parent_id),
        );

        server_txn
            .internal_modify(
                &filter!(f_eq(Attribute::Uuid, PartialValue::Uuid(tuuid))),
                &modlist,
            )
            .expect("Failed to modify user");

        // Session gone.
        let entry = server_txn.internal_search_uuid(tuuid).expect("failed");

        // Note the uat is removed
        let session = entry
            .get_ava_as_session_map(Attribute::UserAuthTokenSession)
            .and_then(|sessions| sessions.get(&parent_id))
            .expect("No session map found");
        assert!(matches!(session.state, SessionState::RevokedAt(_)));

        // The oauth2 session is also removed.
        let session = entry
            .get_ava_as_oauth2session_map(Attribute::OAuth2Session)
            .and_then(|sessions| sessions.get(&session_id))
            .expect("No session map found");
        assert!(matches!(session.state, SessionState::RevokedAt(_)));

        assert!(server_txn.commit().is_ok());
    }

    // Test if an oauth2 session exists, the grace window passes and it's UAT doesn't exist.
    #[qs_test]
    async fn test_session_consistency_oauth2_grace_window_past(server: &QueryServer) {
        let curtime = duration_from_epoch_now();
        let curtime_odt = OffsetDateTime::UNIX_EPOCH + curtime;

        // Set exp to gracewindow.
        let exp_curtime = curtime + AUTH_TOKEN_GRACE_WINDOW;
        // let exp_curtime_odt = OffsetDateTime::UNIX_EPOCH + exp_curtime;

        // Create a user
        let mut server_txn = server.write(curtime).await.unwrap();

        let tuuid = uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930");
        let rs_uuid = Uuid::new_v4();

        let e1 = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Person.to_value()),
            (Attribute::Class, EntryClass::Account.to_value()),
            (Attribute::Name, Value::new_iname("testperson1")),
            (Attribute::Uuid, Value::Uuid(tuuid)),
            (Attribute::Description, Value::new_utf8s("testperson1")),
            (Attribute::DisplayName, Value::new_utf8s("testperson1"))
        );

        let e2 = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Account.to_value()),
            (
                Attribute::Class,
                EntryClass::OAuth2ResourceServer.to_value()
            ),
            (
                Attribute::Class,
                EntryClass::OAuth2ResourceServerBasic.to_value()
            ),
            (Attribute::Uuid, Value::Uuid(rs_uuid)),
            (Attribute::Name, Value::new_iname("test_resource_server")),
            (
                Attribute::DisplayName,
                Value::new_utf8s("test_resource_server")
            ),
            (
                Attribute::OAuth2RsOriginLanding,
                Value::new_url_s("https://demo.example.com").unwrap()
            ),
            // System admins
            (
                Attribute::OAuth2RsScopeMap,
                Value::new_oauthscopemap(
                    UUID_IDM_ALL_ACCOUNTS,
                    btreeset![OAUTH2_SCOPE_OPENID.to_string()]
                )
                .expect("invalid oauthscope")
            )
        );

        let ce = CreateEvent::new_internal(vec![e1, e2]);
        assert!(server_txn.create(&ce).is_ok());

        // Create a fake session.
        let session_id = Uuid::new_v4();
        let parent = Uuid::new_v4();
        let issued_at = curtime_odt;

        let session = Value::Oauth2Session(
            session_id,
            Oauth2Session {
                parent: Some(parent),
                // Note we set the exp to None so we are asserting the removal is due to the lack
                // of the parent session.
                state: SessionState::NeverExpires,
                issued_at,
                rs_uuid,
            },
        );

        // Mod the user
        let modlist = ModifyList::new_append(Attribute::OAuth2Session, session);

        server_txn
            .internal_modify(
                &filter!(f_eq(Attribute::Uuid, PartialValue::Uuid(tuuid))),
                &modlist,
            )
            .expect("Failed to modify user");

        // Still there

        let entry = server_txn.internal_search_uuid(tuuid).expect("failed");

        let session = entry
            .get_ava_as_oauth2session_map(Attribute::OAuth2Session)
            .and_then(|sessions| sessions.get(&session_id))
            .expect("No session map found");
        assert!(matches!(session.state, SessionState::NeverExpires));

        assert!(server_txn.commit().is_ok());

        // Note the exp_curtime now is past the gracewindow. This will trigger
        // consistency to purge the un-matched session.
        let mut server_txn = server.write(exp_curtime).await.unwrap();

        // Mod again - anything will do.
        let modlist = ModifyList::new_purge_and_set(
            Attribute::Description,
            Value::new_utf8s("test person 1 change"),
        );

        server_txn
            .internal_modify(
                &filter!(f_eq(Attribute::Uuid, PartialValue::Uuid(tuuid))),
                &modlist,
            )
            .expect("Failed to modify user");

        // Session gone.
        let entry = server_txn.internal_search_uuid(tuuid).expect("failed");

        // Note it's a not condition now.
        let session = entry
            .get_ava_as_oauth2session_map(Attribute::OAuth2Session)
            .and_then(|sessions| sessions.get(&session_id))
            .expect("No session map found");
        assert!(matches!(session.state, SessionState::RevokedAt(_)));

        assert!(server_txn.commit().is_ok());
    }

    #[qs_test]
    async fn test_session_consistency_expire_when_cred_removed(server: &QueryServer) {
        let curtime = duration_from_epoch_now();
        let curtime_odt = OffsetDateTime::UNIX_EPOCH + curtime;

        let p = CryptoPolicy::minimum();
        let cred = Credential::new_password_only(&p, "test_password", OffsetDateTime::UNIX_EPOCH).unwrap();
        let cred_id = cred.uuid;

        // Create a user
        let mut server_txn = server.write(curtime).await.unwrap();

        let tuuid = uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930");

        let e1 = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Person.to_value()),
            (Attribute::Class, EntryClass::Account.to_value()),
            (Attribute::Name, Value::new_iname("testperson1")),
            (Attribute::Uuid, Value::Uuid(tuuid)),
            (Attribute::Description, Value::new_utf8s("testperson1")),
            (Attribute::DisplayName, Value::new_utf8s("testperson1")),
            (
                Attribute::PrimaryCredential,
                Value::Cred("primary".to_string(), cred.clone())
            )
        );

        let ce = CreateEvent::new_internal(vec![e1]);
        assert!(server_txn.create(&ce).is_ok());

        // Create a fake session.
        let session_id = Uuid::new_v4();
        // No expiry!
        let issued_at = curtime_odt;
        let issued_by = IdentityId::User(tuuid);
        let scope = SessionScope::ReadOnly;

        let session = Value::Session(
            session_id,
            Session {
                label: "label".to_string(),
                state: SessionState::NeverExpires,
                // Need the other inner bits?
                // for the gracewindow.
                issued_at,
                // Who actually created this?
                issued_by,
                cred_id,
                // What is the access scope of this session? This is
                // for auditing purposes.
                scope,
                type_: AuthType::Passkey,
                ext_metadata: Default::default(),
            },
        );

        // Mod the user
        let modlist = ModifyList::new_append(Attribute::UserAuthTokenSession, session);

        server_txn
            .internal_modify(
                &filter!(f_eq(Attribute::Uuid, PartialValue::Uuid(tuuid))),
                &modlist,
            )
            .expect("Failed to modify user");

        // Still there

        let entry = server_txn.internal_search_uuid(tuuid).expect("failed");

        let session = entry
            .get_ava_as_session_map(Attribute::UserAuthTokenSession)
            .and_then(|sessions| sessions.get(&session_id))
            .expect("No session map found");
        assert!(matches!(session.state, SessionState::NeverExpires));

        assert!(server_txn.commit().is_ok());

        // Notice we keep the time the same for the txn.
        let mut server_txn = server.write(curtime).await.unwrap();

        // Remove the primary credential
        let modlist = ModifyList::new_purge(Attribute::PrimaryCredential);

        server_txn
            .internal_modify(
                &filter!(f_eq(Attribute::Uuid, PartialValue::Uuid(tuuid))),
                &modlist,
            )
            .expect("Failed to modify user");

        // Session gone.
        let entry = server_txn.internal_search_uuid(tuuid).expect("failed");

        // Note it's a not condition now.
        let session = entry
            .get_ava_as_session_map(Attribute::UserAuthTokenSession)
            .and_then(|sessions| sessions.get(&session_id))
            .expect("No session map found");
        assert!(matches!(session.state, SessionState::RevokedAt(_)));

        assert!(server_txn.commit().is_ok());
    }
}
