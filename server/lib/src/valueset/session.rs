use crate::{
    be::dbvalue::{
        DbCidV1, DbValueAccessScopeV1, DbValueApiToken, DbValueApiTokenScopeV1, DbValueAuthTypeV1,
        DbValueIdentityId, DbValueOauth2Session, DbValueSession, DbValueSessionExtMetadataV1,
        DbValueSessionStateV1,
    },
    prelude::*,
    repl::cid::Cid,
    schema::SchemaAttribute,
    value::{
        ApiToken, ApiTokenScope, AuthType, OAuth2Session, Session, SessionExtMetadata,
        SessionScope, SessionState,
    },
    valueset::{uuid_to_proto_string, DbValueSetV2, ScimResolveStatus, ValueSet},
};
use kanidm_proto::scim_v1::server::{ScimApiToken, ScimAuthSession, ScimOAuth2Session};
use std::collections::{btree_map::Entry as BTreeEntry, BTreeMap};
use time::OffsetDateTime;

#[derive(Debug, Clone)]
pub struct ValueSetSession {
    map: BTreeMap<Uuid, Session>,
}

impl ValueSetSession {
    pub fn new(u: Uuid, m: Session) -> Box<Self> {
        let mut map = BTreeMap::new();
        map.insert(u, m);
        Box::new(ValueSetSession { map })
    }

    pub fn push(&mut self, u: Uuid, m: Session) -> bool {
        self.map.insert(u, m).is_none()
    }

    fn to_vec_dbvs(&self) -> Vec<DbValueSession> {
        self.map
            .iter()
            .map(|(u, m)| DbValueSession::V4 {
                refer: *u,
                label: m.label.clone(),

                state: match &m.state {
                    SessionState::ExpiresAt(odt) => {
                        debug_assert_eq!(odt.offset(), time::UtcOffset::UTC);
                        #[allow(clippy::expect_used)]
                        odt.format(&Rfc3339)
                            .map(DbValueSessionStateV1::ExpiresAt)
                            .expect("Failed to format timestamp into RFC3339!")
                    }
                    SessionState::NeverExpires => DbValueSessionStateV1::Never,
                    SessionState::RevokedAt(c) => DbValueSessionStateV1::RevokedAt(DbCidV1 {
                        server_id: c.s_uuid,
                        timestamp: c.ts,
                    }),
                },

                issued_at: {
                    debug_assert_eq!(m.issued_at.offset(), time::UtcOffset::UTC);
                    #[allow(clippy::expect_used)]
                    m.issued_at
                        .format(&Rfc3339)
                        .expect("Failed to format timestamp into RFC3339!")
                },
                issued_by: match m.issued_by {
                    IdentityId::Internal(u) => DbValueIdentityId::V2Internal(u),
                    IdentityId::User(u) => DbValueIdentityId::V1Uuid(u),
                    IdentityId::Synch(u) => DbValueIdentityId::V1Sync(u),
                },
                cred_id: m.cred_id,
                scope: match m.scope {
                    SessionScope::ReadOnly => DbValueAccessScopeV1::ReadOnly,
                    SessionScope::ReadWrite => DbValueAccessScopeV1::ReadWrite,
                    SessionScope::PrivilegeCapable => DbValueAccessScopeV1::PrivilegeCapable,
                    SessionScope::Synchronise => DbValueAccessScopeV1::Synchronise,
                },
                type_: match m.type_ {
                    AuthType::Anonymous => DbValueAuthTypeV1::Anonymous,
                    AuthType::Password => DbValueAuthTypeV1::Password,
                    AuthType::GeneratedPassword => DbValueAuthTypeV1::GeneratedPassword,
                    AuthType::PasswordTotp => DbValueAuthTypeV1::PasswordTotp,
                    AuthType::PasswordBackupCode => DbValueAuthTypeV1::PasswordBackupCode,
                    AuthType::PasswordSecurityKey => DbValueAuthTypeV1::PasswordSecurityKey,
                    AuthType::Passkey => DbValueAuthTypeV1::Passkey,
                    AuthType::AttestedPasskey => DbValueAuthTypeV1::AttestedPasskey,
                    AuthType::OAuth2Trust => DbValueAuthTypeV1::OAuth2Trust,
                },
                ext_metadata: match &m.ext_metadata {
                    SessionExtMetadata::None => DbValueSessionExtMetadataV1::None,
                    SessionExtMetadata::OAuth2 {
                        access_expires_at,
                        access_token,
                        refresh_token,
                    } => DbValueSessionExtMetadataV1::OAuth2 {
                        access_expires_at: *access_expires_at,
                        access_token: access_token.clone(),
                        refresh_token: refresh_token.clone(),
                    },
                },
            })
            .collect()
    }

    fn from_dbv_iter<'a>(
        iter: impl Iterator<Item = &'a DbValueSession>,
    ) -> Result<ValueSet, OperationError> {
        let map = iter
            .filter_map(|dbv| {
                match dbv {
                    // We need to ignore all older session records as they lack the AuthType
                    // record which prevents re-auth working.
                    DbValueSession::V1 { .. }
                    | DbValueSession::V2 { .. }
                    | DbValueSession::V3 { .. } => None,
                    DbValueSession::V4 {
                        refer,
                        label,
                        state,
                        issued_at,
                        issued_by,
                        cred_id,
                        scope,
                        type_,
                        ext_metadata,
                    } => {
                        // Convert things.
                        let issued_at = OffsetDateTime::parse(issued_at, &Rfc3339)
                            .map(|odt| odt.to_offset(time::UtcOffset::UTC))
                            .map_err(|e| {
                                admin_error!(
                                    ?e,
                                    "Invalidating session {} due to invalid issued_at timestamp",
                                    refer
                                )
                            })
                            .ok()?;

                        let state = match state {
                            DbValueSessionStateV1::ExpiresAt(e_inner) => {
                                OffsetDateTime::parse(e_inner, &Rfc3339)
                                    .map(|odt| odt.to_offset(time::UtcOffset::UTC))
                                    .map(SessionState::ExpiresAt)
                                    .map_err(|e| {
                                        admin_error!(
                                        ?e,
                                        "Invalidating session {} due to invalid expiry timestamp",
                                        refer
                                    )
                                    })
                                    .ok()?
                            }
                            DbValueSessionStateV1::Never => SessionState::NeverExpires,
                            DbValueSessionStateV1::RevokedAt(dc) => SessionState::RevokedAt(Cid {
                                s_uuid: dc.server_id,
                                ts: dc.timestamp,
                            }),
                        };

                        let issued_by = match issued_by {
                            DbValueIdentityId::V1Internal => IdentityId::Internal(UUID_SYSTEM),
                            DbValueIdentityId::V2Internal(u) => IdentityId::Internal(*u),
                            DbValueIdentityId::V1Uuid(u) => IdentityId::User(*u),
                            DbValueIdentityId::V1Sync(u) => IdentityId::Synch(*u),
                        };

                        let scope = match scope {
                            DbValueAccessScopeV1::IdentityOnly | DbValueAccessScopeV1::ReadOnly => {
                                SessionScope::ReadOnly
                            }
                            DbValueAccessScopeV1::ReadWrite => SessionScope::ReadWrite,
                            DbValueAccessScopeV1::PrivilegeCapable => {
                                SessionScope::PrivilegeCapable
                            }
                            DbValueAccessScopeV1::Synchronise => SessionScope::Synchronise,
                        };

                        let type_ = match type_ {
                            DbValueAuthTypeV1::Anonymous => AuthType::Anonymous,
                            DbValueAuthTypeV1::Password => AuthType::Password,
                            DbValueAuthTypeV1::GeneratedPassword => AuthType::GeneratedPassword,
                            DbValueAuthTypeV1::PasswordTotp => AuthType::PasswordTotp,
                            DbValueAuthTypeV1::PasswordBackupCode => AuthType::PasswordBackupCode,
                            DbValueAuthTypeV1::PasswordSecurityKey => AuthType::PasswordSecurityKey,
                            DbValueAuthTypeV1::Passkey => AuthType::Passkey,
                            DbValueAuthTypeV1::AttestedPasskey => AuthType::AttestedPasskey,
                            DbValueAuthTypeV1::OAuth2Trust => AuthType::OAuth2Trust,
                        };

                        let ext_metadata = match ext_metadata {
                            DbValueSessionExtMetadataV1::None => SessionExtMetadata::None,
                            DbValueSessionExtMetadataV1::OAuth2 {
                                access_expires_at,
                                access_token,
                                refresh_token,
                            } => SessionExtMetadata::OAuth2 {
                                access_expires_at: *access_expires_at,
                                access_token: access_token.clone(),
                                refresh_token: refresh_token.clone(),
                            },
                        };

                        Some((
                            *refer,
                            Session {
                                label: label.clone(),
                                state,
                                issued_at,
                                issued_by,
                                cred_id: *cred_id,
                                scope,
                                type_,
                                ext_metadata,
                            },
                        ))
                    }
                }
            })
            .collect();
        Ok(Box::new(ValueSetSession { map }))
    }

    pub fn from_dbvs2(data: &[DbValueSession]) -> Result<ValueSet, OperationError> {
        Self::from_dbv_iter(data.iter())
    }

    // We need to allow this, because rust doesn't allow us to impl FromIterator on foreign
    // types, and tuples are always foreign.
    #[allow(clippy::should_implement_trait)]
    pub fn from_iter<T>(iter: T) -> Option<Box<Self>>
    where
        T: IntoIterator<Item = (Uuid, Session)>,
    {
        let map = iter.into_iter().collect();
        Some(Box::new(ValueSetSession { map }))
    }
}

impl ValueSetT for ValueSetSession {
    fn insert_checked(&mut self, value: Value) -> Result<bool, OperationError> {
        match value {
            Value::Session(u, m) => {
                if let BTreeEntry::Vacant(e) = self.map.entry(u) {
                    e.insert(m);
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            _ => Err(OperationError::InvalidValueState),
        }
    }

    fn clear(&mut self) {
        self.map.clear();
    }

    fn remove(&mut self, pv: &PartialValue, cid: &Cid) -> bool {
        if let PartialValue::Refer(u) = pv {
            if let Some(session) = self.map.get_mut(u) {
                if !matches!(session.state, SessionState::RevokedAt(_)) {
                    session.state = SessionState::RevokedAt(*cid);
                }
            }
        }
        self.map.is_empty()
    }

    fn purge(&mut self, cid: &Cid) -> bool {
        for session in self.map.values_mut() {
            // Send them all to the shadow realm
            if !matches!(session.state, SessionState::RevokedAt(_)) {
                session.state = SessionState::RevokedAt(*cid)
            }
        }
        // Can't be purged since we need the cid's of revoked to persist.
        false
    }

    fn trim(&mut self, trim_cid: &Cid) {
        // There might be a neater way to do this with less iterations. The problem
        // is we can't just check on what was in b/older, because then we miss
        // trimmable content from the local map. So once the merge is complete we
        // do a pass for trim.
        self.map.retain(|_, session| {
            match &session.state {
                SessionState::RevokedAt(cid) if cid < trim_cid => {
                    // This value is past the replication trim window and can now safely
                    // be removed
                    false
                }
                // Retain all else
                _ => true,
            }
        });

        // Now, assert that there are fewer or equal sessions to the limit.
        if self.map.len() > SESSION_MAXIMUM {
            // At this point we will force a number of sessions to be removed. This
            // is replication safe since other replicas will also be performing
            // the same operation on merge, since we trim by session issuance order.

            // This is a "slow path". This is because we optimise session storage
            // based on fast session lookup, so now we need to actually create an
            // index based on time. We need to also clone here since we need to mutate
            // self.map which would violate mut/imut.

            warn!(
                "entry has exceeded session_maximum limit ({:?}), force trimming will occur",
                SESSION_MAXIMUM
            );

            let time_idx: BTreeMap<OffsetDateTime, Uuid> = self
                .map
                .iter()
                .map(|(session_id, session)| (session.issued_at, *session_id))
                .collect();

            let to_take = self.map.len() - SESSION_MAXIMUM;

            time_idx.values().take(to_take).for_each(|session_id| {
                warn!(?session_id, "force trimmed");
                self.map.remove(session_id);
            });
        }
        // And we're done.
    }

    fn contains(&self, pv: &PartialValue) -> bool {
        match pv {
            PartialValue::Refer(u) => self.map.contains_key(u),
            _ => false,
        }
    }

    fn substring(&self, _pv: &PartialValue) -> bool {
        false
    }

    fn startswith(&self, _pv: &PartialValue) -> bool {
        false
    }

    fn endswith(&self, _pv: &PartialValue) -> bool {
        false
    }

    fn lessthan(&self, _pv: &PartialValue) -> bool {
        false
    }

    fn len(&self) -> usize {
        self.map.len()
    }

    fn generate_idx_eq_keys(&self) -> Vec<String> {
        self.map
            .keys()
            .map(|u| u.as_hyphenated().to_string())
            .collect()
    }

    fn syntax(&self) -> SyntaxType {
        SyntaxType::Session
    }

    fn validate(&self, _schema_attr: &SchemaAttribute) -> bool {
        true
    }

    fn to_proto_string_clone_iter(&self) -> Box<dyn Iterator<Item = String> + '_> {
        Box::new(
            self.map
                .iter()
                .map(|(u, m)| format!("{}: {:?}", uuid_to_proto_string(*u), m)),
        )
    }

    fn to_scim_value(&self) -> Option<ScimResolveStatus> {
        Some(ScimResolveStatus::Resolved(ScimValueKanidm::from(
            self.map
                .iter()
                .map(|(session_id, session)| {
                    let (expires, revoked) = match &session.state {
                        SessionState::ExpiresAt(odt) => (Some(*odt), None),
                        SessionState::NeverExpires => (None, None),
                        SessionState::RevokedAt(cid) => {
                            let odt: OffsetDateTime = cid.into();
                            (None, Some(odt))
                        }
                    };

                    ScimAuthSession {
                        id: *session_id,
                        expires,
                        revoked,

                        issued_at: session.issued_at,
                        issued_by: Uuid::from(&session.issued_by),
                        credential_id: session.cred_id,
                        auth_type: session.type_.to_string(),
                        session_scope: session.scope.to_string(),
                    }
                })
                .collect::<Vec<_>>(),
        )))
    }

    fn to_db_valueset_v2(&self) -> DbValueSetV2 {
        DbValueSetV2::Session(self.to_vec_dbvs())
    }

    fn to_partialvalue_iter(&self) -> Box<dyn Iterator<Item = PartialValue> + '_> {
        Box::new(self.map.keys().cloned().map(PartialValue::Refer))
    }

    fn to_value_iter(&self) -> Box<dyn Iterator<Item = Value> + '_> {
        Box::new(self.map.iter().map(|(u, m)| Value::Session(*u, m.clone())))
    }

    fn equal(&self, other: &ValueSet) -> bool {
        if let Some(other) = other.as_session_map() {
            &self.map == other
        } else {
            debug_assert!(false);
            false
        }
    }

    fn merge(&mut self, other: &ValueSet) -> Result<(), OperationError> {
        if let Some(b) = other.as_session_map() {
            // We can't just do merge maps here, we have to be aware of the
            // session.state value and what it currently is set to.
            for (k_other, v_other) in b.iter() {
                if let Some(v_self) = self.map.get_mut(k_other) {
                    // We only update if greater. This is where RevokedAt
                    // always proceeds other states, and lower revoked
                    // cids will always take effect.
                    if v_other.state > v_self.state {
                        *v_self = v_other.clone();
                    }
                } else {
                    // Not present, just insert.
                    self.map.insert(*k_other, v_other.clone());
                }
            }
            Ok(())
        } else {
            debug_assert!(false);
            Err(OperationError::InvalidValueState)
        }
    }

    fn as_session_map(&self) -> Option<&BTreeMap<Uuid, Session>> {
        Some(&self.map)
    }

    fn as_ref_uuid_iter(&self) -> Option<Box<dyn Iterator<Item = Uuid> + '_>> {
        // This is what ties us as a type that can be refint checked.
        Some(Box::new(self.map.keys().copied()))
    }

    fn repl_merge_valueset(&self, older: &ValueSet, trim_cid: &Cid) -> Option<ValueSet> {
        // If the older value has a different type - return nothing, we
        // just take the newer value.
        let b = older.as_session_map()?;
        // We can't just do merge maps here, we have to be aware of the
        // session.state value and what it currently is set to.
        let mut map = self.map.clone();
        for (k_other, v_other) in b.iter() {
            if let Some(v_self) = map.get_mut(k_other) {
                // We only update if lower. This is where RevokedAt
                // always proceeds other states, and lower revoked
                // cids will always take effect.
                if v_other.state > v_self.state {
                    *v_self = v_other.clone();
                }
            } else {
                // Not present, just insert.
                map.insert(*k_other, v_other.clone());
            }
        }

        let mut vs = Box::new(ValueSetSession { map });

        vs.trim(trim_cid);

        Some(vs)
    }
}

// == oauth2 session ==

#[derive(Debug, Clone)]
pub struct ValueSetOauth2Session {
    map: BTreeMap<Uuid, OAuth2Session>,
    // this is a "filter" to tell us if as rs_id is used anywhere
    // in this set. The reason is so that we don't do O(n) searches
    // on a refer if it's not in this set. The alternate approach is
    // an index on these maps, but its more work to maintain for a rare
    // situation where we actually want to query rs_uuid -> sessions.
    rs_filter: u128,
}

impl ValueSetOauth2Session {
    pub fn new(u: Uuid, m: OAuth2Session) -> Box<Self> {
        let mut map = BTreeMap::new();
        let rs_filter = m.rs_uuid.as_u128();
        map.insert(u, m);
        Box::new(ValueSetOauth2Session { map, rs_filter })
    }

    pub fn push(&mut self, u: Uuid, m: OAuth2Session) -> bool {
        self.rs_filter |= m.rs_uuid.as_u128();
        self.map.insert(u, m).is_none()
    }

    pub fn from_dbvs2(data: Vec<DbValueOauth2Session>) -> Result<ValueSet, OperationError> {
        let mut rs_filter = u128::MIN;
        let map = data
            .into_iter()
            .filter_map(|dbv| {
                match dbv {
                    DbValueOauth2Session::V1 {
                        refer,
                        parent,
                        expiry,
                        issued_at,
                        rs_uuid,
                    } => {
                        // Convert things.
                        let issued_at = OffsetDateTime::parse(&issued_at, &Rfc3339)
                            .map(|odt| odt.to_offset(time::UtcOffset::UTC))
                            .map_err(|e| {
                                admin_error!(
                                    ?e,
                                    "Invalidating session {} due to invalid issued_at timestamp",
                                    refer
                                )
                            })
                            .ok()?;

                        // This is a bit annoying. In the case we can't parse the optional
                        // expiry, we need to NOT return the session so that it's immediately
                        // invalidated. To do this we have to invert some of the options involved
                        // here.
                        let expiry = expiry
                            .map(|e_inner| {
                                OffsetDateTime::parse(&e_inner, &Rfc3339)
                                    .map(|odt| odt.to_offset(time::UtcOffset::UTC))
                                // We now have an
                                // Option<Result<ODT, _>>
                            })
                            .transpose()
                            // Result<Option<ODT>, _>
                            .map_err(|e| {
                                admin_error!(
                                    ?e,
                                    "Invalidating session {} due to invalid expiry timestamp",
                                    refer
                                )
                            })
                            // Option<Option<ODT>>
                            .ok()?;

                        let state = expiry
                            .map(SessionState::ExpiresAt)
                            .unwrap_or(SessionState::NeverExpires);

                        let parent = Some(parent);

                        // Insert to the rs_filter.
                        rs_filter |= rs_uuid.as_u128();
                        Some((
                            refer,
                            OAuth2Session {
                                parent,
                                state,
                                issued_at,
                                rs_uuid,
                            },
                        ))
                    }
                    DbValueOauth2Session::V2 {
                        refer,
                        parent,
                        state,
                        issued_at,
                        rs_uuid,
                    } => {
                        // Convert things.
                        let issued_at = OffsetDateTime::parse(&issued_at, &Rfc3339)
                            .map(|odt| odt.to_offset(time::UtcOffset::UTC))
                            .map_err(|e| {
                                admin_error!(
                                    ?e,
                                    "Invalidating session {} due to invalid issued_at timestamp",
                                    refer
                                )
                            })
                            .ok()?;

                        let state = match state {
                            DbValueSessionStateV1::ExpiresAt(e_inner) => {
                                OffsetDateTime::parse(&e_inner, &Rfc3339)
                                    .map(|odt| odt.to_offset(time::UtcOffset::UTC))
                                    .map(SessionState::ExpiresAt)
                                    .map_err(|e| {
                                        admin_error!(
                                    ?e,
                                    "Invalidating session {} due to invalid expiry timestamp",
                                    refer
                                )
                                    })
                                    .ok()?
                            }
                            DbValueSessionStateV1::Never => SessionState::NeverExpires,
                            DbValueSessionStateV1::RevokedAt(dc) => SessionState::RevokedAt(Cid {
                                s_uuid: dc.server_id,
                                ts: dc.timestamp,
                            }),
                        };

                        rs_filter |= rs_uuid.as_u128();

                        let parent = Some(parent);

                        Some((
                            refer,
                            OAuth2Session {
                                parent,
                                state,
                                issued_at,
                                rs_uuid,
                            },
                        ))
                    } // End V2
                    DbValueOauth2Session::V3 {
                        refer,
                        parent,
                        state,
                        issued_at,
                        rs_uuid,
                    } => {
                        // Convert things.
                        let issued_at = OffsetDateTime::parse(&issued_at, &Rfc3339)
                            .map(|odt| odt.to_offset(time::UtcOffset::UTC))
                            .map_err(|e| {
                                admin_error!(
                                    ?e,
                                    "Invalidating session {} due to invalid issued_at timestamp",
                                    refer
                                )
                            })
                            .ok()?;

                        let state = match state {
                            DbValueSessionStateV1::ExpiresAt(e_inner) => {
                                OffsetDateTime::parse(&e_inner, &Rfc3339)
                                    .map(|odt| odt.to_offset(time::UtcOffset::UTC))
                                    .map(SessionState::ExpiresAt)
                                    .map_err(|e| {
                                        admin_error!(
                                    ?e,
                                    "Invalidating session {} due to invalid expiry timestamp",
                                    refer
                                )
                                    })
                                    .ok()?
                            }
                            DbValueSessionStateV1::Never => SessionState::NeverExpires,
                            DbValueSessionStateV1::RevokedAt(dc) => SessionState::RevokedAt(Cid {
                                s_uuid: dc.server_id,
                                ts: dc.timestamp,
                            }),
                        };

                        rs_filter |= rs_uuid.as_u128();

                        Some((
                            refer,
                            OAuth2Session {
                                parent,
                                state,
                                issued_at,
                                rs_uuid,
                            },
                        ))
                    } // End V3
                }
            })
            .collect();
        Ok(Box::new(ValueSetOauth2Session { map, rs_filter }))
    }

    // We need to allow this, because rust doesn't allow us to impl FromIterator on foreign
    // types, and tuples are always foreign.
    #[allow(clippy::should_implement_trait)]
    pub fn from_iter<T>(iter: T) -> Option<Box<Self>>
    where
        T: IntoIterator<Item = (Uuid, OAuth2Session)>,
    {
        let mut rs_filter = u128::MIN;
        let map = iter
            .into_iter()
            .map(|(u, m)| {
                rs_filter |= m.rs_uuid.as_u128();
                (u, m)
            })
            .collect();
        Some(Box::new(ValueSetOauth2Session { map, rs_filter }))
    }
}

impl ValueSetT for ValueSetOauth2Session {
    fn insert_checked(&mut self, value: Value) -> Result<bool, OperationError> {
        match value {
            Value::OAuth2Session(u, m) => {
                // Unlike other types, this allows overwriting as oauth2 sessions
                // can be *extended* in time length.
                match self.map.entry(u) {
                    BTreeEntry::Vacant(e) => {
                        self.rs_filter |= m.rs_uuid.as_u128();
                        e.insert(m);
                        Ok(true)
                    }
                    BTreeEntry::Occupied(mut e) => {
                        let e_v = e.get_mut();
                        if m.state > e_v.state {
                            // Replace if the state has higher priority.
                            *e_v = m;
                            Ok(true)
                        } else {
                            // Else take no action.
                            Ok(false)
                        }
                    }
                }
            }
            _ => Err(OperationError::InvalidValueState),
        }
    }

    fn clear(&mut self) {
        self.rs_filter = u128::MIN;
        self.map.clear();
    }

    fn remove(&mut self, pv: &PartialValue, cid: &Cid) -> bool {
        if let PartialValue::Refer(u) = pv {
            if let Some(session) = self.map.get_mut(u) {
                if !matches!(session.state, SessionState::RevokedAt(_)) {
                    session.state = SessionState::RevokedAt(*cid);
                }
            } else {
                // What if it's an rs_uuid?
                let u_int = u.as_u128();
                if self.rs_filter & u_int == u_int {
                    // It's there, so we need to do a more costly revoke over the values
                    // that are present.
                    let mut removed = false;
                    self.map.values_mut().for_each(|session| {
                        if session.rs_uuid == *u {
                            session.state = SessionState::RevokedAt(*cid);
                            removed = true;
                        }
                    });
                }
            }
        };
        self.map.is_empty()
    }

    fn purge(&mut self, cid: &Cid) -> bool {
        for session in self.map.values_mut() {
            // Send them all to the shadow realm
            if !matches!(session.state, SessionState::RevokedAt(_)) {
                session.state = SessionState::RevokedAt(*cid)
            }
        }
        // Can't be purged since we need the cid's of revoked to persist.
        false
    }

    fn trim(&mut self, trim_cid: &Cid) {
        // There might be a neater way to do this with less iterations. The problem
        // is we can't just check on what was in b/older, because then we miss
        // trimmable content from the local map. So once the merge is complete we
        // do a pass for trim.
        self.map.retain(|_, session| {
            match &session.state {
                SessionState::RevokedAt(cid) if cid < trim_cid => {
                    // This value is past the replication trim window and can now safely
                    // be removed
                    false
                }
                // Retain all else
                _ => true,
            }
        })
    }

    fn contains(&self, pv: &PartialValue) -> bool {
        match pv {
            PartialValue::Refer(u) => {
                self.map.contains_key(u) || {
                    let u_int = u.as_u128();
                    if self.rs_filter & u_int == u_int {
                        self.map.values().any(|session| {
                            session.rs_uuid == *u
                                && !matches!(session.state, SessionState::RevokedAt(_))
                        })
                    } else {
                        false
                    }
                }
            }
            _ => false,
        }
    }

    fn substring(&self, _pv: &PartialValue) -> bool {
        false
    }

    fn startswith(&self, _pv: &PartialValue) -> bool {
        false
    }

    fn endswith(&self, _pv: &PartialValue) -> bool {
        false
    }

    fn lessthan(&self, _pv: &PartialValue) -> bool {
        false
    }

    fn len(&self) -> usize {
        self.map.len()
    }

    fn generate_idx_eq_keys(&self) -> Vec<String> {
        // Allocate twice as much for worst-case when every session is
        // a unique rs-uuid to prevent re-allocs.
        let mut idx_keys = Vec::with_capacity(self.map.len() * 2);
        for (k, v) in self.map.iter() {
            idx_keys.push(k.as_hyphenated().to_string());
            idx_keys.push(v.rs_uuid.as_hyphenated().to_string());
        }
        idx_keys.sort_unstable();
        idx_keys.dedup();
        idx_keys
    }

    fn syntax(&self) -> SyntaxType {
        SyntaxType::Oauth2Session
    }

    fn validate(&self, _schema_attr: &SchemaAttribute) -> bool {
        true
    }

    fn to_proto_string_clone_iter(&self) -> Box<dyn Iterator<Item = String> + '_> {
        Box::new(
            self.map
                .iter()
                .map(|(u, m)| format!("{}: {:?}", uuid_to_proto_string(*u), m)),
        )
    }

    fn to_scim_value(&self) -> Option<ScimResolveStatus> {
        Some(ScimResolveStatus::Resolved(ScimValueKanidm::from(
            self.map
                .iter()
                .map(|(session_id, session)| {
                    let (expires, revoked) = match &session.state {
                        SessionState::ExpiresAt(odt) => (Some(*odt), None),
                        SessionState::NeverExpires => (None, None),
                        SessionState::RevokedAt(cid) => {
                            let odt: OffsetDateTime = cid.into();
                            (None, Some(odt))
                        }
                    };

                    ScimOAuth2Session {
                        id: *session_id,
                        parent_id: session.parent,
                        client_id: session.rs_uuid,
                        issued_at: session.issued_at,
                        expires,
                        revoked,
                    }
                })
                .collect::<Vec<_>>(),
        )))
    }

    fn to_db_valueset_v2(&self) -> DbValueSetV2 {
        DbValueSetV2::Oauth2Session(
            self.map
                .iter()
                .map(|(u, m)| DbValueOauth2Session::V3 {
                    refer: *u,
                    parent: m.parent,
                    state: match &m.state {
                        SessionState::ExpiresAt(odt) => {
                            debug_assert_eq!(odt.offset(), time::UtcOffset::UTC);
                            #[allow(clippy::expect_used)]
                            odt.format(&Rfc3339)
                                .map(DbValueSessionStateV1::ExpiresAt)
                                .expect("Failed to format timestamp into RFC3339!")
                        }
                        SessionState::NeverExpires => DbValueSessionStateV1::Never,
                        SessionState::RevokedAt(c) => DbValueSessionStateV1::RevokedAt(DbCidV1 {
                            server_id: c.s_uuid,
                            timestamp: c.ts,
                        }),
                    },
                    issued_at: {
                        debug_assert_eq!(m.issued_at.offset(), time::UtcOffset::UTC);
                        #[allow(clippy::expect_used)]
                        m.issued_at
                            .format(&Rfc3339)
                            .expect("Failed to format timestamp as RFC3339")
                    },
                    rs_uuid: m.rs_uuid,
                })
                .collect(),
        )
    }

    fn to_partialvalue_iter(&self) -> Box<dyn Iterator<Item = PartialValue> + '_> {
        Box::new(self.map.keys().cloned().map(PartialValue::Refer))
    }

    fn to_value_iter(&self) -> Box<dyn Iterator<Item = Value> + '_> {
        Box::new(
            self.map
                .iter()
                .map(|(u, m)| Value::OAuth2Session(*u, m.clone())),
        )
    }

    fn equal(&self, other: &ValueSet) -> bool {
        if let Some(other) = other.as_oauth2session_map() {
            &self.map == other
        } else {
            debug_assert!(false);
            false
        }
    }

    fn merge(&mut self, other: &ValueSet) -> Result<(), OperationError> {
        if let Some(b) = other.as_oauth2session_map() {
            // We can't just do merge maps here, we have to be aware of the
            // session.state value and what it currently is set to. We also
            // need to make sure the rs_filter is updated too!
            for (k_other, v_other) in b.iter() {
                if let Some(v_self) = self.map.get_mut(k_other) {
                    // We only update if lower. This is where RevokedAt
                    // always proceeds other states, and lower revoked
                    // cids will always take effect.
                    if v_other.state > v_self.state {
                        *v_self = v_other.clone();
                    }
                } else {
                    // Update the rs_filter!
                    self.rs_filter |= v_other.rs_uuid.as_u128();
                    // Not present, just insert.
                    self.map.insert(*k_other, v_other.clone());
                }
            }
            Ok(())
        } else {
            debug_assert!(false);
            Err(OperationError::InvalidValueState)
        }
    }

    fn as_oauth2session_map(&self) -> Option<&BTreeMap<Uuid, OAuth2Session>> {
        Some(&self.map)
    }

    fn as_ref_uuid_iter(&self) -> Option<Box<dyn Iterator<Item = Uuid> + '_>> {
        // This is what ties us as a type that can be refint checked. We need to
        // bind to our resource servers, not our ids!
        Some(Box::new(self.map.values().map(|m| &m.rs_uuid).copied()))
    }

    fn repl_merge_valueset(&self, older: &ValueSet, trim_cid: &Cid) -> Option<ValueSet> {
        if let Some(b) = older.as_oauth2session_map() {
            // We can't just do merge maps here, we have to be aware of the
            // session.state value and what it currently is set to.
            let mut map = self.map.clone();
            let mut rs_filter = self.rs_filter;
            for (k_other, v_other) in b.iter() {
                if let Some(v_self) = map.get_mut(k_other) {
                    // We only update if greater. This is where RevokedAt
                    // always proceeds other states, and lower revoked
                    // cids will always take effect.
                    if v_other.state > v_self.state {
                        *v_self = v_other.clone();
                    }
                } else {
                    // Not present, just insert.
                    rs_filter |= v_other.rs_uuid.as_u128();
                    map.insert(*k_other, v_other.clone());
                }
            }

            let mut vs = Box::new(ValueSetOauth2Session { map, rs_filter });

            vs.trim(trim_cid);

            Some(vs)
        } else {
            // The older value has a different type - return nothing, we
            // just take the newer value.
            None
        }
    }
}

#[derive(Debug, Clone)]
pub struct ValueSetApiTokenSet {
    map: BTreeMap<Uuid, ApiToken>,
}

impl ValueSetApiTokenSet {
    pub fn new(u: Uuid, m: ApiToken) -> Box<Self> {
        let mut map = BTreeMap::new();
        map.insert(u, m);
        Box::new(Self { map })
    }

    pub fn push(&mut self, u: Uuid, m: ApiToken) -> bool {
        self.map.insert(u, m).is_none()
    }

    pub fn from_dbvs2(data: Vec<DbValueApiToken>) -> Result<ValueSet, OperationError> {
        let map = data
            .into_iter()
            .filter_map(|dbv| {
                match dbv {
                    DbValueApiToken::V1 {
                        refer,
                        label,
                        expiry,
                        issued_at,
                        issued_by,
                        scope,
                    } => {
                        // Convert things.
                        let issued_at = OffsetDateTime::parse(&issued_at, &Rfc3339)
                            .map(|odt| odt.to_offset(time::UtcOffset::UTC))
                            .map_err(|e| {
                                admin_error!(
                                    ?e,
                                    "Invalidating api token {} due to invalid issued_at timestamp",
                                    refer
                                )
                            })
                            .ok()?;

                        // This is a bit annoying. In the case we can't parse the optional
                        // expiry, we need to NOT return the session so that it's immediately
                        // invalidated. To do this we have to invert some of the options involved
                        // here.
                        let expiry = expiry
                            .map(|e_inner| {
                                OffsetDateTime::parse(&e_inner, &Rfc3339)
                                    .map(|odt| odt.to_offset(time::UtcOffset::UTC))
                                // We now have an
                                // Option<Result<ODT, _>>
                            })
                            .transpose()
                            // Result<Option<ODT>, _>
                            .map_err(|e| {
                                admin_error!(
                                    ?e,
                                    "Invalidating api token {} due to invalid expiry timestamp",
                                    refer
                                )
                            })
                            // Option<Option<ODT>>
                            .ok()?;

                        let issued_by = match issued_by {
                            DbValueIdentityId::V1Internal => IdentityId::Internal(UUID_SYSTEM),
                            DbValueIdentityId::V2Internal(u) => IdentityId::Internal(u),
                            DbValueIdentityId::V1Uuid(u) => IdentityId::User(u),
                            DbValueIdentityId::V1Sync(u) => IdentityId::Synch(u),
                        };

                        let scope = match scope {
                            DbValueApiTokenScopeV1::ReadOnly => ApiTokenScope::ReadOnly,
                            DbValueApiTokenScopeV1::ReadWrite => ApiTokenScope::ReadWrite,
                            DbValueApiTokenScopeV1::Synchronise => ApiTokenScope::Synchronise,
                        };

                        Some((
                            refer,
                            ApiToken {
                                label,
                                expiry,
                                issued_at,
                                issued_by,
                                scope,
                            },
                        ))
                    }
                }
            })
            .collect();
        Ok(Box::new(Self { map }))
    }

    // We need to allow this, because rust doesn't allow us to impl FromIterator on foreign
    // types, and tuples are always foreign.
    #[allow(clippy::should_implement_trait)]
    pub fn from_iter<T>(iter: T) -> Option<Box<Self>>
    where
        T: IntoIterator<Item = (Uuid, ApiToken)>,
    {
        let map = iter.into_iter().collect();
        Some(Box::new(Self { map }))
    }
}

impl ValueSetT for ValueSetApiTokenSet {
    fn insert_checked(&mut self, value: Value) -> Result<bool, OperationError> {
        match value {
            Value::ApiToken(u, m) => {
                if let BTreeEntry::Vacant(e) = self.map.entry(u) {
                    e.insert(m);
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            _ => Err(OperationError::InvalidValueState),
        }
    }

    fn clear(&mut self) {
        self.map.clear();
    }

    fn remove(&mut self, pv: &PartialValue, _cid: &Cid) -> bool {
        if let PartialValue::Refer(u) = pv {
            self.map.remove(u);
        };
        self.map.is_empty()
    }

    fn purge(&mut self, _cid: &Cid) -> bool {
        // Could consider making this a TS capable entry.
        true
    }

    fn contains(&self, pv: &PartialValue) -> bool {
        match pv {
            PartialValue::Refer(u) => self.map.contains_key(u),
            _ => false,
        }
    }

    fn substring(&self, _pv: &PartialValue) -> bool {
        false
    }

    fn startswith(&self, _pv: &PartialValue) -> bool {
        false
    }

    fn endswith(&self, _pv: &PartialValue) -> bool {
        false
    }

    fn lessthan(&self, _pv: &PartialValue) -> bool {
        false
    }

    fn len(&self) -> usize {
        self.map.len()
    }

    fn generate_idx_eq_keys(&self) -> Vec<String> {
        self.map
            .keys()
            .map(|u| u.as_hyphenated().to_string())
            .collect()
    }

    fn syntax(&self) -> SyntaxType {
        SyntaxType::ApiToken
    }

    fn validate(&self, _schema_attr: &SchemaAttribute) -> bool {
        self.map.iter().all(|(_, at)| {
            Value::validate_str_escapes(&at.label) && Value::validate_singleline(&at.label)
        })
    }

    fn to_proto_string_clone_iter(&self) -> Box<dyn Iterator<Item = String> + '_> {
        Box::new(
            self.map
                .iter()
                .map(|(u, m)| format!("{}: {:?}", uuid_to_proto_string(*u), m)),
        )
    }

    fn to_scim_value(&self) -> Option<ScimResolveStatus> {
        Some(ScimResolveStatus::Resolved(ScimValueKanidm::from(
            self.map
                .iter()
                .map(|(token_id, token)| ScimApiToken {
                    id: *token_id,
                    label: token.label.clone(),
                    issued_by: Uuid::from(&token.issued_by),
                    issued_at: token.issued_at,
                    expires: token.expiry,
                    scope: token.scope.to_string(),
                })
                .collect::<Vec<_>>(),
        )))
    }

    fn to_db_valueset_v2(&self) -> DbValueSetV2 {
        DbValueSetV2::ApiTokenSet(
            self.map
                .iter()
                .map(|(u, m)| DbValueApiToken::V1 {
                    refer: *u,
                    label: m.label.clone(),
                    expiry: m.expiry.map(|odt| {
                        debug_assert_eq!(odt.offset(), time::UtcOffset::UTC);
                        #[allow(clippy::expect_used)]
                        odt.format(&Rfc3339)
                            .expect("Failed to format timestamp into RFC3339")
                    }),
                    issued_at: {
                        debug_assert_eq!(m.issued_at.offset(), time::UtcOffset::UTC);
                        #[allow(clippy::expect_used)]
                        m.issued_at
                            .format(&Rfc3339)
                            .expect("Failed to format timestamp into RFC3339")
                    },
                    issued_by: match m.issued_by {
                        IdentityId::Internal(u) => DbValueIdentityId::V2Internal(u),
                        IdentityId::User(u) => DbValueIdentityId::V1Uuid(u),
                        IdentityId::Synch(u) => DbValueIdentityId::V1Sync(u),
                    },
                    scope: match m.scope {
                        ApiTokenScope::ReadOnly => DbValueApiTokenScopeV1::ReadOnly,
                        ApiTokenScope::ReadWrite => DbValueApiTokenScopeV1::ReadWrite,
                        ApiTokenScope::Synchronise => DbValueApiTokenScopeV1::Synchronise,
                    },
                })
                .collect(),
        )
    }

    fn to_partialvalue_iter(&self) -> Box<dyn Iterator<Item = PartialValue> + '_> {
        Box::new(self.map.keys().cloned().map(PartialValue::Refer))
    }

    fn to_value_iter(&self) -> Box<dyn Iterator<Item = Value> + '_> {
        Box::new(self.map.iter().map(|(u, m)| Value::ApiToken(*u, m.clone())))
    }

    fn equal(&self, other: &ValueSet) -> bool {
        if let Some(other) = other.as_apitoken_map() {
            &self.map == other
        } else {
            debug_assert!(false);
            false
        }
    }

    fn merge(&mut self, other: &ValueSet) -> Result<(), OperationError> {
        if let Some(b) = other.as_apitoken_map() {
            mergemaps!(self.map, b)
        } else {
            debug_assert!(false);
            Err(OperationError::InvalidValueState)
        }
    }

    fn as_apitoken_map(&self) -> Option<&BTreeMap<Uuid, ApiToken>> {
        Some(&self.map)
    }

    fn as_ref_uuid_iter(&self) -> Option<Box<dyn Iterator<Item = Uuid> + '_>> {
        // This is what ties us as a type that can be refint checked.
        Some(Box::new(self.map.keys().copied()))
    }
}

#[cfg(test)]
mod tests {
    use super::{ValueSetOauth2Session, ValueSetSession, SESSION_MAXIMUM};
    use crate::{
        prelude::{IdentityId, SessionScope, Uuid, ValueSet, UUID_SYSTEM},
        repl::cid::Cid,
        value::{AuthType, OAuth2Session, Session, SessionState},
    };
    use time::OffsetDateTime;

    #[test]
    fn test_valueset_session_purge() {
        let s_uuid = Uuid::new_v4();
        #[deny(clippy::disallowed_methods)]
        let mut vs: ValueSet = ValueSetSession::new(
            s_uuid,
            Session {
                label: "hacks".to_string(),
                state: SessionState::NeverExpires,
                #[allow(clippy::disallowed_methods)]
                issued_at: OffsetDateTime::now_utc(),
                issued_by: IdentityId::Internal(UUID_SYSTEM),
                cred_id: Uuid::new_v4(),
                scope: SessionScope::ReadOnly,
                type_: AuthType::Passkey,
                ext_metadata: Default::default(),
            },
        );

        let zero_cid = Cid::new_zero();

        // Simulate session revocation.
        let r = vs.purge(&zero_cid);

        assert!(!r);
        assert_eq!(vs.len(), 1);

        let session = vs
            .as_session_map()
            .and_then(|map| map.get(&s_uuid))
            .expect("Unable to locate session");

        assert_eq!(session.state, SessionState::RevokedAt(zero_cid));
    }

    #[test]
    fn test_valueset_session_merge_left() {
        let s_uuid = Uuid::new_v4();
        let zero_cid = Cid::new_zero();

        let mut vs_a: ValueSet = ValueSetSession::new(
            s_uuid,
            Session {
                label: "hacks".to_string(),
                state: SessionState::NeverExpires,
                #[allow(clippy::disallowed_methods)]
                issued_at: OffsetDateTime::now_utc(),
                issued_by: IdentityId::Internal(UUID_SYSTEM),
                cred_id: Uuid::new_v4(),
                scope: SessionScope::ReadOnly,
                type_: AuthType::Passkey,
                ext_metadata: Default::default(),
            },
        );

        let vs_b: ValueSet = ValueSetSession::new(
            s_uuid,
            Session {
                label: "hacks".to_string(),
                state: SessionState::RevokedAt(zero_cid.clone()),
                #[allow(clippy::disallowed_methods)]
                issued_at: OffsetDateTime::now_utc(),
                issued_by: IdentityId::Internal(UUID_SYSTEM),
                cred_id: Uuid::new_v4(),
                scope: SessionScope::ReadOnly,
                type_: AuthType::Passkey,
                ext_metadata: Default::default(),
            },
        );

        vs_a.merge(&vs_b).expect("failed to merge");

        let session = vs_a
            .as_session_map()
            .and_then(|map| map.get(&s_uuid))
            .expect("Unable to locate session");

        assert_eq!(session.state, SessionState::RevokedAt(zero_cid));
    }

    #[test]
    fn test_valueset_session_merge_right() {
        let s_uuid = Uuid::new_v4();
        let zero_cid = Cid::new_zero();

        let vs_a: ValueSet = ValueSetSession::new(
            s_uuid,
            Session {
                label: "hacks".to_string(),
                state: SessionState::NeverExpires,
                #[allow(clippy::disallowed_methods)]
                issued_at: OffsetDateTime::now_utc(),
                issued_by: IdentityId::Internal(UUID_SYSTEM),
                cred_id: Uuid::new_v4(),
                scope: SessionScope::ReadOnly,
                type_: AuthType::Passkey,
                ext_metadata: Default::default(),
            },
        );

        let mut vs_b: ValueSet = ValueSetSession::new(
            s_uuid,
            Session {
                label: "hacks".to_string(),
                state: SessionState::RevokedAt(zero_cid.clone()),
                #[allow(clippy::disallowed_methods)]
                issued_at: OffsetDateTime::now_utc(),
                issued_by: IdentityId::Internal(UUID_SYSTEM),
                cred_id: Uuid::new_v4(),
                scope: SessionScope::ReadOnly,
                type_: AuthType::Passkey,
                ext_metadata: Default::default(),
            },
        );

        // Note - inverse order!
        vs_b.merge(&vs_a).expect("failed to merge");

        let session = vs_b
            .as_session_map()
            .and_then(|map| map.get(&s_uuid))
            .expect("Unable to locate session");

        assert_eq!(session.state, SessionState::RevokedAt(zero_cid));
    }

    #[test]
    fn test_valueset_session_repl_merge_left() {
        let s_uuid = Uuid::new_v4();
        let r_uuid = Uuid::new_v4();
        let zero_cid = Cid::new_zero();
        let one_cid = Cid::new_count(1);

        let vs_a: ValueSet = ValueSetSession::new(
            s_uuid,
            Session {
                label: "hacks".to_string(),
                state: SessionState::NeverExpires,
                #[allow(clippy::disallowed_methods)]
                issued_at: OffsetDateTime::now_utc(),
                issued_by: IdentityId::Internal(UUID_SYSTEM),
                cred_id: Uuid::new_v4(),
                scope: SessionScope::ReadOnly,
                type_: AuthType::Passkey,
                ext_metadata: Default::default(),
            },
        );

        let vs_b: ValueSet = ValueSetSession::from_iter([
            (
                s_uuid,
                Session {
                    label: "hacks".to_string(),
                    state: SessionState::RevokedAt(one_cid.clone()),
                    #[allow(clippy::disallowed_methods)]
                    issued_at: OffsetDateTime::now_utc(),
                    issued_by: IdentityId::Internal(UUID_SYSTEM),
                    cred_id: Uuid::new_v4(),
                    scope: SessionScope::ReadOnly,
                    type_: AuthType::Passkey,
                    ext_metadata: Default::default(),
                },
            ),
            (
                r_uuid,
                Session {
                    label: "hacks".to_string(),
                    state: SessionState::RevokedAt(zero_cid.clone()),
                    #[allow(clippy::disallowed_methods)]
                    issued_at: OffsetDateTime::now_utc(),
                    issued_by: IdentityId::Internal(UUID_SYSTEM),
                    cred_id: Uuid::new_v4(),
                    scope: SessionScope::ReadOnly,
                    type_: AuthType::Passkey,
                    ext_metadata: Default::default(),
                },
            ),
        ])
        .expect("Unable to build valueset session");

        let r_vs = vs_a
            .repl_merge_valueset(&vs_b, &one_cid)
            .expect("failed to merge");

        let sessions = r_vs.as_session_map().expect("Unable to locate sessions");

        let session = sessions.get(&s_uuid).expect("Unable to locate session");

        assert_eq!(session.state, SessionState::RevokedAt(one_cid));

        assert!(!sessions.contains_key(&r_uuid));
    }

    #[test]
    fn test_valueset_session_repl_merge_right() {
        let s_uuid = Uuid::new_v4();
        let r_uuid = Uuid::new_v4();
        let zero_cid = Cid::new_zero();
        let one_cid = Cid::new_count(1);

        let vs_a: ValueSet = ValueSetSession::new(
            s_uuid,
            Session {
                label: "hacks".to_string(),
                state: SessionState::NeverExpires,
                #[allow(clippy::disallowed_methods)]
                issued_at: OffsetDateTime::now_utc(),
                issued_by: IdentityId::Internal(UUID_SYSTEM),
                cred_id: Uuid::new_v4(),
                scope: SessionScope::ReadOnly,
                type_: AuthType::Passkey,
                ext_metadata: Default::default(),
            },
        );

        let vs_b: ValueSet = ValueSetSession::from_iter([
            (
                s_uuid,
                Session {
                    label: "hacks".to_string(),
                    state: SessionState::RevokedAt(one_cid.clone()),
                    #[allow(clippy::disallowed_methods)]
                    issued_at: OffsetDateTime::now_utc(),
                    issued_by: IdentityId::Internal(UUID_SYSTEM),
                    cred_id: Uuid::new_v4(),
                    scope: SessionScope::ReadOnly,
                    type_: AuthType::Passkey,
                    ext_metadata: Default::default(),
                },
            ),
            (
                r_uuid,
                Session {
                    label: "hacks".to_string(),
                    state: SessionState::RevokedAt(zero_cid.clone()),
                    #[allow(clippy::disallowed_methods)]
                    issued_at: OffsetDateTime::now_utc(),
                    issued_by: IdentityId::Internal(UUID_SYSTEM),
                    cred_id: Uuid::new_v4(),
                    scope: SessionScope::ReadOnly,
                    type_: AuthType::Passkey,
                    ext_metadata: Default::default(),
                },
            ),
        ])
        .expect("Unable to build valueset session");

        // Note - inverse order!
        let r_vs = vs_b
            .repl_merge_valueset(&vs_a, &one_cid)
            .expect("failed to merge");

        let sessions = r_vs.as_session_map().expect("Unable to locate sessions");

        let session = sessions.get(&s_uuid).expect("Unable to locate session");

        assert_eq!(session.state, SessionState::RevokedAt(one_cid));

        assert!(!sessions.contains_key(&r_uuid));
    }

    #[test]
    fn test_valueset_session_repl_trim() {
        let zero_uuid = Uuid::new_v4();
        let zero_cid = Cid::new_zero();
        let one_uuid = Uuid::new_v4();
        let one_cid = Cid::new_count(1);
        let two_uuid = Uuid::new_v4();
        let two_cid = Cid::new_count(2);

        let mut vs_a: ValueSet = ValueSetSession::from_iter([
            (
                zero_uuid,
                Session {
                    state: SessionState::RevokedAt(zero_cid),
                    label: "hacks".to_string(),
                    #[allow(clippy::disallowed_methods)]
                    issued_at: OffsetDateTime::now_utc(),
                    issued_by: IdentityId::Internal(UUID_SYSTEM),
                    cred_id: Uuid::new_v4(),
                    scope: SessionScope::ReadOnly,
                    type_: AuthType::Passkey,
                    ext_metadata: Default::default(),
                },
            ),
            (
                one_uuid,
                Session {
                    state: SessionState::RevokedAt(one_cid),
                    label: "hacks".to_string(),
                    #[allow(clippy::disallowed_methods)]
                    issued_at: OffsetDateTime::now_utc(),
                    issued_by: IdentityId::Internal(UUID_SYSTEM),
                    cred_id: Uuid::new_v4(),
                    scope: SessionScope::ReadOnly,
                    type_: AuthType::Passkey,
                    ext_metadata: Default::default(),
                },
            ),
            (
                two_uuid,
                Session {
                    state: SessionState::RevokedAt(two_cid.clone()),
                    label: "hacks".to_string(),
                    #[allow(clippy::disallowed_methods)]
                    issued_at: OffsetDateTime::now_utc(),
                    issued_by: IdentityId::Internal(UUID_SYSTEM),
                    cred_id: Uuid::new_v4(),
                    scope: SessionScope::ReadOnly,
                    type_: AuthType::Passkey,
                    ext_metadata: Default::default(),
                },
            ),
        ])
        .unwrap();

        vs_a.trim(&two_cid);

        let sessions = vs_a.as_session_map().expect("Unable to locate session");

        assert!(!sessions.contains_key(&zero_uuid));
        assert!(!sessions.contains_key(&one_uuid));
        assert!(sessions.contains_key(&two_uuid));
    }

    #[test]
    fn test_valueset_session_limit_trim() {
        // Create a session that will be trimmed.
        let zero_uuid = Uuid::new_v4();
        let zero_cid = Cid::new_zero();
        let issued_at = OffsetDateTime::UNIX_EPOCH;

        let session_iter = std::iter::once((
            zero_uuid,
            Session {
                state: SessionState::NeverExpires,
                label: "hacks".to_string(),
                issued_at,
                issued_by: IdentityId::Internal(UUID_SYSTEM),
                cred_id: Uuid::new_v4(),
                scope: SessionScope::ReadOnly,
                type_: AuthType::Passkey,
                ext_metadata: Default::default(),
            },
        ))
        .chain((0..SESSION_MAXIMUM).map(|_| {
            (
                Uuid::new_v4(),
                Session {
                    state: SessionState::NeverExpires,
                    label: "hacks".to_string(),
                    #[allow(clippy::disallowed_methods)]
                    issued_at: OffsetDateTime::now_utc(),
                    issued_by: IdentityId::Internal(UUID_SYSTEM),
                    cred_id: Uuid::new_v4(),
                    scope: SessionScope::ReadOnly,
                    type_: AuthType::Passkey,
                    ext_metadata: Default::default(),
                },
            )
        }));

        let mut vs_a: ValueSet = ValueSetSession::from_iter(session_iter).unwrap();

        assert!(vs_a.len() > SESSION_MAXIMUM);

        vs_a.trim(&zero_cid);

        assert_eq!(vs_a.len(), SESSION_MAXIMUM);

        let sessions = vs_a.as_session_map().expect("Unable to access sessions");

        assert!(!sessions.contains_key(&zero_uuid));
    }

    #[test]
    fn test_valueset_oauth2_session_purge() {
        let s_uuid = Uuid::new_v4();
        let mut vs: ValueSet = ValueSetOauth2Session::new(
            s_uuid,
            OAuth2Session {
                state: SessionState::NeverExpires,
                #[allow(clippy::disallowed_methods)]
                issued_at: OffsetDateTime::now_utc(),
                parent: Some(Uuid::new_v4()),
                rs_uuid: Uuid::new_v4(),
            },
        );

        let zero_cid = Cid::new_zero();

        // Simulate session revocation.
        let r = vs.purge(&zero_cid);

        assert!(!r);
        assert_eq!(vs.len(), 1);

        let session = vs
            .as_oauth2session_map()
            .and_then(|map| map.get(&s_uuid))
            .expect("Unable to locate session");

        assert_eq!(session.state, SessionState::RevokedAt(zero_cid));
    }

    #[test]
    fn test_valueset_oauth2_session_merge_left() {
        let s_uuid = Uuid::new_v4();
        let zero_cid = Cid::new_zero();

        let mut vs_a: ValueSet = ValueSetOauth2Session::new(
            s_uuid,
            OAuth2Session {
                state: SessionState::NeverExpires,
                #[allow(clippy::disallowed_methods)]
                issued_at: OffsetDateTime::now_utc(),
                parent: Some(Uuid::new_v4()),
                rs_uuid: Uuid::new_v4(),
            },
        );

        let vs_b: ValueSet = ValueSetOauth2Session::new(
            s_uuid,
            OAuth2Session {
                state: SessionState::RevokedAt(zero_cid.clone()),
                #[allow(clippy::disallowed_methods)]
                issued_at: OffsetDateTime::now_utc(),
                parent: Some(Uuid::new_v4()),
                rs_uuid: Uuid::new_v4(),
            },
        );

        vs_a.merge(&vs_b).expect("failed to merge");

        let session = vs_a
            .as_oauth2session_map()
            .and_then(|map| map.get(&s_uuid))
            .expect("Unable to locate session");

        assert_eq!(session.state, SessionState::RevokedAt(zero_cid));
    }

    #[test]
    fn test_valueset_oauth2_session_merge_right() {
        let s_uuid = Uuid::new_v4();
        let zero_cid = Cid::new_zero();

        let vs_a: ValueSet = ValueSetOauth2Session::new(
            s_uuid,
            OAuth2Session {
                state: SessionState::NeverExpires,
                #[allow(clippy::disallowed_methods)]
                issued_at: OffsetDateTime::now_utc(),
                parent: Some(Uuid::new_v4()),
                rs_uuid: Uuid::new_v4(),
            },
        );

        let mut vs_b: ValueSet = ValueSetOauth2Session::new(
            s_uuid,
            OAuth2Session {
                state: SessionState::RevokedAt(zero_cid.clone()),
                #[allow(clippy::disallowed_methods)]
                issued_at: OffsetDateTime::now_utc(),
                parent: Some(Uuid::new_v4()),
                rs_uuid: Uuid::new_v4(),
            },
        );

        // Note inverse order
        vs_b.merge(&vs_a).expect("failed to merge");

        let session = vs_b
            .as_oauth2session_map()
            .and_then(|map| map.get(&s_uuid))
            .expect("Unable to locate session");

        assert_eq!(session.state, SessionState::RevokedAt(zero_cid));
    }

    #[test]
    fn test_valueset_oauth2_session_repl_merge_left() {
        let s_uuid = Uuid::new_v4();
        let r_uuid = Uuid::new_v4();
        let zero_cid = Cid::new_zero();
        let one_cid = Cid::new_count(1);

        let vs_a: ValueSet = ValueSetOauth2Session::new(
            s_uuid,
            OAuth2Session {
                state: SessionState::NeverExpires,
                #[allow(clippy::disallowed_methods)]
                issued_at: OffsetDateTime::now_utc(),
                parent: Some(Uuid::new_v4()),
                rs_uuid: Uuid::new_v4(),
            },
        );

        let vs_b: ValueSet = ValueSetOauth2Session::from_iter([
            (
                s_uuid,
                OAuth2Session {
                    state: SessionState::RevokedAt(one_cid.clone()),
                    #[allow(clippy::disallowed_methods)]
                    issued_at: OffsetDateTime::now_utc(),
                    parent: Some(Uuid::new_v4()),
                    rs_uuid: Uuid::new_v4(),
                },
            ),
            (
                r_uuid,
                OAuth2Session {
                    state: SessionState::RevokedAt(zero_cid.clone()),
                    #[allow(clippy::disallowed_methods)]
                    issued_at: OffsetDateTime::now_utc(),
                    parent: Some(Uuid::new_v4()),
                    rs_uuid: Uuid::new_v4(),
                },
            ),
        ])
        .expect("Unable to build valueset oauth2 session");

        let r_vs = vs_a
            .repl_merge_valueset(&vs_b, &one_cid)
            .expect("failed to merge");

        let sessions = r_vs
            .as_oauth2session_map()
            .expect("Unable to locate sessions");

        let session = sessions.get(&s_uuid).expect("Unable to locate session");

        assert_eq!(session.state, SessionState::RevokedAt(one_cid));

        assert!(!sessions.contains_key(&r_uuid));
    }

    #[test]
    fn test_valueset_oauth2_session_repl_merge_right() {
        let s_uuid = Uuid::new_v4();
        let r_uuid = Uuid::new_v4();
        let zero_cid = Cid::new_zero();
        let one_cid = Cid::new_count(1);

        let vs_a: ValueSet = ValueSetOauth2Session::new(
            s_uuid,
            OAuth2Session {
                state: SessionState::NeverExpires,
                #[allow(clippy::disallowed_methods)]
                issued_at: OffsetDateTime::now_utc(),
                parent: Some(Uuid::new_v4()),
                rs_uuid: Uuid::new_v4(),
            },
        );

        let vs_b: ValueSet = ValueSetOauth2Session::from_iter([
            (
                s_uuid,
                OAuth2Session {
                    state: SessionState::RevokedAt(one_cid.clone()),
                    #[allow(clippy::disallowed_methods)]
                    issued_at: OffsetDateTime::now_utc(),
                    parent: Some(Uuid::new_v4()),
                    rs_uuid: Uuid::new_v4(),
                },
            ),
            (
                r_uuid,
                OAuth2Session {
                    state: SessionState::RevokedAt(zero_cid.clone()),
                    #[allow(clippy::disallowed_methods)]
                    issued_at: OffsetDateTime::now_utc(),
                    parent: Some(Uuid::new_v4()),
                    rs_uuid: Uuid::new_v4(),
                },
            ),
        ])
        .expect("Unable to build valueset oauth2 session");

        // Note inverse order
        let r_vs = vs_b
            .repl_merge_valueset(&vs_a, &one_cid)
            .expect("failed to merge");

        let sessions = r_vs
            .as_oauth2session_map()
            .expect("Unable to locate sessions");

        let session = sessions.get(&s_uuid).expect("Unable to locate session");

        assert_eq!(session.state, SessionState::RevokedAt(one_cid));

        assert!(!sessions.contains_key(&r_uuid));
    }

    #[test]
    fn test_valueset_oauth2_session_repl_trim() {
        let zero_uuid = Uuid::new_v4();
        let zero_cid = Cid::new_zero();
        let one_uuid = Uuid::new_v4();
        let one_cid = Cid::new_count(1);
        let two_uuid = Uuid::new_v4();
        let two_cid = Cid::new_count(2);

        let mut vs_a: ValueSet = ValueSetOauth2Session::from_iter([
            (
                zero_uuid,
                OAuth2Session {
                    state: SessionState::RevokedAt(zero_cid),
                    #[allow(clippy::disallowed_methods)]
                    issued_at: OffsetDateTime::now_utc(),
                    parent: Some(Uuid::new_v4()),
                    rs_uuid: Uuid::new_v4(),
                },
            ),
            (
                one_uuid,
                #[allow(clippy::disallowed_methods)]
                OAuth2Session {
                    state: SessionState::RevokedAt(one_cid),
                    issued_at: OffsetDateTime::now_utc(),
                    parent: Some(Uuid::new_v4()),
                    rs_uuid: Uuid::new_v4(),
                },
            ),
            (
                two_uuid,
                OAuth2Session {
                    state: SessionState::RevokedAt(two_cid.clone()),
                    #[allow(clippy::disallowed_methods)]
                    issued_at: OffsetDateTime::now_utc(),
                    parent: Some(Uuid::new_v4()),
                    rs_uuid: Uuid::new_v4(),
                },
            ),
        ])
        .unwrap();

        vs_a.trim(&two_cid);

        let sessions = vs_a
            .as_oauth2session_map()
            .expect("Unable to locate session");

        assert!(!sessions.contains_key(&zero_uuid));
        assert!(!sessions.contains_key(&one_uuid));
        assert!(sessions.contains_key(&two_uuid));
    }

    #[test]
    fn test_scim_session() {
        let s_uuid = uuid::uuid!("3a163ca0-4762-4620-a188-06b750c84c86");

        let vs: ValueSet = ValueSetSession::new(
            s_uuid,
            Session {
                label: "hacks".to_string(),
                state: SessionState::NeverExpires,
                issued_at: OffsetDateTime::UNIX_EPOCH,
                issued_by: IdentityId::Internal(UUID_SYSTEM),
                cred_id: s_uuid,
                scope: SessionScope::ReadOnly,
                type_: AuthType::Passkey,
                ext_metadata: Default::default(),
            },
        );

        let data = r#"
[
  {
    "authType": "passkey",
    "credentialId": "3a163ca0-4762-4620-a188-06b750c84c86",
    "issuedAt": "1970-01-01T00:00:00Z",
    "issuedBy": "00000000-0000-0000-0000-ffffff000000",
    "id": "3a163ca0-4762-4620-a188-06b750c84c86",
    "sessionScope": "read_only"
  }
]
        "#;
        crate::valueset::scim_json_reflexive(&vs, data);
    }

    #[test]
    fn test_scim_oauth2_session() {
        let s_uuid = uuid::uuid!("3a163ca0-4762-4620-a188-06b750c84c86");

        let vs: ValueSet = ValueSetOauth2Session::new(
            s_uuid,
            OAuth2Session {
                state: SessionState::NeverExpires,
                issued_at: OffsetDateTime::UNIX_EPOCH,
                parent: Some(s_uuid),
                rs_uuid: s_uuid,
            },
        );

        let data = r#"
[
  {
    "clientId": "3a163ca0-4762-4620-a188-06b750c84c86",
    "issuedAt": "1970-01-01T00:00:00Z",
    "parentId": "3a163ca0-4762-4620-a188-06b750c84c86",
    "id": "3a163ca0-4762-4620-a188-06b750c84c86"
  }
]
        "#;

        crate::valueset::scim_json_reflexive(&vs, data);
    }
}
