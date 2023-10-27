//! LDAP specific operations handling components. This is where LDAP operations
//! are sent to for processing.

use std::collections::BTreeSet;
use std::iter;

use kanidm_proto::constants::*;
use kanidm_proto::v1::{ApiToken, OperationError, UserAuthToken};
use ldap3_proto::simple::*;
use regex::Regex;
use tracing::trace;
use uuid::Uuid;

use crate::event::SearchEvent;
use crate::idm::event::{LdapAuthEvent, LdapTokenAuthEvent};
use crate::idm::server::{IdmServer, IdmServerTransaction};
use crate::prelude::*;

// Clippy doesn't like Bind here. But proto needs unboxed ldapmsg,
// and ldapboundtoken is moved. Really, it's not too bad, every message here is pretty sucky.
#[allow(clippy::large_enum_variant)]
pub enum LdapResponseState {
    Unbind,
    Disconnect(LdapMsg),
    Bind(LdapBoundToken, LdapMsg),
    Respond(LdapMsg),
    MultiPartResponse(Vec<LdapMsg>),
    BindMultiPartResponse(LdapBoundToken, Vec<LdapMsg>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LdapSession {
    // Maps through and provides anon read, but allows us to check the validity
    // of the account still.
    UnixBind(Uuid),
    UserAuthToken(UserAuthToken),
    ApiToken(ApiToken),
}

#[derive(Debug, Clone)]
pub struct LdapBoundToken {
    // Used to help ID the user doing the action, makes logging nicer.
    pub spn: String,
    pub session_id: Uuid,
    // This is the effective session permission. This is generated from either:
    // * A valid anonymous bind
    // * A valid unix pw bind
    // * A valid ApiToken
    // In a way, this is a stepping stone to an "ident" but allows us to check
    // the session is still "valid" depending on it's origin.
    pub effective_session: LdapSession,
}

pub struct LdapServer {
    rootdse: LdapSearchResultEntry,
    basedn: String,
    dnre: Regex,
    binddnre: Regex,
}

impl LdapServer {
    pub async fn new(idms: &IdmServer) -> Result<Self, OperationError> {
        // let ct = duration_from_epoch_now();
        let mut idms_prox_read = idms.proxy_read().await;
        // This is the rootdse path.
        // get the domain_info item
        let domain_entry = idms_prox_read
            .qs_read
            .internal_search_uuid(UUID_DOMAIN_INFO)?;

        let basedn = domain_entry
            .get_ava_single_iutf8(Attribute::DomainLdapBasedn)
            .map(|s| s.to_string())
            .or_else(|| {
                domain_entry
                    .get_ava_single_iname(Attribute::DomainName)
                    .map(ldap_domain_to_dc)
            })
            .ok_or(OperationError::InvalidEntryState)?;

        let dnre = Regex::new(format!("^((?P<attr>[^=]+)=(?P<val>[^=]+),)?{basedn}$").as_str())
            .map_err(|_| OperationError::InvalidEntryState)?;

        let binddnre = Regex::new(format!("^(([^=,]+)=)?(?P<val>[^=,]+)(,{basedn})?$").as_str())
            .map_err(|_| OperationError::InvalidEntryState)?;

        let rootdse = LdapSearchResultEntry {
            dn: "".to_string(),
            attributes: vec![
                LdapPartialAttribute {
                    atype: ATTR_OBJECTCLASS.to_string(),
                    vals: vec!["top".as_bytes().to_vec()],
                },
                LdapPartialAttribute {
                    atype: "vendorname".to_string(),
                    vals: vec!["Kanidm Project".as_bytes().to_vec()],
                },
                LdapPartialAttribute {
                    atype: "vendorversion".to_string(),
                    vals: vec![env!("CARGO_PKG_VERSION").as_bytes().to_vec()],
                },
                LdapPartialAttribute {
                    atype: "supportedldapversion".to_string(),
                    vals: vec!["3".as_bytes().to_vec()],
                },
                LdapPartialAttribute {
                    atype: "supportedextension".to_string(),
                    vals: vec!["1.3.6.1.4.1.4203.1.11.3".as_bytes().to_vec()],
                },
                LdapPartialAttribute {
                    atype: "supportedfeatures".to_string(),
                    vals: vec!["1.3.6.1.4.1.4203.1.5.1".as_bytes().to_vec()],
                },
                LdapPartialAttribute {
                    atype: "defaultnamingcontext".to_string(),
                    vals: vec![basedn.as_bytes().to_vec()],
                },
            ],
        };

        Ok(LdapServer {
            rootdse,
            basedn,
            dnre,
            binddnre,
        })
    }

    #[instrument(level = "debug", skip_all)]
    async fn do_search(
        &self,
        idms: &IdmServer,
        sr: &SearchRequest,
        uat: &LdapBoundToken,
        // eventid: &Uuid,
    ) -> Result<Vec<LdapMsg>, OperationError> {
        admin_info!("Attempt LDAP Search for {}", uat.spn);
        // If the request is "", Base, Present(Attribute::ObjectClass.into()), [], then we want the rootdse.
        if sr.base.is_empty() && sr.scope == LdapSearchScope::Base {
            admin_info!("LDAP Search success - RootDSE");
            Ok(vec![
                sr.gen_result_entry(self.rootdse.clone()),
                sr.gen_success(),
            ])
        } else {
            // We want something else apparently. Need to do some more work ...
            // Parse the operation and make sure it's sane before we start the txn.

            // This scoping returns an extra filter component.

            let (opt_attr, opt_value) = match self.dnre.captures(sr.base.as_str()) {
                Some(caps) => (
                    caps.name("attr").map(|v| v.as_str().to_string()),
                    caps.name("val").map(|v| v.as_str().to_string()),
                ),
                None => {
                    request_error!("LDAP Search failure - invalid basedn");
                    return Err(OperationError::InvalidRequestState);
                }
            };

            let req_dn = match (opt_attr, opt_value) {
                (Some(a), Some(v)) => Some((a, v)),
                (None, None) => None,
                _ => {
                    request_error!("LDAP Search failure - invalid rdn");
                    return Err(OperationError::InvalidRequestState);
                }
            };

            trace!(rdn = ?req_dn);

            // Map the Some(a,v) to ...?

            let ext_filter = match (&sr.scope, req_dn) {
                // OneLevel and Child searches are veerrrryyy similar for us because child
                // is a "subtree search excluding base". Because we don't have a tree structure at
                // all, this is the same as a onelevel (ald children of base excludeing base).
                (LdapSearchScope::Children, Some(_r)) | (LdapSearchScope::OneLevel, Some(_r)) => {
                    return Ok(vec![sr.gen_success()])
                }
                (LdapSearchScope::Children, None) | (LdapSearchScope::OneLevel, None) => {
                    // exclude domain_info
                    Some(LdapFilter::Not(Box::new(LdapFilter::Equality(
                        Attribute::Uuid.to_string(),
                        STR_UUID_DOMAIN_INFO.to_string(),
                    ))))
                }
                // because we request a specific DN, these are the same since we want the same
                // entry.
                (LdapSearchScope::Base, Some((a, v)))
                | (LdapSearchScope::Subtree, Some((a, v))) => Some(LdapFilter::Equality(a, v)),
                (LdapSearchScope::Base, None) => {
                    // domain_info
                    Some(LdapFilter::Equality(
                        Attribute::Uuid.to_string(),
                        STR_UUID_DOMAIN_INFO.to_string(),
                    ))
                }
                (LdapSearchScope::Subtree, None) => {
                    // No filter changes needed.
                    None
                }
            };

            let mut all_attrs = false;
            let mut all_op_attrs = false;

            // TODO #67: limit the number of attributes here!
            if sr.attrs.is_empty() {
                // If [], then "all" attrs
                all_attrs = true;
            } else {
                sr.attrs.iter().for_each(|a| {
                    if a == "*" {
                        all_attrs = true;
                    } else if a == "+" {
                        // This forces the BE to get all the attrs so we can
                        // map all vattrs.
                        all_attrs = true;
                        all_op_attrs = true;
                    }
                })
            }

            // We need to retain this to know what the client requested.
            let (k_attrs, l_attrs) = if all_op_attrs {
                // We need all attrs, and we do a full v_attr map.
                (None, ldap_all_vattrs())
            } else if all_attrs {
                // We are already getting all attrs, but if there are any virtual attrs
                // we need them in our request as well.
                let req_attrs: Vec<String> = sr
                    .attrs
                    .iter()
                    .filter_map(|a| {
                        let a_lower = a.to_lowercase();

                        if ldap_vattr_map(&a_lower).is_some() {
                            Some(a_lower)
                        } else {
                            None
                        }
                    })
                    .collect();

                (None, req_attrs)
            } else {
                // What the client requested, in LDAP forms.
                let req_attrs: Vec<String> = sr
                    .attrs
                    .iter()
                    .filter_map(|a| {
                        if a == "*" || a == "+" {
                            None
                        } else {
                            Some(a.to_lowercase())
                        }
                    })
                    .collect();
                // This is what the client requested, but mapped to kanidm forms.
                // NOTE: All req_attrs are lowercase at this point.
                let mapped_attrs: BTreeSet<_> = req_attrs
                    .iter()
                    .filter_map(|a| {
                        // EntryDN and DN have special handling in to_ldap in Entry. We don't
                        // need these here, we know they will be returned as part of the transform.
                        if a == "entrydn" || a == "dn" {
                            None
                        } else {
                            Some(AttrString::from(ldap_vattr_map(a).unwrap_or(a)))
                        }
                    })
                    .collect();

                (Some(mapped_attrs), req_attrs)
            };

            admin_info!(attr = ?l_attrs, "LDAP Search Request LDAP Attrs");
            admin_info!(attr = ?k_attrs, "LDAP Search Request Mapped Attrs");

            let ct = duration_from_epoch_now();
            let mut idm_read = idms.proxy_read().await;
            // Now start the txn - we need it for resolving filter components.

            // join the filter, with ext_filter
            let lfilter = match ext_filter {
                Some(ext) => LdapFilter::And(vec![
                    sr.filter.clone(),
                    ext,
                    LdapFilter::Not(Box::new(LdapFilter::Or(vec![
                        LdapFilter::Equality(Attribute::Class.to_string(), "classtype".to_string()),
                        LdapFilter::Equality(
                            Attribute::Class.to_string(),
                            "attributetype".to_string(),
                        ),
                        LdapFilter::Equality(
                            Attribute::Class.to_string(),
                            "access_control_profile".to_string(),
                        ),
                    ]))),
                ]),
                None => LdapFilter::And(vec![
                    sr.filter.clone(),
                    LdapFilter::Not(Box::new(LdapFilter::Or(vec![
                        LdapFilter::Equality(Attribute::Class.to_string(), "classtype".to_string()),
                        LdapFilter::Equality(
                            Attribute::Class.to_string(),
                            "attributetype".to_string(),
                        ),
                        LdapFilter::Equality(
                            Attribute::Class.to_string(),
                            "access_control_profile".to_string(),
                        ),
                    ]))),
                ]),
            };

            admin_info!(filter = ?lfilter, "LDAP Search Filter");

            // Build the event, with the permissions from effective_session
            //
            // ! Remember, searchEvent wraps to ignore hidden for us.
            let ident = idm_read
                .validate_ldap_session(&uat.effective_session, ct)
                .map_err(|e| {
                    admin_error!("Invalid identity: {:?}", e);
                    e
                })?;
            let se = SearchEvent::new_ext_impersonate_uuid(
                &mut idm_read.qs_read,
                ident,
                &lfilter,
                k_attrs,
            )
            .map_err(|e| {
                admin_error!("failed to create search event -> {:?}", e);
                e
            })?;

            let res = idm_read.qs_read.search_ext(&se).map_err(|e| {
                admin_error!("search failure {:?}", e);
                e
            })?;

            // These have already been fully reduced (access controls applied),
            // so we can just transform the values and open palm slam them into
            // the result structure.
            let lres: Result<Vec<_>, _> = res
                .into_iter()
                .map(|e| {
                    e.to_ldap(
                        &mut idm_read.qs_read,
                        self.basedn.as_str(),
                        all_attrs,
                        &l_attrs,
                    )
                    // if okay, wrap in a ldap msg.
                    .map(|r| sr.gen_result_entry(r))
                })
                .chain(iter::once(Ok(sr.gen_success())))
                .collect();

            let lres = lres.map_err(|e| {
                admin_error!("entry resolve failure {:?}", e);
                e
            })?;

            admin_info!(
                nentries = %lres.len(),
                "LDAP Search Success -> number of entries"
            );

            Ok(lres)
        }
    }

    async fn do_bind(
        &self,
        idms: &IdmServer,
        dn: &str,
        pw: &str,
    ) -> Result<Option<LdapBoundToken>, OperationError> {
        security_info!(
            "Attempt LDAP Bind for {}",
            if dn.is_empty() { "anonymous" } else { dn }
        );
        let ct = duration_from_epoch_now();

        let mut idm_auth = idms.auth().await;

        let target_uuid: Uuid = if dn.is_empty() {
            if pw.is_empty() {
                security_info!("✅ LDAP Bind success anonymous");
                UUID_ANONYMOUS
            } else {
                // This is the path to access api-token logins.
                let lae = LdapTokenAuthEvent::from_parts(pw.to_string())?;
                return idm_auth.token_auth_ldap(&lae, ct).await.and_then(|r| {
                    idm_auth.commit().map(|_| {
                        if r.is_some() {
                            security_info!(%dn, "✅ LDAP Bind success");
                        } else {
                            security_info!(%dn, "❌ LDAP Bind failure");
                        };
                        r
                    })
                });
            }
        } else {
            // Is the passed dn requesting token auth?
            // We use dn= here since these are attr=value, and dn is a phantom so it will
            // never be present or match a real value. We also make it an ava so that clients
            // that over-zealously validate dn syntax are happy.
            if dn == "dn=token" {
                let lae = LdapTokenAuthEvent::from_parts(pw.to_string())?;
                return idm_auth.token_auth_ldap(&lae, ct).await.and_then(|r| {
                    idm_auth.commit().map(|_| {
                        if r.is_some() {
                            security_info!(%dn, "✅ LDAP Bind success");
                        } else {
                            security_info!(%dn, "❌ LDAP Bind failure");
                        };
                        r
                    })
                });
            };

            let rdn = self
                .binddnre
                .captures(dn)
                .and_then(|caps| caps.name("val"))
                .map(|v| v.as_str().to_string())
                .ok_or(OperationError::NoMatchingEntries)?;

            trace!(?rdn, "relative dn");

            if rdn.is_empty() {
                // That's weird ...
                return Err(OperationError::NoMatchingEntries);
            }

            idm_auth.qs_read.name_to_uuid(rdn.as_str()).map_err(|e| {
                request_error!(err = ?e, ?rdn, "Error resolving rdn to target");
                e
            })?
        };

        let lae = LdapAuthEvent::from_parts(target_uuid, pw.to_string())?;
        idm_auth.auth_ldap(&lae, ct).await.and_then(|r| {
            idm_auth.commit().map(|_| {
                if r.is_some() {
                    security_info!(%dn, "✅ LDAP Bind (password) success");
                } else {
                    security_info!(%dn, "❌ LDAP Bind failure");
                };
                r
            })
        })
    }

    pub async fn do_op(
        &self,
        idms: &IdmServer,
        server_op: ServerOps,
        uat: Option<LdapBoundToken>,
        eventid: Uuid,
    ) -> Result<LdapResponseState, OperationError> {
        match server_op {
            ServerOps::SimpleBind(sbr) => self
                .do_bind(idms, sbr.dn.as_str(), sbr.pw.as_str())
                .await
                .map(|r| match r {
                    Some(lbt) => LdapResponseState::Bind(lbt, sbr.gen_success()),
                    None => LdapResponseState::Respond(sbr.gen_invalid_cred()),
                })
                .or_else(|e| {
                    let (rc, msg) = operationerr_to_ldapresultcode(e);
                    Ok(LdapResponseState::Respond(sbr.gen_error(rc, msg)))
                }),
            ServerOps::Search(sr) => match uat {
                Some(u) => self
                    .do_search(idms, &sr, &u)
                    .await
                    .map(LdapResponseState::MultiPartResponse)
                    .or_else(|e| {
                        let (rc, msg) = operationerr_to_ldapresultcode(e);
                        Ok(LdapResponseState::Respond(sr.gen_error(rc, msg)))
                    }),
                None => {
                    // Search can occur without a bind, so bind first.
                    let lbt = match self.do_bind(idms, "", "").await {
                        Ok(Some(lbt)) => lbt,
                        Ok(None) => {
                            return Ok(LdapResponseState::Respond(
                                sr.gen_error(LdapResultCode::InvalidCredentials, "".to_string()),
                            ))
                        }
                        Err(e) => {
                            let (rc, msg) = operationerr_to_ldapresultcode(e);
                            return Ok(LdapResponseState::Respond(sr.gen_error(rc, msg)));
                        }
                    };
                    // If okay, do the search.
                    self.do_search(idms, &sr, &lbt)
                        .await
                        .map(|r| LdapResponseState::BindMultiPartResponse(lbt, r))
                        .or_else(|e| {
                            let (rc, msg) = operationerr_to_ldapresultcode(e);
                            Ok(LdapResponseState::Respond(sr.gen_error(rc, msg)))
                        })
                }
            },
            ServerOps::Unbind(_) => {
                // No need to notify on unbind (per rfc4511)
                Ok(LdapResponseState::Unbind)
            }
            ServerOps::Compare(cr) => Ok(LdapResponseState::Respond(
                cr.gen_error(LdapResultCode::Other, "not supported".to_string()),
            )),
            ServerOps::Whoami(wr) => match uat {
                Some(u) => Ok(LdapResponseState::Respond(
                    wr.gen_success(format!("u: {}", u.spn).as_str()),
                )),
                None => Ok(LdapResponseState::Respond(
                    wr.gen_operror(format!("Unbound Connection {eventid}").as_str()),
                )),
            },
        } // end match server op
    }
}

fn ldap_domain_to_dc(input: &str) -> String {
    let mut output: String = String::new();
    input.split('.').for_each(|dc| {
        output.push_str("dc=");
        output.push_str(dc);
        #[allow(clippy::single_char_pattern, clippy::single_char_add_str)]
        output.push_str(",");
    });
    // Remove the last ','
    output.pop();
    output
}

fn operationerr_to_ldapresultcode(e: OperationError) -> (LdapResultCode, String) {
    match e {
        OperationError::InvalidRequestState => {
            (LdapResultCode::ConstraintViolation, "".to_string())
        }
        OperationError::InvalidAttributeName(s) | OperationError::InvalidAttribute(s) => {
            (LdapResultCode::InvalidAttributeSyntax, s)
        }
        OperationError::SchemaViolation(se) => {
            (LdapResultCode::UnwillingToPerform, format!("{se:?}"))
        }
        e => (LdapResultCode::Other, format!("{e:?}")),
    }
}

#[inline]
pub(crate) fn ldap_all_vattrs() -> Vec<String> {
    vec![
        ATTR_CN.to_string(),
        ATTR_EMAIL.to_string(),
        ATTR_LDAP_EMAIL_ADDRESS.to_string(),
        LDAP_ATTR_EMAIL_ALTERNATIVE.to_string(),
        LDAP_ATTR_EMAIL_PRIMARY.to_string(),
        "entrydn".to_string(),
        LDAP_ATTR_ENTRYUUID.to_string(),
        LDAP_ATTR_KEYS.to_string(),
        LDAP_ATTR_MAIL_ALTERNATIVE.to_string(),
        LDAP_ATTR_MAIL_PRIMARY.to_string(),
        ATTR_OBJECTCLASS.to_string(),
        ATTR_LDAP_SSHPUBLICKEY.to_string(),
        ATTR_UIDNUMBER.to_string(),
    ]
}

#[inline]
pub(crate) fn ldap_vattr_map(input: &str) -> Option<&str> {
    // ⚠️  WARNING ⚠️
    // If you modify this list you MUST add these values to
    // corresponding phantom attributes in the schema to prevent
    // incorrect future or duplicate usage.
    //
    //   LDAP NAME     KANI ATTR SOURCE NAME
    match input {
        ATTR_CN => Some(ATTR_NAME),
        ATTR_EMAIL => Some(ATTR_MAIL),
        ATTR_LDAP_EMAIL_ADDRESS => Some(ATTR_MAIL),
        LDAP_ATTR_EMAIL_ALTERNATIVE => Some(ATTR_MAIL),
        LDAP_ATTR_EMAIL_PRIMARY => Some(ATTR_MAIL),
        LDAP_ATTR_ENTRYUUID => Some(ATTR_UUID),
        LDAP_ATTR_KEYS => Some(ATTR_SSH_PUBLICKEY),
        LDAP_ATTR_MAIL_ALTERNATIVE => Some(ATTR_MAIL),
        LDAP_ATTR_MAIL_PRIMARY => Some(ATTR_MAIL),
        ATTR_OBJECTCLASS => Some(ATTR_CLASS),
        ATTR_LDAP_SSHPUBLICKEY => Some(ATTR_SSH_PUBLICKEY), // no-underscore -> underscore
        ATTR_UIDNUMBER => Some(ATTR_GIDNUMBER),             // yes this is intentional
        _ => None,
    }
}

#[inline]
pub(crate) fn ldap_attr_filter_map(input: &str) -> AttrString {
    let a_lower = input.to_lowercase();
    AttrString::from(ldap_vattr_map(&a_lower).unwrap_or(a_lower.as_str()))
}

#[cfg(test)]
mod tests {
    use crate::prelude::*;
    use std::str::FromStr;

    use compact_jwt::{Jws, JwsUnverified};
    use hashbrown::HashSet;
    use kanidm_proto::v1::ApiToken;
    use ldap3_proto::proto::{LdapFilter, LdapOp, LdapSearchScope};
    use ldap3_proto::simple::*;

    use super::{LdapServer, LdapSession};
    use crate::idm::event::UnixPasswordChangeEvent;
    use crate::idm::serviceaccount::GenerateApiTokenEvent;

    const TEST_PASSWORD: &str = "ntaoeuntnaoeuhraohuercahu😍";

    #[idm_test]
    async fn test_ldap_simple_bind(idms: &IdmServer, _idms_delayed: &IdmServerDelayed) {
        let ldaps = LdapServer::new(idms).await.expect("failed to start ldap");

        let mut idms_prox_write = idms.proxy_write(duration_from_epoch_now()).await;
        // make the admin a valid posix account
        let me_posix = ModifyEvent::new_internal_invalid(
            filter!(f_eq(Attribute::Name, PartialValue::new_iname("admin"))),
            ModifyList::new_list(vec![
                Modify::Present(Attribute::Class.into(), EntryClass::PosixAccount.into()),
                Modify::Present(Attribute::GidNumber.into(), Value::new_uint32(2001)),
            ]),
        );
        assert!(idms_prox_write.qs_write.modify(&me_posix).is_ok());

        let pce = UnixPasswordChangeEvent::new_internal(UUID_ADMIN, TEST_PASSWORD);

        assert!(idms_prox_write.set_unix_account_password(&pce).is_ok());
        assert!(idms_prox_write.commit().is_ok()); // Committing all configs

        // default UNIX_PW bind (default is set to true)
        // Hence allows all unix binds
        let admin_t = ldaps
            .do_bind(idms, "admin", TEST_PASSWORD)
            .await
            .unwrap()
            .unwrap();
        assert!(admin_t.effective_session == LdapSession::UnixBind(UUID_ADMIN));
        let admin_t = ldaps
            .do_bind(idms, "admin@example.com", TEST_PASSWORD)
            .await
            .unwrap()
            .unwrap();
        assert!(admin_t.effective_session == LdapSession::UnixBind(UUID_ADMIN));

        // Setting UNIX_PW_BIND flag to false:
        // Hence all of the below authentication will fail (asserts are still satisfied)
        let mut idms_prox_write = idms.proxy_write(duration_from_epoch_now()).await;
        let disallow_unix_pw_flag = ModifyEvent::new_internal_invalid(
            filter!(f_eq(Attribute::Uuid, PartialValue::Uuid(UUID_DOMAIN_INFO))),
            ModifyList::new_purge_and_set(Attribute::DomainLdapAllowUnixPwBind, Value::Bool(false)),
        );
        assert!(idms_prox_write
            .qs_write
            .modify(&disallow_unix_pw_flag)
            .is_ok());
        assert!(idms_prox_write.commit().is_ok());
        let anon_t = ldaps.do_bind(idms, "", "").await.unwrap().unwrap();
        assert!(anon_t.effective_session == LdapSession::UnixBind(UUID_ANONYMOUS));
        assert!(
            ldaps.do_bind(idms, "", "test").await.unwrap_err() == OperationError::NotAuthenticated
        );
        let admin_t = ldaps.do_bind(idms, "admin", TEST_PASSWORD).await.unwrap();
        assert!(admin_t.is_none() == true);

        // Setting UNIX_PW_BIND flag to true :
        let mut idms_prox_write = idms.proxy_write(duration_from_epoch_now()).await;
        let allow_unix_pw_flag = ModifyEvent::new_internal_invalid(
            filter!(f_eq(Attribute::Uuid, PartialValue::Uuid(UUID_DOMAIN_INFO))),
            ModifyList::new_purge_and_set(Attribute::DomainLdapAllowUnixPwBind, Value::Bool(true)),
        );
        assert!(idms_prox_write.qs_write.modify(&allow_unix_pw_flag).is_ok());
        assert!(idms_prox_write.commit().is_ok());

        // Now test the admin and various DN's
        let admin_t = ldaps
            .do_bind(idms, "admin", TEST_PASSWORD)
            .await
            .unwrap()
            .unwrap();
        assert!(admin_t.effective_session == LdapSession::UnixBind(UUID_ADMIN));
        let admin_t = ldaps
            .do_bind(idms, "admin@example.com", TEST_PASSWORD)
            .await
            .unwrap()
            .unwrap();
        assert!(admin_t.effective_session == LdapSession::UnixBind(UUID_ADMIN));
        let admin_t = ldaps
            .do_bind(idms, STR_UUID_ADMIN, TEST_PASSWORD)
            .await
            .unwrap()
            .unwrap();
        assert!(admin_t.effective_session == LdapSession::UnixBind(UUID_ADMIN));
        let admin_t = ldaps
            .do_bind(idms, "name=admin,dc=example,dc=com", TEST_PASSWORD)
            .await
            .unwrap()
            .unwrap();
        assert!(admin_t.effective_session == LdapSession::UnixBind(UUID_ADMIN));
        let admin_t = ldaps
            .do_bind(
                idms,
                "spn=admin@example.com,dc=example,dc=com",
                TEST_PASSWORD,
            )
            .await
            .unwrap()
            .unwrap();
        assert!(admin_t.effective_session == LdapSession::UnixBind(UUID_ADMIN));
        let admin_t = ldaps
            .do_bind(
                idms,
                format!("uuid={STR_UUID_ADMIN},dc=example,dc=com").as_str(),
                TEST_PASSWORD,
            )
            .await
            .unwrap()
            .unwrap();
        assert!(admin_t.effective_session == LdapSession::UnixBind(UUID_ADMIN));

        let admin_t = ldaps
            .do_bind(idms, "name=admin", TEST_PASSWORD)
            .await
            .unwrap()
            .unwrap();
        assert!(admin_t.effective_session == LdapSession::UnixBind(UUID_ADMIN));
        let admin_t = ldaps
            .do_bind(idms, "spn=admin@example.com", TEST_PASSWORD)
            .await
            .unwrap()
            .unwrap();
        assert!(admin_t.effective_session == LdapSession::UnixBind(UUID_ADMIN));
        let admin_t = ldaps
            .do_bind(
                idms,
                format!("uuid={STR_UUID_ADMIN}").as_str(),
                TEST_PASSWORD,
            )
            .await
            .unwrap()
            .unwrap();
        assert!(admin_t.effective_session == LdapSession::UnixBind(UUID_ADMIN));

        let admin_t = ldaps
            .do_bind(idms, "admin,dc=example,dc=com", TEST_PASSWORD)
            .await
            .unwrap()
            .unwrap();
        assert!(admin_t.effective_session == LdapSession::UnixBind(UUID_ADMIN));
        let admin_t = ldaps
            .do_bind(idms, "admin@example.com,dc=example,dc=com", TEST_PASSWORD)
            .await
            .unwrap()
            .unwrap();
        assert!(admin_t.effective_session == LdapSession::UnixBind(UUID_ADMIN));
        let admin_t = ldaps
            .do_bind(
                idms,
                format!("{STR_UUID_ADMIN},dc=example,dc=com").as_str(),
                TEST_PASSWORD,
            )
            .await
            .unwrap()
            .unwrap();
        assert!(admin_t.effective_session == LdapSession::UnixBind(UUID_ADMIN));

        // Bad password, check last to prevent softlocking of the admin account.
        assert!(ldaps
            .do_bind(idms, "admin", "test")
            .await
            .unwrap()
            .is_none());

        // Non-existent and invalid DNs
        assert!(ldaps
            .do_bind(
                idms,
                "spn=admin@example.com,dc=clownshoes,dc=example,dc=com",
                TEST_PASSWORD
            )
            .await
            .is_err());
        assert!(ldaps
            .do_bind(
                idms,
                "spn=claire@example.com,dc=example,dc=com",
                TEST_PASSWORD
            )
            .await
            .is_err());
        assert!(ldaps
            .do_bind(idms, ",dc=example,dc=com", TEST_PASSWORD)
            .await
            .is_err());
        assert!(ldaps
            .do_bind(idms, "dc=example,dc=com", TEST_PASSWORD)
            .await
            .is_err());

        assert!(ldaps.do_bind(idms, "claire", "test").await.is_err());
    }

    macro_rules! assert_entry_contains {
        (
            $entry:expr,
            $dn:expr,
            $($item:expr),*
        ) => {{
            assert!($entry.dn == $dn);
            // Build a set from the attrs.
            let mut attrs = HashSet::new();
            for a in $entry.attributes.iter() {
                for v in a.vals.iter() {
                    attrs.insert((a.atype.as_str(), v.as_slice()));
                }
            };
            info!(?attrs);
            $(
                warn!("{}", $item.0);
                assert!(attrs.contains(&(
                    $item.0.as_ref(), $item.1.as_bytes()
                )));
            )*

        }};
    }

    #[idm_test]
    async fn test_ldap_virtual_attribute_generation(
        idms: &IdmServer,
        _idms_delayed: &IdmServerDelayed,
    ) {
        let ldaps = LdapServer::new(idms).await.expect("failed to start ldap");

        let ssh_ed25519 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAeGW1P6Pc2rPq0XqbRaDKBcXZUPRklo0L1EyR30CwoP william@amethyst";

        // Setup a user we want to check.
        {
            let e1 = entry_init!(
                (Attribute::Class, EntryClass::Object.to_value()),
                (Attribute::Class, EntryClass::Person.to_value()),
                (Attribute::Class, EntryClass::Account.to_value()),
                (Attribute::Class, EntryClass::PosixAccount.to_value()),
                (Attribute::Name, Value::new_iname("testperson1")),
                (
                    Attribute::Uuid,
                    Value::Uuid(uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930"))
                ),
                (Attribute::Description, Value::new_utf8s("testperson1")),
                (Attribute::DisplayName, Value::new_utf8s("testperson1")),
                (Attribute::GidNumber, Value::new_uint32(12345678)),
                (Attribute::LoginShell, Value::new_iutf8("/bin/zsh")),
                (
                    Attribute::SshPublicKey,
                    Value::new_sshkey_str("test", ssh_ed25519).expect("Invalid ssh key")
                )
            );

            let mut server_txn = idms.proxy_write(duration_from_epoch_now()).await;
            let ce = CreateEvent::new_internal(vec![e1]);
            assert!(server_txn
                .qs_write
                .create(&ce)
                .and_then(|_| server_txn.commit())
                .is_ok());
        }

        // Setup the anonymous login.
        let anon_t = ldaps.do_bind(idms, "", "").await.unwrap().unwrap();
        assert!(anon_t.effective_session == LdapSession::UnixBind(UUID_ANONYMOUS));

        // Check that when we request *, we get default list.
        let sr = SearchRequest {
            msgid: 1,
            base: "dc=example,dc=com".to_string(),
            scope: LdapSearchScope::Subtree,
            filter: LdapFilter::Equality(Attribute::Name.to_string(), "testperson1".to_string()),
            attrs: vec!["*".to_string()],
        };
        let r1 = ldaps.do_search(idms, &sr, &anon_t).await.unwrap();

        // The result, and the ldap proto success msg.
        assert!(r1.len() == 2);
        match &r1[0].op {
            LdapOp::SearchResultEntry(lsre) => {
                assert_entry_contains!(
                    lsre,
                    "spn=testperson1@example.com,dc=example,dc=com",
                    (Attribute::Class, EntryClass::Object.to_string()),
                    (Attribute::Class, EntryClass::Person.to_string()),
                    (Attribute::Class, EntryClass::Account.to_string()),
                    (Attribute::Class, EntryClass::PosixAccount.to_string()),
                    (Attribute::DisplayName, "testperson1"),
                    (Attribute::Name, "testperson1"),
                    (Attribute::GidNumber, "12345678"),
                    (Attribute::LoginShell, "/bin/zsh"),
                    (Attribute::SshPublicKey, ssh_ed25519),
                    (Attribute::Uuid, "cc8e95b4-c24f-4d68-ba54-8bed76f63930")
                );
            }
            _ => assert!(false),
        };

        // Check that when we request +, we get all attrs and the vattrs
        let sr = SearchRequest {
            msgid: 1,
            base: "dc=example,dc=com".to_string(),
            scope: LdapSearchScope::Subtree,
            filter: LdapFilter::Equality(Attribute::Name.to_string(), "testperson1".to_string()),
            attrs: vec!["+".to_string()],
        };
        let r1 = ldaps.do_search(idms, &sr, &anon_t).await.unwrap();

        // The result, and the ldap proto success msg.
        assert!(r1.len() == 2);
        match &r1[0].op {
            LdapOp::SearchResultEntry(lsre) => {
                assert_entry_contains!(
                    lsre,
                    "spn=testperson1@example.com,dc=example,dc=com",
                    (Attribute::ObjectClass, EntryClass::Object.as_ref()),
                    (Attribute::ObjectClass, EntryClass::Person.as_ref()),
                    (Attribute::ObjectClass, EntryClass::Account.as_ref()),
                    (Attribute::ObjectClass, EntryClass::PosixAccount.as_ref()),
                    (Attribute::DisplayName, "testperson1"),
                    (Attribute::Name, "testperson1"),
                    (Attribute::GidNumber, "12345678"),
                    (Attribute::LoginShell, "/bin/zsh"),
                    (Attribute::SshPublicKey, ssh_ed25519),
                    (Attribute::EntryUuid, "cc8e95b4-c24f-4d68-ba54-8bed76f63930"),
                    (
                        Attribute::EntryDn,
                        "spn=testperson1@example.com,dc=example,dc=com"
                    ),
                    (Attribute::UidNumber, "12345678"),
                    (Attribute::Cn, "testperson1"),
                    (Attribute::LdapKeys, ssh_ed25519)
                );
            }
            _ => assert!(false),
        };

        // Check that when we request an attr by name, we get all of them correctly.
        let sr = SearchRequest {
            msgid: 1,
            base: "dc=example,dc=com".to_string(),
            scope: LdapSearchScope::Subtree,
            filter: LdapFilter::Equality(Attribute::Name.to_string(), "testperson1".to_string()),
            attrs: vec![
                LDAP_ATTR_NAME.to_string(),
                Attribute::EntryDn.to_string(),
                ATTR_LDAP_KEYS.to_string(),
                Attribute::UidNumber.to_string(),
            ],
        };
        let r1 = ldaps.do_search(idms, &sr, &anon_t).await.unwrap();

        // The result, and the ldap proto success msg.
        assert!(r1.len() == 2);
        match &r1[0].op {
            LdapOp::SearchResultEntry(lsre) => {
                assert_entry_contains!(
                    lsre,
                    "spn=testperson1@example.com,dc=example,dc=com",
                    (Attribute::Name, "testperson1"),
                    (
                        Attribute::EntryDn,
                        "spn=testperson1@example.com,dc=example,dc=com"
                    ),
                    (Attribute::UidNumber, "12345678"),
                    (Attribute::LdapKeys, ssh_ed25519)
                );
            }
            _ => assert!(false),
        };
    }

    #[idm_test]
    async fn test_ldap_token_privilege_granting(
        idms: &IdmServer,
        _idms_delayed: &IdmServerDelayed,
    ) {
        // Setup the ldap server
        let ldaps = LdapServer::new(idms).await.expect("failed to start ldap");

        // Prebuild the search req we'll be using this test.
        let sr = SearchRequest {
            msgid: 1,
            base: "dc=example,dc=com".to_string(),
            scope: LdapSearchScope::Subtree,
            filter: LdapFilter::Equality(Attribute::Name.to_string(), "testperson1".to_string()),
            attrs: vec![
                LDAP_ATTR_NAME,
                LDAP_ATTR_MAIL,
                LDAP_ATTR_MAIL_PRIMARY,
                LDAP_ATTR_MAIL_ALTERNATIVE,
                LDAP_ATTR_EMAIL_PRIMARY,
                LDAP_ATTR_EMAIL_ALTERNATIVE,
            ]
            .into_iter()
            .map(|s| s.to_string())
            .collect(),
        };

        let sa_uuid = uuid::uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930");

        // Configure the user account that will have the tokens issued.
        // Should be a SERVICE account.
        let apitoken = {
            // Create a service account,

            let e1 = entry_init!(
                (Attribute::Class, EntryClass::Object.to_value()),
                (Attribute::Class, EntryClass::ServiceAccount.to_value()),
                (Attribute::Class, EntryClass::Account.to_value()),
                (Attribute::Uuid, Value::Uuid(sa_uuid)),
                (Attribute::Name, Value::new_iname("service_permission_test")),
                (
                    Attribute::DisplayName,
                    Value::new_utf8s("service_permission_test")
                )
            );

            // Setup a person with an email
            let e2 = entry_init!(
                (Attribute::Class, EntryClass::Object.to_value()),
                (Attribute::Class, EntryClass::Person.to_value()),
                (Attribute::Class, EntryClass::Account.to_value()),
                (Attribute::Class, EntryClass::PosixAccount.to_value()),
                (Attribute::Name, Value::new_iname("testperson1")),
                (
                    Attribute::Mail,
                    Value::EmailAddress("testperson1@example.com".to_string(), true)
                ),
                (
                    Attribute::Mail,
                    Value::EmailAddress("testperson1.alternative@example.com".to_string(), false)
                ),
                (Attribute::Description, Value::new_utf8s("testperson1")),
                (Attribute::DisplayName, Value::new_utf8s("testperson1")),
                (Attribute::GidNumber, Value::new_uint32(12345678)),
                (Attribute::LoginShell, Value::new_iutf8("/bin/zsh"))
            );

            // Setup an access control for the service account to view mail attrs.

            let ct = duration_from_epoch_now();

            let mut server_txn = idms.proxy_write(ct).await;
            let ce = CreateEvent::new_internal(vec![e1, e2]);
            assert!(server_txn.qs_write.create(&ce).is_ok());

            // idm_people_read_priv
            let me = ModifyEvent::new_internal_invalid(
                filter!(f_eq(
                    Attribute::Name,
                    PartialValue::new_iname(IDM_PEOPLE_READ_PRIV_V1.name)
                )),
                ModifyList::new_list(vec![Modify::Present(
                    Attribute::Member.into(),
                    Value::Refer(sa_uuid),
                )]),
            );
            assert!(server_txn.qs_write.modify(&me).is_ok());

            // Issue a token
            // make it purpose = ldap <- currently purpose isn't supported,
            // it's an idea for future.
            let gte = GenerateApiTokenEvent::new_internal(sa_uuid, "TestToken", None);

            let apitoken = server_txn
                .service_account_generate_api_token(&gte, ct)
                .expect("Failed to create new apitoken");

            assert!(server_txn.commit().is_ok());

            apitoken
        };

        // assert the token fails on non-ldap events token-xchg <- currently
        // we don't have purpose so this isn't tested.

        // Bind with anonymous, search and show mail attr isn't accessible.
        let anon_lbt = ldaps.do_bind(idms, "", "").await.unwrap().unwrap();
        assert!(anon_lbt.effective_session == LdapSession::UnixBind(UUID_ANONYMOUS));

        let r1 = ldaps.do_search(idms, &sr, &anon_lbt).await.unwrap();
        assert!(r1.len() == 2);
        match &r1[0].op {
            LdapOp::SearchResultEntry(lsre) => {
                assert_entry_contains!(
                    lsre,
                    "spn=testperson1@example.com,dc=example,dc=com",
                    (Attribute::Name, "testperson1")
                );
            }
            _ => assert!(false),
        };

        // Inspect the token to get its uuid out.
        let apitoken_unverified =
            JwsUnverified::from_str(&apitoken).expect("Failed to parse apitoken");

        let apitoken_inner: Jws<ApiToken> = apitoken_unverified
            .validate_embeded()
            .expect("Embedded jwk not found");

        let apitoken_inner = apitoken_inner.into_inner();

        // Bind using the token as a DN
        let sa_lbt = ldaps
            .do_bind(idms, "dn=token", &apitoken)
            .await
            .unwrap()
            .unwrap();
        assert!(sa_lbt.effective_session == LdapSession::ApiToken(apitoken_inner.clone()));

        // Bind using the token as a pw
        let sa_lbt = ldaps.do_bind(idms, "", &apitoken).await.unwrap().unwrap();
        assert!(sa_lbt.effective_session == LdapSession::ApiToken(apitoken_inner));

        // Search and retrieve mail that's now accessible.
        let r1 = ldaps.do_search(idms, &sr, &sa_lbt).await.unwrap();
        assert!(r1.len() == 2);
        match &r1[0].op {
            LdapOp::SearchResultEntry(lsre) => {
                assert_entry_contains!(
                    lsre,
                    "spn=testperson1@example.com,dc=example,dc=com",
                    (Attribute::Name.as_ref(), "testperson1"),
                    (Attribute::Mail.as_ref(), "testperson1@example.com"),
                    (
                        Attribute::Mail.as_ref(),
                        "testperson1.alternative@example.com"
                    ),
                    (LDAP_ATTR_MAIL_PRIMARY, "testperson1@example.com"),
                    (
                        LDAP_ATTR_MAIL_ALTERNATIVE,
                        "testperson1.alternative@example.com"
                    ),
                    (LDAP_ATTR_MAIL_PRIMARY, "testperson1@example.com"),
                    (
                        LDAP_ATTR_MAIL_ALTERNATIVE,
                        "testperson1.alternative@example.com"
                    )
                );
            }
            _ => assert!(false),
        };
    }

    #[idm_test]
    async fn test_ldap_virtual_attribute_with_all_attr_search(
        idms: &IdmServer,
        _idms_delayed: &IdmServerDelayed,
    ) {
        let ldaps = LdapServer::new(idms).await.expect("failed to start ldap");

        let acct_uuid = uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930");

        // Setup a user we want to check.
        {
            let e1 = entry_init!(
                (Attribute::Class, EntryClass::Person.to_value()),
                (Attribute::Class, EntryClass::Account.to_value()),
                (Attribute::Name, Value::new_iname("testperson1")),
                (Attribute::Uuid, Value::Uuid(acct_uuid)),
                (Attribute::Description, Value::new_utf8s("testperson1")),
                (Attribute::DisplayName, Value::new_utf8s("testperson1"))
            );

            let mut server_txn = idms.proxy_write(duration_from_epoch_now()).await;
            assert!(server_txn
                .qs_write
                .internal_create(vec![e1])
                .and_then(|_| server_txn.commit())
                .is_ok());
        }

        // Setup the anonymous login.
        let anon_t = ldaps.do_bind(idms, "", "").await.unwrap().unwrap();
        assert!(anon_t.effective_session == LdapSession::UnixBind(UUID_ANONYMOUS));

        // Check that when we request a virtual attr by name *and* all_attrs we get all the requested values.
        let sr = SearchRequest {
            msgid: 1,
            base: "dc=example,dc=com".to_string(),
            scope: LdapSearchScope::Subtree,
            filter: LdapFilter::Equality(Attribute::Name.to_string(), "testperson1".to_string()),
            attrs: vec![
                "*".to_string(),
                // Already being returned
                LDAP_ATTR_NAME.to_string(),
                // This is a virtual attribute
                Attribute::EntryUuid.to_string(),
            ],
        };
        let r1 = ldaps.do_search(idms, &sr, &anon_t).await.unwrap();

        // The result, and the ldap proto success msg.
        assert!(r1.len() == 2);
        match &r1[0].op {
            LdapOp::SearchResultEntry(lsre) => {
                assert_entry_contains!(
                    lsre,
                    "spn=testperson1@example.com,dc=example,dc=com",
                    (Attribute::Name, "testperson1"),
                    (Attribute::DisplayName, "testperson1"),
                    (Attribute::Uuid, "cc8e95b4-c24f-4d68-ba54-8bed76f63930"),
                    (
                        Attribute::EntryUuid.as_ref(),
                        "cc8e95b4-c24f-4d68-ba54-8bed76f63930"
                    )
                );
            }
            _ => assert!(false),
        };
    }

    #[idm_test]
    async fn test_ldap_rootdse_basedn_change(idms: &IdmServer, _idms_delayed: &IdmServerDelayed) {
        let ldaps = LdapServer::new(idms).await.expect("failed to start ldap");

        let anon_t = ldaps.do_bind(idms, "", "").await.unwrap().unwrap();
        assert!(anon_t.effective_session == LdapSession::UnixBind(UUID_ANONYMOUS));

        let sr = SearchRequest {
            msgid: 1,
            base: "".to_string(),
            scope: LdapSearchScope::Base,
            filter: LdapFilter::Present(Attribute::ObjectClass.to_string()),
            attrs: vec!["*".to_string()],
        };
        let r1 = ldaps.do_search(idms, &sr, &anon_t).await.unwrap();

        trace!(?r1);

        // The result, and the ldap proto success msg.
        assert!(r1.len() == 2);
        match &r1[0].op {
            LdapOp::SearchResultEntry(lsre) => {
                assert_entry_contains!(
                    lsre,
                    "",
                    (Attribute::ObjectClass, "top"),
                    ("vendorname", "Kanidm Project"),
                    ("supportedldapversion", "3"),
                    ("defaultnamingcontext", "dc=example,dc=com")
                );
            }
            _ => assert!(false),
        };

        drop(ldaps);

        // Change the domain basedn

        let mut idms_prox_write = idms.proxy_write(duration_from_epoch_now()).await;
        // make the admin a valid posix account
        let me_posix = ModifyEvent::new_internal_invalid(
            filter!(f_eq(Attribute::Uuid, PartialValue::Uuid(UUID_DOMAIN_INFO))),
            ModifyList::new_purge_and_set(
                Attribute::DomainLdapBasedn,
                Value::new_iutf8("o=kanidmproject"),
            ),
        );
        assert!(idms_prox_write.qs_write.modify(&me_posix).is_ok());

        assert!(idms_prox_write.commit().is_ok());

        // Now re-test
        let ldaps = LdapServer::new(idms).await.expect("failed to start ldap");

        let anon_t = ldaps.do_bind(idms, "", "").await.unwrap().unwrap();
        assert!(anon_t.effective_session == LdapSession::UnixBind(UUID_ANONYMOUS));

        let sr = SearchRequest {
            msgid: 1,
            base: "".to_string(),
            scope: LdapSearchScope::Base,
            filter: LdapFilter::Present(Attribute::ObjectClass.to_string()),
            attrs: vec!["*".to_string()],
        };
        let r1 = ldaps.do_search(idms, &sr, &anon_t).await.unwrap();

        trace!(?r1);

        // The result, and the ldap proto success msg.
        assert!(r1.len() == 2);
        match &r1[0].op {
            LdapOp::SearchResultEntry(lsre) => {
                assert_entry_contains!(
                    lsre,
                    "",
                    (Attribute::ObjectClass, "top"),
                    ("vendorname", "Kanidm Project"),
                    ("supportedldapversion", "3"),
                    ("defaultnamingcontext", "o=kanidmproject")
                );
            }
            _ => assert!(false),
        };
    }
}
