//! LDAP specific operations handling components. This is where LDAP operations
//! are sent to for processing.

use std::collections::BTreeSet;
use std::iter;
use std::str::FromStr;

use compact_jwt::JwsCompact;
use kanidm_proto::constants::*;
use kanidm_proto::internal::{ApiToken, UserAuthToken};
use ldap3_proto::simple::*;
use regex::{Regex, RegexBuilder};
use std::net::IpAddr;
use tracing::trace;
use uuid::Uuid;

use crate::event::SearchEvent;
use crate::idm::event::{LdapApplicationAuthEvent, LdapAuthEvent, LdapTokenAuthEvent};
use crate::idm::server::{IdmServer, IdmServerAuthTransaction, IdmServerTransaction};
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
    ApplicationPasswordBind(Uuid, Uuid),
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
    max_queryable_attrs: usize,
}

#[derive(Debug)]
enum LdapBindTarget {
    Account(Uuid),
    ApiToken,
    Application(String, Uuid),
}

impl LdapServer {
    pub async fn new(idms: &IdmServer) -> Result<Self, OperationError> {
        // let ct = duration_from_epoch_now();
        let mut idms_prox_read = idms.proxy_read().await?;
        // This is the rootdse path.
        // get the domain_info item
        let domain_entry = idms_prox_read
            .qs_read
            .internal_search_uuid(UUID_DOMAIN_INFO)?;

        // Get the maximum number of queryable attributes from the domain entry
        let max_queryable_attrs = domain_entry
            .get_ava_single_uint32(Attribute::LdapMaxQueryableAttrs)
            .map(|u| u as usize)
            .unwrap_or(DEFAULT_LDAP_MAXIMUM_QUERYABLE_ATTRIBUTES);

        let basedn = domain_entry
            .get_ava_single_iutf8(Attribute::DomainLdapBasedn)
            .map(|s| s.to_string())
            .or_else(|| {
                domain_entry
                    .get_ava_single_iname(Attribute::DomainName)
                    .map(ldap_domain_to_dc)
            })
            .ok_or(OperationError::InvalidEntryState)?;

        // It is necessary to swap greed to avoid the first group "<attr>=<val>" matching the
        // next group "app=<app>", son one can use "app=app1,dc=test,dc=net" as search base:
        // Greedy (app=app1,dc=test,dc=net):
        //     Match 1      - app=app1,dc=test,dc=net
        //     Group 1      - app=app1,
        //     Group <attr> - app
        //     Group <val>  - app1
        //     Group 6      - dc=test,dc=net
        // Ungreedy (app=app1,dc=test,dc=net):
        //     Match 1      - app=app1,dc=test,dc=net
        //     Group 4      - app=app1,
        //     Group <app>  - app1
        //     Group 6      - dc=test,dc=net
        let dnre = RegexBuilder::new(
            format!("^((?P<attr>[^=,]+)=(?P<val>[^=,]+),)?(app=(?P<app>[^=,]+),)?({basedn})$")
                .as_str(),
        )
        .swap_greed(true)
        .build()
        .map_err(|_| OperationError::InvalidEntryState)?;

        let binddnre = Regex::new(
            format!("^((([^=,]+)=)?(?P<val>[^=,]+))(,app=(?P<app>[^=,]+))?(,{basedn})?$").as_str(),
        )
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
            max_queryable_attrs,
        })
    }

    #[instrument(level = "debug", skip_all)]
    async fn do_search(
        &self,
        idms: &IdmServer,
        sr: &SearchRequest,
        uat: &LdapBoundToken,
        source: Source,
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
                // OneLevel and Child searches are **very** similar for us because child
                // is a "subtree search excluding base". Because we don't have a tree structure at
                // all, this is the same as a one level (all children of base excluding base).
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

            let mut no_attrs = false;
            let mut all_attrs = false;
            let mut all_op_attrs = false;

            let attrs_len = sr.attrs.len();
            if sr.attrs.is_empty() {
                // If [], then "all" attrs
                all_attrs = true;
            } else if attrs_len < self.max_queryable_attrs {
                sr.attrs.iter().for_each(|a| {
                    if a == "*" {
                        all_attrs = true;
                    } else if a == "+" {
                        // This forces the BE to get all the attrs so we can
                        // map all vattrs.
                        all_attrs = true;
                        all_op_attrs = true;
                    } else if a == "1.1" {
                        /*
                         *  ref https://www.rfc-editor.org/rfc/rfc4511#section-4.5.1.8
                         *
                         *  A list containing only the OID "1.1" indicates that no
                         *  attributes are to be returned. If "1.1" is provided with other
                         *  attributeSelector values, the "1.1" attributeSelector is
                         *  ignored. This OID was chosen because it does not (and can not)
                         *  correspond to any attribute in use.
                         */
                        if sr.attrs.len() == 1 {
                            no_attrs = true;
                        }
                    }
                })
            } else {
                admin_error!(
                    "Too many LDAP attributes requested. Maximum allowed is {}, while your search query had {}",
                    self.max_queryable_attrs, attrs_len
                );
                return Err(OperationError::ResourceLimit);
            }

            // We need to retain this to know what the client requested.
            let (k_attrs, l_attrs) = if no_attrs {
                // Request no attributes and no mapped attributes.
                (None, Vec::with_capacity(0))
            } else if all_op_attrs {
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
                        if a == "*" || a == "+" || a == "1.1" {
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
                    .map(|a| Attribute::from(ldap_vattr_map(a).unwrap_or(a)))
                    .collect();

                (Some(mapped_attrs), req_attrs)
            };

            admin_info!(attr = ?l_attrs, "LDAP Search Request LDAP Attrs");
            admin_info!(attr = ?k_attrs, "LDAP Search Request Mapped Attrs");

            let ct = duration_from_epoch_now();
            let mut idm_read = idms.proxy_read().await?;
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
                .validate_ldap_session(&uat.effective_session, source, ct)
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
            if dn.is_empty() { "(empty dn)" } else { dn }
        );
        let ct = duration_from_epoch_now();

        let mut idm_auth = idms.auth().await?;
        let target = self.bind_target_from_bind_dn(&mut idm_auth, dn, pw).await?;

        let result = match target {
            LdapBindTarget::Account(uuid) => {
                let lae = LdapAuthEvent::from_parts(uuid, pw.to_string())?;
                idm_auth.auth_ldap(&lae, ct).await?
            }
            LdapBindTarget::ApiToken => {
                let jwsc = JwsCompact::from_str(pw).map_err(|err| {
                    error!(?err, "Invalid JwsCompact supplied as authentication token.");
                    OperationError::NotAuthenticated
                })?;

                let lae = LdapTokenAuthEvent::from_parts(jwsc)?;
                idm_auth.token_auth_ldap(&lae, ct).await?
            }
            LdapBindTarget::Application(ref app_name, usr_uuid) => {
                let lae =
                    LdapApplicationAuthEvent::new(app_name.as_str(), usr_uuid, pw.to_string())?;
                idm_auth.application_auth_ldap(&lae, ct).await?
            }
        };

        idm_auth.commit()?;

        if result.is_some() {
            security_info!(
                "✅ LDAP Bind success for {} -> {:?}",
                if dn.is_empty() { "(empty dn)" } else { dn },
                target
            );
        } else {
            security_info!(
                "❌ LDAP Bind failure for {} -> {:?}",
                if dn.is_empty() { "(empty dn)" } else { dn },
                target
            );
        }

        Ok(result)
    }

    #[instrument(level = "debug", skip_all)]
    async fn do_compare(
        &self,
        idms: &IdmServer,
        cr: &CompareRequest,
        uat: &LdapBoundToken,
        source: Source,
    ) -> Result<Vec<LdapMsg>, OperationError> {
        admin_info!("Attempt LDAP CompareRequest for {}", uat.spn);

        let (opt_attr, opt_value) = match self.dnre.captures(cr.entry.as_str()) {
            Some(caps) => (
                caps.name("attr").map(|v| v.as_str().to_string()),
                caps.name("val").map(|v| v.as_str().to_string()),
            ),
            None => {
                request_error!("LDAP Search failure - invalid basedn");
                return Err(OperationError::InvalidRequestState);
            }
        };

        let ext_filter = match (opt_attr, opt_value) {
            (Some(a), Some(v)) => LdapFilter::Equality(a, v),
            _ => {
                request_error!("LDAP Search failure - invalid rdn");
                return Err(OperationError::InvalidRequestState);
            }
        };

        let ct = duration_from_epoch_now();
        let mut idm_read = idms.proxy_read().await?;
        // Now start the txn - we need it for resolving filter components.

        // join the filter, with ext_filter
        let lfilter = LdapFilter::And(vec![
            ext_filter.clone(),
            LdapFilter::Equality(cr.atype.clone(), cr.val.clone()),
            LdapFilter::Not(Box::new(LdapFilter::Or(vec![
                LdapFilter::Equality(Attribute::Class.to_string(), "classtype".to_string()),
                LdapFilter::Equality(Attribute::Class.to_string(), "attributetype".to_string()),
                LdapFilter::Equality(
                    Attribute::Class.to_string(),
                    "access_control_profile".to_string(),
                ),
            ]))),
        ]);

        admin_info!(filter = ?lfilter, "LDAP Compare Filter");

        // Build the event, with the permissions from effective_session
        let ident = idm_read
            .validate_ldap_session(&uat.effective_session, source, ct)
            .map_err(|e| {
                admin_error!("Invalid identity: {:?}", e);
                e
            })?;

        let f = Filter::from_ldap_ro(&ident, &lfilter, &mut idm_read.qs_read)?;
        let filter_orig = f
            .validate(idm_read.qs_read.get_schema())
            .map_err(OperationError::SchemaViolation)?;
        let filter = filter_orig.clone().into_ignore_hidden();

        let ee = ExistsEvent {
            ident: ident.clone(),
            filter,
            filter_orig,
        };

        let res = idm_read.qs_read.exists(&ee).map_err(|e| {
            admin_error!("call to exists failure {:?}", e);
            e
        })?;

        if res {
            admin_info!("LDAP Compare -> True");
            return Ok(vec![cr.gen_compare_true()]);
        }

        // we need to check if the entry exists at all (without the ava).
        let lfilter = LdapFilter::And(vec![
            ext_filter,
            LdapFilter::Not(Box::new(LdapFilter::Or(vec![
                LdapFilter::Equality(Attribute::Class.to_string(), "classtype".to_string()),
                LdapFilter::Equality(Attribute::Class.to_string(), "attributetype".to_string()),
                LdapFilter::Equality(
                    Attribute::Class.to_string(),
                    "access_control_profile".to_string(),
                ),
            ]))),
        ]);
        let f = Filter::from_ldap_ro(&ident, &lfilter, &mut idm_read.qs_read)?;
        let filter_orig = f
            .validate(idm_read.qs_read.get_schema())
            .map_err(OperationError::SchemaViolation)?;
        let filter = filter_orig.clone().into_ignore_hidden();
        let ee = ExistsEvent {
            ident,
            filter,
            filter_orig,
        };

        let res = idm_read.qs_read.exists(&ee).map_err(|e| {
            admin_error!("call to exists failure {:?}", e);
            e
        })?;

        if res {
            admin_info!("LDAP Compare -> False");
            return Ok(vec![cr.gen_compare_false()]);
        }

        Ok(vec![
            cr.gen_error(LdapResultCode::NoSuchObject, "".to_string())
        ])
    }

    pub async fn do_op(
        &self,
        idms: &IdmServer,
        server_op: ServerOps,
        uat: Option<LdapBoundToken>,
        ip_addr: IpAddr,
        eventid: Uuid,
    ) -> Result<LdapResponseState, OperationError> {
        let source = Source::Ldaps(ip_addr);

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
                    .do_search(idms, &sr, &u, source)
                    .await
                    .map(LdapResponseState::MultiPartResponse)
                    .or_else(|e| {
                        let (rc, msg) = operationerr_to_ldapresultcode(e);
                        Ok(LdapResponseState::Respond(sr.gen_error(rc, msg)))
                    }),
                None => {
                    // Search can occur without a bind, so bind first.
                    // This is per section 4 of RFC 4513 (https://www.rfc-editor.org/rfc/rfc4513#section-4).
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
                    self.do_search(idms, &sr, &lbt, Source::Internal)
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
            ServerOps::Compare(cr) => match uat {
                Some(u) => self
                    .do_compare(idms, &cr, &u, source)
                    .await
                    .map(LdapResponseState::MultiPartResponse)
                    .or_else(|e| {
                        let (rc, msg) = operationerr_to_ldapresultcode(e);
                        Ok(LdapResponseState::Respond(cr.gen_error(rc, msg)))
                    }),
                None => {
                    // Compare can occur without a bind, so bind first.
                    // This is per section 4 of RFC 4513 (https://www.rfc-editor.org/rfc/rfc4513#section-4).
                    let lbt = match self.do_bind(idms, "", "").await {
                        Ok(Some(lbt)) => lbt,
                        Ok(None) => {
                            return Ok(LdapResponseState::Respond(
                                cr.gen_error(LdapResultCode::InvalidCredentials, "".to_string()),
                            ))
                        }
                        Err(e) => {
                            let (rc, msg) = operationerr_to_ldapresultcode(e);
                            return Ok(LdapResponseState::Respond(cr.gen_error(rc, msg)));
                        }
                    };
                    // If okay, do the compare.
                    self.do_compare(idms, &cr, &lbt, Source::Internal)
                        .await
                        .map(|r| LdapResponseState::BindMultiPartResponse(lbt, r))
                        .or_else(|e| {
                            let (rc, msg) = operationerr_to_ldapresultcode(e);
                            Ok(LdapResponseState::Respond(cr.gen_error(rc, msg)))
                        })
                }
            },
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

    async fn bind_target_from_bind_dn(
        &self,
        idm_auth: &mut IdmServerAuthTransaction<'_>,
        dn: &str,
        pw: &str,
    ) -> Result<LdapBindTarget, OperationError> {
        if dn.is_empty() {
            if pw.is_empty() {
                return Ok(LdapBindTarget::Account(UUID_ANONYMOUS));
            } else {
                // This is the path to access api-token logins.
                return Ok(LdapBindTarget::ApiToken);
            }
        } else if dn == "dn=token" {
            // Is the passed dn requesting token auth?
            // We use dn= here since these are attr=value, and dn is a phantom so it will
            // never be present or match a real value. We also make it an ava so that clients
            // that over-zealously validate dn syntax are happy.
            return Ok(LdapBindTarget::ApiToken);
        }

        if let Some(captures) = self.binddnre.captures(dn) {
            if let Some(usr) = captures.name("val") {
                let usr = usr.as_str();

                if usr.is_empty() {
                    error!("Failed to parse user name from bind DN, it is empty (capture group is {:#?})", captures.name("val"));
                    return Err(OperationError::NoMatchingEntries);
                }

                let usr_uuid = idm_auth.qs_read.name_to_uuid(usr).map_err(|e| {
                    error!(err = ?e, ?usr, "Error resolving rdn to target");
                    e
                })?;

                if let Some(app) = captures.name("app") {
                    let app = app.as_str();

                    if app.is_empty() {
                        error!("Failed to parse application name from bind DN, it is empty (capture group is {:#?})", captures.name("app"));
                        return Err(OperationError::NoMatchingEntries);
                    }

                    return Ok(LdapBindTarget::Application(app.to_string(), usr_uuid));
                }

                return Ok(LdapBindTarget::Account(usr_uuid));
            }
        }

        error!(
            binddn = ?dn,
            "Failed to parse bind DN - check the basedn and app attribute if present are correct. Examples: name=tobias,app=lounge,{} OR name=ellie,{} OR name=claire,app=table OR name=william ", self.basedn, self.basedn
        );

        Err(OperationError::NoMatchingEntries)
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
        LDAP_ATTR_DN.to_string(),
        LDAP_ATTR_EMAIL_ALTERNATIVE.to_string(),
        LDAP_ATTR_EMAIL_PRIMARY.to_string(),
        LDAP_ATTR_ENTRYDN.to_string(),
        LDAP_ATTR_ENTRYUUID.to_string(),
        LDAP_ATTR_KEYS.to_string(),
        LDAP_ATTR_MAIL_ALTERNATIVE.to_string(),
        LDAP_ATTR_MAIL_PRIMARY.to_string(),
        ATTR_OBJECTCLASS.to_string(),
        ATTR_LDAP_SSHPUBLICKEY.to_string(),
        ATTR_UIDNUMBER.to_string(),
        ATTR_UID.to_string(),
        ATTR_GECOS.to_string(),
        ATTR_HOME_DIRECTORY.to_string(),
        ATTR_PWD_CHANGED_TIME.to_string(),
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
        // EntryDN and DN have special handling in to_ldap in Entry. However, we
        // need to map them to "name" so that if the user has requested dn/entrydn
        // only, then we still requested at least one attribute from the backend
        // allowing the access control tests to take place. Otherwise no entries
        // would be returned.
        ATTR_CN | ATTR_UID | LDAP_ATTR_ENTRYDN | LDAP_ATTR_DN => Some(ATTR_NAME),
        ATTR_GECOS => Some(ATTR_DISPLAYNAME),
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
        ATTR_HOME_DIRECTORY => Some(ATTR_UUID),
        LDAP_ATTR_PWD_CHANGED_TIME => Some(ATTR_PWD_CHANGED_TIME),
        _ => None,
    }
}

#[inline]
pub(crate) fn ldap_attr_filter_map(input: &str) -> Attribute {
    let a_lower = input.to_lowercase();
    Attribute::from(ldap_vattr_map(&a_lower).unwrap_or(a_lower.as_str()))
}

#[cfg(test)]
mod tests {
    use crate::prelude::*;

    use compact_jwt::{dangernoverify::JwsDangerReleaseWithoutVerify, JwsVerifier};
    use hashbrown::HashSet;
    use kanidm_proto::internal::ApiToken;
    use ldap3_proto::proto::{
        LdapFilter, LdapMsg, LdapOp, LdapResultCode, LdapSearchScope, LdapSubstringFilter,
    };
    use ldap3_proto::simple::*;

    use super::{LdapServer, LdapSession};
    use crate::idm::application::GenerateApplicationPasswordEvent;
    use crate::idm::event::{LdapApplicationAuthEvent, UnixPasswordChangeEvent};
    use crate::idm::serviceaccount::GenerateApiTokenEvent;

    const TEST_PASSWORD: &str = "ntaoeuntnaoeuhraohuercahu😍";

    #[idm_test]
    async fn test_ldap_simple_bind(idms: &IdmServer, _idms_delayed: &IdmServerDelayed) {
        let ldaps = LdapServer::new(idms).await.expect("failed to start ldap");

        let mut idms_prox_write = idms.proxy_write(duration_from_epoch_now()).await.unwrap();
        // make the admin a valid posix account
        let me_posix = ModifyEvent::new_internal_invalid(
            filter!(f_eq(Attribute::Name, PartialValue::new_iname("admin"))),
            ModifyList::new_list(vec![
                Modify::Present(Attribute::Class, EntryClass::PosixAccount.into()),
                Modify::Present(Attribute::GidNumber, Value::new_uint32(2001)),
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
        assert_eq!(admin_t.effective_session, LdapSession::UnixBind(UUID_ADMIN));
        let admin_t = ldaps
            .do_bind(idms, "admin@example.com", TEST_PASSWORD)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(admin_t.effective_session, LdapSession::UnixBind(UUID_ADMIN));

        // Setting UNIX_PW_BIND flag to false:
        // Hence all of the below authentication will fail (asserts are still satisfied)
        let mut idms_prox_write = idms.proxy_write(duration_from_epoch_now()).await.unwrap();
        let disallow_unix_pw_flag = ModifyEvent::new_internal_invalid(
            filter!(f_eq(Attribute::Uuid, PartialValue::Uuid(UUID_DOMAIN_INFO))),
            ModifyList::new_purge_and_set(Attribute::LdapAllowUnixPwBind, Value::Bool(false)),
        );
        assert!(idms_prox_write
            .qs_write
            .modify(&disallow_unix_pw_flag)
            .is_ok());
        assert!(idms_prox_write.commit().is_ok());
        let anon_t = ldaps.do_bind(idms, "", "").await.unwrap().unwrap();
        assert_eq!(
            anon_t.effective_session,
            LdapSession::UnixBind(UUID_ANONYMOUS)
        );
        assert!(
            ldaps.do_bind(idms, "", "test").await.unwrap_err() == OperationError::NotAuthenticated
        );
        let admin_t = ldaps.do_bind(idms, "admin", TEST_PASSWORD).await.unwrap();
        assert!(admin_t.is_none());

        // Setting UNIX_PW_BIND flag to true :
        let mut idms_prox_write = idms.proxy_write(duration_from_epoch_now()).await.unwrap();
        let allow_unix_pw_flag = ModifyEvent::new_internal_invalid(
            filter!(f_eq(Attribute::Uuid, PartialValue::Uuid(UUID_DOMAIN_INFO))),
            ModifyList::new_purge_and_set(Attribute::LdapAllowUnixPwBind, Value::Bool(true)),
        );
        assert!(idms_prox_write.qs_write.modify(&allow_unix_pw_flag).is_ok());
        assert!(idms_prox_write.commit().is_ok());

        // Now test the admin and various DN's
        let admin_t = ldaps
            .do_bind(idms, "admin", TEST_PASSWORD)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(admin_t.effective_session, LdapSession::UnixBind(UUID_ADMIN));
        let admin_t = ldaps
            .do_bind(idms, "admin@example.com", TEST_PASSWORD)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(admin_t.effective_session, LdapSession::UnixBind(UUID_ADMIN));
        let admin_t = ldaps
            .do_bind(idms, STR_UUID_ADMIN, TEST_PASSWORD)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(admin_t.effective_session, LdapSession::UnixBind(UUID_ADMIN));
        let admin_t = ldaps
            .do_bind(idms, "name=admin,dc=example,dc=com", TEST_PASSWORD)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(admin_t.effective_session, LdapSession::UnixBind(UUID_ADMIN));
        let admin_t = ldaps
            .do_bind(
                idms,
                "spn=admin@example.com,dc=example,dc=com",
                TEST_PASSWORD,
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(admin_t.effective_session, LdapSession::UnixBind(UUID_ADMIN));
        let admin_t = ldaps
            .do_bind(
                idms,
                format!("uuid={STR_UUID_ADMIN},dc=example,dc=com").as_str(),
                TEST_PASSWORD,
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(admin_t.effective_session, LdapSession::UnixBind(UUID_ADMIN));

        let admin_t = ldaps
            .do_bind(idms, "name=admin", TEST_PASSWORD)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(admin_t.effective_session, LdapSession::UnixBind(UUID_ADMIN));
        let admin_t = ldaps
            .do_bind(idms, "spn=admin@example.com", TEST_PASSWORD)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(admin_t.effective_session, LdapSession::UnixBind(UUID_ADMIN));
        let admin_t = ldaps
            .do_bind(
                idms,
                format!("uuid={STR_UUID_ADMIN}").as_str(),
                TEST_PASSWORD,
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(admin_t.effective_session, LdapSession::UnixBind(UUID_ADMIN));

        let admin_t = ldaps
            .do_bind(idms, "admin,dc=example,dc=com", TEST_PASSWORD)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(admin_t.effective_session, LdapSession::UnixBind(UUID_ADMIN));
        let admin_t = ldaps
            .do_bind(idms, "admin@example.com,dc=example,dc=com", TEST_PASSWORD)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(admin_t.effective_session, LdapSession::UnixBind(UUID_ADMIN));
        let admin_t = ldaps
            .do_bind(
                idms,
                format!("{STR_UUID_ADMIN},dc=example,dc=com").as_str(),
                TEST_PASSWORD,
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(admin_t.effective_session, LdapSession::UnixBind(UUID_ADMIN));

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

    #[idm_test]
    async fn test_ldap_application_dnre(idms: &IdmServer, _idms_delayed: &IdmServerDelayed) {
        let ldaps = LdapServer::new(idms).await.expect("failed to start ldap");

        let testdn = format!("app=app1,{0}", ldaps.basedn);
        let captures = ldaps.dnre.captures(testdn.as_str()).unwrap();
        assert!(captures.name("app").is_some());
        assert!(captures.name("attr").is_none());
        assert!(captures.name("val").is_none());

        let testdn = format!("uid=foo,app=app1,{0}", ldaps.basedn);
        let captures = ldaps.dnre.captures(testdn.as_str()).unwrap();
        assert!(captures.name("app").is_some());
        assert!(captures.name("attr").is_some());
        assert!(captures.name("val").is_some());

        let testdn = format!("uid=foo,{0}", ldaps.basedn);
        let captures = ldaps.dnre.captures(testdn.as_str()).unwrap();
        assert!(captures.name("app").is_none());
        assert!(captures.name("attr").is_some());
        assert!(captures.name("val").is_some());
    }

    #[idm_test]
    async fn test_ldap_application_search(idms: &IdmServer, _idms_delayed: &IdmServerDelayed) {
        let ldaps = LdapServer::new(idms).await.expect("failed to start ldap");

        let usr_uuid = Uuid::new_v4();
        let grp_uuid = Uuid::new_v4();
        let app_uuid = Uuid::new_v4();
        let app_name = "testapp1";

        // Setup person, group and application
        {
            let e1 = entry_init!(
                (Attribute::Class, EntryClass::Object.to_value()),
                (Attribute::Class, EntryClass::Account.to_value()),
                (Attribute::Class, EntryClass::Person.to_value()),
                (Attribute::Name, Value::new_iname("testperson1")),
                (Attribute::Uuid, Value::Uuid(usr_uuid)),
                (Attribute::Description, Value::new_utf8s("testperson1")),
                (Attribute::DisplayName, Value::new_utf8s("testperson1"))
            );

            let e2 = entry_init!(
                (Attribute::Class, EntryClass::Object.to_value()),
                (Attribute::Class, EntryClass::Group.to_value()),
                (Attribute::Name, Value::new_iname("testgroup1")),
                (Attribute::Uuid, Value::Uuid(grp_uuid))
            );

            let e3 = entry_init!(
                (Attribute::Class, EntryClass::Object.to_value()),
                (Attribute::Class, EntryClass::Account.to_value()),
                (Attribute::Class, EntryClass::ServiceAccount.to_value()),
                (Attribute::Class, EntryClass::Application.to_value()),
                (Attribute::DisplayName, Value::new_utf8s("Application")),
                (Attribute::Name, Value::new_iname(app_name)),
                (Attribute::Uuid, Value::Uuid(app_uuid)),
                (Attribute::LinkedGroup, Value::Refer(grp_uuid))
            );

            let ct = duration_from_epoch_now();
            let mut server_txn = idms.proxy_write(ct).await.unwrap();
            assert!(server_txn
                .qs_write
                .internal_create(vec![e1, e2, e3])
                .and_then(|_| server_txn.commit())
                .is_ok());
        }

        // Setup the anonymous login
        let anon_t = ldaps.do_bind(idms, "", "").await.unwrap().unwrap();
        assert_eq!(
            anon_t.effective_session,
            LdapSession::UnixBind(UUID_ANONYMOUS)
        );

        // Searches under application base DN must show same content
        let sr = SearchRequest {
            msgid: 1,
            base: format!("app={app_name},dc=example,dc=com"),
            scope: LdapSearchScope::Subtree,
            filter: LdapFilter::Present(Attribute::ObjectClass.to_string()),
            attrs: vec!["*".to_string()],
        };

        let r1 = ldaps
            .do_search(idms, &sr, &anon_t, Source::Internal)
            .await
            .unwrap();

        let sr = SearchRequest {
            msgid: 1,
            base: "dc=example,dc=com".to_string(),
            scope: LdapSearchScope::Subtree,
            filter: LdapFilter::Present(Attribute::ObjectClass.to_string()),
            attrs: vec!["*".to_string()],
        };

        let r2 = ldaps
            .do_search(idms, &sr, &anon_t, Source::Internal)
            .await
            .unwrap();
        assert!(!r1.is_empty());
        assert_eq!(r1.len(), r2.len());
    }

    #[idm_test]
    async fn test_ldap_spn_search(idms: &IdmServer, _idms_delayed: &IdmServerDelayed) {
        let ldaps = LdapServer::new(idms).await.expect("failed to start ldap");

        let usr_uuid = Uuid::new_v4();
        let usr_name = "panko";

        // Setup person, group and application
        {
            let e1: Entry<EntryInit, EntryNew> = entry_init!(
                (Attribute::Class, EntryClass::Object.to_value()),
                (Attribute::Class, EntryClass::Account.to_value()),
                (Attribute::Class, EntryClass::PosixAccount.to_value()),
                (Attribute::Class, EntryClass::Person.to_value()),
                (Attribute::Name, Value::new_iname(usr_name)),
                (Attribute::Uuid, Value::Uuid(usr_uuid)),
                (Attribute::DisplayName, Value::new_utf8s(usr_name))
            );

            let ct = duration_from_epoch_now();
            let mut server_txn = idms.proxy_write(ct).await.unwrap();

            // Add anonymous to the needed permission groups.
            server_txn
                .qs_write
                .internal_modify_uuid(
                    UUID_IDM_UNIX_AUTHENTICATION_READ,
                    &ModifyList::new_append(Attribute::Member, Value::Refer(UUID_ANONYMOUS)),
                )
                .expect("Unable to modify UNIX_AUTHENTICATION_READ group");

            assert!(server_txn
                .qs_write
                .internal_create(vec![e1])
                .and_then(|_| server_txn.commit())
                .is_ok());
        }

        // Setup the anonymous login
        let anon_t = ldaps.do_bind(idms, "", "").await.unwrap().unwrap();
        assert_eq!(
            anon_t.effective_session,
            LdapSession::UnixBind(UUID_ANONYMOUS)
        );

        // Searching a malformed spn shouldn't cause the query to fail
        let sr = SearchRequest {
            msgid: 1,
            base: "dc=example,dc=com".to_string(),
            scope: LdapSearchScope::Subtree,
            filter: LdapFilter::Or(vec![
                LdapFilter::Equality(Attribute::Name.to_string(), usr_name.to_string()),
                LdapFilter::Equality(Attribute::Spn.to_string(), usr_name.to_string()),
            ]),
            attrs: vec!["*".to_string()],
        };

        let result = ldaps
            .do_search(idms, &sr, &anon_t, Source::Internal)
            .await
            .map(|r| {
                r.into_iter()
                    .filter(|r| matches!(r.op, LdapOp::SearchResultEntry(_)))
                    .collect::<Vec<_>>()
            })
            .unwrap();

        assert!(!result.is_empty());

        let sr = SearchRequest {
            msgid: 1,
            base: "dc=example,dc=com".to_string(),
            scope: LdapSearchScope::Subtree,
            filter: LdapFilter::And(vec![
                LdapFilter::Equality(Attribute::Name.to_string(), usr_name.to_string()),
                LdapFilter::Equality(Attribute::Spn.to_string(), usr_name.to_string()),
            ]),
            attrs: vec!["*".to_string()],
        };

        let empty_result = ldaps
            .do_search(idms, &sr, &anon_t, Source::Internal)
            .await
            .map(|r| {
                r.into_iter()
                    .filter(|r| matches!(r.op, LdapOp::SearchResultEntry(_)))
                    .collect::<Vec<_>>()
            })
            .unwrap();

        assert!(empty_result.is_empty());
    }

    #[idm_test]
    async fn test_ldap_application_bind(idms: &IdmServer, _idms_delayed: &IdmServerDelayed) {
        let ldaps = LdapServer::new(idms).await.expect("failed to start ldap");

        let usr_uuid = Uuid::new_v4();
        let grp_uuid = Uuid::new_v4();
        let app_uuid = Uuid::new_v4();

        // Setup person, group and application
        {
            let e1 = entry_init!(
                (Attribute::Class, EntryClass::Object.to_value()),
                (Attribute::Class, EntryClass::Account.to_value()),
                (Attribute::Class, EntryClass::Person.to_value()),
                (Attribute::Name, Value::new_iname("testperson1")),
                (Attribute::Uuid, Value::Uuid(usr_uuid)),
                (Attribute::Description, Value::new_utf8s("testperson1")),
                (Attribute::DisplayName, Value::new_utf8s("testperson1"))
            );

            let e2 = entry_init!(
                (Attribute::Class, EntryClass::Object.to_value()),
                (Attribute::Class, EntryClass::Group.to_value()),
                (Attribute::Name, Value::new_iname("testgroup1")),
                (Attribute::Uuid, Value::Uuid(grp_uuid))
            );

            let e3 = entry_init!(
                (Attribute::Class, EntryClass::Object.to_value()),
                (Attribute::Class, EntryClass::Account.to_value()),
                (Attribute::Class, EntryClass::ServiceAccount.to_value()),
                (Attribute::Class, EntryClass::Application.to_value()),
                (Attribute::DisplayName, Value::new_utf8s("Application")),
                (Attribute::Name, Value::new_iname("testapp1")),
                (Attribute::Uuid, Value::Uuid(app_uuid)),
                (Attribute::LinkedGroup, Value::Refer(grp_uuid))
            );

            let ct = duration_from_epoch_now();
            let mut server_txn = idms.proxy_write(ct).await.unwrap();
            assert!(server_txn
                .qs_write
                .internal_create(vec![e1, e2, e3])
                .and_then(|_| server_txn.commit())
                .is_ok());
        }

        // No session, user not member of linked group
        let res = ldaps
            .do_bind(idms, "spn=testperson1,app=testapp1,dc=example,dc=com", "")
            .await;
        assert!(res.is_ok());
        assert!(res.unwrap().is_none());

        {
            let ml = ModifyList::new_append(Attribute::Member, Value::Refer(usr_uuid));
            let mut idms_prox_write = idms.proxy_write(duration_from_epoch_now()).await.unwrap();
            assert!(idms_prox_write
                .qs_write
                .internal_modify_uuid(grp_uuid, &ml)
                .is_ok());
            assert!(idms_prox_write.commit().is_ok());
        }

        // No session, user does not have app password for testapp1
        let res = ldaps
            .do_bind(idms, "spn=testperson1,app=testapp1,dc=example,dc=com", "")
            .await;
        assert!(res.is_ok());
        assert!(res.unwrap().is_none());

        let pass1: String;
        let pass2: String;
        let pass3: String;
        {
            let mut idms_prox_write = idms.proxy_write(duration_from_epoch_now()).await.unwrap();

            let ev = GenerateApplicationPasswordEvent::new_internal(
                usr_uuid,
                app_uuid,
                "apppwd1".to_string(),
            );
            (pass1, _) = idms_prox_write
                .generate_application_password(&ev)
                .expect("Failed to generate application password");

            let ev = GenerateApplicationPasswordEvent::new_internal(
                usr_uuid,
                app_uuid,
                "apppwd2".to_string(),
            );
            (pass2, _) = idms_prox_write
                .generate_application_password(&ev)
                .expect("Failed to generate application password");

            assert!(idms_prox_write.commit().is_ok());

            // Application password overwritten on duplicated label
            let mut idms_prox_write = idms.proxy_write(duration_from_epoch_now()).await.unwrap();
            let ev = GenerateApplicationPasswordEvent::new_internal(
                usr_uuid,
                app_uuid,
                "apppwd2".to_string(),
            );
            (pass3, _) = idms_prox_write
                .generate_application_password(&ev)
                .expect("Failed to generate application password");
            assert!(idms_prox_write.commit().is_ok());
        }

        // Got session, app password valid
        let res = ldaps
            .do_bind(
                idms,
                "spn=testperson1,app=testapp1,dc=example,dc=com",
                pass1.as_str(),
            )
            .await;
        assert!(res.is_ok());
        assert!(res.unwrap().is_some());

        // No session, app password overwritten
        let res = ldaps
            .do_bind(
                idms,
                "spn=testperson1,app=testapp1,dc=example,dc=com",
                pass2.as_str(),
            )
            .await;
        assert!(res.is_ok());
        assert!(res.unwrap().is_none());

        // Got session, app password overwritten
        let res = ldaps
            .do_bind(
                idms,
                "spn=testperson1,app=testapp1,dc=example,dc=com",
                pass3.as_str(),
            )
            .await;
        assert!(res.is_ok());
        assert!(res.unwrap().is_some());

        // No session, invalid app password
        let res = ldaps
            .do_bind(
                idms,
                "spn=testperson1,app=testapp1,dc=example,dc=com",
                "FOO",
            )
            .await;
        assert!(res.is_ok());
        assert!(res.unwrap().is_none());
    }

    #[idm_test]
    async fn test_ldap_application_linked_group(
        idms: &IdmServer,
        _idms_delayed: &IdmServerDelayed,
    ) {
        let ldaps = LdapServer::new(idms).await.expect("failed to start ldap");

        let usr_uuid = Uuid::new_v4();
        let usr_name = "testuser1";

        let grp1_uuid = Uuid::new_v4();
        let grp1_name = "testgroup1";
        let grp2_uuid = Uuid::new_v4();
        let grp2_name = "testgroup2";

        let app1_uuid = Uuid::new_v4();
        let app1_name = "testapp1";
        let app2_uuid = Uuid::new_v4();
        let app2_name = "testapp2";

        // Setup person, groups and applications
        {
            let e1 = entry_init!(
                (Attribute::Class, EntryClass::Object.to_value()),
                (Attribute::Class, EntryClass::Account.to_value()),
                (Attribute::Class, EntryClass::Person.to_value()),
                (Attribute::Name, Value::new_iname(usr_name)),
                (Attribute::Uuid, Value::Uuid(usr_uuid)),
                (Attribute::Description, Value::new_utf8s(usr_name)),
                (Attribute::DisplayName, Value::new_utf8s(usr_name))
            );

            let e2 = entry_init!(
                (Attribute::Class, EntryClass::Object.to_value()),
                (Attribute::Class, EntryClass::Group.to_value()),
                (Attribute::Name, Value::new_iname(grp1_name)),
                (Attribute::Uuid, Value::Uuid(grp1_uuid)),
                (Attribute::Member, Value::Refer(usr_uuid))
            );

            let e3 = entry_init!(
                (Attribute::Class, EntryClass::Object.to_value()),
                (Attribute::Class, EntryClass::Group.to_value()),
                (Attribute::Name, Value::new_iname(grp2_name)),
                (Attribute::Uuid, Value::Uuid(grp2_uuid))
            );

            let e4 = entry_init!(
                (Attribute::Class, EntryClass::Object.to_value()),
                (Attribute::Class, EntryClass::Account.to_value()),
                (Attribute::Class, EntryClass::ServiceAccount.to_value()),
                (Attribute::Class, EntryClass::Application.to_value()),
                (Attribute::DisplayName, Value::new_utf8s("Application")),
                (Attribute::Name, Value::new_iname(app1_name)),
                (Attribute::Uuid, Value::Uuid(app1_uuid)),
                (Attribute::LinkedGroup, Value::Refer(grp1_uuid))
            );

            let e5 = entry_init!(
                (Attribute::Class, EntryClass::Object.to_value()),
                (Attribute::Class, EntryClass::Account.to_value()),
                (Attribute::Class, EntryClass::ServiceAccount.to_value()),
                (Attribute::Class, EntryClass::Application.to_value()),
                (Attribute::DisplayName, Value::new_utf8s("Application")),
                (Attribute::Name, Value::new_iname(app2_name)),
                (Attribute::Uuid, Value::Uuid(app2_uuid)),
                (Attribute::LinkedGroup, Value::Refer(grp2_uuid))
            );

            let ct = duration_from_epoch_now();
            let mut server_txn = idms.proxy_write(ct).await.unwrap();
            assert!(server_txn
                .qs_write
                .internal_create(vec![e1, e2, e3, e4, e5])
                .and_then(|_| server_txn.commit())
                .is_ok());
        }

        let pass_app1: String;
        let pass_app2: String;
        {
            let mut idms_prox_write = idms.proxy_write(duration_from_epoch_now()).await.unwrap();

            let ev = GenerateApplicationPasswordEvent::new_internal(
                usr_uuid,
                app1_uuid,
                "label".to_string(),
            );
            (pass_app1, _) = idms_prox_write
                .generate_application_password(&ev)
                .expect("Failed to generate application password");

            // It is possible to generate an application password even if the
            // user is not member of the linked group
            let ev = GenerateApplicationPasswordEvent::new_internal(
                usr_uuid,
                app2_uuid,
                "label".to_string(),
            );
            (pass_app2, _) = idms_prox_write
                .generate_application_password(&ev)
                .expect("Failed to generate application password");

            assert!(idms_prox_write.commit().is_ok());
        }

        // Got session, app password valid
        let res = ldaps
            .do_bind(
                idms,
                format!("spn={usr_name},app={app1_name},dc=example,dc=com").as_str(),
                pass_app1.as_str(),
            )
            .await;
        assert!(res.is_ok());
        assert!(res.unwrap().is_some());

        // No session, not member
        let res = ldaps
            .do_bind(
                idms,
                format!("spn={usr_name},app={app2_name},dc=example,dc=com").as_str(),
                pass_app2.as_str(),
            )
            .await;
        assert!(res.is_ok());
        assert!(res.unwrap().is_none());

        // Add user to grp2
        {
            let ml = ModifyList::new_append(Attribute::Member, Value::Refer(usr_uuid));
            let mut idms_prox_write = idms.proxy_write(duration_from_epoch_now()).await.unwrap();
            assert!(idms_prox_write
                .qs_write
                .internal_modify_uuid(grp2_uuid, &ml)
                .is_ok());
            assert!(idms_prox_write.commit().is_ok());
        }

        // Got session, app password valid
        let res = ldaps
            .do_bind(
                idms,
                format!("spn={usr_name},app={app2_name},dc=example,dc=com").as_str(),
                pass_app2.as_str(),
            )
            .await;
        assert!(res.is_ok());
        assert!(res.unwrap().is_some());

        // No session, wrong app
        let res = ldaps
            .do_bind(
                idms,
                format!("spn={usr_name},app={app1_name},dc=example,dc=com").as_str(),
                pass_app2.as_str(),
            )
            .await;
        assert!(res.is_ok());
        assert!(res.unwrap().is_none());

        // Bind error, app not exists
        {
            let mut idms_prox_write = idms.proxy_write(duration_from_epoch_now()).await.unwrap();
            let de = DeleteEvent::new_internal_invalid(filter!(f_eq(
                Attribute::Uuid,
                PartialValue::Uuid(app2_uuid)
            )));
            assert!(idms_prox_write.qs_write.delete(&de).is_ok());
            assert!(idms_prox_write.commit().is_ok());
        }

        let res = ldaps
            .do_bind(
                idms,
                format!("spn={usr_name},app={app2_name},dc=example,dc=com").as_str(),
                pass_app2.as_str(),
            )
            .await;
        assert!(res.is_err());
    }

    // For testing the timeouts
    // We need times on this scale
    //    not yet valid <-> valid from time <-> current_time <-> expire time <-> expired
    const TEST_CURRENT_TIME: u64 = 6000;
    const TEST_NOT_YET_VALID_TIME: u64 = TEST_CURRENT_TIME - 240;
    const TEST_VALID_FROM_TIME: u64 = TEST_CURRENT_TIME - 120;
    const TEST_EXPIRE_TIME: u64 = TEST_CURRENT_TIME + 120;
    const TEST_AFTER_EXPIRY: u64 = TEST_CURRENT_TIME + 240;

    async fn set_account_valid_time(idms: &IdmServer, acct: Uuid) {
        let mut idms_write = idms.proxy_write(duration_from_epoch_now()).await.unwrap();

        let v_valid_from = Value::new_datetime_epoch(Duration::from_secs(TEST_VALID_FROM_TIME));
        let v_expire = Value::new_datetime_epoch(Duration::from_secs(TEST_EXPIRE_TIME));

        let me = ModifyEvent::new_internal_invalid(
            filter!(f_eq(Attribute::Uuid, PartialValue::Uuid(acct))),
            ModifyList::new_list(vec![
                Modify::Present(Attribute::AccountExpire, v_expire),
                Modify::Present(Attribute::AccountValidFrom, v_valid_from),
            ]),
        );
        assert!(idms_write.qs_write.modify(&me).is_ok());
        idms_write.commit().expect("Must not fail");
    }

    #[idm_test]
    async fn test_ldap_application_valid_from_expire(
        idms: &IdmServer,
        _idms_delayed: &IdmServerDelayed,
    ) {
        let ldaps = LdapServer::new(idms).await.expect("failed to start ldap");

        let usr_uuid = Uuid::new_v4();
        let usr_name = "testuser1";

        let grp1_uuid = Uuid::new_v4();
        let grp1_name = "testgroup1";

        let app1_uuid = Uuid::new_v4();
        let app1_name = "testapp1";

        let pass_app1: String;

        // Setup person, group, application and app password
        {
            let e1 = entry_init!(
                (Attribute::Class, EntryClass::Object.to_value()),
                (Attribute::Class, EntryClass::Account.to_value()),
                (Attribute::Class, EntryClass::Person.to_value()),
                (Attribute::Name, Value::new_iname(usr_name)),
                (Attribute::Uuid, Value::Uuid(usr_uuid)),
                (Attribute::Description, Value::new_utf8s(usr_name)),
                (Attribute::DisplayName, Value::new_utf8s(usr_name))
            );

            let e2 = entry_init!(
                (Attribute::Class, EntryClass::Object.to_value()),
                (Attribute::Class, EntryClass::Group.to_value()),
                (Attribute::Name, Value::new_iname(grp1_name)),
                (Attribute::Uuid, Value::Uuid(grp1_uuid)),
                (Attribute::Member, Value::Refer(usr_uuid))
            );

            let e3 = entry_init!(
                (Attribute::Class, EntryClass::Object.to_value()),
                (Attribute::Class, EntryClass::Account.to_value()),
                (Attribute::Class, EntryClass::ServiceAccount.to_value()),
                (Attribute::Class, EntryClass::Application.to_value()),
                (Attribute::DisplayName, Value::new_utf8s("Application")),
                (Attribute::Name, Value::new_iname(app1_name)),
                (Attribute::Uuid, Value::Uuid(app1_uuid)),
                (Attribute::LinkedGroup, Value::Refer(grp1_uuid))
            );

            let ct = duration_from_epoch_now();
            let mut server_txn = idms.proxy_write(ct).await.unwrap();
            assert!(server_txn
                .qs_write
                .internal_create(vec![e1, e2, e3])
                .and_then(|_| server_txn.commit())
                .is_ok());

            let mut idms_prox_write = idms.proxy_write(duration_from_epoch_now()).await.unwrap();

            let ev = GenerateApplicationPasswordEvent::new_internal(
                usr_uuid,
                app1_uuid,
                "label".to_string(),
            );
            (pass_app1, _) = idms_prox_write
                .generate_application_password(&ev)
                .expect("Failed to generate application password");

            assert!(idms_prox_write.commit().is_ok());
        }

        // Got session, app password valid
        let res = ldaps
            .do_bind(
                idms,
                format!("spn={usr_name},app={app1_name},dc=example,dc=com").as_str(),
                pass_app1.as_str(),
            )
            .await;
        assert!(res.is_ok());
        assert!(res.unwrap().is_some());

        // Any account that is not yet valid / expired can't auth.
        // Set the valid bounds high/low
        // TEST_VALID_FROM_TIME/TEST_EXPIRE_TIME
        set_account_valid_time(idms, usr_uuid).await;

        let time_low = Duration::from_secs(TEST_NOT_YET_VALID_TIME);
        let time = Duration::from_secs(TEST_CURRENT_TIME);
        let time_high = Duration::from_secs(TEST_AFTER_EXPIRY);

        let mut idms_auth = idms.auth().await.unwrap();
        let lae = LdapApplicationAuthEvent::new(app1_name, usr_uuid, pass_app1)
            .expect("Failed to build auth event");

        let r1 = idms_auth
            .application_auth_ldap(&lae, time_low)
            .await
            .expect_err("Authentication succeeded");
        assert_eq!(r1, OperationError::SessionExpired);

        let r1 = idms_auth
            .application_auth_ldap(&lae, time)
            .await
            .expect("Failed auth");
        assert!(r1.is_some());

        let r1 = idms_auth
            .application_auth_ldap(&lae, time_high)
            .await
            .expect_err("Authentication succeeded");
        assert_eq!(r1, OperationError::SessionExpired);
    }

    macro_rules! assert_entry_contains {
        (
            $entry:expr,
            $dn:expr,
            $($item:expr),*
        ) => {{
            assert_eq!($entry.dn, $dn);
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
                (Attribute::GidNumber, Value::new_uint32(12345)),
                (Attribute::LoginShell, Value::new_iutf8("/bin/zsh")),
                (
                    Attribute::SshPublicKey,
                    Value::new_sshkey_str("test", ssh_ed25519).expect("Invalid ssh key")
                )
            );

            let mut server_txn = idms.proxy_write(duration_from_epoch_now()).await.unwrap();

            // Add anonymous to the needed permission groups.
            server_txn
                .qs_write
                .internal_modify_uuid(
                    UUID_IDM_UNIX_AUTHENTICATION_READ,
                    &ModifyList::new_append(Attribute::Member, Value::Refer(UUID_ANONYMOUS)),
                )
                .expect("Unable to modify UNIX_AUTHENTICATION_READ group");

            let ce = CreateEvent::new_internal(vec![e1]);
            assert!(server_txn
                .qs_write
                .create(&ce)
                .and_then(|_| server_txn.commit())
                .is_ok());
        }

        // Setup the anonymous login.
        let anon_t = ldaps.do_bind(idms, "", "").await.unwrap().unwrap();
        assert_eq!(
            anon_t.effective_session,
            LdapSession::UnixBind(UUID_ANONYMOUS)
        );

        // Check that when we request *, we get default list.
        let sr = SearchRequest {
            msgid: 1,
            base: "dc=example,dc=com".to_string(),
            scope: LdapSearchScope::Subtree,
            filter: LdapFilter::Equality(Attribute::Name.to_string(), "testperson1".to_string()),
            attrs: vec!["*".to_string()],
        };
        let r1 = ldaps
            .do_search(idms, &sr, &anon_t, Source::Internal)
            .await
            .unwrap();

        // The result, and the ldap proto success msg.
        assert_eq!(r1.len(), 2);
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
                    (Attribute::GidNumber, "12345"),
                    (Attribute::LoginShell, "/bin/zsh"),
                    (Attribute::SshPublicKey, ssh_ed25519),
                    (Attribute::Uuid, "cc8e95b4-c24f-4d68-ba54-8bed76f63930")
                );
            }
            _ => panic!("Oh no"),
        };

        // Check that when we request +, we get all attrs and the vattrs
        let sr = SearchRequest {
            msgid: 1,
            base: "dc=example,dc=com".to_string(),
            scope: LdapSearchScope::Subtree,
            filter: LdapFilter::Equality(Attribute::Name.to_string(), "testperson1".to_string()),
            attrs: vec!["+".to_string()],
        };
        let r1 = ldaps
            .do_search(idms, &sr, &anon_t, Source::Internal)
            .await
            .unwrap();

        // The result, and the ldap proto success msg.
        assert_eq!(r1.len(), 2);
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
                    (Attribute::GidNumber, "12345"),
                    (Attribute::LoginShell, "/bin/zsh"),
                    (Attribute::SshPublicKey, ssh_ed25519),
                    (Attribute::EntryUuid, "cc8e95b4-c24f-4d68-ba54-8bed76f63930"),
                    (
                        Attribute::HomeDirectory,
                        "/home/cc8e95b4-c24f-4d68-ba54-8bed76f63930"
                    ),
                    (
                        Attribute::EntryDn,
                        "spn=testperson1@example.com,dc=example,dc=com"
                    ),
                    (Attribute::UidNumber, "12345"),
                    (Attribute::Cn, "testperson1"),
                    (Attribute::LdapKeys, ssh_ed25519)
                );
            }
            _ => panic!("Oh no"),
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
        let r1 = ldaps
            .do_search(idms, &sr, &anon_t, Source::Internal)
            .await
            .unwrap();

        // The result, and the ldap proto success msg.
        assert_eq!(r1.len(), 2);
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
                    (Attribute::UidNumber, "12345"),
                    (Attribute::LdapKeys, ssh_ed25519)
                );
            }
            _ => panic!("Oh no"),
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
                (Attribute::GidNumber, Value::new_uint32(12345)),
                (Attribute::LoginShell, Value::new_iutf8("/bin/zsh"))
            );

            let ct = duration_from_epoch_now();

            let mut server_txn = idms.proxy_write(ct).await.unwrap();

            let ce = CreateEvent::new_internal(vec![e1, e2]);
            assert!(server_txn.qs_write.create(&ce).is_ok());

            // Setup an access control for the service account to view mail attrs.
            server_txn
                .qs_write
                .internal_modify_uuid(
                    UUID_IDM_ACCOUNT_MAIL_READ,
                    &ModifyList::new_append(Attribute::Member, Value::Refer(sa_uuid)),
                )
                .expect("Unable to modify UNIX_AUTHENTICATION_READ group");

            // Allow anonymous to read basic posix attrs.
            server_txn
                .qs_write
                .internal_modify_uuid(
                    UUID_IDM_UNIX_AUTHENTICATION_READ,
                    &ModifyList::new_append(Attribute::Member, Value::Refer(UUID_ANONYMOUS)),
                )
                .expect("Unable to modify UNIX_AUTHENTICATION_READ group");

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
        assert_eq!(
            anon_lbt.effective_session,
            LdapSession::UnixBind(UUID_ANONYMOUS)
        );

        let r1 = ldaps
            .do_search(idms, &sr, &anon_lbt, Source::Internal)
            .await
            .unwrap();
        assert_eq!(r1.len(), 2);
        match &r1[0].op {
            LdapOp::SearchResultEntry(lsre) => {
                assert_entry_contains!(
                    lsre,
                    "spn=testperson1@example.com,dc=example,dc=com",
                    (Attribute::Name, "testperson1")
                );
            }
            _ => panic!("Oh no"),
        };

        // Inspect the token to get its uuid out.
        let jws_verifier = JwsDangerReleaseWithoutVerify::default();

        let apitoken_inner = jws_verifier
            .verify(&apitoken)
            .unwrap()
            .from_json::<ApiToken>()
            .unwrap();

        // Bind using the token as a DN
        let sa_lbt = ldaps
            .do_bind(idms, "dn=token", &apitoken.to_string())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            sa_lbt.effective_session,
            LdapSession::ApiToken(apitoken_inner.clone())
        );

        // Bind using the token as a pw
        let sa_lbt = ldaps
            .do_bind(idms, "", &apitoken.to_string())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            sa_lbt.effective_session,
            LdapSession::ApiToken(apitoken_inner)
        );

        // Search and retrieve mail that's now accessible.
        let r1 = ldaps
            .do_search(idms, &sr, &sa_lbt, Source::Internal)
            .await
            .unwrap();
        assert_eq!(r1.len(), 2);
        match &r1[0].op {
            LdapOp::SearchResultEntry(lsre) => {
                assert_entry_contains!(
                    lsre,
                    "spn=testperson1@example.com,dc=example,dc=com",
                    (Attribute::Name, "testperson1"),
                    (Attribute::Mail, "testperson1@example.com"),
                    (Attribute::Mail, "testperson1.alternative@example.com"),
                    (LDAP_ATTR_MAIL_PRIMARY, "testperson1@example.com"),
                    (
                        LDAP_ATTR_MAIL_ALTERNATIVE,
                        "testperson1.alternative@example.com"
                    ),
                    (LDAP_ATTR_EMAIL_PRIMARY, "testperson1@example.com"),
                    (
                        LDAP_ATTR_EMAIL_ALTERNATIVE,
                        "testperson1.alternative@example.com"
                    )
                );
            }
            _ => panic!("Oh no"),
        };

        // ======= test with a substring search

        let sr = SearchRequest {
            msgid: 2,
            base: "dc=example,dc=com".to_string(),
            scope: LdapSearchScope::Subtree,
            filter: LdapFilter::And(vec![
                LdapFilter::Equality(Attribute::Class.to_string(), "posixAccount".to_string()),
                LdapFilter::Substring(
                    LDAP_ATTR_MAIL.to_string(),
                    LdapSubstringFilter {
                        initial: None,
                        any: vec![],
                        final_: Some("@example.com".to_string()),
                    },
                ),
            ]),
            attrs: vec![
                LDAP_ATTR_NAME,
                LDAP_ATTR_MAIL,
                LDAP_ATTR_MAIL_PRIMARY,
                LDAP_ATTR_MAIL_ALTERNATIVE,
            ]
            .into_iter()
            .map(|s| s.to_string())
            .collect(),
        };

        let r1 = ldaps
            .do_search(idms, &sr, &sa_lbt, Source::Internal)
            .await
            .unwrap();

        assert_eq!(r1.len(), 2);
        match &r1[0].op {
            LdapOp::SearchResultEntry(lsre) => {
                assert_entry_contains!(
                    lsre,
                    "spn=testperson1@example.com,dc=example,dc=com",
                    (Attribute::Name, "testperson1"),
                    (Attribute::Mail, "testperson1@example.com"),
                    (Attribute::Mail, "testperson1.alternative@example.com"),
                    (LDAP_ATTR_MAIL_PRIMARY, "testperson1@example.com"),
                    (
                        LDAP_ATTR_MAIL_ALTERNATIVE,
                        "testperson1.alternative@example.com"
                    )
                );
            }
            _ => panic!("Oh no"),
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
                (Attribute::Class, EntryClass::PosixAccount.to_value()),
                (Attribute::Name, Value::new_iname("testperson1")),
                (Attribute::Uuid, Value::Uuid(acct_uuid)),
                (Attribute::Description, Value::new_utf8s("testperson1")),
                (Attribute::DisplayName, Value::new_utf8s("testperson1"))
            );

            let mut server_txn = idms.proxy_write(duration_from_epoch_now()).await.unwrap();

            // Add anonymous to the needed permission groups.
            server_txn
                .qs_write
                .internal_modify_uuid(
                    UUID_IDM_UNIX_AUTHENTICATION_READ,
                    &ModifyList::new_append(Attribute::Member, Value::Refer(UUID_ANONYMOUS)),
                )
                .expect("Unable to modify UNIX_AUTHENTICATION_READ group");

            assert!(server_txn
                .qs_write
                .internal_create(vec![e1])
                .and_then(|_| server_txn.commit())
                .is_ok());
        }

        // Setup the anonymous login.
        let anon_t = ldaps.do_bind(idms, "", "").await.unwrap().unwrap();
        assert_eq!(
            anon_t.effective_session,
            LdapSession::UnixBind(UUID_ANONYMOUS)
        );

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
        let r1 = ldaps
            .do_search(idms, &sr, &anon_t, Source::Internal)
            .await
            .unwrap();

        // The result, and the ldap proto success msg.
        assert_eq!(r1.len(), 2);
        match &r1[0].op {
            LdapOp::SearchResultEntry(lsre) => {
                assert_entry_contains!(
                    lsre,
                    "spn=testperson1@example.com,dc=example,dc=com",
                    (Attribute::Name, "testperson1"),
                    (Attribute::DisplayName, "testperson1"),
                    (Attribute::Uuid, "cc8e95b4-c24f-4d68-ba54-8bed76f63930"),
                    (Attribute::EntryUuid, "cc8e95b4-c24f-4d68-ba54-8bed76f63930")
                );
            }
            _ => panic!("Oh no"),
        };
    }

    // Test behaviour of the 1.1 attribute.
    #[idm_test]
    async fn test_ldap_one_dot_one_attribute(idms: &IdmServer, _idms_delayed: &IdmServerDelayed) {
        let ldaps = LdapServer::new(idms).await.expect("failed to start ldap");

        let acct_uuid = uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930");

        // Setup a user we want to check.
        {
            let e1 = entry_init!(
                (Attribute::Class, EntryClass::Person.to_value()),
                (Attribute::Class, EntryClass::Account.to_value()),
                (Attribute::Class, EntryClass::PosixAccount.to_value()),
                (Attribute::Name, Value::new_iname("testperson1")),
                (Attribute::Uuid, Value::Uuid(acct_uuid)),
                (Attribute::Description, Value::new_utf8s("testperson1")),
                (Attribute::DisplayName, Value::new_utf8s("testperson1"))
            );

            let mut server_txn = idms.proxy_write(duration_from_epoch_now()).await.unwrap();

            // Add anonymous to the needed permission groups.
            server_txn
                .qs_write
                .internal_modify_uuid(
                    UUID_IDM_UNIX_AUTHENTICATION_READ,
                    &ModifyList::new_append(Attribute::Member, Value::Refer(UUID_ANONYMOUS)),
                )
                .expect("Unable to modify UNIX_AUTHENTICATION_READ group");

            assert!(server_txn
                .qs_write
                .internal_create(vec![e1])
                .and_then(|_| server_txn.commit())
                .is_ok());
        }

        // Setup the anonymous login.
        let anon_t = ldaps.do_bind(idms, "", "").await.unwrap().unwrap();
        assert_eq!(
            anon_t.effective_session,
            LdapSession::UnixBind(UUID_ANONYMOUS)
        );

        // If we request only 1.1, we get no attributes.
        let sr = SearchRequest {
            msgid: 1,
            base: "dc=example,dc=com".to_string(),
            scope: LdapSearchScope::Subtree,
            filter: LdapFilter::Equality(Attribute::Name.to_string(), "testperson1".to_string()),
            attrs: vec!["1.1".to_string()],
        };
        let r1 = ldaps
            .do_search(idms, &sr, &anon_t, Source::Internal)
            .await
            .unwrap();

        // The result, and the ldap proto success msg.
        assert_eq!(r1.len(), 2);
        match &r1[0].op {
            LdapOp::SearchResultEntry(lsre) => {
                assert_eq!(
                    lsre.dn.as_str(),
                    "spn=testperson1@example.com,dc=example,dc=com"
                );
                assert!(lsre.attributes.is_empty());
            }
            _ => panic!("Oh no"),
        };

        // If we request 1.1 and another attr, 1.1 is IGNORED.
        let sr = SearchRequest {
            msgid: 1,
            base: "dc=example,dc=com".to_string(),
            scope: LdapSearchScope::Subtree,
            filter: LdapFilter::Equality(Attribute::Name.to_string(), "testperson1".to_string()),
            attrs: vec![
                "1.1".to_string(),
                // This should be present.
                Attribute::EntryUuid.to_string(),
            ],
        };
        let r1 = ldaps
            .do_search(idms, &sr, &anon_t, Source::Internal)
            .await
            .unwrap();

        // The result, and the ldap proto success msg.
        assert_eq!(r1.len(), 2);
        match &r1[0].op {
            LdapOp::SearchResultEntry(lsre) => {
                assert_entry_contains!(
                    lsre,
                    "spn=testperson1@example.com,dc=example,dc=com",
                    (Attribute::EntryUuid, "cc8e95b4-c24f-4d68-ba54-8bed76f63930")
                );
            }
            _ => panic!("Oh no"),
        };
    }

    #[idm_test]
    async fn test_ldap_rootdse_basedn_change(idms: &IdmServer, _idms_delayed: &IdmServerDelayed) {
        let ldaps = LdapServer::new(idms).await.expect("failed to start ldap");

        let anon_t = ldaps.do_bind(idms, "", "").await.unwrap().unwrap();
        assert_eq!(
            anon_t.effective_session,
            LdapSession::UnixBind(UUID_ANONYMOUS)
        );

        let sr = SearchRequest {
            msgid: 1,
            base: "".to_string(),
            scope: LdapSearchScope::Base,
            filter: LdapFilter::Present(Attribute::ObjectClass.to_string()),
            attrs: vec!["*".to_string()],
        };
        let r1 = ldaps
            .do_search(idms, &sr, &anon_t, Source::Internal)
            .await
            .unwrap();

        trace!(?r1);

        // The result, and the ldap proto success msg.
        assert_eq!(r1.len(), 2);
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
            _ => panic!("Oh no"),
        };

        drop(ldaps);

        // Change the domain basedn

        let mut idms_prox_write = idms.proxy_write(duration_from_epoch_now()).await.unwrap();
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
        assert_eq!(
            anon_t.effective_session,
            LdapSession::UnixBind(UUID_ANONYMOUS)
        );

        let sr = SearchRequest {
            msgid: 1,
            base: "".to_string(),
            scope: LdapSearchScope::Base,
            filter: LdapFilter::Present(Attribute::ObjectClass.to_string()),
            attrs: vec!["*".to_string()],
        };
        let r1 = ldaps
            .do_search(idms, &sr, &anon_t, Source::Internal)
            .await
            .unwrap();

        trace!(?r1);

        // The result, and the ldap proto success msg.
        assert_eq!(r1.len(), 2);
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
            _ => panic!("Oh no"),
        };
    }

    #[idm_test]
    async fn test_ldap_sssd_compat(idms: &IdmServer, _idms_delayed: &IdmServerDelayed) {
        let ldaps = LdapServer::new(idms).await.expect("failed to start ldap");

        let acct_uuid = uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930");

        // Setup a user we want to check.
        {
            let e1 = entry_init!(
                (Attribute::Class, EntryClass::Person.to_value()),
                (Attribute::Class, EntryClass::Account.to_value()),
                (Attribute::Class, EntryClass::PosixAccount.to_value()),
                (Attribute::Name, Value::new_iname("testperson1")),
                (Attribute::Uuid, Value::Uuid(acct_uuid)),
                (Attribute::GidNumber, Value::Uint32(12345)),
                (Attribute::Description, Value::new_utf8s("testperson1")),
                (Attribute::DisplayName, Value::new_utf8s("testperson1"))
            );

            let mut server_txn = idms.proxy_write(duration_from_epoch_now()).await.unwrap();

            // Add anonymous to the needed permission groups.
            server_txn
                .qs_write
                .internal_modify_uuid(
                    UUID_IDM_UNIX_AUTHENTICATION_READ,
                    &ModifyList::new_append(Attribute::Member, Value::Refer(UUID_ANONYMOUS)),
                )
                .expect("Unable to modify UNIX_AUTHENTICATION_READ group");

            assert!(server_txn
                .qs_write
                .internal_create(vec![e1])
                .and_then(|_| server_txn.commit())
                .is_ok());
        }

        // Setup the anonymous login.
        let anon_t = ldaps.do_bind(idms, "", "").await.unwrap().unwrap();
        assert_eq!(
            anon_t.effective_session,
            LdapSession::UnixBind(UUID_ANONYMOUS)
        );

        // SSSD tries to just search for silly attrs all the time. We ignore them.
        let sr = SearchRequest {
            msgid: 1,
            base: "dc=example,dc=com".to_string(),
            scope: LdapSearchScope::Subtree,
            filter: LdapFilter::And(vec![
                LdapFilter::Equality(Attribute::Class.to_string(), "sudohost".to_string()),
                LdapFilter::Substring(
                    Attribute::SudoHost.to_string(),
                    LdapSubstringFilter {
                        initial: Some("a".to_string()),
                        any: vec!["x".to_string()],
                        final_: Some("z".to_string()),
                    },
                ),
            ]),
            attrs: vec![
                "*".to_string(),
                // Already being returned
                LDAP_ATTR_NAME.to_string(),
                // This is a virtual attribute
                Attribute::EntryUuid.to_string(),
            ],
        };
        let r1 = ldaps
            .do_search(idms, &sr, &anon_t, Source::Internal)
            .await
            .unwrap();

        // Empty results and ldap proto success msg.
        assert_eq!(r1.len(), 1);

        // Second search

        let sr = SearchRequest {
            msgid: 1,
            base: "dc=example,dc=com".to_string(),
            scope: LdapSearchScope::Subtree,
            filter: LdapFilter::Equality(Attribute::Name.to_string(), "testperson1".to_string()),
            attrs: vec![
                "uid".to_string(),
                "uidNumber".to_string(),
                "gidNumber".to_string(),
                "gecos".to_string(),
                "cn".to_string(),
                "entryuuid".to_string(),
            ],
        };
        let r1 = ldaps
            .do_search(idms, &sr, &anon_t, Source::Internal)
            .await
            .unwrap();

        trace!(?r1);

        // The result, and the ldap proto success msg.
        assert_eq!(r1.len(), 2);
        match &r1[0].op {
            LdapOp::SearchResultEntry(lsre) => {
                assert_entry_contains!(
                    lsre,
                    "spn=testperson1@example.com,dc=example,dc=com",
                    (Attribute::Uid, "testperson1"),
                    (Attribute::Cn, "testperson1"),
                    (Attribute::Gecos, "testperson1"),
                    (Attribute::UidNumber, "12345"),
                    (Attribute::GidNumber, "12345"),
                    (Attribute::EntryUuid, "cc8e95b4-c24f-4d68-ba54-8bed76f63930")
                );
            }
            _ => panic!("Oh no"),
        };
    }

    #[idm_test]
    async fn test_ldap_compare_request(idms: &IdmServer, _idms_delayed: &IdmServerDelayed) {
        let ldaps = LdapServer::new(idms).await.expect("failed to start ldap");

        // Setup a user we want to check.
        {
            let acct_uuid = uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930");

            let e1 = entry_init!(
                (Attribute::Class, EntryClass::Person.to_value()),
                (Attribute::Class, EntryClass::Account.to_value()),
                (Attribute::Class, EntryClass::PosixAccount.to_value()),
                (Attribute::Name, Value::new_iname("testperson1")),
                (Attribute::Uuid, Value::Uuid(acct_uuid)),
                (Attribute::GidNumber, Value::Uint32(12345)),
                (Attribute::Description, Value::new_utf8s("testperson1")),
                (Attribute::DisplayName, Value::new_utf8s("testperson1"))
            );

            let mut server_txn = idms.proxy_write(duration_from_epoch_now()).await.unwrap();

            // Add anonymous to the needed permission groups.
            server_txn
                .qs_write
                .internal_modify_uuid(
                    UUID_IDM_UNIX_AUTHENTICATION_READ,
                    &ModifyList::new_append(Attribute::Member, Value::Refer(UUID_ANONYMOUS)),
                )
                .expect("Unable to modify UNIX_AUTHENTICATION_READ group");

            assert!(server_txn
                .qs_write
                .internal_create(vec![e1])
                .and_then(|_| server_txn.commit())
                .is_ok());
        }

        // Setup the anonymous login.
        let anon_t = ldaps.do_bind(idms, "", "").await.unwrap().unwrap();
        assert_eq!(
            anon_t.effective_session,
            LdapSession::UnixBind(UUID_ANONYMOUS)
        );

        #[track_caller]
        fn assert_compare_result(r: &[LdapMsg], code: &LdapResultCode) {
            assert_eq!(r.len(), 1);
            match &r[0].op {
                LdapOp::CompareResult(lcr) => {
                    assert_eq!(&lcr.code, code);
                }
                _ => panic!("Oh no"),
            };
        }

        let cr = CompareRequest {
            msgid: 1,
            entry: "name=testperson1,dc=example,dc=com".to_string(),
            atype: Attribute::Name.to_string(),
            val: "testperson1".to_string(),
        };

        assert_compare_result(
            &ldaps
                .do_compare(idms, &cr, &anon_t, Source::Internal)
                .await
                .unwrap(),
            &LdapResultCode::CompareTrue,
        );

        let cr = CompareRequest {
            msgid: 1,
            entry: "name=testperson1,dc=example,dc=com".to_string(),
            atype: Attribute::GidNumber.to_string(),
            val: "12345".to_string(),
        };

        assert_compare_result(
            &ldaps
                .do_compare(idms, &cr, &anon_t, Source::Internal)
                .await
                .unwrap(),
            &LdapResultCode::CompareTrue,
        );

        let cr = CompareRequest {
            msgid: 1,
            entry: "name=testperson1,dc=example,dc=com".to_string(),
            atype: Attribute::Name.to_string(),
            val: "other".to_string(),
        };
        assert_compare_result(
            &ldaps
                .do_compare(idms, &cr, &anon_t, Source::Internal)
                .await
                .unwrap(),
            &LdapResultCode::CompareFalse,
        );

        let cr = CompareRequest {
            msgid: 1,
            entry: "name=other,dc=example,dc=com".to_string(),
            atype: Attribute::Name.to_string(),
            val: "other".to_string(),
        };
        assert_compare_result(
            &ldaps
                .do_compare(idms, &cr, &anon_t, Source::Internal)
                .await
                .unwrap(),
            &LdapResultCode::NoSuchObject,
        );

        let cr = CompareRequest {
            msgid: 1,
            entry: "invalidentry".to_string(),
            atype: Attribute::Name.to_string(),
            val: "other".to_string(),
        };
        assert!(&ldaps
            .do_compare(idms, &cr, &anon_t, Source::Internal)
            .await
            .is_err());

        let cr = CompareRequest {
            msgid: 1,
            entry: "name=other,dc=example,dc=com".to_string(),
            atype: "invalid".to_string(),
            val: "other".to_string(),
        };
        assert_eq!(
            &ldaps
                .do_compare(idms, &cr, &anon_t, Source::Internal)
                .await
                .unwrap_err(),
            &OperationError::InvalidAttributeName("invalid".to_string()),
        );
    }

    #[idm_test]
    async fn test_ldap_maximum_queryable_attributes(
        idms: &IdmServer,
        _idms_delayed: &IdmServerDelayed,
    ) {
        // Set the max queryable attrs to 2

        let mut server_txn = idms.proxy_write(duration_from_epoch_now()).await.unwrap();

        let set_ldap_maximum_queryable_attrs = ModifyEvent::new_internal_invalid(
            filter!(f_eq(Attribute::Uuid, PartialValue::Uuid(UUID_DOMAIN_INFO))),
            ModifyList::new_purge_and_set(Attribute::LdapMaxQueryableAttrs, Value::Uint32(2)),
        );
        assert!(server_txn
            .qs_write
            .modify(&set_ldap_maximum_queryable_attrs)
            .and_then(|_| server_txn.commit())
            .is_ok());

        let ldaps = LdapServer::new(idms).await.expect("failed to start ldap");

        let usr_uuid = Uuid::new_v4();
        let grp_uuid = Uuid::new_v4();
        let app_uuid = Uuid::new_v4();
        let app_name = "testapp1";

        // Setup person, group and application
        {
            let e1 = entry_init!(
                (Attribute::Class, EntryClass::Object.to_value()),
                (Attribute::Class, EntryClass::Account.to_value()),
                (Attribute::Class, EntryClass::Person.to_value()),
                (Attribute::Name, Value::new_iname("testperson1")),
                (Attribute::Uuid, Value::Uuid(usr_uuid)),
                (Attribute::Description, Value::new_utf8s("testperson1")),
                (Attribute::DisplayName, Value::new_utf8s("testperson1"))
            );

            let e2 = entry_init!(
                (Attribute::Class, EntryClass::Object.to_value()),
                (Attribute::Class, EntryClass::Group.to_value()),
                (Attribute::Name, Value::new_iname("testgroup1")),
                (Attribute::Uuid, Value::Uuid(grp_uuid))
            );

            let e3 = entry_init!(
                (Attribute::Class, EntryClass::Object.to_value()),
                (Attribute::Class, EntryClass::Account.to_value()),
                (Attribute::Class, EntryClass::ServiceAccount.to_value()),
                (Attribute::Class, EntryClass::Application.to_value()),
                (Attribute::DisplayName, Value::new_utf8s("Application")),
                (Attribute::Name, Value::new_iname(app_name)),
                (Attribute::Uuid, Value::Uuid(app_uuid)),
                (Attribute::LinkedGroup, Value::Refer(grp_uuid))
            );

            let ct = duration_from_epoch_now();
            let mut server_txn = idms.proxy_write(ct).await.unwrap();
            assert!(server_txn
                .qs_write
                .internal_create(vec![e1, e2, e3])
                .and_then(|_| server_txn.commit())
                .is_ok());
        }

        // Setup the anonymous login
        let anon_t = ldaps.do_bind(idms, "", "").await.unwrap().unwrap();
        assert_eq!(
            anon_t.effective_session,
            LdapSession::UnixBind(UUID_ANONYMOUS)
        );

        let invalid_search = SearchRequest {
            msgid: 1,
            base: "dc=example,dc=com".to_string(),
            scope: LdapSearchScope::Subtree,
            filter: LdapFilter::Present(Attribute::ObjectClass.to_string()),
            attrs: vec![
                "objectClass".to_string(),
                "cn".to_string(),
                "givenName".to_string(),
            ],
        };

        let valid_search = SearchRequest {
            msgid: 1,
            base: "dc=example,dc=com".to_string(),
            scope: LdapSearchScope::Subtree,
            filter: LdapFilter::Present(Attribute::ObjectClass.to_string()),
            attrs: vec!["objectClass: person".to_string()],
        };

        let invalid_res: Result<Vec<LdapMsg>, OperationError> = ldaps
            .do_search(idms, &invalid_search, &anon_t, Source::Internal)
            .await;

        let valid_res: Result<Vec<LdapMsg>, OperationError> = ldaps
            .do_search(idms, &valid_search, &anon_t, Source::Internal)
            .await;

        assert_eq!(invalid_res, Err(OperationError::ResourceLimit));
        assert!(valid_res.is_ok());
    }
}
