use super::{
    proto::{
        ReplEntryV1, ReplIncrementalContext, ReplIncrementalEntryV1, ReplRefreshContext,
        ReplRuvRange,
    },
    ruv::{RangeDiffStatus, ReplicationUpdateVector, ReplicationUpdateVectorTransaction},
};
use crate::{
    be::{
        keystorage::{KeyHandle, KeyHandleId},
        BackendTransaction,
    },
    prelude::*,
};
use crypto_glue::{
    der::SecretDocument,
    ecdsa_p256::{self, EcdsaP256DerSignature, EcdsaP256SigningKey, EcdsaP256VerifyingKey},
    traits::Pkcs8EncodePrivateKey,
    x509::{
        self, profile::cabf::tls::*, Builder, Certificate, CertificateBuilder, GeneralName,
        GeneralizedTime, Ia5String, OctetString, SubjectAltName, SubjectPublicKeyInfoOwned,
        Validity,
    },
};
use rustls::pki_types::{IpAddr, ServerName};
use std::str::FromStr;

impl QueryServerWriteTransaction<'_> {
    fn supplier_generate_key_cert(
        &mut self,
        domain_name: &str,
    ) -> Result<(SecretDocument, Certificate), OperationError> {
        // Invalid, must need to re-generate.
        let s_uuid = self.get_server_uuid();

        let private_key = ecdsa_p256::new_key();
        let signing_key = EcdsaP256SigningKey::from(&private_key);
        let verifying_key = EcdsaP256VerifyingKey::from(&signing_key);

        let pub_key = SubjectPublicKeyInfoOwned::from_key(&verifying_key).map_err(|err| {
            error!(?err, "Unable to create public key from private key");
            OperationError::CryptographyError
        })?;

        let not_before = GeneralizedTime::from_unix_duration(self.get_curtime())
            .map(x509::Time::from)
            .map_err(|err| {
                error!(?err, "Unable to convert current time to GeneralizedTime");
                OperationError::CryptographyError
            })?;
        let not_after = GeneralizedTime::from_unix_duration(
            self.get_curtime() + Duration::from_secs(REPL_MTLS_CERTIFICATE_EXPIRY),
        )
        .map(x509::Time::from)
        .map_err(|err| {
            error!(?err, "Unable to convert current time to GeneralizedTime");
            OperationError::CryptographyError
        })?;

        let validity = Validity::new(not_before, not_after);

        let serial_number = x509::uuid_to_serial(s_uuid);
        // Important - for some reason O= here doesn't propogate to issuer, I suspect
        // due to being a CAB profile.
        let subject = x509::Name::from_str(&format!("CN={s_uuid}")).map_err(|err| {
            error!(?err, "Unable to parse subject dn");
            OperationError::CryptographyError
        })?;

        // Subject Alt Name
        // We need to understand how rustls treats this to issue the correct SAN value.
        // How does rustls interpret this name?
        let Ok(server_name) = ServerName::try_from(domain_name.to_owned()) else {
            error!("Invalid server name for replication");
            return Err(OperationError::CryptographyError);
        };

        let names = match server_name {
            ServerName::DnsName(_) => {
                let alt_name = Ia5String::new(domain_name).map_err(|err| {
                    error!(?err, "Invalid subject alt name");
                    OperationError::CryptographyError
                })?;
                vec![GeneralName::DnsName(alt_name)]
            }
            ServerName::IpAddress(IpAddr::V4(ipv4_addr)) => {
                let ip_address = OctetString::new(*ipv4_addr.as_ref()).map_err(|err| {
                    error!(?err, "Unable to convert ipv4 address to octet string");
                    OperationError::CryptographyError
                })?;
                vec![GeneralName::IpAddress(ip_address)]
            }
            ServerName::IpAddress(IpAddr::V6(ipv6_addr)) => {
                let ip_address = OctetString::new(*ipv6_addr.as_ref()).map_err(|err| {
                    error!(?err, "Unable to convert ipv6 address to octet string");
                    OperationError::CryptographyError
                })?;
                vec![GeneralName::IpAddress(ip_address)]
            }

            _ => return Err(OperationError::CryptographyError),
        };

        let subject_alt_name = SubjectAltName(names.clone());

        let certificate_type =
            CertificateType::domain_validated(subject.clone(), names).map_err(|err| {
                error!(?err, "Unable to construct certificate type");
                OperationError::CryptographyError
            })?;

        let profile = Subscriber {
            certificate_type,
            issuer: subject,
            client_auth: true,
            tls12_options: Default::default(),
            enable_data_encipherment: Default::default(),
        };

        let mut x509_builder = CertificateBuilder::new(profile, serial_number, validity, pub_key)
            .map_err(|err| {
            error!(?err, "Unable to construct certificate builder");
            OperationError::CryptographyError
        })?;

        x509_builder
            .add_extension(&subject_alt_name)
            .map_err(|err| {
                error!(?err, "Unable to add subject alt name");
                OperationError::CryptographyError
            })?;

        let x509 = x509_builder
            .build::<EcdsaP256SigningKey, EcdsaP256DerSignature>(&signing_key)
            .map_err(|err| {
                error!(?err, "Unable to generate self signed key/cert");
                OperationError::CryptographyError
            })?;

        let private = private_key.to_pkcs8_der().map_err(|err| {
            error!(?err, "Unable to encode private key");
            OperationError::CryptographyError
        })?;

        let kh = KeyHandle::X509Key {
            private: private.clone(),
            x509: x509.clone(),
        };

        self.get_be_txn()
            .set_key_handle(KeyHandleId::ReplicationKey, kh)
            .map_err(|err| {
                error!(?err, "Unable to persist replication key");
                err
            })
            .map(|()| (private, x509))
    }

    #[instrument(level = "info", skip_all)]
    pub fn supplier_renew_key_cert(&mut self, domain_name: &str) -> Result<(), OperationError> {
        self.supplier_generate_key_cert(domain_name).map(|_| ())
    }

    #[instrument(level = "debug", skip_all)]
    pub fn supplier_get_key_cert(
        &mut self,
        domain_name: &str,
    ) -> Result<(SecretDocument, Certificate), OperationError> {
        // Later we need to put this through a HSM or similar, but we will always need a way
        // to persist a handle, so we still need the db write and load components.

        // Does the handle exist?
        let maybe_key_handle = self
            .get_be_txn()
            .get_key_handle(KeyHandleId::ReplicationKey)
            .map_err(|err| {
                error!(?err, "Unable to access replication key");
                err
            })?;

        // Can you process the keyhandle?
        let key_cert = match maybe_key_handle {
            Some(KeyHandle::X509Key { private, x509 }) => (private, x509),
            /*
            Some(Keyhandle::...) => {
                // invalid key
                // error? regenerate?
            }
            */
            None => self.supplier_generate_key_cert(domain_name)?,
        };

        Ok(key_cert)
    }
}

impl QueryServerReadTransaction<'_> {
    // Given a consumers state, calculate the differential of changes they
    // need to be sent to bring them to the equivalent state.

    // We use the RUV or Cookie to determine if:
    // * The consumer requires a full-reinit.
    // * Which entry attr-states need to be sent, if any

    #[instrument(level = "debug", skip_all)]
    pub fn supplier_provide_changes(
        &mut self,
        ctx_ruv: ReplRuvRange,
    ) -> Result<ReplIncrementalContext, OperationError> {
        // Convert types if needed. This way we can compare ruv's correctly.
        let (ctx_domain_uuid, ctx_ranges) = match ctx_ruv {
            ReplRuvRange::V1 {
                domain_uuid,
                ranges,
            } => (domain_uuid, ranges),
        };

        if ctx_domain_uuid != self.d_info.d_uuid {
            error!("Replication - Consumer Domain UUID does not match our local domain uuid.");
            debug!(consumer_domain_uuid = ?ctx_domain_uuid, supplier_domain_uuid = ?self.d_info.d_uuid);
            return Ok(ReplIncrementalContext::DomainMismatch);
        }

        // This is a reasonably tricky part of the code, because we are attempting to do a
        // distributed and async liveness check. What content has the consumer seen? What
        // could they have trimmed from their own RUV?
        //
        // Since tombstone purging always creates an anchor, then there are always "pings"
        // effectively going out of "empty" changes that drive the RUV forward. This assists us
        // to detect this situation.
        //
        // If a server has been replicating correctly, then it should have at least *some* overlap
        // with us since content has always advanced.
        //
        // If a server has "stalled" then it will have *no* overlap. This can manifest as a need
        // to supply all ranges as though they were new because the lagging consumer has trimmed out
        // all the old content.
        //
        // When a server is newly added it will have overlap because it will have refreshed from
        // another server.
        //
        // When a server is "trimmed" from the RUV, it no longer influences the overlap decision
        // because the other servers will have continued to advance.

        let trim_cid = *self.trim_cid();

        let supplier_ruv = self.get_be_txn().get_ruv();

        let our_ranges = supplier_ruv.filter_ruv_range(&trim_cid).map_err(|e| {
            error!(err = ?e, "Unable to access supplier RUV range");
            e
        })?;

        // Compare this to our internal ranges - work out the list of entry
        // id's that are now different.

        let supply_ranges = ReplicationUpdateVector::range_diff(&ctx_ranges, &our_ranges);

        // If empty, return an empty set of changes!

        let ranges = match supply_ranges {
            RangeDiffStatus::Ok(ranges) => ranges,
            RangeDiffStatus::Refresh { lag_range } => {
                error!("Replication - Consumer is lagging and must be refreshed.");
                debug!(?lag_range);
                debug!(consumer_ranges = ?ctx_ranges);
                debug!(supplier_ranges = ?our_ranges);
                return Ok(ReplIncrementalContext::RefreshRequired);
            }
            RangeDiffStatus::Unwilling { adv_range } => {
                error!("Replication - Supplier is lagging and must be investigated.");
                debug!(?adv_range);
                debug!(consumer_ranges = ?ctx_ranges);
                debug!(supplier_ranges = ?our_ranges);
                return Ok(ReplIncrementalContext::UnwillingToSupply);
            }
            RangeDiffStatus::Critical {
                lag_range,
                adv_range,
            } => {
                error!(?adv_range, ?lag_range, "Replication Critical - Consumers are advanced of us, and also lagging! This must be immediately investigated!");
                debug!(consumer_ranges = ?ctx_ranges);
                debug!(supplier_ranges = ?our_ranges);
                return Ok(ReplIncrementalContext::UnwillingToSupply);
            }
            RangeDiffStatus::NoRUVOverlap => {
                error!("Replication Critical - Consumers RUV has desynchronised and diverged! This must be immediately investigated!");
                debug!(consumer_ranges = ?ctx_ranges);
                debug!(supplier_ranges = ?our_ranges);
                return Ok(ReplIncrementalContext::UnwillingToSupply);
            }
        };

        debug!("these ranges will be supplied");
        debug!(supply_ranges = ?ranges);
        debug!(consumer_ranges = ?ctx_ranges);
        debug!(supplier_ranges = ?our_ranges);

        if ranges.is_empty() {
            debug!("No Changes Available");
            return Ok(ReplIncrementalContext::NoChangesAvailable);
        }

        // From the set of change id's, fetch those entries.
        // This is done by supplying the ranges to the be which extracts
        // the entries affected by the idls in question.
        let entries = self.get_be_txn().retrieve_range(&ranges).map_err(|e| {
            admin_error!(?e, "backend failure");
            OperationError::Backend
        })?;

        // Separate the entries into schema, meta and remaining.
        let (schema_entries, rem_entries): (Vec<_>, Vec<_>) = entries.into_iter().partition(|e| {
            e.get_ava_set(Attribute::Class)
                .map(|cls| {
                    cls.contains(&EntryClass::AttributeType.into() as &PartialValue)
                        || cls.contains(&EntryClass::ClassType.into() as &PartialValue)
                })
                .unwrap_or(false)
        });

        let (meta_entries, entries): (Vec<_>, Vec<_>) = rem_entries.into_iter().partition(|e| {
            e.get_ava_set(Attribute::Class)
                .map(|cls| {
                    cls.contains(&EntryClass::DomainInfo.into() as &PartialValue)
                        || cls.contains(&EntryClass::SystemInfo.into() as &PartialValue)
                        || cls.contains(&EntryClass::SystemConfig.into() as &PartialValue)
                        || cls.contains(&EntryClass::KeyProvider.into() as &PartialValue)
                })
                .unwrap_or(false)
        });

        trace!(?schema_entries);
        trace!(?meta_entries);
        trace!(?entries);

        // For each entry, determine the changes that exist on the entry that fall
        // into the ruv range - reduce to a incremental set of changes.

        let schema = self.get_schema();
        let domain_version = self.d_info.d_vers;
        let domain_patch_level = if self.d_info.d_devel_taint {
            u32::MAX
        } else {
            self.d_info.d_patch_level
        };
        let domain_uuid = self.d_info.d_uuid;

        let schema_entries: Vec<_> = schema_entries
            .into_iter()
            .map(|e| ReplIncrementalEntryV1::new(e.as_ref(), schema, &ranges))
            .collect();

        let meta_entries: Vec<_> = meta_entries
            .into_iter()
            .map(|e| ReplIncrementalEntryV1::new(e.as_ref(), schema, &ranges))
            .collect();

        let entries: Vec<_> = entries
            .into_iter()
            .map(|e| ReplIncrementalEntryV1::new(e.as_ref(), schema, &ranges))
            .collect();

        // Finally, populate the ranges with anchors from the RUV
        let supplier_ruv = self.get_be_txn().get_ruv();
        let ranges = supplier_ruv.get_anchored_ranges(ranges)?;

        // Build the incremental context.
        Ok(ReplIncrementalContext::V1 {
            domain_version,
            domain_patch_level,
            domain_uuid,
            ranges,
            schema_entries,
            meta_entries,
            entries,
        })
    }

    #[instrument(level = "debug", skip_all)]
    pub fn supplier_provide_refresh(&mut self) -> Result<ReplRefreshContext, OperationError> {
        // Get the current schema. We use this for attribute and entry filtering.
        let schema = self.get_schema();

        // A refresh must provide
        //
        // * the current domain version
        let domain_version = self.d_info.d_vers;
        let domain_devel = self.d_info.d_devel_taint;
        let domain_uuid = self.d_info.d_uuid;

        let trim_cid = *self.trim_cid();

        // What is the set of data we are providing?
        let ranges = self
            .get_be_txn()
            .get_ruv()
            .filter_ruv_range(&trim_cid)
            .map_err(|e| {
                error!(err = ?e, "Unable to access supplier RUV range");
                e
            })?;

        // * the domain uuid
        // * the set of schema entries
        // * the set of non-schema entries
        // - We must exclude certain entries and attributes!
        //   * schema defines what we exclude!

        let schema_filter_inner = f_or!([
            f_eq(Attribute::Class, EntryClass::AttributeType.into()),
            f_eq(Attribute::Class, EntryClass::ClassType.into()),
        ]);

        let schema_filter = filter!(schema_filter_inner.clone());

        let meta_filter_inner = f_or!([
            f_eq(Attribute::Class, EntryClass::DomainInfo.into()),
            f_eq(Attribute::Class, EntryClass::SystemInfo.into()),
            f_eq(Attribute::Class, EntryClass::SystemConfig.into()),
            f_eq(Attribute::Class, EntryClass::KeyProvider.into()),
        ]);

        let meta_filter = filter!(meta_filter_inner.clone());

        let entry_filter = filter_all!(f_or!([
            f_and!([
                f_pres(Attribute::Class),
                f_andnot(f_or(vec![schema_filter_inner, meta_filter_inner])),
            ]),
            f_eq(Attribute::Class, EntryClass::Tombstone.into()),
            f_eq(Attribute::Class, EntryClass::Recycled.into()),
        ]));

        let schema_entries = self
            .internal_search(schema_filter)
            .map(|ent| {
                ent.into_iter()
                    .map(|e| ReplEntryV1::new(e.as_ref(), schema))
                    .collect()
            })
            .inspect_err(|err| {
                error!(?err, "Failed to access schema entries");
            })?;

        let meta_entries = self
            .internal_search(meta_filter)
            .map(|ent| {
                ent.into_iter()
                    .map(|e| ReplEntryV1::new(e.as_ref(), schema))
                    .collect()
            })
            .inspect_err(|err| {
                error!(?err, "Failed to access meta entries");
            })?;

        let entries = self
            .internal_search(entry_filter)
            .map(|ent| {
                ent.into_iter()
                    .map(|e| ReplEntryV1::new(e.as_ref(), schema))
                    .collect()
            })
            .inspect_err(|err| {
                error!(?err, "Failed to access entries");
            })?;

        // Finally, populate the ranges with anchors from the RUV
        let supplier_ruv = self.get_be_txn().get_ruv();
        let ranges = supplier_ruv.get_anchored_ranges(ranges)?;

        Ok(ReplRefreshContext::V1 {
            domain_version,
            domain_devel,
            domain_uuid,
            ranges,
            schema_entries,
            meta_entries,
            entries,
        })
    }
}
