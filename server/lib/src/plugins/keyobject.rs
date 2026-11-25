use crate::{plugins::Plugin, prelude::*};
use std::sync::Arc;

pub struct KeyObjectManagement {}

impl Plugin for KeyObjectManagement {
    fn id() -> &'static str {
        "plugin_keyobject_management"
    }

    #[instrument(
        level = "debug",
        name = "keyobject_management::pre_create_transform",
        skip_all
    )]
    fn pre_create_transform(
        qs: &mut QueryServerWriteTransaction,
        cand: &mut Vec<Entry<EntryInvalid, EntryNew>>,
        _ce: &CreateEvent,
    ) -> Result<(), OperationError> {
        Self::apply_keyobject_inner(qs, cand)
    }

    #[instrument(level = "debug", name = "keyobject_management::pre_modify", skip_all)]
    fn pre_modify(
        qs: &mut QueryServerWriteTransaction,
        _pre_cand: &[Arc<EntrySealedCommitted>],
        cand: &mut Vec<Entry<EntryInvalid, EntryCommitted>>,
        _me: &ModifyEvent,
    ) -> Result<(), OperationError> {
        Self::apply_keyobject_inner(qs, cand)
    }

    #[instrument(
        level = "debug",
        name = "keyobject_management::pre_batch_modify",
        skip_all
    )]
    fn pre_batch_modify(
        qs: &mut QueryServerWriteTransaction,
        _pre_cand: &[Arc<EntrySealedCommitted>],
        cand: &mut Vec<Entry<EntryInvalid, EntryCommitted>>,
        _me: &BatchModifyEvent,
    ) -> Result<(), OperationError> {
        Self::apply_keyobject_inner(qs, cand)
    }

    /*
    #[instrument(level = "debug", name = "keyobject_management::pre_delete", skip_all)]
    fn pre_delete(
        _qs: &mut QueryServerWriteTransaction,
        // Should these be EntrySealed
        _cand: &mut Vec<Entry<EntryInvalid, EntryCommitted>>,
        _de: &DeleteEvent,
    ) -> Result<(), OperationError> {
        Ok(())
    }
    */

    #[instrument(level = "debug", name = "keyobject_management::verify", skip_all)]
    fn verify(qs: &mut QueryServerReadTransaction) -> Vec<Result<(), ConsistencyError>> {
        let filt_in = filter!(f_eq(Attribute::Class, EntryClass::KeyProvider.into()));

        let key_providers = match qs
            .internal_search(filt_in)
            .map_err(|_| Err(ConsistencyError::QueryServerSearchFailure))
        {
            Ok(all_cand) => all_cand,
            Err(e) => return vec![e],
        };

        // Put the providers into a map by uuid.
        let key_providers: hashbrown::HashSet<_> = key_providers
            .into_iter()
            .map(|entry| entry.get_uuid())
            .collect();

        let filt_in = filter!(f_eq(Attribute::Class, EntryClass::KeyObject.into()));

        let key_objects = match qs
            .internal_search(filt_in)
            .map_err(|_| Err(ConsistencyError::QueryServerSearchFailure))
        {
            Ok(all_cand) => all_cand,
            Err(e) => return vec![e],
        };

        key_objects
            .into_iter()
            .filter_map(|key_object_entry| {
                let object_uuid = key_object_entry.get_uuid();

                // Each key objects must relate to a provider.
                let Some(provider_uuid) =
                    key_object_entry.get_ava_single_refer(Attribute::KeyProvider)
                else {
                    error!(?object_uuid, "Invalid key object, no key provider uuid.");
                    return Some(ConsistencyError::KeyProviderUuidMissing {
                        key_object: object_uuid,
                    });
                };

                if !key_providers.contains(&provider_uuid) {
                    error!(
                        ?object_uuid,
                        ?provider_uuid,
                        "Invalid key object, key provider referenced is not found."
                    );
                    return Some(ConsistencyError::KeyProviderNotFound {
                        key_object: object_uuid,
                        provider: provider_uuid,
                    });
                }

                // Every key object needs at least *one* key it stores.
                let has_jwt_es256 = key_object_entry
                    .attribute_equality(Attribute::Class, &EntryClass::KeyObjectJwtEs256.into());

                let has_jwt_rs256 = key_object_entry
                    .attribute_equality(Attribute::Class, &EntryClass::KeyObjectJwtRs256.into());

                let has_hkdf_s256 = key_object_entry
                    .attribute_equality(Attribute::Class, &EntryClass::KeyObjectHkdfS256.into());

                let has_key = has_jwt_es256 || has_jwt_rs256 || has_hkdf_s256;

                if !has_key {
                    error!(?object_uuid, "Invalid key object, contains no keys.");
                    return Some(ConsistencyError::KeyProviderNoKeys {
                        key_object: object_uuid,
                    });
                }

                None
            })
            .map(Err)
            .collect::<Vec<_>>()
    }
}

impl KeyObjectManagement {
    fn apply_keyobject_inner<T: Clone>(
        qs: &mut QueryServerWriteTransaction,
        cand: &mut [Entry<EntryInvalid, T>],
    ) -> Result<(), OperationError> {
        // New keys will be valid from right meow!
        let valid_from = qs.get_curtime();
        let txn_cid = *qs.get_cid();
        let key_providers = qs.get_key_providers_mut();
        // ====================================================================
        // Transform any found KeyObjects and manage any related key operations
        // for them

        cand.iter_mut()
            .filter(|entry| {
                entry.attribute_equality(Attribute::Class, &EntryClass::KeyObject.into())
            })
            .try_for_each(|entry| {
                // The entry should not have set any type of KeyObject at this point.
                // Should we force delete those attrs here just in case?
                entry.remove_ava(Attribute::Class, &EntryClass::KeyObjectInternal.into());

                // Must be set by now.
                let key_object_uuid = entry
                    .get_uuid()
                    .ok_or(OperationError::KP0008KeyObjectMissingUuid)?;

                trace!(?key_object_uuid, "Setting up key object");

                // Get the default provider, and create a new ephemeral key object
                // inside it. If the object existed already, we clone it so that we can stage
                // our changes.
                let mut key_object = key_providers.get_or_create_in_default(key_object_uuid)?;

                // Import any keys that we were asked to import. This is before revocation so that
                // any keyId here might also be able to be revoked.
                let maybe_import = entry.pop_ava(Attribute::KeyActionImportJwsEs256);
                if let Some(import_keys) = maybe_import
                    .as_ref()
                    .and_then(|vs| vs.as_private_binary_set())
                {
                    key_object.jws_es256_import(import_keys, valid_from, &txn_cid)?;
                }

                let maybe_import = entry.pop_ava(Attribute::KeyActionImportJwsRs256);
                if let Some(import_keys) = maybe_import
                    .as_ref()
                    .and_then(|vs| vs.as_private_binary_set())
                {
                    key_object.jws_rs256_import(import_keys, valid_from, &txn_cid)?;
                }

                // If revoke. This weird looking let dance is to ensure that the inner hexstring set
                // lives long enough.
                let maybe_revoked = entry.pop_ava(Attribute::KeyActionRevoke);
                if let Some(revoke_keys) =
                    maybe_revoked.as_ref().and_then(|vs| vs.as_hexstring_set())
                {
                    key_object.revoke_keys(revoke_keys, &txn_cid)?;
                }

                // Rotation is after revocation, but before assertion. This way if the user
                // asked for rotation and revocation, we don't double rotate when we get to
                // the assert phase. We also only get a rotation time if the time is in the
                // future, to avoid rotating keys in the past.
                if let Some(rotation_time) = entry
                    .pop_ava(Attribute::KeyActionRotate)
                    .and_then(|vs| vs.to_datetime_single())
                    .map(|odt| {
                        let secs = odt.unix_timestamp() as u64;
                        if secs > valid_from.as_secs() {
                            Duration::from_secs(secs)
                        } else {
                            valid_from
                        }
                    })
                {
                    debug!(?rotation_time, "initiate key rotation");
                    key_object.rotate_keys(rotation_time, &txn_cid)?;
                }

                if entry.attribute_equality(Attribute::Class, &EntryClass::KeyObjectHkdfS256.into())
                {
                    key_object.hkdf_s256_assert(Duration::ZERO, &txn_cid)?;
                }

                if entry.attribute_equality(Attribute::Class, &EntryClass::KeyObjectJwtEs256.into())
                {
                    // Assert that this object has a valid es256 key present. Post revoke, it may NOT
                    // be present. This differs to rotate, in that the assert verifies we have at least
                    // *one* key that is valid in all conditions.
                    key_object.jws_es256_assert(Duration::ZERO, &txn_cid)?;
                }

                if entry.attribute_equality(Attribute::Class, &EntryClass::KeyObjectJwtHs256.into())
                {
                    key_object.jws_hs256_assert(Duration::ZERO, &txn_cid)?;
                }

                if entry.attribute_equality(Attribute::Class, &EntryClass::KeyObjectJwtRs256.into())
                {
                    key_object.jws_rs256_assert(Duration::ZERO, &txn_cid)?;
                }

                if entry
                    .attribute_equality(Attribute::Class, &EntryClass::KeyObjectJweA128GCM.into())
                {
                    key_object.jwe_a128gcm_assert(Duration::ZERO, &txn_cid)?;
                }

                if entry
                    .attribute_equality(Attribute::Class, &EntryClass::KeyObjectJweA256GCM.into())
                {
                    key_object.jwe_a256gcm_assert(Duration::ZERO, &txn_cid)?;
                }

                // Turn that object into it's entry template to create. I think we need to make this
                // some kind of merge_vs?
                key_object
                    .as_valuesets()?
                    .into_iter()
                    .try_for_each(|(attribute, valueset)| {
                        entry.merge_ava_set(&attribute, valueset)
                    })?;

                Ok(())
            })
    }
}

// Unlike other plugins, tests for this plugin will be located in server/lib/src/server/keys.
//
// The reason is because we can preconfigure different providers to test these paths in future.
