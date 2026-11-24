use crate::{
    credential::totp::{Totp, TotpAlgo, TotpDigits},
    idm::server::IdmServerProxyReadTransaction,
    prelude::*,
    server::{identity::Identity, keys::KeyProvidersTransaction},
};
use crypto_glue::hmac_s256::HmacSha256Key;
use kanidm_proto::internal::IdentifyUserResponse;
use std::sync::Arc;
use uuid::Uuid;

// This is longer than a normal TOTP step as we expect users to be talking
// to each other, so it could take a few minutes.
static TOTP_STEP: u64 = 300;

#[derive(Debug)]
pub struct IdentifyUserStartEvent {
    pub target: Uuid,
    pub ident: Identity,
}

impl IdentifyUserStartEvent {
    pub fn new(target: Uuid, ident: Identity) -> Self {
        IdentifyUserStartEvent { target, ident }
    }
}
pub struct IdentifyUserDisplayCodeEvent {
    pub target: Uuid,
    pub ident: Identity,
}

impl IdentifyUserDisplayCodeEvent {
    pub fn new(target: Uuid, ident: Identity) -> Self {
        IdentifyUserDisplayCodeEvent { target, ident }
    }
}

pub struct IdentifyUserSubmitCodeEvent {
    pub code: u32,
    pub target: Uuid,
    pub ident: Identity,
}

impl IdentifyUserSubmitCodeEvent {
    pub fn new(target: Uuid, ident: Identity, code: u32) -> Self {
        IdentifyUserSubmitCodeEvent {
            target,
            ident,
            code,
        }
    }
}

impl IdmServerProxyReadTransaction<'_> {
    pub fn handle_identify_user_start(
        &mut self,
        IdentifyUserStartEvent { target, ident }: &IdentifyUserStartEvent,
        current_time: Duration,
    ) -> Result<IdentifyUserResponse, OperationError> {
        let (ident_entry, target_entry) = match self.get_involved_entries(ident, *target) {
            Ok(tuple) => tuple,
            Err(early_response) => return Ok(early_response),
        };

        let response = if ident_entry.get_uuid() < target_entry.get_uuid() {
            IdentifyUserResponse::WaitForCode
        } else {
            let totp_secret = self.get_totp(current_time, &ident_entry, &target_entry)?;

            let totp_value = totp_secret
                .do_totp_duration_from_epoch(&current_time)
                .map_err(|_| OperationError::CryptographyError)?;

            IdentifyUserResponse::ProvideCode {
                step: TOTP_STEP as u32,
                totp: totp_value,
            }
        };
        Ok(response)
    }

    pub fn handle_identify_user_display_code(
        &mut self,
        IdentifyUserDisplayCodeEvent { target, ident }: &IdentifyUserDisplayCodeEvent,
        current_time: Duration,
    ) -> Result<IdentifyUserResponse, OperationError> {
        let (ident_entry, target_entry) = match self.get_involved_entries(ident, *target) {
            Ok(tuple) => tuple,
            Err(early_response) => return Ok(early_response),
        };

        let totp_secret = self.get_totp(current_time, &ident_entry, &target_entry)?;

        let totp_value = totp_secret
            .do_totp_duration_from_epoch(&current_time)
            .map_err(|_| OperationError::CryptographyError)?;

        Ok(IdentifyUserResponse::ProvideCode {
            step: TOTP_STEP as u32,
            totp: totp_value,
        })
    }

    pub fn handle_identify_user_submit_code(
        &mut self,
        IdentifyUserSubmitCodeEvent {
            target,
            ident,
            code,
        }: &IdentifyUserSubmitCodeEvent,
        current_time: Duration,
    ) -> Result<IdentifyUserResponse, OperationError> {
        let (ident_entry, target_entry) = match self.get_involved_entries(ident, *target) {
            Ok(tuple) => tuple,
            Err(early_response) => return Ok(early_response),
        };

        let totp_secret = self.get_totp(current_time, &target_entry, &ident_entry)?;

        if !totp_secret.verify(*code, current_time) {
            return Ok(IdentifyUserResponse::CodeFailure);
        }

        // if we waited the first it means now it's time to go for ProvideCode, otherwise we just confirm that the code is correct
        // (we know this for a fact as we have already checked that the code is correct)
        let response = if ident_entry.get_uuid() < target_entry.get_uuid() {
            let totp_secret = self.get_totp(current_time, &ident_entry, &target_entry)?;
            let totp_value = totp_secret
                .do_totp_duration_from_epoch(&current_time)
                .map_err(|_| OperationError::CryptographyError)?;
            IdentifyUserResponse::ProvideCode {
                step: TOTP_STEP as u32,
                totp: totp_value,
            }
        } else {
            IdentifyUserResponse::Success
        };
        Ok(response)
    }

    fn get_involved_entries(
        &mut self,
        ident: &Identity,
        target: Uuid,
    ) -> Result<(Arc<EntrySealedCommitted>, Arc<EntrySealedCommitted>), IdentifyUserResponse> {
        if self
            .qs_read
            .get_key_providers()
            .get_key_object_handle(UUID_DOMAIN_ID_VERIFICATION_KEY)
            .is_none()
        {
            return Err(IdentifyUserResponse::IdentityVerificationUnavailable);
        }

        let Some(ident_entry) = ident.get_user_entry() else {
            return Err(IdentifyUserResponse::IdentityVerificationUnavailable);
        };

        let Ok(target_entry) = self.get_partner_entry(target) else {
            return Err(IdentifyUserResponse::IdentityVerificationUnavailable);
        };

        if ident_entry.get_uuid() == target_entry.get_uuid() {
            return Err(IdentifyUserResponse::IdentityVerificationUnavailable);
        }

        Ok((ident_entry, target_entry))
    }

    fn get_partner_entry(
        &mut self,
        target: Uuid,
    ) -> Result<Arc<EntrySealedCommitted>, OperationError> {
        self.qs_read
            .internal_search_uuid(target)
            .inspect_err(|err| error!(?err, ?target, "Failed to retrieve entry",))
    }

    fn get_totp(
        &mut self,
        current_time: Duration,
        initiating_entry: &EntrySealedCommitted,
        receiving_entry: &EntrySealedCommitted,
    ) -> Result<Totp, OperationError> {
        let key_object = self
            .qs_read
            .get_key_providers()
            .get_key_object_handle(UUID_DOMAIN_ID_VERIFICATION_KEY)
            .ok_or(OperationError::KP0078KeyObjectNotFound)?;

        let initiating_uuid = initiating_entry.get_uuid();
        let receiving_uuid = receiving_entry.get_uuid();

        // Uuid's are always 16 bytes, so this is 32.
        let mut info_bytes: [u8; 32] = [0; 32];
        info_bytes[..16].copy_from_slice(initiating_uuid.as_bytes());
        info_bytes[16..].copy_from_slice(receiving_uuid.as_bytes());

        let mut shared_key = HmacSha256Key::default();
        key_object.hkdf_s256_expand(&info_bytes, shared_key.as_mut_slice(), current_time)?;

        let totp = Totp::new(
            shared_key.as_slice().to_vec(),
            TOTP_STEP,
            TotpAlgo::Sha256,
            TotpDigits::Six,
        );
        Ok(totp)
    }
}

#[cfg(test)]
mod test {
    use crate::{
        idm::identityverification::{
            IdentifyUserDisplayCodeEvent, IdentifyUserStartEvent, IdentifyUserSubmitCodeEvent,
        },
        prelude::*,
    };
    use kanidm_proto::internal::IdentifyUserResponse;

    #[idm_test]
    async fn test_identity_verification_unavailable(
        idms: &IdmServer,
        _idms_delayed: &IdmServerDelayed,
    ) {
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = idms.proxy_write(ct).await.unwrap();

        let invalid_user_uuid = Uuid::new_v4();
        let valid_user_uuid = Uuid::new_v4();

        let e2 = create_valid_user_account(valid_user_uuid, "valid_idv_user");

        let ce = CreateEvent::new_internal(vec![e2]);
        assert!(idms_prox_write.qs_write.create(&ce).is_ok());
        assert!(idms_prox_write.commit().is_ok());

        let mut idms_prox_read = idms.proxy_read().await.unwrap();

        let ident = idms_prox_read
            .qs_read
            .internal_search_uuid(valid_user_uuid)
            .map(Identity::from_impersonate_entry_readonly)
            .expect("Failed to impersonate identity");

        // Can't ID verify to system Internal
        let res = idms_prox_read
            .handle_identify_user_start(
                &IdentifyUserStartEvent::new(valid_user_uuid, Identity::from_internal()),
                ct,
            )
            .expect("failed to start id verification");

        assert!(matches!(
            res,
            IdentifyUserResponse::IdentityVerificationUnavailable
        ));

        // We can't ID verify to ourself.
        let res = idms_prox_read
            .handle_identify_user_start(
                &IdentifyUserStartEvent::new(valid_user_uuid, ident.clone()),
                ct,
            )
            .expect("failed to start id verification");

        assert!(matches!(
            res,
            IdentifyUserResponse::IdentityVerificationUnavailable
        ));

        // Can't do IDV to a UUID that doesn't exist.
        let res = idms_prox_read
            .handle_identify_user_start(
                &IdentifyUserStartEvent::new(invalid_user_uuid, ident.clone()),
                ct,
            )
            .expect("failed to start id verification");

        assert!(matches!(
            res,
            IdentifyUserResponse::IdentityVerificationUnavailable
        ));
    }

    #[idm_test]
    async fn test_idv_flow(idms: &IdmServer, _idms_delayed: &IdmServerDelayed) {
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = idms.proxy_write(ct).await.unwrap();
        let user_a_uuid = uuid::uuid!("20f44860-7db3-40f4-a2c3-d9f163f855ec");
        let user_b_uuid = uuid::uuid!("dde1de53-cbd2-439c-a3c9-bde6ee026e78");
        let e1 = create_valid_user_account(user_a_uuid, "idv_user_a");
        let e2 = create_valid_user_account(user_b_uuid, "idv_user_b");
        let ce = CreateEvent::new_internal(vec![e1, e2]);

        assert!(idms_prox_write.qs_write.create(&ce).is_ok());
        assert!(idms_prox_write.commit().is_ok());

        let mut idms_prox_read = idms.proxy_read().await.unwrap();

        let user_a = idms_prox_read
            .qs_read
            .internal_search_uuid(user_a_uuid)
            .map(Identity::from_impersonate_entry_readonly)
            .expect("Failed to impersonate identity");

        let user_b = idms_prox_read
            .qs_read
            .internal_search_uuid(user_b_uuid)
            .map(Identity::from_impersonate_entry_readonly)
            .expect("Failed to impersonate identity");

        // First we retrieve the higher user code
        let res_higher_user = idms_prox_read
            .handle_identify_user_start(
                &IdentifyUserStartEvent::new(user_a_uuid, user_b.clone()),
                ct,
            )
            .expect("Failed to retrieve code.");

        let higher_user_totp = match res_higher_user {
            IdentifyUserResponse::ProvideCode { totp, .. } => totp,
            state => {
                error!(?state);
                unreachable!()
            }
        };

        // DisplayCode shows the same result.
        let res_higher_user = idms_prox_read
            .handle_identify_user_display_code(
                &IdentifyUserDisplayCodeEvent::new(user_a_uuid, user_b.clone()),
                ct,
            )
            .expect("Failed to retrieve code.");

        let higher_user_totp_display = match res_higher_user {
            IdentifyUserResponse::ProvideCode { totp, .. } => totp,
            state => {
                error!(?state);
                unreachable!()
            }
        };

        assert_eq!(higher_user_totp_display, higher_user_totp);

        // The lower user is in state "wait"
        let lower_user_state = idms_prox_read
            .handle_identify_user_start(
                &IdentifyUserStartEvent::new(user_b_uuid, user_a.clone()),
                ct,
            )
            .expect("Failed start idv.");

        assert!(matches!(
            lower_user_state,
            IdentifyUserResponse::WaitForCode
        ));

        // Submit an incorrect code as the lower user.
        let lower_user_state = idms_prox_read
            .handle_identify_user_submit_code(
                &IdentifyUserSubmitCodeEvent::new(
                    user_b_uuid,
                    user_a.clone(),
                    higher_user_totp + 1,
                ),
                ct,
            )
            .expect("Failed to retrieve code.");

        match lower_user_state {
            IdentifyUserResponse::CodeFailure => {}
            state => {
                error!(?state);
                unreachable!()
            }
        };

        // Submit the correct code as the lower user,
        let lower_user_state = idms_prox_read
            .handle_identify_user_submit_code(
                &IdentifyUserSubmitCodeEvent::new(user_b_uuid, user_a.clone(), higher_user_totp),
                ct,
            )
            .expect("Failed to retrieve code.");

        let lower_user_totp = match lower_user_state {
            IdentifyUserResponse::ProvideCode { totp, .. } => totp,
            state => {
                error!(?state);
                unreachable!()
            }
        };

        debug!(?higher_user_totp, ?lower_user_totp);
        assert_ne!(higher_user_totp, lower_user_totp);

        // Assert that the lower user code display is correct.
        let lower_user_state = idms_prox_read
            .handle_identify_user_display_code(
                &IdentifyUserDisplayCodeEvent::new(user_b_uuid, user_a.clone()),
                ct,
            )
            .expect("Failed to retrieve code.");

        let lower_user_totp_display = match lower_user_state {
            IdentifyUserResponse::ProvideCode { totp, .. } => totp,
            state => {
                error!(?state);
                unreachable!()
            }
        };

        assert_eq!(lower_user_totp_display, lower_user_totp);

        // Submit the wrong code as the higher user
        let higher_user_state = idms_prox_read
            .handle_identify_user_submit_code(
                &IdentifyUserSubmitCodeEvent::new(user_a_uuid, user_b.clone(), lower_user_totp + 1),
                ct,
            )
            .expect("Failed to retrieve code.");

        match higher_user_state {
            IdentifyUserResponse::CodeFailure => {}
            state => {
                error!(?state);
                unreachable!()
            }
        };

        // Now check that the higher user can submit correctly.
        let higher_user_state = idms_prox_read
            .handle_identify_user_submit_code(
                &IdentifyUserSubmitCodeEvent::new(user_a_uuid, user_b.clone(), lower_user_totp),
                ct,
            )
            .expect("Failed to retrieve code.");

        match higher_user_state {
            IdentifyUserResponse::Success => {}
            state => {
                error!(?state);
                unreachable!()
            }
        };
    }

    fn create_valid_user_account(uuid: Uuid, name: &str) -> EntryInitNew {
        entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Account.to_value()),
            (Attribute::Class, EntryClass::Person.to_value()),
            (Attribute::Name, Value::new_iname(name)),
            (Attribute::Uuid, Value::Uuid(uuid)),
            (Attribute::Description, Value::new_utf8s("some valid user")),
            (Attribute::DisplayName, Value::new_utf8s("Some valid user"))
        )
    }
}
