// Transform password import requests into proper kanidm credentials.
use std::convert::TryFrom;
use std::iter::once;
use std::sync::Arc;

use time::OffsetDateTime;

use crate::credential::{Credential, Password};
use crate::event::{CreateEvent, ModifyEvent};
use crate::plugins::Plugin;
use crate::prelude::*;

pub struct CredImport {}

impl Plugin for CredImport {
    fn id() -> &'static str {
        "plugin_password_import"
    }

    #[instrument(
        level = "debug",
        name = "password_import_pre_create_transform",
        skip_all
    )]
    fn pre_create_transform(
        qs: &mut QueryServerWriteTransaction,
        cand: &mut Vec<Entry<EntryInvalid, EntryNew>>,
        _ce: &CreateEvent,
    ) -> Result<(), OperationError> {
        Self::modify_inner(cand, qs.get_curtime_odt())
    }

    #[instrument(level = "debug", name = "password_import_pre_modify", skip_all)]
    fn pre_modify(
        qs: &mut QueryServerWriteTransaction,
        _pre_cand: &[Arc<EntrySealedCommitted>],
        cand: &mut Vec<Entry<EntryInvalid, EntryCommitted>>,
        _me: &ModifyEvent,
    ) -> Result<(), OperationError> {
        Self::modify_inner(cand, qs.get_curtime_odt())
    }

    #[instrument(level = "debug", name = "password_import_pre_batch_modify", skip_all)]
    fn pre_batch_modify(
        qs: &mut QueryServerWriteTransaction,
        _pre_cand: &[Arc<EntrySealedCommitted>],
        cand: &mut Vec<Entry<EntryInvalid, EntryCommitted>>,
        _me: &BatchModifyEvent,
    ) -> Result<(), OperationError> {
        Self::modify_inner(cand, qs.get_curtime_odt())
    }
}

impl CredImport {
    fn modify_inner<T: Clone>(cand: &mut [Entry<EntryInvalid, T>], timestamp: OffsetDateTime) -> Result<(), OperationError> {
        cand.iter_mut().try_for_each(|entry| {
            // PASSWORD IMPORT
            if let Some(vs) = entry.pop_ava(Attribute::PasswordImport) {
                // if there are multiple, fail.
                let im_pw = vs.to_utf8_single().ok_or_else(|| {
                    OperationError::Plugin(PluginError::CredImport(
                        format!("{} has incorrect value type - should be a single utf8 string", Attribute::PasswordImport),
                    ))
                })?;

                // convert the import_password_string to a password
                let pw = Password::try_from(im_pw).map_err(|err| {
                    error!(entry_id = %entry.get_display_id(), "{} was unable to convert hash format - {}", Attribute::PasswordImport, err);
                    OperationError::Plugin(PluginError::CredImport(
                        "password_import was unable to convert hash format".to_string(),
                    ))
                })?;

                // does the entry have a primary cred?
                match entry.get_ava_single_credential(Attribute::PrimaryCredential) {
                    Some(c) => {
                        let c = c.update_password(pw, timestamp);
                        entry.set_ava(
                            &Attribute::PrimaryCredential,
                            once(Value::new_credential("primary", c)),
                        );
                    }
                    None => {
                        // just set it then!
                        let c = Credential::new_from_password(pw, timestamp);
                        entry.set_ava(
                            &Attribute::PrimaryCredential,
                            once(Value::new_credential("primary", c)),
                        );
                    }
                }
            };

            // TOTP IMPORT - Must be subsequent to password import to allow primary cred to
            // be created.
            if let Some(vs) = entry.pop_ava(Attribute::TotpImport) {
                // Get the map.
                let totps = vs.as_totp_map().ok_or_else(|| {
                    OperationError::Plugin(PluginError::CredImport(
                        format!("{} has incorrect value type - should be a map of totp", Attribute::TotpImport)
                    ))
                })?;

                if let Some(c) = entry.get_ava_single_credential(Attribute::PrimaryCredential) {
                    let c = totps.iter().fold(c.clone(), |acc, (label, totp)| {
                        acc.append_totp(label.clone(), totp.clone(), timestamp)
                    });
                    entry.set_ava(
                        &Attribute::PrimaryCredential,
                        once(Value::new_credential("primary", c)),
                    );
                } else {
                    return Err(OperationError::Plugin(PluginError::CredImport(
                        format!("{} can not be used if {} (password) is missing"
                            ,Attribute::TotpImport, Attribute::PrimaryCredential),
                    )));
                }
            }

            // UNIX PASSWORD IMPORT
            if let Some(vs) = entry.pop_ava(Attribute::UnixPasswordImport) {
                // if there are multiple, fail.
                let im_pw = vs.to_utf8_single().ok_or_else(|| {
                    OperationError::Plugin(PluginError::CredImport(
                        format!("{} has incorrect value type - should be a single utf8 string", Attribute::UnixPasswordImport),
                    ))
                })?;

                // convert the import_password_string to a password
                let pw = Password::try_from(im_pw).map_err(|_| {
                    let len = if im_pw.len() > 5 {
                        4
                    } else {
                        im_pw.len() - 1
                    };
                    let hint = im_pw.split_at_checked(len)
                        .map(|(a, _)| a)
                        .unwrap_or("CORRUPT");
                    let id = entry.get_display_id();

                    error!(%hint, entry_id = %id, "{} was unable to convert hash format", Attribute::UnixPasswordImport);

                    OperationError::Plugin(PluginError::CredImport(
                        "unix_password_import was unable to convert hash format".to_string(),
                    ))
                })?;

                // Unix pw's aren't like primary, we can just splat them here.
                let c = Credential::new_from_password(pw, timestamp);
                entry.set_ava(
                    &Attribute::UnixPassword,
                    once(Value::new_credential("primary", c)),
                );
            };

            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::credential::totp::{Totp, TOTP_DEFAULT_STEP};
    use crate::credential::{Credential, CredentialType};
    use crate::prelude::*;
    use kanidm_lib_crypto::CryptoPolicy;

    const IMPORT_HASH: &str =
        "pbkdf2_sha256$36000$xIEozuZVAoYm$uW1b35DUKyhvQAf1mBqMvoBDcqSD06juzyO/nmyV0+w=";
    // const IMPORT_PASSWORD: &'static str = "eicieY7ahchaoCh0eeTa";

    #[test]
    fn test_pre_create_password_import_1() {
        let preload: Vec<Entry<EntryInit, EntryNew>> = Vec::with_capacity(0);

        let e = entry_init!(
            (Attribute::Class, EntryClass::Account.to_value()),
            (Attribute::Class, EntryClass::Person.to_value()),
            (Attribute::Name, Value::new_iname("testperson")),
            (
                Attribute::Description,
                Value::Utf8("testperson".to_string())
            ),
            (
                Attribute::DisplayName,
                Value::Utf8("testperson".to_string())
            ),
            (
                Attribute::Uuid,
                Value::Uuid(uuid!("d2b496bd-8493-47b7-8142-f568b5cf47ee"))
            ),
            (
                Attribute::PasswordImport,
                Value::Utf8(
                    "pbkdf2_sha256$36000$xIEozuZVAoYm$uW1b35DUKyhvQAf1mBqMvoBDcqSD06juzyO/nmyV0+w="
                        .into()
                )
            )
        );

        let create = vec![e];

        run_create_test!(Ok(None), preload, create, None, |_| {});
    }

    #[test]
    fn test_modify_password_import_1() {
        let ea = entry_init!(
            (Attribute::Class, EntryClass::Account.to_value()),
            (Attribute::Class, EntryClass::Person.to_value()),
            (Attribute::Name, Value::new_iname("testperson")),
            (
                Attribute::Description,
                Value::Utf8("testperson".to_string())
            ),
            (
                Attribute::DisplayName,
                Value::Utf8("testperson".to_string())
            ),
            (
                Attribute::Uuid,
                Value::Uuid(uuid!("d2b496bd-8493-47b7-8142-f568b5cf47ee"))
            )
        );

        let preload = vec![ea];

        run_modify_test!(
            Ok(()),
            preload,
            filter!(f_eq(Attribute::Name, PartialValue::new_iutf8("testperson"))),
            ModifyList::new_list(vec![Modify::Present(
                Attribute::PasswordImport,
                Value::from(IMPORT_HASH)
            )]),
            None,
            |_| {},
            |_| {}
        );
    }

    #[test]
    fn test_modify_password_import_2() {
        let mut ea = entry_init!(
            (Attribute::Class, EntryClass::Account.to_value()),
            (Attribute::Class, EntryClass::Person.to_value()),
            (Attribute::Name, Value::new_iname("testperson")),
            (
                Attribute::Description,
                Value::Utf8("testperson".to_string())
            ),
            (
                Attribute::DisplayName,
                Value::Utf8("testperson".to_string())
            ),
            (
                Attribute::Uuid,
                Value::Uuid(uuid!("d2b496bd-8493-47b7-8142-f568b5cf47ee"))
            )
        );

        let p = CryptoPolicy::minimum();
        let c = Credential::new_password_only(&p, "password").unwrap();
        ea.add_ava(
            Attribute::PrimaryCredential,
            Value::new_credential("primary", c),
        );

        let preload = vec![ea];

        run_modify_test!(
            Ok(()),
            preload,
            filter!(f_eq(Attribute::Name, PartialValue::new_iutf8("testperson"))),
            ModifyList::new_list(vec![Modify::Present(
                Attribute::PasswordImport,
                Value::from(IMPORT_HASH)
            )]),
            None,
            |_| {},
            |_| {}
        );
    }

    #[test]
    fn test_modify_password_import_3_totp() {
        let mut ea = entry_init!(
            (Attribute::Class, EntryClass::Account.to_value()),
            (Attribute::Class, EntryClass::Person.to_value()),
            (Attribute::Name, Value::new_iname("testperson")),
            (
                Attribute::Description,
                Value::Utf8("testperson".to_string())
            ),
            (
                Attribute::DisplayName,
                Value::Utf8("testperson".to_string())
            ),
            (
                Attribute::Uuid,
                Value::Uuid(uuid!("d2b496bd-8493-47b7-8142-f568b5cf47ee"))
            )
        );

        let totp = Totp::generate_secure(TOTP_DEFAULT_STEP);
        let p = CryptoPolicy::minimum();
        let c = Credential::new_password_only(&p, "password")
            .unwrap()
            .append_totp("totp".to_string(), totp);
        ea.add_ava(
            Attribute::PrimaryCredential,
            Value::new_credential("primary", c),
        );

        let preload = vec![ea];

        run_modify_test!(
            Ok(()),
            preload,
            filter!(f_eq(Attribute::Name, PartialValue::new_iutf8("testperson"))),
            ModifyList::new_list(vec![Modify::Present(
                Attribute::PasswordImport,
                Value::from(IMPORT_HASH)
            )]),
            None,
            |_| {},
            |qs: &mut QueryServerWriteTransaction| {
                let e = qs
                    .internal_search_uuid(uuid!("d2b496bd-8493-47b7-8142-f568b5cf47ee"))
                    .expect("failed to get entry");
                let c = e
                    .get_ava_single_credential(Attribute::PrimaryCredential)
                    .expect("failed to get primary cred.");
                match &c.type_ {
                    CredentialType::PasswordMfa(_pw, totp, webauthn, backup_code) => {
                        assert_eq!(totp.len(), 1);
                        assert!(webauthn.is_empty());
                        assert!(backup_code.is_none());
                    }
                    _ => panic!("Oh no"),
                };
            }
        );
    }

    #[test]
    fn test_modify_cred_import_pw_and_multi_totp() {
        let euuid = Uuid::new_v4();

        let ea = entry_init!(
            (Attribute::Class, EntryClass::Account.to_value()),
            (Attribute::Class, EntryClass::Person.to_value()),
            (Attribute::Name, Value::new_iname("testperson")),
            (
                Attribute::Description,
                Value::Utf8("testperson".to_string())
            ),
            (
                Attribute::DisplayName,
                Value::Utf8("testperson".to_string())
            ),
            (Attribute::Uuid, Value::Uuid(euuid))
        );

        let preload = vec![ea];

        let totp_a = Totp::generate_secure(TOTP_DEFAULT_STEP);
        let totp_b = Totp::generate_secure(TOTP_DEFAULT_STEP);

        run_modify_test!(
            Ok(()),
            preload,
            filter!(f_eq(Attribute::Name, PartialValue::new_iutf8("testperson"))),
            ModifyList::new_list(vec![
                Modify::Present(
                    Attribute::PasswordImport,
                    Value::Utf8(IMPORT_HASH.to_string())
                ),
                Modify::Present(
                    Attribute::TotpImport,
                    Value::TotpSecret("a".to_string(), totp_a.clone())
                ),
                Modify::Present(
                    Attribute::TotpImport,
                    Value::TotpSecret("b".to_string(), totp_b.clone())
                )
            ]),
            None,
            |_| {},
            |qs: &mut QueryServerWriteTransaction| {
                let e = qs.internal_search_uuid(euuid).expect("failed to get entry");
                let c = e
                    .get_ava_single_credential(Attribute::PrimaryCredential)
                    .expect("failed to get primary cred.");
                match &c.type_ {
                    CredentialType::PasswordMfa(_pw, totp, webauthn, backup_code) => {
                        assert_eq!(totp.len(), 2);
                        assert!(webauthn.is_empty());
                        assert!(backup_code.is_none());

                        assert_eq!(totp.get("a"), Some(&totp_a));
                        assert_eq!(totp.get("b"), Some(&totp_b));
                    }
                    _ => panic!("Oh no"),
                };
            }
        );
    }

    #[test]
    fn test_modify_cred_import_pw_missing_with_totp() {
        let euuid = Uuid::new_v4();

        let ea = entry_init!(
            (Attribute::Class, EntryClass::Account.to_value()),
            (Attribute::Class, EntryClass::Person.to_value()),
            (Attribute::Name, Value::new_iname("testperson")),
            (
                Attribute::Description,
                Value::Utf8("testperson".to_string())
            ),
            (
                Attribute::DisplayName,
                Value::Utf8("testperson".to_string())
            ),
            (Attribute::Uuid, Value::Uuid(euuid))
        );

        let preload = vec![ea];

        let totp_a = Totp::generate_secure(TOTP_DEFAULT_STEP);

        run_modify_test!(
            Err(OperationError::Plugin(PluginError::CredImport(
                "totp_import can not be used if primary_credential (password) is missing"
                    .to_string()
            ))),
            preload,
            filter!(f_eq(Attribute::Name, PartialValue::new_iutf8("testperson"))),
            ModifyList::new_list(vec![Modify::Present(
                Attribute::TotpImport,
                Value::TotpSecret("a".to_string(), totp_a)
            )]),
            None,
            |_| {},
            |_| {}
        );
    }

    #[test]
    fn test_modify_unix_password_import() {
        let ea = entry_init!(
            (Attribute::Class, EntryClass::Account.to_value()),
            (Attribute::Class, EntryClass::PosixAccount.to_value()),
            (Attribute::Class, EntryClass::Person.to_value()),
            (Attribute::Name, Value::new_iname("testperson")),
            (
                Attribute::Description,
                Value::Utf8("testperson".to_string())
            ),
            (
                Attribute::DisplayName,
                Value::Utf8("testperson".to_string())
            ),
            (
                Attribute::Uuid,
                Value::Uuid(uuid!("d2b496bd-8493-47b7-8142-f568b5cf47ee"))
            )
        );

        let preload = vec![ea];

        run_modify_test!(
            Ok(()),
            preload,
            filter!(f_eq(Attribute::Name, PartialValue::new_iutf8("testperson"))),
            ModifyList::new_list(vec![Modify::Present(
                Attribute::UnixPasswordImport,
                Value::from(IMPORT_HASH)
            )]),
            None,
            |_| {},
            |qs: &mut QueryServerWriteTransaction| {
                let e = qs
                    .internal_search_uuid(uuid!("d2b496bd-8493-47b7-8142-f568b5cf47ee"))
                    .expect("failed to get entry");
                let c = e
                    .get_ava_single_credential(Attribute::UnixPassword)
                    .expect("failed to get unix cred.");

                assert!(matches!(&c.type_, CredentialType::Password(_pw)));
            }
        );
    }
}
