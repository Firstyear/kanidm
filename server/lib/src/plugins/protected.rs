// System protected objects. Items matching specific requirements
// may only have certain modifications performed.

use hashbrown::HashSet;
use std::sync::Arc;

use crate::event::{CreateEvent, DeleteEvent, ModifyEvent};
use crate::modify::Modify;
use crate::plugins::Plugin;
use crate::prelude::*;

pub struct Protected {}

// Here is the declaration of all the attrs that can be altered by
// a call on a system object. We trust they are allowed because
// schema will have checked this, and we don't allow class changes!

lazy_static! {
    static ref ALLOWED_ATTRS: HashSet<Attribute> = {
        let attrs = vec![
        // Allow modification of some schema class types to allow local extension
        // of schema types.
        Attribute::Must,
        Attribute::May,
        // modification of some domain info types for local configuratiomn.
        Attribute::DomainSsid,
        Attribute::DomainLdapBasedn,
        Attribute::LdapAllowUnixPwBind,
        Attribute::FernetPrivateKeyStr,
        Attribute::Es256PrivateKeyDer,
        Attribute::KeyActionRevoke,
        Attribute::KeyActionRotate,
        Attribute::IdVerificationEcKey,
        Attribute::BadlistPassword,
        Attribute::DeniedName,
        Attribute::DomainDisplayName,
        Attribute::Image,
        // modification of account policy values for dyngroup.
        Attribute::AuthSessionExpiry,
        Attribute::AuthPasswordMinimumLength,
        Attribute::CredentialTypeMinimum,
        Attribute::PrivilegeExpiry,
        Attribute::WebauthnAttestationCaList,
        ];

        let mut m = HashSet::with_capacity(attrs.len());
        m.extend(attrs);

        m
    };

    static ref PROTECTED_ENTRYCLASSES: Vec<EntryClass> =
        vec![
            EntryClass::System,
            EntryClass::DomainInfo,
            EntryClass::SystemInfo,
            EntryClass::SystemConfig,
            EntryClass::DynGroup,
            EntryClass::SyncObject,
            EntryClass::Tombstone,
            EntryClass::Recycled,
        ];
}

impl Plugin for Protected {
    fn id() -> &'static str {
        "plugin_protected"
    }

    #[instrument(level = "debug", name = "protected_pre_create", skip_all)]
    fn pre_create(
        _qs: &mut QueryServerWriteTransaction,
        // List of what we will commit that is valid?
        cand: &[Entry<EntrySealed, EntryNew>],
        ce: &CreateEvent,
    ) -> Result<(), OperationError> {
        if ce.ident.is_internal() {
            trace!("Internal operation, not enforcing system object protection");
            return Ok(());
        }

        cand.iter().try_fold((), |(), cand| {
            if PROTECTED_ENTRYCLASSES
                .iter()
                .any(|c| cand.attribute_equality(Attribute::Class, &c.to_partialvalue()))
            {
                trace!("Rejecting operation during pre_create check");
                Err(OperationError::SystemProtectedObject)
            } else {
                Ok(())
            }
        })
    }

    #[instrument(level = "debug", name = "protected_pre_modify", skip_all)]
    fn pre_modify(
        _qs: &mut QueryServerWriteTransaction,
        _pre_cand: &[Arc<EntrySealedCommitted>],
        cand: &mut Vec<EntryInvalidCommitted>,
        me: &ModifyEvent,
    ) -> Result<(), OperationError> {
        if me.ident.is_internal() {
            trace!("Internal operation, not enforcing system object protection");
            return Ok(());
        }
        // Prevent adding class: system, domain_info, tombstone, or recycled.
        me.modlist.iter().try_fold((), |(), m| match m {
            Modify::Present(a, v) => {
                if a == Attribute::Class.as_ref()
                    && PROTECTED_ENTRYCLASSES.iter().any(|c| v == &c.to_value())
                {
                    trace!("Rejecting operation during pre_modify check");
                    Err(OperationError::SystemProtectedObject)
                } else {
                    Ok(())
                }
            }
            _ => Ok(()),
        })?;

        // HARD block mods on tombstone or recycle. We soft block on the rest as they may
        // have some allowed attrs.
        cand.iter().try_fold((), |(), cand| {
            if cand.attribute_equality(Attribute::Class, &EntryClass::Tombstone.into())
                || cand.attribute_equality(Attribute::Class, &EntryClass::Recycled.into())
            {
                Err(OperationError::SystemProtectedObject)
            } else {
                Ok(())
            }
        })?;

        // if class: system, check the mods are "allowed"
        let system_pres = cand.iter().any(|c| {
            // We don't need to check for domain info here because domain_info has a class
            // system also. We just need to block it from being created.
            c.attribute_equality(Attribute::Class, &EntryClass::System.into())
        });

        trace!("class: system -> {}", system_pres);
        // No system types being altered, return.
        if !system_pres {
            return Ok(());
        }

        // Something altered is system, check if it's allowed.
        me.modlist.into_iter().try_fold((), |(), m| {
            // Already hit an error, move on.
            let a = match m {
                Modify::Present(a, _)
                | Modify::Removed(a, _)
                | Modify::Set(a, _)
                | Modify::Purged(a) => Some(a),
                Modify::Assert(_, _) => None,
            };
            if let Some(attr) = a {
                match ALLOWED_ATTRS.contains(attr) {
                    true => Ok(()),
                    false => {
                        trace!("If you're getting this, you need to modify the ALLOWED_ATTRS list");
                        Err(OperationError::SystemProtectedObject)
                    }
                }
            } else {
                // Was not a mod needing checking
                Ok(())
            }
        })
    }

    #[instrument(level = "debug", name = "protected_pre_batch_modify", skip_all)]
    fn pre_batch_modify(
        _qs: &mut QueryServerWriteTransaction,
        _pre_cand: &[Arc<EntrySealedCommitted>],
        cand: &mut Vec<EntryInvalidCommitted>,
        me: &BatchModifyEvent,
    ) -> Result<(), OperationError> {
        if me.ident.is_internal() {
            trace!("Internal operation, not enforcing system object protection");
            return Ok(());
        }

        me.modset
            .values()
            .flat_map(|ml| ml.iter())
            .try_fold((), |(), m| match m {
                Modify::Present(a, v) => {
                    if a == Attribute::Class.as_ref()
                        && PROTECTED_ENTRYCLASSES.iter().any(|c| v == &c.to_value())
                    {
                        trace!("Rejecting operation during pre_batch_modify check");
                        Err(OperationError::SystemProtectedObject)
                    } else {
                        Ok(())
                    }
                }
                _ => Ok(()),
            })?;

        // HARD block mods on tombstone or recycle. We soft block on the rest as they may
        // have some allowed attrs.
        cand.iter().try_fold((), |(), cand| {
            if cand.attribute_equality(Attribute::Class, &EntryClass::Tombstone.into())
                || cand.attribute_equality(Attribute::Class, &EntryClass::Recycled.into())
            {
                Err(OperationError::SystemProtectedObject)
            } else {
                Ok(())
            }
        })?;

        // if class: system, check the mods are "allowed"
        let system_pres = cand.iter().any(|c| {
            // We don't need to check for domain info here because domain_info has a class
            // system also. We just need to block it from being created.
            c.attribute_equality(Attribute::Class, &EntryClass::System.into())
        });

        trace!("{}: system -> {}", Attribute::Class, system_pres);
        // No system types being altered, return.
        if !system_pres {
            return Ok(());
        }

        // Something altered is system, check if it's allowed.
        me.modset
            .values()
            .flat_map(|ml| ml.iter())
            .try_fold((), |(), m| {
                // Already hit an error, move on.
                let a = match m {
                    Modify::Present(a, _) | Modify::Removed(a, _) | Modify::Set(a, _) | Modify::Purged(a) => Some(a),
                    Modify::Assert(_, _) => None,
                };
                if let Some(attr) = a {
                    match ALLOWED_ATTRS.contains(attr) {
                        true => Ok(()),
                        false => {

                        trace!("Rejecting operation during pre_batch_modify check, if you're getting this check ALLOWED_ATTRS");
                            Err(OperationError::SystemProtectedObject)
                        },
                    }
                } else {
                    // Was not a mod needing checking
                    Ok(())
                }
            })
    }

    #[instrument(level = "debug", name = "protected_pre_delete", skip_all)]
    fn pre_delete(
        _qs: &mut QueryServerWriteTransaction,
        // Should these be EntrySealed
        cand: &mut Vec<Entry<EntryInvalid, EntryCommitted>>,
        de: &DeleteEvent,
    ) -> Result<(), OperationError> {
        if de.ident.is_internal() {
            trace!("Internal operation, not enforcing system object protection");
            return Ok(());
        }

        cand.iter().try_fold((), |(), cand| {
            if PROTECTED_ENTRYCLASSES
                .iter()
                .any(|c| cand.attribute_equality(Attribute::Class, &c.to_partialvalue()))
            {
                trace!("Rejecting operation during pre_delete check");
                Err(OperationError::SystemProtectedObject)
            } else {
                Ok(())
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::prelude::*;
    use std::sync::Arc;

    const UUID_TEST_ACCOUNT: Uuid = uuid::uuid!("cc8e95b4-c24f-4d68-ba54-8bed76f63930");
    const UUID_TEST_GROUP: Uuid = uuid::uuid!("81ec1640-3637-4a2f-8a52-874fa3c3c92f");
    const UUID_TEST_ACP: Uuid = uuid::uuid!("acae81d6-5ea7-4bd8-8f7f-fcec4c0dd647");

    lazy_static! {
        pub static ref TEST_ACCOUNT: EntryInitNew = entry_init!(
            (Attribute::Class, EntryClass::Account.to_value()),
            (Attribute::Class, EntryClass::ServiceAccount.to_value()),
            (Attribute::Class, EntryClass::MemberOf.to_value()),
            (Attribute::Name, Value::new_iname("test_account_1")),
            (Attribute::DisplayName, Value::new_utf8s("test_account_1")),
            (Attribute::Uuid, Value::Uuid(UUID_TEST_ACCOUNT)),
            (Attribute::MemberOf, Value::Refer(UUID_TEST_GROUP))
        );
        pub static ref TEST_GROUP: EntryInitNew = entry_init!(
            (Attribute::Class, EntryClass::Group.to_value()),
            (Attribute::Name, Value::new_iname("test_group_a")),
            (Attribute::Uuid, Value::Uuid(UUID_TEST_GROUP)),
            (Attribute::Member, Value::Refer(UUID_TEST_ACCOUNT))
        );
        pub static ref ALLOW_ALL: EntryInitNew = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (
                Attribute::Class,
                EntryClass::AccessControlProfile.to_value()
            ),
            (
                Attribute::Class,
                EntryClass::AccessControlTargetScope.to_value()
            ),
            (
                Attribute::Class,
                EntryClass::AccessControlReceiverGroup.to_value()
            ),
            (Attribute::Class, EntryClass::AccessControlModify.to_value()),
            (Attribute::Class, EntryClass::AccessControlCreate.to_value()),
            (Attribute::Class, EntryClass::AccessControlDelete.to_value()),
            (Attribute::Class, EntryClass::AccessControlSearch.to_value()),
            (
                Attribute::Name,
                Value::new_iname("idm_admins_acp_allow_all_test")
            ),
            (Attribute::Uuid, Value::Uuid(UUID_TEST_ACP)),
            (Attribute::AcpReceiverGroup, Value::Refer(UUID_TEST_GROUP)),
            (
                Attribute::AcpTargetScope,
                Value::new_json_filter_s("{\"pres\":\"class\"}").expect("filter")
            ),
            (Attribute::AcpSearchAttr, Value::from(Attribute::Name)),
            (Attribute::AcpSearchAttr, Value::from(Attribute::Class)),
            (Attribute::AcpSearchAttr, Value::from(Attribute::Uuid)),
            (Attribute::AcpSearchAttr, Value::new_iutf8("classname")),
            (
                Attribute::AcpSearchAttr,
                Value::new_iutf8(Attribute::AttributeName.as_ref())
            ),
            (Attribute::AcpModifyClass, EntryClass::System.to_value()),
            (Attribute::AcpModifyClass, Value::new_iutf8("domain_info")),
            (
                Attribute::AcpModifyRemovedAttr,
                Value::from(Attribute::Class)
            ),
            (
                Attribute::AcpModifyRemovedAttr,
                Value::from(Attribute::DisplayName)
            ),
            (Attribute::AcpModifyRemovedAttr, Value::from(Attribute::May)),
            (
                Attribute::AcpModifyRemovedAttr,
                Value::from(Attribute::Must)
            ),
            (
                Attribute::AcpModifyRemovedAttr,
                Value::from(Attribute::DomainName)
            ),
            (
                Attribute::AcpModifyRemovedAttr,
                Value::from(Attribute::DomainDisplayName)
            ),
            (
                Attribute::AcpModifyRemovedAttr,
                Value::from(Attribute::DomainUuid)
            ),
            (
                Attribute::AcpModifyRemovedAttr,
                Value::from(Attribute::DomainSsid)
            ),
            (
                Attribute::AcpModifyRemovedAttr,
                Value::from(Attribute::FernetPrivateKeyStr)
            ),
            (
                Attribute::AcpModifyRemovedAttr,
                Value::from(Attribute::Es256PrivateKeyDer)
            ),
            (
                Attribute::AcpModifyRemovedAttr,
                Value::from(Attribute::PrivateCookieKey)
            ),
            (
                Attribute::AcpModifyPresentAttr,
                Value::from(Attribute::Class)
            ),
            (
                Attribute::AcpModifyPresentAttr,
                Value::from(Attribute::DisplayName)
            ),
            (Attribute::AcpModifyPresentAttr, Value::from(Attribute::May)),
            (
                Attribute::AcpModifyPresentAttr,
                Value::from(Attribute::Must)
            ),
            (
                Attribute::AcpModifyPresentAttr,
                Value::from(Attribute::DomainName)
            ),
            (
                Attribute::AcpModifyPresentAttr,
                Value::from(Attribute::DomainDisplayName)
            ),
            (
                Attribute::AcpModifyPresentAttr,
                Value::from(Attribute::DomainUuid)
            ),
            (
                Attribute::AcpModifyPresentAttr,
                Value::from(Attribute::DomainSsid)
            ),
            (
                Attribute::AcpModifyPresentAttr,
                Value::from(Attribute::FernetPrivateKeyStr)
            ),
            (
                Attribute::AcpModifyPresentAttr,
                Value::from(Attribute::Es256PrivateKeyDer)
            ),
            (
                Attribute::AcpModifyPresentAttr,
                Value::from(Attribute::PrivateCookieKey)
            ),
            (Attribute::AcpCreateClass, EntryClass::Object.to_value()),
            (Attribute::AcpCreateClass, EntryClass::Account.to_value()),
            (Attribute::AcpCreateClass, EntryClass::Person.to_value()),
            (Attribute::AcpCreateClass, EntryClass::System.to_value()),
            (Attribute::AcpCreateClass, EntryClass::DomainInfo.to_value()),
            (Attribute::AcpCreateAttr, Value::from(Attribute::Name)),
            (Attribute::AcpCreateAttr, EntryClass::Class.to_value(),),
            (
                Attribute::AcpCreateAttr,
                Value::from(Attribute::Description),
            ),
            (
                Attribute::AcpCreateAttr,
                Value::from(Attribute::DisplayName),
            ),
            (Attribute::AcpCreateAttr, Value::from(Attribute::DomainName),),
            (
                Attribute::AcpCreateAttr,
                Value::from(Attribute::DomainDisplayName)
            ),
            (Attribute::AcpCreateAttr, Value::from(Attribute::DomainUuid)),
            (Attribute::AcpCreateAttr, Value::from(Attribute::DomainSsid)),
            (Attribute::AcpCreateAttr, Value::from(Attribute::Uuid)),
            (
                Attribute::AcpCreateAttr,
                Value::from(Attribute::FernetPrivateKeyStr)
            ),
            (
                Attribute::AcpCreateAttr,
                Value::from(Attribute::Es256PrivateKeyDer)
            ),
            (
                Attribute::AcpCreateAttr,
                Value::from(Attribute::PrivateCookieKey)
            ),
            (Attribute::AcpCreateAttr, Value::from(Attribute::Version))
        );
        pub static ref PRELOAD: Vec<EntryInitNew> =
            vec![TEST_ACCOUNT.clone(), TEST_GROUP.clone(), ALLOW_ALL.clone()];
        pub static ref E_TEST_ACCOUNT: Arc<EntrySealedCommitted> =
            Arc::new(TEST_ACCOUNT.clone().into_sealed_committed());
    }

    #[test]
    fn test_pre_create_deny() {
        // Test creating with class: system is rejected.
        let e = entry_init!(
            (Attribute::Class, EntryClass::Account.to_value()),
            (Attribute::Class, EntryClass::Person.to_value()),
            (Attribute::Class, EntryClass::System.to_value()),
            (Attribute::Name, Value::new_iname("testperson")),
            (
                Attribute::DisplayName,
                Value::Utf8("testperson".to_string())
            )
        );

        let create = vec![e];
        let preload = PRELOAD.clone();

        run_create_test!(
            Err(OperationError::SystemProtectedObject),
            preload,
            create,
            Some(E_TEST_ACCOUNT.clone()),
            |_| {}
        );
    }

    #[test]
    fn test_pre_modify_system_deny() {
        // Test modify of class to a system is denied
        let e = entry_init!(
            (Attribute::Class, EntryClass::Account.to_value()),
            (Attribute::Class, EntryClass::Person.to_value()),
            (Attribute::Class, EntryClass::System.to_value()),
            (Attribute::Name, Value::new_iname("testperson")),
            (
                Attribute::DisplayName,
                Value::Utf8("testperson".to_string())
            )
        );

        let mut preload = PRELOAD.clone();
        preload.push(e);

        run_modify_test!(
            Err(OperationError::SystemProtectedObject),
            preload,
            filter!(f_eq(Attribute::Name, PartialValue::new_iname("testperson"))),
            modlist!([
                m_purge(Attribute::DisplayName),
                m_pres(Attribute::DisplayName, &Value::new_utf8s("system test")),
            ]),
            Some(E_TEST_ACCOUNT.clone()),
            |_| {},
            |_| {}
        );
    }

    #[test]
    fn test_pre_modify_class_add_deny() {
        // Show that adding a system class is denied
        // TODO: replace this with a `SchemaClass` object
        let e = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::ClassType.to_value()),
            (Attribute::ClassName, Value::new_iutf8("testclass")),
            (
                Attribute::Uuid,
                Value::Uuid(uuid::uuid!("66c68b2f-d02c-4243-8013-7946e40fe321"))
            ),
            (
                Attribute::Description,
                Value::Utf8("class test".to_string())
            )
        );
        let mut preload = PRELOAD.clone();
        preload.push(e);

        run_modify_test!(
            Ok(()),
            preload,
            filter!(f_eq(
                Attribute::ClassName,
                PartialValue::new_iutf8("testclass")
            )),
            modlist!([
                m_pres(Attribute::May, &Value::from(Attribute::Name)),
                m_pres(Attribute::Must, &Value::from(Attribute::Name)),
            ]),
            Some(E_TEST_ACCOUNT.clone()),
            |_| {},
            |_| {}
        );
    }

    #[test]
    fn test_pre_delete_deny() {
        // Test deleting with class: system is rejected.
        let e = entry_init!(
            (Attribute::Class, EntryClass::Account.to_value()),
            (Attribute::Class, EntryClass::Person.to_value()),
            (Attribute::Class, EntryClass::System.to_value()),
            (Attribute::Name, Value::new_iname("testperson")),
            (
                Attribute::DisplayName,
                Value::Utf8("testperson".to_string())
            )
        );

        let mut preload = PRELOAD.clone();
        preload.push(e);

        run_delete_test!(
            Err(OperationError::SystemProtectedObject),
            preload,
            filter!(f_eq(Attribute::Name, PartialValue::new_iname("testperson"))),
            Some(E_TEST_ACCOUNT.clone()),
            |_| {}
        );
    }

    #[test]
    fn test_modify_domain() {
        // Can edit *my* domain_ssid and domain_name
        // Show that adding a system class is denied
        let e = entry_init!(
            (Attribute::Class, EntryClass::DomainInfo.to_value()),
            (Attribute::Name, Value::new_iname("domain_example.net.au")),
            (Attribute::Uuid, Value::Uuid(uuid::uuid!("96fd1112-28bc-48ae-9dda-5acb4719aaba"))),
            (
                Attribute::Description,
                Value::new_utf8s("Demonstration of a remote domain's info being created for uuid generation in test_modify_domain")
            ),
            (Attribute::DomainUuid, Value::Uuid(uuid::uuid!("96fd1112-28bc-48ae-9dda-5acb4719aaba"))),
            (Attribute::DomainName, Value::new_iname("example.net.au")),
            (Attribute::DomainDisplayName, Value::Utf8("example.net.au".to_string())),
            (Attribute::DomainSsid, Value::Utf8("Example_Wifi".to_string())),
            (Attribute::Version, Value::Uint32(1))
        );

        let mut preload = PRELOAD.clone();
        preload.push(e);

        run_modify_test!(
            Ok(()),
            preload,
            filter!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("domain_example.net.au")
            )),
            modlist!([
                m_purge(Attribute::DomainSsid),
                m_pres(Attribute::DomainSsid, &Value::new_utf8s("NewExampleWifi")),
            ]),
            Some(E_TEST_ACCOUNT.clone()),
            |_| {},
            |_| {}
        );
    }

    #[test]
    fn test_ext_create_domain() {
        // can not add a domain_info type - note the lack of class: system
        let e = entry_init!(
            (Attribute::Class, EntryClass::DomainInfo.to_value()),
            (Attribute::Name, Value::new_iname("domain_example.net.au")),
            (Attribute::Uuid, Value::Uuid(uuid::uuid!("96fd1112-28bc-48ae-9dda-5acb4719aaba"))),
            (
                Attribute::Description,
                Value::new_utf8s("Demonstration of a remote domain's info being created for uuid generation in test_modify_domain")
            ),
            (Attribute::DomainUuid, Value::Uuid(uuid::uuid!("96fd1112-28bc-48ae-9dda-5acb4719aaba"))),
            (Attribute::DomainName, Value::new_iname("example.net.au")),
            (Attribute::DomainDisplayName, Value::Utf8("example.net.au".to_string())),
            (Attribute::DomainSsid, Value::Utf8("Example_Wifi".to_string())),
            (Attribute::Version, Value::Uint32(1))
        );

        let create = vec![e];
        let preload = PRELOAD.clone();

        run_create_test!(
            Err(OperationError::SystemProtectedObject),
            preload,
            create,
            Some(E_TEST_ACCOUNT.clone()),
            |_| {}
        );
    }

    #[test]
    fn test_delete_domain() {
        // On the real thing we have a class: system, but to prove the point ...
        let e = entry_init!(
            (Attribute::Class, EntryClass::DomainInfo.to_value()),
            (Attribute::Name, Value::new_iname("domain_example.net.au")),
            (Attribute::Uuid, Value::Uuid(uuid::uuid!("96fd1112-28bc-48ae-9dda-5acb4719aaba"))),
            (
                Attribute::Description,
                Value::new_utf8s("Demonstration of a remote domain's info being created for uuid generation in test_modify_domain")
            ),
            (Attribute::DomainUuid, Value::Uuid(uuid::uuid!("96fd1112-28bc-48ae-9dda-5acb4719aaba"))),
            (Attribute::DomainName, Value::new_iname("example.net.au")),
            (Attribute::DomainDisplayName, Value::Utf8("example.net.au".to_string())),
            (Attribute::DomainSsid, Value::Utf8("Example_Wifi".to_string())),
            (Attribute::Version, Value::Uint32(1))
        );

        let mut preload = PRELOAD.clone();
        preload.push(e);

        run_delete_test!(
            Err(OperationError::SystemProtectedObject),
            preload,
            filter!(f_eq(
                Attribute::Name,
                PartialValue::new_iname("domain_example.net.au")
            )),
            Some(E_TEST_ACCOUNT.clone()),
            |_| {}
        );
    }
}
