#![allow(clippy::expect_used)]
//! Constant Entries for the IDM

use crate::constants::uuids::*;
use crate::entry::EntryInitNew;
use crate::prelude::*;
use crate::value::Value;
use kanidm_proto::internal::Filter as ProtoFilter;

lazy_static! {
    /// either recycled or tombstone
    pub static ref FILTER_RECYCLED_OR_TOMBSTONE: ProtoFilter = ProtoFilter::Or(vec![
        match_class_filter!(EntryClass::Recycled),
        match_class_filter!(EntryClass::Tombstone),
    ]);

    /// not either recycled or tombstone
    pub static ref FILTER_ANDNOT_TOMBSTONE_OR_RECYCLED: ProtoFilter =
        ProtoFilter::AndNot(Box::new(FILTER_RECYCLED_OR_TOMBSTONE.clone()));

    /// members of 000000001000 / idm_high_privilege
    pub static ref FILTER_HP: ProtoFilter = ProtoFilter::Eq(
        Attribute::MemberOf.to_string(),
        UUID_IDM_HIGH_PRIVILEGE.to_string(),
    );

    /// OR ( HP, Recycled, Tombstone)
    pub static ref FILTER_HP_OR_RECYCLED_OR_TOMBSTONE: ProtoFilter = ProtoFilter::Or(vec![
        FILTER_HP.clone(),
        match_class_filter!(EntryClass::Recycled),
        match_class_filter!(EntryClass::Tombstone),
    ]);

    pub static ref FILTER_ANDNOT_HP_OR_RECYCLED_OR_TOMBSTONE: ProtoFilter =
        ProtoFilter::AndNot(Box::new(FILTER_HP_OR_RECYCLED_OR_TOMBSTONE.clone()));

    pub static ref DEFAULT_TARGET_SCOPE: ProtoFilter = ProtoFilter::And(Vec::with_capacity(0));

}

#[derive(Clone, Debug, Default)]
/// Who will receive the privileges of this ACP.
pub enum BuiltinAcpReceiver {
    #[default]
    None,
    /// This functions as an "OR" condition, that membership of *at least one* of these UUIDs
    /// is sufficient for you to receive the access control.
    Group(Vec<Uuid>),
    EntryManager,
}

#[derive(Clone, Debug, Default)]
/// Objects that are affected by the rules of this ACP.
pub enum BuiltinAcpTarget {
    #[default]
    None,
    // Self,
    Filter(ProtoFilter),
    // MemberOf ( Uuid ),
}

#[derive(Clone, Debug, Default)]
/// Built-in Access Control Profile definitions
pub struct BuiltinAcp {
    classes: Vec<EntryClass>,
    pub name: &'static str,
    uuid: Uuid,
    description: &'static str,
    receiver: BuiltinAcpReceiver,
    target: BuiltinAcpTarget,
    search_attrs: Vec<Attribute>,
    modify_present_attrs: Vec<Attribute>,
    modify_removed_attrs: Vec<Attribute>,
    modify_classes: Vec<EntryClass>,
    modify_present_classes: Vec<EntryClass>,
    modify_remove_classes: Vec<EntryClass>,
    create_classes: Vec<EntryClass>,
    create_attrs: Vec<Attribute>,
}

impl From<BuiltinAcp> for EntryInitNew {
    #[allow(clippy::panic)]
    fn from(value: BuiltinAcp) -> Self {
        let mut entry = EntryInitNew::default();

        #[allow(clippy::panic)]
        if value.name.is_empty() {
            panic!("Builtin ACP has no name! {:?}", value);
        }
        #[allow(clippy::panic)]
        if value.classes.is_empty() {
            panic!("Builtin ACP has no classes! {:?}", value);
        }

        value.classes.iter().for_each(|class| {
            entry.add_ava(Attribute::Class, class.to_value());
        });

        entry.set_ava(Attribute::Name, [Value::new_iname(value.name)]);

        if value.uuid >= DYNAMIC_RANGE_MINIMUM_UUID {
            panic!("Builtin ACP has invalid UUID! {:?}", value);
        }

        entry.set_ava(Attribute::Uuid, [Value::Uuid(value.uuid)]);
        entry.set_ava(
            Attribute::Description,
            [Value::new_utf8s(value.description)],
        );

        match &value.receiver {
            #[allow(clippy::panic)]
            BuiltinAcpReceiver::None => {
                panic!("Builtin ACP has no receiver! {:?}", &value);
            }
            BuiltinAcpReceiver::Group(list) => {
                entry.add_ava(
                    Attribute::Class,
                    EntryClass::AccessControlReceiverGroup.to_value(),
                );
                for group in list {
                    entry.set_ava(Attribute::AcpReceiverGroup, [Value::Refer(*group)]);
                }
            }
            BuiltinAcpReceiver::EntryManager => {
                entry.add_ava(
                    Attribute::Class,
                    EntryClass::AccessControlReceiverEntryManager.to_value(),
                );
            }
        };

        match &value.target {
            #[allow(clippy::panic)]
            BuiltinAcpTarget::None => {
                panic!("Builtin ACP has no target! {:?}", &value);
            }
            BuiltinAcpTarget::Filter(proto_filter) => {
                entry.add_ava(
                    Attribute::Class,
                    EntryClass::AccessControlTargetScope.to_value(),
                );
                entry.set_ava(
                    Attribute::AcpTargetScope,
                    [Value::JsonFilt(proto_filter.clone())],
                );
            }
        }

        entry.set_ava(
            Attribute::AcpSearchAttr,
            value
                .search_attrs
                .into_iter()
                .map(Value::from)
                .collect::<Vec<Value>>(),
        );
        value.modify_present_attrs.into_iter().for_each(|attr| {
            entry.add_ava(Attribute::AcpModifyPresentAttr, Value::from(attr));
        });
        value.modify_removed_attrs.into_iter().for_each(|attr| {
            entry.add_ava(Attribute::AcpModifyRemovedAttr, Value::from(attr));
        });

        value.modify_classes.into_iter().for_each(|class| {
            entry.add_ava(Attribute::AcpModifyClass, Value::from(class));
        });

        value.modify_present_classes.into_iter().for_each(|class| {
            entry.add_ava(Attribute::AcpModifyPresentClass, Value::from(class));
        });

        value.modify_remove_classes.into_iter().for_each(|class| {
            entry.add_ava(Attribute::AcpModifyRemoveClass, Value::from(class));
        });

        value.create_classes.into_iter().for_each(|class| {
            entry.add_ava(Attribute::AcpCreateClass, Value::from(class));
        });
        value.create_attrs.into_iter().for_each(|attr| {
            entry.add_ava(Attribute::AcpCreateAttr, Value::from(attr));
        });
        entry
    }
}

lazy_static! {
    pub static ref IDM_ACP_RECYCLE_BIN_SEARCH_V1: BuiltinAcp = BuiltinAcp {
        uuid: UUID_IDM_ACP_RECYCLE_BIN_SEARCH_V1,
        name: "idm_acp_recycle_bin_search",
        description: "Builtin IDM recycle bin search permission.",
        classes: vec![
            EntryClass::Object,
            EntryClass::AccessControlProfile,
            EntryClass::AccessControlSearch,
        ],
        receiver: BuiltinAcpReceiver::Group(vec![UUID_IDM_RECYCLE_BIN_ADMINS]),
        target: BuiltinAcpTarget::Filter(ProtoFilter::Eq(
            Attribute::Class.to_string(),
            ATTR_RECYCLED.to_string()
        )),

        search_attrs: vec![
            Attribute::Class,
            Attribute::Name,
            Attribute::Uuid,
            Attribute::LastModifiedCid,
        ],
        ..Default::default()
    };
}

lazy_static! {
    pub static ref IDM_ACP_RECYCLE_BIN_REVIVE_V1: BuiltinAcp = BuiltinAcp {
        uuid: UUID_IDM_ACP_RECYCLE_BIN_REVIVE_V1,
        name: "idm_acp_recycle_bin_revive",
        description: "Builtin IDM recycle bin revive permission.",
        classes: vec![
            EntryClass::Object,
            EntryClass::AccessControlProfile,
            EntryClass::AccessControlModify,
        ],
        receiver: BuiltinAcpReceiver::Group(vec![UUID_IDM_RECYCLE_BIN_ADMINS]),
        target: BuiltinAcpTarget::Filter(ProtoFilter::Eq(
            Attribute::Class.to_string(),
            ATTR_RECYCLED.to_string()
        )),
        modify_removed_attrs: vec![Attribute::Class],
        modify_remove_classes: vec![EntryClass::Recycled],
        ..Default::default()
    };
}

lazy_static! {
    pub static ref IDM_ACP_SCHEMA_WRITE_ATTRS_V1: BuiltinAcp = BuiltinAcp{
        classes: vec![
            EntryClass::Object,
            EntryClass::AccessControlProfile,
            EntryClass::AccessControlCreate,
            EntryClass::AccessControlModify,
            EntryClass::AccessControlSearch
        ],
        name: "idm_acp_schema_write_attrs",
        uuid: UUID_IDM_ACP_SCHEMA_WRITE_ATTRS_V1,
        description: "Builtin IDM Control for management of schema attributes.",
        receiver: BuiltinAcpReceiver::Group ( vec![UUID_IDM_SCHEMA_ADMINS] ),
        // has a class, and isn't recycled/tombstoned
        target: BuiltinAcpTarget::Filter( ProtoFilter::And(vec![
            ProtoFilter::Eq(EntryClass::Class.to_string(),EntryClass::AttributeType.to_string()),
            FILTER_ANDNOT_TOMBSTONE_OR_RECYCLED.clone()
        ])),
        search_attrs: vec![
            Attribute::Class,
            Attribute::Description,
            Attribute::Index,
            Attribute::Unique,
            Attribute::MultiValue,
            Attribute::AttributeName,
            Attribute::Syntax,
            Attribute::Uuid,
        ],
        modify_removed_attrs: vec![
            Attribute::Description,
            Attribute::Index,
            Attribute::Unique,
            Attribute::MultiValue,
            Attribute::Syntax,
        ],
        modify_present_attrs: vec![
            Attribute::Description,
            Attribute::Index,
            Attribute::Unique,
            Attribute::MultiValue,
            Attribute::Syntax,
        ],
        create_attrs: vec![
            Attribute::Class,
            Attribute::Description,
            Attribute::Index,
            Attribute::Unique,
            Attribute::MultiValue,
            Attribute::AttributeName,
            Attribute::Syntax,
            Attribute::Uuid,
        ],
        create_classes: vec![
            EntryClass::Object,
            EntryClass::AttributeType,
        ],
        ..Default::default()
    };
}

lazy_static! {
    pub static ref IDM_ACP_SCHEMA_WRITE_CLASSES_V1: BuiltinAcp = BuiltinAcp {
        classes: vec![
            EntryClass::Object,
            EntryClass::AccessControlProfile,
            EntryClass::AccessControlCreate,
            EntryClass::AccessControlModify,
            EntryClass::AccessControlSearch
        ],
        name: "idm_acp_schema_write_classes",
        uuid: UUID_IDM_ACP_SCHEMA_WRITE_CLASSES_V1,
        description: "Builtin IDM Control for management of schema classes.",
        receiver: BuiltinAcpReceiver::Group(vec![UUID_IDM_SCHEMA_ADMINS]),
        target: BuiltinAcpTarget::Filter(ProtoFilter::And(vec![
            ProtoFilter::Eq(
                EntryClass::Class.to_string(),
                EntryClass::ClassType.to_string()
            ),
            FILTER_ANDNOT_TOMBSTONE_OR_RECYCLED.clone()
        ])),
        search_attrs: vec![
            Attribute::Class,
            Attribute::ClassName,
            Attribute::Description,
            Attribute::SystemMay,
            Attribute::May,
            Attribute::SystemMust,
            Attribute::Must,
            Attribute::Uuid,
        ],
        modify_removed_attrs: vec![
            Attribute::Class,
            Attribute::Description,
            Attribute::May,
            Attribute::Must,
        ],
        modify_present_attrs: vec![
            Attribute::Name,
            Attribute::Description,
            Attribute::May,
            Attribute::Must,
        ],
        create_attrs: vec![
            Attribute::Class,
            Attribute::ClassName,
            Attribute::Description,
            Attribute::May,
            Attribute::Must,
            Attribute::Uuid,
        ],
        create_classes: vec![EntryClass::Object, EntryClass::ClassType,],
        ..Default::default()
    };
}

lazy_static! {
    pub static ref IDM_ACP_ACP_MANAGE_V1: BuiltinAcp = BuiltinAcp {
        classes: vec![
            EntryClass::Object,
            EntryClass::AccessControlProfile,
            EntryClass::AccessControlCreate,
            EntryClass::AccessControlDelete,
            EntryClass::AccessControlModify,
            EntryClass::AccessControlSearch
        ],
        name: "idm_acp_acp_manage",
        uuid: UUID_IDM_ACP_ACP_MANAGE_V1,
        description: "Builtin IDM Control for access profiles management.",
        receiver: BuiltinAcpReceiver::Group(vec![UUID_IDM_ACCESS_CONTROL_ADMINS]),
        target: BuiltinAcpTarget::Filter(ProtoFilter::And(vec![
            ProtoFilter::Eq(
                EntryClass::Class.to_string(),
                EntryClass::AccessControlProfile.to_string()
            ),
            FILTER_ANDNOT_TOMBSTONE_OR_RECYCLED.clone()
        ])),
        search_attrs: vec![
            Attribute::Class,
            Attribute::Name,
            Attribute::Description,
            Attribute::AcpEnable,
            Attribute::AcpReceiverGroup,
            Attribute::AcpTargetScope,
            Attribute::AcpSearchAttr,
            Attribute::AcpModifyRemovedAttr,
            Attribute::AcpModifyPresentAttr,
            Attribute::AcpModifyClass,
            Attribute::AcpCreateClass,
            Attribute::AcpCreateAttr,
        ],
        modify_removed_attrs: vec![
            Attribute::Class,
            Attribute::Name,
            Attribute::Description,
            Attribute::AcpEnable,
            Attribute::AcpReceiverGroup,
            Attribute::AcpTargetScope,
            Attribute::AcpSearchAttr,
            Attribute::AcpModifyRemovedAttr,
            Attribute::AcpModifyPresentAttr,
            Attribute::AcpModifyClass,
            Attribute::AcpCreateClass,
            Attribute::AcpCreateAttr,
        ],
        modify_present_attrs: vec![
            Attribute::Class,
            Attribute::Name,
            Attribute::Description,
            Attribute::AcpEnable,
            Attribute::AcpReceiverGroup,
            Attribute::AcpTargetScope,
            Attribute::AcpSearchAttr,
            Attribute::AcpModifyRemovedAttr,
            Attribute::AcpModifyPresentAttr,
            Attribute::AcpModifyClass,
            Attribute::AcpCreateClass,
            Attribute::AcpCreateAttr,
        ],
        create_attrs: vec![
            Attribute::Class,
            Attribute::Name,
            Attribute::Description,
            Attribute::AcpEnable,
            Attribute::AcpReceiverGroup,
            Attribute::AcpTargetScope,
            Attribute::AcpSearchAttr,
            Attribute::AcpModifyRemovedAttr,
            Attribute::AcpModifyPresentAttr,
            Attribute::AcpModifyClass,
            Attribute::AcpCreateClass,
            Attribute::AcpCreateAttr,
        ],
        modify_classes: vec![
            EntryClass::AccessControlProfile,
            EntryClass::AccessControlSearch,
            EntryClass::AccessControlModify,
            EntryClass::AccessControlCreate,
            EntryClass::AccessControlDelete,
        ],
        create_classes: vec![
            EntryClass::AccessControlProfile,
            EntryClass::AccessControlSearch,
            EntryClass::AccessControlModify,
            EntryClass::AccessControlCreate,
            EntryClass::AccessControlDelete,
        ],
        ..Default::default()
    };
}

lazy_static! {
    pub static ref IDM_ACP_GROUP_READ_V1: BuiltinAcp = BuiltinAcp {
        classes: vec![
            EntryClass::Object,
            EntryClass::AccessControlProfile,
            EntryClass::AccessControlSearch
        ],
        name: "idm_acp_group_read",
        uuid: UUID_IDM_ACP_GROUP_READ,
        description:
            "Builtin IDM Control for allowing all groups to be read by access control admins",
        receiver: BuiltinAcpReceiver::Group(vec![
            UUID_IDM_ACCESS_CONTROL_ADMINS,
            // UUID_IDM_SERVICE_DESK,
            // UUID_IDM_PEOPLE_ADMINS,
        ]),
        target: BuiltinAcpTarget::Filter(ProtoFilter::And(vec![
            match_class_filter!(EntryClass::Group),
            FILTER_ANDNOT_TOMBSTONE_OR_RECYCLED.clone(),
        ])),
        search_attrs: vec![
            Attribute::Class,
            Attribute::DynMember,
            Attribute::Name,
            Attribute::Uuid,
            Attribute::Spn,
            Attribute::Description,
            Attribute::Member,
            Attribute::EntryManagedBy,
        ],
        ..Default::default()
    };
}

lazy_static! {
    pub static ref IDM_ACP_GROUP_ENTRY_MANAGED_BY_MODIFY_V1: BuiltinAcp = BuiltinAcp {
        classes: vec![
            EntryClass::Object,
            EntryClass::AccessControlProfile,
            EntryClass::AccessControlModify,
            EntryClass::AccessControlSearch
        ],
        name: "idm_acp_group_entry_managed_by_modify",
        uuid: UUID_IDM_ACP_GROUP_ENTRY_MANAGED_BY_MODIFY,
        description: "Builtin IDM Control for allowing entry_managed_by to be set on group entries",
        receiver: BuiltinAcpReceiver::Group(vec![UUID_IDM_ACCESS_CONTROL_ADMINS]),
        target: BuiltinAcpTarget::Filter(ProtoFilter::And(vec![
            match_class_filter!(EntryClass::Group),
            FILTER_ANDNOT_HP_OR_RECYCLED_OR_TOMBSTONE.clone(),
        ])),
        search_attrs: vec![
            Attribute::Class,
            Attribute::Name,
            Attribute::Spn,
            Attribute::Uuid,
            Attribute::EntryManagedBy,
        ],
        modify_removed_attrs: vec![Attribute::EntryManagedBy],
        modify_present_attrs: vec![Attribute::EntryManagedBy],
        ..Default::default()
    };
}

lazy_static! {
    pub static ref IDM_ACP_GROUP_ACCOUNT_POLICY_MANAGE_DL6: BuiltinAcp = BuiltinAcp {
        classes: vec![
            EntryClass::Object,
            EntryClass::AccessControlProfile,
            EntryClass::AccessControlModify,
            EntryClass::AccessControlSearch
        ],
        name: "idm_acp_group_account_policy_manage",
        uuid: UUID_IDM_ACP_GROUP_ACCOUNT_POLICY_MANAGE,
        description: "Builtin IDM Control for management of account policy on groups",
        receiver: BuiltinAcpReceiver::Group(vec![UUID_IDM_ACCOUNT_POLICY_ADMINS]),
        target: BuiltinAcpTarget::Filter(ProtoFilter::And(vec![
            match_class_filter!(EntryClass::Group),
            FILTER_ANDNOT_TOMBSTONE_OR_RECYCLED.clone()
        ])),
        search_attrs: vec![
            Attribute::Class,
            Attribute::Name,
            Attribute::Uuid,
            Attribute::AuthSessionExpiry,
            Attribute::AuthPasswordMinimumLength,
            Attribute::CredentialTypeMinimum,
            Attribute::PrivilegeExpiry,
            Attribute::WebauthnAttestationCaList,
            Attribute::LimitSearchMaxResults,
            Attribute::LimitSearchMaxFilterTest,
        ],
        modify_removed_attrs: vec![
            Attribute::Class,
            Attribute::AuthSessionExpiry,
            Attribute::AuthPasswordMinimumLength,
            Attribute::CredentialTypeMinimum,
            Attribute::PrivilegeExpiry,
            Attribute::WebauthnAttestationCaList,
            Attribute::LimitSearchMaxResults,
            Attribute::LimitSearchMaxFilterTest,
        ],
        modify_present_attrs: vec![
            Attribute::Class,
            Attribute::AuthSessionExpiry,
            Attribute::AuthPasswordMinimumLength,
            Attribute::CredentialTypeMinimum,
            Attribute::PrivilegeExpiry,
            Attribute::WebauthnAttestationCaList,
            Attribute::LimitSearchMaxResults,
            Attribute::LimitSearchMaxFilterTest,
        ],
        modify_classes: vec![EntryClass::AccountPolicy,],
        ..Default::default()
    };
}

lazy_static! {
    pub static ref IDM_ACP_GROUP_ACCOUNT_POLICY_MANAGE_DL8: BuiltinAcp = BuiltinAcp {
        classes: vec![
            EntryClass::Object,
            EntryClass::AccessControlProfile,
            EntryClass::AccessControlModify,
            EntryClass::AccessControlSearch
        ],
        name: "idm_acp_group_account_policy_manage",
        uuid: UUID_IDM_ACP_GROUP_ACCOUNT_POLICY_MANAGE,
        description: "Builtin IDM Control for management of account policy on groups",
        receiver: BuiltinAcpReceiver::Group(vec![UUID_IDM_ACCOUNT_POLICY_ADMINS]),
        target: BuiltinAcpTarget::Filter(ProtoFilter::And(vec![
            match_class_filter!(EntryClass::Group),
            FILTER_ANDNOT_TOMBSTONE_OR_RECYCLED.clone()
        ])),
        search_attrs: vec![
            Attribute::Class,
            Attribute::Name,
            Attribute::Uuid,
            Attribute::AuthSessionExpiry,
            Attribute::AuthPasswordMinimumLength,
            Attribute::CredentialTypeMinimum,
            Attribute::PrivilegeExpiry,
            Attribute::WebauthnAttestationCaList,
            Attribute::LimitSearchMaxResults,
            Attribute::LimitSearchMaxFilterTest,
            Attribute::AllowPrimaryCredFallback,
        ],
        modify_removed_attrs: vec![
            Attribute::Class,
            Attribute::AuthSessionExpiry,
            Attribute::AuthPasswordMinimumLength,
            Attribute::CredentialTypeMinimum,
            Attribute::PrivilegeExpiry,
            Attribute::WebauthnAttestationCaList,
            Attribute::LimitSearchMaxResults,
            Attribute::LimitSearchMaxFilterTest,
            Attribute::AllowPrimaryCredFallback,
        ],
        modify_present_attrs: vec![
            Attribute::Class,
            Attribute::AuthSessionExpiry,
            Attribute::AuthPasswordMinimumLength,
            Attribute::CredentialTypeMinimum,
            Attribute::PrivilegeExpiry,
            Attribute::WebauthnAttestationCaList,
            Attribute::LimitSearchMaxResults,
            Attribute::LimitSearchMaxFilterTest,
            Attribute::AllowPrimaryCredFallback,
        ],
        modify_classes: vec![EntryClass::AccountPolicy,],
        ..Default::default()
    };
}

lazy_static! {
    pub static ref IDM_ACP_OAUTH2_MANAGE_DL4: BuiltinAcp = BuiltinAcp {
        classes: vec![
            EntryClass::Object,
            EntryClass::AccessControlProfile,
            EntryClass::AccessControlCreate,
            EntryClass::AccessControlDelete,
            EntryClass::AccessControlModify,
            EntryClass::AccessControlSearch
        ],
        name: "idm_acp_hp_oauth2_manage_priv",
        uuid: UUID_IDM_ACP_OAUTH2_MANAGE_V1,
        description: "Builtin IDM Control for managing oauth2 resource server integrations.",
        receiver: BuiltinAcpReceiver::Group(vec![UUID_IDM_OAUTH2_ADMINS]),
        target: BuiltinAcpTarget::Filter(ProtoFilter::And(vec![
            match_class_filter!(EntryClass::OAuth2ResourceServer),
            FILTER_ANDNOT_TOMBSTONE_OR_RECYCLED.clone(),
        ])),
        search_attrs: vec![
            Attribute::Class,
            Attribute::Description,
            Attribute::DisplayName,
            Attribute::OAuth2RsName,
            Attribute::OAuth2RsOrigin,
            Attribute::OAuth2RsOriginLanding,
            Attribute::OAuth2RsScopeMap,
            Attribute::OAuth2RsSupScopeMap,
            Attribute::OAuth2RsBasicSecret,
            Attribute::OAuth2RsTokenKey,
            Attribute::Es256PrivateKeyDer,
            Attribute::OAuth2AllowInsecureClientDisablePkce,
            Attribute::Rs256PrivateKeyDer,
            Attribute::OAuth2JwtLegacyCryptoEnable,
            Attribute::OAuth2PreferShortUsername,
            Attribute::OAuth2AllowLocalhostRedirect,
            Attribute::OAuth2RsClaimMap,
            Attribute::Image,
        ],
        modify_removed_attrs: vec![
            Attribute::Description,
            Attribute::DisplayName,
            Attribute::OAuth2RsName,
            Attribute::OAuth2RsOrigin,
            Attribute::OAuth2RsOriginLanding,
            Attribute::OAuth2RsScopeMap,
            Attribute::OAuth2RsSupScopeMap,
            Attribute::OAuth2RsBasicSecret,
            Attribute::OAuth2RsTokenKey,
            Attribute::Es256PrivateKeyDer,
            Attribute::OAuth2AllowInsecureClientDisablePkce,
            Attribute::Rs256PrivateKeyDer,
            Attribute::OAuth2JwtLegacyCryptoEnable,
            Attribute::OAuth2PreferShortUsername,
            Attribute::OAuth2AllowLocalhostRedirect,
            Attribute::OAuth2RsClaimMap,
            Attribute::Image,
        ],
        modify_present_attrs: vec![
            Attribute::Description,
            Attribute::DisplayName,
            Attribute::OAuth2RsName,
            Attribute::OAuth2RsOrigin,
            Attribute::OAuth2RsOriginLanding,
            Attribute::OAuth2RsSupScopeMap,
            Attribute::OAuth2RsScopeMap,
            Attribute::OAuth2AllowInsecureClientDisablePkce,
            Attribute::OAuth2JwtLegacyCryptoEnable,
            Attribute::OAuth2PreferShortUsername,
            Attribute::OAuth2AllowLocalhostRedirect,
            Attribute::OAuth2RsClaimMap,
            Attribute::Image,
        ],
        create_attrs: vec![
            Attribute::Class,
            Attribute::Description,
            Attribute::DisplayName,
            Attribute::OAuth2RsName,
            Attribute::OAuth2RsOrigin,
            Attribute::OAuth2RsOriginLanding,
            Attribute::OAuth2RsSupScopeMap,
            Attribute::OAuth2RsScopeMap,
            Attribute::OAuth2AllowInsecureClientDisablePkce,
            Attribute::OAuth2JwtLegacyCryptoEnable,
            Attribute::OAuth2PreferShortUsername,
            Attribute::OAuth2AllowLocalhostRedirect,
            Attribute::OAuth2RsClaimMap,
            Attribute::Image,
        ],
        create_classes: vec![
            EntryClass::Object,
            EntryClass::OAuth2ResourceServer,
            EntryClass::OAuth2ResourceServerBasic,
            EntryClass::OAuth2ResourceServerPublic,
        ],
        ..Default::default()
    };
}

lazy_static! {
    pub static ref IDM_ACP_OAUTH2_MANAGE_DL5: BuiltinAcp = BuiltinAcp {
        classes: vec![
            EntryClass::Object,
            EntryClass::AccessControlProfile,
            EntryClass::AccessControlCreate,
            EntryClass::AccessControlDelete,
            EntryClass::AccessControlModify,
            EntryClass::AccessControlSearch
        ],
        name: "idm_acp_hp_oauth2_manage_priv",
        uuid: UUID_IDM_ACP_OAUTH2_MANAGE_V1,
        description: "Builtin IDM Control for managing oauth2 resource server integrations.",
        receiver: BuiltinAcpReceiver::Group(vec![UUID_IDM_OAUTH2_ADMINS]),
        target: BuiltinAcpTarget::Filter(ProtoFilter::And(vec![
            match_class_filter!(EntryClass::OAuth2ResourceServer),
            FILTER_ANDNOT_TOMBSTONE_OR_RECYCLED.clone(),
        ])),
        search_attrs: vec![
            Attribute::Class,
            Attribute::Description,
            Attribute::DisplayName,
            Attribute::Name,
            Attribute::Spn,
            Attribute::OAuth2Session,
            Attribute::OAuth2RsOrigin,
            Attribute::OAuth2RsOriginLanding,
            Attribute::OAuth2RsScopeMap,
            Attribute::OAuth2RsSupScopeMap,
            Attribute::OAuth2RsBasicSecret,
            Attribute::OAuth2RsTokenKey,
            Attribute::Es256PrivateKeyDer,
            Attribute::OAuth2AllowInsecureClientDisablePkce,
            Attribute::Rs256PrivateKeyDer,
            Attribute::OAuth2JwtLegacyCryptoEnable,
            Attribute::OAuth2PreferShortUsername,
            Attribute::OAuth2AllowLocalhostRedirect,
            Attribute::OAuth2RsClaimMap,
            Attribute::Image,
        ],
        modify_removed_attrs: vec![
            Attribute::Description,
            Attribute::DisplayName,
            Attribute::Name,
            Attribute::OAuth2Session,
            Attribute::OAuth2RsOrigin,
            Attribute::OAuth2RsOriginLanding,
            Attribute::OAuth2RsScopeMap,
            Attribute::OAuth2RsSupScopeMap,
            Attribute::OAuth2RsBasicSecret,
            Attribute::OAuth2RsTokenKey,
            Attribute::Es256PrivateKeyDer,
            Attribute::OAuth2AllowInsecureClientDisablePkce,
            Attribute::Rs256PrivateKeyDer,
            Attribute::OAuth2JwtLegacyCryptoEnable,
            Attribute::OAuth2PreferShortUsername,
            Attribute::OAuth2AllowLocalhostRedirect,
            Attribute::OAuth2RsClaimMap,
            Attribute::Image,
        ],
        modify_present_attrs: vec![
            Attribute::Description,
            Attribute::DisplayName,
            Attribute::Name,
            Attribute::OAuth2RsOrigin,
            Attribute::OAuth2RsOriginLanding,
            Attribute::OAuth2RsSupScopeMap,
            Attribute::OAuth2RsScopeMap,
            Attribute::OAuth2AllowInsecureClientDisablePkce,
            Attribute::OAuth2JwtLegacyCryptoEnable,
            Attribute::OAuth2PreferShortUsername,
            Attribute::OAuth2AllowLocalhostRedirect,
            Attribute::OAuth2RsClaimMap,
            Attribute::Image,
        ],
        create_attrs: vec![
            Attribute::Class,
            Attribute::Description,
            Attribute::Name,
            Attribute::DisplayName,
            Attribute::OAuth2RsName,
            Attribute::OAuth2RsOrigin,
            Attribute::OAuth2RsOriginLanding,
            Attribute::OAuth2RsSupScopeMap,
            Attribute::OAuth2RsScopeMap,
            Attribute::OAuth2AllowInsecureClientDisablePkce,
            Attribute::OAuth2JwtLegacyCryptoEnable,
            Attribute::OAuth2PreferShortUsername,
            Attribute::OAuth2AllowLocalhostRedirect,
            Attribute::OAuth2RsClaimMap,
            Attribute::Image,
        ],
        create_classes: vec![
            EntryClass::Object,
            EntryClass::Account,
            EntryClass::OAuth2ResourceServer,
            EntryClass::OAuth2ResourceServerBasic,
            EntryClass::OAuth2ResourceServerPublic,
        ],
        ..Default::default()
    };
}

lazy_static! {
    pub static ref IDM_ACP_OAUTH2_MANAGE_DL7: BuiltinAcp = BuiltinAcp {
        classes: vec![
            EntryClass::Object,
            EntryClass::AccessControlProfile,
            EntryClass::AccessControlCreate,
            EntryClass::AccessControlDelete,
            EntryClass::AccessControlModify,
            EntryClass::AccessControlSearch
        ],
        name: "idm_acp_hp_oauth2_manage_priv",
        uuid: UUID_IDM_ACP_OAUTH2_MANAGE_V1,
        description: "Builtin IDM Control for managing oauth2 resource server integrations.",
        receiver: BuiltinAcpReceiver::Group(vec![UUID_IDM_OAUTH2_ADMINS]),
        target: BuiltinAcpTarget::Filter(ProtoFilter::And(vec![
            match_class_filter!(EntryClass::OAuth2ResourceServer),
            FILTER_ANDNOT_TOMBSTONE_OR_RECYCLED.clone(),
        ])),
        search_attrs: vec![
            Attribute::Class,
            Attribute::Description,
            Attribute::DisplayName,
            Attribute::Name,
            Attribute::Spn,
            Attribute::OAuth2Session,
            Attribute::OAuth2RsOrigin,
            Attribute::OAuth2RsOriginLanding,
            Attribute::OAuth2RsScopeMap,
            Attribute::OAuth2RsSupScopeMap,
            Attribute::OAuth2RsBasicSecret,
            Attribute::OAuth2RsTokenKey,
            Attribute::Es256PrivateKeyDer,
            Attribute::OAuth2AllowInsecureClientDisablePkce,
            Attribute::Rs256PrivateKeyDer,
            Attribute::OAuth2JwtLegacyCryptoEnable,
            Attribute::OAuth2PreferShortUsername,
            Attribute::OAuth2AllowLocalhostRedirect,
            Attribute::OAuth2RsClaimMap,
            Attribute::Image,
            Attribute::OAuth2StrictRedirectUri,
        ],
        modify_removed_attrs: vec![
            Attribute::Description,
            Attribute::DisplayName,
            Attribute::Name,
            Attribute::OAuth2Session,
            Attribute::OAuth2RsOrigin,
            Attribute::OAuth2RsOriginLanding,
            Attribute::OAuth2RsScopeMap,
            Attribute::OAuth2RsSupScopeMap,
            Attribute::OAuth2RsBasicSecret,
            Attribute::OAuth2RsTokenKey,
            Attribute::Es256PrivateKeyDer,
            Attribute::OAuth2AllowInsecureClientDisablePkce,
            Attribute::Rs256PrivateKeyDer,
            Attribute::OAuth2JwtLegacyCryptoEnable,
            Attribute::OAuth2PreferShortUsername,
            Attribute::OAuth2AllowLocalhostRedirect,
            Attribute::OAuth2RsClaimMap,
            Attribute::Image,
            Attribute::OAuth2StrictRedirectUri,
        ],
        modify_present_attrs: vec![
            Attribute::Description,
            Attribute::DisplayName,
            Attribute::Name,
            Attribute::OAuth2RsOrigin,
            Attribute::OAuth2RsOriginLanding,
            Attribute::OAuth2RsSupScopeMap,
            Attribute::OAuth2RsScopeMap,
            Attribute::OAuth2AllowInsecureClientDisablePkce,
            Attribute::OAuth2JwtLegacyCryptoEnable,
            Attribute::OAuth2PreferShortUsername,
            Attribute::OAuth2AllowLocalhostRedirect,
            Attribute::OAuth2RsClaimMap,
            Attribute::Image,
            Attribute::OAuth2StrictRedirectUri,
        ],
        create_attrs: vec![
            Attribute::Class,
            Attribute::Description,
            Attribute::Name,
            Attribute::DisplayName,
            Attribute::OAuth2RsName,
            Attribute::OAuth2RsOrigin,
            Attribute::OAuth2RsOriginLanding,
            Attribute::OAuth2RsSupScopeMap,
            Attribute::OAuth2RsScopeMap,
            Attribute::OAuth2AllowInsecureClientDisablePkce,
            Attribute::OAuth2JwtLegacyCryptoEnable,
            Attribute::OAuth2PreferShortUsername,
            Attribute::OAuth2AllowLocalhostRedirect,
            Attribute::OAuth2RsClaimMap,
            Attribute::Image,
            Attribute::OAuth2StrictRedirectUri,
        ],
        create_classes: vec![
            EntryClass::Object,
            EntryClass::Account,
            EntryClass::OAuth2ResourceServer,
            EntryClass::OAuth2ResourceServerBasic,
            EntryClass::OAuth2ResourceServerPublic,
        ],
        ..Default::default()
    };
}

lazy_static! {
    pub static ref IDM_ACP_OAUTH2_MANAGE_DL9: BuiltinAcp = BuiltinAcp {
        classes: vec![
            EntryClass::Object,
            EntryClass::AccessControlProfile,
            EntryClass::AccessControlCreate,
            EntryClass::AccessControlDelete,
            EntryClass::AccessControlModify,
            EntryClass::AccessControlSearch
        ],
        name: "idm_acp_oauth2_manage",
        uuid: UUID_IDM_ACP_OAUTH2_MANAGE_V1,
        description: "Builtin IDM Control for managing OAuth2 resource server integrations.",
        receiver: BuiltinAcpReceiver::Group(vec![UUID_IDM_OAUTH2_ADMINS]),
        target: BuiltinAcpTarget::Filter(ProtoFilter::And(vec![
            match_class_filter!(EntryClass::OAuth2ResourceServer),
            FILTER_ANDNOT_TOMBSTONE_OR_RECYCLED.clone(),
        ])),
        search_attrs: vec![
            Attribute::Class,
            Attribute::Description,
            Attribute::DisplayName,
            Attribute::Name,
            Attribute::Spn,
            Attribute::OAuth2Session,
            Attribute::OAuth2RsOrigin,
            Attribute::OAuth2RsOriginLanding,
            Attribute::OAuth2RsScopeMap,
            Attribute::OAuth2RsSupScopeMap,
            Attribute::OAuth2RsBasicSecret,
            Attribute::OAuth2RsTokenKey,
            Attribute::Es256PrivateKeyDer,
            Attribute::OAuth2AllowInsecureClientDisablePkce,
            Attribute::Rs256PrivateKeyDer,
            Attribute::OAuth2JwtLegacyCryptoEnable,
            Attribute::OAuth2PreferShortUsername,
            Attribute::OAuth2AllowLocalhostRedirect,
            Attribute::OAuth2RsClaimMap,
            Attribute::Image,
            Attribute::OAuth2StrictRedirectUri,
            Attribute::OAuth2DeviceFlowEnable,
        ],
        modify_removed_attrs: vec![
            Attribute::Description,
            Attribute::DisplayName,
            Attribute::Name,
            Attribute::OAuth2Session,
            Attribute::OAuth2RsOrigin,
            Attribute::OAuth2RsOriginLanding,
            Attribute::OAuth2RsScopeMap,
            Attribute::OAuth2RsSupScopeMap,
            Attribute::OAuth2RsBasicSecret,
            Attribute::OAuth2RsTokenKey,
            Attribute::Es256PrivateKeyDer,
            Attribute::OAuth2AllowInsecureClientDisablePkce,
            Attribute::Rs256PrivateKeyDer,
            Attribute::OAuth2JwtLegacyCryptoEnable,
            Attribute::OAuth2PreferShortUsername,
            Attribute::OAuth2AllowLocalhostRedirect,
            Attribute::OAuth2RsClaimMap,
            Attribute::Image,
            Attribute::OAuth2StrictRedirectUri,
            Attribute::OAuth2DeviceFlowEnable,
        ],
        modify_present_attrs: vec![
            Attribute::Description,
            Attribute::DisplayName,
            Attribute::Name,
            Attribute::OAuth2RsOrigin,
            Attribute::OAuth2RsOriginLanding,
            Attribute::OAuth2RsSupScopeMap,
            Attribute::OAuth2RsScopeMap,
            Attribute::OAuth2AllowInsecureClientDisablePkce,
            Attribute::OAuth2JwtLegacyCryptoEnable,
            Attribute::OAuth2PreferShortUsername,
            Attribute::OAuth2AllowLocalhostRedirect,
            Attribute::OAuth2RsClaimMap,
            Attribute::Image,
            Attribute::OAuth2StrictRedirectUri,
            Attribute::OAuth2DeviceFlowEnable,
        ],
        create_attrs: vec![
            Attribute::Class,
            Attribute::Description,
            Attribute::Name,
            Attribute::DisplayName,
            Attribute::OAuth2RsName,
            Attribute::OAuth2RsOrigin,
            Attribute::OAuth2RsOriginLanding,
            Attribute::OAuth2RsSupScopeMap,
            Attribute::OAuth2RsScopeMap,
            Attribute::OAuth2AllowInsecureClientDisablePkce,
            Attribute::OAuth2JwtLegacyCryptoEnable,
            Attribute::OAuth2PreferShortUsername,
            Attribute::OAuth2AllowLocalhostRedirect,
            Attribute::OAuth2RsClaimMap,
            Attribute::Image,
            Attribute::OAuth2StrictRedirectUri,
            Attribute::OAuth2DeviceFlowEnable,
        ],
        create_classes: vec![
            EntryClass::Object,
            EntryClass::Account,
            EntryClass::OAuth2ResourceServer,
            EntryClass::OAuth2ResourceServerBasic,
            EntryClass::OAuth2ResourceServerPublic,
        ],
        ..Default::default()
    };
}

lazy_static! {
    pub static ref IDM_ACP_DOMAIN_ADMIN_DL6: BuiltinAcp = BuiltinAcp {
        classes: vec![
            EntryClass::Object,
            EntryClass::AccessControlProfile,
            EntryClass::AccessControlModify,
            EntryClass::AccessControlSearch
        ],
        name: "idm_acp_domain_admin",
        uuid: UUID_IDM_ACP_DOMAIN_ADMIN_V1,
        description: "Builtin IDM Control for granting domain info administration locally",
        receiver: BuiltinAcpReceiver::Group(vec![UUID_DOMAIN_ADMINS]),
        target: BuiltinAcpTarget::Filter(ProtoFilter::And(vec![
            ProtoFilter::Eq(
                Attribute::Uuid.to_string(),
                STR_UUID_DOMAIN_INFO.to_string()
            ),
            FILTER_ANDNOT_TOMBSTONE_OR_RECYCLED.clone()
        ])),
        search_attrs: vec![
            Attribute::Class,
            Attribute::Name,
            Attribute::Uuid,
            Attribute::DomainDisplayName,
            Attribute::DomainName,
            Attribute::DomainLdapBasedn,
            Attribute::LdapMaxQueryableAttrs,
            Attribute::DomainSsid,
            Attribute::DomainUuid,
            // Grants read access to the key object.
            // But this means we have to specify every type of key object?
            // Future william problem ...
            Attribute::KeyInternalData,
            Attribute::LdapAllowUnixPwBind,
            Attribute::Version,
        ],
        modify_removed_attrs: vec![
            Attribute::DomainDisplayName,
            Attribute::DomainSsid,
            Attribute::DomainLdapBasedn,
            Attribute::LdapMaxQueryableAttrs,
            Attribute::LdapAllowUnixPwBind,
            Attribute::KeyActionRevoke,
            Attribute::KeyActionRotate,
        ],
        modify_present_attrs: vec![
            Attribute::DomainDisplayName,
            Attribute::DomainLdapBasedn,
            Attribute::LdapMaxQueryableAttrs,
            Attribute::DomainSsid,
            Attribute::LdapAllowUnixPwBind,
            Attribute::KeyActionRevoke,
            Attribute::KeyActionRotate,
        ],
        ..Default::default()
    };
}

lazy_static! {
    pub static ref IDM_ACP_DOMAIN_ADMIN_DL8: BuiltinAcp = BuiltinAcp {
        classes: vec![
            EntryClass::Object,
            EntryClass::AccessControlProfile,
            EntryClass::AccessControlModify,
            EntryClass::AccessControlSearch
        ],
        name: "idm_acp_domain_admin",
        uuid: UUID_IDM_ACP_DOMAIN_ADMIN_V1,
        description: "Builtin IDM Control for granting domain info administration locally",
        receiver: BuiltinAcpReceiver::Group(vec![UUID_DOMAIN_ADMINS]),
        target: BuiltinAcpTarget::Filter(ProtoFilter::And(vec![
            ProtoFilter::Eq(
                Attribute::Uuid.to_string(),
                STR_UUID_DOMAIN_INFO.to_string()
            ),
            FILTER_ANDNOT_TOMBSTONE_OR_RECYCLED.clone()
        ])),
        search_attrs: vec![
            Attribute::Class,
            Attribute::Name,
            Attribute::Uuid,
            Attribute::DomainDisplayName,
            Attribute::DomainName,
            Attribute::DomainLdapBasedn,
            Attribute::LdapMaxQueryableAttrs,
            Attribute::DomainSsid,
            Attribute::DomainUuid,
            Attribute::KeyInternalData,
            Attribute::LdapAllowUnixPwBind,
            Attribute::Version,
            Attribute::Image,
        ],
        modify_removed_attrs: vec![
            Attribute::DomainDisplayName,
            Attribute::DomainSsid,
            Attribute::DomainLdapBasedn,
            Attribute::LdapMaxQueryableAttrs,
            Attribute::LdapAllowUnixPwBind,
            Attribute::KeyActionRevoke,
            Attribute::KeyActionRotate,
            Attribute::Image,
        ],
        modify_present_attrs: vec![
            Attribute::DomainDisplayName,
            Attribute::DomainLdapBasedn,
            Attribute::LdapMaxQueryableAttrs,
            Attribute::DomainSsid,
            Attribute::LdapAllowUnixPwBind,
            Attribute::KeyActionRevoke,
            Attribute::KeyActionRotate,
            Attribute::Image,
        ],
        ..Default::default()
    };
}

lazy_static! {
    pub static ref IDM_ACP_DOMAIN_ADMIN_DL9: BuiltinAcp = BuiltinAcp {
        classes: vec![
            EntryClass::Object,
            EntryClass::AccessControlProfile,
            EntryClass::AccessControlModify,
            EntryClass::AccessControlSearch
        ],
        name: "idm_acp_domain_admin",
        uuid: UUID_IDM_ACP_DOMAIN_ADMIN_V1,
        description: "Builtin IDM Control for granting domain info administration locally",
        receiver: BuiltinAcpReceiver::Group(vec![UUID_DOMAIN_ADMINS]),
        target: BuiltinAcpTarget::Filter(ProtoFilter::And(vec![
            ProtoFilter::Eq(
                Attribute::Uuid.to_string(),
                STR_UUID_DOMAIN_INFO.to_string()
            ),
            FILTER_ANDNOT_TOMBSTONE_OR_RECYCLED.clone()
        ])),
        search_attrs: vec![
            Attribute::Class,
            Attribute::Name,
            Attribute::Uuid,
            Attribute::DomainAllowEasterEggs,
            Attribute::DomainDisplayName,
            Attribute::DomainName,
            Attribute::DomainLdapBasedn,
            Attribute::LdapMaxQueryableAttrs,
            Attribute::DomainSsid,
            Attribute::DomainUuid,
            Attribute::KeyInternalData,
            Attribute::LdapAllowUnixPwBind,
            Attribute::Version,
            Attribute::Image,
        ],
        modify_removed_attrs: vec![
            Attribute::DomainDisplayName,
            Attribute::DomainSsid,
            Attribute::DomainLdapBasedn,
            Attribute::LdapMaxQueryableAttrs,
            Attribute::DomainAllowEasterEggs,
            Attribute::LdapAllowUnixPwBind,
            Attribute::KeyActionRevoke,
            Attribute::KeyActionRotate,
            Attribute::Image,
        ],
        modify_present_attrs: vec![
            Attribute::DomainDisplayName,
            Attribute::DomainLdapBasedn,
            Attribute::LdapMaxQueryableAttrs,
            Attribute::DomainSsid,
            Attribute::DomainAllowEasterEggs,
            Attribute::LdapAllowUnixPwBind,
            Attribute::KeyActionRevoke,
            Attribute::KeyActionRotate,
            Attribute::Image,
        ],
        ..Default::default()
    };
}

lazy_static! {
    pub static ref IDM_ACP_SYNC_ACCOUNT_MANAGE_V1: BuiltinAcp = BuiltinAcp {
        classes: vec![
            EntryClass::Object,
            EntryClass::AccessControlProfile,
            EntryClass::AccessControlCreate,
            EntryClass::AccessControlDelete,
            EntryClass::AccessControlModify,
            EntryClass::AccessControlSearch,
        ],
        name: "idm_acp_sync_account_manage",
        uuid: UUID_IDM_ACP_SYNC_ACCOUNT_MANAGE_V1,
        description: "Builtin IDM Control for managing IDM synchronisation accounts / connections",
        receiver: BuiltinAcpReceiver::Group(vec![UUID_DOMAIN_ADMINS]),
        target: BuiltinAcpTarget::Filter(ProtoFilter::And(vec![
            ProtoFilter::Eq(
                Attribute::Class.to_string(),
                EntryClass::SyncAccount.to_string()
            ),
            FILTER_ANDNOT_TOMBSTONE_OR_RECYCLED.clone(),
        ])),
        search_attrs: vec![
            Attribute::Class,
            Attribute::Uuid,
            Attribute::Name,
            Attribute::Description,
            Attribute::JwsEs256PrivateKey,
            Attribute::SyncTokenSession,
            Attribute::SyncCredentialPortal,
            Attribute::SyncYieldAuthority,
            Attribute::SyncCookie,
        ],
        modify_removed_attrs: vec![
            Attribute::Name,
            Attribute::Description,
            Attribute::JwsEs256PrivateKey,
            Attribute::SyncTokenSession,
            Attribute::SyncCredentialPortal,
            Attribute::SyncCookie,
            Attribute::SyncYieldAuthority,
        ],
        modify_present_attrs: vec![
            Attribute::Name,
            Attribute::Description,
            Attribute::SyncTokenSession,
            Attribute::SyncCredentialPortal,
            Attribute::SyncYieldAuthority,
        ],
        create_attrs: vec![Attribute::Class, Attribute::Name, Attribute::Description,],
        create_classes: vec![EntryClass::Object, EntryClass::SyncAccount,],
        ..Default::default()
    };
}

lazy_static! {
    pub static ref IDM_ACP_GROUP_ENTRY_MANAGER_V1: BuiltinAcp = BuiltinAcp{
        classes: vec![
            EntryClass::Object,
            EntryClass::AccessControlProfile,
            EntryClass::AccessControlModify,
            EntryClass::AccessControlSearch
            ],
        name: "idm_acp_group_entry_manager",
        uuid: UUID_IDM_ACP_GROUP_ENTRY_MANAGER_V1,
        description: "Builtin IDM Control for allowing EntryManager to read and modify groups",
        receiver: BuiltinAcpReceiver::EntryManager,
        // Any group
        target: BuiltinAcpTarget::Filter( ProtoFilter::And(vec![
            match_class_filter!(EntryClass::Group),
            FILTER_ANDNOT_TOMBSTONE_OR_RECYCLED.clone()
        ])),
        search_attrs: vec![
            Attribute::Class,
            Attribute::Name,
            Attribute::Uuid,
            Attribute::Spn,
            Attribute::Uuid,
            Attribute::Description,
            Attribute::Member,
            Attribute::DynMember,
            Attribute::EntryManagedBy,
        ],
        modify_present_attrs: vec![
            Attribute::Description,
            Attribute::Member,
        ],
        modify_removed_attrs: vec![
            Attribute::Description,
            Attribute::Member,
        ],
        ..Default::default()
    };
}

lazy_static! {
    pub static ref IDM_ACP_RADIUS_SERVERS_V1: BuiltinAcp = BuiltinAcp {
        classes: vec![
            EntryClass::Object,
            EntryClass::AccessControlProfile,
            EntryClass::AccessControlSearch,
        ],
        name: "idm_acp_radius_servers",
        uuid: UUID_IDM_ACP_RADIUS_SERVERS_V1,
        description:
            "Builtin IDM Control for RADIUS servers to read credentials and other needed details.",
        receiver: BuiltinAcpReceiver::Group(vec![UUID_IDM_RADIUS_SERVERS]),
        target: BuiltinAcpTarget::Filter(ProtoFilter::And(vec![
            ProtoFilter::Pres(EntryClass::Class.to_string()),
            FILTER_ANDNOT_TOMBSTONE_OR_RECYCLED.clone()
        ])),
        search_attrs: vec![
            Attribute::Class,
            Attribute::Name,
            Attribute::Spn,
            Attribute::Uuid,
            Attribute::RadiusSecret,
        ],
        ..Default::default()
    };
}

lazy_static! {
    pub static ref IDM_ACP_RADIUS_SECRET_MANAGE_V1: BuiltinAcp = BuiltinAcp {
        classes: vec![
            EntryClass::Object,
            EntryClass::AccessControlProfile,
            EntryClass::AccessControlModify,
            EntryClass::AccessControlSearch,
        ],
        name: "idm_acp_radius_secret_manage",
        uuid: UUID_IDM_ACP_RADIUS_SECRET_MANAGE_V1,
        description: "Builtin IDM Control allowing reads and writes to user radius secrets.",
        receiver: BuiltinAcpReceiver::Group(vec![UUID_IDM_RADIUS_ADMINS]),
        target: BuiltinAcpTarget::Filter(ProtoFilter::And(vec![
            match_class_filter!(EntryClass::Account),
            FILTER_ANDNOT_TOMBSTONE_OR_RECYCLED.clone()
        ])),
        search_attrs: vec![Attribute::RadiusSecret],
        modify_present_attrs: vec![Attribute::RadiusSecret],
        modify_removed_attrs: vec![Attribute::RadiusSecret],
        ..Default::default()
    };
}

lazy_static! {
    pub static ref IDM_ACP_MAIL_SERVERS_DL8: BuiltinAcp = BuiltinAcp {
        classes: vec![
            EntryClass::Object,
            EntryClass::AccessControlProfile,
            EntryClass::AccessControlSearch,
        ],
        name: "idm_acp_mail_servers",
        uuid: UUID_IDM_ACP_MAIL_SERVERS,
        description:
            "Builtin IDM Control for MAIL servers to read email addresses and other needed attributes.",
        receiver: BuiltinAcpReceiver::Group(vec![UUID_IDM_MAIL_SERVERS]),
        target: BuiltinAcpTarget::Filter(ProtoFilter::And(vec![
            ProtoFilter::Or(vec![
                match_class_filter!(EntryClass::Account),
                match_class_filter!(EntryClass::Group),
            ]),
            FILTER_ANDNOT_TOMBSTONE_OR_RECYCLED.clone()
        ])),
        search_attrs: vec![
            Attribute::Class,
            Attribute::Name,
            Attribute::Spn,
            Attribute::Uuid,
            Attribute::DisplayName,
            Attribute::Mail,
            Attribute::Member,
            Attribute::DynMember,
            Attribute::MemberOf,
            Attribute::GidNumber,
        ],
        ..Default::default()
    };
}

lazy_static! {
    pub static ref IDM_ACP_PEOPLE_SELF_WRITE_MAIL_V1: BuiltinAcp = BuiltinAcp {
        classes: vec![
            EntryClass::Object,
            EntryClass::AccessControlProfile,
            EntryClass::AccessControlModify,
        ],
        name: "idm_acp_people_self_write_mail",
        uuid: UUID_IDM_ACP_PEOPLE_SELF_WRITE_MAIL,
        description: "Builtin IDM Control for self write of mail for people accounts.",
        receiver: BuiltinAcpReceiver::Group(vec![UUID_IDM_PEOPLE_SELF_MAIL_WRITE]),
        target: BuiltinAcpTarget::Filter(ProtoFilter::And(vec![
            match_class_filter!(EntryClass::Person).clone(),
            match_class_filter!(EntryClass::Account).clone(),
            ProtoFilter::SelfUuid,
        ])),
        modify_removed_attrs: vec![Attribute::Mail],
        modify_present_attrs: vec![Attribute::Mail],
        ..Default::default()
    };
}

lazy_static! {
    pub static ref IDM_ACP_SELF_READ_V1: BuiltinAcp = BuiltinAcp {
        name: "idm_acp_self_read",
        uuid: UUID_IDM_ACP_SELF_READ,
        description:
            "Builtin IDM Control for self read - required for whoami and many other functions",
        classes: vec![
            EntryClass::Object,
            EntryClass::AccessControlProfile,
            EntryClass::AccessControlSearch,
        ],
        receiver: BuiltinAcpReceiver::Group(vec![UUID_IDM_ALL_ACCOUNTS]),
        target: BuiltinAcpTarget::Filter(ProtoFilter::SelfUuid),
        search_attrs: vec![
            Attribute::Class,
            Attribute::Name,
            Attribute::Spn,
            Attribute::DisplayName,
            Attribute::LegalName,
            Attribute::Class,
            Attribute::MemberOf,
            Attribute::Mail,
            Attribute::RadiusSecret,
            Attribute::GidNumber,
            Attribute::LoginShell,
            Attribute::Uuid,
            Attribute::SyncParentUuid,
            Attribute::AccountExpire,
            Attribute::AccountValidFrom,
            Attribute::PrimaryCredential,
            Attribute::UserAuthTokenSession,
            Attribute::PassKeys,
            Attribute::AttestedPasskeys,
        ],
        ..Default::default()
    };
}

lazy_static! {
    pub static ref IDM_ACP_SELF_READ_DL8: BuiltinAcp = BuiltinAcp {
        name: "idm_acp_self_read",
        uuid: UUID_IDM_ACP_SELF_READ,
        description:
            "Builtin IDM Control for self read - required for whoami and many other functions",
        classes: vec![
            EntryClass::Object,
            EntryClass::AccessControlProfile,
            EntryClass::AccessControlSearch,
        ],
        receiver: BuiltinAcpReceiver::Group(vec![UUID_IDM_ALL_ACCOUNTS]),
        target: BuiltinAcpTarget::Filter(ProtoFilter::SelfUuid),
        search_attrs: vec![
            Attribute::Class,
            Attribute::Name,
            Attribute::Spn,
            Attribute::DisplayName,
            Attribute::LegalName,
            Attribute::Class,
            Attribute::MemberOf,
            Attribute::Mail,
            Attribute::RadiusSecret,
            Attribute::GidNumber,
            Attribute::LoginShell,
            Attribute::Uuid,
            Attribute::SyncParentUuid,
            Attribute::AccountExpire,
            Attribute::AccountValidFrom,
            Attribute::PrimaryCredential,
            Attribute::UserAuthTokenSession,
            Attribute::PassKeys,
            Attribute::AttestedPasskeys,
            Attribute::ApplicationPassword,
            Attribute::SshPublicKey,
            Attribute::UnixPassword,
        ],
        ..Default::default()
    };
}

lazy_static! {
    pub static ref IDM_ACP_SELF_WRITE_V1: BuiltinAcp = BuiltinAcp{
        name: "idm_acp_self_write",
        uuid: UUID_IDM_ACP_SELF_WRITE_V1,
        classes: vec![
            EntryClass::Object,
            EntryClass::AccessControlProfile,
            EntryClass::AccessControlModify,
            ],
        description: "Builtin IDM Control for self write - required for people to update their own identities and credentials in line with best practices.",
        receiver: BuiltinAcpReceiver::Group ( vec![UUID_IDM_ALL_PERSONS] ),
        target: BuiltinAcpTarget::Filter(ProtoFilter::SelfUuid),
        modify_removed_attrs: vec![
            Attribute::DisplayName,
            Attribute::LegalName,
            Attribute::RadiusSecret,
            Attribute::PrimaryCredential,
            Attribute::SshPublicKey,
            Attribute::UnixPassword,
            Attribute::PassKeys,
            Attribute::AttestedPasskeys,
            Attribute::UserAuthTokenSession,
            Attribute::ApplicationPassword,
        ],
        modify_present_attrs: vec![
            Attribute::DisplayName,
            Attribute::LegalName,
            Attribute::RadiusSecret,
            Attribute::PrimaryCredential,
            Attribute::SshPublicKey,
            Attribute::UnixPassword,
            Attribute::PassKeys,
            Attribute::AttestedPasskeys,
            Attribute::ApplicationPassword,
        ],
        ..Default::default()
    };
}

lazy_static! {
    pub static ref IDM_ACP_SELF_WRITE_DL7: BuiltinAcp = BuiltinAcp{
        name: "idm_acp_self_write",
        uuid: UUID_IDM_ACP_SELF_WRITE_V1,
        classes: vec![
            EntryClass::Object,
            EntryClass::AccessControlProfile,
            EntryClass::AccessControlModify,
            ],
        description: "Builtin IDM Control for self write - required for people to update their own credentials in line with best practices.",
        receiver: BuiltinAcpReceiver::Group ( vec![UUID_IDM_ALL_PERSONS] ),
        target: BuiltinAcpTarget::Filter(ProtoFilter::SelfUuid),
        modify_removed_attrs: vec![
            Attribute::RadiusSecret,
            Attribute::PrimaryCredential,
            Attribute::SshPublicKey,
            Attribute::UnixPassword,
            Attribute::PassKeys,
            Attribute::AttestedPasskeys,
            Attribute::UserAuthTokenSession,
        ],
        modify_present_attrs: vec![
            Attribute::RadiusSecret,
            Attribute::PrimaryCredential,
            Attribute::SshPublicKey,
            Attribute::UnixPassword,
            Attribute::PassKeys,
            Attribute::AttestedPasskeys,
        ],
        ..Default::default()
    };
}

lazy_static! {
    pub static ref IDM_ACP_SELF_WRITE_DL8: BuiltinAcp = BuiltinAcp{
        name: "idm_acp_self_write",
        uuid: UUID_IDM_ACP_SELF_WRITE_V1,
        classes: vec![
            EntryClass::Object,
            EntryClass::AccessControlProfile,
            EntryClass::AccessControlModify,
            ],
        description: "Builtin IDM Control for self write - required for people to update their own credentials in line with best practices.",
        receiver: BuiltinAcpReceiver::Group ( vec![UUID_IDM_ALL_PERSONS] ),
        target: BuiltinAcpTarget::Filter(ProtoFilter::SelfUuid),
        modify_removed_attrs: vec![
            Attribute::RadiusSecret,
            Attribute::PrimaryCredential,
            Attribute::SshPublicKey,
            Attribute::UnixPassword,
            Attribute::PassKeys,
            Attribute::AttestedPasskeys,
            Attribute::UserAuthTokenSession,
            Attribute::ApplicationPassword,
        ],
        modify_present_attrs: vec![
            Attribute::RadiusSecret,
            Attribute::PrimaryCredential,
            Attribute::SshPublicKey,
            Attribute::UnixPassword,
            Attribute::PassKeys,
            Attribute::AttestedPasskeys,
            Attribute::ApplicationPassword,
        ],
        ..Default::default()
    };
}

lazy_static! {
    pub static ref IDM_ACP_SELF_NAME_WRITE_V1: BuiltinAcp = BuiltinAcp{
        name: "idm_acp_self_name_write",
        uuid: UUID_IDM_ACP_SELF_NAME_WRITE_V1,
        classes: vec![
            EntryClass::Object,
            EntryClass::AccessControlProfile,
            EntryClass::AccessControlModify,
            ],
        description: "Builtin IDM Control for self write of name - required for people to update their own identities in line with best practices.",
        receiver: BuiltinAcpReceiver::Group ( vec![UUID_IDM_ALL_PERSONS] ),
        target: BuiltinAcpTarget::Filter(ProtoFilter::SelfUuid),
        modify_removed_attrs: vec![
            Attribute::Name,
        ],
        modify_present_attrs: vec![
            Attribute::Name,
        ],
        ..Default::default()
    };
}

lazy_static! {
    pub static ref IDM_ACP_SELF_NAME_WRITE_DL7: BuiltinAcp = BuiltinAcp{
        name: "idm_acp_self_name_write",
        uuid: UUID_IDM_ACP_SELF_NAME_WRITE_V1,
        classes: vec![
            EntryClass::Object,
            EntryClass::AccessControlProfile,
            EntryClass::AccessControlModify,
            ],
        description: "Builtin IDM Control for self write of name - required for people to update their own identities in line with best practices.",
        receiver: BuiltinAcpReceiver::Group ( vec![UUID_IDM_PEOPLE_SELF_NAME_WRITE] ),
        target: BuiltinAcpTarget::Filter(ProtoFilter::And(vec![
            ProtoFilter::SelfUuid,
            match_class_filter!(EntryClass::Person).clone(),
            FILTER_ANDNOT_TOMBSTONE_OR_RECYCLED.clone(),
        ])),
        modify_removed_attrs: vec![
            Attribute::Name,
            Attribute::DisplayName,
            Attribute::LegalName,
        ],
        modify_present_attrs: vec![
            Attribute::Name,
            Attribute::DisplayName,
            Attribute::LegalName,
        ],
        ..Default::default()
    };
}

lazy_static! {
    pub static ref IDM_ACP_ACCOUNT_SELF_WRITE_V1: BuiltinAcp = BuiltinAcp {
        name: "idm_acp_account_self_write",
        uuid: UUID_IDM_ACP_ACCOUNT_SELF_WRITE_V1,
        description: "Builtin IDM Control for self write - required for accounts to update their own session state.",
        classes: vec![
            EntryClass::Object,
            EntryClass::AccessControlProfile,
            EntryClass::AccessControlModify
            ],
        receiver: BuiltinAcpReceiver::Group ( vec![UUID_IDM_ALL_ACCOUNTS] ),
        target: BuiltinAcpTarget::Filter(ProtoFilter::SelfUuid),
        modify_removed_attrs: vec![
            Attribute::UserAuthTokenSession
            ],
        ..Default::default()
    };
}

lazy_static! {
    pub static ref IDM_ACP_ALL_ACCOUNTS_POSIX_READ_V1: BuiltinAcp = BuiltinAcp {
        classes: vec![
            EntryClass::Object,
            EntryClass::AccessControlProfile,
            EntryClass::AccessControlSearch,
        ],
        name: "idm_acp_all_accounts_posix_read",
        uuid: UUID_IDM_ACP_ALL_ACCOUNTS_POSIX_READ_V1,
        description:
            "Builtin IDM Control for reading minimal posix attrs - applies anonymous and all authenticated accounts.",
        receiver: BuiltinAcpReceiver::Group ( vec![UUID_IDM_ALL_ACCOUNTS] ),
        target: BuiltinAcpTarget::Filter( ProtoFilter::And(
            vec![
                ProtoFilter::Or(vec![
                    match_class_filter!(EntryClass::Account),
                    match_class_filter!(EntryClass::Group),
                ]),
                FILTER_ANDNOT_TOMBSTONE_OR_RECYCLED.clone(),
            ]
        )),
        search_attrs: vec![
            Attribute::Class,
            Attribute::Name,
            Attribute::Spn,
            Attribute::DisplayName,
            Attribute::Class,
            Attribute::MemberOf,
            Attribute::Member,
            Attribute::DynMember,
            Attribute::Uuid,
            Attribute::GidNumber,
            Attribute::LoginShell,
            Attribute::SshPublicKey,
        ],
        ..Default::default()
    };
}

lazy_static! {
    pub static ref IDM_ACP_ACCOUNT_MAIL_READ_DL6: BuiltinAcp = BuiltinAcp {
        classes: vec![
            EntryClass::Object,
            EntryClass::AccessControlProfile,
            EntryClass::AccessControlSearch
        ],
        name: "idm_acp_account_mail_read",
        uuid: UUID_IDM_ACP_ACCOUNT_MAIL_READ_V1,
        description: "Builtin IDM Control for reading account and group mail attributes.",
        receiver: BuiltinAcpReceiver::Group(vec![UUID_IDM_ACCOUNT_MAIL_READ]),
        target: BuiltinAcpTarget::Filter(ProtoFilter::And(vec![
            ProtoFilter::Or(vec![
                match_class_filter!(EntryClass::Account),
                match_class_filter!(EntryClass::Group),
            ]),
            FILTER_ANDNOT_TOMBSTONE_OR_RECYCLED.clone(),
        ])),
        search_attrs: vec![Attribute::Mail],
        ..Default::default()
    };
}

lazy_static! {
    pub static ref IDM_ACP_SYSTEM_CONFIG_ACCOUNT_POLICY_MANAGE_V1: BuiltinAcp = BuiltinAcp {
        classes: vec![
            EntryClass::Object,
            EntryClass::AccessControlProfile,
            EntryClass::AccessControlModify,
            EntryClass::AccessControlSearch
        ],
        name: "idm_acp_system_config_account_policy_manage",
        uuid: UUID_IDM_ACP_SYSTEM_CONFIG_ACCOUNT_POLICY_MANAGE_V1,
        description: "Builtin IDM Control for granting system configuration of account policy",
        receiver: BuiltinAcpReceiver::Group(vec![UUID_IDM_ACCOUNT_POLICY_ADMINS]),
        target: BuiltinAcpTarget::Filter(ProtoFilter::And(vec![
            ProtoFilter::Eq(
                Attribute::Uuid.to_string(),
                STR_UUID_SYSTEM_CONFIG.to_string()
            ),
            FILTER_ANDNOT_TOMBSTONE_OR_RECYCLED.clone()
        ])),
        search_attrs: vec![
            Attribute::Class,
            Attribute::Name,
            Attribute::Uuid,
            Attribute::Description,
            Attribute::BadlistPassword,
            Attribute::DeniedName,
            Attribute::AuthSessionExpiry,
            Attribute::PrivilegeExpiry,
            Attribute::Version,
        ],
        modify_removed_attrs: vec![
            Attribute::BadlistPassword,
            Attribute::DeniedName,
            Attribute::AuthSessionExpiry,
            Attribute::PrivilegeExpiry,
        ],
        modify_present_attrs: vec![
            Attribute::BadlistPassword,
            Attribute::DeniedName,
            Attribute::AuthSessionExpiry,
            Attribute::PrivilegeExpiry,
        ],
        ..Default::default()
    };
}

lazy_static! {
    pub static ref IDM_ACP_HP_GROUP_UNIX_MANAGE_V1: BuiltinAcp = BuiltinAcp{
        classes: vec![
            EntryClass::Object,
            EntryClass::AccessControlProfile,
            EntryClass::AccessControlModify,
            EntryClass::AccessControlSearch
        ],
        name: "idm_acp_hp_group_unix_manage",
        uuid: UUID_IDM_ACP_HP_GROUP_UNIX_MANAGE_V1,
        description: "Builtin IDM Control for managing and extending high privilege groups with unix attributes",
        receiver: BuiltinAcpReceiver::Group ( vec![UUID_IDM_UNIX_ADMINS] ),
        // HP group, not Recycled/Tombstone
        target: BuiltinAcpTarget::Filter( ProtoFilter::And(vec![
            match_class_filter!(EntryClass::Group),
            FILTER_HP.clone(),
            FILTER_ANDNOT_TOMBSTONE_OR_RECYCLED.clone(),
        ])),
        search_attrs: vec![
            Attribute::DynMember,
            Attribute::Class,
            Attribute::Name,
            Attribute::Uuid,
            Attribute::Spn,
            Attribute::Description,
            Attribute::Member,
            Attribute::GidNumber,
        ],
        modify_removed_attrs: vec![
            Attribute::GidNumber,
        ],
        modify_present_attrs: vec![
            Attribute::Class,
            Attribute::GidNumber,
        ],
        modify_classes: vec![
            EntryClass::PosixGroup,
        ],
        ..Default::default()
    };
}

lazy_static! {
    pub static ref IDM_ACP_GROUP_MANAGE_DL6: BuiltinAcp = BuiltinAcp{
        classes: vec![
            EntryClass::Object,
            EntryClass::AccessControlProfile,
            EntryClass::AccessControlCreate,
            EntryClass::AccessControlDelete,
            EntryClass::AccessControlModify,
            EntryClass::AccessControlSearch
            ],
        name: "idm_acp_group_manage",
        uuid: UUID_IDM_ACP_GROUP_MANAGE_V1,
        description: "Builtin IDM Control for creating and deleting groups in the directory",
        receiver: BuiltinAcpReceiver::Group ( vec![UUID_IDM_GROUP_ADMINS] ),
         // group which is not in HP, Recycled, Tombstone
         target: BuiltinAcpTarget::Filter( ProtoFilter::And(vec![
            match_class_filter!(EntryClass::Group),
            FILTER_ANDNOT_HP_OR_RECYCLED_OR_TOMBSTONE.clone(),
        ])),
        search_attrs: vec![
            Attribute::Class,
            Attribute::Name,
            Attribute::Uuid,
            Attribute::Spn,
            Attribute::Uuid,
            Attribute::Description,
            Attribute::Mail,
            Attribute::Member,
            Attribute::DynMember,
            Attribute::EntryManagedBy,
        ],
        create_attrs: vec![
            Attribute::Class,
            Attribute::Name,
            Attribute::Uuid,
            Attribute::Description,
            Attribute::Mail,
            Attribute::Member,
            Attribute::EntryManagedBy,
        ],
        create_classes: vec![
            EntryClass::Object,
            EntryClass::Group,
        ],
        modify_present_attrs: vec![
            Attribute::Name,
            Attribute::Description,
            Attribute::Mail,
            Attribute::Member,
        ],
        modify_removed_attrs: vec![
            Attribute::Name,
            Attribute::Description,
            Attribute::Mail,
            Attribute::Member,
        ],
        ..Default::default()
    };
}

lazy_static! {
    pub static ref IDM_ACP_GROUP_MANAGE_DL9: BuiltinAcp = BuiltinAcp{
        classes: vec![
            EntryClass::Object,
            EntryClass::AccessControlProfile,
            EntryClass::AccessControlCreate,
            EntryClass::AccessControlDelete,
            EntryClass::AccessControlModify,
            EntryClass::AccessControlSearch
            ],
        name: "idm_acp_group_manage",
        uuid: UUID_IDM_ACP_GROUP_MANAGE_V1,
        description: "Builtin IDM Control for creating and deleting groups in the directory",
        receiver: BuiltinAcpReceiver::Group ( vec![UUID_IDM_GROUP_ADMINS] ),
         // group which is not in HP, Recycled, Tombstone
         target: BuiltinAcpTarget::Filter( ProtoFilter::And(vec![
            match_class_filter!(EntryClass::Group),
            FILTER_ANDNOT_HP_OR_RECYCLED_OR_TOMBSTONE.clone(),
        ])),
        search_attrs: vec![
            Attribute::Class,
            Attribute::Name,
            Attribute::Uuid,
            Attribute::Spn,
            Attribute::Uuid,
            Attribute::Description,
            Attribute::Mail,
            Attribute::Member,
            Attribute::DynMember,
            Attribute::EntryManagedBy,
        ],
        create_attrs: vec![
            Attribute::Class,
            Attribute::Name,
            Attribute::Uuid,
            Attribute::Description,
            Attribute::Mail,
            Attribute::Member,
            Attribute::EntryManagedBy,
        ],
        create_classes: vec![
            EntryClass::Object,
            EntryClass::Group,
        ],
        modify_present_attrs: vec![
            Attribute::Name,
            Attribute::Description,
            Attribute::Mail,
            Attribute::Member,
            Attribute::EntryManagedBy,
        ],
        modify_removed_attrs: vec![
            Attribute::Name,
            Attribute::Description,
            Attribute::Mail,
            Attribute::Member,
            Attribute::EntryManagedBy,
        ],
        ..Default::default()
    };
}

lazy_static! {
    pub static ref IDM_ACP_GROUP_UNIX_MANAGE_V1: BuiltinAcp = BuiltinAcp {
        classes: vec![
            EntryClass::Object,
            EntryClass::AccessControlProfile,
            EntryClass::AccessControlModify,
            EntryClass::AccessControlSearch
        ],
        name: "idm_acp_group_unix_manage",
        uuid: UUID_IDM_ACP_GROUP_UNIX_MANAGE_V1,
        description: "Builtin IDM Control for managing unix groups",
        receiver: BuiltinAcpReceiver::Group(vec![UUID_IDM_UNIX_ADMINS]),
        target: BuiltinAcpTarget::Filter(ProtoFilter::And(vec![
            match_class_filter!(EntryClass::Group),
            FILTER_ANDNOT_HP_OR_RECYCLED_OR_TOMBSTONE.clone(),
        ])),
        search_attrs: vec![
            Attribute::DynMember,
            Attribute::Class,
            Attribute::Name,
            Attribute::Uuid,
            Attribute::Spn,
            Attribute::Description,
            Attribute::Member,
            Attribute::GidNumber,
        ],
        modify_removed_attrs: vec![Attribute::GidNumber,],
        modify_present_attrs: vec![Attribute::Class, Attribute::GidNumber,],
        modify_classes: vec![EntryClass::PosixGroup,],
        ..Default::default()
    };
}

lazy_static! {
    pub static ref IDM_ACP_ACCOUNT_UNIX_EXTEND_V1: BuiltinAcp = BuiltinAcp {
        classes: vec![
            EntryClass::Object,
            EntryClass::AccessControlProfile,
            EntryClass::AccessControlModify,
            EntryClass::AccessControlSearch
        ],
        name: "idm_acp_account_unix_extend",
        uuid: UUID_IDM_ACP_ACCOUNT_UNIX_EXTEND_V1,
        description: "Builtin IDM Control for managing and extending unix accounts",
        receiver: BuiltinAcpReceiver::Group(vec![UUID_IDM_UNIX_ADMINS]),
        target: BuiltinAcpTarget::Filter(ProtoFilter::And(vec![
            match_class_filter!(EntryClass::Account),
            FILTER_ANDNOT_TOMBSTONE_OR_RECYCLED.clone(),
        ])),
        search_attrs: vec![
            Attribute::Class,
            Attribute::Name,
            Attribute::Uuid,
            Attribute::Spn,
            Attribute::Description,
            Attribute::GidNumber,
            Attribute::LoginShell,
            Attribute::UnixPassword,
            Attribute::SshPublicKey,
        ],
        modify_removed_attrs: vec![
            Attribute::GidNumber,
            Attribute::LoginShell,
            Attribute::UnixPassword,
            Attribute::SshPublicKey,
        ],
        modify_present_attrs: vec![
            Attribute::Class,
            Attribute::GidNumber,
            Attribute::LoginShell,
            Attribute::UnixPassword,
            Attribute::SshPublicKey,
        ],
        modify_classes: vec![EntryClass::PosixAccount,],
        ..Default::default()
    };
}

lazy_static! {
    pub static ref IDM_ACP_PEOPLE_PII_READ_V1: BuiltinAcp = BuiltinAcp {
        classes: vec![
            EntryClass::Object,
            EntryClass::AccessControlProfile,
            EntryClass::AccessControlSearch,
        ],
        name: "idm_acp_people_pii_read",
        uuid: UUID_IDM_ACP_PEOPLE_PII_READ_V1,
        description: "Builtin IDM Control for reading personal and sensitive data.",
        receiver: BuiltinAcpReceiver::Group(vec![UUID_IDM_PEOPLE_ADMINS, UUID_IDM_PEOPLE_PII_READ]),
        target: BuiltinAcpTarget::Filter(ProtoFilter::And(vec![
            match_class_filter!(EntryClass::Person).clone(),
            FILTER_ANDNOT_TOMBSTONE_OR_RECYCLED.clone(),
        ])),
        search_attrs: vec![
            Attribute::Class,
            Attribute::Name,
            Attribute::Uuid,
            Attribute::Spn,
            Attribute::DisplayName,
            Attribute::LegalName,
            Attribute::Mail,
        ],
        ..Default::default()
    };
}

lazy_static! {
    pub static ref IDM_ACP_PEOPLE_PII_MANAGE_V1: BuiltinAcp = BuiltinAcp {
        classes: vec![
            EntryClass::Object,
            EntryClass::AccessControlProfile,
            EntryClass::AccessControlModify
        ],
        name: "idm_acp_people_pii_manage",
        uuid: UUID_IDM_ACP_PEOPLE_PII_MANAGE_V1,
        description: "Builtin IDM Control for modifying peoples personal and sensitive data",
        receiver: BuiltinAcpReceiver::Group(vec![UUID_IDM_PEOPLE_ADMINS]),
        target: BuiltinAcpTarget::Filter(ProtoFilter::And(vec![
            match_class_filter!(EntryClass::Person),
            FILTER_ANDNOT_TOMBSTONE_OR_RECYCLED.clone(),
        ])),
        modify_removed_attrs: vec![
            Attribute::Name,
            Attribute::DisplayName,
            Attribute::LegalName,
            Attribute::Mail,
        ],
        modify_present_attrs: vec![
            Attribute::Name,
            Attribute::DisplayName,
            Attribute::LegalName,
            Attribute::Mail,
        ],
        ..Default::default()
    };
}

lazy_static! {
    pub static ref IDM_ACP_PEOPLE_CREATE_DL6: BuiltinAcp = BuiltinAcp {
        classes: vec![
            EntryClass::Object,
            EntryClass::AccessControlProfile,
            EntryClass::AccessControlCreate,
        ],
        name: "idm_acp_people_create",
        uuid: UUID_IDM_ACP_PEOPLE_CREATE_V1,
        description: "Builtin IDM Control for creating new persons.",
        receiver: BuiltinAcpReceiver::Group(vec![
            UUID_IDM_PEOPLE_ADMINS,
            UUID_IDM_PEOPLE_ON_BOARDING
        ]),
        target: BuiltinAcpTarget::Filter(ProtoFilter::And(vec![
            match_class_filter!(EntryClass::Person).clone(),
            match_class_filter!(EntryClass::Account).clone(),
            FILTER_ANDNOT_TOMBSTONE_OR_RECYCLED.clone(),
        ])),
        create_attrs: vec![
            Attribute::Class,
            Attribute::Uuid,
            Attribute::Name,
            Attribute::DisplayName,
            Attribute::Mail,
            Attribute::AccountExpire,
            Attribute::AccountValidFrom,
        ],
        create_classes: vec![EntryClass::Object, EntryClass::Account, EntryClass::Person,],
        ..Default::default()
    };
}

lazy_static! {
    pub static ref IDM_ACP_PEOPLE_MANAGE_V1: BuiltinAcp = BuiltinAcp {
        classes: vec![
            EntryClass::Object,
            EntryClass::AccessControlProfile,
            EntryClass::AccessControlModify,
        ],
        name: "idm_acp_people_manage",
        uuid: UUID_IDM_ACP_PEOPLE_MANAGE_V1,
        description: "Builtin IDM Control for management of peoples non sensitive attributes.",
        receiver: BuiltinAcpReceiver::Group(vec![UUID_IDM_PEOPLE_ADMINS]),
        target: BuiltinAcpTarget::Filter(ProtoFilter::And(vec![
            match_class_filter!(EntryClass::Person),
            match_class_filter!(EntryClass::Account),
            FILTER_ANDNOT_HP_OR_RECYCLED_OR_TOMBSTONE.clone(),
        ])),
        modify_removed_attrs: vec![Attribute::AccountExpire, Attribute::AccountValidFrom,],
        modify_present_attrs: vec![Attribute::AccountExpire, Attribute::AccountValidFrom,],
        ..Default::default()
    };
}

// Person Read
lazy_static! {
    pub static ref IDM_ACP_PEOPLE_READ_V1: BuiltinAcp = BuiltinAcp {
        classes: vec![
            EntryClass::Object,
            EntryClass::AccessControlProfile,
            EntryClass::AccessControlSearch,
        ],
        name: "idm_acp_people_read",
        uuid: UUID_IDM_ACP_PEOPLE_READ_V1,
        description: "Builtin IDM Control for reading non-sensitive data.",
        receiver: BuiltinAcpReceiver::Group(vec![
            UUID_IDM_PEOPLE_ADMINS,
            UUID_IDM_PEOPLE_PII_READ,
            UUID_IDM_ACCOUNT_MAIL_READ,
            UUID_IDM_SERVICE_DESK
        ]),
        target: BuiltinAcpTarget::Filter(ProtoFilter::And(vec![
            match_class_filter!(EntryClass::Person).clone(),
            FILTER_ANDNOT_TOMBSTONE_OR_RECYCLED.clone(),
        ])),
        search_attrs: vec![
            Attribute::Class,
            Attribute::Name,
            Attribute::Spn,
            Attribute::Uuid,
            Attribute::DisplayName,
            Attribute::MemberOf,
            Attribute::Uuid,
            Attribute::AccountExpire,
            Attribute::AccountValidFrom,
        ],
        ..Default::default()
    };
}

// Person Delete
lazy_static! {
    pub static ref IDM_ACP_PEOPLE_DELETE_V1: BuiltinAcp = BuiltinAcp {
        classes: vec![
            EntryClass::Object,
            EntryClass::AccessControlProfile,
            EntryClass::AccessControlDelete,
        ],
        name: "idm_acp_people_delete",
        uuid: UUID_IDM_ACP_PEOPLE_DELETE_V1,
        description: "Builtin IDM Control for deleting persons.",
        receiver: BuiltinAcpReceiver::Group(vec![UUID_IDM_PEOPLE_ADMINS,]),
        target: BuiltinAcpTarget::Filter(ProtoFilter::And(vec![
            match_class_filter!(EntryClass::Person).clone(),
            match_class_filter!(EntryClass::Account).clone(),
            FILTER_ANDNOT_TOMBSTONE_OR_RECYCLED.clone(),
        ])),
        ..Default::default()
    };
}

// Person Account Credential Reset
lazy_static! {
    pub static ref IDM_ACP_PEOPLE_CREDENTIAL_RESET_V1: BuiltinAcp = BuiltinAcp {
        classes: vec![
            EntryClass::Object,
            EntryClass::AccessControlProfile,
            EntryClass::AccessControlModify,
            EntryClass::AccessControlSearch
        ],
        name: "idm_acp_people_credential_reset",
        uuid: UUID_IDM_ACP_PEOPLE_CREDENTIAL_RESET_V1,
        description: "Builtin IDM Control for resetting peoples credentials ",
        receiver: BuiltinAcpReceiver::Group(vec![
            UUID_IDM_PEOPLE_ADMINS,
            UUID_IDM_SERVICE_DESK,
            UUID_IDM_PEOPLE_ON_BOARDING,
        ]),
        target: BuiltinAcpTarget::Filter(ProtoFilter::And(vec![
            match_class_filter!(EntryClass::Person),
            match_class_filter!(EntryClass::Account),
            FILTER_ANDNOT_HP_OR_RECYCLED_OR_TOMBSTONE.clone(),
        ])),
        search_attrs: vec![
            Attribute::Class,
            Attribute::Uuid,
            Attribute::Name,
            Attribute::Spn,
            Attribute::PrimaryCredential,
            Attribute::AccountExpire,
            Attribute::AccountValidFrom,
            Attribute::PassKeys,
            Attribute::AttestedPasskeys,
        ],
        modify_removed_attrs: vec![
            Attribute::PrimaryCredential,
            Attribute::PassKeys,
            Attribute::AttestedPasskeys,
        ],
        modify_present_attrs: vec![
            Attribute::PrimaryCredential,
            Attribute::PassKeys,
            Attribute::AttestedPasskeys,
        ],
        ..Default::default()
    };
}

// HP Person Account Credential Reset
lazy_static! {
    pub static ref IDM_ACP_HP_PEOPLE_CREDENTIAL_RESET_V1: BuiltinAcp = BuiltinAcp {
        classes: vec![
            EntryClass::Object,
            EntryClass::AccessControlProfile,
            EntryClass::AccessControlModify,
            EntryClass::AccessControlSearch
        ],
        name: "idm_acp_hp_people_credential_reset",
        uuid: UUID_IDM_ACP_HP_PEOPLE_CREDENTIAL_RESET_V1,
        description: "Builtin IDM Control for resetting high privilege peoples credentials ",
        receiver: BuiltinAcpReceiver::Group(vec![UUID_IDM_PEOPLE_ADMINS,]),
        target: BuiltinAcpTarget::Filter(ProtoFilter::And(vec![
            match_class_filter!(EntryClass::Person),
            match_class_filter!(EntryClass::Account),
            FILTER_HP.clone(),
            FILTER_ANDNOT_TOMBSTONE_OR_RECYCLED.clone(),
        ])),
        search_attrs: vec![
            Attribute::Class,
            Attribute::Uuid,
            Attribute::Name,
            Attribute::Spn,
            Attribute::PrimaryCredential,
            Attribute::AccountExpire,
            Attribute::AccountValidFrom,
            Attribute::PassKeys,
            Attribute::AttestedPasskeys,
        ],
        modify_removed_attrs: vec![
            Attribute::PrimaryCredential,
            Attribute::AccountExpire,
            Attribute::AccountValidFrom,
            Attribute::PassKeys,
            Attribute::AttestedPasskeys,
        ],
        modify_present_attrs: vec![
            Attribute::PrimaryCredential,
            Attribute::AccountExpire,
            Attribute::AccountValidFrom,
            Attribute::PassKeys,
            Attribute::AttestedPasskeys,
        ],
        ..Default::default()
    };
}

// Service Account Create/Manage
//   needs to be able to assign to entry managed by
lazy_static! {
    pub static ref IDM_ACP_SERVICE_ACCOUNT_CREATE_V1: BuiltinAcp = BuiltinAcp {
        classes: vec![
            EntryClass::Object,
            EntryClass::AccessControlProfile,
            EntryClass::AccessControlCreate,
        ],
        name: "idm_acp_service_account_create",
        uuid: UUID_IDM_ACP_SERVICE_ACCOUNT_CREATE_V1,
        description: "Builtin IDM Control for creating new service accounts.",
        receiver: BuiltinAcpReceiver::Group(vec![UUID_IDM_SERVICE_ACCOUNT_ADMINS]),
        target: BuiltinAcpTarget::Filter(ProtoFilter::And(vec![
            match_class_filter!(EntryClass::ServiceAccount).clone(),
            match_class_filter!(EntryClass::Account).clone(),
            FILTER_ANDNOT_TOMBSTONE_OR_RECYCLED.clone(),
        ])),
        create_attrs: vec![
            Attribute::Class,
            Attribute::Name,
            Attribute::DisplayName,
            Attribute::EntryManagedBy,
            Attribute::Description,
            Attribute::AccountExpire,
            Attribute::AccountValidFrom,
        ],
        create_classes: vec![
            EntryClass::Object,
            EntryClass::Account,
            EntryClass::ServiceAccount,
        ],
        ..Default::default()
    };
}

lazy_static! {
    pub static ref IDM_ACP_SERVICE_ACCOUNT_MANAGE_V1: BuiltinAcp = BuiltinAcp {
        classes: vec![
            EntryClass::Object,
            EntryClass::AccessControlProfile,
            EntryClass::AccessControlModify
        ],
        name: "idm_acp_service_account_manage",
        uuid: UUID_IDM_ACP_SERVICE_ACCOUNT_MANAGE_V1,
        description: "Builtin IDM Control for modifying service account data",
        receiver: BuiltinAcpReceiver::Group(vec![UUID_IDM_SERVICE_ACCOUNT_ADMINS]),
        target: BuiltinAcpTarget::Filter(ProtoFilter::And(vec![
            match_class_filter!(EntryClass::ServiceAccount).clone(),
            match_class_filter!(EntryClass::Account).clone(),
            FILTER_ANDNOT_HP_OR_RECYCLED_OR_TOMBSTONE.clone(),
        ])),
        modify_removed_attrs: vec![
            Attribute::Name,
            Attribute::DisplayName,
            Attribute::Mail,
            Attribute::SshPublicKey,
            Attribute::UnixPassword,
            Attribute::PrimaryCredential,
            Attribute::ApiTokenSession,
            Attribute::UserAuthTokenSession,
        ],
        modify_present_attrs: vec![Attribute::Name, Attribute::DisplayName, Attribute::Mail,],
        ..Default::default()
    };
}

lazy_static! {
    pub static ref IDM_ACP_SERVICE_ACCOUNT_DELETE_V1: BuiltinAcp = BuiltinAcp {
        classes: vec![
            EntryClass::Object,
            EntryClass::AccessControlProfile,
            EntryClass::AccessControlDelete,
        ],
        name: "idm_acp_service_account_delete",
        uuid: UUID_IDM_ACP_SERVICE_ACCOUNT_DELETE_V1,
        description: "Builtin IDM Control for deleting service accounts.",
        receiver: BuiltinAcpReceiver::Group(vec![UUID_IDM_SERVICE_ACCOUNT_ADMINS]),
        target: BuiltinAcpTarget::Filter(ProtoFilter::And(vec![
            match_class_filter!(EntryClass::ServiceAccount).clone(),
            match_class_filter!(EntryClass::Account).clone(),
            FILTER_ANDNOT_HP_OR_RECYCLED_OR_TOMBSTONE.clone(),
        ])),
        ..Default::default()
    };
}

// Service Account Credential Manage
//   entry managed by?

lazy_static! {
    pub static ref IDM_ACP_SERVICE_ACCOUNT_ENTRY_MANAGER_V1: BuiltinAcp = BuiltinAcp{
        classes: vec![
            EntryClass::Object,
            EntryClass::AccessControlProfile,
            EntryClass::AccessControlModify,
            EntryClass::AccessControlSearch
        ],
        name: "idm_acp_service_account_entry_manager",
        uuid: UUID_IDM_ACP_SERVICE_ACCOUNT_ENTRY_MANAGER_V1,
        description: "Builtin IDM Control for allowing entry managers to modify service accounts",
        receiver: BuiltinAcpReceiver::EntryManager,
        target: BuiltinAcpTarget::Filter( ProtoFilter::And(vec![
            match_class_filter!(EntryClass::Account),
            match_class_filter!(EntryClass::ServiceAccount),
            FILTER_ANDNOT_TOMBSTONE_OR_RECYCLED.clone(),
        ])),
        search_attrs: vec![
            Attribute::Class,
            Attribute::Name,
            Attribute::Spn,
            Attribute::Uuid,
            Attribute::EntryManagedBy,
            Attribute::DisplayName,
            Attribute::SshPublicKey,
            Attribute::GidNumber,
            Attribute::LoginShell,
            Attribute::UnixPassword,
            Attribute::PassKeys,
            Attribute::PrimaryCredential,
            Attribute::AccountExpire,
            Attribute::AccountValidFrom,
            Attribute::ApiTokenSession,
            Attribute::UserAuthTokenSession,
        ],
        modify_removed_attrs: vec![
            Attribute::DisplayName,
            Attribute::SshPublicKey,
            Attribute::PrimaryCredential,
            Attribute::UnixPassword,
            // For legacy upgrades we allow removing this.
            Attribute::PassKeys,
            Attribute::AccountExpire,
            Attribute::AccountValidFrom,
            Attribute::ApiTokenSession,
            Attribute::UserAuthTokenSession,
        ],
        modify_present_attrs: vec![
            Attribute::DisplayName,
            Attribute::SshPublicKey,
            Attribute::PrimaryCredential,
            // Should this be a thing? I think no?
            // Attribute::UnixPassword,
            Attribute::AccountExpire,
            Attribute::AccountValidFrom,
            Attribute::ApiTokenSession,
        ],
        ..Default::default()
    };
}

// Service Account Access Manager
lazy_static! {
    pub static ref IDM_ACP_SERVICE_ACCOUNT_ENTRY_MANAGED_BY_MODIFY_V1: BuiltinAcp = BuiltinAcp {
        classes: vec![
            EntryClass::Object,
            EntryClass::AccessControlProfile,
            EntryClass::AccessControlModify,
            EntryClass::AccessControlSearch
        ],
        name: "idm_acp_service_account_entry_managed_by_modify",
        uuid: UUID_IDM_ACP_SERVICE_ACCOUNT_ENTRY_MANAGED_BY_MODIFY,
        description:
            "Builtin IDM Control for allowing entry_managed_by to be set on service account entries",
        receiver: BuiltinAcpReceiver::Group(vec![UUID_IDM_SERVICE_ACCOUNT_ADMINS]),
        target: BuiltinAcpTarget::Filter(ProtoFilter::And(vec![
            match_class_filter!(EntryClass::ServiceAccount).clone(),
            match_class_filter!(EntryClass::Account).clone(),
            FILTER_ANDNOT_HP_OR_RECYCLED_OR_TOMBSTONE.clone(),
        ])),
        search_attrs: vec![
            Attribute::Class,
            Attribute::Name,
            Attribute::Spn,
            Attribute::Uuid,
            Attribute::EntryManagedBy,
        ],
        modify_removed_attrs: vec![Attribute::EntryManagedBy],
        modify_present_attrs: vec![Attribute::EntryManagedBy],
        ..Default::default()
    };
}

lazy_static! {
    pub static ref IDM_ACP_HP_SERVICE_ACCOUNT_ENTRY_MANAGED_BY_MODIFY_V1: BuiltinAcp = BuiltinAcp {
        classes: vec![
            EntryClass::Object,
            EntryClass::AccessControlProfile,
            EntryClass::AccessControlModify,
            EntryClass::AccessControlSearch
        ],
        name: "idm_acp_hp_service_account_entry_managed_by",
        uuid: UUID_IDM_ACP_HP_SERVICE_ACCOUNT_ENTRY_MANAGED_BY_MODIFY,
        description: "Builtin IDM Control for allowing entry_managed_by to be set on high priv service account entries",
        receiver: BuiltinAcpReceiver::Group(vec![UUID_IDM_ACCESS_CONTROL_ADMINS]),
        target: BuiltinAcpTarget::Filter(ProtoFilter::And(vec![
            match_class_filter!(EntryClass::ServiceAccount).clone(),
            match_class_filter!(EntryClass::Account).clone(),
            FILTER_HP.clone(),
            FILTER_ANDNOT_TOMBSTONE_OR_RECYCLED.clone(),
        ])),
        search_attrs: vec![
            Attribute::Class,
            Attribute::Name,
            Attribute::Spn,
            Attribute::Uuid,
            Attribute::EntryManagedBy,
        ],
        modify_removed_attrs: vec![Attribute::EntryManagedBy],
        modify_present_attrs: vec![Attribute::EntryManagedBy],
        ..Default::default()
    };
}

lazy_static! {
    pub static ref IDM_ACP_HP_CLIENT_CERTIFICATE_MANAGER_DL7: BuiltinAcp = BuiltinAcp {
        classes: vec![
            EntryClass::Object,
            EntryClass::AccessControlProfile,
            EntryClass::AccessControlCreate,
            EntryClass::AccessControlDelete,
            EntryClass::AccessControlModify,
            EntryClass::AccessControlSearch
        ],
        name: "idm_acp_hp_client_certificate_manager",
        uuid: UUID_IDM_ACP_HP_CLIENT_CERTIFICATE_MANAGER,
        description: "Builtin IDM Control for allowing client certificate management.",
        receiver: BuiltinAcpReceiver::Group(vec![UUID_IDM_CLIENT_CERTIFICATE_ADMINS]),
        target: BuiltinAcpTarget::Filter(ProtoFilter::And(vec![
            ProtoFilter::Eq(
                EntryClass::Class.to_string(),
                EntryClass::ClientCertificate.to_string()
            ),
            FILTER_ANDNOT_TOMBSTONE_OR_RECYCLED.clone()
        ])),
        search_attrs: vec![
            Attribute::Class,
            Attribute::Uuid,
            Attribute::Certificate,
            Attribute::Refers,
        ],
        modify_removed_attrs: vec![Attribute::Certificate, Attribute::Refers,],
        modify_present_attrs: vec![Attribute::Certificate, Attribute::Refers,],
        create_attrs: vec![Attribute::Class, Attribute::Certificate, Attribute::Refers,],
        create_classes: vec![EntryClass::Object, EntryClass::ClientCertificate,],
        ..Default::default()
    };
}

lazy_static! {
    pub static ref IDM_ACP_APPLICATION_MANAGE_DL8: BuiltinAcp = BuiltinAcp{
        classes: vec![
            EntryClass::Object,
            EntryClass::AccessControlProfile,
            EntryClass::AccessControlCreate,
            EntryClass::AccessControlDelete,
            EntryClass::AccessControlModify,
            EntryClass::AccessControlSearch
            ],
        name: "idm_acp_application_manage",
        uuid: UUID_IDM_ACP_APPLICATION_MANAGE,
        description: "Builtin IDM Control for creating and deleting applications in the directory",
        receiver: BuiltinAcpReceiver::Group ( vec![UUID_IDM_APPLICATION_ADMINS] ),
        // Any application
        target: BuiltinAcpTarget::Filter( ProtoFilter::And(vec![
            match_class_filter!(EntryClass::Application),
            FILTER_ANDNOT_TOMBSTONE_OR_RECYCLED.clone()
        ])),
        search_attrs: vec![
            Attribute::Class,
            Attribute::Uuid,
            Attribute::Name,
            Attribute::Description,
            Attribute::DisplayName,
            Attribute::Mail,
            Attribute::UnixPassword,
            Attribute::ApiTokenSession,
            Attribute::UserAuthTokenSession,
            Attribute::LinkedGroup,
            Attribute::EntryManagedBy,
        ],
        create_attrs: vec![
            Attribute::Class,
            Attribute::Uuid,
            Attribute::Name,
            Attribute::Description,
            Attribute::DisplayName,
            Attribute::Mail,
            Attribute::LinkedGroup,
            Attribute::EntryManagedBy,
        ],
        create_classes: vec![
            EntryClass::Object,
            EntryClass::Account,
            EntryClass::ServiceAccount,
            EntryClass::Application,
        ],
        modify_present_attrs: vec![
            Attribute::Name,
            Attribute::Description,
            Attribute::DisplayName,
            Attribute::Mail,
            Attribute::UnixPassword,
            Attribute::ApiTokenSession,
            Attribute::LinkedGroup,
            Attribute::EntryManagedBy,
        ],
        modify_removed_attrs: vec![
            Attribute::Name,
            Attribute::Description,
            Attribute::DisplayName,
            Attribute::Mail,
            Attribute::UnixPassword,
            Attribute::ApiTokenSession,
            Attribute::UserAuthTokenSession,
            Attribute::LinkedGroup,
            Attribute::EntryManagedBy,
        ],
        ..Default::default()
    };
}

lazy_static! {
    pub static ref IDM_ACP_APPLICATION_ENTRY_MANAGER_DL8: BuiltinAcp = BuiltinAcp {
        classes: vec![
            EntryClass::Object,
            EntryClass::AccessControlProfile,
            EntryClass::AccessControlModify,
            EntryClass::AccessControlSearch
        ],
        name: "idm_acp_application_entry_manager",
        uuid: UUID_IDM_ACP_APPLICATION_ENTRY_MANAGER,
        description: "Builtin IDM Control for allowing EntryManager to read and modify applications",
        receiver: BuiltinAcpReceiver::EntryManager,
        // Applications that belong to the Entry Manager.
        target: BuiltinAcpTarget::Filter( ProtoFilter::And(vec![
            match_class_filter!(EntryClass::Application),
            FILTER_ANDNOT_TOMBSTONE_OR_RECYCLED.clone()
        ])),
        search_attrs: vec![
            Attribute::Class,
            Attribute::Uuid,
            Attribute::Name,
            Attribute::DisplayName,
            Attribute::Mail,
            Attribute::UnixPassword,
            Attribute::ApiTokenSession,
            Attribute::UserAuthTokenSession,
            Attribute::Description,
            Attribute::LinkedGroup,
            Attribute::EntryManagedBy,
        ],
        modify_present_attrs: vec![
            Attribute::Name,
            Attribute::Description,
            Attribute::DisplayName,
            Attribute::Mail,
            Attribute::UnixPassword,
            Attribute::ApiTokenSession,
            Attribute::LinkedGroup,
        ],
        modify_removed_attrs: vec![
            Attribute::Name,
            Attribute::Description,
            Attribute::DisplayName,
            Attribute::Mail,
            Attribute::UnixPassword,
            Attribute::ApiTokenSession,
            Attribute::UserAuthTokenSession,
            Attribute::LinkedGroup,
        ],
        ..Default::default()
    };
}
