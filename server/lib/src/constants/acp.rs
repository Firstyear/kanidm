#![allow(clippy::expect_used)]
//! Constant Entries for the IDM

use crate::constants::uuids::*;
use crate::entry::EntryInitNew;
use crate::prelude::*;
use crate::value::Value;
use kanidm_proto::v1::Filter as ProtoFilter;

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

    pub static ref DEFAULT_TARGET_SCOPE: ProtoFilter = ProtoFilter::And(Vec::with_capacity(0));

}

#[derive(Clone, Debug)]
/// Built-in Access Control Profile definitions
pub struct BuiltinAcp {
    classes: Vec<EntryClass>,
    pub name: &'static str,
    uuid: Uuid,
    description: &'static str,
    receiver_group: Uuid,
    target_scope: ProtoFilter,
    search_attrs: Vec<Attribute>,
    modify_present_attrs: Vec<Attribute>,
    modify_removed_attrs: Vec<Attribute>,
    modify_classes: Vec<EntryClass>,
    create_classes: Vec<EntryClass>,
    create_attrs: Vec<Attribute>,
}

impl Default for BuiltinAcp {
    fn default() -> Self {
        Self {
            classes: Default::default(),
            name: Default::default(),
            uuid: Default::default(),
            description: Default::default(),
            receiver_group: Default::default(),
            search_attrs: Default::default(),
            modify_present_attrs: Default::default(),
            modify_removed_attrs: Default::default(),
            modify_classes: Default::default(),
            target_scope: DEFAULT_TARGET_SCOPE.clone(), // evals to matching nothing
            create_classes: Default::default(),
            create_attrs: Default::default(),
        }
    }
}

impl From<BuiltinAcp> for EntryInitNew {
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
        #[allow(clippy::panic)]
        if DEFAULT_TARGET_SCOPE.clone() == value.target_scope {
            panic!("Builtin ACP has an invalid target_scope! {:?}", value);
        }

        value.classes.into_iter().for_each(|class| {
            entry.add_ava(Attribute::Class, class.to_value());
        });

        entry.set_ava(Attribute::Name, [Value::new_iname(value.name)]);
        entry.set_ava(Attribute::Uuid, [Value::Uuid(value.uuid)]);
        entry.set_ava(
            Attribute::Description,
            [Value::new_utf8s(value.description)],
        );
        entry.set_ava(
            Attribute::AcpReceiverGroup,
            [Value::Refer(value.receiver_group)],
        );
        entry.set_ava(
            Attribute::AcpTargetScope,
            [Value::JsonFilt(value.target_scope)],
        );

        entry.set_ava(
            Attribute::AcpSearchAttr,
            value
                .search_attrs
                .into_iter()
                .map(|sa| sa.to_value())
                .collect::<Vec<Value>>(),
        );
        value.modify_present_attrs.into_iter().for_each(|attr| {
            entry.add_ava(Attribute::AcpModifyPresentAttr, attr.to_value());
        });
        value.modify_removed_attrs.into_iter().for_each(|attr| {
            entry.add_ava(Attribute::AcpModifyRemovedAttr, attr.to_value());
        });
        value.modify_classes.into_iter().for_each(|class| {
            entry.add_ava(Attribute::AcpModifyClass, class.to_value());
        });
        value.create_classes.into_iter().for_each(|class| {
            entry.add_ava(Attribute::AcpCreateClass, class.to_value());
        });
        value.create_attrs.into_iter().for_each(|attr| {
            entry.add_ava(Attribute::AcpCreateAttr, attr.to_value());
        });
        entry
    }
}

lazy_static! {
    pub static ref IDM_ADMINS_ACP_RECYCLE_SEARCH_V1: BuiltinAcp = BuiltinAcp {
        uuid: UUID_IDM_ADMINS_ACP_RECYCLE_SEARCH_V1,
        name: "idm_admins_acp_recycle_search",
        description: "Builtin IDM admin recycle bin search permission.",
        classes: vec![
            EntryClass::Object,
            EntryClass::AccessControlProfile,
            EntryClass::AccessControlSearch,
        ],
        receiver_group: UUID_SYSTEM_ADMINS,
        target_scope: ProtoFilter::Eq(Attribute::Class.to_string(), ATTR_RECYCLED.to_string()),

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
    pub static ref IDM_ADMINS_ACP_REVIVE_V1: BuiltinAcp = BuiltinAcp {
        uuid: UUID_IDM_ADMINS_ACP_REVIVE_V1,
        name: "idm_admins_acp_revive",
        description: "Builtin IDM admin recycle bin revive permission.",
        classes: vec![
            EntryClass::Object,
            EntryClass::AccessControlProfile,
            EntryClass::AccessControlModify,
        ],
        receiver_group: UUID_SYSTEM_ADMINS,
        target_scope: ProtoFilter::Eq(Attribute::Class.to_string(), ATTR_RECYCLED.to_string()),
        modify_removed_attrs: vec![Attribute::Class],
        modify_classes: vec![EntryClass::Recycled],
        ..Default::default()
    };
}

lazy_static! {
    pub static ref IDM_SELF_ACP_READ_V1: BuiltinAcp = BuiltinAcp {
        name: "idm_self_acp_read",
        uuid: UUID_IDM_SELF_ACP_READ_V1,
        description:
            "Builtin IDM Control for self read - required for whoami and many other functions",
        classes: vec![
            EntryClass::Object,
            EntryClass::AccessControlProfile,
            EntryClass::AccessControlSearch,
        ],
        receiver_group: UUID_IDM_ALL_ACCOUNTS,
        target_scope: ProtoFilter::SelfUuid,
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
            Attribute::DeviceKeys,
        ],
        ..Default::default()
    };

    pub static ref IDM_SELF_ACP_WRITE_V1: BuiltinAcp = BuiltinAcp{
        name: "idm_self_acp_write",
        uuid: UUID_IDM_SELF_ACP_WRITE_V1,
        classes: vec![
            EntryClass::Object,
            EntryClass::AccessControlProfile,
            EntryClass::AccessControlModify,
            ],
        description: "Builtin IDM Control for self write - required for people to update their own identities and credentials in line with best practices.",
        receiver_group: UUID_IDM_ALL_PERSONS,
        target_scope:
        ProtoFilter::And(
            vec![
                match_class_filter!(EntryClass::Person),
                ProtoFilter::Eq(EntryClass::Class.to_string(), EntryClass::Account.to_string()),
                match_class_filter!(EntryClass::Account),
                ProtoFilter::SelfUuid,
            ]
        ),
        modify_removed_attrs: vec![
            Attribute::Name,
            Attribute::DisplayName,
            Attribute::LegalName,
            Attribute::RadiusSecret,
            Attribute::PrimaryCredential,
            Attribute::SshPublicKey,
            Attribute::UnixPassword,
            Attribute::PassKeys,
            Attribute::DeviceKeys,
            Attribute::UserAuthTokenSession,
        ],
        modify_present_attrs: vec![
            Attribute::Name,
            Attribute::DisplayName,
            Attribute::LegalName,
            Attribute::RadiusSecret,
            Attribute::PrimaryCredential,
            Attribute::SshPublicKey,
            Attribute::UnixPassword,
            Attribute::PassKeys,
            Attribute::DeviceKeys,
        ],
        ..Default::default()
        };

    pub static ref IDM_ACCOUNT_SELF_ACP_WRITE_V1: BuiltinAcp = BuiltinAcp {
        name: "idm_self_account_acp_write",
        uuid: UUID_IDM_ACCOUNT_SELF_ACP_WRITE_V1,
        description: "Builtin IDM Control for self write - required for accounts to update their own session state.",
        classes: vec![
            EntryClass::Object,
            EntryClass::AccessControlProfile,
            EntryClass::AccessControlModify
            ],
        receiver_group: UUID_IDM_ALL_ACCOUNTS,
        target_scope: ProtoFilter::And(vec![ProtoFilter::Eq(Attribute::Class.to_string(), Attribute::Account.to_string()), ProtoFilter::SelfUuid]),
        modify_removed_attrs: vec![
            Attribute::UserAuthTokenSession
            ],
        ..Default::default()
    };
}

lazy_static! {
    pub static ref E_IDM_PEOPLE_SELF_ACP_WRITE_MAIL_PRIV_V1: BuiltinAcp = BuiltinAcp {
        classes: vec![
            EntryClass::Object,
            EntryClass::AccessControlProfile,
            EntryClass::AccessControlModify,
        ],
        name: "idm_people_self_acp_write_mail",
        uuid: UUID_IDM_PEOPLE_SELF_ACP_WRITE_MAIL_V1,
        description: "Builtin IDM Control for self write of mail for people accounts.",
        receiver_group: UUID_IDM_PEOPLE_SELF_WRITE_MAIL_PRIV,
        target_scope: ProtoFilter::And(vec![
            match_class_filter!(EntryClass::Person).clone(),
            match_class_filter!(EntryClass::Account).clone(),
            ProtoFilter::SelfUuid,
        ]),
        modify_removed_attrs: vec![Attribute::Mail],
        modify_present_attrs: vec![Attribute::Mail],
        ..Default::default()
    };
}

lazy_static! {
    pub static ref IDM_ALL_ACP_READ_V1: BuiltinAcp = BuiltinAcp {
        classes: vec![
            EntryClass::Object,
            EntryClass::AccessControlProfile,
            EntryClass::AccessControlSearch,
        ],
        name: "idm_all_acp_read",
        uuid: UUID_IDM_ALL_ACP_READ_V1,
        description:
            "Builtin IDM Control for all read - e.g. anonymous and all authenticated accounts.",
        receiver_group: UUID_IDM_ALL_ACCOUNTS,
        target_scope: ProtoFilter::And(
            vec![
                ProtoFilter::Or(vec![
                    match_class_filter!(EntryClass::Account),
                    match_class_filter!(EntryClass::Group),
                ]),
                FILTER_ANDNOT_TOMBSTONE_OR_RECYCLED.clone(),
            ]
        ),

        // Value::new_json_filter_s(
        //     "{\"and\":
        //              [{\"or\":
        //                  [{\"eq\": [\"class\",\"account\"]},
        //                   {\"eq\": [\"class\",\"group\"]}]
        //               },
        //              {\"andnot\":
        //                  {\"or\":
        //                      [{\"eq\": [\"class\", \"tombstone\"]},
        //                       {\"eq\": [\"class\", \"recycled\"]}
        //                      ]
        //                  }
        //              }
        //          ]}"
        // )
        // .expect("Invalid JSON filter"),
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
    pub static ref IDM_ACP_PEOPLE_READ_PRIV_V1: BuiltinAcp = BuiltinAcp {
        classes: vec![
            EntryClass::Object,
            EntryClass::AccessControlProfile,
            EntryClass::AccessControlSearch,
        ],
        name: "idm_acp_people_read_priv",
        uuid: UUID_IDM_ACP_PEOPLE_READ_PRIV_V1,
        description: "Builtin IDM Control for reading personal sensitive data.",
        receiver_group: UUID_IDM_PEOPLE_READ_PRIV,
        target_scope: ProtoFilter::And(vec![
            match_class_filter!(EntryClass::Person).clone(),
            ProtoFilter::AndNot(Box::new(FILTER_HP_OR_RECYCLED_OR_TOMBSTONE.clone())),
        ]),
        search_attrs: vec![
            Attribute::Class,
            Attribute::Name,
            Attribute::DisplayName,
            Attribute::LegalName,
            Attribute::Mail,
        ],
        ..Default::default()
    };
}

lazy_static! {
    pub static ref IDM_ACP_PEOPLE_WRITE_PRIV_V1: BuiltinAcp = BuiltinAcp {
        classes: vec![
            EntryClass::Object,
            EntryClass::AccessControlProfile,
            EntryClass::AccessControlModify
        ],
        name: "idm_acp_people_write_priv",
        uuid: UUID_IDM_ACP_PEOPLE_WRITE_PRIV_V1,
        description: "Builtin IDM Control for managing personal and sensitive data.",
        receiver_group: UUID_IDM_PEOPLE_WRITE_PRIV,

        target_scope: ProtoFilter::And(vec![
            match_class_filter!(EntryClass::Person).clone(),
            ProtoFilter::AndNot(Box::new(FILTER_HP_OR_RECYCLED_OR_TOMBSTONE.clone())),
        ]),

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
    pub static ref IDM_ACP_PEOPLE_MANAGE_PRIV_V1: BuiltinAcp = BuiltinAcp {
        classes: vec![
            EntryClass::Object,
            EntryClass::AccessControlProfile,
            EntryClass::AccessControlDelete,
            EntryClass::AccessControlCreate
        ],
        name: "idm_acp_people_manage",
        uuid: UUID_IDM_ACP_PEOPLE_MANAGE_PRIV_V1,
        description: "Builtin IDM Control for creating person (user) accounts",
        receiver_group: UUID_IDM_PEOPLE_MANAGE_PRIV,
        target_scope: ProtoFilter::And(vec![
            match_class_filter!(EntryClass::Person),
            match_class_filter!(EntryClass::Account),
            ProtoFilter::AndNot(Box::new(FILTER_HP_OR_RECYCLED_OR_TOMBSTONE.clone())),
        ]),

        create_attrs: vec![
            Attribute::Class,
            Attribute::Name,
            Attribute::DisplayName,
            Attribute::LegalName,
            Attribute::PrimaryCredential,
            Attribute::SshPublicKey,
            Attribute::Mail,
            Attribute::AccountExpire,
            Attribute::AccountValidFrom,
            Attribute::PassKeys,
            Attribute::DeviceKeys,
        ],
        create_classes: vec![EntryClass::Object, EntryClass::Account, EntryClass::Person,],
        ..Default::default()
    };
}

// 31 - password import modification priv
// right now, create requires you to have access to every attribute in a single snapshot,
// so people will need to two step (create then import pw). Later we could add another
// acp that allows the create here too? Should it be separate?
lazy_static! {
    pub static ref IDM_ACP_PEOPLE_ACCOUNT_PASSWORD_IMPORT_PRIV_V1: BuiltinAcp = BuiltinAcp {
        classes: vec![
            EntryClass::Object,
            EntryClass::AccessControlProfile,
            EntryClass::AccessControlModify
        ],
        name: "idm_acp_people_account_password_import_priv",
        uuid: UUID_IDM_ACP_PEOPLE_ACCOUNT_PASSWORD_IMPORT_PRIV_V1,
        description:
            "Builtin IDM Control for allowing imports of passwords to people+account types.",
        receiver_group: UUID_IDM_PEOPLE_ACCOUNT_PASSWORD_IMPORT_PRIV,
        target_scope: ProtoFilter::And(vec![
            match_class_filter!(EntryClass::Person),
            match_class_filter!(EntryClass::Account),
            ProtoFilter::AndNot(Box::new(FILTER_HP_OR_RECYCLED_OR_TOMBSTONE.clone())),
        ]),

        modify_removed_attrs: vec![Attribute::PasswordImport],
        modify_present_attrs: vec![Attribute::PasswordImport],
        ..Default::default()
    };
}

lazy_static! {
    pub static ref IDM_ACP_PEOPLE_EXTEND_PRIV_V1: BuiltinAcp = BuiltinAcp {
        classes: vec![
            EntryClass::Object,
            EntryClass::AccessControlProfile,
            EntryClass::AccessControlModify
        ],
        name: "idm_acp_people_extend_priv",
        uuid: UUID_IDM_ACP_PEOPLE_EXTEND_PRIV_V1,
        description: "Builtin IDM Control for allowing person class extension",
        receiver_group: UUID_IDM_PEOPLE_EXTEND_PRIV,
        target_scope: ProtoFilter::And(vec![
            match_class_filter!(EntryClass::Account).clone(),
            ProtoFilter::AndNot(Box::new(FILTER_HP_OR_RECYCLED_OR_TOMBSTONE.clone())),
        ]),
        modify_removed_attrs: vec![
            Attribute::Name,
            Attribute::DisplayName,
            Attribute::LegalName,
            Attribute::Mail,
        ],
        modify_present_attrs: vec![
            Attribute::Class,
            Attribute::Name,
            Attribute::DisplayName,
            Attribute::LegalName,
            Attribute::Name,
        ],
        modify_classes: vec![EntryClass::Person,],
        ..Default::default()
    };
    pub static ref IDM_ACP_HP_PEOPLE_READ_PRIV_V1: BuiltinAcp = BuiltinAcp {
        classes: vec![
            EntryClass::Object,
            EntryClass::AccessControlProfile,
            EntryClass::AccessControlSearch,
        ],
        name: "idm_acp_hp_people_read_priv",
        uuid: UUID_IDM_ACP_HP_PEOPLE_READ_PRIV_V1,
        description: "Builtin IDM Control for reading high privilege personal sensitive data.",
        receiver_group: UUID_IDM_HP_PEOPLE_READ_PRIV,
        target_scope: ProtoFilter::And(vec![
            match_class_filter!(EntryClass::Person).clone(),
            ProtoFilter::AndNot(Box::new(FILTER_HP_OR_RECYCLED_OR_TOMBSTONE.clone())),
        ]),
        search_attrs: vec![
            Attribute::Name,
            Attribute::DisplayName,
            Attribute::LegalName,
            Attribute::Mail,
        ],
        ..Default::default()
    };
}

lazy_static! {
    pub static ref IDM_ACP_ACCOUNT_MAIL_READ_PRIV_V1: BuiltinAcp = BuiltinAcp {
        classes: vec![
            EntryClass::Object,
            EntryClass::AccessControlProfile,
            EntryClass::AccessControlSearch
        ],
        name: "idm_acp_account_mail_read_priv",
        uuid: UUID_IDM_ACP_ACCOUNT_MAIL_READ_PRIV_V1,
        description: "Builtin IDM Control for reading account mail attributes.",
        receiver_group: UUID_IDM_ACCOUNT_MAIL_READ_PRIV,
        target_scope: ProtoFilter::And(vec![
            match_class_filter!(EntryClass::Account),
            FILTER_ANDNOT_TOMBSTONE_OR_RECYCLED.clone(),
        ]),

        search_attrs: vec![Attribute::Mail],
        ..Default::default()
    };
    pub static ref IDM_ACP_HP_PEOPLE_WRITE_PRIV_V1: BuiltinAcp = BuiltinAcp {
        classes: vec![
            EntryClass::Object,
            EntryClass::AccessControlProfile,
            EntryClass::AccessControlModify
        ],
        name: "idm_acp_hp_people_write_priv",
        uuid: UUID_IDM_ACP_HP_PEOPLE_WRITE_PRIV_V1,
        description: "Builtin IDM Control for managing privilege personal and sensitive data.",
        receiver_group: UUID_IDM_HP_PEOPLE_WRITE_PRIV,
        target_scope: ProtoFilter::And(vec![
            match_class_filter!(EntryClass::Person).clone(),
            ProtoFilter::Eq(
                Attribute::MemberOf.to_string(),
                UUID_IDM_HIGH_PRIVILEGE.to_string()
            ),
            ProtoFilter::AndNot(Box::new(FILTER_HP_OR_RECYCLED_OR_TOMBSTONE.clone())),
        ]),
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
            Attribute::Name,
        ],
        ..Default::default()
    };
    pub static ref IDM_ACP_HP_PEOPLE_EXTEND_PRIV_V1: BuiltinAcp = BuiltinAcp {
        classes: vec![
            EntryClass::Object,
            EntryClass::AccessControlProfile,
            EntryClass::AccessControlModify
        ],
        name: "idm_acp_hp_people_extend_priv",
        uuid: UUID_IDM_ACP_HP_PEOPLE_EXTEND_PRIV_V1,
        description: "Builtin IDM Control for allowing privilege person class extension",
        receiver_group: UUID_IDM_HP_PEOPLE_EXTEND_PRIV,
        target_scope: ProtoFilter::And(vec![
            match_class_filter!(EntryClass::Account),
            ProtoFilter::Eq(
                Attribute::MemberOf.to_string(),
                UUID_IDM_HIGH_PRIVILEGE.to_string()
            ),
            FILTER_ANDNOT_TOMBSTONE_OR_RECYCLED.clone()
        ]),
        modify_removed_attrs: vec![
            Attribute::Name,
            Attribute::DisplayName,
            Attribute::LegalName,
            Attribute::Mail,
        ],
        modify_present_attrs: vec![
            Attribute::Class,
            Attribute::Name,
            Attribute::DisplayName,
            Attribute::LegalName,
            Attribute::Name,
        ],
        modify_classes: vec![EntryClass::Person,],
        ..Default::default()
    };
}

// -- end people

lazy_static! {
    pub static ref IDM_ACP_GROUP_WRITE_PRIV_V1: BuiltinAcp = BuiltinAcp{
        classes: vec![
            EntryClass::Object,
            EntryClass::AccessControlProfile,
            EntryClass::AccessControlModify,
            EntryClass::AccessControlSearch
        ],
        name: "idm_acp_group_write_priv",
        uuid: UUID_IDM_ACP_GROUP_WRITE_PRIV_V1,
        description: "Builtin IDM Control for managing groups",
        receiver_group: UUID_IDM_GROUP_WRITE_PRIV,
        // group which is not in HP, Recycled, Tombstone
        target_scope: ProtoFilter::And(vec![
            match_class_filter!(EntryClass::Group),
            ProtoFilter::AndNot(Box::new(FILTER_HP_OR_RECYCLED_OR_TOMBSTONE.clone())),

        ]),
        search_attrs: vec![
            Attribute::Class,
            Attribute::Name,
            Attribute::Uuid,
            Attribute::Spn,
            Attribute::Uuid,
            Attribute::Description,
            Attribute::Member,
            Attribute::DynMember,

        ],
        modify_present_attrs: vec![
            Attribute::Name,
            Attribute::Description,
            Attribute::Member,
        ],
        modify_removed_attrs: vec![
            Attribute::Name,
            Attribute::Description,
            Attribute::Member,
        ],
        ..Default::default()
    };
}

lazy_static! {
    pub static ref IDM_ACP_ACCOUNT_READ_PRIV_V1: BuiltinAcp = BuiltinAcp{
        classes: vec![
            EntryClass::Object,
            EntryClass::AccessControlProfile,
            EntryClass::AccessControlSearch
        ],
        name: "idm_acp_account_read_priv",
        uuid: UUID_IDM_ACP_ACCOUNT_READ_PRIV_V1,
        description: "Builtin IDM Control for reading accounts.",
        receiver_group: UUID_IDM_ACCOUNT_READ_PRIV,
        // Account which is not in HP, Recycled, Tombstone
        target_scope: ProtoFilter::And(vec![
            match_class_filter!(EntryClass::Account),
            ProtoFilter::AndNot(Box::new(FILTER_HP_OR_RECYCLED_OR_TOMBSTONE.clone())),
        ]),

        search_attrs: vec![
            Attribute::Class,
            Attribute::Name,
            Attribute::Spn,
            Attribute::Uuid,
            Attribute::DisplayName,
            Attribute::SshPublicKey,
            Attribute::PrimaryCredential,
            Attribute::MemberOf,
            Attribute::Mail,
            Attribute::GidNumber,
            Attribute::AccountExpire,
            Attribute::AccountValidFrom,
            Attribute::PassKeys,
            Attribute::DeviceKeys,
            Attribute::ApiTokenSession,
            Attribute::UserAuthTokenSession,
        ],
        ..Default::default()
    };
}

lazy_static! {
    pub static ref IDM_ACP_ACCOUNT_WRITE_PRIV_V1: BuiltinAcp = BuiltinAcp{
        classes: vec![
            EntryClass::Object,
            EntryClass::AccessControlProfile,
            EntryClass::AccessControlModify
        ],
        name: "idm_acp_account_write_priv",
        uuid: UUID_IDM_ACP_ACCOUNT_WRITE_PRIV_V1,
        description: "Builtin IDM Control for managing all accounts (both person and service).",
        receiver_group: UUID_IDM_ACCOUNT_WRITE_PRIV,
        // Account which is not in HP, Recycled, Tombstone
        target_scope: ProtoFilter::And(vec![
            match_class_filter!(EntryClass::Account),
            ProtoFilter::AndNot(Box::new(FILTER_HP_OR_RECYCLED_OR_TOMBSTONE.clone())),
        ]),

        modify_removed_attrs: vec![
            Attribute::Name,
            Attribute::DisplayName,
            Attribute::SshPublicKey,
            Attribute::PrimaryCredential,
            Attribute::Mail,
            Attribute::AccountExpire,
            Attribute::AccountValidFrom,
            Attribute::PassKeys,
            Attribute::DeviceKeys,
            Attribute::ApiTokenSession,
            Attribute::UserAuthTokenSession,
            Attribute::IdVerificationEcKey,
        ],
        modify_present_attrs: vec![
            Attribute::Name,
            Attribute::DisplayName,
            Attribute::SshPublicKey,
            Attribute::PrimaryCredential,
            Attribute::Mail,
            Attribute::AccountExpire,
            Attribute::AccountValidFrom,
            Attribute::PassKeys,
            Attribute::DeviceKeys,
            Attribute::ApiTokenSession,
        ],
        ..Default::default()

    };
}

lazy_static! {
    pub static ref IDM_ACP_ACCOUNT_MANAGE_PRIV_V1: BuiltinAcp = BuiltinAcp{
        classes: vec![
            EntryClass::Object,
            EntryClass::AccessControlProfile,
            EntryClass::AccessControlDelete,
            EntryClass::AccessControlCreate,
        ],
        name: "idm_acp_account_manage",
        uuid: UUID_IDM_ACP_ACCOUNT_MANAGE_PRIV_V1,
        description: "Builtin IDM Control for creating and deleting (service) accounts",
        receiver_group: UUID_IDM_ACCOUNT_MANAGE_PRIV,
        // Account which is not in HP, Recycled, Tombstone
        target_scope: ProtoFilter::And(vec![
            match_class_filter!(EntryClass::Account),
            ProtoFilter::AndNot(Box::new(FILTER_HP_OR_RECYCLED_OR_TOMBSTONE.clone())),
        ]),
        create_attrs: vec![
            Attribute::Class,
            Attribute::Name,
            Attribute::DisplayName,
            Attribute::Description,
            Attribute::PrimaryCredential,
            Attribute::SshPublicKey,
            Attribute::Mail,
            Attribute::AccountExpire,
            Attribute::AccountValidFrom,
            Attribute::PassKeys,
            Attribute::DeviceKeys,
        ],
        create_classes: vec![
            EntryClass::Object,
            EntryClass::Account,
            EntryClass::ServiceAccount,
        ],
        ..Default::default()
    };
}

// 14 radius read acp JSON_IDM_RADIUS_SERVERS_V1
// The targetscope of this could change later to a "radius access" group or similar so we can add/remove
//  users from having radius access easier.

lazy_static! {
    pub static ref IDM_ACP_RADIUS_SECRET_READ_PRIV_V1: BuiltinAcp = BuiltinAcp{
        classes: vec![
            EntryClass::Object,
            EntryClass::AccessControlProfile,
            EntryClass::AccessControlSearch,
        ],
        name: "idm_acp_radius_secret_read_priv",
        uuid: UUID_IDM_ACP_RADIUS_SECRET_READ_PRIV_V1,
        description: "Builtin IDM Control for reading user radius secrets.",
        receiver_group: UUID_IDM_RADIUS_SECRET_READ_PRIV_V1,
        // Account which is not in HP, Recycled, Tombstone
        target_scope: ProtoFilter::And(vec![
            match_class_filter!(EntryClass::Account),
            ProtoFilter::AndNot(Box::new(FILTER_HP_OR_RECYCLED_OR_TOMBSTONE.clone())),
        ]),
        search_attrs: vec![
            Attribute::RadiusSecret
        ],
        ..Default::default()
    };


    pub static ref IDM_ACP_RADIUS_SECRET_WRITE_PRIV_V1: BuiltinAcp = BuiltinAcp{
        classes: vec![
            EntryClass::Object,
            EntryClass::AccessControlProfile,
            EntryClass::AccessControlModify,
        ],
        name: "idm_acp_radius_secret_write_priv",
        uuid: UUID_IDM_ACP_RADIUS_SECRET_WRITE_PRIV_V1,
        description: "Builtin IDM Control allowing writes to user radius secrets.",
        receiver_group: UUID_IDM_RADIUS_SECRET_WRITE_PRIV_V1,
        // Account which is not in HP, Recycled, Tombstone
        target_scope: ProtoFilter::And(vec![
            match_class_filter!(EntryClass::Account),
            ProtoFilter::AndNot(Box::new(FILTER_HP_OR_RECYCLED_OR_TOMBSTONE.clone())),
        ]),
        modify_present_attrs:vec![Attribute::RadiusSecret],
        modify_removed_attrs: vec![Attribute::RadiusSecret],
        ..Default::default()


    };


    pub static ref IDM_ACP_RADIUS_SERVERS_V1: BuiltinAcp = BuiltinAcp{
        classes: vec![
            EntryClass::Object,
            EntryClass::AccessControlProfile,
            EntryClass::AccessControlSearch,
        ],
        name: "idm_acp_radius_servers",
        uuid: UUID_IDM_ACP_RADIUS_SERVERS_V1,
        description: "Builtin IDM Control for RADIUS servers to read credentials and other needed details.",
        receiver_group: UUID_IDM_RADIUS_SERVERS,
        // has a class, and isn't recycled/tombstoned
        target_scope: ProtoFilter::And(vec![
            ProtoFilter::Pres(EntryClass::Class.to_string()),
            FILTER_ANDNOT_TOMBSTONE_OR_RECYCLED.clone()
        ]),
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
    pub static ref IDM_ACP_HP_ACCOUNT_READ_PRIV_V1: BuiltinAcp = BuiltinAcp{
        classes: vec![
            EntryClass::Object,
            EntryClass::AccessControlProfile,
            EntryClass::AccessControlSearch,
        ],
        name: "idm_acp_hp_account_read_priv",
        uuid: UUID_IDM_ACP_HP_ACCOUNT_READ_PRIV_V1,
        description: "Builtin IDM Control for reading high privilege accounts.",
        receiver_group: UUID_IDM_HP_ACCOUNT_READ_PRIV,
        // account, in hp, not recycled/tombstoned
        target_scope: ProtoFilter::And(vec![
            match_class_filter!(EntryClass::Account),
            FILTER_HP.clone(),
            FILTER_ANDNOT_TOMBSTONE_OR_RECYCLED.clone(),
        ]),
        search_attrs: vec![
            Attribute::Class,
            Attribute::Name,
            Attribute::Spn,
            Attribute::Uuid,
            Attribute::DisplayName,
            Attribute::SshPublicKey,
            Attribute::PrimaryCredential,
            Attribute::MemberOf,
            Attribute::AccountExpire,
            Attribute::AccountValidFrom,
            Attribute::PassKeys,
            Attribute::DeviceKeys,
            Attribute::ApiTokenSession,
            Attribute::UserAuthTokenSession,
        ],
        ..Default::default()
    };

    pub static ref IDM_ACP_HP_ACCOUNT_WRITE_PRIV_V1: BuiltinAcp = BuiltinAcp{
        classes: vec![
            EntryClass::Object,
            EntryClass::AccessControlProfile,
            EntryClass::AccessControlModify],
        name: "idm_acp_hp_account_write_priv",
        uuid: UUID_IDM_ACP_HP_ACCOUNT_WRITE_PRIV_V1,
        description: "Builtin IDM Control for managing high privilege accounts (both person and service).",
        receiver_group: UUID_IDM_HP_ACCOUNT_WRITE_PRIV,
        // account, in hp, not recycled/tombstoned
        target_scope: ProtoFilter::And(vec![
            match_class_filter!(EntryClass::Account),
            FILTER_HP.clone(),
            FILTER_ANDNOT_TOMBSTONE_OR_RECYCLED.clone(),
        ]),
        modify_removed_attrs: vec![
            Attribute::Name,
            Attribute::DisplayName,
            Attribute::SshPublicKey,
            Attribute::PrimaryCredential,
            Attribute::AccountExpire,
            Attribute::AccountValidFrom,
            Attribute::PassKeys,
            Attribute::DeviceKeys,
            Attribute::ApiTokenSession,
            Attribute::UserAuthTokenSession,
            Attribute::IdVerificationEcKey,
        ],
        modify_present_attrs: vec![
            Attribute::Name,
            Attribute::DisplayName,
            Attribute::SshPublicKey,
            Attribute::PrimaryCredential,
            Attribute::AccountExpire,
            Attribute::AccountValidFrom,
            Attribute::PassKeys,
            Attribute::DeviceKeys,
            Attribute::ApiTokenSession,
        ],
        ..Default::default()
    };
}

lazy_static! {
    pub static ref IDM_ACP_HP_GROUP_WRITE_PRIV_V1: BuiltinAcp = BuiltinAcp{
        classes: vec![
            EntryClass::Object,
        EntryClass::AccessControlProfile,
        EntryClass::AccessControlModify,
        EntryClass::AccessControlSearch],
        name: "idm_acp_hp_group_write_priv",
        uuid: UUID_IDM_ACP_HP_GROUP_WRITE_PRIV_V1,
        description: "Builtin IDM Control for managing high privilege groups",
        receiver_group: UUID_IDM_HP_GROUP_WRITE_PRIV,
        // group, is HP, isn't recycled/tombstoned
        target_scope: ProtoFilter::And(vec![
            match_class_filter!(EntryClass::Group),
            FILTER_HP.clone(),
            FILTER_ANDNOT_TOMBSTONE_OR_RECYCLED.clone(),
        ]),
        // Value::new_json_filter_s(
        //         "{\"and\":
        //             [{\"eq\": [\"class\",\"group\"]},
        //             {\"eq\": [\"memberof\",\"00000000-0000-0000-0000-000000001000\"]},
        //             {\"andnot\": {\"or\": [{\"eq\": [\"class\", \"tombstone\"]}, {\"eq\": [\"class\", \"recycled\"]}]}}]}"
        //     )
        //         .expect("Invalid JSON filter"),
        search_attrs: vec![
            Attribute::Class,
            Attribute::Name,
            Attribute::Uuid,
            Attribute::Spn,
            Attribute::Uuid,
            Attribute::Description,
            Attribute::Member,
            Attribute::DynMember,
        ],
        modify_removed_attrs: vec![
            Attribute::Name,
            Attribute::Description,
            Attribute::Member,
        ],
        modify_present_attrs: vec![
            Attribute::Name,
            Attribute::Description,
            Attribute::Member,
        ],
        ..Default::default()
    };
}

lazy_static! {
    pub static ref IDM_ACP_SCHEMA_WRITE_ATTRS_PRIV_V1: BuiltinAcp = BuiltinAcp{
        classes: vec![
            EntryClass::Object,
            EntryClass::AccessControlProfile,
            EntryClass::AccessControlCreate,
            EntryClass::AccessControlModify,
            EntryClass::AccessControlSearch
        ],
        name: "idm_acp_schema_write_attrs_priv",
        uuid: UUID_IDM_ACP_SCHEMA_WRITE_ATTRS_PRIV_V1,
        description: "Builtin IDM Control for management of schema attributes.",
        receiver_group: UUID_IDM_SCHEMA_MANAGE_PRIV,
        // has a class, and isn't recycled/tombstoned
        target_scope: ProtoFilter::And(vec![
            ProtoFilter::Eq(EntryClass::Class.to_string(),EntryClass::AttributeType.to_string()),
            FILTER_ANDNOT_TOMBSTONE_OR_RECYCLED.clone()
        ]),

        // Value::new_json_filter_s(
        //         "{\"and\": [{\"eq\": [\"class\",\"attributetype\"]}, {\"andnot\": {\"or\": [{\"eq\": [\"class\", \"tombstone\"]}, {\"eq\": [\"class\", \"recycled\"]}]}}]}"
        //     )
        //         .expect("Invalid JSON filter"),
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
    pub static ref IDM_ACP_ACP_MANAGE_PRIV_V1: BuiltinAcp = BuiltinAcp{
        classes: vec![
            EntryClass::Object,
            EntryClass::AccessControlProfile,
            EntryClass::AccessControlCreate,
            EntryClass::AccessControlDelete,
            EntryClass::AccessControlModify,
            EntryClass::AccessControlSearch
        ],
        name: "idm_acp_acp_manage_priv",
        uuid: UUID_IDM_ACP_ACP_MANAGE_PRIV_V1,
        description: "Builtin IDM Control for access profiles management.",
        receiver_group: UUID_IDM_ACP_MANAGE_PRIV,
         // has a class, and isn't recycled/tombstoned
         target_scope: ProtoFilter::And(vec![
            ProtoFilter::Eq(EntryClass::Class.to_string(),EntryClass::AccessControlProfile.to_string()),
            FILTER_ANDNOT_TOMBSTONE_OR_RECYCLED.clone()
        ]),
        // target_scope: Value::new_json_filter_s(
        //         "{\"and\": [{\"eq\": [\"class\",\"access_control_profile\"]}, {\"andnot\": {\"or\": [{\"eq\": [\"class\", \"tombstone\"]}, {\"eq\": [\"class\", \"recycled\"]}]}}]}"
        //     )
        //         .expect("Invalid JSON filter"),
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
    };


    pub static ref IDM_ACP_SCHEMA_WRITE_CLASSES_PRIV_V1: BuiltinAcp = BuiltinAcp{
        classes: vec![
            EntryClass::Object,
            EntryClass::AccessControlProfile,
            EntryClass::AccessControlCreate,
            EntryClass::AccessControlModify,
            EntryClass::AccessControlSearch
        ],
        name: "idm_acp_schema_write_classes_priv",
        uuid: UUID_IDM_ACP_SCHEMA_WRITE_CLASSES_PRIV_V1,
        description: "Builtin IDM Control for management of schema classes.",
        receiver_group: UUID_IDM_SCHEMA_MANAGE_PRIV,
        target_scope: ProtoFilter::And(vec![
            ProtoFilter::Eq(EntryClass::Class.to_string(), EntryClass::ClassType.to_string()),
            FILTER_ANDNOT_TOMBSTONE_OR_RECYCLED.clone()
        ]),
        // Value::new_json_filter_s(
        //         "{\"and\": [{\"eq\": [\"class\",\"classtype\"]},
        //         {\"andnot\": {\"or\": [{\"eq\": [\"class\", \"tombstone\"]}, {\"eq\": [\"class\", \"recycled\"]}]}}]}"
        //     )
        //         .expect("Invalid JSON filter"),
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
        create_classes: vec![
            EntryClass::Object,
            EntryClass::ClassType,
        ],
        ..Default::default()
    };

    pub static ref IDM_ACP_GROUP_MANAGE_PRIV_V1: BuiltinAcp = BuiltinAcp{
        classes: vec![
            EntryClass::Object,
            EntryClass::AccessControlProfile,
            EntryClass::AccessControlDelete,
            EntryClass::AccessControlCreate
            ],
        name: "idm_acp_group_manage",
        uuid: UUID_IDM_ACP_GROUP_MANAGE_PRIV_V1,
        description: "Builtin IDM Control for creating and deleting groups in the directory",
        receiver_group: UUID_IDM_GROUP_MANAGE_PRIV,
         // group which is not in HP, Recycled, Tombstone
         target_scope: ProtoFilter::And(vec![
            match_class_filter!(EntryClass::Group),
            ProtoFilter::AndNot(Box::new(FILTER_HP_OR_RECYCLED_OR_TOMBSTONE.clone())),

        ]),
        // target_scope: Value::new_json_filter_s(
        //         "{\"and\": [{\"eq\": [\"class\",\"group\"]}, {\"andnot\": {\"or\": [{\"eq\": [\"memberof\",\"00000000-0000-0000-0000-000000001000\"]}, {\"eq\": [\"class\", \"tombstone\"]}, {\"eq\": [\"class\", \"recycled\"]}]}}]}"
        //     )
        //         .expect("Invalid JSON filter"),
        create_attrs: vec![
            Attribute::Class,
            Attribute::Name,
            Attribute::Description,
            Attribute::Member,
        ],
        create_classes: vec![
            EntryClass::Object,
            EntryClass::Group,
        ],
        ..Default::default()
    };

    pub static ref IDM_ACP_GROUP_ACCOUNT_POLICY_MANAGE_PRIV_V1: BuiltinAcp = BuiltinAcp{
        classes: vec![
            EntryClass::Object,
            EntryClass::AccessControlProfile,
            EntryClass::AccessControlCreate,
            EntryClass::AccessControlModify,
            EntryClass::AccessControlSearch
            ],
        name: "idm_acp_group_account_policy_manage",
        uuid: UUID_IDM_GROUP_ACCOUNT_POLICY_MANAGE_PRIV,
        description: "Builtin IDM Control for management of account policy on groups",
        // For now just target SA because we are going to rework this soon and I think
        // there isn't a great reason to make more small priv groups that we plan to
        // erase.
        receiver_group: UUID_SYSTEM_ADMINS,
         // group which is not in HP, Recycled, Tombstone
         target_scope: ProtoFilter::And(vec![
            match_class_filter!(EntryClass::Group),
            ProtoFilter::AndNot(Box::new(FILTER_HP_OR_RECYCLED_OR_TOMBSTONE.clone())),

        ]),
        search_attrs: vec![
            Attribute::Class,
            Attribute::Name,
            Attribute::Uuid,
            Attribute::AuthSessionExpiry,
            Attribute::PrivilegeExpiry,
        ],
        modify_removed_attrs: vec![
            Attribute::Class,
            Attribute::AuthSessionExpiry,
            Attribute::PrivilegeExpiry,
        ],
        modify_present_attrs: vec![
            Attribute::Class,
            Attribute::AuthSessionExpiry,
            Attribute::PrivilegeExpiry,
        ],
        modify_classes: vec![
            EntryClass::AccountPolicy,
        ],
        create_attrs: vec![
            Attribute::Class,
        ],
        create_classes: vec![
            EntryClass::AccountPolicy,
        ],
    };
}

lazy_static! {
    pub static ref IDM_ACP_HP_ACCOUNT_MANAGE_PRIV_V1: BuiltinAcp = BuiltinAcp{
        classes: vec![
            EntryClass::Object,
            EntryClass::AccessControlProfile,
            EntryClass::AccessControlDelete,
            EntryClass::AccessControlCreate
        ],
        name: "idm_acp_hp_account_manage",
        uuid: UUID_IDM_ACP_HP_ACCOUNT_MANAGE_PRIV_V1,
        description: "Builtin IDM Control for creating and deleting hp and regular (service) accounts",
        receiver_group: UUID_IDM_HP_ACCOUNT_MANAGE_PRIV,
        // account that's not tombstoned?
        target_scope: ProtoFilter::And(vec![
            match_class_filter!(EntryClass::Account),
            FILTER_ANDNOT_TOMBSTONE_OR_RECYCLED.clone(),
        ]),
        create_attrs: vec![
            Attribute::Class,
            Attribute::Name,
            Attribute::DisplayName,
            Attribute::Description,
            Attribute::PrimaryCredential,
            Attribute::SshPublicKey,
            Attribute::AccountExpire,
            Attribute::AccountValidFrom,
            Attribute::PassKeys,
            Attribute::DeviceKeys,
        ],
        create_classes: vec![
            EntryClass::Object,
            EntryClass::Account,
            EntryClass::ServiceAccount,
        ],
        ..Default::default()
    };


    pub static ref IDM_ACP_HP_GROUP_MANAGE_PRIV_V1: BuiltinAcp = BuiltinAcp{
        classes: vec![
            EntryClass::Object,
            EntryClass::AccessControlProfile,
            EntryClass::AccessControlDelete,
            EntryClass::AccessControlCreate
        ],
        name: "idm_acp_hp_group_manage",
        uuid: UUID_IDM_ACP_HP_GROUP_MANAGE_PRIV_V1,
        description: "Builtin IDM Control for creating and deleting hp and regular groups in the directory",
        receiver_group: UUID_IDM_HP_GROUP_MANAGE_PRIV,
        // account that's not tombstoned?
        target_scope: ProtoFilter::And(vec![
            match_class_filter!(EntryClass::Group),
            FILTER_ANDNOT_TOMBSTONE_OR_RECYCLED.clone(),
        ]),
        create_attrs: vec![
            Attribute::Class,
            Attribute::Name,
            Attribute::Description,
            Attribute::Member,
        ],
        create_classes: vec![
            EntryClass::Object,
            EntryClass::Group,
        ],
        ..Default::default()
    };

    pub static ref IDM_ACP_DOMAIN_ADMIN_PRIV_V1: BuiltinAcp = BuiltinAcp{
        classes: vec![
            EntryClass::Object,
            EntryClass::AccessControlProfile,
            EntryClass::AccessControlModify,
            EntryClass::AccessControlSearch
        ],
        name: "idm_acp_domain_admin_priv",
        uuid: UUID_IDM_ACP_DOMAIN_ADMIN_PRIV_V1,
        description: "Builtin IDM Control for granting domain info administration locally",
        receiver_group: UUID_DOMAIN_ADMINS,
        // STR_UUID_DOMAIN_INFO
        target_scope: ProtoFilter::And(vec![
            ProtoFilter::Eq(Attribute::Uuid.to_string(),STR_UUID_DOMAIN_INFO.to_string()),
            FILTER_ANDNOT_TOMBSTONE_OR_RECYCLED.clone()
        ]),
        // target_scope: Value::new_json_filter_s(
        //         "{\"and\": [{\"eq\": [\"uuid\",\"00000000-0000-0000-0000-ffffff000025\"]}, {\"andnot\": {\"or\": [{\"eq\": [\"class\", \"tombstone\"]}, {\"eq\": [\"class\", \"recycled\"]}]}}]}"
        //     )
        //         .expect("Invalid JSON filter"),
        search_attrs: vec![
            Attribute::Class,
            Attribute::Name,
            Attribute::Uuid,
            Attribute::DomainDisplayName,
            Attribute::DomainName,
            Attribute::DomainLdapBasedn,
            Attribute::DomainSsid,
            Attribute::DomainUuid,
            Attribute::Es256PrivateKeyDer,
            Attribute::FernetPrivateKeyStr,
            Attribute::CookiePrivateKey,
            Attribute::LdapAllowUnixPwBind,
        ],
        modify_removed_attrs: vec![
            Attribute::DomainDisplayName,
            Attribute::DomainSsid,
            Attribute::DomainLdapBasedn,
            Attribute::Es256PrivateKeyDer,
            Attribute::CookiePrivateKey,
            Attribute::FernetPrivateKeyStr,
            Attribute::LdapAllowUnixPwBind,
        ],
        modify_present_attrs: vec![
            Attribute::DomainDisplayName,
            Attribute::DomainLdapBasedn,
            Attribute::DomainSsid,
            Attribute::LdapAllowUnixPwBind,
        ],
        ..Default::default()
    };
}

lazy_static! {
    pub static ref IDM_ACP_SYSTEM_CONFIG_PRIV_V1: BuiltinAcp = BuiltinAcp{
        classes: vec![
            EntryClass::Object,
            EntryClass::AccessControlProfile,
            EntryClass::AccessControlModify,
            EntryClass::AccessControlSearch
        ],
        name: "idm_acp_system_config_priv",
        uuid: UUID_IDM_ACP_SYSTEM_CONFIG_PRIV_V1,
        description: "Builtin IDM Control for granting system configuration rights",
        receiver_group: UUID_SYSTEM_ADMINS,
        target_scope: ProtoFilter::And(vec![
            ProtoFilter::Eq(Attribute::Uuid.to_string(),STR_UUID_SYSTEM_CONFIG.to_string()),
            FILTER_ANDNOT_TOMBSTONE_OR_RECYCLED.clone()
        ]),
        // Value::new_json_filter_s(
        //         "{\"and\": [{\"eq\": [\"uuid\",\"00000000-0000-0000-0000-ffffff000027\"]}, {\"andnot\": {\"or\": [{\"eq\": [\"class\", \"tombstone\"]}, {\"eq\": [\"class\", \"recycled\"]}]}}]}"
        //     )
        //         .expect("Invalid JSON filter"),
        search_attrs: vec![
            Attribute::Class,
            Attribute::Name,
            Attribute::Uuid,
            Attribute::Description,
            Attribute::BadlistPassword,
            Attribute::DeniedName,
        ],
        modify_removed_attrs: vec![Attribute::BadlistPassword, Attribute::DeniedName],
        modify_present_attrs: vec![Attribute::BadlistPassword, Attribute::DeniedName],
        ..Default::default()
    };

    pub static ref IDM_ACP_SYSTEM_CONFIG_SESSION_EXP_PRIV_V1: BuiltinAcp = BuiltinAcp{
        classes: vec![
            EntryClass::Object,
            EntryClass::AccessControlProfile,
            EntryClass::AccessControlModify,
            EntryClass::AccessControlSearch
        ],
        name: "idm_acp_system_config_session_exp_priv",
        uuid: UUID_IDM_ACP_SYSTEM_CONFIG_SESSION_EXP_PRIV_V1,
        description: "Builtin IDM Control for granting session expiry configuration rights",
        receiver_group: UUID_SYSTEM_ADMINS,
        target_scope: ProtoFilter::And(vec![
            ProtoFilter::Eq(Attribute::Uuid.to_string(),STR_UUID_SYSTEM_CONFIG.to_string()),
            FILTER_ANDNOT_TOMBSTONE_OR_RECYCLED.clone()
        ]),

        // Value::new_json_filter_s(
        //         "{\"and\": [{\"eq\": [\"uuid\",\"00000000-0000-0000-0000-ffffff000027\"]}, {\"andnot\": {\"or\": [{\"eq\": [\"class\", \"tombstone\"]}, {\"eq\": [\"class\", \"recycled\"]}]}}]}"
        //     )
        //         .expect("Invalid JSON filter"),
        search_attrs:vec![
            Attribute::Class,
            Attribute::Name,
            Attribute::Uuid,
            Attribute::Description,
            Attribute::AuthSessionExpiry,
            Attribute::PrivilegeExpiry,
        ],
        modify_removed_attrs:vec![
            Attribute::AuthSessionExpiry,
            Attribute::PrivilegeExpiry,
        ],
        modify_present_attrs:vec![
            Attribute::AuthSessionExpiry,
            Attribute::PrivilegeExpiry,
        ],
        ..Default::default()

    };
}

lazy_static! {
    pub static ref IDM_ACP_ACCOUNT_UNIX_EXTEND_PRIV_V1: BuiltinAcp = BuiltinAcp{
        classes: vec![
            EntryClass::Object,
            EntryClass::AccessControlProfile,
            EntryClass::AccessControlModify,
            EntryClass::AccessControlSearch
        ],
        name: "idm_acp_account_unix_extend_priv",
        uuid: UUID_IDM_ACP_ACCOUNT_UNIX_EXTEND_PRIV_V1,
        description: "Builtin IDM Control for managing and extending unix accounts",
        receiver_group: UUID_IDM_ACCOUNT_UNIX_EXTEND_PRIV,
        // account not in HP, Recycled, Tombstone
        target_scope: ProtoFilter::And(vec![
            match_class_filter!(EntryClass::Account),
            ProtoFilter::AndNot(Box::new(FILTER_HP_OR_RECYCLED_OR_TOMBSTONE.clone())),
        ]),

        // Value::new_json_filter_s(
        //         "{\"and\": [{\"eq\": [\"class\",\"account\"]}, {\"andnot\": {\"or\": [
            // {\"eq\": [\"memberof\",\"00000000-0000-0000-0000-000000001000\"]},
            // {\"eq\": [\"class\", \"tombstone\"]},
            // {\"eq\": [\"class\", \"recycled\"]}]}}]}"
        //     )
        //         .expect("Invalid JSON filter"),
        search_attrs: vec![
            Attribute::Class,
            Attribute::Name,
            Attribute::Uuid,
            Attribute::Spn,
            Attribute::Description,
            Attribute::GidNumber,
            Attribute::LoginShell,
            Attribute::UnixPassword,
        ],
        modify_removed_attrs: vec![
            Attribute::GidNumber,
            Attribute::LoginShell,
            Attribute::UnixPassword,
        ],
        modify_present_attrs: vec![
            Attribute::Class,
            Attribute::GidNumber,
            Attribute::LoginShell,
            Attribute::UnixPassword,
        ],
        modify_classes: vec![
            EntryClass::PosixAccount,
        ],
        ..Default::default()
    };

    pub static ref IDM_ACP_GROUP_UNIX_EXTEND_PRIV_V1: BuiltinAcp = BuiltinAcp{
        classes: vec![
            EntryClass::Object,
            EntryClass::AccessControlProfile,
            EntryClass::AccessControlModify,
            EntryClass::AccessControlSearch
            ],
        name: "idm_acp_group_unix_extend_priv",
        uuid: UUID_IDM_ACP_GROUP_UNIX_EXTEND_PRIV_V1,
        description: "Builtin IDM Control for managing and extending unix groups",
        receiver_group: UUID_IDM_GROUP_UNIX_EXTEND_PRIV,
        // group not in HP, Recycled, Tombstone
        target_scope: ProtoFilter::And(vec![
            match_class_filter!(EntryClass::Group),
            ProtoFilter::AndNot(Box::new(FILTER_HP_OR_RECYCLED_OR_TOMBSTONE.clone())),
        ]),

        // Value::new_json_filter_s(
        //         "{\"and\": [{\"eq\": [\"class\",\"group\"]}, {\"andnot\": {\"or\": [{\"eq\": [\"memberof\",\"00000000-0000-0000-0000-000000001000\"]}, {\"eq\": [\"class\", \"tombstone\"]}, {\"eq\": [\"class\", \"recycled\"]}]}}]}"
        //     )
        //         .expect("Invalid JSON filter"),
        search_attrs: vec![
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

    pub static ref E_IDM_HP_ACP_ACCOUNT_UNIX_EXTEND_PRIV_V1: BuiltinAcp = BuiltinAcp{
        classes: vec![
            EntryClass::Object,
            EntryClass::AccessControlProfile,
            EntryClass::AccessControlModify,
            EntryClass::AccessControlSearch
        ],
        name: "idm_acp_hp_account_unix_extend_priv",
        uuid: UUID_IDM_HP_ACP_ACCOUNT_UNIX_EXTEND_PRIV_V1,
        description: "Builtin IDM Control for managing and extending unix accounts",
        receiver_group: UUID_IDM_HP_ACCOUNT_UNIX_EXTEND_PRIV,
        // account not in HP, Recycled, Tombstone
        target_scope: ProtoFilter::And(vec![
            match_class_filter!(EntryClass::Account),
            FILTER_HP.clone(),
            FILTER_ANDNOT_TOMBSTONE_OR_RECYCLED.clone(),
        ]),

        // Value::new_json_filter_s(
        //         "{\"and\": [{\"eq\": [\"class\",\"account\"]}, {\"eq\": [\"memberof\",\"00000000-0000-0000-0000-000000001000\"]}, {\"andnot\": {\"or\": [{\"eq\": [\"class\", \"tombstone\"]}, {\"eq\": [\"class\", \"recycled\"]}]}}]}"
        //     )
        //         .expect("Invalid JSON filter"),
        search_attrs: vec![
            Attribute::Class,
            Attribute::Name,
            Attribute::Uuid,
            Attribute::Spn,
            Attribute::Description,
            Attribute::GidNumber,
            Attribute::LoginShell,
            Attribute::UnixPassword,
        ],
        modify_removed_attrs: vec![
            Attribute::GidNumber,
            Attribute::LoginShell,
            Attribute::UnixPassword,
        ],
        modify_present_attrs: vec![
            Attribute::Class,
            Attribute::GidNumber,
            Attribute::LoginShell,
            Attribute::UnixPassword,
        ],
        modify_classes: vec![
            EntryClass::PosixAccount,
        ],
        ..Default::default()
    };
}

lazy_static! {
    pub static ref E_IDM_HP_ACP_GROUP_UNIX_EXTEND_PRIV_V1: BuiltinAcp = BuiltinAcp{
        classes: vec![
            EntryClass::Object,
            EntryClass::AccessControlProfile,
            EntryClass::AccessControlModify,
            EntryClass::AccessControlSearch
        ],
        name: "idm_acp_hp_group_unix_extend_priv",
        uuid: UUID_IDM_HP_ACP_GROUP_UNIX_EXTEND_PRIV_V1,
        description: "Builtin IDM Control for managing and extending unix high privilege groups",
        receiver_group: UUID_IDM_HP_GROUP_UNIX_EXTEND_PRIV,
        // HP group, not Recycled/Tombstone
        target_scope: ProtoFilter::And(vec![
            match_class_filter!(EntryClass::Group),
            FILTER_HP.clone(),
            ProtoFilter::AndNot(Box::new(FILTER_RECYCLED_OR_TOMBSTONE.clone())),
        ]),

        // target_scope: Value::new_json_filter_s(
        //         "{\"and\": [{\"eq\": [\"class\",\"group\"]}, {\"eq\": [\"memberof\",\"00000000-0000-0000-0000-000000001000\"]},
        // {\"andnot\": {\"or\":
            // [{\"eq\": [\"class\", \"tombstone\"]}, {\"eq\": [\"class\", \"recycled\"]}]}}]}"
        //     )
        //         .expect("Invalid JSON filter"),
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
    pub static ref E_IDM_HP_ACP_OAUTH2_MANAGE_PRIV_V1: BuiltinAcp = BuiltinAcp {
        classes: vec![
            EntryClass::Object,
            EntryClass::AccessControlProfile,
            EntryClass::AccessControlCreate,
            EntryClass::AccessControlDelete,
            EntryClass::AccessControlModify,
            EntryClass::AccessControlSearch
        ],
        name: "idm_acp_hp_oauth2_manage_priv",
        uuid: UUID_IDM_HP_ACP_OAUTH2_MANAGE_PRIV_V1,
        description: "Builtin IDM Control for managing oauth2 resource server integrations.",
        receiver_group: UUID_IDM_HP_OAUTH2_MANAGE_PRIV,
        target_scope: ProtoFilter::And(vec![
            match_class_filter!(EntryClass::OAuth2ResourceServer),
            FILTER_ANDNOT_TOMBSTONE_OR_RECYCLED.clone(),
        ]),
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
    pub static ref E_IDM_HP_ACP_SERVICE_ACCOUNT_INTO_PERSON_MIGRATE_V1: BuiltinAcp = BuiltinAcp {
        classes: vec![
            EntryClass::Object,
            EntryClass::AccessControlProfile,
            EntryClass::AccessControlModify,
            EntryClass::AccessControlSearch
        ],
        name: "idm_hp_acp_service_account_into_person_migrate",
        uuid: UUID_IDM_HP_ACP_SERVICE_ACCOUNT_INTO_PERSON_MIGRATE_V1,
        description: "Builtin IDM Control allowing service accounts to be migrated into persons",
        receiver_group: UUID_IDM_HP_SERVICE_ACCOUNT_INTO_PERSON_MIGRATE_PRIV,
        target_scope: ProtoFilter::And(vec![
            match_class_filter!(EntryClass::Account),
            FILTER_ANDNOT_TOMBSTONE_OR_RECYCLED.clone(),
        ]),

        search_attrs: vec![
            Attribute::Class,
            Attribute::Name,
            Attribute::Uuid,
            Attribute::Spn,
        ],

        modify_present_attrs: vec![Attribute::Class],
        modify_removed_attrs: vec![Attribute::Class],
        modify_classes: vec![EntryClass::ServiceAccount, EntryClass::Person,],
        ..Default::default()
    };
}

lazy_static! {
    pub static ref E_IDM_HP_ACP_SYNC_ACCOUNT_MANAGE_PRIV_V1: BuiltinAcp = BuiltinAcp {
        classes: vec![
            EntryClass::Object,
            EntryClass::AccessControlProfile,
            EntryClass::AccessControlCreate,
            EntryClass::AccessControlDelete,
            EntryClass::AccessControlModify,
            EntryClass::AccessControlSearch,
        ],
        name: "idm_acp_hp_sync_account_manage_priv",
        uuid: UUID_IDM_HP_ACP_SYNC_ACCOUNT_MANAGE_PRIV_V1,
        description: "Builtin IDM Control for managing IDM synchronisation accounts / connections",
        receiver_group: UUID_IDM_HP_SYNC_ACCOUNT_MANAGE_PRIV,
        target_scope: ProtoFilter::And(vec![
            ProtoFilter::Eq(
                Attribute::Class.to_string(),
                EntryClass::SyncAccount.to_string()
            ),
            ProtoFilter::AndNot(Box::new(ProtoFilter::Or(vec![
                ProtoFilter::Eq(
                    Attribute::Class.to_string(),
                    EntryClass::Tombstone.to_string()
                ),
                ProtoFilter::Eq(
                    Attribute::Class.to_string(),
                    EntryClass::Tombstone.to_string()
                ),
            ]))),
        ]),
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
