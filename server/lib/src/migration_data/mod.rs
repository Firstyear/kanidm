pub(crate) mod dl12;
pub(crate) mod dl13;
pub(crate) mod dl14;
pub(crate) mod dl15;
pub(crate) mod dl_1_12;
pub(crate) mod dl_1_13;

pub(crate) mod system;

#[cfg(test)]
pub(crate) use dl_1_13 as latest;

mod types;

#[cfg(test)]
pub use self::types::BuiltinAccount;

#[cfg(test)]
pub(crate) use latest::accounts::BUILTIN_ACCOUNT_ANONYMOUS_DL6 as BUILTIN_ACCOUNT_ANONYMOUS;

/// Builtin System Admin account.
#[cfg(test)]
pub static BUILTIN_ACCOUNT_TEST_PERSON: BuiltinAccount = BuiltinAccount {
    account_type: kanidm_proto::v1::AccountType::Person,
    entry_managed_by: None,
    name: "test_person",
    uuid: crate::constants::uuids::UUID_TESTPERSON_1,
    description: "Test Person",
    displayname: "Test Person",
};
