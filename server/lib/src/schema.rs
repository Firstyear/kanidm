//! [Schema] are one of the foundational concepts of the server. They provide a
//! set of rules to enforce that an [Entry]'s values must be compliant to, to be
//! considered valid for commit to the database. This allows us to provide
//! requirements and structure as to what an [Entry] must have and may contain
//! which enables many other parts to function.
//!
//! To define this structure we define [Attribute]s that provide rules for how
//! an ava should be structured. We also define the [SchemaClass]es that define
//! the rules of which [Attribute]s may or must exist on an [Entry] for it
//! to be considered valid. An [Entry] must have at between 1 and infinite
//! [SchemaClass]es. [SchemaClass] entries are additive.
//!

use crate::be::IdxKey;
use crate::prelude::*;
use crate::valueset::ValueSet;
use concread::cowcell::*;
use hashbrown::{HashMap, HashSet};
use std::collections::BTreeSet;
use tracing::trace;
use uuid::Uuid;

// representations of schema that confines object types, classes
// and attributes. This ties in deeply with "Entry".
//
// In the future this will parse/read it's schema from the db
// but we have to bootstrap with some core types.

/// Schema stores the set of [`Classes`] and [`Attributes`] that the server will
/// use to validate [`Entries`], [`Filters`] and [`Modifications`]. Additionally the
/// schema stores an extracted copy of the current attribute indexing metadata that
/// is used by the backend during queries.
///
/// [`Filters`]: ../filter/index.html
/// [`Modifications`]: ../modify/index.html
/// [`Entries`]: ../entry/index.html
/// [`Attributes`]: struct.SchemaAttribute.html
/// [`Classes`]: struct.SchemaClass.html
pub struct Schema {
    classes: CowCell<HashMap<AttrString, SchemaClass>>,
    attributes: CowCell<HashMap<Attribute, SchemaAttribute>>,
    unique_cache: CowCell<Vec<Attribute>>,
    ref_cache: CowCell<HashMap<Attribute, SchemaAttribute>>,
}

/// A writable transaction of the working schema set. You should not change this directly,
/// the writability is for the server internally to allow reloading of the schema. Changes
/// you make will be lost when the server re-reads the schema from disk.
pub struct SchemaWriteTransaction<'a> {
    classes: CowCellWriteTxn<'a, HashMap<AttrString, SchemaClass>>,
    attributes: CowCellWriteTxn<'a, HashMap<Attribute, SchemaAttribute>>,

    unique_cache: CowCellWriteTxn<'a, Vec<Attribute>>,
    ref_cache: CowCellWriteTxn<'a, HashMap<Attribute, SchemaAttribute>>,
}

/// A readonly transaction of the working schema set.
pub struct SchemaReadTransaction {
    classes: CowCellReadTxn<HashMap<AttrString, SchemaClass>>,
    attributes: CowCellReadTxn<HashMap<Attribute, SchemaAttribute>>,

    unique_cache: CowCellReadTxn<Vec<Attribute>>,
    ref_cache: CowCellReadTxn<HashMap<Attribute, SchemaAttribute>>,
}

#[derive(Debug, Clone, Copy, Default)]
pub enum Replicated {
    #[default]
    True,
    False,
}

impl From<Replicated> for bool {
    fn from(value: Replicated) -> bool {
        match value {
            Replicated::True => true,
            Replicated::False => false,
        }
    }
}

impl From<bool> for Replicated {
    fn from(value: bool) -> Self {
        match value {
            true => Replicated::True,
            false => Replicated::False,
        }
    }
}

/// An item representing an attribute and the rules that enforce it. These rules enforce if an
/// attribute on an [`Entry`] may be single or multi value, must be unique amongst all other types
/// of this attribute, if the attribute should be [`indexed`], and what type of data [`syntax`] it may hold.
///
/// [`Entry`]: ../entry/index.html
/// [`indexed`]: ../value/enum.IndexType.html
/// [`syntax`]: ../value/enum.SyntaxType.html
#[derive(Debug, Clone, Default)]
pub struct SchemaAttribute {
    pub name: Attribute,
    pub uuid: Uuid,
    pub description: String,
    /// Defines if the attribute may have one or multiple values associated to it.
    pub multivalue: bool,
    /// If this flag is set, all instances of this attribute must be a unique value in the database.
    pub unique: bool,
    /// This defines that the value is a phantom - it is "not real", can never "be real". It
    /// is synthesised in memory, and will never be written to the database. This can exist for
    /// placeholders like cn/uid in ldap.
    pub phantom: bool,
    /// This boolean defines if this attribute may be altered by an external IDP sync
    /// agreement.
    pub sync_allowed: bool,

    /// If set the value of this attribute get replicated to other servers
    pub replicated: Replicated,
    /// Define if this attribute is indexed or not according to its syntax type rule
    pub indexed: bool,
    /// THe type of data that this attribute may hold.
    pub syntax: SyntaxType,
}

impl SchemaAttribute {
    pub fn try_from(value: &Entry<EntrySealed, EntryCommitted>) -> Result<Self, OperationError> {
        // Convert entry to a schema attribute.

        // uuid
        let uuid = value.get_uuid();

        // class
        if !value.attribute_equality(Attribute::Class, &EntryClass::AttributeType.into()) {
            admin_error!(
                "class {} not present - {:?}",
                EntryClass::AttributeType,
                uuid
            );
            return Err(OperationError::InvalidSchemaState(format!(
                "missing {}",
                EntryClass::AttributeType
            )));
        }

        // name
        let name = value
            .get_ava_single_iutf8(Attribute::AttributeName)
            .map(|s| s.into())
            .ok_or_else(|| {
                admin_error!("missing {} - {:?}", Attribute::AttributeName, uuid);
                OperationError::InvalidSchemaState("missing attributename".to_string())
            })?;
        // description
        let description = value
            .get_ava_single_utf8(Attribute::Description)
            .map(|s| s.to_string())
            .ok_or_else(|| {
                admin_error!("missing {} - {}", Attribute::Description, name);
                OperationError::InvalidSchemaState("missing description".to_string())
            })?;

        // multivalue
        let multivalue = value
            .get_ava_single_bool(Attribute::MultiValue)
            .ok_or_else(|| {
                admin_error!("missing {} - {}", Attribute::MultiValue, name);
                OperationError::InvalidSchemaState("missing multivalue".to_string())
            })?;

        let unique = value
            .get_ava_single_bool(Attribute::Unique)
            .ok_or_else(|| {
                admin_error!("missing {} - {}", Attribute::Unique, name);
                OperationError::InvalidSchemaState("missing unique".to_string())
            })?;

        let phantom = value
            .get_ava_single_bool(Attribute::Phantom)
            .unwrap_or_default();

        let sync_allowed = value
            .get_ava_single_bool(Attribute::SyncAllowed)
            .unwrap_or_default();

        // Default, all attributes are replicated unless you opt in for them to NOT be.
        // Generally this is internal to the server only, so we don't advertise it.
        let replicated = value
            .get_ava_single_bool(Attribute::Replicated)
            .map(Replicated::from)
            .unwrap_or_default();

        let indexed = value
            .get_ava_single_bool(Attribute::Indexed)
            .unwrap_or_default();

        // syntax type
        let syntax = value
            .get_ava_single_syntax(Attribute::Syntax)
            .ok_or_else(|| {
                admin_error!("missing {} - {}", Attribute::Syntax, name);
                OperationError::InvalidSchemaState(format!("missing {}", Attribute::Syntax))
            })?;

        trace!(?name, ?indexed);

        Ok(SchemaAttribute {
            name,
            uuid,
            description,
            multivalue,
            unique,
            phantom,
            sync_allowed,
            replicated,
            indexed,
            syntax,
        })
    }

    // There may be a difference between a value and a filter value on complex
    // types - IE a complex type may have multiple parts that are secret, but a filter
    // on that may only use a single tagged attribute for example.
    pub fn validate_partialvalue(
        &self,
        a: &Attribute,
        v: &PartialValue,
    ) -> Result<(), SchemaError> {
        let r = match self.syntax {
            SyntaxType::Boolean => matches!(v, PartialValue::Bool(_)),
            SyntaxType::SyntaxId => matches!(v, PartialValue::Syntax(_)),
            SyntaxType::IndexId => matches!(v, PartialValue::Index(_)),
            SyntaxType::Uuid => matches!(v, PartialValue::Uuid(_)),
            SyntaxType::ReferenceUuid => matches!(v, PartialValue::Refer(_)),
            SyntaxType::Utf8StringInsensitive => matches!(v, PartialValue::Iutf8(_)),
            SyntaxType::Utf8StringIname => matches!(v, PartialValue::Iname(_)),
            SyntaxType::Utf8String => matches!(v, PartialValue::Utf8(_)),
            SyntaxType::JsonFilter => matches!(v, PartialValue::JsonFilt(_)),
            SyntaxType::Credential => matches!(v, PartialValue::Cred(_)),
            SyntaxType::SecretUtf8String => matches!(v, PartialValue::SecretValue),
            SyntaxType::SshKey => matches!(v, PartialValue::SshKey(_)),
            SyntaxType::SecurityPrincipalName => matches!(v, PartialValue::Spn(_, _)),
            SyntaxType::Uint32 => matches!(v, PartialValue::Uint32(_)),
            SyntaxType::Int64 => matches!(v, PartialValue::Int64(_)),
            SyntaxType::Uint64 => matches!(v, PartialValue::Uint64(_)),
            SyntaxType::Cid => matches!(v, PartialValue::Cid(_)),
            SyntaxType::NsUniqueId => matches!(v, PartialValue::Nsuniqueid(_)),
            SyntaxType::DateTime => matches!(v, PartialValue::DateTime(_)),
            SyntaxType::EmailAddress => matches!(v, PartialValue::EmailAddress(_)),
            SyntaxType::Url => matches!(v, PartialValue::Url(_)),
            SyntaxType::OauthScope => matches!(v, PartialValue::OauthScope(_)),
            SyntaxType::OauthScopeMap => matches!(v, PartialValue::Refer(_)),
            SyntaxType::OauthClaimMap => {
                matches!(v, PartialValue::Iutf8(_))
                    || matches!(v, PartialValue::Refer(_))
                    || matches!(v, PartialValue::OauthClaimValue(_, _, _))
                    || matches!(v, PartialValue::OauthClaim(_, _))
            }
            SyntaxType::PrivateBinary => matches!(v, PartialValue::PrivateBinary),
            SyntaxType::IntentToken => matches!(v, PartialValue::IntentToken(_)),
            SyntaxType::Passkey => matches!(v, PartialValue::Passkey(_)),
            SyntaxType::AttestedPasskey => matches!(v, PartialValue::AttestedPasskey(_)),
            // Allow refer types.
            SyntaxType::Session => matches!(v, PartialValue::Refer(_)),
            SyntaxType::ApiToken => matches!(v, PartialValue::Refer(_)),
            SyntaxType::Oauth2Session => matches!(v, PartialValue::Refer(_)),
            // These are just insensitive string lookups on the hex-ified kid.
            SyntaxType::JwsKeyEs256 => matches!(v, PartialValue::Iutf8(_)),
            SyntaxType::JwsKeyRs256 => matches!(v, PartialValue::Iutf8(_)),
            SyntaxType::UiHint => matches!(v, PartialValue::UiHint(_)),
            SyntaxType::EcKeyPrivate => matches!(v, PartialValue::SecretValue),
            // Comparing on the label.
            SyntaxType::TotpSecret => matches!(v, PartialValue::Utf8(_)),
            SyntaxType::AuditLogString => matches!(v, PartialValue::Utf8(_)),
            SyntaxType::Image => matches!(v, PartialValue::Utf8(_)),
            SyntaxType::CredentialType => matches!(v, PartialValue::CredentialType(_)),

            SyntaxType::HexString | SyntaxType::Certificate | SyntaxType::KeyInternal => {
                matches!(v, PartialValue::HexString(_))
            }

            SyntaxType::WebauthnAttestationCaList => false,
            SyntaxType::ApplicationPassword => {
                matches!(v, PartialValue::Uuid(_)) || matches!(v, PartialValue::Refer(_))
            }
            SyntaxType::Sha256 => matches!(v, PartialValue::Sha256(_)),
            // SyntaxType::Json => matches!(v, PartialValue::Json),
            // Should not be queried
            SyntaxType::Json | SyntaxType::Message => false,
        };
        if r {
            Ok(())
        } else {
            error!(
                ?a,
                ?self,
                ?v,
                "validate_partialvalue InvalidAttributeSyntax"
            );
            Err(SchemaError::InvalidAttributeSyntax(a.to_string()))
        }
    }

    pub fn validate_value(&self, a: &Attribute, v: &Value) -> Result<(), SchemaError> {
        let r = v.validate()
            && match self.syntax {
                SyntaxType::Boolean => matches!(v, Value::Bool(_)),
                SyntaxType::SyntaxId => matches!(v, Value::Syntax(_)),
                SyntaxType::IndexId => matches!(v, Value::Index(_)),
                SyntaxType::Uuid => matches!(v, Value::Uuid(_)),
                SyntaxType::ReferenceUuid => matches!(v, Value::Refer(_)),
                SyntaxType::Utf8StringInsensitive => matches!(v, Value::Iutf8(_)),
                SyntaxType::Utf8StringIname => matches!(v, Value::Iname(_)),
                SyntaxType::Utf8String => matches!(v, Value::Utf8(_)),
                SyntaxType::JsonFilter => matches!(v, Value::JsonFilt(_)),
                SyntaxType::Credential => matches!(v, Value::Cred(_, _)),
                SyntaxType::SecretUtf8String => matches!(v, Value::SecretValue(_)),
                SyntaxType::SshKey => matches!(v, Value::SshKey(_, _)),
                SyntaxType::SecurityPrincipalName => matches!(v, Value::Spn(_, _)),
                SyntaxType::Uint32 => matches!(v, Value::Uint32(_)),
                SyntaxType::Int64 => matches!(v, Value::Int64(_)),
                SyntaxType::Uint64 => matches!(v, Value::Uint64(_)),
                SyntaxType::Cid => matches!(v, Value::Cid(_)),
                SyntaxType::NsUniqueId => matches!(v, Value::Nsuniqueid(_)),
                SyntaxType::DateTime => matches!(v, Value::DateTime(_)),
                SyntaxType::EmailAddress => matches!(v, Value::EmailAddress(_, _)),
                SyntaxType::Url => matches!(v, Value::Url(_)),
                SyntaxType::OauthScope => matches!(v, Value::OauthScope(_)),
                SyntaxType::OauthScopeMap => matches!(v, Value::OauthScopeMap(_, _)),
                SyntaxType::OauthClaimMap => {
                    matches!(v, Value::OauthClaimValue(_, _, _))
                        || matches!(v, Value::OauthClaimMap(_, _))
                }
                SyntaxType::PrivateBinary => matches!(v, Value::PrivateBinary(_)),
                SyntaxType::IntentToken => matches!(v, Value::IntentToken(_, _)),
                SyntaxType::Passkey => matches!(v, Value::Passkey(_, _, _)),
                SyntaxType::AttestedPasskey => matches!(v, Value::AttestedPasskey(_, _, _)),
                SyntaxType::Session => matches!(v, Value::Session(_, _)),
                SyntaxType::ApiToken => matches!(v, Value::ApiToken(_, _)),
                SyntaxType::Oauth2Session => matches!(v, Value::Oauth2Session(_, _)),
                SyntaxType::JwsKeyEs256 => matches!(v, Value::JwsKeyEs256(_)),
                SyntaxType::JwsKeyRs256 => matches!(v, Value::JwsKeyRs256(_)),
                SyntaxType::UiHint => matches!(v, Value::UiHint(_)),
                SyntaxType::TotpSecret => matches!(v, Value::TotpSecret(_, _)),
                SyntaxType::AuditLogString => matches!(v, Value::Utf8(_)),
                SyntaxType::EcKeyPrivate => matches!(v, Value::EcKeyPrivate(_)),
                SyntaxType::Image => matches!(v, Value::Image(_)),
                SyntaxType::CredentialType => matches!(v, Value::CredentialType(_)),
                SyntaxType::WebauthnAttestationCaList => {
                    matches!(v, Value::WebauthnAttestationCaList(_))
                }
                SyntaxType::KeyInternal => matches!(v, Value::KeyInternal { .. }),
                SyntaxType::HexString => matches!(v, Value::HexString(_)),
                SyntaxType::Certificate => matches!(v, Value::Certificate(_)),
                SyntaxType::ApplicationPassword => matches!(v, Value::ApplicationPassword(..)),
                SyntaxType::Json => matches!(v, Value::Json(_)),
                SyntaxType::Sha256 => matches!(v, Value::Sha256(_)),
                SyntaxType::Message => false,
            };
        if r {
            Ok(())
        } else {
            error!(
                ?a,
                ?self,
                ?v,
                "validate_value failure - InvalidAttributeSyntax"
            );
            Err(SchemaError::InvalidAttributeSyntax(a.to_string()))
        }
    }

    pub fn validate_ava(&self, a: &Attribute, ava: &ValueSet) -> Result<(), SchemaError> {
        trace!("Checking for valid {:?} -> {:?}", self.name, ava);
        // Check multivalue
        if !self.multivalue && ava.len() > 1 {
            // lrequest_error!("Ava len > 1 on single value attribute!");
            admin_error!("Ava len > 1 on single value attribute!");
            return Err(SchemaError::InvalidAttributeSyntax(a.to_string()));
        };
        // If syntax, check the type is correct
        let valid = self.syntax == ava.syntax();
        if valid && ava.validate(self) {
            Ok(())
        } else {
            error!(
                ?a,
                "validate_ava - InvalidAttributeSyntax for {:?}", self.syntax
            );
            Err(SchemaError::InvalidAttributeSyntax(a.to_string()))
        }
    }
}

/// An item representing a class and the rules for that class. These rules enforce that an
/// [`Entry`]'s avas conform to a set of requirements, giving structure to an entry about
/// what avas must or may exist. The kanidm project provides attributes in `systemmust` and
/// `systemmay`, which can not be altered. An administrator may extend these in the `must`
/// and `may` attributes.
///
/// Classes are additive, meaning that if there are two classes, the `may` rules of both union,
/// and that if an attribute is `must` on one class, and `may` in another, the `must` rule
/// takes precedence. It is not possible to combine classes in an incompatible way due to these
/// rules.
///
/// That in mind, an entry that has one of every possible class would probably be nonsensical,
/// but the addition rules make it easy to construct and understand with concepts like [`access`]
/// controls or accounts and posix extensions.
///
/// [`Entry`]: ../entry/index.html
/// [`access`]: ../access/index.html
#[derive(Debug, Clone, Default)]
pub struct SchemaClass {
    pub name: AttrString,
    pub uuid: Uuid,
    pub description: String,
    pub sync_allowed: bool,
    /// This allows modification of system types to be extended in custom ways
    pub systemmay: Vec<Attribute>,
    pub may: Vec<Attribute>,
    pub systemmust: Vec<Attribute>,
    pub must: Vec<Attribute>,
    /// A list of classes that this extends. These are an "or", as at least one
    /// of the supplementing classes must also be present. Think of this as
    /// "inherits toward" or "provides". This is just as "strict" as requires but
    /// operates in the opposite direction allowing a tree structure.
    pub systemsupplements: Vec<AttrString>,
    pub supplements: Vec<AttrString>,
    /// A list of classes that can not co-exist with this item at the same time.
    pub systemexcludes: Vec<AttrString>,
    pub excludes: Vec<AttrString>,
}

impl SchemaClass {
    pub fn try_from(value: &Entry<EntrySealed, EntryCommitted>) -> Result<Self, OperationError> {
        // uuid
        let uuid = value.get_uuid();
        // Convert entry to a schema class.
        if !value.attribute_equality(Attribute::Class, &EntryClass::ClassType.into()) {
            error!("class classtype not present - {:?}", uuid);
            return Err(OperationError::InvalidSchemaState(
                "missing classtype".to_string(),
            ));
        }

        // name
        let name = value
            .get_ava_single_iutf8(Attribute::ClassName)
            .map(AttrString::from)
            .ok_or_else(|| {
                error!("missing {} - {:?}", Attribute::ClassName, uuid);
                OperationError::InvalidSchemaState(format!("missing {}", Attribute::ClassName))
            })?;

        // description
        let description = value
            .get_ava_single_utf8(Attribute::Description)
            .map(String::from)
            .ok_or_else(|| {
                error!("missing {} - {}", Attribute::Description, name);
                OperationError::InvalidSchemaState(format!("missing {}", Attribute::Description))
            })?;

        let sync_allowed = value
            .get_ava_single_bool(Attribute::SyncAllowed)
            .unwrap_or(false);

        // These are all "optional" lists of strings.
        let systemmay = value
            .get_ava_iter_iutf8(Attribute::SystemMay)
            .into_iter()
            .flat_map(|iter| iter.map(Attribute::from))
            .collect();
        let systemmust = value
            .get_ava_iter_iutf8(Attribute::SystemMust)
            .into_iter()
            .flat_map(|iter| iter.map(Attribute::from))
            .collect();
        let may = value
            .get_ava_iter_iutf8(Attribute::May)
            .into_iter()
            .flat_map(|iter| iter.map(Attribute::from))
            .collect();
        let must = value
            .get_ava_iter_iutf8(Attribute::Must)
            .into_iter()
            .flat_map(|iter| iter.map(Attribute::from))
            .collect();

        let systemsupplements = value
            .get_ava_iter_iutf8(Attribute::SystemSupplements)
            .map(|i| i.map(|v| v.into()).collect())
            .unwrap_or_default();
        let supplements = value
            .get_ava_iter_iutf8(Attribute::Supplements)
            .map(|i| i.map(|v| v.into()).collect())
            .unwrap_or_default();
        let systemexcludes = value
            .get_ava_iter_iutf8(Attribute::SystemExcludes)
            .map(|i| i.map(|v| v.into()).collect())
            .unwrap_or_default();
        let excludes = value
            .get_ava_iter_iutf8(Attribute::Excludes)
            .map(|i| i.map(|v| v.into()).collect())
            .unwrap_or_default();

        Ok(SchemaClass {
            name,
            uuid,
            description,
            sync_allowed,
            systemmay,
            may,
            systemmust,
            must,
            systemsupplements,
            supplements,
            systemexcludes,
            excludes,
        })
    }

    /// An iterator over the full set of attrs that may or must exist
    /// on this class.
    pub fn may_iter(&self) -> impl Iterator<Item = &Attribute> {
        self.systemmay
            .iter()
            .chain(self.may.iter())
            .chain(self.systemmust.iter())
            .chain(self.must.iter())
    }
}

pub trait SchemaTransaction {
    fn get_classes(&self) -> &HashMap<AttrString, SchemaClass>;
    fn get_attributes(&self) -> &HashMap<Attribute, SchemaAttribute>;

    fn get_attributes_unique(&self) -> &Vec<Attribute>;
    fn get_reference_types(&self) -> &HashMap<Attribute, SchemaAttribute>;

    fn validate(&self) -> Vec<Result<(), ConsistencyError>> {
        let mut res = Vec::with_capacity(0);

        let class_snapshot = self.get_classes();
        let attribute_snapshot = self.get_attributes();

        // We need to check that every uuid is unique because during tests we aren't doing
        // a disk reload, which means we were missing this and causing potential migration
        // failures on upgrade.

        let mut unique_uuid_set = HashSet::new();
        class_snapshot
            .values()
            .map(|class| &class.uuid)
            .chain(attribute_snapshot.values().map(|attr| &attr.uuid))
            .for_each(|uuid| {
                // If the set did not have this value present, true is returned.
                if !unique_uuid_set.insert(uuid) {
                    res.push(Err(ConsistencyError::SchemaUuidNotUnique(*uuid)))
                }
            });

        class_snapshot.values().for_each(|class| {
            // report the class we are checking
            class
                .systemmay
                .iter()
                .chain(class.may.iter())
                .chain(class.systemmust.iter())
                .chain(class.must.iter())
                .for_each(|a| {
                    match attribute_snapshot.get(a) {
                        Some(attr) => {
                            // We have the attribute, ensure it's not a phantom.
                            if attr.phantom {
                                res.push(Err(ConsistencyError::SchemaClassPhantomAttribute(
                                    class.name.to_string(),
                                    a.to_string(),
                                )))
                            }
                        }
                        None => {
                            // No such attr, something is missing!
                            res.push(Err(ConsistencyError::SchemaClassMissingAttribute(
                                class.name.to_string(),
                                a.to_string(),
                            )))
                        }
                    }
                })
        }); // end for
        res
    }

    fn is_replicated(&self, attr: &Attribute) -> bool {
        match self.get_attributes().get(attr) {
            Some(a_schema) => {
                // We'll likely add more conditions here later.
                // Allow items that are replicated and not phantoms
                a_schema.replicated.into() && !a_schema.phantom
            }
            None => {
                warn!(
                    "Attribute {} was not found in schema during replication request",
                    attr
                );
                false
            }
        }
    }

    fn is_multivalue(&self, attr: &Attribute) -> Result<bool, SchemaError> {
        match self.get_attributes().get(attr) {
            Some(a_schema) => Ok(a_schema.multivalue),
            None => {
                // ladmin_error!("Attribute does not exist?!");
                Err(SchemaError::InvalidAttribute(attr.to_string()))
            }
        }
    }

    fn normalise_attr_if_exists(&self, an: &str) -> Option<Attribute> {
        let attr = Attribute::from(an);
        if self.get_attributes().contains_key(&attr) {
            Some(attr)
        } else {
            None
        }
    }

    fn query_attrs_difference(
        &self,
        prev_class: &BTreeSet<&str>,
        new_iutf8: &BTreeSet<&str>,
    ) -> Result<(BTreeSet<&str>, BTreeSet<&str>), SchemaError> {
        let schema_classes = self.get_classes();

        let mut invalid_classes = Vec::with_capacity(0);

        let prev_attrs: BTreeSet<&str> = prev_class
            .iter()
            .filter_map(|cls| match schema_classes.get(*cls) {
                Some(x) => Some(x.may_iter()),
                None => {
                    admin_debug!("invalid class: {:?}", cls);
                    invalid_classes.push(cls.to_string());
                    None
                }
            })
            // flatten all the inner iters.
            .flatten()
            .map(|s| s.as_str())
            .collect();

        if !invalid_classes.is_empty() {
            return Err(SchemaError::InvalidClass(invalid_classes));
        };

        let new_attrs: BTreeSet<&str> = new_iutf8
            .iter()
            .filter_map(|cls| match schema_classes.get(*cls) {
                Some(x) => Some(x.may_iter()),
                None => {
                    admin_debug!("invalid class: {:?}", cls);
                    invalid_classes.push(cls.to_string());
                    None
                }
            })
            // flatten all the inner iters.
            .flatten()
            .map(|s| s.as_str())
            .collect();

        if !invalid_classes.is_empty() {
            return Err(SchemaError::InvalidClass(invalid_classes));
        };

        let removed = prev_attrs.difference(&new_attrs).copied().collect();
        let added = new_attrs.difference(&prev_attrs).copied().collect();

        Ok((added, removed))
    }
}

impl SchemaWriteTransaction<'_> {
    // Schema probably needs to be part of the backend, so that commits are wholly atomic
    // but in the current design, we need to open be first, then schema, but we have to commit be
    // first, then schema to ensure that the be content matches our schema. Saying this, if your
    // schema commit fails we need to roll back still .... How great are transactions.
    // At the least, this is what validation is for!
    pub fn commit(self) -> Result<(), OperationError> {
        let SchemaWriteTransaction {
            classes,
            attributes,
            unique_cache,
            ref_cache,
        } = self;

        unique_cache.commit();
        ref_cache.commit();
        classes.commit();
        attributes.commit();
        Ok(())
    }

    pub fn update_attributes(
        &mut self,
        attributetypes: Vec<SchemaAttribute>,
    ) -> Result<(), OperationError> {
        // purge all old attributes.
        self.attributes.clear();

        self.unique_cache.clear();
        self.ref_cache.clear();
        // Update with new ones.
        // Do we need to check for dups?
        // No, they'll over-write each other ... but we do need name uniqueness.
        attributetypes.into_iter().for_each(|a| {
            // Update the unique and ref caches.
            if a.syntax == SyntaxType::ReferenceUuid ||
                a.syntax == SyntaxType::OauthScopeMap ||
                a.syntax == SyntaxType::OauthClaimMap ||
                // So that when an rs is removed we trigger removal of the sessions.
                a.syntax == SyntaxType::Oauth2Session ||
                // When an application is removed we trigger removal of passwords
                a.syntax == SyntaxType::ApplicationPassword
            // May not need to be a ref type since it doesn't have external links/impact?
            // || a.syntax == SyntaxType::Session
            {
                self.ref_cache.insert(a.name.clone(), a.clone());
            }
            if a.unique {
                self.unique_cache.push(a.name.clone());
            }
            // Finally insert.
            self.attributes.insert(a.name.clone(), a);
        });

        Ok(())
    }

    pub fn update_classes(&mut self, classtypes: Vec<SchemaClass>) -> Result<(), OperationError> {
        // purge all old attributes.
        self.classes.clear();
        // Update with new ones.
        // Do we need to check for dups?
        // No, they'll over-write each other ... but we do need name uniqueness.
        classtypes.into_iter().for_each(|a| {
            self.classes.insert(a.name.clone(), a);
        });
        Ok(())
    }

    pub fn to_entries(&self) -> Vec<Entry<EntryInit, EntryNew>> {
        let r: Vec<_> = self
            .attributes
            .values()
            .map(Entry::<EntryInit, EntryNew>::from)
            .chain(
                self.classes
                    .values()
                    .map(Entry::<EntryInit, EntryNew>::from),
            )
            .collect();
        r
    }

    pub fn reload_idxmeta(&self) -> Vec<IdxKey> {
        self.get_attributes()
            .values()
            .flat_map(|a| {
                // Unique values must be indexed
                if a.indexed || a.unique {
                    a.syntax.index_types()
                } else {
                    &[]
                }
                .iter()
                .map(move |itype: &IndexType| IdxKey {
                    attr: a.name.clone(),
                    itype: *itype,
                })
            })
            .collect()
    }

    /// Generate the minimal in memory schema needed to begin the server bootstrap
    /// process. This should contain the most critical schema definitions that the
    /// server requires to be able to read in other schema objects and persist them
    /// into our database.
    ///
    /// THIS IS FOR SYSTEM CRITICAL INTERNAL SCHEMA ONLY
    ///
    /// Schema should otherwise be in our migration data - not here.
    #[instrument(level = "debug", name = "schema::generate_in_memory", skip_all)]
    pub fn generate_in_memory(&mut self) -> Result<(), OperationError> {
        self.classes.clear();
        self.attributes.clear();
        // Bootstrap in definitions of our own schema types
        // First, add all the needed core attributes for schema parsing
        self.attributes.insert(
            Attribute::Class,
            SchemaAttribute {
                name: Attribute::Class,
                uuid: UUID_SCHEMA_ATTR_CLASS,
                description: String::from("The set of classes defining an object"),
                multivalue: true,
                unique: false,
                phantom: false,
                sync_allowed: false,
                replicated: Replicated::True,
                indexed: true,
                syntax: SyntaxType::Utf8StringInsensitive,
            },
        );
        self.attributes.insert(
            Attribute::Uuid,
            SchemaAttribute {
                name: Attribute::Uuid,
                uuid: UUID_SCHEMA_ATTR_UUID,
                description: String::from("The universal unique id of the object"),
                multivalue: false,
                // Uniqueness is handled by base.rs, not attrunique here due to
                // needing to check recycled objects too.
                unique: false,
                phantom: false,
                sync_allowed: false,
                replicated: Replicated::True,
                indexed: true,
                syntax: SyntaxType::Uuid,
            },
        );
        self.attributes.insert(
            Attribute::SourceUuid,
            SchemaAttribute {
                name: Attribute::SourceUuid,
                uuid: UUID_SCHEMA_ATTR_SOURCE_UUID,
                description: String::from(
                    "The universal unique id of the source object(s) which conflicted with this entry",
                ),
                multivalue: true,
                // Uniqueness is handled by base.rs, not attrunique here due to
                // needing to check recycled objects too.
                unique: false,
                phantom: false,
                sync_allowed: false,
                replicated: Replicated::True,
                indexed: true,
                syntax: SyntaxType::Uuid,
            },
        );
        self.attributes.insert(
            Attribute::CreatedAtCid,
            SchemaAttribute {
                name: Attribute::CreatedAtCid,
                uuid: UUID_SCHEMA_ATTR_CREATED_AT_CID,
                description: String::from("The cid when this entry was created"),
                multivalue: false,
                // Uniqueness is handled by base.rs, not attrunique here due to
                // needing to check recycled objects too.
                unique: false,
                phantom: false,
                sync_allowed: false,
                replicated: Replicated::False,
                indexed: false,
                syntax: SyntaxType::Cid,
            },
        );
        self.attributes.insert(
            Attribute::LastModifiedCid,
            SchemaAttribute {
                name: Attribute::LastModifiedCid,
                uuid: UUID_SCHEMA_ATTR_LAST_MOD_CID,
                description: String::from("The cid of the last change to this object"),
                multivalue: false,
                // Uniqueness is handled by base.rs, not attrunique here due to
                // needing to check recycled objects too.
                unique: false,
                phantom: false,
                sync_allowed: false,
                replicated: Replicated::False,
                indexed: false,
                syntax: SyntaxType::Cid,
            },
        );
        self.attributes.insert(
            Attribute::Name,
            SchemaAttribute {
                name: Attribute::Name,
                uuid: UUID_SCHEMA_ATTR_NAME,
                description: String::from("The shortform name of an object"),
                multivalue: false,
                unique: true,
                phantom: false,
                sync_allowed: true,
                replicated: Replicated::True,
                indexed: true,
                syntax: SyntaxType::Utf8StringIname,
            },
        );
        self.attributes.insert(
            Attribute::Spn,
            SchemaAttribute {
                name: Attribute::Spn,
                uuid: UUID_SCHEMA_ATTR_SPN,
                description: String::from(
                    "The Security Principal Name of an object, unique across all domain trusts",
                ),
                multivalue: false,
                unique: true,
                phantom: false,
                sync_allowed: false,
                replicated: Replicated::True,
                indexed: true,
                syntax: SyntaxType::SecurityPrincipalName,
            },
        );
        self.attributes.insert(
            Attribute::AttributeName,
            SchemaAttribute {
                name: Attribute::AttributeName,
                uuid: UUID_SCHEMA_ATTR_ATTRIBUTENAME,
                description: String::from("The name of a schema attribute"),
                multivalue: false,
                unique: true,
                phantom: false,
                sync_allowed: false,
                replicated: Replicated::True,
                indexed: true,
                syntax: SyntaxType::Utf8StringInsensitive,
            },
        );
        self.attributes.insert(
            Attribute::ClassName,
            SchemaAttribute {
                name: Attribute::ClassName,
                uuid: UUID_SCHEMA_ATTR_CLASSNAME,
                description: String::from("The name of a schema class"),
                multivalue: false,
                unique: true,
                phantom: false,
                sync_allowed: false,
                replicated: Replicated::True,
                indexed: true,
                syntax: SyntaxType::Utf8StringInsensitive,
            },
        );
        self.attributes.insert(
            Attribute::Description,
            SchemaAttribute {
                name: Attribute::Description,
                uuid: UUID_SCHEMA_ATTR_DESCRIPTION,
                description: String::from("A description of an attribute, object or class"),
                multivalue: false,
                unique: false,
                phantom: false,
                sync_allowed: true,
                replicated: Replicated::True,
                indexed: false,
                syntax: SyntaxType::Utf8String,
            },
        );
        self.attributes.insert(Attribute::MultiValue, SchemaAttribute {
                name: Attribute::MultiValue,
                uuid: UUID_SCHEMA_ATTR_MULTIVALUE,
                description: String::from("If true, this attribute is able to store multiple values rather than just a single value."),
                multivalue: false,
                unique: false,
                phantom: false,
                sync_allowed: false,
                replicated: Replicated::True,
                indexed: false,
                syntax: SyntaxType::Boolean,
            });
        self.attributes.insert(Attribute::Phantom, SchemaAttribute {
                name: Attribute::Phantom,
                uuid: UUID_SCHEMA_ATTR_PHANTOM,
                description: String::from("If true, this attribute must NOT be present in any may/must sets of a class as. This represents generated attributes."),
                multivalue: false,
                unique: false,
                phantom: false,
                sync_allowed: false,
                replicated: Replicated::True,
                indexed: false,
                syntax: SyntaxType::Boolean,
            });
        self.attributes.insert(Attribute::SyncAllowed, SchemaAttribute {
                name: Attribute::SyncAllowed,
                uuid: UUID_SCHEMA_ATTR_SYNC_ALLOWED,
                description: String::from("If true, this attribute or class can by synchronised by an external scim import"),
                multivalue: false,
                unique: false,
                phantom: false,
                sync_allowed: false,
                replicated: Replicated::True,
                indexed: false,
                syntax: SyntaxType::Boolean,
            });
        self.attributes.insert(Attribute::Replicated, SchemaAttribute {
                name: Attribute::Replicated,
                uuid: UUID_SCHEMA_ATTR_REPLICATED,
                description: String::from("If true, this attribute or class can by replicated between nodes in the topology"),
                multivalue: false,
                unique: false,
                phantom: false,
                sync_allowed: false,
                replicated: Replicated::True,
                indexed: false,
                syntax: SyntaxType::Boolean,
            });
        self.attributes.insert(
            Attribute::Unique,
            SchemaAttribute {
                name: Attribute::Unique,
                uuid: UUID_SCHEMA_ATTR_UNIQUE,
                description: String::from(
                    "If true, this attribute must store a unique value through out the database.",
                ),
                multivalue: false,
                unique: false,
                phantom: false,
                sync_allowed: false,
                replicated: Replicated::True,
                indexed: false,
                syntax: SyntaxType::Boolean,
            },
        );
        self.attributes.insert(
            Attribute::Index,
            SchemaAttribute {
                name: Attribute::Index,
                uuid: UUID_SCHEMA_ATTR_INDEX,
                description: String::from(
                    "Describe the indexes to apply to instances of this attribute.",
                ),
                multivalue: true,
                unique: false,
                phantom: false,
                sync_allowed: false,
                replicated: Replicated::True,
                indexed: false,
                syntax: SyntaxType::IndexId,
            },
        );
        self.attributes.insert(
            Attribute::Indexed,
            SchemaAttribute {
                name: Attribute::Indexed,
                uuid: UUID_SCHEMA_ATTR_INDEXED,
                description: String::from(
                    "A boolean stating if this attribute will be indexed according to its syntax rules."
                ),
                multivalue: false,
                unique: false,
                phantom: false,
                sync_allowed: false,
                replicated: Replicated::True,
                indexed: false,
                syntax: SyntaxType::Boolean,
            },
        );
        self.attributes.insert(
            Attribute::Syntax,
            SchemaAttribute {
                name: Attribute::Syntax,
                uuid: UUID_SCHEMA_ATTR_SYNTAX,
                description: String::from(
                    "Describe the syntax of this attribute. This affects indexing and sorting.",
                ),
                multivalue: false,
                unique: false,
                phantom: false,
                sync_allowed: false,
                replicated: Replicated::True,
                indexed: false,
                syntax: SyntaxType::SyntaxId,
            },
        );
        self.attributes.insert(
            Attribute::SystemMay,
            SchemaAttribute {
                name: Attribute::SystemMay,
                uuid: UUID_SCHEMA_ATTR_SYSTEMMAY,
                description: String::from(
                    "A list of system provided optional attributes this class can store.",
                ),
                multivalue: true,
                unique: false,
                phantom: false,
                sync_allowed: false,
                replicated: Replicated::True,
                indexed: false,
                syntax: SyntaxType::Utf8StringInsensitive,
            },
        );
        self.attributes.insert(
            Attribute::May,
            SchemaAttribute {
                name: Attribute::May,
                uuid: UUID_SCHEMA_ATTR_MAY,
                description: String::from(
                    "A user modifiable list of optional attributes this class can store.",
                ),
                multivalue: true,
                unique: false,
                phantom: false,
                sync_allowed: false,
                replicated: Replicated::True,
                indexed: false,
                syntax: SyntaxType::Utf8StringInsensitive,
            },
        );
        self.attributes.insert(
            Attribute::SystemMust,
            SchemaAttribute {
                name: Attribute::SystemMust,
                uuid: UUID_SCHEMA_ATTR_SYSTEMMUST,
                description: String::from(
                    "A list of system provided required attributes this class must store.",
                ),
                multivalue: true,
                unique: false,
                phantom: false,
                sync_allowed: false,
                replicated: Replicated::True,
                indexed: false,
                syntax: SyntaxType::Utf8StringInsensitive,
            },
        );
        self.attributes.insert(
            Attribute::Must,
            SchemaAttribute {
                name: Attribute::Must,
                uuid: UUID_SCHEMA_ATTR_MUST,
                description: String::from(
                    "A user modifiable list of required attributes this class must store.",
                ),
                multivalue: true,
                unique: false,
                phantom: false,
                sync_allowed: false,
                replicated: Replicated::True,
                indexed: false,
                syntax: SyntaxType::Utf8StringInsensitive,
            },
        );
        self.attributes.insert(
            Attribute::SystemSupplements,
            SchemaAttribute {
                name: Attribute::SystemSupplements,
                uuid: UUID_SCHEMA_ATTR_SYSTEMSUPPLEMENTS,
                description: String::from(
                    "A set of classes that this type supplements, where this class can't exist without their presence.",
                ),
                multivalue: true,
                unique: false,
                phantom: false,
                sync_allowed: false,
                replicated: Replicated::True,
                indexed: false,
                syntax: SyntaxType::Utf8StringInsensitive,
            },
        );
        self.attributes.insert(
            Attribute::Supplements,
            SchemaAttribute {
                name: Attribute::Supplements,
                uuid: UUID_SCHEMA_ATTR_SUPPLEMENTS,
                description: String::from(
                    "A set of user modifiable classes, where this determines that at least one other type must supplement this type",
                ),
                multivalue: true,
                unique: false,
                phantom: false,
                sync_allowed: false,
                replicated: Replicated::True,
                indexed: false,
                syntax: SyntaxType::Utf8StringInsensitive,
            },
        );
        self.attributes.insert(
            Attribute::SystemExcludes,
            SchemaAttribute {
                name: Attribute::SystemExcludes,
                uuid: UUID_SCHEMA_ATTR_SYSTEMEXCLUDES,
                description: String::from(
                    "A set of classes that are denied presence in connection to this class",
                ),
                multivalue: true,
                unique: false,
                phantom: false,
                sync_allowed: false,
                replicated: Replicated::True,
                indexed: false,
                syntax: SyntaxType::Utf8StringInsensitive,
            },
        );
        self.attributes.insert(
            Attribute::Excludes,
            SchemaAttribute {
                name: Attribute::Excludes,
                uuid: UUID_SCHEMA_ATTR_EXCLUDES,
                description: String::from(
                    "A set of user modifiable classes that are denied presence in connection to this class",
                ),
                multivalue: true,
                unique: false,
                phantom: false,
                sync_allowed: false,
                replicated: Replicated::True,
                indexed: false,
                syntax: SyntaxType::Utf8StringInsensitive,
            },
        );

        // SYSINFO attrs
        // ACP attributes.
        self.attributes.insert(
            Attribute::AcpEnable,
            SchemaAttribute {
                name: Attribute::AcpEnable,
                uuid: UUID_SCHEMA_ATTR_ACP_ENABLE,
                description: String::from("A flag to determine if this ACP is active for application. True is enabled, and enforced. False is checked but not enforced."),
                multivalue: false,
                unique: false,
                phantom: false,
                sync_allowed: false,
                replicated: Replicated::True,
                indexed: true,
                syntax: SyntaxType::Boolean,
            },
        );

        self.attributes.insert(
            Attribute::AcpReceiver,
            SchemaAttribute {
                name: Attribute::AcpReceiver,
                uuid: UUID_SCHEMA_ATTR_ACP_RECEIVER,
                description: String::from(
                    "Who the ACP applies to, constraining or allowing operations.",
                ),
                multivalue: false,
                unique: false,
                phantom: false,
                sync_allowed: false,
                replicated: Replicated::True,
                indexed: true,
                syntax: SyntaxType::JsonFilter,
            },
        );
        self.attributes.insert(
            Attribute::AcpReceiverGroup,
            SchemaAttribute {
                name: Attribute::AcpReceiverGroup,
                uuid: UUID_SCHEMA_ATTR_ACP_RECEIVER_GROUP,
                description: String::from(
                    "The group that receives this access control to allow access",
                ),
                multivalue: true,
                unique: false,
                phantom: false,
                sync_allowed: false,
                replicated: Replicated::True,
                indexed: true,
                syntax: SyntaxType::ReferenceUuid,
            },
        );

        self.attributes.insert(
            Attribute::AcpTargetScope,
            SchemaAttribute {
                name: Attribute::AcpTargetScope,
                uuid: UUID_SCHEMA_ATTR_ACP_TARGETSCOPE,
                description: String::from(
                    "The effective targets of the ACP, e.g. what will be acted upon.",
                ),
                multivalue: false,
                unique: false,
                phantom: false,
                sync_allowed: false,
                replicated: Replicated::True,
                indexed: true,
                syntax: SyntaxType::JsonFilter,
            },
        );
        self.attributes.insert(
            Attribute::AcpSearchAttr,
            SchemaAttribute {
                name: Attribute::AcpSearchAttr,
                uuid: UUID_SCHEMA_ATTR_ACP_SEARCH_ATTR,
                description: String::from(
                    "The attributes that may be viewed or searched by the receiver on targetscope.",
                ),
                multivalue: true,
                unique: false,
                phantom: false,
                sync_allowed: false,
                replicated: Replicated::True,
                indexed: true,
                syntax: SyntaxType::Utf8StringInsensitive,
            },
        );
        self.attributes.insert(
            Attribute::AcpCreateClass,
            SchemaAttribute {
                name: Attribute::AcpCreateClass,
                uuid: UUID_SCHEMA_ATTR_ACP_CREATE_CLASS,
                description: String::from("The set of classes that can be created on a new entry."),
                multivalue: true,
                unique: false,
                phantom: false,
                sync_allowed: false,
                replicated: Replicated::True,
                indexed: true,
                syntax: SyntaxType::Utf8StringInsensitive,
            },
        );
        self.attributes.insert(
            Attribute::AcpCreateAttr,
            SchemaAttribute {
                name: Attribute::AcpCreateAttr,
                uuid: UUID_SCHEMA_ATTR_ACP_CREATE_ATTR,
                description: String::from(
                    "The set of attribute types that can be created on an entry.",
                ),
                multivalue: true,
                unique: false,
                phantom: false,
                sync_allowed: false,
                replicated: Replicated::True,
                indexed: true,
                syntax: SyntaxType::Utf8StringInsensitive,
            },
        );

        self.attributes.insert(
            Attribute::AcpModifyRemovedAttr,
            SchemaAttribute {
                name: Attribute::AcpModifyRemovedAttr,
                uuid: UUID_SCHEMA_ATTR_ACP_MODIFY_REMOVEDATTR,
                description: String::from(
                    "The set of attribute types that could be removed or purged in a modification.",
                ),
                multivalue: true,
                unique: false,
                phantom: false,
                sync_allowed: false,
                replicated: Replicated::True,
                indexed: true,
                syntax: SyntaxType::Utf8StringInsensitive,
            },
        );
        self.attributes.insert(
            Attribute::AcpModifyPresentAttr,
            SchemaAttribute {
                name: Attribute::AcpModifyPresentAttr,
                uuid: UUID_SCHEMA_ATTR_ACP_MODIFY_PRESENTATTR,
                description: String::from(
                    "The set of attribute types that could be added or asserted in a modification.",
                ),
                multivalue: true,
                unique: false,
                phantom: false,
                sync_allowed: false,
                replicated: Replicated::True,
                indexed: true,
                syntax: SyntaxType::Utf8StringInsensitive,
            },
        );
        self.attributes.insert(
            Attribute::AcpModifyClass,
            SchemaAttribute {
                name: Attribute::AcpModifyClass,
                uuid: UUID_SCHEMA_ATTR_ACP_MODIFY_CLASS,
                description: String::from("The set of class values that could be asserted or added to an entry. Only applies to modify::present operations on class."),
                multivalue: true,
                unique: false,
                phantom: false,
                sync_allowed: false,
                replicated: Replicated::True,
                indexed: true,
                syntax: SyntaxType::Utf8StringInsensitive,
            },
        );
        self.attributes.insert(
                Attribute::AcpModifyPresentClass,
                SchemaAttribute {
                    name: Attribute::AcpModifyPresentClass,
                    uuid: UUID_SCHEMA_ATTR_ACP_MODIFY_PRESENT_CLASS,
                    description: String::from("The set of class values that could be asserted or added to an entry. Only applies to modify::present operations on class."),
                    multivalue: true,
                    unique: false,
                    phantom: false,
                    sync_allowed: false,
                    replicated: Replicated::True,
                    indexed: false,
                    syntax: SyntaxType::Utf8StringInsensitive,
                },
            );
        self.attributes.insert(
                Attribute::AcpModifyRemoveClass,
                SchemaAttribute {
                    name: Attribute::AcpModifyRemoveClass,
                    uuid: UUID_SCHEMA_ATTR_ACP_MODIFY_REMOVE_CLASS,
                    description: String::from("The set of class values that could be asserted or added to an entry. Only applies to modify::remove operations on class."),
                    multivalue: true,
                    unique: false,
                    phantom: false,
                    sync_allowed: false,
                    replicated: Replicated::True,
                    indexed: false,
                    syntax: SyntaxType::Utf8StringInsensitive,
                },
            );
        self.attributes.insert(
            Attribute::EntryManagedBy,
            SchemaAttribute {
                name: Attribute::EntryManagedBy,
                uuid: UUID_SCHEMA_ATTR_ENTRY_MANAGED_BY,
                description: String::from(
                    "A reference to a group that has access to manage the content of this entry.",
                ),
                multivalue: false,
                unique: false,
                phantom: false,
                sync_allowed: false,
                replicated: Replicated::True,
                indexed: true,
                syntax: SyntaxType::ReferenceUuid,
            },
        );
        // MO/Member
        self.attributes.insert(
            Attribute::MemberOf,
            SchemaAttribute {
                name: Attribute::MemberOf,
                uuid: UUID_SCHEMA_ATTR_MEMBEROF,
                description: String::from("reverse group membership of the object"),
                multivalue: true,
                unique: false,
                phantom: false,
                sync_allowed: false,
                replicated: Replicated::False,
                indexed: true,
                syntax: SyntaxType::ReferenceUuid,
            },
        );
        self.attributes.insert(
            Attribute::DirectMemberOf,
            SchemaAttribute {
                name: Attribute::DirectMemberOf,
                uuid: UUID_SCHEMA_ATTR_DIRECTMEMBEROF,
                description: String::from("reverse direct group membership of the object"),
                multivalue: true,
                unique: false,
                phantom: false,
                sync_allowed: false,
                replicated: Replicated::False,
                indexed: true,
                syntax: SyntaxType::ReferenceUuid,
            },
        );
        self.attributes.insert(
            Attribute::RecycledDirectMemberOf,
            SchemaAttribute {
                name: Attribute::RecycledDirectMemberOf,
                uuid: UUID_SCHEMA_ATTR_RECYCLEDDIRECTMEMBEROF,
                description: String::from("recycled reverse direct group membership of the object to assist in revive operations."),
                multivalue: true,
                unique: false,
                phantom: false,
                sync_allowed: false,
                // Unlike DMO this must be replicated so that on a recycle event, these groups
                //  "at delete" are replicated to partners. This avoids us having to replicate
                // DMO which is very costly, while still retaining our ability to revive entries
                // and their group memberships as a best effort.
                replicated: Replicated::True,
                indexed: true,
                syntax: SyntaxType::ReferenceUuid,
            },
        );
        self.attributes.insert(
            Attribute::Member,
            SchemaAttribute {
                name: Attribute::Member,
                uuid: UUID_SCHEMA_ATTR_MEMBER,
                description: String::from("List of members of the group"),
                multivalue: true,
                unique: false,
                phantom: false,
                sync_allowed: true,
                replicated: Replicated::True,
                indexed: true,
                syntax: SyntaxType::ReferenceUuid,
            },
        );
        self.attributes.insert(
            Attribute::DynMember,
            SchemaAttribute {
                name: Attribute::DynMember,
                uuid: UUID_SCHEMA_ATTR_DYNMEMBER,
                description: String::from("List of dynamic members of the group"),
                multivalue: true,
                unique: false,
                phantom: false,
                sync_allowed: true,
                replicated: Replicated::False,
                indexed: true,
                syntax: SyntaxType::ReferenceUuid,
            },
        );

        self.attributes.insert(
            Attribute::Refers,
            SchemaAttribute {
                name: Attribute::Refers,
                uuid: UUID_SCHEMA_ATTR_REFERS,
                description: String::from("A reference to another object"),
                multivalue: false,
                unique: false,
                phantom: false,
                sync_allowed: false,
                replicated: Replicated::True,
                indexed: true,
                syntax: SyntaxType::ReferenceUuid,
            },
        );

        self.attributes.insert(
            Attribute::CascadeDeleted,
            SchemaAttribute {
                name: Attribute::CascadeDeleted,
                uuid: UUID_SCHEMA_ATTR_CASCADE_DELETED,
                description: String::from("A marker attribute denoting that this entry was deleted by cascade when this UUID was deleted."),
                multivalue: false,
                unique: false,
                phantom: false,
                sync_allowed: false,
                replicated: Replicated::True,
                indexed: true,
                // NOTE: This has to be Uuid so that referential integrity doesn't consider
                // this value in its operation.
                syntax: SyntaxType::Uuid,
            },
        );

        // Migration related
        self.attributes.insert(
            Attribute::Version,
            SchemaAttribute {
                name: Attribute::Version,
                uuid: UUID_SCHEMA_ATTR_VERSION,
                description: String::from(
                    "The systems internal migration version for provided objects",
                ),
                multivalue: false,
                unique: false,
                phantom: false,
                sync_allowed: false,
                replicated: Replicated::True,
                indexed: false,
                syntax: SyntaxType::Uint32,
            },
        );
        // Domain for sysinfo
        self.attributes.insert(
            Attribute::Domain,
            SchemaAttribute {
                name: Attribute::Domain,
                uuid: UUID_SCHEMA_ATTR_DOMAIN,
                description: String::from("A DNS Domain name entry."),
                multivalue: true,
                unique: false,
                phantom: false,
                sync_allowed: false,
                replicated: Replicated::True,
                indexed: true,
                syntax: SyntaxType::Utf8StringIname,
            },
        );
        self.attributes.insert(
            Attribute::Claim,
            SchemaAttribute {
                name: Attribute::Claim,
                uuid: UUID_SCHEMA_ATTR_CLAIM,
                description: String::from(
                    "The string identifier of an extracted claim that can be filtered",
                ),
                multivalue: true,
                unique: false,
                phantom: true,
                sync_allowed: false,
                replicated: Replicated::True,
                indexed: false,
                syntax: SyntaxType::Utf8StringInsensitive,
            },
        );
        self.attributes.insert(
            Attribute::Scope,
            SchemaAttribute {
                name: Attribute::Scope,
                uuid: UUID_SCHEMA_ATTR_SCOPE,
                description: String::from(
                    "The string identifier of a permission scope in a session",
                ),
                multivalue: true,
                unique: false,
                phantom: true,
                sync_allowed: false,
                replicated: Replicated::True,
                indexed: false,
                syntax: SyntaxType::Utf8StringInsensitive,
            },
        );

        // External Scim Sync
        self.attributes.insert(
            Attribute::SyncExternalId,
            SchemaAttribute {
                name: Attribute::SyncExternalId,
                uuid: UUID_SCHEMA_ATTR_SYNC_EXTERNAL_ID,
                description: String::from(
                    "An external string ID of an entry imported from a sync agreement",
                ),
                multivalue: false,
                unique: true,
                phantom: false,
                sync_allowed: false,
                replicated: Replicated::True,
                indexed: true,
                syntax: SyntaxType::Utf8StringInsensitive,
            },
        );
        self.attributes.insert(
            Attribute::SyncParentUuid,
            SchemaAttribute {
                name: Attribute::SyncParentUuid,
                uuid: UUID_SCHEMA_ATTR_SYNC_PARENT_UUID,
                description: String::from(
                    "The UUID of the parent sync agreement that created this entry.",
                ),
                multivalue: false,
                unique: false,
                phantom: false,
                sync_allowed: false,
                replicated: Replicated::True,
                indexed: true,
                syntax: SyntaxType::ReferenceUuid,
            },
        );
        self.attributes.insert(
            Attribute::SyncClass,
            SchemaAttribute {
                name: Attribute::SyncClass,
                uuid: UUID_SCHEMA_ATTR_SYNC_CLASS,
                description: String::from("The set of classes requested by the sync client."),
                multivalue: true,
                unique: false,
                phantom: false,
                sync_allowed: false,
                replicated: Replicated::True,
                indexed: false,
                syntax: SyntaxType::Utf8StringInsensitive,
            },
        );

        self.attributes.insert(
            Attribute::PasswordImport,
            SchemaAttribute {
                name: Attribute::PasswordImport,
                uuid: UUID_SCHEMA_ATTR_PASSWORD_IMPORT,
                description: String::from("An imported password hash from an external system."),
                multivalue: false,
                unique: false,
                phantom: true,
                sync_allowed: true,
                replicated: Replicated::False,
                indexed: false,
                syntax: SyntaxType::Utf8String,
            },
        );

        self.attributes.insert(
            Attribute::UnixPasswordImport,
            SchemaAttribute {
                name: Attribute::UnixPasswordImport,
                uuid: UUID_SCHEMA_ATTR_UNIX_PASSWORD_IMPORT,
                description: String::from(
                    "An imported unix password hash from an external system.",
                ),
                multivalue: false,
                unique: false,
                phantom: true,
                sync_allowed: true,
                replicated: Replicated::False,
                indexed: false,
                syntax: SyntaxType::Utf8String,
            },
        );

        self.attributes.insert(
            Attribute::TotpImport,
            SchemaAttribute {
                name: Attribute::TotpImport,
                uuid: UUID_SCHEMA_ATTR_TOTP_IMPORT,
                description: String::from("An imported totp secret from an external system."),
                multivalue: true,
                unique: false,
                phantom: true,
                sync_allowed: true,
                replicated: Replicated::False,
                indexed: false,
                syntax: SyntaxType::TotpSecret,
            },
        );

        // LDAP Masking Phantoms
        self.attributes.insert(
            Attribute::Dn,
            SchemaAttribute {
                name: Attribute::Dn,
                uuid: UUID_SCHEMA_ATTR_DN,
                description: String::from("An LDAP Compatible DN"),
                multivalue: false,
                unique: false,
                phantom: true,
                sync_allowed: false,
                replicated: Replicated::False,
                indexed: false,
                syntax: SyntaxType::Utf8StringInsensitive,
            },
        );
        self.attributes.insert(
            Attribute::EntryDn,
            SchemaAttribute {
                name: Attribute::EntryDn,
                uuid: UUID_SCHEMA_ATTR_ENTRYDN,
                description: String::from("An LDAP Compatible EntryDN"),
                multivalue: false,
                unique: false,
                phantom: true,
                sync_allowed: false,
                replicated: Replicated::False,
                indexed: false,
                syntax: SyntaxType::Utf8StringInsensitive,
            },
        );
        self.attributes.insert(
            Attribute::EntryUuid,
            SchemaAttribute {
                name: Attribute::EntryUuid,
                uuid: UUID_SCHEMA_ATTR_ENTRYUUID,
                description: String::from("An LDAP Compatible entryUUID"),
                multivalue: false,
                unique: false,
                phantom: true,
                sync_allowed: false,
                replicated: Replicated::False,
                indexed: false,
                syntax: SyntaxType::Uuid,
            },
        );
        self.attributes.insert(
            Attribute::ObjectClass,
            SchemaAttribute {
                name: Attribute::ObjectClass,
                uuid: UUID_SCHEMA_ATTR_OBJECTCLASS,
                description: String::from("An LDAP Compatible objectClass"),
                multivalue: true,
                unique: false,
                phantom: true,
                sync_allowed: false,
                replicated: Replicated::False,
                indexed: false,
                syntax: SyntaxType::Utf8StringInsensitive,
            },
        );
        self.attributes.insert(
            Attribute::Cn,
            SchemaAttribute {
                name: Attribute::Cn,
                uuid: UUID_SCHEMA_ATTR_CN,
                description: String::from("An LDAP Compatible objectClass"),
                multivalue: false,
                unique: false,
                phantom: true,
                sync_allowed: false,
                replicated: Replicated::False,
                indexed: false,
                syntax: SyntaxType::Utf8StringIname,
            },
        );
        self.attributes.insert(
            Attribute::LdapKeys, // keys
            SchemaAttribute {
                name: Attribute::LdapKeys, // keys
                uuid: UUID_SCHEMA_ATTR_KEYS,
                description: String::from("An LDAP Compatible keys (ssh)"),
                multivalue: true,
                unique: false,
                phantom: true,
                sync_allowed: false,
                replicated: Replicated::False,
                indexed: false,
                syntax: SyntaxType::SshKey,
            },
        );
        self.attributes.insert(
            Attribute::LdapSshPublicKey,
            SchemaAttribute {
                name: Attribute::LdapSshPublicKey,
                uuid: UUID_SCHEMA_ATTR_SSHPUBLICKEY,
                description: String::from("An LDAP Compatible sshPublicKey"),
                multivalue: true,
                unique: false,
                phantom: true,
                sync_allowed: false,
                replicated: Replicated::False,
                indexed: false,
                syntax: SyntaxType::SshKey,
            },
        );
        self.attributes.insert(
            Attribute::Email,
            SchemaAttribute {
                name: Attribute::Email,
                uuid: UUID_SCHEMA_ATTR_EMAIL,
                description: String::from("An LDAP Compatible email"),
                multivalue: true,
                unique: false,
                phantom: true,
                sync_allowed: false,
                replicated: Replicated::False,
                indexed: false,
                syntax: SyntaxType::EmailAddress,
            },
        );
        self.attributes.insert(
            Attribute::EmailPrimary,
            SchemaAttribute {
                name: Attribute::EmailPrimary,
                uuid: UUID_SCHEMA_ATTR_EMAILPRIMARY,
                description: String::from("An LDAP Compatible primary email"),
                multivalue: false,
                unique: false,
                phantom: true,
                sync_allowed: false,
                replicated: Replicated::False,
                indexed: false,
                syntax: SyntaxType::EmailAddress,
            },
        );
        self.attributes.insert(
            Attribute::EmailAlternative,
            SchemaAttribute {
                name: Attribute::EmailAlternative,
                uuid: UUID_SCHEMA_ATTR_EMAILALTERNATIVE,
                description: String::from("An LDAP Compatible alternative email"),
                multivalue: false,
                unique: false,
                phantom: true,
                sync_allowed: false,
                replicated: Replicated::False,
                indexed: false,
                syntax: SyntaxType::EmailAddress,
            },
        );
        self.attributes.insert(
            Attribute::LdapEmailAddress,
            SchemaAttribute {
                name: Attribute::LdapEmailAddress,
                uuid: UUID_SCHEMA_ATTR_EMAILADDRESS,
                description: String::from("An LDAP Compatible emailAddress"),
                multivalue: true,
                unique: false,
                phantom: true,
                sync_allowed: false,
                replicated: Replicated::False,
                indexed: false,
                syntax: SyntaxType::EmailAddress,
            },
        );
        self.attributes.insert(
            Attribute::Gecos,
            SchemaAttribute {
                name: Attribute::Gecos,
                uuid: UUID_SCHEMA_ATTR_GECOS,
                description: String::from("An LDAP Compatible gecos."),
                multivalue: false,
                unique: false,
                phantom: true,
                sync_allowed: false,
                replicated: Replicated::False,
                indexed: false,
                syntax: SyntaxType::Utf8String,
            },
        );
        self.attributes.insert(
            Attribute::Uid,
            SchemaAttribute {
                name: Attribute::Uid,
                uuid: UUID_SCHEMA_ATTR_UID,
                description: String::from("An LDAP Compatible uid."),
                multivalue: false,
                unique: false,
                phantom: true,
                sync_allowed: false,
                replicated: Replicated::False,
                indexed: false,
                syntax: SyntaxType::Utf8String,
            },
        );
        self.attributes.insert(
            Attribute::UidNumber,
            SchemaAttribute {
                name: Attribute::UidNumber,
                uuid: UUID_SCHEMA_ATTR_UIDNUMBER,
                description: String::from("An LDAP Compatible uidNumber."),
                multivalue: false,
                unique: false,
                phantom: true,
                sync_allowed: false,
                replicated: Replicated::False,
                indexed: false,
                syntax: SyntaxType::Uint32,
            },
        );
        self.attributes.insert(
            Attribute::SudoHost,
            SchemaAttribute {
                name: Attribute::SudoHost,
                uuid: UUID_SCHEMA_ATTR_SUDOHOST,
                description: String::from("An LDAP Compatible sudohost."),
                multivalue: false,
                unique: false,
                phantom: true,
                sync_allowed: false,
                replicated: Replicated::False,
                indexed: false,
                syntax: SyntaxType::Utf8String,
            },
        );
        self.attributes.insert(
            Attribute::HomeDirectory,
            SchemaAttribute {
                name: Attribute::HomeDirectory,
                uuid: UUID_SCHEMA_ATTR_HOME_DIRECTORY,
                description: String::from("An LDAP Compatible homeDirectory."),
                multivalue: false,
                unique: false,
                phantom: true,
                sync_allowed: false,
                replicated: Replicated::False,
                indexed: false,
                syntax: SyntaxType::Utf8String,
            },
        );
        // end LDAP masking phantoms

        // THIS IS FOR SYSTEM CRITICAL INTERNAL SCHEMA ONLY

        // =================================================================

        self.classes.insert(
            EntryClass::AttributeType.into(),
            SchemaClass {
                name: EntryClass::AttributeType.into(),
                uuid: UUID_SCHEMA_CLASS_ATTRIBUTETYPE,
                description: String::from("Definition of a schema attribute"),
                systemmay: vec![
                    Attribute::Replicated,
                    Attribute::Phantom,
                    Attribute::SyncAllowed,
                    Attribute::Index,
                    Attribute::Indexed,
                ],
                systemmust: vec![
                    Attribute::Class,
                    Attribute::AttributeName,
                    Attribute::MultiValue,
                    Attribute::Unique,
                    Attribute::Syntax,
                    Attribute::Description,
                ],
                systemexcludes: vec![EntryClass::ClassType.into()],
                ..Default::default()
            },
        );
        self.classes.insert(
            EntryClass::ClassType.into(),
            SchemaClass {
                name: EntryClass::ClassType.into(),
                uuid: UUID_SCHEMA_CLASS_CLASSTYPE,
                description: String::from("Definition of a schema classtype"),
                systemmay: vec![
                    Attribute::SyncAllowed,
                    Attribute::SystemMay,
                    Attribute::May,
                    Attribute::SystemMust,
                    Attribute::Must,
                    Attribute::SystemSupplements,
                    Attribute::Supplements,
                    Attribute::SystemExcludes,
                    Attribute::Excludes,
                ],
                systemmust: vec![
                    Attribute::Class,
                    Attribute::ClassName,
                    Attribute::Description,
                ],
                systemexcludes: vec![Attribute::AttributeType.into()],
                ..Default::default()
            },
        );
        self.classes.insert(
            EntryClass::Object.into(),
            SchemaClass {
                name: EntryClass::Object.into(),
                uuid: UUID_SCHEMA_CLASS_OBJECT,
                description: String::from("A system created class that all objects must contain"),
                systemmay: vec![
                    Attribute::Description,
                    Attribute::EntryManagedBy,
                    Attribute::MemberOf,
                    Attribute::DirectMemberOf,
                ],
                systemmust: vec![
                    Attribute::Class,
                    Attribute::Uuid,
                    Attribute::LastModifiedCid,
                    Attribute::CreatedAtCid,
                ],
                ..Default::default()
            },
        );
        self.classes.insert(
            EntryClass::Builtin.into(),
            SchemaClass {
                name: EntryClass::Builtin.into(),
                uuid: UUID_SCHEMA_CLASS_BUILTIN,
                description: String::from("A marker class denoting builtin entries"),
                ..Default::default()
            },
        );
        self.classes.insert(
            EntryClass::MemberOf.into(),
            SchemaClass {
                name: EntryClass::MemberOf.into(),
                uuid: UUID_SCHEMA_CLASS_MEMBEROF,
                description: String::from(
                    "Class that is dynamically added to recipients of memberof or directmemberof. TO BE REMOVED.",
                ),
                ..Default::default()
            },
        );
        self.classes.insert(
            EntryClass::ExtensibleObject.into(),
            SchemaClass {
                name: EntryClass::ExtensibleObject.into(),
                uuid: UUID_SCHEMA_CLASS_EXTENSIBLEOBJECT,
                description: String::from(
                    "A class type that has green hair and turns off all rules ...",
                ),
                ..Default::default()
            },
        );
        /* These two classes are core to the entry lifecycle for recycling and tombstoning */
        self.classes.insert(
                EntryClass::Recycled.into(),
                SchemaClass {
                    name: EntryClass::Recycled.into(),
                    uuid: UUID_SCHEMA_CLASS_RECYCLED,
                    description: String::from("An object that has been deleted, but still recoverable via the revive operation. Recycled objects are not modifiable, only revivable."),
                    systemmay: vec![Attribute::RecycledDirectMemberOf, Attribute::CascadeDeleted],
                    .. Default::default()
                },
            );
        self.classes.insert(
                EntryClass::Tombstone.into(),
                SchemaClass {
                    name: EntryClass::Tombstone.into(),
                    uuid: UUID_SCHEMA_CLASS_TOMBSTONE,
                    description: String::from("An object that is purged from the recycle bin. This is a system internal state. Tombstones have no attributes beside UUID."),
                    systemmust: vec![
                        Attribute::Class,
                        Attribute::Uuid,
                    ],
                    .. Default::default()
                },
            );
        self.classes.insert(
            EntryClass::Conflict.into(),
            SchemaClass {
                name: EntryClass::Conflict.into(),
                uuid: UUID_SCHEMA_CLASS_CONFLICT,
                description: String::from(
                    "An entry representing conflicts that occurred during replication",
                ),
                systemmust: vec![Attribute::SourceUuid],
                systemsupplements: vec![EntryClass::Recycled.into()],
                ..Default::default()
            },
        );
        // sysinfo
        self.classes.insert(
            EntryClass::SystemInfo.into(),
            SchemaClass {
                name: EntryClass::SystemInfo.into(),
                uuid: UUID_SCHEMA_CLASS_SYSTEM_INFO,
                description: String::from("System metadata object class"),
                systemmust: vec![Attribute::Version],
                ..Default::default()
            },
        );
        // ACP
        self.classes.insert(
            EntryClass::AccessControlSearch.into(),
            SchemaClass {
                name: EntryClass::AccessControlSearch.into(),
                uuid: UUID_SCHEMA_CLASS_ACCESS_CONTROL_SEARCH,
                description: String::from("System Access Control Search Class"),
                systemmust: vec![Attribute::AcpSearchAttr],
                ..Default::default()
            },
        );
        self.classes.insert(
            EntryClass::AccessControlDelete.into(),
            SchemaClass {
                name: EntryClass::AccessControlDelete.into(),
                uuid: UUID_SCHEMA_CLASS_ACCESS_CONTROL_DELETE,
                description: String::from("System Access Control DELETE Class"),
                ..Default::default()
            },
        );
        self.classes.insert(
            EntryClass::AccessControlModify.into(),
            SchemaClass {
                name: EntryClass::AccessControlModify.into(),
                uuid: UUID_SCHEMA_CLASS_ACCESS_CONTROL_MODIFY,
                description: String::from("System Access Control Modify Class"),
                systemmay: vec![
                    Attribute::AcpModifyRemovedAttr,
                    Attribute::AcpModifyPresentAttr,
                    Attribute::AcpModifyClass,
                    Attribute::AcpModifyPresentClass,
                    Attribute::AcpModifyRemoveClass,
                ],
                ..Default::default()
            },
        );
        self.classes.insert(
            EntryClass::AccessControlCreate.into(),
            SchemaClass {
                name: EntryClass::AccessControlCreate.into(),
                uuid: UUID_SCHEMA_CLASS_ACCESS_CONTROL_CREATE,
                description: String::from("System Access Control Create Class"),
                systemmay: vec![Attribute::AcpCreateClass, Attribute::AcpCreateAttr],
                ..Default::default()
            },
        );
        self.classes.insert(
            EntryClass::AccessControlProfile.into(),
            SchemaClass {
                name: EntryClass::AccessControlProfile.into(),
                uuid: UUID_SCHEMA_CLASS_ACCESS_CONTROL_PROFILE,
                description: String::from("System Access Control Profile Class"),
                systemmay: vec![Attribute::AcpEnable, Attribute::Description],
                systemmust: vec![Attribute::Name],
                systemsupplements: vec![
                    EntryClass::AccessControlSearch.into(),
                    EntryClass::AccessControlDelete.into(),
                    EntryClass::AccessControlModify.into(),
                    EntryClass::AccessControlCreate.into(),
                ],
                ..Default::default()
            },
        );
        self.classes.insert(
            EntryClass::AccessControlReceiverEntryManager.into(),
            SchemaClass {
                name: EntryClass::AccessControlReceiverEntryManager.into(),
                uuid: UUID_SCHEMA_CLASS_ACCESS_CONTROL_RECEIVER_ENTRY_MANAGER,
                description: String::from("System Access Control Profile Receiver - Entry Manager"),
                systemexcludes: vec![EntryClass::AccessControlReceiverGroup.into()],
                systemsupplements: vec![EntryClass::AccessControlProfile.into()],
                ..Default::default()
            },
        );
        self.classes.insert(
            EntryClass::AccessControlReceiverGroup.into(),
            SchemaClass {
                name: EntryClass::AccessControlReceiverGroup.into(),
                uuid: UUID_SCHEMA_CLASS_ACCESS_CONTROL_RECEIVER_GROUP,
                description: String::from("System Access Control Profile Receiver - Group"),
                systemmay: vec![Attribute::AcpReceiver],
                systemmust: vec![Attribute::AcpReceiverGroup],
                systemsupplements: vec![EntryClass::AccessControlProfile.into()],
                systemexcludes: vec![EntryClass::AccessControlReceiverEntryManager.into()],
                ..Default::default()
            },
        );
        self.classes.insert(
            EntryClass::AccessControlTargetScope.into(),
            SchemaClass {
                name: EntryClass::AccessControlTargetScope.into(),
                uuid: UUID_SCHEMA_CLASS_ACCESS_CONTROL_TARGET_SCOPE,
                description: String::from("System Access Control Profile Target - Scope"),
                systemmust: vec![Attribute::AcpTargetScope],
                systemsupplements: vec![EntryClass::AccessControlProfile.into()],
                ..Default::default()
            },
        );

        // System attrs
        self.classes.insert(
            EntryClass::System.into(),
            SchemaClass {
                name: EntryClass::System.into(),
                uuid: UUID_SCHEMA_CLASS_SYSTEM,
                description: String::from("A class denoting that a type is system generated and protected. It has special internal behaviour."),
                .. Default::default()
            },
        );
        self.classes.insert(
            EntryClass::SyncObject.into(),
            SchemaClass {
                name: EntryClass::SyncObject.into(),
                uuid: UUID_SCHEMA_CLASS_SYNC_OBJECT,
                description: String::from("A class denoting that an entry is synchronised from an external source. This entry may not be modifiable."),
                systemmust: vec![
                    Attribute::SyncParentUuid
                ],
                systemmay: vec![
                    Attribute::SyncExternalId,
                    Attribute::SyncClass,
                ],
                .. Default::default()
            },
        );

        let r = self.validate();
        if r.is_empty() {
            admin_debug!("schema validate -> passed");
            Ok(())
        } else {
            admin_error!(err = ?r, "schema validate -> errors");
            Err(OperationError::ConsistencyError(
                r.into_iter().filter_map(|v| v.err()).collect(),
            ))
        }
    }
}

impl SchemaTransaction for SchemaWriteTransaction<'_> {
    fn get_attributes_unique(&self) -> &Vec<Attribute> {
        &self.unique_cache
    }

    fn get_reference_types(&self) -> &HashMap<Attribute, SchemaAttribute> {
        &self.ref_cache
    }

    fn get_classes(&self) -> &HashMap<AttrString, SchemaClass> {
        &self.classes
    }

    fn get_attributes(&self) -> &HashMap<Attribute, SchemaAttribute> {
        &self.attributes
    }
}

impl SchemaTransaction for SchemaReadTransaction {
    fn get_attributes_unique(&self) -> &Vec<Attribute> {
        &self.unique_cache
    }

    fn get_reference_types(&self) -> &HashMap<Attribute, SchemaAttribute> {
        &self.ref_cache
    }

    fn get_classes(&self) -> &HashMap<AttrString, SchemaClass> {
        &self.classes
    }

    fn get_attributes(&self) -> &HashMap<Attribute, SchemaAttribute> {
        &self.attributes
    }
}

impl Schema {
    pub fn new() -> Result<Self, OperationError> {
        let s = Schema {
            classes: CowCell::new(HashMap::with_capacity(128)),
            attributes: CowCell::new(HashMap::with_capacity(128)),
            unique_cache: CowCell::new(Vec::with_capacity(0)),
            ref_cache: CowCell::new(HashMap::with_capacity(64)),
        };
        let mut sw = s.write();
        let r1 = sw.generate_in_memory();
        debug_assert!(r1.is_ok());
        r1?;
        let r2 = sw.commit().map(|_| s);
        debug_assert!(r2.is_ok());
        r2
    }

    pub fn read(&self) -> SchemaReadTransaction {
        SchemaReadTransaction {
            classes: self.classes.read(),
            attributes: self.attributes.read(),
            unique_cache: self.unique_cache.read(),
            ref_cache: self.ref_cache.read(),
        }
    }

    pub fn write(&self) -> SchemaWriteTransaction<'_> {
        SchemaWriteTransaction {
            classes: self.classes.write(),
            attributes: self.attributes.write(),
            unique_cache: self.unique_cache.write(),
            ref_cache: self.ref_cache.write(),
        }
    }

    #[cfg(test)]
    pub(crate) fn write_blocking(&self) -> SchemaWriteTransaction<'_> {
        self.write()
    }
}

#[cfg(test)]
mod tests {
    use crate::prelude::*;
    use crate::schema::{Schema, SchemaAttribute, SchemaClass, SchemaTransaction, SyntaxType};
    use uuid::Uuid;

    // use crate::proto_v1::Filter as ProtoFilter;

    macro_rules! validate_schema {
        ($sch:ident) => {{
            // Turns into a result type
            let r: Result<Vec<()>, ConsistencyError> = $sch.validate().into_iter().collect();
            assert!(r.is_ok());
        }};
    }

    macro_rules! sch_from_entry_ok {
        (
            $e:expr,
            $type:ty
        ) => {{
            let ev1 = $e.into_sealed_committed();

            let r1 = <$type>::try_from(&ev1);
            assert!(r1.is_ok());
        }};
    }

    macro_rules! sch_from_entry_err {
        (
            $e:expr,
            $type:ty
        ) => {{
            let ev1 = $e.into_sealed_committed();

            let r1 = <$type>::try_from(&ev1);
            assert!(r1.is_err());
        }};
    }

    #[test]
    fn test_schema_attribute_from_entry() {
        sketching::test_init();

        sch_from_entry_err!(
            entry_init!(
                (Attribute::Class, EntryClass::Object.to_value()),
                (Attribute::Class, EntryClass::AttributeType.to_value()),
                (
                    Attribute::AttributeName,
                    Value::new_iutf8("schema_attr_test")
                ),
                (
                    Attribute::Uuid,
                    Value::Uuid(uuid::uuid!("66c68b2f-d02c-4243-8013-7946e40fe321"))
                ),
                (Attribute::Unique, Value::Bool(false))
            ),
            SchemaAttribute
        );

        sch_from_entry_err!(
            entry_init!(
                (Attribute::Class, EntryClass::Object.to_value()),
                (Attribute::Class, EntryClass::AttributeType.to_value()),
                (
                    Attribute::AttributeName,
                    Value::new_iutf8("schema_attr_test")
                ),
                (
                    Attribute::Uuid,
                    Value::Uuid(uuid::uuid!("66c68b2f-d02c-4243-8013-7946e40fe321"))
                ),
                (Attribute::MultiValue, Value::Bool(false)),
                (Attribute::Unique, Value::Bool(false)),
                (Attribute::Syntax, Value::Syntax(SyntaxType::Utf8String))
            ),
            SchemaAttribute
        );

        sch_from_entry_err!(
            entry_init!(
                (Attribute::Class, EntryClass::Object.to_value()),
                (Attribute::Class, EntryClass::AttributeType.to_value()),
                (
                    Attribute::AttributeName,
                    Value::new_iutf8("schema_attr_test")
                ),
                (
                    Attribute::Uuid,
                    Value::Uuid(uuid::uuid!("66c68b2f-d02c-4243-8013-7946e40fe321"))
                ),
                (
                    Attribute::Description,
                    Value::Utf8("Test attr parsing".to_string())
                ),
                (Attribute::MultiValue, Value::Utf8("htouaoeu".to_string())),
                (Attribute::Unique, Value::Bool(false)),
                (Attribute::Syntax, Value::Syntax(SyntaxType::Utf8String))
            ),
            SchemaAttribute
        );

        sch_from_entry_err!(
            entry_init!(
                (Attribute::Class, EntryClass::Object.to_value()),
                (Attribute::Class, EntryClass::AttributeType.to_value()),
                (
                    Attribute::AttributeName,
                    Value::new_iutf8("schema_attr_test")
                ),
                (
                    Attribute::Uuid,
                    Value::Uuid(uuid::uuid!("66c68b2f-d02c-4243-8013-7946e40fe321"))
                ),
                (
                    Attribute::Description,
                    Value::Utf8("Test attr parsing".to_string())
                ),
                (Attribute::MultiValue, Value::Bool(false)),
                (Attribute::Unique, Value::Bool(false)),
                (Attribute::Syntax, Value::Utf8("TNEOUNTUH".to_string()))
            ),
            SchemaAttribute
        );

        // Index is allowed to be empty
        sch_from_entry_ok!(
            entry_init!(
                (Attribute::Class, EntryClass::Object.to_value()),
                (Attribute::Class, EntryClass::AttributeType.to_value()),
                (
                    Attribute::AttributeName,
                    Value::new_iutf8("schema_attr_test")
                ),
                (
                    Attribute::Uuid,
                    Value::Uuid(uuid::uuid!("66c68b2f-d02c-4243-8013-7946e40fe321"))
                ),
                (
                    Attribute::Description,
                    Value::Utf8("Test attr parsing".to_string())
                ),
                (Attribute::MultiValue, Value::Bool(false)),
                (Attribute::Unique, Value::Bool(false)),
                (Attribute::Syntax, Value::Syntax(SyntaxType::Utf8String))
            ),
            SchemaAttribute
        );

        // Index present
        sch_from_entry_ok!(
            entry_init!(
                (Attribute::Class, EntryClass::Object.to_value()),
                (Attribute::Class, EntryClass::AttributeType.to_value()),
                (
                    Attribute::AttributeName,
                    Value::new_iutf8("schema_attr_test")
                ),
                (
                    Attribute::Uuid,
                    Value::Uuid(uuid::uuid!("66c68b2f-d02c-4243-8013-7946e40fe321"))
                ),
                (
                    Attribute::Description,
                    Value::Utf8("Test attr parsing".to_string())
                ),
                (Attribute::MultiValue, Value::Bool(false)),
                (Attribute::Unique, Value::Bool(false)),
                (Attribute::Syntax, Value::Syntax(SyntaxType::Utf8String)),
                (Attribute::Index, Value::Bool(true))
            ),
            SchemaAttribute
        );
    }

    #[test]
    fn test_schema_class_from_entry() {
        sch_from_entry_err!(
            entry_init!(
                (Attribute::Class, EntryClass::Object.to_value()),
                (Attribute::Class, EntryClass::ClassType.to_value()),
                (Attribute::ClassName, Value::new_iutf8("schema_class_test")),
                (
                    Attribute::Uuid,
                    Value::Uuid(uuid::uuid!("66c68b2f-d02c-4243-8013-7946e40fe321"))
                )
            ),
            SchemaClass
        );

        sch_from_entry_err!(
            entry_init!(
                (Attribute::Class, EntryClass::Object.to_value()),
                (Attribute::ClassName, Value::new_iutf8("schema_class_test")),
                (
                    Attribute::Uuid,
                    Value::Uuid(uuid::uuid!("66c68b2f-d02c-4243-8013-7946e40fe321"))
                ),
                (
                    Attribute::Description,
                    Value::Utf8("class test".to_string())
                )
            ),
            SchemaClass
        );

        // Classes can be valid with no attributes provided.
        sch_from_entry_ok!(
            entry_init!(
                (Attribute::Class, EntryClass::Object.to_value()),
                (Attribute::Class, EntryClass::ClassType.to_value()),
                (Attribute::ClassName, Value::new_iutf8("schema_class_test")),
                (
                    Attribute::Uuid,
                    Value::Uuid(uuid::uuid!("66c68b2f-d02c-4243-8013-7946e40fe321"))
                ),
                (
                    Attribute::Description,
                    Value::Utf8("class test".to_string())
                )
            ),
            SchemaClass
        );

        // Classes with various may/must
        sch_from_entry_ok!(
            entry_init!(
                (Attribute::Class, EntryClass::Object.to_value()),
                (Attribute::Class, EntryClass::ClassType.to_value()),
                (Attribute::ClassName, Value::new_iutf8("schema_class_test")),
                (
                    Attribute::Uuid,
                    Value::Uuid(uuid::uuid!("66c68b2f-d02c-4243-8013-7946e40fe321"))
                ),
                (
                    Attribute::Description,
                    Value::Utf8("class test".to_string())
                ),
                (Attribute::SystemMust, Value::new_iutf8("a"))
            ),
            SchemaClass
        );

        sch_from_entry_ok!(
            entry_init!(
                (Attribute::Class, EntryClass::Object.to_value()),
                (Attribute::Class, EntryClass::ClassType.to_value()),
                (Attribute::ClassName, Value::new_iutf8("schema_class_test")),
                (
                    Attribute::Uuid,
                    Value::Uuid(uuid::uuid!("66c68b2f-d02c-4243-8013-7946e40fe321"))
                ),
                (
                    Attribute::Description,
                    Value::Utf8("class test".to_string())
                ),
                (Attribute::SystemMay, Value::new_iutf8("a"))
            ),
            SchemaClass
        );

        sch_from_entry_ok!(
            entry_init!(
                (Attribute::Class, EntryClass::Object.to_value()),
                (Attribute::Class, EntryClass::ClassType.to_value()),
                (Attribute::ClassName, Value::new_iutf8("schema_class_test")),
                (
                    Attribute::Uuid,
                    Value::Uuid(uuid::uuid!("66c68b2f-d02c-4243-8013-7946e40fe321"))
                ),
                (
                    Attribute::Description,
                    Value::Utf8("class test".to_string())
                ),
                (Attribute::May, Value::new_iutf8("a")),
                (Attribute::Must, Value::new_iutf8("b"))
            ),
            SchemaClass
        );

        sch_from_entry_ok!(
            entry_init!(
                (Attribute::Class, EntryClass::Object.to_value()),
                (Attribute::Class, EntryClass::ClassType.to_value()),
                (Attribute::ClassName, Value::new_iutf8("schema_class_test")),
                (
                    Attribute::Uuid,
                    Value::Uuid(uuid::uuid!("66c68b2f-d02c-4243-8013-7946e40fe321"))
                ),
                (
                    Attribute::Description,
                    Value::Utf8("class test".to_string())
                ),
                (Attribute::May, Value::new_iutf8("a")),
                (Attribute::Must, Value::new_iutf8("b")),
                (Attribute::SystemMay, Value::new_iutf8("c")),
                (Attribute::SystemMust, Value::new_iutf8("d"))
            ),
            SchemaClass
        );
    }

    #[test]
    fn test_schema_attribute_simple() {
        // Test schemaAttribute validation of types.

        // Test single value string
        let single_value_string = SchemaAttribute {
            name: Attribute::from("single_value"),
            uuid: Uuid::new_v4(),
            description: String::from(""),
            syntax: SyntaxType::Utf8StringInsensitive,
            ..Default::default()
        };

        let r1 = single_value_string
            .validate_ava(&Attribute::from("single_value"), &(vs_iutf8!["test"] as _));
        assert_eq!(r1, Ok(()));

        let rvs = vs_iutf8!["test1", "test2"] as _;
        let r2 = single_value_string.validate_ava(&Attribute::from("single_value"), &rvs);
        assert_eq!(
            r2,
            Err(SchemaError::InvalidAttributeSyntax(
                "single_value".to_string()
            ))
        );

        // test multivalue string, boolean

        let multi_value_string = SchemaAttribute {
            name: Attribute::from("mv_string"),
            uuid: Uuid::new_v4(),
            description: String::from(""),
            multivalue: true,
            syntax: SyntaxType::Utf8String,
            ..Default::default()
        };

        let rvs = vs_utf8!["test1".to_string(), "test2".to_string()] as _;
        let r5 = multi_value_string.validate_ava(&Attribute::from("mv_string"), &rvs);
        assert_eq!(r5, Ok(()));

        let multi_value_boolean = SchemaAttribute {
            name: Attribute::from("mv_bool"),
            uuid: Uuid::new_v4(),
            description: String::from(""),
            multivalue: true,
            syntax: SyntaxType::Boolean,
            ..Default::default()
        };

        // Since valueset now disallows such shenanigans at a type level, this can't occur
        /*
        let rvs = unsafe {
            valueset![
                Value::new_bool(true),
                Value::new_iutf8("test1"),
                Value::new_iutf8("test2")
            ]
        };
        let r3 = multi_value_boolean.validate_ava("mv_bool", &rvs);
        assert_eq!(
            r3,
            Err(SchemaError::InvalidAttributeSyntax("mv_bool".to_string()))
        );
        */

        let rvs = vs_bool![true, false];
        let r4 = multi_value_boolean.validate_ava(&Attribute::from("mv_bool"), &(rvs as _));
        assert_eq!(r4, Ok(()));

        // syntax_id and index_type values
        let single_value_syntax = SchemaAttribute {
            name: Attribute::from("sv_syntax"),
            uuid: Uuid::new_v4(),
            description: String::from(""),
            syntax: SyntaxType::SyntaxId,
            ..Default::default()
        };

        let rvs = vs_syntax![SyntaxType::try_from("UTF8STRING").unwrap()] as _;
        let r6 = single_value_syntax.validate_ava(&Attribute::from("sv_syntax"), &rvs);
        assert_eq!(r6, Ok(()));

        let rvs = vs_utf8!["thaeountaheu".to_string()] as _;
        let r7 = single_value_syntax.validate_ava(&Attribute::from("sv_syntax"), &rvs);
        assert_eq!(
            r7,
            Err(SchemaError::InvalidAttributeSyntax("sv_syntax".to_string()))
        );

        let single_value_index = SchemaAttribute {
            name: Attribute::from("sv_index"),
            uuid: Uuid::new_v4(),
            description: String::from(""),
            syntax: SyntaxType::IndexId,
            ..Default::default()
        };

        let rvs = vs_utf8!["thaeountaheu".to_string()] as _;
        let r9 = single_value_index.validate_ava(&Attribute::from("sv_index"), &rvs);
        assert_eq!(
            r9,
            Err(SchemaError::InvalidAttributeSyntax("sv_index".to_string()))
        );
    }

    #[test]
    fn test_schema_simple() {
        let schema = Schema::new().expect("failed to create schema");
        let schema_ro = schema.read();
        validate_schema!(schema_ro);
    }

    #[test]
    fn test_schema_entries() {
        sketching::test_init();
        // Given an entry, assert it's schema is valid
        // We do
        let schema_outer = Schema::new().expect("failed to create schema");
        let schema = schema_outer.read();

        let e_no_uuid = entry_init!().into_invalid_new();

        assert_eq!(
            e_no_uuid.validate(&schema),
            Err(SchemaError::MissingMustAttribute(vec![Attribute::Uuid]))
        );

        let e_no_class = entry_init!((
            Attribute::Uuid,
            Value::Uuid(uuid::uuid!("db237e8a-0079-4b8c-8a56-593b22aa44d1"))
        ))
        .into_invalid_new();

        assert_eq!(e_no_class.validate(&schema), Err(SchemaError::NoClassFound));

        let e_bad_class = entry_init!(
            (
                Attribute::Uuid,
                Value::Uuid(uuid::uuid!("db237e8a-0079-4b8c-8a56-593b22aa44d1"))
            ),
            (Attribute::Class, Value::new_iutf8("zzzzzz"))
        )
        .into_invalid_new();
        assert_eq!(
            e_bad_class.validate(&schema),
            Err(SchemaError::InvalidClass(vec!["zzzzzz".to_string()]))
        );

        let e_attr_invalid = entry_init!(
            (
                Attribute::Uuid,
                Value::Uuid(uuid::uuid!("db237e8a-0079-4b8c-8a56-593b22aa44d1"))
            ),
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::AttributeType.to_value())
        )
        .into_invalid_new();
        let res = e_attr_invalid.validate(&schema);
        matches!(res, Err(SchemaError::MissingMustAttribute(_)));

        let e_attr_invalid_may = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::AttributeType.to_value()),
            (Attribute::AttributeName, Value::new_iutf8("testattr")),
            (Attribute::Description, Value::Utf8("testattr".to_string())),
            (Attribute::MultiValue, Value::Bool(false)),
            (Attribute::Unique, Value::Bool(false)),
            (Attribute::Syntax, Value::Syntax(SyntaxType::Utf8String)),
            (
                Attribute::Uuid,
                Value::Uuid(uuid::uuid!("db237e8a-0079-4b8c-8a56-593b22aa44d1"))
            ),
            (Attribute::TestAttr, Value::Utf8("zzzz".to_string()))
        )
        .into_invalid_new();

        assert_eq!(
            e_attr_invalid_may.validate(&schema),
            Err(SchemaError::AttributeNotValidForClass(
                Attribute::TestAttr.to_string()
            ))
        );

        let e_attr_invalid_syn = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::AttributeType.to_value()),
            (Attribute::AttributeName, Value::new_iutf8("testattr")),
            (Attribute::Description, Value::Utf8("testattr".to_string())),
            (Attribute::MultiValue, Value::Utf8("false".to_string())),
            (Attribute::Unique, Value::Bool(false)),
            (Attribute::Syntax, Value::Syntax(SyntaxType::Utf8String)),
            (
                Attribute::Uuid,
                Value::Uuid(uuid::uuid!("db237e8a-0079-4b8c-8a56-593b22aa44d1"))
            )
        )
        .into_invalid_new();

        assert_eq!(
            e_attr_invalid_syn.validate(&schema),
            Err(SchemaError::InvalidAttributeSyntax(
                "multivalue".to_string()
            ))
        );

        // You may not have the phantom.
        let e_phantom = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::AttributeType.to_value()),
            (Attribute::AttributeName, Value::new_iutf8("testattr")),
            (Attribute::Description, Value::Utf8("testattr".to_string())),
            (Attribute::MultiValue, Value::Bool(false)),
            (Attribute::Unique, Value::Bool(false)),
            (Attribute::Syntax, Value::Syntax(SyntaxType::Utf8String)),
            (
                Attribute::Uuid,
                Value::Uuid(uuid::uuid!("db237e8a-0079-4b8c-8a56-593b22aa44d1"))
            ),
            (
                Attribute::PasswordImport,
                Value::Utf8("password".to_string())
            )
        )
        .into_invalid_new();
        assert!(e_phantom.validate(&schema).is_err());

        let e_ok = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::AttributeType.to_value()),
            (Attribute::AttributeName, Value::new_iutf8("testattr")),
            (Attribute::Description, Value::Utf8("testattr".to_string())),
            (Attribute::MultiValue, Value::Bool(true)),
            (Attribute::Unique, Value::Bool(false)),
            (Attribute::Syntax, Value::Syntax(SyntaxType::Utf8String)),
            (
                Attribute::Uuid,
                Value::Uuid(uuid::uuid!("db237e8a-0079-4b8c-8a56-593b22aa44d1"))
            )
        )
        .into_invalid_new();
        assert!(e_ok.validate(&schema).is_ok());
    }

    #[test]
    fn test_schema_extensible() {
        let schema_outer = Schema::new().expect("failed to create schema");
        let schema = schema_outer.read();
        // Just because you are extensible, doesn't mean you can be lazy
        let e_extensible_bad = entry_init!(
            (Attribute::Class, EntryClass::ExtensibleObject.to_value()),
            (
                Attribute::Uuid,
                Value::Uuid(uuid::uuid!("db237e8a-0079-4b8c-8a56-593b22aa44d1"))
            ),
            (Attribute::MultiValue, Value::Utf8("zzzz".to_string()))
        )
        .into_invalid_new();

        assert_eq!(
            e_extensible_bad.validate(&schema),
            Err(SchemaError::InvalidAttributeSyntax(
                "multivalue".to_string()
            ))
        );

        // Extensible doesn't mean you can have the phantoms
        let e_extensible_phantom = entry_init!(
            (Attribute::Class, EntryClass::ExtensibleObject.to_value()),
            (
                Attribute::Uuid,
                Value::Uuid(uuid::uuid!("db237e8a-0079-4b8c-8a56-593b22aa44d1"))
            ),
            (Attribute::PasswordImport, Value::Utf8("zzzz".to_string()))
        )
        .into_invalid_new();

        assert_eq!(
            e_extensible_phantom.validate(&schema),
            Err(SchemaError::PhantomAttribute(
                Attribute::PasswordImport.to_string()
            ))
        );

        let e_extensible = entry_init!(
            (Attribute::Class, EntryClass::ExtensibleObject.to_value()),
            (
                Attribute::Uuid,
                Value::Uuid(uuid::uuid!("db237e8a-0079-4b8c-8a56-593b22aa44d1"))
            ),
            (Attribute::MultiValue, Value::Bool(true))
        )
        .into_invalid_new();

        /* Is okay because extensible! */
        assert!(e_extensible.validate(&schema).is_ok());
    }

    #[test]
    fn test_schema_filter_validation() {
        let schema_outer = Schema::new().expect("failed to create schema");
        let schema = schema_outer.read();

        // test syntax of bool
        let f_bool = filter_all!(f_eq(Attribute::MultiValue, PartialValue::new_iutf8("zzzz")));
        assert_eq!(
            f_bool.validate(&schema),
            Err(SchemaError::InvalidAttributeSyntax(
                "multivalue".to_string()
            ))
        );
        // test insensitive values
        let f_insense = filter_all!(f_eq(Attribute::Class, EntryClass::AttributeType.into()));
        assert_eq!(
            f_insense.validate(&schema),
            Ok(filter_valid!(f_eq(
                Attribute::Class,
                EntryClass::AttributeType.into()
            )))
        );
        // Test the recursive structures validate
        let f_or_empty = filter_all!(f_or!([]));
        assert_eq!(f_or_empty.validate(&schema), Err(SchemaError::EmptyFilter));
        let f_or = filter_all!(f_or!([f_eq(
            Attribute::MultiValue,
            PartialValue::new_iutf8("zzzz")
        )]));
        assert_eq!(
            f_or.validate(&schema),
            Err(SchemaError::InvalidAttributeSyntax(
                "multivalue".to_string()
            ))
        );
        let f_or_mult = filter_all!(f_and!([
            f_eq(Attribute::Class, EntryClass::AttributeType.into()),
            f_eq(Attribute::MultiValue, PartialValue::new_iutf8("zzzzzzz")),
        ]));
        assert_eq!(
            f_or_mult.validate(&schema),
            Err(SchemaError::InvalidAttributeSyntax(
                "multivalue".to_string()
            ))
        );
        // Test mixed case attr name - this is a pass, due to normalisation
        let f_or_ok = filter_all!(f_andnot(f_and!([
            f_eq(Attribute::Class, EntryClass::AttributeType.into()),
            f_sub(Attribute::Class, EntryClass::ClassType.into()),
            f_pres(Attribute::Class)
        ])));
        assert_eq!(
            f_or_ok.validate(&schema),
            Ok(filter_valid!(f_andnot(f_and!([
                f_eq(Attribute::Class, EntryClass::AttributeType.into()),
                f_sub(Attribute::Class, EntryClass::ClassType.into()),
                f_pres(Attribute::Class)
            ]))))
        );
    }

    #[test]
    fn test_schema_class_phantom_reject() {
        // Check that entries can be normalised and validated sanely
        let schema_outer = Schema::new().expect("failed to create schema");
        let mut schema = schema_outer.write_blocking();

        assert!(schema.validate().is_empty());

        // Attempt to create a class with a phantom attribute, should be refused.
        let class = SchemaClass {
            name: AttrString::from("testobject"),
            uuid: Uuid::new_v4(),
            description: String::from("test object"),
            systemmay: vec![Attribute::Claim],
            ..Default::default()
        };

        assert!(schema.update_classes(vec![class]).is_ok());

        assert_eq!(schema.validate().len(), 1);
    }

    #[test]
    fn test_schema_class_exclusion_requires() {
        sketching::test_init();

        let schema_outer = Schema::new().expect("failed to create schema");
        let mut schema = schema_outer.write_blocking();

        assert!(schema.validate().is_empty());

        // We setup some classes that have requires and excludes and check that they
        // are enforced correctly.
        let class_account = SchemaClass {
            name: Attribute::Account.into(),
            uuid: Uuid::new_v4(),
            description: String::from("account object"),
            systemmust: vec![
                Attribute::Class,
                Attribute::Uuid,
                Attribute::LastModifiedCid,
                Attribute::CreatedAtCid,
            ],
            systemsupplements: vec![EntryClass::Service.into(), EntryClass::Person.into()],
            ..Default::default()
        };

        let class_person = SchemaClass {
            name: EntryClass::Person.into(),
            uuid: Uuid::new_v4(),
            description: String::from("person object"),
            systemmust: vec![
                Attribute::Class,
                Attribute::Uuid,
                Attribute::LastModifiedCid,
                Attribute::CreatedAtCid,
            ],
            ..Default::default()
        };

        let class_service = SchemaClass {
            name: EntryClass::Service.into(),
            uuid: Uuid::new_v4(),
            description: String::from("service object"),
            systemmust: vec![
                Attribute::Class,
                Attribute::Uuid,
                Attribute::LastModifiedCid,
                Attribute::CreatedAtCid,
            ],
            excludes: vec![EntryClass::Person.into()],
            ..Default::default()
        };

        assert!(schema
            .update_classes(vec![class_account, class_person, class_service])
            .is_ok());

        // Missing person or service account.
        let e_account = entry_init!(
            (Attribute::Class, EntryClass::Account.to_value()),
            (Attribute::Uuid, Value::Uuid(Uuid::new_v4()))
        )
        .into_invalid_new();

        assert_eq!(
            e_account.validate(&schema),
            Err(SchemaError::SupplementsNotSatisfied(vec![
                EntryClass::Service.into(),
                EntryClass::Person.into(),
            ]))
        );

        // Service account missing account
        /*
        let e_service = unsafe { entry_init!(
            (Attribute::Class, EntryClass::Service.to_value()),
            (Attribute::Uuid, Value::new_uuid(Uuid::new_v4()))
        ).into_invalid_new() };

        assert_eq!(
            e_service.validate(&schema),
            Err(SchemaError::RequiresNotSatisfied(vec![Attribute::Account.to_string()]))
        );
        */

        // Service can't have person
        let e_service_person = entry_init!(
            (Attribute::Class, EntryClass::Service.to_value()),
            (Attribute::Class, EntryClass::Account.to_value()),
            (Attribute::Class, EntryClass::Person.to_value()),
            (Attribute::Uuid, Value::Uuid(Uuid::new_v4()))
        )
        .into_invalid_new();

        assert_eq!(
            e_service_person.validate(&schema),
            Err(SchemaError::ExcludesNotSatisfied(vec![
                EntryClass::Person.to_string()
            ]))
        );

        // These are valid configurations.
        let e_service_valid = entry_init!(
            (Attribute::Class, EntryClass::Service.to_value()),
            (Attribute::Class, EntryClass::Account.to_value()),
            (Attribute::Uuid, Value::Uuid(Uuid::new_v4()))
        )
        .into_invalid_new();

        assert!(e_service_valid.validate(&schema).is_ok());

        let e_person_valid = entry_init!(
            (Attribute::Class, EntryClass::Person.to_value()),
            (Attribute::Class, EntryClass::Account.to_value()),
            (Attribute::Uuid, Value::Uuid(Uuid::new_v4()))
        )
        .into_invalid_new();

        assert!(e_person_valid.validate(&schema).is_ok());

        let e_person_valid = entry_init!(
            (Attribute::Class, EntryClass::Person.to_value()),
            (Attribute::Uuid, Value::Uuid(Uuid::new_v4()))
        )
        .into_invalid_new();

        assert!(e_person_valid.validate(&schema).is_ok());
    }
}
