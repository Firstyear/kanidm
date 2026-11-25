//! This module contains the server's async tasks that are called from the various frontend
//! components to conduct operations. These are separated based on protocol versions and
//! if they are read or write transactions internally.

use kanidmd_lib::idm::{ldap::LdapServer, server::IdmServer};
use std::sync::Arc;

pub struct QueryServerReadV1 {
    pub(crate) idms: Arc<IdmServer>,
    ldap: Arc<LdapServer>,
}

impl QueryServerReadV1 {
    pub fn new(idms: Arc<IdmServer>, ldap: Arc<LdapServer>) -> Self {
        debug!("Starting query server read worker ...");
        QueryServerReadV1 { idms, ldap }
    }

    pub fn start_static(idms: Arc<IdmServer>, ldap: Arc<LdapServer>) -> &'static Self {
        let x = Box::new(QueryServerReadV1::new(idms, ldap));

        let x_ref = Box::leak(x);
        &(*x_ref)
    }
}

pub struct QueryServerWriteV1 {
    pub(crate) idms: Arc<IdmServer>,
}

impl QueryServerWriteV1 {
    pub fn new(idms: Arc<IdmServer>) -> Self {
        debug!("Starting a query server write worker ...");
        QueryServerWriteV1 { idms }
    }

    pub fn start_static(idms: Arc<IdmServer>) -> &'static QueryServerWriteV1 {
        let x = Box::new(QueryServerWriteV1::new(idms));

        let x_ptr = Box::leak(x);
        &(*x_ptr)
    }
}

pub mod internal;
pub mod models;
pub mod read_action;
pub mod v1_read;
pub mod v1_scim;
pub mod v1_write;
pub mod write_action;
