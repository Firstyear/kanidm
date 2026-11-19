use crate::{idm::server::IdmServerProxyReadTransaction, prelude::*};
use kanidm_proto::internal::AppLink;

impl IdmServerProxyReadTransaction<'_> {
    pub fn list_applinks(&mut self, ident: &Identity) -> Result<Vec<AppLink>, OperationError> {
        // From the member-of of the ident.
        let Some(ident_mo) = ident.get_memberof() else {
            debug!("Ident has no memberof, no applinks are present");
            return Ok(Vec::with_capacity(0));
        };

        // Formerly we did an internal search here, but we no longer need to since we have
        // the access control module setup so that we can search for and see rs that we
        // have access to.
        //
        // We do this weird looking f_executed/f_intent shenanigans to actually search
        // on what we have access to, but we apply access as though we did a search on
        // class=oauth2_resource_server instead, and we still apply access here.
        let f_executed = filter!(f_or(
            ident_mo
                .iter()
                .copied()
                .map(|uuid| { f_eq(Attribute::OAuth2RsScopeMap, PartialValue::Refer(uuid)) })
                .collect()
        ));
        let f_intent = filter!(f_eq(
            Attribute::Class,
            EntryClass::OAuth2ResourceServer.into()
        ));

        // _ext reduces the entries based on access.
        let oauth2_related = self
            .qs_read
            .impersonate_search_ext(f_executed, f_intent, ident)?;
        trace!(?oauth2_related);

        // Aggregate results to a Vec of AppLink
        let mut apps = oauth2_related
            .iter()
            .filter_map(|entry| {
                let display_name = entry
                    .get_ava_single_utf8(Attribute::DisplayName)
                    .map(str::to_string)?;

                let redirect_url = entry
                    .get_ava_single_url(Attribute::OAuth2RsOriginLanding)
                    .cloned()?;

                let name = entry
                    .get_ava_single_iname(Attribute::Name)
                    .map(str::to_string)?;

                let has_image = entry.get_ava_single_image(Attribute::Image).is_some();

                Some(AppLink::Oauth2 {
                    name,
                    display_name,
                    redirect_url,
                    has_image,
                })
            })
            .collect::<Vec<_>>();

        // Sort by display name
        apps.sort_unstable_by_key(|a| match a {
            AppLink::Oauth2 { display_name, .. } => display_name.clone(),
        });

        debug!("returned {} related apps", apps.len());
        trace!(?apps);

        Ok(apps)
    }
}

#[cfg(test)]
mod tests {
    use crate::prelude::*;
    use kanidm_proto::internal::AppLink;

    #[idm_test]
    async fn test_idm_applinks_list(idms: &IdmServer, _idms_delayed: &mut IdmServerDelayed) {
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = idms.proxy_write(ct).await.unwrap();

        // Create an RS, the user and a group..
        let usr_uuid = Uuid::new_v4();
        let grp_uuid = Uuid::new_v4();

        let e_rs: Entry<EntryInit, EntryNew> = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Account.to_value()),
            (
                Attribute::Class,
                EntryClass::OAuth2ResourceServer.to_value()
            ),
            (
                Attribute::Class,
                EntryClass::OAuth2ResourceServerBasic.to_value()
            ),
            (Attribute::Name, Value::new_iname("test_resource_server")),
            (
                Attribute::DisplayName,
                Value::new_utf8s("test_resource_server")
            ),
            (
                Attribute::OAuth2RsOrigin,
                Value::new_urln_s("https://demo.example.com").unwrap()
            ),
            (
                Attribute::OAuth2RsOriginLanding,
                Value::new_url_s("https://demo.example.com/landing").unwrap()
            ),
            // System admins
            (
                Attribute::OAuth2RsScopeMap,
                Value::new_oauthscopemap(
                    grp_uuid,
                    btreeset![kanidm_proto::constants::OAUTH2_SCOPE_READ.to_string()]
                )
                .expect("invalid oauthscope")
            )
        );

        let e_usr = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Account.to_value()),
            (Attribute::Class, EntryClass::Person.to_value()),
            (Attribute::Name, Value::new_iname("testaccount")),
            (Attribute::Uuid, Value::Uuid(usr_uuid)),
            (Attribute::Description, Value::new_utf8s("testaccount")),
            (Attribute::DisplayName, Value::new_utf8s("Test Account"))
        );

        let e_grp = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Group.to_value()),
            (Attribute::Uuid, Value::Uuid(grp_uuid)),
            (Attribute::Name, Value::new_iname("test_oauth2_group"))
        );

        let ce = CreateEvent::new_internal(vec![e_rs, e_grp, e_usr]);
        assert!(idms_prox_write.qs_write.create(&ce).is_ok());
        assert!(idms_prox_write.commit().is_ok());

        // Now do an applink query, they will not be there.
        let mut idms_prox_read = idms.proxy_read().await.unwrap();

        let ident = idms_prox_read
            .qs_read
            .internal_search_uuid(usr_uuid)
            .map(Identity::from_impersonate_entry_readonly)
            .expect("Failed to impersonate identity");

        let apps = idms_prox_read
            .list_applinks(&ident)
            .expect("Failed to access related apps");

        assert!(apps.is_empty());
        drop(idms_prox_read);

        // Add them to the group.
        let mut idms_prox_write = idms.proxy_write(ct).await.unwrap();
        let me_inv_m = ModifyEvent::new_internal_invalid(
            filter!(f_eq(Attribute::Uuid, PartialValue::Refer(grp_uuid))),
            ModifyList::new_append(Attribute::Member, Value::ReferN(usr_uuid)),
        );
        assert!(idms_prox_write.qs_write.modify(&me_inv_m).is_ok());
        assert!(idms_prox_write.commit().is_ok());

        let mut idms_prox_read = idms.proxy_read().await.unwrap();

        let ident = idms_prox_read
            .qs_read
            .internal_search_uuid(usr_uuid)
            .map(Identity::from_impersonate_entry_readonly)
            .expect("Failed to impersonate identity");

        let apps = idms_prox_read
            .list_applinks(&ident)
            .expect("Failed to access related apps");

        let app = apps.first().expect("No apps return!");

        assert!(match app {
            AppLink::Oauth2 {
                name,
                display_name,
                redirect_url,
                has_image,
            } => {
                name == "test_resource_server"
                    && display_name == "test_resource_server"
                    && redirect_url
                        == &Url::parse("https://demo.example.com/landing")
                            .expect("Failed to parse URL")
                    && !has_image
            } // _ => false,
        })
    }
}
