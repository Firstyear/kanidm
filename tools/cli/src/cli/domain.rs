use crate::common::OpType;
use crate::{handle_client_error, DomainOpt};

impl DomainOpt {
    pub fn debug(&self) -> bool {
        match self {
            DomainOpt::SetDisplayName(copt) => copt.copt.debug,
            DomainOpt::SetLdapBasedn { copt, .. }
            | DomainOpt::SetLdapAllowUnixPasswordBind { copt, .. } => copt.debug,
            DomainOpt::Show(copt) | DomainOpt::ResetTokenKey(copt) => copt.debug,
        }
    }

    pub async fn exec(&self) {
        match self {
            DomainOpt::SetDisplayName(opt) => {
                eprintln!(
                    "Attempting to set the domain's display name to: {:?}",
                    opt.new_display_name
                );
                let client = opt.copt.to_client(OpType::Write).await;
                match client
                    .idm_domain_set_display_name(&opt.new_display_name)
                    .await
                {
                    Ok(_) => println!("Success"),
                    Err(e) => handle_client_error(e, &opt.copt.output_mode),
                }
            }
            DomainOpt::SetLdapBasedn { copt, new_basedn } => {
                eprintln!(
                    "Attempting to set the domain's ldap basedn to: {:?}",
                    new_basedn
                );
                let client = copt.to_client(OpType::Write).await;
                match client.idm_domain_set_ldap_basedn(new_basedn).await {
                    Ok(_) => println!("Success"),
                    Err(e) => handle_client_error(e, &copt.output_mode),
                }
            }
            DomainOpt::SetLdapAllowUnixPasswordBind { copt, enable } => {
                let client = copt.to_client(OpType::Write).await;
                match client.idm_set_ldap_allow_unix_password_bind(*enable).await {
                    Ok(_) => println!("Success"),
                    Err(e) => handle_client_error(e, &copt.output_mode),
                }
            }
            DomainOpt::Show(copt) => {
                let client = copt.to_client(OpType::Read).await;
                match client.idm_domain_get().await {
                    Ok(e) => println!("{}", e),
                    Err(e) => handle_client_error(e, &copt.output_mode),
                }
            }
            DomainOpt::ResetTokenKey(copt) => {
                let client = copt.to_client(OpType::Write).await;
                match client.idm_domain_reset_token_key().await {
                    Ok(_) => println!("Success"),
                    Err(e) => handle_client_error(e, &copt.output_mode),
                }
            }
        }
    }
}
