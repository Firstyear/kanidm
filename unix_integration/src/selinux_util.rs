use kanidm_utils_users::get_user_name_by_uid;
use std::ffi::CString;
use std::path::Path;
use std::process::Command;

use selinux::{
    current_mode, kernel_support, label::back_end::File, label::Labeler, KernelSupport,
    SELinuxMode, SecurityContext,
};

pub fn supported() -> bool {
    // check if the running kernel has SELinux support
    if matches!(kernel_support(), KernelSupport::Unsupported) {
        return false;
    }
    // check if SELinux is actually running
    match current_mode() {
        SELinuxMode::Permissive | SELinuxMode::Enforcing => true,
        _ => false,
    }
}

fn do_setfscreatecon_for_path(path_raw: &String, labeler: &Labeler<File>) -> Result<(), String> {
    match labeler.look_up(&CString::new(path_raw.to_owned()).unwrap(), 0) {
        Ok(context) => {
            if context.set_for_new_file_system_objects(true).is_err() {
                return Err("Failed setting creation context home directory path".to_string());
            }
            Ok(())
        }
        Err(_) => {
            return Err("Failed looking up default context for home directory path".to_string());
        }
    }
}

fn get_labeler() -> Result<Labeler<File>, String> {
    if let Ok(v) = Labeler::new(&[], true) {
        Ok(v)
    } else {
        Err("Failed getting handle for SELinux labeling".to_string())
    }
}

pub enum SelinuxLabeler {
    None,
    Enabled {
        labeler: Labeler<File>,
        sel_lookup_path_raw: String,
    },
}

impl SelinuxLabeler {
    pub fn new(gid: u32, home_prefix: &str) -> Result<Self, String> {
        let labeler = get_labeler()?;

        // Construct a path for SELinux context lookups.
        // We do this because the policy only associates a home directory to its owning
        // user by the name of the directory. Since the real user's home directory is (by
        // default) their uuid or spn, its context will always be the policy default
        // (usually user_u or unconfined_u). This lookup path is used to ask the policy
        // what the context SHOULD be, and we will create policy equivalence rules below
        // so that relabels in the future do not break it.
        #[cfg(all(target_family = "unix", feature = "selinux"))]
        // Yes, gid, because we use the GID number for both the user's UID and primary GID
        let sel_lookup_path_raw = match get_user_name_by_uid(gid) {
            Some(v) => format!("{}{}", home_prefix, v.to_str().unwrap()),
            None => {
                return Err("Failed looking up username by uid for SELinux relabeling".to_string());
            }
        };

        Ok(SelinuxLabeler::Enabled {
            labeler,
            sel_lookup_path_raw,
        })
    }

    pub fn new_noop() -> Self {
        SelinuxLabeler::None
    }

    pub fn do_setfscreatecon_for_path(&self) -> Result<(), String> {
        match &self {
            SelinuxLabeler::None => Ok(()),
            SelinuxLabeler::Enabled {
                labeler,
                sel_lookup_path_raw,
            } => do_setfscreatecon_for_path(sel_lookup_path_raw, labeler),
        }
    }

    pub fn label_path<P: AsRef<Path>>(&self, path: P) -> Result<(), String> {
        match &self {
            SelinuxLabeler::None => Ok(()),
            SelinuxLabeler::Enabled {
                labeler,
                sel_lookup_path_raw,
            } => {
                let sel_lookup_path = Path::new(&sel_lookup_path_raw).join(path.as_ref());
                do_setfscreatecon_for_path(&sel_lookup_path.to_str().unwrap().to_string(), &labeler)
            }
        }
    }

    pub fn setup_equivalence_rule(&self, path: &str) -> Result<(), String> {
        match &self {
            SelinuxLabeler::None => Ok(()),
            SelinuxLabeler::Enabled {
                labeler: _,
                sel_lookup_path_raw,
            } => Command::new("semanage")
                .args(["fcontext", "-ae", sel_lookup_path_raw, &path])
                .spawn()
                .map(|_| ())
                .map_err(|_| "Failed creating SELinux policy equivalence rule".to_string()),
        }
    }

    pub fn set_default_context_for_fs_objects(&self) -> Result<(), String> {
        match &self {
            SelinuxLabeler::None => Ok(()),
            SelinuxLabeler::Enabled { .. } => {
                SecurityContext::set_default_context_for_new_file_system_objects()
                    .map(|_| ())
                    .map_err(|_| "Failed resetting SELinux file creation contexts".to_string())
            }
        }
    }
}
