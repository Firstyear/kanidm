use libc::passwd as c_passwd;
use libc::{gid_t, uid_t};
use std::ffi::{CStr, OsStr, OsString};
use std::os::unix::ffi::OsStrExt;
use std::{mem, ptr};

pub fn get_current_uid() -> uid_t {
    unsafe { libc::getuid() }
}

pub fn get_effective_uid() -> uid_t {
    unsafe { libc::geteuid() }
}

pub fn get_current_gid() -> gid_t {
    unsafe { libc::getgid() }
}

pub fn get_effective_gid() -> gid_t {
    unsafe { libc::getegid() }
}

pub fn get_user_name_by_uid(uid: uid_t) -> Option<OsString> {
    let mut passwd = unsafe { mem::zeroed::<c_passwd>() };
    let mut buf = vec![0; 2048];
    let mut result = ptr::null_mut::<c_passwd>();

    #[cfg(feature = "logging")]
    trace!("Running getpwuid_r for user #{}", uid);

    loop {
        let r =
            unsafe { libc::getpwuid_r(uid, &mut passwd, buf.as_mut_ptr(), buf.len(), &mut result) };

        if r != libc::ERANGE {
            break;
        }

        let newsize = buf.len().checked_mul(2)?;
        buf.resize(newsize, 0);
    }

    if result.is_null() {
        // There is no such user, or an error has occurred.
        // errno gets set if there’s an error.
        return None;
    }

    if result != &mut passwd {
        // The result of getpwuid_r should be its input passwd.
        return None;
    }

    let name = unsafe {
        OsStr::from_bytes(CStr::from_ptr(result.read().pw_name).to_bytes()).to_os_string()
    };

    Some(name)
}
