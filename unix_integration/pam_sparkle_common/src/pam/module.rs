//! Functions for use in pam modules.

use crate::core::PamHandler;
use crate::pam::constants::{
    PamFlag, PamItemType, PamResultCode, PAM_PROMPT_ECHO_OFF, PAM_TEXT_INFO,
};
use crate::pam::conv::PamConv;
use crate::pam::items::{PamAuthTok, PamRHost, PamService, PamTty};
use libc::{c_char, c_void};
use sparkle_unix_common::unix_proto::DeviceAuthorizationResponse;
use sparkle_unix_common::unix_proto::PamServiceInfo;
use std::ffi::{CStr, CString};
use std::{mem, ptr};

/// Opaque type, used as a pointer when making pam API calls.
///
/// A module is invoked via an external function such as `pam_sm_authenticate`.
/// Such a call provides a pam handle pointer.  The same pointer should be given
/// as an argument when making API calls.
#[allow(missing_copy_implementations)]
pub enum PamHandle {}

#[allow(missing_copy_implementations)]
enum PamItemT {}

#[allow(missing_copy_implementations)]
pub enum PamDataT {}

#[link(name = "pam")]
extern "C" {
    /*
    fn pam_get_data(
        pamh: *const PamHandle,
        module_data_name: *const c_char,
        data: &mut *const PamDataT,
    ) -> PamResultCode;

    fn pam_set_data(
        pamh: *const PamHandle,
        module_data_name: *const c_char,
        data: *mut PamDataT,
        cleanup: unsafe extern "C" fn(
            pamh: *const PamHandle,
            data: *mut PamDataT,
            error_status: PamResultCode,
        ),
    ) -> PamResultCode;
    */

    fn pam_get_item(
        pamh: *const PamHandle,
        item_type: PamItemType,
        item: &mut *const PamItemT,
    ) -> PamResultCode;

    /*
    fn pam_set_item(pamh: *mut PamHandle, item_type: PamItemType, item: &PamItemT)
        -> PamResultCode;
    */

    fn pam_get_user(
        pamh: *const PamHandle,
        user: &mut *const c_char,
        prompt: *const c_char,
    ) -> PamResultCode;

    fn pam_getenvlist(pamh: *const PamHandle) -> *mut *mut c_char;

    #[allow(dead_code)]
    fn pam_putenv(pamh: *const PamHandle, value: *const c_char) -> PamResultCode;
}

/// # Safety
///
/// We're doing what we can for this one, but it's FFI.
pub unsafe extern "C" fn cleanup<T>(_: *const PamHandle, c_data: *mut PamDataT, _: PamResultCode) {
    let c_data = Box::from_raw(c_data);
    let data: Box<T> = mem::transmute(c_data);
    mem::drop(data);
}

pub type PamResult<T> = Result<T, PamResultCode>;

/// # Safety
///
/// Type-level mapping for safely retrieving values with `get_item`.
///
/// See `pam_get_item` in
/// <http://www.linux-pam.org/Linux-PAM-html/mwg-expected-by-module-item.html>
pub trait PamItem {
    /// Maps a Rust type to a pam constant.
    ///
    /// For example, the type PamConv maps to the constant PAM_CONV.  The pam
    /// API contract specifies that when the API function `pam_get_item` is
    /// called with the constant PAM_CONV, it will return a value of type
    /// `PamConv`.
    fn item_type() -> PamItemType;
}

impl PamHandle {
    /*
    /// # Safety
    ///
    /// Gets some value, identified by `key`, that has been set by the module
    /// previously.
    ///
    /// See `pam_get_data` in
    /// <http://www.linux-pam.org/Linux-PAM-html/mwg-expected-by-module-item.html>
    unsafe fn get_data<'a, T>(&'a self, key: &str) -> PamResult<&'a T> {
        let c_key = CString::new(key).unwrap();
        let mut ptr: *const PamDataT = ptr::null();
        let res = pam_get_data(self, c_key.as_ptr(), &mut ptr);
        if PamResultCode::PAM_SUCCESS == res && !ptr.is_null() {
            let typed_ptr: *const T = ptr as *const T;
            let data: &T = &*typed_ptr;
            Ok(data)
        } else {
            Err(res)
        }
    }

    /// Stores a value that can be retrieved later with `get_data`.  The value lives
    /// as long as the current pam cycle.
    ///
    /// See `pam_set_data` in
    /// <http://www.linux-pam.org/Linux-PAM-html/mwg-expected-by-module-item.html>
    fn set_data<T>(&self, key: &str, data: Box<T>) -> PamResult<()> {
        let c_key = CString::new(key).unwrap();
        let res = unsafe {
            let c_data: Box<PamDataT> = mem::transmute(data);
            let c_data = Box::into_raw(c_data);
            pam_set_data(self, c_key.as_ptr(), c_data, cleanup::<T>)
        };
        if PamResultCode::PAM_SUCCESS == res {
            Ok(())
        } else {
            Err(res)
        }
    }
    */

    /// Retrieves a value that has been set, possibly by the pam client.  This is
    /// particularly useful for getting a `PamConv` reference.
    ///
    /// See `pam_get_item` in
    /// <http://www.linux-pam.org/Linux-PAM-html/mwg-expected-by-module-item.html>
    fn get_item<'a, T: PamItem>(&self) -> PamResult<&'a T> {
        let mut ptr: *const PamItemT = ptr::null();
        let (res, item) = unsafe {
            let r = pam_get_item(self, T::item_type(), &mut ptr);
            let typed_ptr: *const T = ptr as *const T;
            let t: &T = &*typed_ptr;
            (r, t)
        };
        if PamResultCode::PAM_SUCCESS == res {
            Ok(item)
        } else {
            Err(res)
        }
    }

    fn get_item_string<T: PamItem>(&self) -> PamResult<Option<String>> {
        let mut ptr: *const PamItemT = ptr::null();
        let (res, item) = unsafe {
            let r = pam_get_item(self, T::item_type(), &mut ptr);
            let t = if PamResultCode::PAM_SUCCESS == r && !ptr.is_null() {
                let typed_ptr: *const c_char = ptr as *const c_char;
                Some(CStr::from_ptr(typed_ptr).to_string_lossy().into_owned())
            } else {
                None
            };
            (r, t)
        };
        if PamResultCode::PAM_SUCCESS == res {
            Ok(item)
        } else {
            Err(res)
        }
    }

    /*
    /// Sets a value in the pam context. The value can be retrieved using
    /// `get_item`.
    ///
    /// Note that all items are strings, except `PAM_CONV` and `PAM_FAIL_DELAY`.
    ///
    /// See `pam_set_item` in
    /// <http://www.linux-pam.org/Linux-PAM-html/mwg-expected-by-module-item.html>
    fn set_item_str<T: PamItem>(&mut self, item: &str) -> PamResult<()> {
        let c_item = CString::new(item).unwrap();

        let res = unsafe {
            pam_set_item(
                self,
                T::item_type(),
                // unwrapping is okay here, as c_item will not be a NULL
                // pointer
                (c_item.as_ptr() as *const PamItemT).as_ref().unwrap(),
            )
        };
        if PamResultCode::PAM_SUCCESS == res {
            Ok(())
        } else {
            Err(res)
        }
    }
    */

    /// Retrieves the name of the user who is authenticating or logging in.
    ///
    /// This is really a specialization of `get_item`.
    ///
    /// See `pam_get_user` in
    /// <http://www.linux-pam.org/Linux-PAM-html/mwg-expected-by-module-item.html>
    fn get_user(&self, prompt: Option<&str>) -> PamResult<String> {
        let mut ptr: *const c_char = ptr::null_mut();
        let res = match prompt {
            Some(p) => {
                let c_prompt = CString::new(p).map_err(|_| PamResultCode::PAM_CONV_ERR)?;
                unsafe { pam_get_user(self, &mut ptr, c_prompt.as_ptr()) }
            }
            None => unsafe { pam_get_user(self, &mut ptr, ptr::null()) },
        };

        if PamResultCode::PAM_SUCCESS == res {
            if ptr.is_null() {
                Err(PamResultCode::PAM_AUTHINFO_UNAVAIL)
            } else {
                let bytes = unsafe { CStr::from_ptr(ptr).to_bytes() };
                String::from_utf8(bytes.to_vec()).map_err(|_| PamResultCode::PAM_CONV_ERR)
            }
        } else {
            Err(res)
        }
    }

    fn get_authtok(&self) -> PamResult<Option<String>> {
        self.get_item_string::<PamAuthTok>()
    }

    fn get_tty(&self) -> PamResult<Option<String>> {
        self.get_item_string::<PamTty>()
    }

    fn get_rhost(&self) -> PamResult<Option<String>> {
        self.get_item_string::<PamRHost>()
    }

    fn get_service(&self) -> PamResult<Option<String>> {
        self.get_item_string::<PamService>()
    }

    fn get_pam_info(&self) -> PamResult<PamServiceInfo> {
        let maybe_tty = self.get_tty()?;
        let maybe_rhost = self.get_rhost()?;
        let maybe_service = self.get_service()?;

        tracing::debug!(?maybe_tty, ?maybe_rhost, ?maybe_service);

        match (maybe_tty, maybe_rhost, maybe_service) {
            (tty, rhost, Some(service)) => Ok(PamServiceInfo {
                service,
                tty,
                rhost,
            }),
            _ => Err(PamResultCode::PAM_CONV_ERR),
        }
    }

    fn get_conv(&self) -> PamResult<&PamConv> {
        self.get_item::<PamConv>()
    }

    fn get_envlist(&self) -> PamResult<Vec<String>> {
        let array_ptr = unsafe { pam_getenvlist(self) };

        if array_ptr.is_null() {
            return Err(PamResultCode::PAM_CONV_ERR);
        }

        let mut work_array = Vec::new();

        unsafe {
            let mut offset = 0;
            let mut str_ptr = *array_ptr;

            while !str_ptr.is_null() {
                let c_str = CStr::from_ptr(str_ptr);

                let rust_str = c_str.to_string_lossy();
                work_array.push(rust_str.to_string());

                libc::free(str_ptr as *mut c_void);

                offset += 1;
                str_ptr = *(array_ptr.add(offset));
            }

            libc::free(array_ptr as *mut c_void);
        }

        Ok(work_array)
    }

    #[allow(dead_code)]
    fn putenv(&self, value: &str) -> PamResult<()> {
        let c_value = CString::new(value).map_err(|_| PamResultCode::PAM_CONV_ERR)?;

        let res = unsafe { pam_putenv(self, c_value.as_ptr()) };

        if PamResultCode::PAM_SUCCESS == res {
            Ok(())
        } else {
            Err(res)
        }
    }
}

impl PamHandler for PamHandle {
    fn account_id(&self) -> PamResult<String> {
        self.get_user(None)
    }

    fn service_info(&self) -> PamResult<PamServiceInfo> {
        self.get_pam_info()
    }

    fn envlist(&self) -> PamResult<Vec<String>> {
        self.get_envlist()
    }

    fn set_env(&self, value: &str) -> PamResult<()> {
        self.putenv(value)
    }

    fn authtok(&self) -> PamResult<Option<String>> {
        self.get_authtok()
    }

    fn message(&self, msg: &str) -> PamResult<()> {
        let conv = self.get_conv()?;
        conv.send(PAM_TEXT_INFO, msg).map(|_| ())
    }

    fn prompt_for_password(&self) -> PamResult<Option<String>> {
        let conv = self.get_conv()?;
        conv.send(PAM_PROMPT_ECHO_OFF, "Password: ")
    }

    fn prompt_for_mfacode(&self) -> PamResult<Option<String>> {
        let conv = self.get_conv()?;
        conv.send(PAM_PROMPT_ECHO_OFF, "Code: ")
    }

    fn prompt_for_pin(&self, msg: Option<&str>) -> PamResult<Option<String>> {
        let conv = self.get_conv()?;
        let msg = msg.unwrap_or("PIN: ");
        conv.send(PAM_PROMPT_ECHO_OFF, msg)
    }

    fn message_device_grant(&self, data: &DeviceAuthorizationResponse) -> PamResult<()> {
        let conv = self.get_conv()?;
        let msg = match &data.message {
            Some(msg) => msg.clone(),
            None => format!(
                "Using a browser on another device, visit:\n{}\nAnd enter the code:\n{}",
                data.verification_uri, data.user_code
            ),
        };
        conv.send(PAM_TEXT_INFO, &msg).map(|_| ())
    }
}

/// Provides functions that are invoked by the entrypoints generated by the
/// [`pam_hooks!` macro](../macro.pam_hooks.html).
///
/// All of hooks are ignored by PAM dispatch by default given the default return value of `PAM_IGNORE`.
/// Override any functions that you want to handle with your module. See `man pam(3)`.
#[allow(unused_variables)]
pub trait PamHooks {
    /// This function performs the task of establishing whether the user is permitted to gain access at
    /// this time. It should be understood that the user has previously been validated by an
    /// authentication module. This function checks for other things. Such things might be: the time of
    /// day or the date, the terminal line, remote hostname, etc. This function may also determine
    /// things like the expiration on passwords, and respond that the user change it before continuing.
    fn acct_mgmt(pamh: &PamHandle, args: Vec<&CStr>, flags: PamFlag) -> PamResultCode {
        PamResultCode::PAM_IGNORE
    }

    /// This function performs the task of authenticating the user.
    fn sm_authenticate(pamh: &PamHandle, args: Vec<&CStr>, flags: PamFlag) -> PamResultCode {
        PamResultCode::PAM_IGNORE
    }

    /// This function is used to (re-)set the authentication token of the user.
    ///
    /// The PAM library calls this function twice in succession. The first time with
    /// PAM_PRELIM_CHECK and then, if the module does not return PAM_TRY_AGAIN, subsequently with
    /// PAM_UPDATE_AUTHTOK. It is only on the second call that the authorization token is
    /// (possibly) changed.
    fn sm_chauthtok(pamh: &PamHandle, args: Vec<&CStr>, flags: PamFlag) -> PamResultCode {
        PamResultCode::PAM_IGNORE
    }

    /// This function is called to terminate a session.
    fn sm_close_session(pamh: &PamHandle, args: Vec<&CStr>, flags: PamFlag) -> PamResultCode {
        PamResultCode::PAM_IGNORE
    }

    /// This function is called to commence a session.
    fn sm_open_session(pamh: &PamHandle, args: Vec<&CStr>, flags: PamFlag) -> PamResultCode {
        PamResultCode::PAM_IGNORE
    }

    /// This function performs the task of altering the credentials of the user with respect to the
    /// corresponding authorization scheme. Generally, an authentication module may have access to more
    /// information about a user than their authentication token. This function is used to make such
    /// information available to the application. It should only be called after the user has been
    /// authenticated but before a session has been established.
    fn sm_setcred(pamh: &PamHandle, args: Vec<&CStr>, flags: PamFlag) -> PamResultCode {
        PamResultCode::PAM_IGNORE
    }
}
