use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_void};

use crate::api::NativeResult;
use crate::runtime;

type JNIEnv = *mut *const c_void;
type JObject = *mut c_void;
type JString = *mut c_void;

const NEW_STRING_UTF: usize = 167;
const GET_STRING_UTF_CHARS: usize = 169;
const RELEASE_STRING_UTF_CHARS: usize = 170;

#[no_mangle]
pub extern "system" fn Java_vpn_myboroda_omega_OmegaNative_nativeBridgeVersion(
    _env: JNIEnv,
    _receiver: JObject,
) -> i32 {
    crate::omega_android_bridge_version() as i32
}

#[no_mangle]
pub extern "system" fn Java_vpn_myboroda_omega_OmegaNative_nativeStartHandshake(
    env: JNIEnv,
    _receiver: JObject,
    server: JString,
    device_id: JString,
    device_token: JString,
    device_name: JString,
    transport: JString,
    protected_udp_fd: i32,
) -> JString {
    let response = unsafe {
        runtime::start_handshake(
            &java_string(env, server),
            &java_string(env, device_id),
            &java_string(env, device_token),
            &java_string(env, device_name),
            &java_string(env, transport),
            protected_udp_fd,
        )
    };
    unsafe { new_java_string(env, &response.to_json()) }
}

#[no_mangle]
pub extern "system" fn Java_vpn_myboroda_omega_OmegaNative_nativeContinueWithTunFd(
    env: JNIEnv,
    _receiver: JObject,
    handle: i64,
    tun_fd: i32,
) -> JString {
    let result = if handle <= 0 {
        NativeResult::err("invalid native session handle")
    } else {
        runtime::continue_with_tun_fd(handle as u64, tun_fd)
    };
    unsafe { new_java_string(env, &result.to_json()) }
}

#[no_mangle]
pub extern "system" fn Java_vpn_myboroda_omega_OmegaNative_nativeStop(
    env: JNIEnv,
    _receiver: JObject,
    handle: i64,
) -> JString {
    let result = if handle <= 0 {
        NativeResult::ok("No active native session.")
    } else {
        runtime::stop(handle as u64)
    };
    unsafe { new_java_string(env, &result.to_json()) }
}

unsafe fn java_string(env: JNIEnv, value: JString) -> String {
    if env.is_null() || value.is_null() {
        return String::new();
    }
    let Some(get_chars) = jni_fn::<
        unsafe extern "system" fn(JNIEnv, JString, *mut u8) -> *const c_char,
    >(env, GET_STRING_UTF_CHARS) else {
        return String::new();
    };
    let Some(release_chars) = jni_fn::<unsafe extern "system" fn(JNIEnv, JString, *const c_char)>(
        env,
        RELEASE_STRING_UTF_CHARS,
    ) else {
        return String::new();
    };

    let ptr = get_chars(env, value, std::ptr::null_mut());
    if ptr.is_null() {
        return String::new();
    }
    let text = CStr::from_ptr(ptr).to_string_lossy().into_owned();
    release_chars(env, value, ptr);
    text
}

unsafe fn new_java_string(env: JNIEnv, value: &str) -> JString {
    if env.is_null() {
        return std::ptr::null_mut();
    }
    let Some(new_string) =
        jni_fn::<unsafe extern "system" fn(JNIEnv, *const c_char) -> JString>(env, NEW_STRING_UTF)
    else {
        return std::ptr::null_mut();
    };
    let sanitized = value.replace('\0', "\\u0000");
    let c_string = CString::new(sanitized).unwrap_or_else(|_| CString::new("{}").unwrap());
    new_string(env, c_string.as_ptr())
}

unsafe fn jni_fn<T: Copy>(env: JNIEnv, index: usize) -> Option<T> {
    let table = *env as *const *const c_void;
    if table.is_null() {
        return None;
    }
    let ptr = *table.add(index);
    if ptr.is_null() {
        None
    } else {
        Some(std::mem::transmute_copy::<*const c_void, T>(&ptr))
    }
}
