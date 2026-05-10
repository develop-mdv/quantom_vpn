pub mod api;
pub mod config;
pub mod ffi;
pub mod runtime;

#[no_mangle]
pub extern "C" fn omega_android_bridge_version() -> u32 {
    1
}
