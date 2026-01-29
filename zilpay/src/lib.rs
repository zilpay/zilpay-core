pub use background;
pub use cache;
pub use cipher;
pub use config;
pub use crypto;
pub use errors;
pub use history;
pub use intl;
pub use network;
pub use proto;
pub use qrcodes;
pub use rpc;
pub use session;
pub use settings;
pub use token;
pub use wallet;

#[cfg(target_os = "android")]
mod android_log {
    use std::ffi::CString;
    use std::os::raw::{c_char, c_int};

    // Android log priority levels
    #[allow(dead_code)]
    pub const ANDROID_LOG_DEBUG: c_int = 3;
    #[allow(dead_code)]
    pub const ANDROID_LOG_INFO: c_int = 4;
    #[allow(dead_code)]
    pub const ANDROID_LOG_WARN: c_int = 5;
    #[allow(dead_code)]
    pub const ANDROID_LOG_ERROR: c_int = 6;

    #[link(name = "log")]
    extern "C" {
        pub fn __android_log_write(prio: c_int, tag: *const c_char, text: *const c_char) -> c_int;
    }

    pub fn log(priority: c_int, tag: &str, message: &str) {
        unsafe {
            let tag_cstring = CString::new(tag).unwrap_or_else(|_| CString::new("ZilPay").unwrap());
            let msg_cstring = CString::new(message).unwrap_or_else(|_| CString::new("").unwrap());
            __android_log_write(priority, tag_cstring.as_ptr(), msg_cstring.as_ptr());
        }
    }
}

#[cfg(target_os = "android")]
#[macro_export]
macro_rules! android_log_debug {
    ($tag:expr, $($arg:tt)*) => {
        $crate::android_log::log($crate::android_log::ANDROID_LOG_DEBUG, $tag, &format!($($arg)*));
    };
}

#[cfg(target_os = "android")]
#[macro_export]
macro_rules! android_log_info {
    ($tag:expr, $($arg:tt)*) => {
        $crate::android_log::log($crate::android_log::ANDROID_LOG_INFO, $tag, &format!($($arg)*));
    };
}

#[cfg(target_os = "android")]
#[macro_export]
macro_rules! android_log_warn {
    ($tag:expr, $($arg:tt)*) => {
        $crate::android_log::log($crate::android_log::ANDROID_LOG_WARN, $tag, &format!($($arg)*));
    };
}

#[cfg(target_os = "android")]
#[macro_export]
macro_rules! android_log_error {
    ($tag:expr, $($arg:tt)*) => {
        $crate::android_log::log($crate::android_log::ANDROID_LOG_ERROR, $tag, &format!($($arg)*));
    };
}

// For non-Android platforms, these macros just use println
#[cfg(not(target_os = "android"))]
#[macro_export]
macro_rules! android_log_debug {
    ($tag:expr, $($arg:tt)*) => {
        println!("[{}] DEBUG: {}", $tag, format!($($arg)*));
    };
}

#[cfg(not(target_os = "android"))]
#[macro_export]
macro_rules! android_log_info {
    ($tag:expr, $($arg:tt)*) => {
        println!("[{}] INFO: {}", $tag, format!($($arg)*));
    };
}

#[cfg(not(target_os = "android"))]
#[macro_export]
macro_rules! android_log_warn {
    ($tag:expr, $($arg:tt)*) => {
        println!("[{}] WARN: {}", $tag, format!($($arg)*));
    };
}

#[cfg(not(target_os = "android"))]
#[macro_export]
macro_rules! android_log_error {
    ($tag:expr, $($arg:tt)*) => {
        println!("[{}] ERROR: {}", $tag, format!($($arg)*));
    };
}

pub fn init() -> Result<(), String> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    #[cfg(target_os = "android")]
    android_log_info!("ZilPay", "ZilPay core initialized");

    Ok(())
}
