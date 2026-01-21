#[cfg(any(target_os = "macos", target_os = "ios"))]
pub use crate::keychain_store_apple::*;

#[cfg(target_os = "android")]
pub use crate::keychain_store_android::*;

#[cfg(target_os = "linux")]
pub use crate::keychain_store_linux::*;

#[cfg(target_os = "windows")]
pub use crate::keychain_store_windows::*;

#[cfg(not(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "android",
    target_os = "linux",
    target_os = "windows"
)))]
pub fn store_key_in_secure_enclave(_key: &[u8], _service: &str) -> Result<(), SessionErrors> {
    Err(SessionErrors::KeychainError(
        errors::keychain::KeyChainErrors::PlatformNotSupported,
    ))
}

#[cfg(not(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "android",
    target_os = "linux",
    target_os = "windows"
)))]
pub fn retrieve_key_from_secure_enclave(_service: &str) -> Result<Vec<u8>, SessionErrors> {
    Err(SessionErrors::KeychainError(
        errors::keychain::KeyChainErrors::PlatformNotSupported,
    ))
}

#[cfg(not(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "android",
    target_os = "linux",
    target_os = "windows"
)))]
pub fn delete_key_from_secure_enclave(_service: &str) -> Result<(), SessionErrors> {
    Err(SessionErrors::KeychainError(
        errors::keychain::KeyChainErrors::PlatformNotSupported,
    ))
}
