use config::{cipher::PROOF_SALT, sha::SHA512_SIZE};
use sha2::{Digest, Sha512};

#[cfg(any(target_os = "macos", target_os = "ios"))]
use crate::keychain_store_apple::get_device_identifier;

#[cfg(target_os = "android")]
use crate::keychain_store_android::get_device_identifier;

#[cfg(target_os = "linux")]
use crate::keychain_store_linux::get_device_identifier;

#[cfg(target_os = "windows")]
use crate::keychain_store_windows::get_device_identifier;

pub fn get_device_signature() -> [u8; SHA512_SIZE] {
    let identifiers = get_device_identifier().unwrap_or_default();
    let combined = identifiers.join("") + PROOF_SALT;

    let mut hasher = Sha512::new();
    hasher.update(combined.as_bytes());
    let result = hasher.finalize();

    let mut signature = [0u8; 64];
    signature.copy_from_slice(&result);

    signature
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_device_signature() {
        let signature = get_device_signature();
        assert_eq!(signature.len(), 64);

        let signature2 = get_device_signature();
        assert_eq!(signature, signature2);
        assert_ne!(signature, [0u8; 64]);
    }

    #[test]
    fn test_get_device_identifier() {
        let identifier = get_device_identifier().expect("Should get device identifier");
        assert!(!identifier.is_empty());

        let identifier2 = get_device_identifier().expect("Should get device identifier again");
        assert_eq!(identifier, identifier2);
    }
}
