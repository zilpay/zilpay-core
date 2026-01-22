#[cfg(any(target_os = "macos", target_os = "ios"))]
pub use crate::keychain_store_apple::*;

#[cfg(target_os = "android")]
pub use crate::keychain_store_android::*;

#[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "android")))]
mod default_keyring {
    use config::session::KEYCHAIN_SERVICE;
    use errors::session::SessionErrors;
    use secrecy::{ExposeSecret, SecretSlice};

    pub async fn store_key_in_secure_enclave(
        key: &[u8],
        wallet_key: &str,
    ) -> Result<(), SessionErrors> {
        let entry = keyring::Entry::new(KEYCHAIN_SERVICE, wallet_key).map_err(|e| {
            SessionErrors::KeychainError(errors::keychain::KeyChainErrors::KeyringError(
                e.to_string(),
            ))
        })?;

        let secret = SecretSlice::new(key.into());
        let encoded = hex::encode(secret.expose_secret());

        entry.set_password(&encoded).map_err(|e| {
            SessionErrors::KeychainError(errors::keychain::KeyChainErrors::KeyringError(
                e.to_string(),
            ))
        })?;

        Ok(())
    }

    pub async fn retrieve_key_from_secure_enclave(
        wallet_key: &str,
    ) -> Result<SecretSlice<u8>, SessionErrors> {
        let entry = keyring::Entry::new(KEYCHAIN_SERVICE, wallet_key).map_err(|e| {
            SessionErrors::KeychainError(errors::keychain::KeyChainErrors::KeyringError(
                e.to_string(),
            ))
        })?;

        let encoded = entry.get_password().map_err(|e| {
            SessionErrors::KeychainError(errors::keychain::KeyChainErrors::KeyringError(
                e.to_string(),
            ))
        })?;

        let secret = SecretSlice::new(
            hex::decode(encoded)
                .map_err(|_| SessionErrors::InvalidDecryptSession)?
                .into(),
        );

        Ok(secret)
    }

    pub async fn delete_key_from_secure_enclave(wallet_key: &str) -> Result<(), SessionErrors> {
        let entry = keyring::Entry::new(KEYCHAIN_SERVICE, wallet_key).map_err(|e| {
            SessionErrors::KeychainError(errors::keychain::KeyChainErrors::KeyringError(
                e.to_string(),
            ))
        })?;

        entry.delete_credential().map_err(|e| {
            SessionErrors::KeychainError(errors::keychain::KeyChainErrors::KeyringError(
                e.to_string(),
            ))
        })?;

        Ok(())
    }
}

#[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "android")))]
pub use default_keyring::*;
