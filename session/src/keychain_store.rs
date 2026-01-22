#[cfg(any(target_os = "macos", target_os = "ios"))]
pub use crate::keychain_store_apple::*;

#[cfg(target_os = "android")]
pub use crate::keychain_store_android::*;

#[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "android")))]
mod default_keyring {
    use config::session::KEYCHAIN_SERVICE;
    use errors::session::SessionErrors;
    use secrecy::{ExposeSecret, SecretSlice};
    use zeroize::Zeroize;

    pub async fn store_key_in_secure_enclave(
        mut key: SecretSlice<u8>,
        wallet_key: &str,
    ) -> Result<(), SessionErrors> {
        let wallet_key_owned = wallet_key.to_string();

        tokio::task::spawn_blocking(move || {
            let entry = keyring::Entry::new(KEYCHAIN_SERVICE, &wallet_key_owned).map_err(|e| {
                SessionErrors::KeychainError(errors::keychain::KeyChainErrors::KeyringError(
                    e.to_string(),
                ))
            })?;

            let result = entry.set_secret(key.expose_secret()).map_err(|e| {
                SessionErrors::KeychainError(errors::keychain::KeyChainErrors::KeyringError(
                    e.to_string(),
                ))
            });

            key.zeroize();

            result
        })
        .await
        .map_err(|e| {
            SessionErrors::KeychainError(errors::keychain::KeyChainErrors::KeyringError(format!(
                "Task join error: {}",
                e
            )))
        })?
    }

    pub async fn retrieve_key_from_secure_enclave(
        wallet_key: &str,
    ) -> Result<SecretSlice<u8>, SessionErrors> {
        let wallet_key_owned = wallet_key.to_string();

        tokio::task::spawn_blocking(move || {
            let entry = keyring::Entry::new(KEYCHAIN_SERVICE, &wallet_key_owned).map_err(|e| {
                SessionErrors::KeychainError(errors::keychain::KeyChainErrors::KeyringError(
                    e.to_string(),
                ))
            })?;

            let secret_bytes = entry.get_secret().map_err(|e| {
                SessionErrors::KeychainError(errors::keychain::KeyChainErrors::KeyringError(
                    e.to_string(),
                ))
            })?;

            Ok(SecretSlice::new(secret_bytes.into()))
        })
        .await
        .map_err(|e| {
            SessionErrors::KeychainError(errors::keychain::KeyChainErrors::KeyringError(format!(
                "Task join error: {}",
                e
            )))
        })?
    }

    pub async fn delete_key_from_secure_enclave(wallet_key: &str) -> Result<(), SessionErrors> {
        let wallet_key_owned = wallet_key.to_string();

        tokio::task::spawn_blocking(move || {
            let entry = keyring::Entry::new(KEYCHAIN_SERVICE, &wallet_key_owned).map_err(|e| {
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
        })
        .await
        .map_err(|e| {
            SessionErrors::KeychainError(errors::keychain::KeyChainErrors::KeyringError(format!(
                "Task join error: {}",
                e
            )))
        })?
    }
}

#[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "android")))]
pub use default_keyring::*;
