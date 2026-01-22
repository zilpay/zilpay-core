use config::session::KEYCHAIN_SERVICE;
use core_foundation::base::TCFType;
use errors::{keychain::KeyChainErrors, session::SessionErrors};
use secrecy::SecretSlice;
use security_framework::{
    access_control::SecAccessControl,
    passwords::{
        delete_generic_password, generic_password, set_generic_password_options, PasswordOptions,
    },
};
use security_framework_sys::access_control::{
    kSecAccessControlUserPresence, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
    SecAccessControlCreateWithFlags,
};
use std::ptr;

pub async fn store_key_in_secure_enclave(
    key: &[u8],
    wallet_key: &str,
) -> Result<(), SessionErrors> {
    let key_vec = key.to_vec();
    let wallet_key_owned = wallet_key.to_string();

    tokio::task::spawn_blocking(move || {
        let access_control_ref = unsafe {
            SecAccessControlCreateWithFlags(
                ptr::null_mut(),
                kSecAttrAccessibleWhenUnlockedThisDeviceOnly as _,
                kSecAccessControlUserPresence as _,
                ptr::null_mut(),
            )
        };

        if access_control_ref.is_null() {
            return Err(SessionErrors::KeychainError(
                KeyChainErrors::AppleKeychainError("Failed to create SecAccessControl".to_string()),
            ));
        }

        let access_control = unsafe { SecAccessControl::wrap_under_create_rule(access_control_ref) };
        let mut options = PasswordOptions::new_generic_password(KEYCHAIN_SERVICE, &wallet_key_owned);

        options.set_access_control(access_control);

        delete_generic_password(KEYCHAIN_SERVICE, &wallet_key_owned).unwrap_or_default();

        set_generic_password_options(&key_vec, options).map_err(|e| {
            SessionErrors::KeychainError(KeyChainErrors::AppleKeychainError(e.to_string()))
        })?;

        Ok(())
    })
    .await
    .map_err(|e| {
        SessionErrors::KeychainError(KeyChainErrors::AppleKeychainError(format!(
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
        let read_options = PasswordOptions::new_generic_password(KEYCHAIN_SERVICE, &wallet_key_owned);
        let results = generic_password(read_options).map_err(|e| {
            SessionErrors::KeychainError(KeyChainErrors::AppleKeychainError(e.to_string()))
        })?;

        Ok(SecretSlice::new(results.into()))
    })
    .await
    .map_err(|e| {
        SessionErrors::KeychainError(KeyChainErrors::AppleKeychainError(format!(
            "Task join error: {}",
            e
        )))
    })?
}

pub async fn delete_key_from_secure_enclave(wallet_key: &str) -> Result<(), SessionErrors> {
    let wallet_key_owned = wallet_key.to_string();

    tokio::task::spawn_blocking(move || {
        delete_generic_password(KEYCHAIN_SERVICE, &wallet_key_owned).map_err(|e| {
            SessionErrors::KeychainError(KeyChainErrors::AppleKeychainError(e.to_string()))
        })
    })
    .await
    .map_err(|e| {
        SessionErrors::KeychainError(KeyChainErrors::AppleKeychainError(format!(
            "Task join error: {}",
            e
        )))
    })?
}
