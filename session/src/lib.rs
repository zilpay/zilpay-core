use ::argon2::Config as Argon2Config;
use cipher::{argon2, keychain::KeyChain, options::CipherOrders};
use config::argon::{KEY_SIZE, SESSION_SALT};
use errors::session::SessionErrors;

pub fn encrypt_session(
    fingerprint: &[u8],
    seed_bytes: &[u8; KEY_SIZE],
    options: &[CipherOrders],
    argon2_config: &Argon2Config,
) -> Result<Vec<u8>, SessionErrors> {
    let argon_seed = argon2::derive_key(fingerprint, SESSION_SALT, argon2_config)
        .map_err(SessionErrors::ArgonError)?;
    let keychain = KeyChain::from_seed(&argon_seed).map_err(SessionErrors::KeychainError)?;
    let seed_cipher = keychain
        .encrypt(seed_bytes.to_vec(), options)
        .map_err(SessionErrors::KeychainError)?;

    Ok(seed_cipher)
}

pub fn decrypt_session(
    fingerprint: &[u8],
    seed_cipher: Vec<u8>,
    options: &[CipherOrders],
    argon2_config: &Argon2Config,
) -> Result<[u8; KEY_SIZE], SessionErrors> {
    let argon_seed = argon2::derive_key(fingerprint, SESSION_SALT, argon2_config)
        .map_err(SessionErrors::ArgonError)?;
    let keychain = KeyChain::from_seed(&argon_seed).map_err(SessionErrors::KeychainError)?;
    let seed_bytes: [u8; KEY_SIZE] = keychain
        .decrypt(seed_cipher, options)
        .map_err(SessionErrors::KeychainError)?
        .try_into()
        .map_err(|_| SessionErrors::InvalidDecryptSession)?;

    Ok(seed_bytes)
}

pub mod keychain_store;
pub mod management;

#[cfg(any(target_os = "macos", target_os = "ios"))]
mod keychain_store_apple;

#[cfg(target_os = "android")]
mod keychain_store_android;

#[cfg(target_os = "linux")]
mod keychain_store_linux;

#[cfg(target_os = "windows")]
mod keychain_store_windows;

#[cfg(test)]
mod tests {
    use super::*;
    use config::argon::KEY_SIZE;

    fn setup_test_data<'a>() -> ([u8; KEY_SIZE], &'a [u8], [CipherOrders; 2]) {
        let test_seed = [1u8; KEY_SIZE];
        let test_fingerprint = "test_device_id_123".as_bytes();
        let options = [CipherOrders::AESGCM256, CipherOrders::NTRUP1277];
        (test_seed, test_fingerprint, options)
    }

    #[test]
    fn test_successful_encryption_decryption_cycle() {
        let (seed, fingerprint, options) = setup_test_data();

        let encrypted =
            encrypt_session(fingerprint, &seed, &options, &argon2::ARGON2_DEFAULT_CONFIG)
                .expect("Encryption should succeed");

        assert_ne!(&encrypted.as_slice(), &seed);

        let decrypted = decrypt_session(
            fingerprint,
            encrypted,
            &options,
            &argon2::ARGON2_DEFAULT_CONFIG,
        )
        .expect("Decryption should succeed");

        assert_eq!(decrypted, seed);
    }

    #[test]
    fn test_wrong_fingerprint_fails() {
        let (seed, fingerprint, options) = setup_test_data();

        let encrypted =
            encrypt_session(fingerprint, &seed, &options, &argon2::ARGON2_DEFAULT_CONFIG)
                .expect("Encryption should succeed");
        let wrong_fingerprint = "wrong_device_id_456".as_bytes();
        let result = decrypt_session(
            wrong_fingerprint,
            encrypted,
            &options,
            &argon2::ARGON2_DEFAULT_CONFIG,
        );

        assert!(matches!(result, Err(SessionErrors::KeychainError(_))));
    }

    #[test]
    fn test_wrong_cipher_options() {
        let (seed, fingerprint, options) = setup_test_data();

        let encrypted =
            encrypt_session(fingerprint, &seed, &options, &argon2::ARGON2_DEFAULT_CONFIG)
                .expect("Encryption should succeed");
        let wrong_options = vec![CipherOrders::NTRUP1277];
        let result = decrypt_session(
            fingerprint,
            encrypted,
            &wrong_options,
            &argon2::ARGON2_DEFAULT_CONFIG,
        );

        assert!(matches!(result, Err(SessionErrors::InvalidDecryptSession)));
    }

    #[test]
    fn test_large_fingerprint() {
        let (seed, _, options) = setup_test_data();
        let large_fingerprint = "a".repeat(10000);

        let result = encrypt_session(
            large_fingerprint.as_bytes(),
            &seed,
            &options,
            &argon2::ARGON2_DEFAULT_CONFIG,
        );

        let encrypted = result.expect("Should handle large fingerprint");
        let decrypted = decrypt_session(
            large_fingerprint.as_bytes(),
            encrypted,
            &options,
            &argon2::ARGON2_DEFAULT_CONFIG,
        )
        .expect("Should decrypt successfully");

        assert_eq!(decrypted, seed);
    }
}
