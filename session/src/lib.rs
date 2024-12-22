use ::argon2::Config as Argon2Config;
use cipher::{argon2, keychain::KeyChain, options::CipherOrders};
use config::argon::{KEY_SIZE, SESSION_SALT};
use zil_errors::session::SessionErrors;

/// Encrypts a seed using device-specific fingerprint and layered encryption
///
/// # Overview
/// Implements a multi-layer encryption scheme using a device fingerprint to encrypt
/// a seed value (typically a password). The encryption process:
/// 1. Derives a key from the device fingerprint using Argon2
/// 2. Generates a keychain from the derived key
/// 3. Applies multiple encryption layers based on provided cipher options
///
/// # Arguments
/// * `fingerprint` - Device-specific identifier used for key derivation
/// * `seed_bytes` - Fixed-size array of bytes to encrypt (must be KEY_SIZE bytes)
/// * `options` - Ordered sequence of encryption algorithms to apply
/// * `argon2_config` - Argon2 password hashing configuration parameters
///
/// # Returns
/// * `Ok(Vec<u8>)` - Encrypted seed as a byte vector
/// * `Err(SessionErrors)` - Error indicating failed:
///   - Key derivation (`ArgonError`)
///   - Keychain initialization (`KeychainError`)
///   - Encryption process (`KeychainError`)
///
pub fn encrypt_session(
    fingerprint: &str,
    seed_bytes: &[u8; KEY_SIZE],
    options: &[CipherOrders],
    argon2_config: &Argon2Config,
) -> Result<Vec<u8>, SessionErrors> {
    let argon_seed = argon2::derive_key(fingerprint.as_bytes(), SESSION_SALT, argon2_config)
        .map_err(SessionErrors::ArgonError)?;
    let keychain = KeyChain::from_seed(&argon_seed).map_err(SessionErrors::KeychainError)?;
    let seed_cipher = keychain
        .encrypt(seed_bytes.to_vec(), options)
        .map_err(SessionErrors::KeychainError)?;

    Ok(seed_cipher)
}

/// Decrypts a previously encrypted seed using device fingerprint
///
/// # Overview
/// Reverses the encryption performed by `encrypt_session()`. The decryption process:
/// 1. Derives the same key from the device fingerprint using Argon2
/// 2. Reconstructs the keychain from the derived key
/// 3. Applies decryption layers in reverse order
///
/// # Arguments
/// * `fingerprint` - Device-specific identifier (must match encryption fingerprint)
/// * `seed_cipher` - Encrypted bytes from previous `encrypt_session()` call
/// * `options` - Ordered sequence of encryption algorithms (must match encryption sequence)
/// * `argon2_config` - Argon2 password hashing configuration parameters
///
/// # Returns
/// * `Ok([u8; KEY_SIZE])` - Decrypted seed as fixed-size byte array
/// * `Err(SessionErrors)` - Error indicating failed:
///   - Key derivation (`ArgonError`)
///   - Keychain initialization (`KeychainError`)
///   - Decryption process (`KeychainError`)
///   - Invalid decrypted seed size (`InvalidDecryptSession`)
///
/// # Security Considerations
/// * Fingerprint must exactly match the one used for encryption
/// * Cipher options must match the encryption sequence
/// * Failed decryption may indicate tampering or incorrect device fingerprint
pub fn decrypt_session(
    fingerprint: &str,
    seed_cipher: Vec<u8>,
    options: &[CipherOrders],
    argon2_config: &Argon2Config,
) -> Result<[u8; KEY_SIZE], SessionErrors> {
    let argon_seed = argon2::derive_key(fingerprint.as_bytes(), SESSION_SALT, argon2_config)
        .map_err(SessionErrors::ArgonError)?;
    let keychain = KeyChain::from_seed(&argon_seed).map_err(SessionErrors::KeychainError)?;
    let seed_bytes: [u8; KEY_SIZE] = keychain
        .decrypt(seed_cipher, options)
        .map_err(SessionErrors::KeychainError)?
        .try_into()
        .map_err(|_| SessionErrors::InvalidDecryptSession)?;

    Ok(seed_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use config::argon::KEY_SIZE;

    fn setup_test_data() -> ([u8; KEY_SIZE], String, [CipherOrders; 2]) {
        let test_seed = [1u8; KEY_SIZE];
        let test_fingerprint = "test_device_id_123".to_string();
        let options = [CipherOrders::AESGCM256, CipherOrders::NTRUP1277];
        (test_seed, test_fingerprint, options)
    }

    #[test]
    fn test_successful_encryption_decryption_cycle() {
        let (seed, fingerprint, options) = setup_test_data();

        let encrypted = encrypt_session(
            &fingerprint,
            &seed,
            &options,
            &argon2::ARGON2_DEFAULT_CONFIG,
        )
        .expect("Encryption should succeed");

        assert_ne!(&encrypted.as_slice(), &seed);

        let decrypted = decrypt_session(
            &fingerprint,
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

        let encrypted = encrypt_session(
            &fingerprint,
            &seed,
            &options,
            &argon2::ARGON2_DEFAULT_CONFIG,
        )
        .expect("Encryption should succeed");
        let wrong_fingerprint = "wrong_device_id_456";
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

        let encrypted = encrypt_session(
            &fingerprint,
            &seed,
            &options,
            &argon2::ARGON2_DEFAULT_CONFIG,
        )
        .expect("Encryption should succeed");
        let wrong_options = vec![CipherOrders::NTRUP1277];
        let result = decrypt_session(
            &fingerprint,
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
            &large_fingerprint,
            &seed,
            &options,
            &argon2::ARGON2_DEFAULT_CONFIG,
        );

        let encrypted = result.expect("Should handle large fingerprint");
        let decrypted = decrypt_session(
            &large_fingerprint,
            encrypted,
            &options,
            &argon2::ARGON2_DEFAULT_CONFIG,
        )
        .expect("Should decrypt successfully");

        assert_eq!(decrypted, seed);
    }
}
