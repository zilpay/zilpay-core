use cipher::{argon2, keychain::KeyChain, options::CipherOrders};
use config::argon::{KEY_SIZE, SESSION_SALT};
use zil_errors::session::SessionErrors;

/// Encrypts a seed (password) using device fingerprint and multiple encryption layers
///
/// This function implements a multi-layer encryption scheme where a device-specific
/// fingerprint is used to encrypt a cached password/seed. The process involves:
/// 1. Deriving a key from the device fingerprint using Argon2
/// 2. Creating a keychain from the derived key
/// 3. Encrypting the seed using multiple cipher layers
///
/// # Parameters
/// * `fingerprint` - A device-specific identifier string containing static device information
///                   Used as the base for key derivation
/// * `seed_bytes` - The password/seed to be encrypted (must be KEY_SIZE bytes long)
///                  This is typically a cached password that needs to be secured
/// * `options` - Vector of encryption layer configurations (CipherOrders)
///               Specifies the sequence and types of encryption to be applied
///
/// # Returns
/// * `Ok(Vec<u8>)` - The encrypted seed as a byte vector if successful
/// * `Err(SessionErrors)` - Various error types that might occur during:
///   - Argon2 key derivation
///   - Keychain creation
///   - Encryption process
///
/// # Security Notes
/// - The fingerprint should be reliably reproducible across sessions
/// - The seed_bytes should be properly generated and secured before passing
/// - The encryption layers (options) should be carefully chosen for security requirements
pub fn encrypt_session(
    fingerprint: &str,
    seed_bytes: &[u8; KEY_SIZE],
    options: &[CipherOrders],
) -> Result<Vec<u8>, SessionErrors> {
    let argon_seed = argon2::derive_key(fingerprint.as_bytes(), SESSION_SALT)
        .map_err(SessionErrors::ArgonError)?;
    let keychain = KeyChain::from_seed(&argon_seed).map_err(SessionErrors::KeychainError)?;
    let seed_cipher = keychain
        .encrypt(seed_bytes.to_vec(), options)
        .map_err(SessionErrors::KeychainError)?;

    Ok(seed_cipher)
}

/// Decrypts a previously encrypted seed using device fingerprint and encryption layers
///
/// This function is the inverse operation of `from_fingerprint()`. It decrypts a seed
/// (typically a cached password) that was encrypted using a device-specific fingerprint.
/// The process involves:
/// 1. Deriving the same key from the device fingerprint using Argon2
/// 2. Recreating the keychain from the derived key
/// 3. Decrypting the seed using the same cipher layers in reverse order
///
/// # Parameters
/// * `fingerprint` - A device-specific identifier string containing static device information
///                   Must match the fingerprint used for encryption
/// * `seed_cipher` - The encrypted seed bytes that were returned from `from_fingerprint()`
/// * `options` - Vector of encryption layer configurations (CipherOrders)
///               Must match the exact sequence used during encryption
///
/// # Returns
/// * `Ok([u8; KEY_SIZE])` - The decrypted seed as a fixed-size byte array if successful
/// * `Err(SessionErrors)` - Various error types that might occur during:
///   - Argon2 key derivation
///   - Keychain creation
///   - Decryption process
///   - Invalid seed size after decryption
///
/// # Security Notes
/// - The fingerprint must exactly match the one used for encryption
/// - The options sequence must match the encryption sequence
/// - Failed decryption might indicate tampering or incorrect device fingerprint
///
pub fn decrypt_session(
    fingerprint: &str,
    seed_cipher: Vec<u8>,
    options: &[CipherOrders],
) -> Result<[u8; KEY_SIZE], SessionErrors> {
    let argon_seed = argon2::derive_key(fingerprint.as_bytes(), SESSION_SALT)
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

        let encrypted =
            encrypt_session(&fingerprint, &seed, &options).expect("Encryption should succeed");

        assert_ne!(&encrypted.as_slice(), &seed);

        let decrypted =
            decrypt_session(&fingerprint, encrypted, &options).expect("Decryption should succeed");

        assert_eq!(decrypted, seed);
    }

    #[test]
    fn test_wrong_fingerprint_fails() {
        let (seed, fingerprint, options) = setup_test_data();

        let encrypted =
            encrypt_session(&fingerprint, &seed, &options).expect("Encryption should succeed");
        let wrong_fingerprint = "wrong_device_id_456";
        let result = decrypt_session(wrong_fingerprint, encrypted, &options);

        assert!(matches!(result, Err(SessionErrors::KeychainError(_))));
    }

    #[test]
    fn test_wrong_cipher_options() {
        let (seed, fingerprint, options) = setup_test_data();

        let encrypted =
            encrypt_session(&fingerprint, &seed, &options).expect("Encryption should succeed");
        let wrong_options = vec![CipherOrders::NTRUP1277];
        let result = decrypt_session(&fingerprint, encrypted, &wrong_options);

        assert!(matches!(result, Err(SessionErrors::InvalidDecryptSession)));
    }

    #[test]
    fn test_large_fingerprint() {
        let (seed, _, options) = setup_test_data();
        let large_fingerprint = "a".repeat(10000);

        let result = encrypt_session(&large_fingerprint, &seed, &options);

        let encrypted = result.expect("Should handle large fingerprint");
        let decrypted = decrypt_session(&large_fingerprint, encrypted, &options)
            .expect("Should decrypt successfully");

        assert_eq!(decrypted, seed);
    }
}
