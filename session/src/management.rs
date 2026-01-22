use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use cipher::{keychain::KeyChain, options::CipherOrders};
use config::{
    argon::KEY_SIZE,
    sha::{SHA256_SIZE, SHA512_SIZE},
};
use errors::session::SessionErrors;
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use secrecy::{ExposeSecret, SecretSlice};
use storage::LocalStorage;
use zeroize::Zeroize;

use crate::keychain_store::{retrieve_key_from_secure_enclave, store_key_in_secure_enclave};

pub trait SessionManagement {
    fn create_session(&self, words_bytes: SecretSlice<u8>) -> Result<(), SessionErrors>;
    fn unlock_session(&self) -> Result<SecretSlice<u8>, SessionErrors>;
    fn is_session_active(&self) -> bool;
    fn clear_session(&self) -> Result<(), SessionErrors>;
}

pub struct SessionManager<'a> {
    storage: Arc<LocalStorage>,
    ttl: Duration,
    wallet_key: &'a [u8; SHA256_SIZE],
}

impl<'a> SessionManager<'a> {
    pub fn new(
        storage: Arc<LocalStorage>,
        ttl_secs: u64,
        wallet_key: &'a [u8; SHA256_SIZE],
    ) -> Self {
        Self {
            storage,
            ttl: Duration::from_secs(ttl_secs),
            wallet_key: wallet_key,
        }
    }

    fn wallet_key_hex(&self) -> String {
        hex::encode(self.wallet_key)
    }

    fn storage_key(&self, wallet_key: &str) -> String {
        format!("session_{}", wallet_key)
    }

    fn cipher_orders() -> [CipherOrders; 1] {
        [CipherOrders::AESGCM256]
    }

    fn generate_random_key() -> [u8; SHA512_SIZE] {
        let mut rng = ChaCha20Rng::from_entropy();
        let mut key = [0u8; SHA512_SIZE];
        rng.fill_bytes(&mut key);
        key
    }

    fn current_timestamp() -> Result<u64, SessionErrors> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .map_err(|_| {
                SessionErrors::StorageError(
                    errors::storage::LocalStorageError::StorageTimeWentBackwards,
                )
            })
    }

    fn parse_storage_value(&self, value: &[u8]) -> Option<(u64, Vec<u8>)> {
        let value_str = String::from_utf8_lossy(value);
        let parts: Vec<&str> = value_str.split(':').collect();

        if parts.len() != 2 {
            return None;
        }

        let timestamp = parts[0].parse::<u64>().ok()?;
        let encrypted_words = hex::decode(parts[1]).ok()?;

        Some((timestamp, encrypted_words))
    }

    fn is_timestamp_valid(&self, timestamp: u64) -> bool {
        if let Ok(current) = Self::current_timestamp() {
            timestamp + self.ttl.as_secs() > current
        } else {
            false
        }
    }
}

impl<'a> SessionManagement for SessionManager<'a> {
    fn create_session(&self, words_bytes: SecretSlice<u8>) -> Result<(), SessionErrors> {
        let wallet_key = self.wallet_key_hex();
        let mut random_key = Self::generate_random_key();

        let keychain = KeyChain::from_seed(&random_key).map_err(SessionErrors::KeychainError)?;
        let cipher_orders = Self::cipher_orders();
        let encrypted_words = keychain
            .encrypt(words_bytes.expose_secret().to_vec(), &cipher_orders)
            .map_err(SessionErrors::KeychainError)?;

        let timestamp = Self::current_timestamp()?;
        let hex_enc_words = hex::encode(&encrypted_words);
        let storage_value = format!("{}:{}", timestamp, hex_enc_words);

        let storage_key = self.storage_key(&wallet_key);
        self.storage
            .set(storage_key.as_bytes(), storage_value.as_bytes())
            .map_err(SessionErrors::StorageError)?;

        store_key_in_secure_enclave(&random_key, &wallet_key)?;

        random_key.zeroize();

        Ok(())
    }

    fn unlock_session(&self) -> Result<SecretSlice<u8>, SessionErrors> {
        todo!()
    }

    fn is_session_active(&self) -> bool {
        let wallet_key = self.wallet_key_hex();
        let storage_key = self.storage_key(&wallet_key);

        let stored_value = match self.storage.get(storage_key.as_bytes()) {
            Ok(value) => value,
            Err(_) => return false,
        };

        let (timestamp, encrypted_words) = match self.parse_storage_value(&stored_value) {
            Some(parsed) => parsed,
            None => return false,
        };

        if !self.is_timestamp_valid(timestamp) {
            return false;
        }

        let retrieved_key_vec: SecretSlice<u8> = match retrieve_key_from_secure_enclave(&wallet_key)
        {
            Ok(key) => key,
            Err(_) => return false,
        };
        let retrieved_key: [u8; KEY_SIZE] = match retrieved_key_vec.expose_secret().try_into() {
            Ok(key) => key,
            Err(_) => return false,
        };

        let keychain = match KeyChain::from_seed(&retrieved_key.into()) {
            Ok(kc) => kc,
            Err(_) => return false,
        };

        let cipher_orders = Self::cipher_orders();
        keychain.decrypt(encrypted_words, &cipher_orders).is_ok()
    }

    fn clear_session(&self) -> Result<(), SessionErrors> {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, time::UNIX_EPOCH};

    fn setup_temp_storage() -> (LocalStorage, String) {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let temp_path = format!("/tmp/test_session_{}", timestamp);
        let storage = LocalStorage::from(&temp_path).expect("Failed to create temp storage");
        (storage, temp_path)
    }

    fn cleanup_temp_storage(path: &str) {
        let _ = fs::remove_dir_all(path);
    }

    #[test]
    fn test_create_session() {
        let (storage, temp_path) = setup_temp_storage();
        let wallet_key: [u8; SHA256_SIZE] = [42u8; SHA256_SIZE];
        let words_bytes = b"test seed phrase words bytes".to_vec();
        let secret_words = SecretSlice::new(words_bytes.into_boxed_slice());

        let manager = SessionManager::new(Arc::new(storage), 3600, &wallet_key);

        manager.create_session(secret_words).unwrap();

        cleanup_temp_storage(&temp_path);
    }

    #[test]
    fn test_is_session_active() {
        let (storage, temp_path) = setup_temp_storage();
        let wallet_key: [u8; SHA256_SIZE] = [42u8; SHA256_SIZE];
        let words_bytes = b"test seed phrase words bytes".to_vec();
        let secret_words = SecretSlice::new(words_bytes.clone().into_boxed_slice());

        let manager = SessionManager::new(Arc::new(storage), 3600, &wallet_key);

        assert!(
            !manager.is_session_active(),
            "Session should not be active before creation"
        );

        manager.create_session(secret_words).unwrap();

        assert!(
            manager.is_session_active(),
            "Session should be active after creation"
        );

        cleanup_temp_storage(&temp_path);
    }

    #[test]
    fn test_is_session_expired() {
        let (storage, temp_path) = setup_temp_storage();
        let wallet_key: [u8; SHA256_SIZE] = [42u8; SHA256_SIZE];
        let words_bytes = b"test seed phrase words bytes".to_vec();
        let secret_words = SecretSlice::new(words_bytes.into_boxed_slice());

        let manager = SessionManager::new(Arc::new(storage), 1, &wallet_key);

        manager.create_session(secret_words).unwrap();

        std::thread::sleep(Duration::from_secs(2));

        assert!(
            !manager.is_session_active(),
            "Session should be expired after TTL"
        );

        cleanup_temp_storage(&temp_path);
    }
}
