use async_trait::async_trait;
use cipher::{keychain::KeyChain, options::CipherOrders};
use config::{
    argon::KEY_SIZE,
    sha::{SHA256_SIZE, SHA512_SIZE},
};
use errors::session::SessionErrors;
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use secrecy::{ExposeSecret, SecretSlice};
use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use storage::LocalStorage;
use zeroize::Zeroize;

use crate::keychain_store::{retrieve_key_from_secure_enclave, store_key_in_secure_enclave};

#[async_trait]
pub trait SessionManagement {
    async fn create_session(&self, words_bytes: SecretSlice<u8>) -> Result<(), SessionErrors>;
    async fn unlock_session(&self) -> Result<SecretSlice<u8>, SessionErrors>;
    async fn is_session_active(&self) -> bool;
    async fn clear_session(&self) -> Result<(), SessionErrors>;
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

    fn cipher_orders() -> [CipherOrders; 3] {
        [
            CipherOrders::AESGCM256,
            CipherOrders::KUZNECHIK,
            CipherOrders::NTRUP1277,
        ]
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

#[async_trait]
impl<'a> SessionManagement for SessionManager<'a> {
    async fn create_session(&self, words_bytes: SecretSlice<u8>) -> Result<(), SessionErrors> {
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

        store_key_in_secure_enclave(&random_key, &wallet_key).await?;

        random_key.zeroize();

        Ok(())
    }

    async fn unlock_session(&self) -> Result<SecretSlice<u8>, SessionErrors> {
        todo!()
    }

    async fn is_session_active(&self) -> bool {
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

        let retrieved_key_vec: SecretSlice<u8> =
            match retrieve_key_from_secure_enclave(&wallet_key).await {
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

    async fn clear_session(&self) -> Result<(), SessionErrors> {
        todo!()
    }
}
