use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use cipher::{keychain::KeyChain, options::CipherOrders};
use config::sha::{SHA256_SIZE, SHA512_SIZE};
use errors::session::SessionErrors;
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use secrecy::{ExposeSecret, SecretSlice};
use storage::LocalStorage;
use zeroize::Zeroize;

use crate::keychain_store::{
    delete_key_from_secure_enclave, retrieve_key_from_secure_enclave, store_key_in_secure_enclave,
};

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

    fn storage_key(&self, wallet_key: &str) -> String {
        format!("session_{}", wallet_key)
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
}

impl<'a> SessionManagement for SessionManager<'a> {
    fn create_session(&self, words_bytes: SecretSlice<u8>) -> Result<(), SessionErrors> {
        let wallet_key = hex::encode(self.wallet_key);
        let mut random_key = Self::generate_random_key();

        let keychain = KeyChain::from_seed(&random_key).map_err(SessionErrors::KeychainError)?;

        let cipher_orders = [CipherOrders::AESGCM256];
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
        todo!()
    }

    fn clear_session(&self) -> Result<(), SessionErrors> {
        todo!()
    }
}
