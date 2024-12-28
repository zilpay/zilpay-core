use crate::wallet_data::WalletData;
use crate::wallet_token::TokenManagement;
use crate::Result;
use crate::Wallet;
use crate::WalletAddrType;
use rand::Rng;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::sync::Arc;
use storage::LocalStorage;
use zil_errors::wallet::WalletErrors;

/// Storage operations for secure data persistence
pub trait StorageOperations {
    type Error;

    /// Loads wallet data from storage using a unique key
    ///
    /// * `key` - The unique identifier for stored data
    /// * `storage` - Storage instance for data access
    fn load_from_storage(
        key: &WalletAddrType,
        storage: Arc<LocalStorage>,
    ) -> std::result::Result<Self, Self::Error>
    where
        Self: Sized;

    /// Securely saves data to storage with random key generation
    ///
    /// * `cipher_entropy` - Encrypted data to store
    /// * `storage` - Storage instance for data persistence
    fn safe_storage_save(
        cipher_entropy: &[u8],
        storage: Arc<LocalStorage>,
    ) -> std::result::Result<usize, Self::Error>;

    /// Persists current wallet state to storage
    fn save_to_storage(&self) -> std::result::Result<(), Self::Error>;
}

impl StorageOperations for Wallet {
    type Error = WalletErrors;

    fn load_from_storage(key: &WalletAddrType, storage: Arc<LocalStorage>) -> Result<Self> {
        let data = storage.get(key)?;
        let data = WalletData::from_bytes(&data)?;
        let ftokens = Vec::with_capacity(0);

        Ok(Self {
            storage,
            data,
            ftokens,
        })
    }

    fn safe_storage_save(cipher_entropy: &[u8], storage: Arc<LocalStorage>) -> Result<usize> {
        let mut rng = ChaCha20Rng::from_entropy();
        let mut cipher_entropy_key: usize;

        loop {
            cipher_entropy_key = rng.gen();
            let key = usize::to_le_bytes(cipher_entropy_key);
            let is_exists_key = storage.exists(&key)?;

            if is_exists_key {
                continue;
            }

            storage.set(&key, cipher_entropy)?;

            break;
        }

        Ok(cipher_entropy_key)
    }

    fn save_to_storage(&self) -> Result<()> {
        let ft_bytes = bincode::serialize(&self.ftokens)
            .map_err(|e| WalletErrors::TokenSerdeError(e.to_string()))?;
        let token_key = Wallet::get_token_db_key(&self.data.wallet_address);

        self.storage
            .set(&self.data.wallet_address, &self.data.to_bytes()?)?;
        self.storage.set(&token_key, &ft_bytes)?;
        self.storage.flush()?;

        Ok(())
    }
}
