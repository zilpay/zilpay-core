use std::{collections::HashSet, sync::Arc};

use async_trait::async_trait;
use bip39::Mnemonic;
use cipher::argon2::Argon2Seed;
use config::{argon::KEY_SIZE, sha::SHA256_SIZE};
use crypto::bip49::Bip49DerivationPath;
use network::provider::NetworkProvider;
use proto::{
    keypair::KeyPair,
    pubkey::PubKey,
    secret_key::SecretKey,
    signature::Signature,
    tx::{TransactionReceipt, TransactionRequest},
};
use storage::LocalStorage;
use token::ft::FToken;

use crate::{wallet_data::AuthMethod, Bip39Params, LedgerParams, WalletConfig};

pub type WalletAddrType = [u8; SHA256_SIZE];

/// Storage operations for secure data persistence
pub trait StorageOperations {
    type Error;

    /// Loads wallet data from storage using a unique key
    ///
    /// * `key` - The unique identifier for stored data
    /// * `storage` - Storage instance for data access
    fn load_from_storage(
        key: &[u8; SHA256_SIZE],
        storage: Arc<LocalStorage>,
    ) -> Result<Self, Self::Error>
    where
        Self: Sized;

    /// Securely saves data to storage with random key generation
    ///
    /// * `cipher_entropy` - Encrypted data to store
    /// * `storage` - Storage instance for data persistence
    fn safe_storage_save(
        cipher_entropy: &[u8],
        storage: Arc<LocalStorage>,
    ) -> Result<usize, Self::Error>;

    /// Persists current wallet state to storage
    fn save_to_storage(&self) -> Result<(), Self::Error>;
}

/// Core wallet initialization operations
pub trait WalletInit {
    type Error;

    /// Creates a new hardware wallet instance using Ledger device
    fn from_ledger(
        params: LedgerParams,
        proof: &[u8; KEY_SIZE],
        config: WalletConfig,
    ) -> Result<Self, Self::Error>
    where
        Self: Sized;

    /// Creates a new wallet instance from an existing secret key
    fn from_sk(
        sk: &SecretKey,
        name: String,
        proof: &[u8; KEY_SIZE],
        config: WalletConfig,
        wallet_name: String,
        biometric_type: AuthMethod,
        providers: HashSet<NetworkProvider>,
    ) -> Result<Self, Self::Error>
    where
        Self: Sized;

    /// Creates a new wallet instance from BIP39 mnemonic words
    fn from_bip39_words(params: Bip39Params) -> Result<Self, Self::Error>
    where
        Self: Sized;
}

/// Cryptographic operations for wallet security
pub trait WalletCrypto {
    type Error;

    /// Retrieves the keypair for a specific account index
    fn reveal_keypair(
        &self,
        account_index: usize,
        seed_bytes: &[u8; KEY_SIZE],
        passphrase: Option<&str>,
    ) -> Result<KeyPair, Self::Error>;

    /// Retrieves the BIP39 mnemonic phrase
    fn reveal_mnemonic(&self, seed_bytes: &[u8; KEY_SIZE]) -> Result<Mnemonic, Self::Error>;

    /// Signs a message using the specified account
    fn sign_message(
        &self,
        msg: &[u8],
        account_index: usize,
        seed_bytes: &[u8; KEY_SIZE],
        passphrase: Option<&str>,
    ) -> Result<Signature, Self::Error>;
}

/// Transaction handling capabilities
#[async_trait]
pub trait TransactionSigning {
    type Error;

    /// Signs a blockchain transaction request
    async fn sign_transaction(
        &self,
        tx: &TransactionRequest,
        account_index: usize,
        seed_bytes: &[u8; KEY_SIZE],
        passphrase: Option<&str>,
    ) -> Result<TransactionReceipt, Self::Error>;
}

/// Account management functionalities
pub trait AccountManagement {
    type Error;

    /// Adds a new hardware wallet account
    fn add_ledger_account(
        &mut self,
        name: String,
        pub_key: &PubKey,
        index: usize,
    ) -> Result<(), Self::Error>;

    /// Creates the next account in BIP39 derivation path
    fn add_next_bip39_account(
        &mut self,
        name: String,
        bip49: &Bip49DerivationPath,
        passphrase: &str,
        seed_bytes: &[u8; KEY_SIZE],
    ) -> Result<(), Self::Error>;

    /// Changes the currently active account
    fn select_account(&mut self, account_index: usize) -> Result<(), Self::Error>;
}

/// Token handling operations
pub trait TokenManagement {
    type Error;

    /// Registers a new fungible token in the wallet
    fn add_ftoken(&mut self, token: FToken) -> Result<(), Self::Error>;

    /// Removes a fungible token from the wallet
    fn remove_ftoken(&mut self, index: usize) -> Result<(), Self::Error>;
}

/// Authentication and security operations
pub trait WalletSecurity {
    type Error;

    /// Unlocks the wallet using provided seed bytes
    fn unlock(&mut self, seed_bytes: &Argon2Seed) -> Result<(), Self::Error>;
}

/// Wallet backup operations
pub trait WalletBackup {
    type Error;

    /// Creates an encrypted backup of the wallet
    fn create_backup(&self, password: &str) -> Result<Vec<u8>, Self::Error>;

    /// Restores wallet from an encrypted backup
    fn restore_from_backup(backup: &[u8], password: &str) -> Result<Self, Self::Error>
    where
        Self: Sized;
}

/// Network management operations
pub trait NetworkOperations {
    type Error;

    /// Adds a new network provider
    fn add_provider(&mut self, provider: NetworkProvider) -> Result<(), Self::Error>;

    /// Removes an existing network provider
    fn remove_provider(&mut self, provider: &NetworkProvider) -> Result<(), Self::Error>;

    /// Sets the active network provider
    fn set_active_provider(&mut self, provider: NetworkProvider) -> Result<(), Self::Error>;
}
