use std::sync::Arc;

use async_trait::async_trait;
use bip39::Language;
use config::sha::SHA512_SIZE;
use serde_json::Value;
use settings::{
    common_settings::CommonSettings,
    locale::Locale,
    notifications::{NotificationState, Notifications},
    theme::Theme,
    wallet_settings::WalletSettings,
};
use storage::LocalStorage;
use wallet::{LedgerParams, Wallet};

use crate::{
    book::AddressBookEntry, connections::Connection, BackgroundBip39Params, BackgroundSKParams,
};

/// Provides cryptographic operations for wallet management
pub trait CryptoOperations {
    type Error;

    /// Generates a BIP39 mnemonic phrase with specified word count
    ///
    /// * `count` - Number of words (12, 15, 18, 21, or 24)
    fn gen_bip39(count: u8) -> Result<String, Self::Error>;

    /// Finds invalid words in a BIP39 mnemonic phrase
    ///
    /// * `words` - Vector of words to validate
    /// * `lang` - BIP39 language for validation
    fn find_invalid_bip39_words(words: &[String], lang: Language) -> Vec<usize>;

    /// Generates a new cryptographic key pair
    fn gen_keypair() -> Result<(String, String), Self::Error>;
}

/// Manages wallet operations including unlocking and creation
pub trait WalletManagement {
    type Error;

    /// Unlocks a wallet using password authentication
    ///
    /// * `password` - User password
    /// * `device_indicators` - Device-specific identifiers
    /// * `wallet_index` - Index of the wallet to unlock
    fn unlock_wallet_with_password(
        &mut self,
        password: &str,
        device_indicators: &[String],
        wallet_index: usize,
    ) -> Result<[u8; SHA512_SIZE], Self::Error>;

    /// Unlocks a wallet using an existing session
    ///
    /// * `session_cipher` - Encrypted session data
    /// * `device_indicators` - Device-specific identifiers
    /// * `wallet_index` - Index of the wallet to unlock
    fn unlock_wallet_with_session(
        &mut self,
        session_cipher: Vec<u8>,
        device_indicators: &[String],
        wallet_index: usize,
    ) -> Result<[u8; SHA512_SIZE], Self::Error>;

    /// Creates a new BIP39 wallet
    fn add_bip39_wallet(&mut self, params: BackgroundBip39Params) -> Result<Vec<u8>, Self::Error>;

    /// Creates a new Ledger wallet
    fn add_ledger_wallet(
        &mut self,
        params: LedgerParams,
        wallet_settings: WalletSettings,
        device_indicators: &[String],
    ) -> Result<Vec<u8>, Self::Error>;

    /// Creates a new wallet from secret key
    fn add_sk_wallet(&mut self, params: BackgroundSKParams) -> Result<Vec<u8>, Self::Error>;

    /// Retrieves a wallet by its index
    fn get_wallet_by_index(&self, wallet_index: usize) -> Result<&Wallet, Self::Error>;
}

/// Manages application settings and preferences
pub trait SettingsManagement {
    type Error;

    fn load_global_settings(storage: Arc<LocalStorage>) -> CommonSettings;

    /// Enables or disables global notifications
    fn set_global_notifications(&mut self, global_enabled: bool) -> Result<(), Self::Error>;

    /// Updates notification settings for a specific wallet
    fn set_wallet_notifications(
        &mut self,
        wallet_index: usize,
        notification: NotificationState,
    ) -> Result<(), Self::Error>;

    /// Updates application locale
    fn set_locale(&mut self, new_locale: Locale) -> Result<(), Self::Error>;

    /// Updates application theme
    fn set_theme(&mut self, new_theme: Theme) -> Result<(), Self::Error>;

    /// Updates notification settings
    fn set_notifications(&mut self, new_notifications: Notifications) -> Result<(), Self::Error>;

    /// Saves current settings to storage
    fn save_settings(&self) -> Result<(), Self::Error>;
}

/// Manages connections between wallets and external services
#[async_trait]
pub trait ConnectionManagement {
    type Error;

    /// Retrieves all active connections
    fn get_connections(&self) -> Vec<Connection>;

    /// Associates a wallet with a domain
    fn add_wallet_to_connection(
        &self,
        domain: String,
        wallet_index: usize,
    ) -> Result<(), Self::Error>;

    /// Adds a new connection
    fn add_connection(&self, connection: Connection) -> Result<(), Self::Error>;
}

/// Manages the address book functionality
pub trait AddressBookManagement {
    type Error;

    /// Retrieves all address book entries
    fn get_address_book(&self) -> Vec<AddressBookEntry>;

    /// Adds a new entry to the address book
    fn add_to_address_book(&self, address: AddressBookEntry) -> Result<(), Self::Error>;
}

/// Manages currency exchange rates
#[async_trait]
pub trait RatesManagement {
    type Error;

    /// Updates current exchange rates
    async fn update_rates(&self) -> Result<Value, Self::Error>;

    /// Retrieves current exchange rates
    fn get_rates(&self) -> Value;
}

/// Manages storage operations and persistence
pub trait StorageManagement {
    type Error;

    /// Initializes storage from a given path
    fn from_storage_path(path: &str) -> Result<Self, Self::Error>
    where
        Self: Sized;

    /// Saves current indicators state
    fn save_indicators(&self) -> Result<(), Self::Error>;
}
