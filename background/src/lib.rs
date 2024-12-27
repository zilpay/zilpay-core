pub use bip39::{Language, Mnemonic};

use crypto::bip49::Bip49DerivationPath;
use network::provider::NetworkProvider;
use proto::secret_key::SecretKey;
use settings::{common_settings::CommonSettings, wallet_settings::WalletSettings};
use std::{collections::HashSet, sync::Arc};
use storage::LocalStorage;
use wallet::{traits::WalletAddrType, wallet_data::AuthMethod, Wallet};
use zil_errors::background::BackgroundError;

pub type Result<T> = std::result::Result<T, BackgroundError>;

pub struct BackgroundBip39Params<'a> {
    pub password: &'a str,
    pub mnemonic_str: &'a str,
    pub passphrase: &'a str,
    pub wallet_name: String,
    pub biometric_type: AuthMethod,
    pub device_indicators: &'a [String],
    pub wallet_settings: WalletSettings,
    pub accounts: &'a [(Bip49DerivationPath, String)],
    pub providers: HashSet<NetworkProvider>,
}

pub struct BackgroundSKParams<'a> {
    pub password: &'a str,
    pub secret_key: &'a SecretKey,
    pub account_name: String,
    pub wallet_name: String,
    pub biometric_type: AuthMethod,
    pub device_indicators: &'a [String],
    pub wallet_settings: WalletSettings,
    pub providers: HashSet<NetworkProvider>,
}

pub struct Background {
    storage: Arc<LocalStorage>,
    pub wallets: Vec<Wallet>,
    pub indicators: Vec<WalletAddrType>,
    pub is_old_storage: bool,
    pub settings: CommonSettings,
}

pub mod bg_book;
pub mod bg_connections;
pub mod bg_crypto;
pub mod bg_rates;
pub mod bg_settings;
pub mod bg_storage;
pub mod bg_wallet;
pub mod book;
pub mod connections;
pub mod device_indicators;
