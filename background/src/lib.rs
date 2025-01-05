pub use bip39::{Language, Mnemonic};

use crypto::bip49::Bip49DerivationPath;
use network::provider::NetworkProvider;
use proto::{pubkey::PubKey, secret_key::SecretKey};
use settings::{common_settings::CommonSettings, wallet_settings::WalletSettings};
use std::sync::Arc;
use storage::LocalStorage;
use token::ft::FToken;
use wallet::{wallet_data::AuthMethod, Wallet, WalletAddrType};
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
    pub provider: usize,
    pub ftokens: Vec<FToken>,
}

pub struct BackgroundSKParams<'a> {
    pub password: &'a str,
    pub secret_key: SecretKey,
    pub wallet_name: String,
    pub biometric_type: AuthMethod,
    pub device_indicators: &'a [String],
    pub wallet_settings: WalletSettings,
    pub provider: usize,
    pub ftokens: Vec<FToken>,
}

pub struct BackgroundLedgerParams {
    pub ledger_id: Vec<u8>,
    pub pub_key: PubKey,
    pub wallet_name: String,
    pub account_name: String,
    pub wallet_index: usize,
    pub biometric_type: AuthMethod,
    pub wallet_settings: WalletSettings,
    pub provider_index: usize,
    pub ftokens: Vec<FToken>,
}

pub struct Background {
    storage: Arc<LocalStorage>,
    pub wallets: Vec<Wallet>,
    pub indicators: Vec<WalletAddrType>,
    pub settings: CommonSettings,
    pub providers: Vec<NetworkProvider>,
}

pub mod bg_book;
pub mod bg_connections;
pub mod bg_crypto;
pub mod bg_provider;
pub mod bg_rates;
pub mod bg_settings;
pub mod bg_storage;
pub mod bg_token;
pub mod bg_tx;
pub mod bg_wallet;
pub mod book;
pub mod connections;
pub mod device_indicators;
