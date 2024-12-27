use std::sync::Arc;

use cipher::argon2::{derive_key, Argon2Seed};
use config::argon::KEY_SIZE;
use config::cipher::{PROOF_SALT, PROOF_SIZE};
use proto::pubkey::PubKey;

use bip39::Mnemonic;
use cipher::keychain::KeyChain;
use config::sha::SHA256_SIZE;
use crypto::bip49::Bip49DerivationPath;
use settings::wallet_settings::WalletSettings;
use storage::LocalStorage;
use token::ft::FToken;
use wallet_data::{AuthMethod, WalletData};
use zil_errors::wallet::WalletErrors;

pub type WalletAddrType = [u8; SHA256_SIZE];
pub type Result<T> = std::result::Result<T, WalletErrors>;

pub struct WalletConfig {
    pub storage: Arc<LocalStorage>,
    pub keychain: KeyChain,
    pub settings: WalletSettings,
}

pub struct LedgerParams<'a> {
    pub pub_key: &'a PubKey,
    pub ledger_id: Vec<u8>,
    pub name: String,
    pub wallet_index: usize,
    pub wallet_name: String,
    pub biometric_type: AuthMethod,
    pub provider_index: usize,
}

pub struct Bip39Params<'a> {
    pub proof: &'a [u8; KEY_SIZE],
    pub mnemonic: &'a Mnemonic,
    pub passphrase: &'a str,
    pub indexes: &'a [(Bip49DerivationPath, String)],
    pub config: WalletConfig,
    pub wallet_name: String,
    pub biometric_type: AuthMethod,
    pub provider_index: usize,
}

pub struct Wallet {
    storage: Arc<LocalStorage>,
    pub data: WalletData,
    pub ftokens: Vec<FToken>,
}

impl Wallet {
    fn unlock_iternel(&mut self, seed_bytes: &Argon2Seed) -> Result<KeyChain> {
        let keychain = KeyChain::from_seed(seed_bytes).map_err(WalletErrors::KeyChainError)?;

        let proof_key = usize::to_le_bytes(self.data.proof_key);
        let cipher_proof = self
            .storage
            .get(&proof_key)
            .map_err(WalletErrors::FailToGetProofFromStorage)?;

        let origin_proof = keychain
            .get_proof(&cipher_proof, &self.data.settings.cipher_orders)
            .or(Err(WalletErrors::KeyChainFailToGetProof))?;

        let argon2_config = self.data.settings.argon_params.into_config();
        let proof = derive_key(&seed_bytes[..PROOF_SIZE], PROOF_SALT, &argon2_config)
            .map_err(WalletErrors::ArgonCipherErrors)?;

        if proof != origin_proof {
            return Err(WalletErrors::ProofNotMatch);
        }

        Ok(keychain)
    }
}

pub mod account;
pub mod account_type;
pub mod wallet_account;
pub mod wallet_backup;
pub mod wallet_crypto;
pub mod wallet_data;
pub mod wallet_init;
pub mod wallet_network;
pub mod wallet_security;
pub mod wallet_storage;
pub mod wallet_token;
pub mod wallet_transaction;
pub mod wallet_types;
