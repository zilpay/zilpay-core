use std::sync::Arc;

use cipher::argon2::{derive_key, Argon2Seed};
use config::argon::KEY_SIZE;
use config::cipher::{PROOF_SALT, PROOF_SIZE};
use proto::pubkey::PubKey;

use bip39::Mnemonic;
use cipher::keychain::KeyChain;
use config::sha::SHA256_SIZE;
use crypto::bip49::DerivationPath;
use errors::wallet::WalletErrors;
use proto::secret_key::SecretKey;
use settings::wallet_settings::WalletSettings;
use storage::LocalStorage;
use wallet_data::AuthMethod;
use wallet_storage::StorageOperations;

pub type WalletAddrType = [u8; SHA256_SIZE];
pub type Result<T> = std::result::Result<T, WalletErrors>;

pub struct WalletConfig {
    pub storage: Arc<LocalStorage>,
    pub keychain: KeyChain,
    pub settings: WalletSettings,
}

pub struct LedgerParams {
    pub pub_key: PubKey,
    pub ledger_id: Vec<u8>,
    pub proof: [u8; KEY_SIZE],
    pub account_name: String,
    pub wallet_index: usize,
    pub wallet_name: String,
    pub biometric_type: AuthMethod,
    pub chain_hash: u64,
}

pub struct SecretKeyParams {
    pub sk: SecretKey,
    pub proof: [u8; KEY_SIZE],
    pub wallet_name: String,
    pub biometric_type: AuthMethod,
    pub chain_hash: u64,
}

pub struct Bip39Params<'a> {
    pub proof: [u8; KEY_SIZE],
    pub mnemonic: &'a Mnemonic,
    pub passphrase: &'a str,
    pub indexes: &'a [(DerivationPath, String)],
    pub wallet_name: String,
    pub biometric_type: AuthMethod,
    pub chain_hash: u64,
}

pub struct Wallet {
    storage: Arc<LocalStorage>,
    pub wallet_address: WalletAddrType,
}

impl Wallet {
    fn unlock_iternel(&self, seed_bytes: &Argon2Seed) -> Result<KeyChain> {
        let keychain = KeyChain::from_seed(seed_bytes).map_err(WalletErrors::KeyChainError)?;
        let data = self.get_wallet_data()?;

        let proof_key = usize::to_le_bytes(data.proof_key);
        let cipher_proof = self
            .storage
            .get(&proof_key)
            .map_err(WalletErrors::FailToGetProofFromStorage)?;

        let origin_proof = keychain
            .get_proof(&cipher_proof, &data.settings.cipher_orders)
            .or(Err(WalletErrors::KeyChainFailToGetProof))?;

        let argon2_config = data.settings.argon_params.into_config();
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
pub mod wallet_crypto;
pub mod wallet_data;
pub mod wallet_init;
pub mod wallet_security;
pub mod wallet_storage;
pub mod wallet_token;
pub mod wallet_transaction;
pub mod wallet_types;
