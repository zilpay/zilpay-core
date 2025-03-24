use crate::{bg_provider::ProvidersManagement, bg_wallet::WalletManagement, Result};
use std::sync::Arc;

use cipher::{
    argon2::{self, Argon2Seed, ARGON2_DEFAULT_CONFIG},
    keychain::KeyChain,
    options::CipherOrders,
};
use config::{
    sha::SHA256_SIZE,
    storage::{GLOBAL_SETTINGS_DB_KEY_V1, INDICATORS_DB_KEY_V1},
};
use errors::background::BackgroundError;
use rpc::network_config::ChainConfig;
use serde::{Deserialize, Serialize};
use settings::common_settings::CommonSettings;
use storage::LocalStorage;
use token::ft::FToken;
use wallet::{
    wallet_crypto::WalletCrypto, wallet_data::WalletData, wallet_storage::StorageOperations,
    wallet_types::WalletTypes, Wallet, WalletAddrType,
};

use crate::Background;

pub const SIGNATURE: &[u8] = b"ZILPAY_BACKUP";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct KeyStore {
    pub wallet_data: WalletData,
    pub wallet_address: WalletAddrType,
    pub chain_config: ChainConfig,
    pub ftokens: Vec<FToken>,
    pub keys: Vec<u8>,
}

impl KeyStore {
    pub fn from_backup(cipher_backup: Vec<u8>, argon_seed: &Argon2Seed) -> Result<KeyStore> {
        if cipher_backup.len() <= SIGNATURE.len() || &cipher_backup[..SIGNATURE.len()] != SIGNATURE
        {
            return Err(BackgroundError::InvalidBackupSignature);
        }

        if cipher_backup.len() <= SIGNATURE.len() + 1 {
            return Err(BackgroundError::InvalidBackupFormat);
        }

        let version = cipher_backup[SIGNATURE.len()];
        if version != 0 {
            return Err(BackgroundError::UnsupportedBackupVersion(version));
        }

        if cipher_backup.len() <= SIGNATURE.len() + 2 {
            return Err(BackgroundError::InvalidBackupFormat);
        }

        let cipher_orders_len = cipher_backup[SIGNATURE.len() + 1] as usize;

        if cipher_backup.len() < SIGNATURE.len() + 2 + cipher_orders_len {
            return Err(BackgroundError::InvalidBackupFormat);
        }

        let cipher_orders_start = SIGNATURE.len() + 2;
        let cipher_orders_end = cipher_orders_start + cipher_orders_len;
        let cipher_orders_bytes = &cipher_backup[cipher_orders_start..cipher_orders_end];

        let mut cipher_orders = Vec::with_capacity(cipher_orders_len);
        for &byte in cipher_orders_bytes {
            if let Ok(cipher) = CipherOrders::from_code(byte) {
                cipher_orders.push(cipher);
            } else {
                return Err(BackgroundError::InvalidBackupFormat);
            }
        }

        if cipher_orders.is_empty() {
            return Err(BackgroundError::InvalidBackupFormat);
        }

        let encrypted_data = cipher_backup[cipher_orders_end..].to_vec();

        let keychain = KeyChain::from_seed(argon_seed)?;
        let decrypted_data = keychain.decrypt(encrypted_data, &cipher_orders)?;

        let keystore: KeyStore = bincode::deserialize(&decrypted_data)?;

        Ok(keystore)
    }
}

pub trait StorageManagement {
    type Error;

    fn from_storage_path(path: &str) -> std::result::Result<Self, Self::Error>
    where
        Self: Sized;
    fn load_global_settings(storage: Arc<LocalStorage>) -> CommonSettings;
    fn get_indicators(storage: Arc<LocalStorage>) -> Vec<[u8; SHA256_SIZE]>;
    fn save_indicators(
        &self,
        indicators: Vec<[u8; SHA256_SIZE]>,
    ) -> std::result::Result<(), Self::Error>;
    fn save_settings(&self, settings: CommonSettings) -> std::result::Result<(), Self::Error>;
    fn get_keystore(
        &self,
        wallet_index: usize,
        password: &str,
        device_indicators: &[String],
    ) -> std::result::Result<Vec<u8>, Self::Error>;
    fn load_keystore(
        &self,
        backup_cipher: Vec<u8>,
        password: &str,
        device_indicators: &[String],
    ) -> std::result::Result<(), Self::Error>;
}

impl StorageManagement for Background {
    type Error = BackgroundError;

    fn load_keystore(
        &self,
        backup_cipher: Vec<u8>,
        password: &str,
        device_indicators: &[String],
    ) -> Result<()> {
        let argon_seed = argon2::derive_key(password.as_bytes(), "", &ARGON2_DEFAULT_CONFIG)
            .map_err(BackgroundError::ArgonPasswordHashError)?;
        let keystore = KeyStore::from_backup(backup_cipher, &argon_seed)?;

        Ok(())
    }

    fn get_keystore(
        &self,
        wallet_index: usize,
        password: &str,
        device_indicators: &[String],
    ) -> Result<Vec<u8>> {
        let argon_seed =
            self.unlock_wallet_with_password(password, device_indicators, wallet_index)?;
        let wallet = self.get_wallet_by_index(wallet_index)?;
        let wallet_data = wallet.get_wallet_data()?;
        let ftokens = wallet.get_ftokens()?;
        let chain_config = self.get_provider(wallet_data.default_chain_hash)?.config;
        let cipher_orders = wallet_data.settings.cipher_orders.clone();
        let keys = match wallet_data.wallet_type {
            WalletTypes::Ledger(_) => Vec::with_capacity(0),
            WalletTypes::SecretPhrase((_, _)) => wallet
                .reveal_mnemonic(&argon_seed)?
                .to_string()
                .into_bytes(),
            WalletTypes::SecretKey => wallet
                .reveal_keypair(0, &argon_seed, None)?
                .to_bytes()?
                .to_vec(),
        };
        let keystore = KeyStore {
            wallet_data,
            chain_config,
            ftokens,
            keys,
            wallet_address: wallet.wallet_address,
        };
        let new_argon_seed = argon2::derive_key(password.as_bytes(), "", &ARGON2_DEFAULT_CONFIG)
            .map_err(BackgroundError::ArgonPasswordHashError)?;

        let keystore_bytes = bincode::serialize(&keystore)?;
        let keystore_version: u8 = 0;
        let keychain = KeyChain::from_seed(&new_argon_seed)?;
        let cipher_bytes = keychain.encrypt(keystore_bytes, &cipher_orders)?;
        let cipher_orders_bytes = cipher_orders.iter().map(|c| c.code()).collect::<Vec<u8>>();

        let total_len = SIGNATURE.len() + 1 + 1 + cipher_orders_bytes.len() + cipher_bytes.len();
        let mut result = Vec::with_capacity(total_len);
        result.extend_from_slice(SIGNATURE);
        result.push(keystore_version);
        result.push(cipher_orders_bytes.len() as u8);
        result.extend(cipher_orders_bytes);
        result.extend(cipher_bytes);

        Ok(result)
    }

    fn load_global_settings(storage: Arc<LocalStorage>) -> CommonSettings {
        let bytes = storage.get(GLOBAL_SETTINGS_DB_KEY_V1).unwrap_or_default();

        if bytes.is_empty() {
            return CommonSettings::default();
        }

        bincode::deserialize(&bytes).unwrap_or(CommonSettings::default())
    }

    fn get_indicators(storage: Arc<LocalStorage>) -> Vec<[u8; SHA256_SIZE]> {
        storage
            .get(INDICATORS_DB_KEY_V1)
            .unwrap_or_default()
            .chunks(SHA256_SIZE)
            .map(|chunk| {
                let mut array = [0u8; SHA256_SIZE];
                array.copy_from_slice(chunk);
                array
            })
            .collect::<Vec<[u8; SHA256_SIZE]>>()
    }

    fn from_storage_path(path: &str) -> Result<Self> {
        let storage = LocalStorage::from(path)?;
        let storage = Arc::new(storage);
        let indicators = Self::get_indicators(Arc::clone(&storage));
        let mut wallets = Vec::with_capacity(indicators.len());

        for addr in &indicators {
            let w = Wallet::init_wallet(*addr, Arc::clone(&storage))?;

            wallets.push(w);
        }

        Ok(Self { storage, wallets })
    }

    fn save_settings(&self, settings: CommonSettings) -> Result<()> {
        let bytes =
            bincode::serialize(&settings).or(Err(BackgroundError::FailToSerializeNetworks))?;

        self.storage.set(GLOBAL_SETTINGS_DB_KEY_V1, &bytes)?;
        self.storage.flush()?;

        Ok(())
    }

    fn save_indicators(&self, indicators: Vec<[u8; SHA256_SIZE]>) -> Result<()> {
        let bytes: Vec<u8> = indicators
            .iter()
            .flat_map(|array| array.iter().cloned())
            .collect();

        self.storage.set(INDICATORS_DB_KEY_V1, &bytes)?;
        self.storage.flush()?;

        Ok(())
    }
}

#[cfg(test)]
mod tests_background {
    use super::*;
    use crate::{
        bg_crypto::CryptoOperations, bg_provider::ProvidersManagement, bg_wallet::WalletManagement,
        BackgroundBip39Params,
    };
    use crypto::{bip49::DerivationPath, slip44};
    use rand::Rng;
    use rpc::network_config::{ChainConfig, Explorer};

    fn setup_test_background() -> (Background, String) {
        let mut rng = rand::thread_rng();
        let dir = format!("/tmp/{}", rng.gen::<usize>());
        let bg = Background::from_storage_path(&dir).unwrap();
        (bg, dir)
    }

    fn create_test_network_config() -> ChainConfig {
        ChainConfig {
            ftokens: vec![],
            logo: String::new(),
            diff_block_time: 0,
            testnet: None,
            chain_ids: [1, 0],
            name: "Test Network".to_string(),
            chain: "TEST".to_string(),
            short_name: String::new(),
            rpc: vec!["https://test.network".to_string()],
            features: vec![155, 1559],
            slip_44: slip44::ETHEREUM,
            ens: None,
            explorers: vec![Explorer {
                name: "TestExplorer".to_string(),
                url: "https://test.explorer".to_string(),
                icon: None,
                standard: 3091,
            }],
            fallback_enabled: true,
        }
    }

    #[test]
    fn test_store_and_load_from_storage() {
        let (mut bg, dir) = setup_test_background();

        assert_eq!(bg.wallets.len(), 0);

        let password = "test_password";
        let words = Background::gen_bip39(12).unwrap();
        let accounts = [(DerivationPath::new(slip44::ETHEREUM, 0), "Name".to_string())];
        let net_conf = create_test_network_config();

        bg.add_provider(net_conf.clone()).unwrap();
        bg.add_bip39_wallet(BackgroundBip39Params {
            password,
            chain_hash: net_conf.hash(),
            mnemonic_str: &words,
            mnemonic_check: true,
            accounts: &accounts,
            wallet_settings: Default::default(),
            passphrase: "",
            wallet_name: String::new(),
            biometric_type: Default::default(),
            device_indicators: &[String::from("apple"), String::from("0000")],
            ftokens: vec![],
        })
        .unwrap();

        assert_eq!(bg.wallets.len(), 1);

        let wallet_address = bg.wallets.first().unwrap().wallet_address;

        drop(bg);

        let bg = Background::from_storage_path(&dir).unwrap();

        assert_eq!(bg.wallets.first().unwrap().wallet_address, wallet_address);
    }

    #[test]
    fn test_multiple_wallets() {
        let (mut bg, _) = setup_test_background();
        let net_conf = create_test_network_config();

        bg.add_provider(net_conf.clone()).unwrap();

        let words1 = Background::gen_bip39(12).unwrap();
        let accounts1 = [(
            DerivationPath::new(slip44::ETHEREUM, 0),
            "Wallet1".to_string(),
        )];

        bg.add_bip39_wallet(BackgroundBip39Params {
            password: "pass1",
            chain_hash: net_conf.hash(),
            mnemonic_str: &words1,
            mnemonic_check: true,
            accounts: &accounts1,
            wallet_settings: Default::default(),
            passphrase: "",
            wallet_name: String::from("Wallet1"),
            biometric_type: Default::default(),
            device_indicators: &[String::from("apple"), String::from("0001")],
            ftokens: vec![],
        })
        .unwrap();

        // Add second wallet
        let words2 = Background::gen_bip39(12).unwrap();
        let accounts2 = [(
            DerivationPath::new(slip44::ETHEREUM, 0),
            "Wallet2".to_string(),
        )];

        bg.add_bip39_wallet(BackgroundBip39Params {
            password: "pass2",
            chain_hash: net_conf.hash(),
            mnemonic_check: true,
            mnemonic_str: &words2,
            accounts: &accounts2,
            wallet_settings: Default::default(),
            passphrase: "",
            wallet_name: String::from("Wallet2"),
            biometric_type: Default::default(),
            device_indicators: &[String::from("apple"), String::from("0002")],
            ftokens: vec![],
        })
        .unwrap();

        assert_eq!(bg.wallets.len(), 2);
        assert_ne!(bg.wallets[0].wallet_address, bg.wallets[1].wallet_address);
    }

    #[test]
    fn test_keystore() {
        let (mut bg, _) = setup_test_background();
        let net_conf = create_test_network_config();
        const PASSWORD: &str = "shit password";

        bg.add_provider(net_conf.clone()).unwrap();

        let words1 = Background::gen_bip39(12).unwrap();
        let accounts1 = [(
            DerivationPath::new(slip44::ETHEREUM, 0),
            "keystore wallet".to_string(),
        )];

        bg.add_bip39_wallet(BackgroundBip39Params {
            password: PASSWORD,
            chain_hash: net_conf.hash(),
            mnemonic_str: &words1,
            mnemonic_check: true,
            accounts: &accounts1,
            wallet_settings: Default::default(),
            passphrase: "",
            wallet_name: String::from("shit walelt"),
            biometric_type: Default::default(),
            device_indicators: &[],
            ftokens: vec![],
        })
        .unwrap();
        let keystore_bytes = bg.get_keystore(0, PASSWORD, &[]).unwrap();
        let argon_seed =
            argon2::derive_key(PASSWORD.as_bytes(), "", &ARGON2_DEFAULT_CONFIG).unwrap();
        let keystore = KeyStore::from_backup(keystore_bytes, &argon_seed).unwrap();
        let wallet = bg.get_wallet_by_index(0).unwrap();
        let wallet_data = wallet.get_wallet_data().unwrap();

        assert_eq!(keystore.keys, words1.to_string().into_bytes());
        assert_eq!(keystore.chain_config, net_conf);
        assert_eq!(keystore.wallet_address, wallet.wallet_address);
        assert_eq!(keystore.wallet_data, wallet_data);
    }

    #[test]
    fn test_load_from_keystore() {
        let (mut bg, _) = setup_test_background();
        let net_conf = create_test_network_config();
        const PASSWORD: &str = "shit password";

        bg.add_provider(net_conf.clone()).unwrap();

        let words1 = Background::gen_bip39(12).unwrap();
        let accounts1 = [(
            DerivationPath::new(slip44::ETHEREUM, 0),
            "keystore wallet".to_string(),
        )];

        bg.add_bip39_wallet(BackgroundBip39Params {
            password: PASSWORD,
            chain_hash: net_conf.hash(),
            mnemonic_str: &words1,
            mnemonic_check: true,
            accounts: &accounts1,
            wallet_settings: Default::default(),
            passphrase: "",
            wallet_name: String::from("shit walelt"),
            biometric_type: Default::default(),
            device_indicators: &[],
            ftokens: vec![],
        })
        .unwrap();
        let keystore_bytes = bg.get_keystore(0, PASSWORD, &[]).unwrap();
    }
}
