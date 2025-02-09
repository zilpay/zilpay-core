use crate::Result;
use std::sync::Arc;

use config::{
    sha::SHA256_SIZE,
    storage::{GLOBAL_SETTINGS_DB_KEY, INDICATORS_DB_KEY},
};
use errors::background::BackgroundError;
use settings::common_settings::CommonSettings;
use storage::LocalStorage;
use wallet::{wallet_storage::StorageOperations, Wallet};

use crate::Background;

/// Manages storage operations and persistence
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
    fn save_settings(&self) -> std::result::Result<(), Self::Error>;
}

impl StorageManagement for Background {
    type Error = BackgroundError;

    fn load_global_settings(storage: Arc<LocalStorage>) -> CommonSettings {
        let bytes = storage.get(GLOBAL_SETTINGS_DB_KEY).unwrap_or_default();

        if bytes.is_empty() {
            return CommonSettings::default();
        }

        bincode::deserialize(&bytes).unwrap_or(CommonSettings::default())
    }

    fn get_indicators(storage: Arc<LocalStorage>) -> Vec<[u8; SHA256_SIZE]> {
        storage
            .get(INDICATORS_DB_KEY)
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
        // TODO: check old storage from first ZilPay version if indicators is empty
        let indicators = Self::get_indicators(Arc::clone(&storage));
        let mut wallets = Vec::with_capacity(indicators.len());
        let settings = Self::load_global_settings(Arc::clone(&storage));

        for addr in &indicators {
            let w = Wallet::init_wallet(*addr, Arc::clone(&storage))?;

            wallets.push(w);
        }

        Ok(Self {
            storage,
            wallets,
            settings,
        })
    }

    fn save_settings(&self) -> Result<()> {
        let bytes =
            bincode::serialize(&self.settings).or(Err(BackgroundError::FailToSerializeNetworks))?;

        self.storage.set(GLOBAL_SETTINGS_DB_KEY, &bytes)?;
        self.storage.flush()?;

        Ok(())
    }

    fn save_indicators(&self, indicators: Vec<[u8; SHA256_SIZE]>) -> Result<()> {
        let bytes: Vec<u8> = indicators
            .iter()
            .flat_map(|array| array.iter().cloned())
            .collect();

        self.storage.set(INDICATORS_DB_KEY, &bytes)?;
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
            testnet: None,
            chain_ids: None,
            name: "Test Network".to_string(),
            chain: "TEST".to_string(),
            short_name: String::new(),
            rpc: vec!["https://test.network".to_string()],
            features: vec![155, 1559],
            chain_id: 1,
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

        // Add first wallet
        let words1 = Background::gen_bip39(12).unwrap();
        let accounts1 = [(
            DerivationPath::new(slip44::ETHEREUM, 0),
            "Wallet1".to_string(),
        )];

        bg.add_bip39_wallet(BackgroundBip39Params {
            password: "pass1",
            chain_hash: net_conf.hash(),
            mnemonic_str: &words1,
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
}
