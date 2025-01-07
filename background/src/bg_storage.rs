use crate::Result;
use std::sync::Arc;

use config::{
    sha::SHA256_SIZE,
    storage::{GLOBAL_SETTINGS_DB_KEY, INDICATORS_DB_KEY},
};
use errors::background::BackgroundError;
use network::{common::Provider, provider::NetworkProvider};
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
        let providers: Vec<NetworkProvider> =
            NetworkProvider::load_network_configs(Arc::clone(&storage));

        for addr in &indicators {
            let w = Wallet::init_wallet(*addr, Arc::clone(&storage))?;

            wallets.push(w);
        }

        Ok(Self {
            providers,
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
    use crate::{
        bg_crypto::CryptoOperations, bg_provider::ProvidersManagement, bg_wallet::WalletManagement,
        BackgroundBip39Params,
    };

    use super::*;
    use crypto::bip49::Bip49DerivationPath;
    use rand::Rng;
    use rpc::network_config::NetworkConfig;

    fn setup_test_background() -> (Background, String) {
        let mut rng = rand::thread_rng();
        let dir = format!("/tmp/{}", rng.gen::<usize>());
        let bg = Background::from_storage_path(&dir).unwrap();
        (bg, dir)
    }

    #[test]
    fn test_store_and_load_from_storage() {
        let (mut bg, dir) = setup_test_background();

        assert_eq!(bg.wallets.len(), 0);

        let password = "test_password";
        let words = Background::gen_bip39(12).unwrap();
        let accounts = [(Bip49DerivationPath::Ethereum(0), "Name".to_string())];
        let net_conf = NetworkConfig::new("", 0, vec!["".to_string()]);

        bg.add_provider(net_conf).unwrap();
        bg.add_bip39_wallet(BackgroundBip39Params {
            password,
            provider: 0,
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
}
