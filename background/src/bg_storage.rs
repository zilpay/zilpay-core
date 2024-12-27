use crate::Result;
use std::sync::Arc;

use config::{
    sha::SHA256_SIZE,
    storage::{GLOBAL_SETTINGS_DB_KEY, INDICATORS_DB_KEY},
};
use network::provider::NetworkProvider;
use settings::common_settings::CommonSettings;
use storage::LocalStorage;
use wallet::{wallet_storage::StorageOperations, Wallet};
use zil_errors::background::BackgroundError;

use crate::Background;

/// Manages storage operations and persistence
pub trait StorageManagement {
    type Error;

    /// Initializes storage from a given path
    fn from_storage_path(path: &str) -> std::result::Result<Self, Self::Error>
    where
        Self: Sized;

    fn load_global_settings(storage: Arc<LocalStorage>) -> CommonSettings;

    /// Saves current indicators state
    fn save_indicators(&self) -> std::result::Result<(), Self::Error>;

    /// Saves current settings to storage
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

    fn from_storage_path(path: &str) -> Result<Self> {
        let storage = LocalStorage::from(path)?;
        let storage = Arc::new(storage);
        // TODO: check old storage from first ZilPay version if indicators is empty
        let indicators = storage
            .get(INDICATORS_DB_KEY)
            .unwrap_or_default()
            .chunks(SHA256_SIZE)
            .map(|chunk| {
                let mut array = [0u8; SHA256_SIZE];
                array.copy_from_slice(chunk);
                array
            })
            .collect::<Vec<[u8; SHA256_SIZE]>>();
        let mut wallets = Vec::with_capacity(indicators.len());
        let settings = Self::load_global_settings(Arc::clone(&storage));
        let providers: Vec<NetworkProvider> = Vec::with_capacity(0); // TODO: empty, need to load from storage.

        for addr in &indicators {
            let w = Wallet::load_from_storage(addr, Arc::clone(&storage))?;

            wallets.push(w);
        }

        Ok(Self {
            providers,
            storage,
            wallets,
            indicators,
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

    fn save_indicators(&self) -> Result<()> {
        let bytes: Vec<u8> = self
            .indicators
            .iter()
            .flat_map(|array| array.iter().cloned())
            .collect();

        self.storage.set(INDICATORS_DB_KEY, &bytes)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests_background {
    use crate::{bg_crypto::CryptoOperations, bg_wallet::WalletManagement, BackgroundBip39Params};

    use super::*;
    use crypto::bip49::Bip49DerivationPath;
    use rand::Rng;

    fn setup_test_background() -> (Background, String) {
        let mut rng = rand::thread_rng();
        let dir = format!("/tmp/{}", rng.gen::<usize>());
        let bg = Background::from_storage_path(&dir).unwrap();
        (bg, dir)
    }

    #[test]
    fn test_add_more_wallets_bip39() {
        let (mut bg, dir) = setup_test_background();

        assert_eq!(bg.wallets.len(), 0);

        let password = "test_password";
        let words = Background::gen_bip39(12).unwrap();
        let accounts = [(Bip49DerivationPath::Ethereum(0), "Name".to_string())];

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
        })
        .unwrap();

        assert_eq!(bg.wallets.len(), 1);

        let wallet_address = bg.wallets[0].data.wallet_address;

        drop(bg);

        let bg = Background::from_storage_path(&dir).unwrap();

        assert_eq!(bg.wallets[0].data.wallet_address, wallet_address);
    }
}
