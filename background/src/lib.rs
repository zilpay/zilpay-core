use std::rc::Rc;

use bip39::Mnemonic;
use cipher::{argon2, keychain::KeyChain};
use config::{
    cipher::PROOF_SIZE,
    sha::SHA256_SIZE,
    storage::{INDICATORS_DB_KEY, SELECTED_WALLET_DB_KEY},
    SYS_SIZE,
};
use crypto::bip49::Bip49DerivationPath;
use session::Session;
use settings::common_settings::CommonSettings;
use storage::LocalStorage;
use wallet::{Wallet, WalletConfig};
use zil_errors::background::BackgroundError;

pub struct Background {
    storage: Rc<LocalStorage>,
    pub wallets: Vec<Wallet>,
    pub selected: usize,
    pub indicators: Vec<[u8; SHA256_SIZE]>,
    pub is_old_storage: bool,
    pub settings: CommonSettings,
}

impl Background {
    pub fn from_storage_path(path: &str) -> Result<Self, BackgroundError> {
        let storage =
            LocalStorage::from(path).map_err(BackgroundError::TryInitLocalStorageError)?;
        let storage = Rc::new(storage);
        let is_old_storage = false; // TODO: check old storage from first ZilPay version

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
        let selected: [u8; SYS_SIZE] = storage
            .get(SELECTED_WALLET_DB_KEY)
            .unwrap_or_default()
            .try_into()
            .unwrap_or_default();
        let selected = usize::from_ne_bytes(selected);
        let mut wallets = Vec::new();

        for addr in indicators {
            let session = Session::default();
            let w = Wallet::load_from_storage(&addr, Rc::clone(&storage), session)
                .map_err(BackgroundError::TryLoadWalletError)?;

            wallets.push(w);
        }

        Ok(Self {
            storage,
            wallets,
            selected,
            indicators: Vec::new(),
            is_old_storage,
            settings: Default::default(),
        })
    }

    pub fn add_bip39_wallet<F>(
        &mut self,
        password: &str,
        mnemonic_str: &str,
        indexes: &[usize],
        derive_fn: F,
    ) -> Result<[u8; SHA256_SIZE], BackgroundError>
    where
        F: Fn(usize) -> Bip49DerivationPath,
    {
        let argon_seed = argon2::derive_key(password.as_bytes())
            .map_err(BackgroundError::ArgonPasswordHashError)?;
        let (session, key) =
            Session::unlock(&argon_seed).map_err(BackgroundError::CreateSessionError)?;
        let keychain =
            KeyChain::from_seed(&argon_seed).map_err(BackgroundError::FailCreateKeychain)?;
        let mnemonic = Mnemonic::parse_in_normalized(bip39::Language::English, mnemonic_str)
            .map_err(|e| BackgroundError::FailParseMnemonicWords(e.to_string()))?;
        let indexes: Vec<(Bip49DerivationPath, String)> = indexes
            .iter()
            .map(|i| (derive_fn(*i), format!("account {i}")))
            .collect();
        let proof = argon2::derive_key(&argon_seed[..PROOF_SIZE])
            .map_err(BackgroundError::ArgonCreateProofError)?;
        let wallet_config = WalletConfig {
            session,
            keychain,
            storage: Rc::clone(&self.storage),
            settings: Default::default(), // TODO: setup settings
        };
        let wallet = Wallet::from_bip39_words(&proof, &mnemonic, "", &indexes, wallet_config)
            .map_err(BackgroundError::FailToInitWallet)?;
        let indicator = wallet.key().map_err(BackgroundError::FailToInitWallet)?;

        wallet
            .save_to_storage()
            .map_err(BackgroundError::FailToSaveWallet)?;
        self.indicators.push(indicator);
        self.wallets.push(wallet);
        self.save_indicators()?;

        Ok(key)
    }

    fn save_indicators(&self) -> Result<(), BackgroundError> {
        let bytes: Vec<u8> = self
            .indicators
            .iter()
            .flat_map(|array| array.iter().cloned())
            .collect();

        self.storage
            .set(SELECTED_WALLET_DB_KEY, &bytes)
            .map_err(BackgroundError::FailToWriteIndicatorsWallet)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests_background {
    use super::*;

    #[test]
    fn test_from_path() {
        let bg = Background::from_storage_path("/home/").unwrap();
        assert_eq!(bg.wallets.len(), 0);
        assert_eq!(bg.selected, 0);
    }
}
