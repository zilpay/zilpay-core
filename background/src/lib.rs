use std::rc::Rc;

use bip39::Mnemonic;
use cipher::{argon2, keychain::KeyChain};
use config::{
    cipher::PROOF_SIZE,
    sha::SHA256_SIZE,
    storage::{INDICATORS_DB_KEY, SELECTED_WALLET_DB_KEY},
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
    pub selected: [u8; SHA256_SIZE],
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
        let selected: [u8; SHA256_SIZE] = storage
            .get(SELECTED_WALLET_DB_KEY)
            .unwrap_or_default()
            .try_into()
            .unwrap_or_default();
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
        self.selected = indicator;

        self.save_indicators()?;
        self.save_selected()?;

        Ok(key)
    }

    fn save_indicators(&self) -> Result<(), BackgroundError> {
        let bytes: Vec<u8> = self
            .indicators
            .iter()
            .flat_map(|array| array.iter().cloned())
            .collect();

        self.storage
            .set(INDICATORS_DB_KEY, &bytes)
            .map_err(BackgroundError::FailToWriteIndicatorsWallet)?;

        Ok(())
    }

    fn save_selected(&self) -> Result<(), BackgroundError> {
        self.storage
            .set(SELECTED_WALLET_DB_KEY, &self.selected)
            .map_err(BackgroundError::FailWriteSelectedWallet)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests_background {
    use config::wallet;
    use rand::Rng;

    use super::*;

    #[test]
    fn test_from_bip39() {
        let mut rng = rand::thread_rng();
        let dir = format!("/tmp/{}", rng.gen::<usize>());
        let mut bg = Background::from_storage_path(&dir).unwrap();

        assert_eq!(bg.wallets.len(), 0);
        assert_eq!(bg.selected, [0u8; SHA256_SIZE]);

        let password = "test_password";
        let words: &str =
            "green process gate doctor slide whip priority shrug diamond crumble average help";
        let indexes = [0, 1, 2, 3, 4, 5, 6, 7];
        let derive = Bip49DerivationPath::Zilliqa;

        let key = bg
            .add_bip39_wallet(password, words, &indexes, derive)
            .unwrap();

        assert_eq!(bg.wallets.len(), 1);

        let wallet = bg.wallets.first_mut().unwrap();

        let res_words = wallet.reveal_mnemonic(&key).unwrap().to_string();

        assert_eq!(res_words, words);

        wallet.lock();

        assert!(wallet.reveal_mnemonic(&key).is_err());
    }
}
