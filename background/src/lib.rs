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
            .map_err(BackgroundError::FailTogetIndicators)?
            .chunks(SHA256_SIZE)
            .map(|chunk| {
                let mut array = [0u8; SHA256_SIZE];
                array.copy_from_slice(chunk);
                array
            })
            .collect::<Vec<[u8; SHA256_SIZE]>>();
        let selected: [u8; SYS_SIZE] = storage
            .get(SELECTED_WALLET_DB_KEY)
            .map_err(BackgroundError::FailToLoadSelectedIndicators)?
            .try_into()
            .or(Err(BackgroundError::FailTosliceSelectedIndicators))?;
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

    pub fn wallet_from_bip39(
        &mut self,
        password: &str,
        mnemonic_str: &str,
        indexes: &[usize],
    ) -> String {
        let argon_seed = argon2::derive_key(password.as_bytes()).unwrap();
        let (session, key) = Session::unlock(&argon_seed).unwrap();
        let keychain = KeyChain::from_seed(&argon_seed).unwrap();
        let mnemonic =
            Mnemonic::parse_in_normalized(bip39::Language::English, mnemonic_str).unwrap();
        let indexes: Vec<(Bip49DerivationPath, String)> = indexes
            .iter()
            .map(|i| (Bip49DerivationPath::Ethereum(*i), format!("account {i}")))
            .collect();
        let proof = argon2::derive_key(&argon_seed[..PROOF_SIZE]).unwrap();
        let wallet_config = WalletConfig {
            session,
            keychain,
            storage: Rc::clone(&self.storage),
            settings: Default::default(),
        };
        let wallet =
            Wallet::from_bip39_words(&proof, &mnemonic, "", &indexes, wallet_config).unwrap();

        wallet.save_to_storage().unwrap();
        self.wallets.push(wallet);

        hex::encode(key)
    }
}
