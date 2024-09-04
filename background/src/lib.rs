use bip39::Mnemonic;
use cipher::{argon2, keychain::KeyChain};
use config::{cipher::PROOF_SIZE, sha::SHA256_SIZE};
use crypto::bip49::Bip49DerivationPath;
use session::Session;
use settings::common_settings::CommonSettings;
use storage::LocalStorage;
use wallet::{Wallet, WalletConfig};
use zil_errors::ZilliqaErrors;

pub struct Background<'a> {
    storage: LocalStorage,
    pub wallets: Vec<Wallet<'a>>,
    pub selected: usize,
    pub indicators: Vec<[u8; SHA256_SIZE]>,
    pub is_old_storage: bool,
    pub settings: CommonSettings,
}

impl<'a> Background<'a> {
    pub fn from_storage_path<'b>(path: &str) -> Result<Self, ZilliqaErrors<'b>> {
        let storage = LocalStorage::from(path).map_err(ZilliqaErrors::TryInitLocalStorageError)?;
        let is_old_storage = false; // TODO: check old storage from first ZilPay version

        Ok(Self {
            storage,
            wallets: Vec::new(),
            selected: 0,
            indicators: Vec::new(),
            is_old_storage,
            settings: Default::default(),
        })
    }

    pub fn wallet_from_bip39(&'a mut self, password: &str, mnemonic_str: &str, indexes: &[usize]) {
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
            storage: &self.storage,
            settings: Default::default(),
        };
        let wallet =
            Wallet::from_bip39_words(&proof, &mnemonic, "", &indexes, wallet_config).unwrap();

        self.wallets.push(wallet)
    }
}
