use async_trait::async_trait;
pub use bip39::{Language, Mnemonic};

use book::AddressBookEntry;
use cipher::{argon2, keychain::KeyChain};
use config::{
    cipher::{PROOF_SALT, PROOF_SIZE},
    sha::{SHA256_SIZE, SHA512_SIZE},
    storage::{
        ADDRESS_BOOK_DB_KEY, CONNECTIONS_LIST_DB_KEY, CURRENCIES_RATES_DB_KEY,
        GLOBAL_SETTINGS_DB_KEY, INDICATORS_DB_KEY,
    },
};
use connections::Connection;
use crypto::bip49::Bip49DerivationPath;
use device_indicators::create_wallet_device_indicator;
use network::provider::NetworkProvider;
use proto::{keypair::KeyPair, secret_key::SecretKey};
use serde_json::{json, Value};
use session::{decrypt_session, encrypt_session};
use settings::{
    common_settings::CommonSettings,
    locale::Locale,
    notifications::{NotificationState, Notifications},
    theme::Theme,
    wallet_settings::WalletSettings,
};
use std::{collections::HashSet, sync::Arc};
use storage::LocalStorage;
use traits::{
    AddressBookManagement, ConnectionManagement, CryptoOperations, RatesManagement,
    SettingsManagement, StorageManagement, WalletManagement,
};
use wallet::{
    wallet_data::AuthMethod, wallet_types::WalletTypes, Bip39Params, LedgerParams, Wallet,
    WalletAddrType, WalletConfig,
};
use zil_errors::background::BackgroundError;

use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

type Result<T> = std::result::Result<T, BackgroundError>;

pub struct BackgroundBip39Params<'a> {
    pub password: &'a str,
    pub mnemonic_str: &'a str,
    pub passphrase: &'a str,
    pub wallet_name: String,
    pub biometric_type: AuthMethod,
    pub device_indicators: &'a [String],
    pub wallet_settings: WalletSettings,
    pub accounts: &'a [(Bip49DerivationPath, String)],
    pub providers: HashSet<NetworkProvider>,
}

pub struct BackgroundSKParams<'a> {
    pub password: &'a str,
    pub secret_key: &'a SecretKey,
    pub account_name: String,
    pub wallet_name: String,
    pub biometric_type: AuthMethod,
    pub device_indicators: &'a [String],
    pub wallet_settings: WalletSettings,
    pub providers: HashSet<NetworkProvider>,
}

pub struct Background {
    storage: Arc<LocalStorage>,
    pub wallets: Vec<Wallet>,
    pub indicators: Vec<WalletAddrType>,
    pub is_old_storage: bool,
    pub settings: CommonSettings,
}

fn load_global_settings(storage: Arc<LocalStorage>) -> CommonSettings {
    let bytes = storage.get(GLOBAL_SETTINGS_DB_KEY).unwrap_or_default();

    if bytes.is_empty() {
        return CommonSettings::default();
    }

    bincode::deserialize(&bytes).unwrap_or(CommonSettings::default())
}

impl CryptoOperations for Background {
    type Error = BackgroundError;

    fn gen_bip39(count: u8) -> Result<String> {
        if ![12, 15, 18, 21, 24].contains(&count) {
            return Err(BackgroundError::InvalidWordCount(count));
        }

        let entropy_bits = (count as usize * 11) - (count as usize / 3);
        let entropy_bytes = (entropy_bits + 7) / 8;
        let mut rng = ChaCha20Rng::from_entropy();
        let mut entropy = vec![0u8; entropy_bytes];

        rng.fill_bytes(&mut entropy);

        let m = Mnemonic::from_entropy_in(Language::English, &entropy)
            .map_err(|e| BackgroundError::FailToGenBip39FromEntropy(e.to_string()))?;

        Ok(m.to_string())
    }

    fn find_invalid_bip39_words(words: &[String], lang: Language) -> Vec<usize> {
        let word_list = lang.word_list();

        words
            .iter()
            .enumerate()
            .filter(|(_, word)| !word_list.contains(&word.as_str()))
            .map(|(index, _)| index)
            .collect()
    }

    fn gen_keypair() -> Result<(String, String)> {
        let (pub_key, secret_key) =
            KeyPair::gen_keys_bytes().map_err(BackgroundError::FailToGenKeyPair)?;

        Ok((hex::encode(secret_key), hex::encode(pub_key)))
    }
}

impl StorageManagement for Background {
    type Error = BackgroundError;

    fn from_storage_path(path: &str) -> Result<Self> {
        let storage = LocalStorage::from(path)?;
        let storage = Arc::new(storage);
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
        let mut wallets = Vec::new();
        let settings = load_global_settings(Arc::clone(&storage));

        for addr in &indicators {
            let w = Wallet::load_from_storage(addr, Arc::clone(&storage))
                .map_err(BackgroundError::TryLoadWalletError)?;

            wallets.push(w);
        }

        Ok(Self {
            storage,
            wallets,
            indicators,
            is_old_storage,
            settings,
        })
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

impl SettingsManagement for Background {
    type Error = BackgroundError;

    fn load_global_settings(storage: Arc<LocalStorage>) -> CommonSettings {
        let bytes = storage.get(GLOBAL_SETTINGS_DB_KEY).unwrap_or_default();

        if bytes.is_empty() {
            return CommonSettings::default();
        }

        bincode::deserialize(&bytes).unwrap_or(CommonSettings::default())
    }

    fn set_global_notifications(&mut self, global_enabled: bool) -> Result<()> {
        self.settings.notifications.global_enabled = global_enabled;
        self.save_settings()?;

        Ok(())
    }

    fn set_wallet_notifications(
        &mut self,
        wallet_index: usize,
        notification: NotificationState,
    ) -> Result<()> {
        self.settings
            .notifications
            .wallet_states
            .insert(wallet_index, notification);
        self.save_settings()?;

        Ok(())
    }

    fn set_locale(&mut self, new_locale: Locale) -> Result<()> {
        self.settings.locale = new_locale;
        self.save_settings()?;

        Ok(())
    }

    fn set_theme(&mut self, new_theme: Theme) -> Result<()> {
        self.settings.theme = new_theme;
        self.save_settings()?;

        Ok(())
    }

    fn set_notifications(&mut self, new_notifications: Notifications) -> Result<()> {
        self.settings.notifications = new_notifications;
        self.save_settings()?;

        Ok(())
    }

    fn save_settings(&self) -> Result<()> {
        let bytes =
            bincode::serialize(&self.settings).or(Err(BackgroundError::FailToSerializeNetworks))?;

        self.storage.set(GLOBAL_SETTINGS_DB_KEY, &bytes)?;
        self.storage.flush()?;

        Ok(())
    }
}

impl WalletManagement for Background {
    type Error = BackgroundError;

    fn unlock_wallet_with_password(
        &mut self,
        password: &str,
        device_indicators: &[String],
        wallet_index: usize,
    ) -> Result<[u8; SHA512_SIZE]> {
        let wallet = self
            .wallets
            .get_mut(wallet_index)
            .ok_or(BackgroundError::WalletNotExists(wallet_index))?;
        let device_indicator = device_indicators.join(":");
        let argon_seed = argon2::derive_key(
            password.as_bytes(),
            &device_indicator,
            &wallet.data.settings.argon_params.into_config(),
        )
        .map_err(BackgroundError::ArgonPasswordHashError)?;

        wallet
            .unlock(&argon_seed)
            .map_err(BackgroundError::FailUnlockWallet)?;

        Ok(argon_seed)
    }

    fn unlock_wallet_with_session(
        &mut self,
        session_cipher: Vec<u8>,
        device_indicators: &[String],
        wallet_index: usize,
    ) -> Result<[u8; SHA512_SIZE]> {
        let wallet = self
            .wallets
            .get_mut(wallet_index)
            .ok_or(BackgroundError::WalletNotExists(wallet_index))?;

        let wallet_device_indicators =
            create_wallet_device_indicator(&wallet.data.wallet_address, device_indicators);

        let seed_bytes = decrypt_session(
            &wallet_device_indicators,
            session_cipher,
            &wallet.data.settings.cipher_orders,
            &wallet.data.settings.argon_params.into_config(),
        )
        .map_err(BackgroundError::DecryptSessionError)?;

        wallet
            .unlock(&seed_bytes)
            .map_err(BackgroundError::FailUnlockWallet)?;

        Ok(seed_bytes)
    }

    fn add_bip39_wallet(&mut self, params: BackgroundBip39Params) -> Result<Vec<u8>> {
        let device_indicator = params.device_indicators.join(":");
        let argon_seed = argon2::derive_key(
            params.password.as_bytes(),
            &device_indicator,
            &params.wallet_settings.argon_params.into_config(),
        )
        .map_err(BackgroundError::ArgonPasswordHashError)?;
        let keychain =
            KeyChain::from_seed(&argon_seed).map_err(BackgroundError::FailCreateKeychain)?;
        let mnemonic = Mnemonic::parse_in_normalized(bip39::Language::English, params.mnemonic_str)
            .map_err(|e| BackgroundError::FailParseMnemonicWords(e.to_string()))?;
        let proof = argon2::derive_key(
            &argon_seed[..PROOF_SIZE],
            PROOF_SALT,
            &params.wallet_settings.argon_params.into_config(),
        )
        .map_err(BackgroundError::ArgonCreateProofError)?;
        let wallet_config = WalletConfig {
            keychain,
            storage: Arc::clone(&self.storage),
            settings: params.wallet_settings,
        };
        let wallet = Wallet::from_bip39_words(Bip39Params {
            proof: &proof,
            mnemonic: &mnemonic,
            passphrase: params.passphrase,
            indexes: params.accounts,
            config: wallet_config,
            wallet_name: params.wallet_name,
            biometric_type: params.biometric_type,
            providers: params.providers,
        })
        .map_err(BackgroundError::FailToInitWallet)?;
        let wallet_device_indicators =
            create_wallet_device_indicator(&wallet.data.wallet_address, params.device_indicators);

        let session = if wallet.data.biometric_type == AuthMethod::None {
            Vec::new()
        } else {
            encrypt_session(
                &wallet_device_indicators,
                &argon_seed,
                &wallet.data.settings.cipher_orders,
                &wallet.data.settings.argon_params.into_config(),
            )
            .map_err(BackgroundError::CreateSessionError)?
        };

        wallet
            .save_to_storage()
            .map_err(BackgroundError::FailToSaveWallet)?;

        self.indicators.push(wallet.data.wallet_address);
        self.wallets.push(wallet);
        self.save_indicators()?;
        self.storage.flush()?;

        Ok(session)
    }

    fn add_ledger_wallet(
        &mut self,
        params: LedgerParams,
        wallet_settings: WalletSettings,
        device_indicators: &[String],
    ) -> Result<Vec<u8>> {
        if self
            .wallets
            .iter()
            .any(|w| w.data.wallet_type == WalletTypes::Ledger(params.ledger_id.clone()))
        {
            return Err(BackgroundError::LedgerIdExists(
                String::from_utf8(params.ledger_id.clone()).unwrap_or_default(),
            ));
        }

        let device_indicator = device_indicators.join(":");
        let argon_seed = argon2::derive_key(
            device_indicator.as_bytes(),
            &device_indicator,
            &wallet_settings.argon_params.into_config(),
        )
        .map_err(BackgroundError::ArgonPasswordHashError)?;
        let keychain =
            KeyChain::from_seed(&argon_seed).map_err(BackgroundError::FailCreateKeychain)?;
        let proof = argon2::derive_key(
            &argon_seed[..PROOF_SIZE],
            PROOF_SALT,
            &wallet_settings.argon_params.into_config(),
        )
        .map_err(BackgroundError::ArgonCreateProofError)?;
        let wallet_config = WalletConfig {
            keychain,
            storage: Arc::clone(&self.storage),
            settings: wallet_settings,
        };
        let options = &wallet_config.settings.cipher_orders.clone();
        let wallet = Wallet::from_ledger(params, &proof, wallet_config)
            .map_err(BackgroundError::FailToInitWallet)?;

        let device_indicators =
            create_wallet_device_indicator(&wallet.data.wallet_address, device_indicators);
        let session = encrypt_session(
            &device_indicators,
            &argon_seed,
            options,
            &wallet.data.settings.argon_params.into_config(),
        )
        .map_err(BackgroundError::CreateSessionError)?;

        wallet
            .save_to_storage()
            .map_err(BackgroundError::FailToSaveWallet)?;

        self.indicators.push(wallet.data.wallet_address);
        self.wallets.push(wallet);
        self.save_indicators()?;
        self.storage.flush()?;

        Ok(session)
    }

    fn add_sk_wallet(&mut self, params: BackgroundSKParams) -> Result<Vec<u8>> {
        // TODO: check this device_indicators is right or not.
        let device_indicator = params.device_indicators.join(":");
        let argon_seed = argon2::derive_key(
            params.password.as_bytes(),
            &device_indicator,
            &params.wallet_settings.argon_params.into_config(),
        )
        .map_err(BackgroundError::ArgonPasswordHashError)?;
        let keychain =
            KeyChain::from_seed(&argon_seed).map_err(BackgroundError::FailCreateKeychain)?;
        let proof = argon2::derive_key(
            &argon_seed[..PROOF_SIZE],
            PROOF_SALT,
            &params.wallet_settings.argon_params.into_config(),
        )
        .map_err(BackgroundError::ArgonCreateProofError)?;
        let wallet_config = WalletConfig {
            keychain,
            storage: Arc::clone(&self.storage),
            settings: params.wallet_settings,
        };
        let options = &wallet_config.settings.cipher_orders.clone();
        let wallet = Wallet::from_sk(
            params.secret_key,
            params.account_name,
            &proof,
            wallet_config,
            params.wallet_name,
            params.biometric_type,
            params.providers,
        )
        .map_err(BackgroundError::FailToInitWallet)?;

        let wallet_device_indicators =
            create_wallet_device_indicator(&wallet.data.wallet_address, params.device_indicators);
        let session = if wallet.data.biometric_type == AuthMethod::None {
            Vec::new()
        } else {
            encrypt_session(
                &wallet_device_indicators,
                &argon_seed,
                options,
                &wallet.data.settings.argon_params.into_config(),
            )
            .map_err(BackgroundError::CreateSessionError)?
        };

        wallet
            .save_to_storage()
            .map_err(BackgroundError::FailToSaveWallet)?;
        self.indicators.push(wallet.data.wallet_address);
        self.wallets.push(wallet);
        self.save_indicators()?;
        self.storage.flush()?;

        Ok(session)
    }

    fn get_wallet_by_index(&self, wallet_index: usize) -> Result<&Wallet> {
        self.wallets
            .get(wallet_index)
            .ok_or(BackgroundError::WalletNotExists(wallet_index))
    }
}

impl ConnectionManagement for Background {
    type Error = BackgroundError;

    fn get_connections(&self) -> Vec<Connection> {
        let bytes = self
            .storage
            .get(CONNECTIONS_LIST_DB_KEY)
            .unwrap_or_default();

        if bytes.is_empty() {
            return Vec::with_capacity(1);
        }

        bincode::deserialize(&bytes).unwrap_or(Vec::with_capacity(1))
    }

    fn add_wallet_to_connection(&self, domain: String, wallet_index: usize) -> Result<()> {
        let mut connections = self.get_connections();

        let connection = connections
            .iter_mut()
            .find(|c| c.domain == domain)
            .ok_or_else(|| BackgroundError::ConnectionNotFound(domain.clone()))?;

        if self.wallets.get(wallet_index).is_none() {
            return Err(BackgroundError::WalletNotExists(wallet_index));
        }

        connection.add_wallet(wallet_index);
        connection.update_last_connected();

        let bytes = bincode::serialize(&connections)
            .map_err(|e| BackgroundError::FailToSerializeConnections(e.to_string()))?;

        self.storage.set(CONNECTIONS_LIST_DB_KEY, &bytes)?;
        self.storage.flush()?;

        Ok(())
    }

    fn add_connection(&self, connection: Connection) -> Result<()> {
        let mut connections = self.get_connections();

        if connections.iter().any(|c| c.domain == connection.domain) {
            return Err(BackgroundError::ConnectionAlreadyExists(connection.domain));
        }

        connections.push(connection);

        let bytes = bincode::serialize(&connections)
            .map_err(|e| BackgroundError::FailToSerializeConnections(e.to_string()))?;

        self.storage.set(CONNECTIONS_LIST_DB_KEY, &bytes)?;
        self.storage.flush()?;

        Ok(())
    }
}

impl AddressBookManagement for Background {
    type Error = BackgroundError;

    fn get_address_book(&self) -> Vec<AddressBookEntry> {
        let bytes = self.storage.get(ADDRESS_BOOK_DB_KEY).unwrap_or_default();

        if bytes.is_empty() {
            return Vec::with_capacity(1);
        }

        bincode::deserialize(&bytes).unwrap_or(Vec::with_capacity(1))
    }

    fn add_to_address_book(&self, address: AddressBookEntry) -> Result<()> {
        let mut book = self.get_address_book();

        if book.iter().any(|c| c.addr == address.addr) {
            return Err(BackgroundError::AddressAlreadyExists(
                address.addr.auto_format(),
            ));
        }

        book.push(address);

        let bytes =
            bincode::serialize(&book).or(Err(BackgroundError::FailToSerializeAddressBook))?;

        self.storage.set(ADDRESS_BOOK_DB_KEY, &bytes)?;
        self.storage.flush()?;

        Ok(())
    }
}

#[async_trait]
impl RatesManagement for Background {
    type Error = BackgroundError;

    async fn update_rates(&self) -> Result<Value> {
        // TODO: remake this method with timestamp and struct.
        // let rates = fetch_rates()
        //     .await
        //     .map_err(BackgroundError::NetworkErrors)?;
        // let bytes =
        //     serde_json::to_vec(&json!([])).or(Err(BackgroundError::FailToSerializeRates))?;

        // self.storage
        //     .set(CURRENCIES_RATES_DB_KEY, &bytes)
        //     .map_err(BackgroundError::FailToWriteIndicatorsWallet)?;
        // self.storage
        //     .flush()
        //     .map_err(BackgroundError::LocalStorageFlushError)?;

        Ok(json!([]))
    }

    fn get_rates(&self) -> Value {
        let bytes = self
            .storage
            .get(CURRENCIES_RATES_DB_KEY)
            .unwrap_or_default();

        if bytes.is_empty() {
            // TODO: remake it with struct and timestamp.
            return json!([]);
        }

        serde_json::from_slice(&bytes).unwrap_or(json!([]))
    }
}

pub mod book;
pub mod connections;
pub mod device_indicators;
pub mod traits;

#[cfg(test)]
mod tests_background {
    use super::*;
    use config::{
        argon::KEY_SIZE,
        key::{PUB_KEY_SIZE, SECRET_KEY_SIZE},
    };
    use connections::DAppColors;
    use proto::{address::Address, keypair::KeyPair};
    use rand::Rng;
    use session::decrypt_session;

    fn setup_test_background() -> (Background, String) {
        let mut rng = rand::thread_rng();
        let dir = format!("/tmp/{}", rng.gen::<usize>());
        let bg = Background::from_storage_path(&dir).unwrap();
        (bg, dir)
    }

    #[test]
    fn test_bip39_words_exists() {
        let words: Vec<String> =
            "area scale vital sell radio pattern not_exits_word mean similar picnic grain gain"
                .split(" ")
                .map(|v| v.to_string())
                .collect();

        let not_exists_ids = Background::find_invalid_bip39_words(&words, Language::English);

        assert_eq!(not_exists_ids, vec![6])
    }

    #[test]
    fn test_add_more_wallets_bip39() {
        let (mut bg, dir) = setup_test_background();

        assert_eq!(bg.wallets.len(), 0);

        let password = "test_password";
        let words: &str =
            "area scale vital sell radio pattern poverty mean similar picnic grain gain";
        let accounts = [(Bip49DerivationPath::Zilliqa(0), "Name".to_string())];

        let _key = bg
            .add_bip39_wallet(BackgroundBip39Params {
                password,
                providers: HashSet::new(),
                mnemonic_str: words,
                accounts: &accounts,
                wallet_settings: Default::default(),
                passphrase: "",
                wallet_name: String::new(),
                biometric_type: Default::default(),
                device_indicators: &[String::from("apple"), String::from("0000")],
            })
            .unwrap();

        assert_eq!(bg.wallets.len(), 1);

        drop(bg);

        let mut bg = Background::from_storage_path(&dir).unwrap();

        let _key = bg
            .add_bip39_wallet(BackgroundBip39Params {
                password,
                providers: HashSet::new(),
                mnemonic_str: words,
                accounts: &accounts,
                wallet_settings: Default::default(),
                passphrase: "",
                wallet_name: String::new(),
                biometric_type: Default::default(),
                device_indicators: &[String::from("apple"), String::from("1102")],
            })
            .unwrap();

        let password = "test_password";
        let words: &str =
            "clap chair edit noise sugar box raccoon play another hobby soccer fringe";
        let accounts = [
            (Bip49DerivationPath::Zilliqa(0), "Name".to_string()),
            (Bip49DerivationPath::Zilliqa(1), "account 1".to_string()),
        ];

        let _key = bg
            .add_bip39_wallet(BackgroundBip39Params {
                password,
                providers: HashSet::new(),
                accounts: &accounts,
                mnemonic_str: words,
                wallet_settings: Default::default(),
                passphrase: "",
                wallet_name: String::new(),
                device_indicators: &[String::from("apple"), String::from("43498")],
                biometric_type: Default::default(),
            })
            .unwrap();

        drop(bg);

        let bg = Background::from_storage_path(&dir).unwrap();

        assert_eq!(bg.wallets.len(), 3);
    }

    #[test]
    fn test_from_bip39() {
        let (mut bg, dir) = setup_test_background();

        assert_eq!(bg.wallets.len(), 0);

        let password = "test_password";
        let words: &str =
            "green process gate doctor slide whip priority shrug diamond crumble average help";
        let accounts = [
            (Bip49DerivationPath::Zilliqa(0), "Account 0".to_string()),
            (Bip49DerivationPath::Zilliqa(1), "Account 1".to_string()),
            (Bip49DerivationPath::Zilliqa(2), "Account 2".to_string()),
            (Bip49DerivationPath::Zilliqa(3), "Account 3".to_string()),
            (Bip49DerivationPath::Zilliqa(4), "Account 4".to_string()),
            (Bip49DerivationPath::Zilliqa(5), "Account 5".to_string()),
            (Bip49DerivationPath::Zilliqa(6), "Account 6".to_string()),
            (Bip49DerivationPath::Zilliqa(7), "Account 7".to_string()),
        ];
        let device_indicators = [String::from("apple"), String::from("4354")];

        let session = bg
            .add_bip39_wallet(BackgroundBip39Params {
                device_indicators: &device_indicators,
                password,
                mnemonic_str: words,
                accounts: &accounts,
                wallet_settings: Default::default(),
                passphrase: "",
                wallet_name: String::new(),
                biometric_type: AuthMethod::FaceId,
                providers: HashSet::new(),
            })
            .unwrap();

        assert_eq!(bg.wallets.len(), 1);

        drop(bg);

        let mut bg = Background::from_storage_path(&dir).unwrap();
        let wallet = bg.wallets.first_mut().unwrap();

        let wallet_device_indicators =
            create_wallet_device_indicator(&wallet.data.wallet_address, &device_indicators);

        let seed_bytes = decrypt_session(
            &wallet_device_indicators,
            session,
            &wallet.data.settings.cipher_orders,
            &wallet.data.settings.argon_params.into_config(),
        )
        .unwrap();

        assert_eq!(
            wallet.unlock(&[42u8; KEY_SIZE]),
            Err(zil_errors::wallet::WalletErrors::KeyChainFailToGetProof)
        );

        wallet.unlock(&seed_bytes).unwrap();

        let res_words = wallet.reveal_mnemonic(&seed_bytes).unwrap().to_string();

        assert_eq!(res_words, words);

        let keypair = wallet.reveal_keypair(1, &seed_bytes, None).unwrap();
        let sk = keypair.get_secretkey().unwrap();

        assert_eq!(
            sk.to_string(),
            "00fe8b8ee252f3d1348ca68c8537cb4d26a44826abe12a227df3b5db47bf6e0fe3"
        );
    }

    #[test]
    fn test_from_ledger() {
        let mut rng = rand::thread_rng();
        let (mut bg, dir) = setup_test_background();

        let mut ledger_id = vec![0u8; 32];

        rng.fill_bytes(&mut ledger_id);

        assert_eq!(bg.wallets.len(), 0);

        let device_indicators = [String::from("android"), String::from("4354")];
        let keypair = KeyPair::gen_sha256().unwrap();
        let pub_key = keypair.get_pubkey().unwrap();

        let session = bg
            .add_ledger_wallet(
                LedgerParams {
                    pub_key: &pub_key,
                    name: String::from("account 0"),
                    ledger_id,

                    wallet_index: 0,
                    wallet_name: String::from("Ledger nano x"),
                    biometric_type: AuthMethod::FaceId,
                    providers: HashSet::new(),
                },
                Default::default(),
                &device_indicators,
            )
            .unwrap();

        assert_eq!(bg.wallets.len(), 1);

        drop(bg);

        let mut bg = Background::from_storage_path(&dir).unwrap();

        bg.unlock_wallet_with_session(session.clone(), &device_indicators, 0)
            .unwrap();

        let wallet = bg.wallets.first_mut().unwrap();
        assert_eq!(
            wallet.unlock(&[42u8; KEY_SIZE]),
            Err(zil_errors::wallet::WalletErrors::KeyChainFailToGetProof)
        );
    }

    #[test]
    fn test_2_same_ledger() {
        let (mut bg, _dir) = setup_test_background();
        let ledger_id = "ledger_id".as_bytes().to_vec();

        assert_eq!(bg.wallets.len(), 0);

        let device_indicators = [String::from("android"), String::from("4354")];
        let keypair = KeyPair::gen_sha256().unwrap();
        let pub_key = keypair.get_pubkey().unwrap();

        bg.add_ledger_wallet(
            LedgerParams {
                pub_key: &pub_key,
                name: String::from("account 0"),
                ledger_id: ledger_id.clone(),
                wallet_index: 0,
                wallet_name: String::from("Ledger nano x"),
                biometric_type: AuthMethod::FaceId,
                providers: HashSet::new(),
            },
            Default::default(),
            &device_indicators,
        )
        .unwrap();

        assert_eq!(
            bg.add_ledger_wallet(
                LedgerParams {
                    pub_key: &pub_key,
                    name: String::from("account 0"),
                    ledger_id: ledger_id.clone(),
                    wallet_index: 0,
                    wallet_name: String::from("Ledger nano x"),
                    providers: HashSet::new(),
                    biometric_type: AuthMethod::FaceId,
                },
                Default::default(),
                &device_indicators,
            ),
            Err(BackgroundError::LedgerIdExists(
                String::from_utf8(ledger_id).unwrap()
            ))
        )
    }

    #[test]
    fn test_from_sk() {
        let (mut bg, dir) = setup_test_background();

        assert_eq!(bg.wallets.len(), 0);

        let password = "pass";
        let keypair = KeyPair::gen_sha256().unwrap();
        let sk = keypair.get_secretkey().unwrap();
        let name = "SK Account 0".to_string();
        let device_indicators = vec![String::from("test"), String::from("0543543")];
        let session = bg
            .add_sk_wallet(BackgroundSKParams {
                providers: HashSet::new(),
                password,
                secret_key: &sk,
                account_name: name,
                wallet_settings: Default::default(),
                wallet_name: "test_wallet name".to_string(),
                biometric_type: AuthMethod::Fingerprint,
                device_indicators: &device_indicators,
            })
            .unwrap();

        assert_eq!(bg.wallets.len(), 1);

        drop(bg);
        let mut bg = Background::from_storage_path(&dir).unwrap();
        let wallet = bg.wallets.first_mut().unwrap();
        let wallet_device_indicators =
            create_wallet_device_indicator(&wallet.data.wallet_address, &device_indicators);

        let seed_bytes = decrypt_session(
            &wallet_device_indicators,
            session,
            &wallet.data.settings.cipher_orders,
            &wallet.data.settings.argon_params.into_config(),
        )
        .unwrap();

        assert_eq!(
            wallet.reveal_mnemonic(&seed_bytes),
            Err(zil_errors::wallet::WalletErrors::InvalidAccountType)
        );
        assert_eq!(
            wallet.unlock(&[42u8; KEY_SIZE]),
            Err(zil_errors::wallet::WalletErrors::KeyChainFailToGetProof)
        );

        wallet.unlock(&seed_bytes).unwrap();

        let res_keypair = wallet.reveal_keypair(0, &seed_bytes, None).unwrap();

        assert_eq!(res_keypair, keypair);
    }

    #[test]
    fn test_bip39_gen() {
        let words = Background::gen_bip39(12).unwrap();
        assert_eq!(words.split(" ").collect::<Vec<&str>>().len(), 12);

        let words = Background::gen_bip39(15).unwrap();
        assert_eq!(words.split(" ").collect::<Vec<&str>>().len(), 15);

        let words = Background::gen_bip39(18).unwrap();
        assert_eq!(words.split(" ").collect::<Vec<&str>>().len(), 18);

        let words = Background::gen_bip39(21).unwrap();
        assert_eq!(words.split(" ").collect::<Vec<&str>>().len(), 21);

        let words = Background::gen_bip39(24).unwrap();
        assert_eq!(words.split(" ").collect::<Vec<&str>>().len(), 24);

        assert_eq!(
            Background::gen_bip39(33 /* wrong number */),
            Err(BackgroundError::InvalidWordCount(33))
        );
    }

    #[test]
    fn test_keypair_gen() {
        let (sk, pk) = Background::gen_keypair().unwrap();

        assert_eq!(hex::decode(sk).unwrap().len(), SECRET_KEY_SIZE);
        assert_eq!(hex::decode(pk).unwrap().len(), PUB_KEY_SIZE);
    }

    #[test]
    fn test_address_book() {
        let (bg, dir) = setup_test_background();
        // Test empty address book
        let book = bg.get_address_book();
        assert!(book.is_empty());

        // Create test address
        let name = "Test Contact".to_string();
        let address =
            Address::from_eth_address("0x1234567890123456789012345678901234567890").unwrap();
        let entry = AddressBookEntry {
            name,
            addr: address.clone(),
            net: 0,
        };

        // Add address to book
        bg.add_to_address_book(entry.clone()).unwrap();

        // Verify address was added
        let book = bg.get_address_book();
        assert_eq!(book.len(), 1);
        assert_eq!(&book[0].name, "Test Contact");
        assert_eq!(&book[0].addr, &address);
        // Add another address
        let name2 = "Second Contact".to_string();
        let address2 =
            Address::from_eth_address("0xabcdefabcdefabcdefabcdefabcdefabcdefabcd").unwrap();
        let entry2 = AddressBookEntry {
            name: name2,
            addr: address2.clone(),
            net: 0,
        };

        bg.add_to_address_book(entry2.clone()).unwrap();

        // Verify both addresses exist
        let book = bg.get_address_book();
        assert_eq!(book.len(), 2);
        assert_eq!(book[1].name, "Second Contact");
        assert_eq!(book[1].addr, address2);

        // Test persistence - create new instance
        drop(bg);
        let bg2 = Background::from_storage_path(&dir).unwrap();
        let book = bg2.get_address_book();

        assert_eq!(book.len(), 2);
        assert_eq!(book[0].name, "Test Contact");
        assert_eq!(book[0].addr, address);
        assert_eq!(book[1].name, "Second Contact");
        assert_eq!(book[1].addr, address2);
    }

    #[test]
    fn test_connections_storage() {
        let (bg, dir) = setup_test_background();

        // Test empty connections
        let connections = bg.get_connections();
        assert!(connections.is_empty());

        // Create test connection
        let colors = DAppColors {
            primary: "#000000".to_string(),
            secondary: Some("#FFFFFF".to_string()),
            background: None,
            text: None,
        };

        let connection = Connection::new(
            "example.com".to_string(),
            0,
            "Example DApp".to_string(),
            Some(colors),
        );

        // Add connection
        bg.add_connection(connection.clone()).unwrap();

        // Try to add duplicate connection

        assert_eq!(
            bg.add_connection(connection.clone()),
            Err(BackgroundError::ConnectionAlreadyExists(
                "example.com".to_string()
            ))
        );

        // Verify first connection
        let connections = bg.get_connections();
        assert_eq!(connections.len(), 1);
        let first_conn = &connections[0];
        assert_eq!(first_conn.domain, "example.com");
        assert_eq!(first_conn.title, "Example DApp");

        // Test persistence
        drop(bg);
        let bg2 = Background::from_storage_path(&dir).unwrap();
        let loaded_connections = bg2.get_connections();

        assert_eq!(loaded_connections.len(), 1);
        let loaded_conn = &loaded_connections[0];
        assert_eq!(loaded_conn.domain, "example.com");
        assert_eq!(loaded_conn.title, "Example DApp");
        assert!(loaded_conn.colors.is_some());
        assert!(loaded_conn.is_wallet_connected(0));
    }

    #[test]
    fn test_add_wallet_to_connection() {
        let (mut bg, dir) = setup_test_background();

        assert_eq!(bg.wallets.len(), 0);

        let password = "test_password";
        let words: &str =
            "area scale vital sell radio pattern poverty mean similar picnic grain gain";
        let accounts = [
            (Bip49DerivationPath::Zilliqa(0), "first".to_string()),
            (Bip49DerivationPath::Zilliqa(1), "second".to_string()),
        ];

        bg.add_bip39_wallet(BackgroundBip39Params {
            password,
            providers: HashSet::new(),
            mnemonic_str: words,
            accounts: &accounts,
            wallet_settings: Default::default(),
            passphrase: "",
            wallet_name: String::new(),
            biometric_type: Default::default(),
            device_indicators: &[String::from("apple"), String::from("0000")],
        })
        .unwrap();

        assert_eq!(bg.wallets.len(), 1);

        let device_indicators = [String::from("android"), String::from("4354")];
        let keypair = KeyPair::gen_sha256().unwrap();
        let pub_key = keypair.get_pubkey().unwrap();
        let mut ledger_id = vec![0u8; 32];

        let mut rng = rand::thread_rng();
        rng.fill_bytes(&mut ledger_id);

        bg.add_ledger_wallet(
            LedgerParams {
                providers: HashSet::new(),
                pub_key: &pub_key,
                name: String::from("account 0"),
                ledger_id,
                wallet_index: 0,
                wallet_name: String::from("Ledger nano x"),
                biometric_type: AuthMethod::FaceId,
            },
            Default::default(),
            &device_indicators,
        )
        .unwrap();

        drop(bg);

        let bg = Background::from_storage_path(&dir).unwrap();

        // Create and add initial connection
        let connection = Connection::new(
            "example.com".to_string(),
            0,
            "Example DApp".to_string(),
            None,
        );
        bg.add_connection(connection).unwrap();

        // Add new wallet to connection
        bg.add_wallet_to_connection("example.com".to_string(), 1)
            .unwrap();

        // Verify wallet was added
        let connections = bg.get_connections();
        assert_eq!(connections.len(), 1);
        let updated_conn = &connections[0];

        assert!(updated_conn.is_wallet_connected(0));
        assert!(updated_conn.is_wallet_connected(1));

        // Test adding wallet to non-existent connection
        match bg.add_wallet_to_connection("nonexistent.com".to_string(), 1) {
            Err(BackgroundError::ConnectionNotFound(domain)) => {
                assert_eq!(domain, "nonexistent.com");
            }
            _ => panic!("Expected ConnectionNotFound error"),
        }

        // Test persistence
        drop(bg);
        let bg2 = Background::from_storage_path(&dir).unwrap();
        let loaded_connections = bg2.get_connections();

        assert_eq!(loaded_connections.len(), 1);
        let loaded_conn = &loaded_connections[0];
        assert!(loaded_conn.is_wallet_connected(0));
        assert!(loaded_conn.is_wallet_connected(1));
    }
}
