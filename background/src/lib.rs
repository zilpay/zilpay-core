pub use bip39::{Language, Mnemonic};

use cipher::{argon2, keychain::KeyChain};
use config::{
    cipher::{PROOF_SALT, PROOF_SIZE},
    sha::{SHA256_SIZE, SHA512_SIZE},
    storage::{INDICATORS_DB_KEY, NETWORK_DB_KEY},
};
use crypto::bip49::Bip49DerivationPath;
use network::provider::NetworkProvider;
use proto::{address::Address, keypair::KeyPair, secret_key::SecretKey};
use session::{decrypt_session, encrypt_session};
use settings::common_settings::CommonSettings;
use std::sync::Arc;
use storage::LocalStorage;
use wallet::{
    ft::FToken, wallet_data::AuthMethod, wallet_types::WalletTypes, Bip39Params, LedgerParams,
    Wallet, WalletConfig,
};
use zil_errors::{background::BackgroundError, network::NetworkErrors};

use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

pub struct BackgroundBip39Params<'a> {
    pub password: &'a str,
    pub mnemonic_str: &'a str,
    pub passphrase: &'a str,
    pub wallet_name: String,
    pub biometric_type: AuthMethod,
    pub device_indicators: &'a [String],
    pub network: &'a [usize],
    pub accounts: &'a [(Bip49DerivationPath, String)],
}

pub struct BackgroundSKParams<'a> {
    pub password: &'a str,
    pub secret_key: &'a SecretKey,
    pub account_name: String,
    pub wallet_name: String,
    pub biometric_type: AuthMethod,
    pub device_indicators: &'a [String],
    pub network: Vec<usize>,
}

pub struct Background {
    storage: Arc<LocalStorage>,
    pub wallets: Vec<Wallet>,
    pub indicators: Vec<[u8; SHA256_SIZE]>,
    pub is_old_storage: bool,
    pub settings: CommonSettings,
    pub netowrk: Vec<NetworkProvider>,
}

fn load_network(storage: Arc<LocalStorage>) -> Vec<NetworkProvider> {
    let bytes = storage.get(NETWORK_DB_KEY).unwrap_or_default();

    if bytes.is_empty() {
        return NetworkProvider::new_vec();
    }

    serde_json::from_slice(&bytes).unwrap_or(NetworkProvider::new_vec())
}

impl Background {
    pub fn gen_bip39(count: u8) -> Result<String, BackgroundError> {
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

    pub fn find_invalid_bip39_words(words: &[String], lang: Language) -> Vec<usize> {
        let word_list = lang.word_list();

        words
            .iter()
            .enumerate()
            .filter(|(_, word)| !word_list.contains(&word.as_str()))
            .map(|(index, _)| index)
            .collect()
    }

    pub fn gen_keypair() -> Result<(String, String), BackgroundError> {
        let (pub_key, secret_key) =
            KeyPair::gen_keys_bytes().map_err(BackgroundError::FailToGenKeyPair)?;

        Ok((hex::encode(secret_key), hex::encode(pub_key)))
    }
}

impl Background {
    pub fn from_storage_path(path: &str) -> Result<Self, BackgroundError> {
        let storage =
            LocalStorage::from(path).map_err(BackgroundError::TryInitLocalStorageError)?;
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
        let netowrk = load_network(Arc::clone(&storage));

        for addr in &indicators {
            let w = Wallet::load_from_storage(addr, Arc::clone(&storage))
                .map_err(BackgroundError::TryLoadWalletError)?;

            wallets.push(w);
        }

        Ok(Self {
            netowrk,
            storage,
            wallets,
            indicators,
            is_old_storage,
            settings: Default::default(),
        })
    }

    pub fn unlock_wallet_with_password(
        &mut self,
        password: &str,
        device_indicators: &[String],
        wallet_index: usize,
    ) -> Result<[u8; SHA512_SIZE], BackgroundError> {
        let device_indicator = device_indicators.join(":");
        let argon_seed = argon2::derive_key(password.as_bytes(), &device_indicator)
            .map_err(BackgroundError::ArgonPasswordHashError)?;
        let wallet = self
            .wallets
            .get_mut(wallet_index)
            .ok_or(BackgroundError::WalletNotExists(wallet_index))?;

        wallet
            .unlock(&argon_seed)
            .map_err(BackgroundError::FailUnlockWallet)?;

        Ok(argon_seed)
    }

    pub fn unlock_wallet_with_session(
        &mut self,
        session_cipher: Vec<u8>,
        device_indicators: &[String],
        wallet_index: usize,
    ) -> Result<[u8; SHA512_SIZE], BackgroundError> {
        let wallet = self
            .wallets
            .get_mut(wallet_index)
            .ok_or(BackgroundError::WalletNotExists(wallet_index))?;
        let wallet_device_indicators = std::iter::once(wallet.data.wallet_address.clone())
            .chain(device_indicators.iter().cloned())
            .collect::<Vec<_>>()
            .join(":");

        let seed_bytes = decrypt_session(
            &wallet_device_indicators,
            session_cipher,
            &wallet.data.settings.cipher_orders,
        )
        .map_err(BackgroundError::DecryptSessionError)?;

        wallet
            .unlock(&seed_bytes)
            .map_err(BackgroundError::FailUnlockWallet)?;

        Ok(seed_bytes)
    }

    pub fn add_bip39_wallet(
        &mut self,
        params: BackgroundBip39Params,
    ) -> Result<Vec<u8>, BackgroundError> {
        let device_indicator = params.device_indicators.join(":");
        let argon_seed = argon2::derive_key(params.password.as_bytes(), &device_indicator)
            .map_err(BackgroundError::ArgonPasswordHashError)?;
        let keychain =
            KeyChain::from_seed(&argon_seed).map_err(BackgroundError::FailCreateKeychain)?;
        let mnemonic = Mnemonic::parse_in_normalized(bip39::Language::English, params.mnemonic_str)
            .map_err(|e| BackgroundError::FailParseMnemonicWords(e.to_string()))?;
        let proof = argon2::derive_key(&argon_seed[..PROOF_SIZE], PROOF_SALT)
            .map_err(BackgroundError::ArgonCreateProofError)?;
        let wallet_config = WalletConfig {
            keychain,
            storage: Arc::clone(&self.storage),
            settings: Default::default(), // TODO: setup settings
        };
        let options = &wallet_config.settings.cipher_orders.clone();
        let wallet = Wallet::from_bip39_words(Bip39Params {
            proof: &proof,
            mnemonic: &mnemonic,
            passphrase: params.passphrase,
            indexes: params.accounts,
            config: wallet_config,
            wallet_name: params.wallet_name,
            biometric_type: params.biometric_type,
            network: params.network,
        })
        .map_err(BackgroundError::FailToInitWallet)?;
        let indicator = wallet.key().map_err(BackgroundError::FailToInitWallet)?;
        let device_indicator = std::iter::once(hex::encode(indicator))
            .chain(params.device_indicators.iter().cloned())
            .collect::<Vec<_>>()
            .join(":");

        let session = if wallet.data.biometric_type == AuthMethod::None {
            Vec::new()
        } else {
            encrypt_session(&device_indicator, &argon_seed, options)
                .map_err(BackgroundError::CreateSessionError)?
        };

        wallet
            .save_to_storage()
            .map_err(BackgroundError::FailToSaveWallet)?;

        self.indicators.push(indicator);
        self.wallets.push(wallet);
        self.save_indicators()?;
        self.storage
            .flush()
            .map_err(BackgroundError::LocalStorageFlushError)?;

        Ok(session)
    }

    pub fn add_ledger_wallet(
        &mut self,
        params: LedgerParams,
        device_indicators: &[String],
    ) -> Result<Vec<u8>, BackgroundError> {
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
        let argon_seed = argon2::derive_key(device_indicator.as_bytes(), &device_indicator)
            .map_err(BackgroundError::ArgonPasswordHashError)?;
        let keychain =
            KeyChain::from_seed(&argon_seed).map_err(BackgroundError::FailCreateKeychain)?;
        let proof = argon2::derive_key(&argon_seed[..PROOF_SIZE], PROOF_SALT)
            .map_err(BackgroundError::ArgonCreateProofError)?;
        let wallet_config = WalletConfig {
            keychain,
            storage: Arc::clone(&self.storage),
            settings: Default::default(), // TODO: setup settings
        };
        let options = &wallet_config.settings.cipher_orders.clone();
        let wallet = Wallet::from_ledger(params, &proof, wallet_config)
            .map_err(BackgroundError::FailToInitWallet)?;
        let indicator = wallet.key().map_err(BackgroundError::FailToInitWallet)?;
        let device_indicator = std::iter::once(hex::encode(indicator))
            .chain(device_indicators.iter().cloned())
            .collect::<Vec<_>>()
            .join(":");
        let session = encrypt_session(&device_indicator, &argon_seed, options)
            .map_err(BackgroundError::CreateSessionError)?;

        wallet
            .save_to_storage()
            .map_err(BackgroundError::FailToSaveWallet)?;

        self.indicators.push(indicator);
        self.wallets.push(wallet);
        self.save_indicators()?;
        self.storage
            .flush()
            .map_err(BackgroundError::LocalStorageFlushError)?;

        Ok(session)
    }

    pub fn add_sk_wallet(
        &mut self,
        params: BackgroundSKParams,
    ) -> Result<Vec<u8>, BackgroundError> {
        let device_indicator = params.device_indicators.join(":");
        let argon_seed = argon2::derive_key(params.password.as_bytes(), &device_indicator)
            .map_err(BackgroundError::ArgonPasswordHashError)?;
        let keychain =
            KeyChain::from_seed(&argon_seed).map_err(BackgroundError::FailCreateKeychain)?;
        let proof = argon2::derive_key(&argon_seed[..PROOF_SIZE], PROOF_SALT)
            .map_err(BackgroundError::ArgonCreateProofError)?;
        let wallet_config = WalletConfig {
            keychain,
            storage: Arc::clone(&self.storage),
            settings: Default::default(), // TODO: setup settings
        };
        let options = &wallet_config.settings.cipher_orders.clone();
        let wallet = Wallet::from_sk(
            params.secret_key,
            params.account_name,
            &proof,
            wallet_config,
            params.wallet_name,
            params.biometric_type,
            params.network,
        )
        .map_err(BackgroundError::FailToInitWallet)?;

        let indicator = wallet.key().map_err(BackgroundError::FailToInitWallet)?;
        let device_indicator = std::iter::once(hex::encode(indicator))
            .chain(params.device_indicators.iter().cloned())
            .collect::<Vec<_>>()
            .join(":");

        let session = if wallet.data.biometric_type == AuthMethod::None {
            Vec::new()
        } else {
            encrypt_session(&device_indicator, &argon_seed, options)
                .map_err(BackgroundError::CreateSessionError)?
        };

        wallet
            .save_to_storage()
            .map_err(BackgroundError::FailToSaveWallet)?;
        self.indicators.push(indicator);
        self.wallets.push(wallet);
        self.save_indicators()?;
        self.storage
            .flush()
            .map_err(BackgroundError::LocalStorageFlushError)?;

        Ok(session)
    }

    pub async fn update_nodes(&mut self, id: usize) -> Result<(), BackgroundError> {
        let net_pointer = self
            .netowrk
            .get_mut(id)
            .ok_or(BackgroundError::NetworkProviderNotExists(id))?;

        net_pointer
            .update_nodes()
            .await
            .map_err(BackgroundError::NetworkErrors)?;

        self.save_network()?;
        self.storage
            .flush()
            .map_err(BackgroundError::LocalStorageFlushError)?;

        Ok(())
    }

    pub async fn get_ftoken_meta(
        &self,
        wallet_index: usize,
        contract: Address,
    ) -> Result<FToken, BackgroundError> {
        let w = self
            .wallets
            .get(wallet_index)
            .ok_or(BackgroundError::WalletNotExists(wallet_index))?;
        let accounts = w
            .data
            .accounts
            .iter()
            .map(|a| a.addr.clone())
            .collect::<Vec<Address>>();
        let mut error: NetworkErrors = NetworkErrors::ResponseParseError;

        for net_id in &w.data.network {
            match self
                .netowrk
                .get(*net_id)
                .ok_or(BackgroundError::NetworkProviderNotExists(*net_id))?
                .get_ftoken_meta(&contract, &accounts)
                .await
            {
                Ok(meta) => {
                    return Ok(meta);
                }
                Err(e) => {
                    error = e;
                    continue;
                }
            }
        }

        Err(BackgroundError::NetworkErrors(error))
    }

    pub async fn sync_ftokens_balances(
        &mut self,
        wallet_index: usize,
    ) -> Result<(), BackgroundError> {
        let w = self
            .wallets
            .get_mut(wallet_index)
            .ok_or(BackgroundError::WalletNotExists(wallet_index))?;

        if w.ftokens.is_empty() {
            return Err(BackgroundError::FailUnlockWallet(
                zil_errors::wallet::WalletErrors::KeyChainFailToGetProof,
            ));
        }

        let addresses = w
            .data
            .accounts
            .iter()
            .map(|a| a.addr.clone())
            .collect::<Vec<Address>>();

        for net_id in &w.data.network {
            self.netowrk
                .get_mut(*net_id)
                .ok_or(BackgroundError::NetworkProviderNotExists(*net_id))?
                .get_tokens_balances(&mut w.ftokens, &addresses)
                .await
                .map_err(BackgroundError::NetworkErrors)?;
        }

        w.save_to_storage()
            .map_err(BackgroundError::FailToSaveWallet)?;
        self.storage
            .flush()
            .map_err(BackgroundError::LocalStorageFlushError)?;

        Ok(())
    }

    fn save_network(&self) -> Result<(), BackgroundError> {
        let bytes =
            serde_json::to_vec(&self.netowrk).or(Err(BackgroundError::FailToSerializeNetworks))?;

        self.storage
            .set(NETWORK_DB_KEY, &bytes)
            .map_err(BackgroundError::FailToWriteIndicatorsWallet)?;

        Ok(())
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
}

#[cfg(test)]
mod tests_background {
    use super::*;
    use config::{
        argon::KEY_SIZE,
        key::{PUB_KEY_SIZE, SECRET_KEY_SIZE},
    };
    use proto::keypair::KeyPair;
    use rand::Rng;
    use session::decrypt_session;

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
        let mut rng = rand::thread_rng();
        let dir = format!("/tmp/{}", rng.gen::<usize>());
        let mut bg = Background::from_storage_path(&dir).unwrap();

        assert_eq!(bg.wallets.len(), 0);

        let password = "test_password";
        let words: &str =
            "area scale vital sell radio pattern poverty mean similar picnic grain gain";
        let accounts = [(Bip49DerivationPath::Zilliqa(0), "Name".to_string())];
        let network = [0];

        let _key = bg
            .add_bip39_wallet(BackgroundBip39Params {
                password,
                network: &network,
                mnemonic_str: words,
                accounts: &accounts,
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
                network: &network,
                mnemonic_str: words,
                accounts: &accounts,
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
                network: &network,
                accounts: &accounts,
                mnemonic_str: words,
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
        let mut rng = rand::thread_rng();
        let dir = format!("/tmp/{}", rng.gen::<usize>());
        let mut bg = Background::from_storage_path(&dir).unwrap();

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
        let network = [0];

        let session = bg
            .add_bip39_wallet(BackgroundBip39Params {
                device_indicators: &device_indicators,
                password,
                mnemonic_str: words,
                accounts: &accounts,
                passphrase: "",
                wallet_name: String::new(),
                biometric_type: AuthMethod::FaceId,
                network: &network,
            })
            .unwrap();

        assert_eq!(bg.wallets.len(), 1);

        drop(bg);

        let mut bg = Background::from_storage_path(&dir).unwrap();
        let wallet = bg.wallets.first_mut().unwrap();

        let wallet_device_indicators = std::iter::once(wallet.data.wallet_address.clone())
            .chain(device_indicators)
            .collect::<Vec<_>>()
            .join(":");

        let seed_bytes = decrypt_session(
            &wallet_device_indicators,
            session,
            &wallet.data.settings.cipher_orders,
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
        let dir = format!("/tmp/{}", rng.gen::<usize>());
        let mut bg = Background::from_storage_path(&dir).unwrap();
        let mut ledger_id = vec![0u8; 32];

        rng.fill_bytes(&mut ledger_id);

        assert_eq!(bg.wallets.len(), 0);

        let device_indicators = [String::from("android"), String::from("4354")];
        let keypair = KeyPair::gen_sha256().unwrap();
        let pub_key = keypair.get_pubkey().unwrap();
        let networks = vec![0];

        let session = bg
            .add_ledger_wallet(
                LedgerParams {
                    networks,
                    pub_key: &pub_key,
                    name: String::from("account 0"),
                    ledger_id,
                    wallet_index: 0,
                    wallet_name: String::from("Ledger nano x"),
                    biometric_type: AuthMethod::FaceId,
                },
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
        let mut rng = rand::thread_rng();
        let dir = format!("/tmp/{}", rng.gen::<usize>());
        let mut bg = Background::from_storage_path(&dir).unwrap();
        let ledger_id = "ledger_id".as_bytes().to_vec();

        assert_eq!(bg.wallets.len(), 0);

        let device_indicators = [String::from("android"), String::from("4354")];
        let keypair = KeyPair::gen_sha256().unwrap();
        let pub_key = keypair.get_pubkey().unwrap();
        let networks = vec![0];

        bg.add_ledger_wallet(
            LedgerParams {
                networks: networks.clone(),
                pub_key: &pub_key,
                name: String::from("account 0"),
                ledger_id: ledger_id.clone(),
                wallet_index: 0,
                wallet_name: String::from("Ledger nano x"),
                biometric_type: AuthMethod::FaceId,
            },
            &device_indicators,
        )
        .unwrap();

        assert_eq!(
            bg.add_ledger_wallet(
                LedgerParams {
                    networks,
                    pub_key: &pub_key,
                    name: String::from("account 0"),
                    ledger_id: ledger_id.clone(),
                    wallet_index: 0,
                    wallet_name: String::from("Ledger nano x"),
                    biometric_type: AuthMethod::FaceId,
                },
                &device_indicators,
            ),
            Err(BackgroundError::LedgerIdExists(
                String::from_utf8(ledger_id).unwrap()
            ))
        )
    }

    #[test]
    fn test_from_sk() {
        let mut rng = rand::thread_rng();
        let dir = format!("/tmp/{}", rng.gen::<usize>());
        let mut bg = Background::from_storage_path(&dir).unwrap();

        assert_eq!(bg.wallets.len(), 0);

        let password = "pass";
        let keypair = KeyPair::gen_sha256().unwrap();
        let sk = keypair.get_secretkey().unwrap();
        let name = "SK Account 0".to_string();
        let device_indicators = vec![String::from("test"), String::from("0543543")];
        let network = vec![0];
        let session = bg
            .add_sk_wallet(BackgroundSKParams {
                network,
                password,
                secret_key: &sk,
                account_name: name,
                wallet_name: "test_wallet name".to_string(),
                biometric_type: AuthMethod::Fingerprint,
                device_indicators: &device_indicators,
            })
            .unwrap();

        assert_eq!(bg.wallets.len(), 1);

        drop(bg);
        let mut bg = Background::from_storage_path(&dir).unwrap();
        let wallet = bg.wallets.first_mut().unwrap();
        let wallet_device_indicators = std::iter::once(wallet.data.wallet_address.clone())
            .chain(device_indicators)
            .collect::<Vec<_>>()
            .join(":");

        let seed_bytes = decrypt_session(
            &wallet_device_indicators,
            session,
            &wallet.data.settings.cipher_orders,
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
}
