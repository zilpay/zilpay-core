use bip39::{Language, Mnemonic};
use cipher::{argon2, keychain::KeyChain};
use config::{
    cipher::{PROOF_SALT, PROOF_SIZE},
    sha::SHA256_SIZE,
    storage::{FTOKENS_DB_KEY, INDICATORS_DB_KEY},
};
use crypto::bip49::Bip49DerivationPath;
use network::provider::NetworkProvider;
use proto::{keypair::KeyPair, secret_key::SecretKey};
use session::{decrypt_session, encrypt_session};
use settings::common_settings::CommonSettings;
use std::sync::Arc;
use storage::LocalStorage;
use wallet::{
    ft::FToken, wallet_data::AuthMethod, wallet_types::WalletTypes, Bip39Params, LedgerParams,
    Wallet, WalletConfig,
};
use zil_errors::background::BackgroundError;

use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

pub struct BackgroundBip39Params<'a> {
    pub password: &'a str,
    pub mnemonic_str: &'a str,
    pub indexes: &'a [usize],
    pub passphrase: &'a str,
    pub wallet_name: String,
    pub biometric_type: AuthMethod,
    pub device_indicators: &'a [String],
    pub network: Vec<usize>,
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
    pub ftokens: Vec<FToken>,
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
            .map_err(|e| BackgroundError::FailtToGenBip39FromEntropy(e.to_string()))?;

        Ok(m.to_string())
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
        let netowrk = NetworkProvider::new_vec();
        let mut ftokens = vec![FToken::zil(), FToken::eth()]; // init default tokens

        // ftokens.copy_from_slice();

        for addr in &indicators {
            let w = Wallet::load_from_storage(addr, Arc::clone(&storage))
                .map_err(BackgroundError::TryLoadWalletError)?;

            wallets.push(w);
        }

        Ok(Self {
            ftokens,
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
    ) -> Result<(), BackgroundError> {
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

        Ok(())
    }

    pub fn unlock_wallet_with_session(
        &mut self,
        session_cipher: Vec<u8>,
        device_indicators: &[String],
        wallet_index: usize,
    ) -> Result<(), BackgroundError> {
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
            &wallet.data.settings.crypto.cipher_orders,
        )
        .map_err(BackgroundError::DecryptSessionError)?;

        wallet
            .unlock(&seed_bytes)
            .map_err(BackgroundError::FailUnlockWallet)?;

        Ok(())
    }

    pub fn add_bip39_wallet<F>(
        &mut self,
        params: BackgroundBip39Params,
        derive_fn: F,
    ) -> Result<Vec<u8>, BackgroundError>
    where
        F: Fn(usize) -> Bip49DerivationPath,
    {
        let device_indicator = params.device_indicators.join(":");
        let argon_seed = argon2::derive_key(params.password.as_bytes(), &device_indicator)
            .map_err(BackgroundError::ArgonPasswordHashError)?;
        let keychain =
            KeyChain::from_seed(&argon_seed).map_err(BackgroundError::FailCreateKeychain)?;
        let mnemonic = Mnemonic::parse_in_normalized(bip39::Language::English, params.mnemonic_str)
            .map_err(|e| BackgroundError::FailParseMnemonicWords(e.to_string()))?;
        let indexes: Vec<(Bip49DerivationPath, String)> = params
            .indexes
            .iter()
            .map(|i| (derive_fn(*i), format!("account {i}")))
            .collect();
        let proof = argon2::derive_key(&argon_seed[..PROOF_SIZE], PROOF_SALT)
            .map_err(BackgroundError::ArgonCreateProofError)?;
        let wallet_config = WalletConfig {
            keychain,
            storage: Arc::clone(&self.storage),
            settings: Default::default(), // TODO: setup settings
        };
        let options = &wallet_config.settings.crypto.cipher_orders.clone();
        let wallet = Wallet::from_bip39_words(Bip39Params {
            proof: &proof,
            mnemonic: &mnemonic,
            passphrase: params.passphrase,
            indexes: &indexes,
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

        let session = if params.biometric_type == AuthMethod::None {
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
            return Err(BackgroundError::LedgerIdExists);
        }

        let device_indicator = device_indicators.join(":");
        let argon_seed = argon2::derive_key(device_indicator.as_bytes(), "ledger")
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
        let biometric_type = params.biometric_type;
        let options = &wallet_config.settings.crypto.cipher_orders.clone();
        let wallet = Wallet::from_ledger(params, &proof, wallet_config)
            .map_err(BackgroundError::FailToInitWallet)?;
        let indicator = wallet.key().map_err(BackgroundError::FailToInitWallet)?;
        let device_indicator = std::iter::once(hex::encode(indicator))
            .chain(device_indicators.iter().cloned())
            .collect::<Vec<_>>()
            .join(":");
        let session = if biometric_type == AuthMethod::None {
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
        let options = &wallet_config.settings.crypto.cipher_orders.clone();
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

        let session = if params.biometric_type == AuthMethod::None {
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

    fn load_ftokens(&self) -> Result<Vec<FToken>, BackgroundError> {
        let bytes = self.storage.get(FTOKENS_DB_KEY).unwrap_or_default();

        if bytes.is_empty() {
            return Ok(Vec::new());
        }

        let ftokens: Vec<FToken> = serde_json::from_slice(&bytes).unwrap_or_default();

        Ok(ftokens)
    }

    fn save_ftokens(&self) -> Result<(), BackgroundError> {
        let ftokens: Vec<&FToken> = self.ftokens.iter().filter(|token| !token.default).collect();
        let bytes = serde_json::to_vec(&ftokens).or(Err(BackgroundError::FailToSerializeToken))?;

        self.storage
            .set(FTOKENS_DB_KEY, &bytes)
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
    fn test_add_more_wallets_bip39() {
        let mut rng = rand::thread_rng();
        let dir = format!("/tmp/{}", rng.gen::<usize>());
        let mut bg = Background::from_storage_path(&dir).unwrap();

        assert_eq!(bg.wallets.len(), 0);

        let password = "test_password";
        let words: &str =
            "area scale vital sell radio pattern poverty mean similar picnic grain gain";
        let indexes = [0usize];
        let derive = Bip49DerivationPath::Zilliqa;
        let network = vec![0];

        let _key = bg
            .add_bip39_wallet(
                BackgroundBip39Params {
                    password,
                    network: network.clone(),
                    mnemonic_str: words,
                    indexes: &indexes,
                    passphrase: "",
                    wallet_name: String::new(),
                    biometric_type: Default::default(),
                    device_indicators: &[String::from("apple"), String::from("0000")],
                },
                derive,
            )
            .unwrap();

        assert_eq!(bg.wallets.len(), 1);

        drop(bg);

        let mut bg = Background::from_storage_path(&dir).unwrap();

        let _key = bg
            .add_bip39_wallet(
                BackgroundBip39Params {
                    password,
                    network: network.clone(),
                    mnemonic_str: words,
                    indexes: &indexes,
                    passphrase: "",
                    wallet_name: String::new(),
                    biometric_type: Default::default(),
                    device_indicators: &[String::from("apple"), String::from("1102")],
                },
                derive,
            )
            .unwrap();

        let password = "test_password";
        let words: &str =
            "clap chair edit noise sugar box raccoon play another hobby soccer fringe";
        let indexes = [0, 1];
        let derive = Bip49DerivationPath::Zilliqa;

        let _key = bg
            .add_bip39_wallet(
                BackgroundBip39Params {
                    password,
                    network,
                    mnemonic_str: words,
                    indexes: &indexes,
                    passphrase: "",
                    wallet_name: String::new(),
                    device_indicators: &[String::from("apple"), String::from("43498")],
                    biometric_type: Default::default(),
                },
                derive,
            )
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
        let indexes = [0, 1, 2, 3, 4, 5, 6, 7];
        let derive = Bip49DerivationPath::Zilliqa;
        let device_indicators = [String::from("apple"), String::from("4354")];
        let network = vec![0];

        let session = bg
            .add_bip39_wallet(
                BackgroundBip39Params {
                    device_indicators: &device_indicators,
                    password,
                    mnemonic_str: words,
                    indexes: &indexes,
                    passphrase: "",
                    wallet_name: String::new(),
                    biometric_type: AuthMethod::FaceId,
                    network,
                },
                derive,
            )
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
            &wallet.data.settings.crypto.cipher_orders,
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
        let wallet = bg.wallets.first_mut().unwrap();

        let wallet_device_indicators = std::iter::once(wallet.data.wallet_address.clone())
            .chain(device_indicators)
            .collect::<Vec<_>>()
            .join(":");

        let seed_bytes = decrypt_session(
            &wallet_device_indicators,
            session,
            &wallet.data.settings.crypto.cipher_orders,
        )
        .unwrap();

        assert_eq!(
            wallet.unlock(&[42u8; KEY_SIZE]),
            Err(zil_errors::wallet::WalletErrors::KeyChainFailToGetProof)
        );

        wallet.unlock(&seed_bytes).unwrap();
    }

    #[test]
    fn test_2_same_ledger() {
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
                    ledger_id,
                    wallet_index: 0,
                    wallet_name: String::from("Ledger nano x"),
                    biometric_type: AuthMethod::FaceId,
                },
                &device_indicators,
            ),
            Err(BackgroundError::LedgerIdExists)
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
            &wallet.data.settings.crypto.cipher_orders,
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
