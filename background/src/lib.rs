use bip39::{Language, Mnemonic};
use cipher::{argon2, keychain::KeyChain};
use config::{cipher::PROOF_SIZE, sha::SHA256_SIZE, storage::INDICATORS_DB_KEY};
use crypto::bip49::Bip49DerivationPath;
use proto::{keypair::KeyPair, secret_key::SecretKey};
use session::Session;
use settings::common_settings::CommonSettings;
use std::sync::Arc;
use storage::LocalStorage;
use wallet::{wallet_data::AuthMethod, Wallet, WalletConfig};
use zil_errors::background::BackgroundError;

use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

pub struct Bip39Params<'a> {
    pub password: &'a str,
    pub mnemonic_str: &'a str,
    pub indexes: &'a [usize],
    pub passphrase: &'a str,
    pub wallet_name: String,
    pub biometric_type: AuthMethod,
}

pub struct Background {
    storage: Arc<LocalStorage>,
    pub wallets: Vec<Wallet>,
    pub indicators: Vec<[u8; SHA256_SIZE]>,
    pub is_old_storage: bool,
    pub settings: CommonSettings,
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

        for addr in &indicators {
            let session = Session::default();
            let w = Wallet::load_from_storage(addr, Arc::clone(&storage), session)
                .map_err(BackgroundError::TryLoadWalletError)?;

            wallets.push(w);
        }

        Ok(Self {
            storage,
            wallets,
            indicators,
            is_old_storage,
            settings: Default::default(),
        })
    }

    pub fn add_bip39_wallet<'a, F>(
        &mut self,
        params: Bip39Params<'a>,
        derive_fn: F,
    ) -> Result<[u8; SHA256_SIZE], BackgroundError>
    where
        F: Fn(usize) -> Bip49DerivationPath,
    {
        let argon_seed = argon2::derive_key(params.password.as_bytes())
            .map_err(BackgroundError::ArgonPasswordHashError)?;
        let (session, key) =
            Session::unlock(&argon_seed).map_err(BackgroundError::CreateSessionError)?;
        let keychain =
            KeyChain::from_seed(&argon_seed).map_err(BackgroundError::FailCreateKeychain)?;
        let mnemonic = Mnemonic::parse_in_normalized(bip39::Language::English, params.mnemonic_str)
            .map_err(|e| BackgroundError::FailParseMnemonicWords(e.to_string()))?;
        let indexes: Vec<(Bip49DerivationPath, String)> = params
            .indexes
            .iter()
            .map(|i| (derive_fn(*i), format!("account {i}")))
            .collect();
        let proof = argon2::derive_key(&argon_seed[..PROOF_SIZE])
            .map_err(BackgroundError::ArgonCreateProofError)?;
        let wallet_config = WalletConfig {
            session,
            keychain,
            storage: Arc::clone(&self.storage),
            settings: Default::default(), // TODO: setup settings
        };
        let wallet = Wallet::from_bip39_words(
            &proof,
            &mnemonic,
            params.passphrase,
            &indexes,
            wallet_config,
            params.wallet_name,
            params.biometric_type,
        )
        .map_err(BackgroundError::FailToInitWallet)?;
        let indicator = wallet.key().map_err(BackgroundError::FailToInitWallet)?;

        wallet
            .save_to_storage()
            .map_err(BackgroundError::FailToSaveWallet)?;

        println!("self.indicators {:?}", self.indicators);
        self.indicators.push(indicator);

        self.wallets.push(wallet);

        self.save_indicators()?;

        self.storage
            .flush()
            .map_err(BackgroundError::LocalStorageFlushError)?;

        Ok(key)
    }

    pub fn add_sk_wallet(
        &mut self,
        password: &str,
        secret_key: &SecretKey,
        account_name: String,
        wallet_name: String,
        biometric_type: AuthMethod,
    ) -> Result<[u8; SHA256_SIZE], BackgroundError> {
        let argon_seed = argon2::derive_key(password.as_bytes())
            .map_err(BackgroundError::ArgonPasswordHashError)?;
        let (session, key) =
            Session::unlock(&argon_seed).map_err(BackgroundError::CreateSessionError)?;
        let keychain =
            KeyChain::from_seed(&argon_seed).map_err(BackgroundError::FailCreateKeychain)?;
        let proof = argon2::derive_key(&argon_seed[..PROOF_SIZE])
            .map_err(BackgroundError::ArgonCreateProofError)?;
        let wallet_config = WalletConfig {
            session,
            keychain,
            storage: Arc::clone(&self.storage),
            settings: Default::default(), // TODO: setup settings
        };
        let wallet = Wallet::from_sk(
            secret_key,
            account_name,
            &proof,
            wallet_config,
            wallet_name,
            biometric_type,
        )
        .map_err(BackgroundError::FailToInitWallet)?;
        let indicator = wallet.key().map_err(BackgroundError::FailToInitWallet)?;

        wallet
            .save_to_storage()
            .map_err(BackgroundError::FailToSaveWallet)?;
        self.indicators.push(indicator);
        self.wallets.push(wallet);

        self.save_indicators()?;

        self.storage
            .flush()
            .map_err(BackgroundError::LocalStorageFlushError)?;

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
}

#[cfg(test)]
mod tests_background {
    use super::*;
    use config::key::{PUB_KEY_SIZE, SECRET_KEY_SIZE};
    use proto::keypair::KeyPair;
    use rand::Rng;

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

        let _key = bg
            .add_bip39_wallet(
                Bip39Params {
                    password,
                    mnemonic_str: words,
                    indexes: &indexes,
                    passphrase: "",
                    wallet_name: String::new(),
                    biometric_type: Default::default(),
                },
                derive,
            )
            .unwrap();

        assert_eq!(bg.wallets.len(), 1);

        drop(bg);

        let mut bg = Background::from_storage_path(&dir).unwrap();

        let _key = bg
            .add_bip39_wallet(
                Bip39Params {
                    password,
                    mnemonic_str: words,
                    indexes: &indexes,
                    passphrase: "",
                    wallet_name: String::new(),
                    biometric_type: Default::default(),
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
                Bip39Params {
                    password,
                    mnemonic_str: words,
                    indexes: &indexes,
                    passphrase: "",
                    wallet_name: String::new(),
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

        let key = bg
            .add_bip39_wallet(
                Bip39Params {
                    password,
                    mnemonic_str: words,
                    indexes: &indexes,
                    passphrase: "",
                    wallet_name: String::new(),
                    biometric_type: Default::default(),
                },
                derive,
            )
            .unwrap();

        assert_eq!(bg.wallets.len(), 1);

        drop(bg);

        let mut bg = Background::from_storage_path(&dir).unwrap();
        let wallet = bg.wallets.first_mut().unwrap();

        assert_eq!(
            wallet.reveal_mnemonic(&key),
            Err(zil_errors::wallet::WalletErrors::DisabledSessions)
        );
        assert_eq!(
            wallet.unlock("wrong_passwordf".as_bytes()),
            Err(zil_errors::wallet::WalletErrors::KeyChainFailToGetProof)
        );

        let new_key = wallet.unlock(password.as_bytes()).unwrap();
        let res_words = wallet.reveal_mnemonic(&new_key).unwrap().to_string();

        assert_eq!(res_words, words);

        let keypair = wallet.reveal_keypair(1, &new_key, None).unwrap();
        let sk = keypair.get_secretkey().unwrap();

        assert_eq!(
            sk.to_string(),
            "00fe8b8ee252f3d1348ca68c8537cb4d26a44826abe12a227df3b5db47bf6e0fe3"
        );

        wallet.lock();

        assert!(wallet.reveal_mnemonic(&key).is_err());
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
        let key = bg
            .add_sk_wallet(
                password,
                &sk,
                name,
                "test account name".to_string(),
                AuthMethod::None,
            )
            .unwrap();

        assert_eq!(bg.wallets.len(), 1);

        drop(bg);
        let mut bg = Background::from_storage_path(&dir).unwrap();
        let wallet = bg.wallets.first_mut().unwrap();

        assert_eq!(
            wallet.reveal_mnemonic(&key),
            Err(zil_errors::wallet::WalletErrors::DisabledSessions)
        );
        assert_eq!(
            wallet.unlock("wrong_passwordf".as_bytes()),
            Err(zil_errors::wallet::WalletErrors::KeyChainFailToGetProof)
        );

        let new_key = wallet.unlock(password.as_bytes()).unwrap();

        assert_eq!(
            wallet.reveal_mnemonic(&key),
            Err(zil_errors::wallet::WalletErrors::InvalidAccountType)
        );

        let res_keypair = wallet.reveal_keypair(0, &new_key, None).unwrap();

        assert_eq!(res_keypair, keypair);
        wallet.lock();
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
