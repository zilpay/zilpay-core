pub mod account;
pub mod account_type;
pub mod ft;
pub mod wallet_data;
pub mod wallet_types;

use std::sync::Arc;

use cipher::argon2::derive_key;
use config::argon::KEY_SIZE;
use config::cipher::{PROOF_SALT, PROOF_SIZE};
use config::storage::FTOKENS_DB_KEY;
use ft::FToken;
use proto::keypair::KeyPair;
use proto::pubkey::PubKey;
use proto::secret_key::SecretKey;
use proto::signature::Signature;
use proto::tx::{TransactionReceipt, TransactionRequest};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

use bincode::{FromBytes, ToBytes};
use bip39::Mnemonic;
use cipher::keychain::KeyChain;
use config::sha::SHA256_SIZE;
use config::wallet::{N_BYTES_HASH, N_SALT};
use crypto::bip49::Bip49DerivationPath;
use settings::wallet_settings::WalletSettings;
use sha2::{Digest, Sha256};
use storage::LocalStorage;
use wallet_data::{AuthMethod, WalletData};
use wallet_types::WalletTypes;
use zil_errors::wallet::WalletErrors;

pub struct WalletConfig {
    pub storage: Arc<LocalStorage>,
    pub keychain: KeyChain,
    pub settings: WalletSettings,
}

pub struct LedgerParams<'a> {
    pub pub_key: &'a PubKey,
    pub ledger_id: Vec<u8>,
    pub name: String,
    pub wallet_index: usize,
    pub wallet_name: String,
    pub biometric_type: AuthMethod,
    pub networks: Vec<usize>,
}

pub struct Bip39Params<'a> {
    pub proof: &'a [u8; KEY_SIZE],
    pub mnemonic: &'a Mnemonic,
    pub passphrase: &'a str,
    pub indexes: &'a [(Bip49DerivationPath, String)],
    pub config: WalletConfig,
    pub wallet_name: String,
    pub biometric_type: AuthMethod,
    pub network: Vec<usize>,
}

pub struct Wallet {
    storage: Arc<LocalStorage>,
    pub data: WalletData,
    pub ftokens: Vec<FToken>,
}

fn safe_storage_save(
    cipher_entropy: &[u8],
    storage: Arc<LocalStorage>,
) -> Result<usize, WalletErrors> {
    let mut rng = ChaCha20Rng::from_entropy();
    let mut cipher_entropy_key: usize;

    loop {
        cipher_entropy_key = rng.r#gen();
        let key = usize::to_le_bytes(cipher_entropy_key);
        let is_exists_key = storage
            .exists(&key)
            .map_err(WalletErrors::FailToSaveCipher)?;

        if is_exists_key {
            continue;
        }

        storage
            .set(&key, cipher_entropy)
            .map_err(WalletErrors::FailToSaveCipher)?;

        break;
    }

    Ok(cipher_entropy_key)
}

impl Wallet {
    pub const ZIL_DEFAULT_TOKENS: usize = 1;
    pub const ETH_DEFAULT_TOKENS: usize = 1;

    pub fn load_from_storage(
        key: &[u8; SHA256_SIZE],
        storage: Arc<LocalStorage>,
    ) -> Result<Self, WalletErrors> {
        let data = storage
            .get(key)
            .map_err(WalletErrors::FailToLoadWalletData)?;
        let data = serde_json::from_slice::<WalletData>(&data)
            .or(Err(WalletErrors::FailToDeserializeWalletData))?;
        let ftokens = Vec::new();

        Ok(Self {
            storage,
            data,
            ftokens,
        })
    }

    pub fn from_ledger(
        params: LedgerParams,
        proof: &[u8; KEY_SIZE],
        config: WalletConfig,
    ) -> Result<Self, WalletErrors> {
        // TODO: add cipher for encrypt account index.
        let cipher_proof = config
            .keychain
            .make_proof(proof, &config.settings.crypto.cipher_orders)
            .map_err(WalletErrors::KeyChainMakeCipherProofError)?;
        let proof_key = safe_storage_save(&cipher_proof, Arc::clone(&config.storage))?;
        drop(cipher_proof);

        let mut hasher = Sha256::new();

        hasher.update(params.pub_key.as_bytes());
        hasher.update(&params.ledger_id);

        let wallet_address: [u8; SHA256_SIZE] = hasher.finalize().into();
        let wallet_address = hex::encode(wallet_address);
        let account =
            account::Account::from_ledger(params.pub_key, params.name, params.wallet_index)
                .or(Err(WalletErrors::InvalidSecretKeyAccount))?;

        let accounts: Vec<account::Account> = vec![account];
        let data = WalletData {
            network: params.networks,
            wallet_name: params.wallet_name,
            biometric_type: params.biometric_type,
            proof_key,
            settings: config.settings,
            accounts,
            wallet_address,
            wallet_type: WalletTypes::Ledger(params.ledger_id),
            selected_account: 0,
        };
        let ftokens = match params.pub_key {
            PubKey::Secp256k1Sha256Zilliqa(_) => {
                vec![FToken::zil()]
            }
            PubKey::Secp256k1Keccak256Ethereum(_) => {
                vec![FToken::eth()]
            }
            _ => unreachable!(),
        };

        Ok(Self {
            storage: config.storage,
            data,
            ftokens,
        })
    }

    pub fn from_sk(
        sk: &SecretKey,
        name: String,
        proof: &[u8; KEY_SIZE],
        config: WalletConfig,
        wallet_name: String,
        biometric_type: AuthMethod,
        network: Vec<usize>,
    ) -> Result<Self, WalletErrors> {
        let sk_as_bytes = sk.to_bytes().map_err(WalletErrors::FailToGetSKBytes)?;
        let mut combined = [0u8; SHA256_SIZE];

        combined[..N_BYTES_HASH].copy_from_slice(&sk_as_bytes[..N_BYTES_HASH]);
        combined[N_BYTES_HASH..].copy_from_slice(&N_SALT);

        let cipher_sk = config
            .keychain
            .encrypt(sk_as_bytes.to_vec(), &config.settings.crypto.cipher_orders)
            .or(Err(WalletErrors::TryEncryptSecretKeyError))?;
        let cipher_proof = config
            .keychain
            .make_proof(proof, &config.settings.crypto.cipher_orders)
            .map_err(WalletErrors::KeyChainMakeCipherProofError)?;
        let proof_key = safe_storage_save(&cipher_proof, Arc::clone(&config.storage))?;
        drop(cipher_proof);
        let cipher_entropy_key = safe_storage_save(&cipher_sk, Arc::clone(&config.storage))?;

        let mut hasher = Sha256::new();
        hasher.update(combined);

        let wallet_address: [u8; SHA256_SIZE] = hasher.finalize().into();
        let wallet_address = hex::encode(wallet_address);
        // SecretKey may stores only one account.
        let account = account::Account::from_secret_key(sk, name, cipher_entropy_key)
            .or(Err(WalletErrors::InvalidSecretKeyAccount))?;
        let accounts: Vec<account::Account> = vec![account];
        let data = WalletData {
            network,
            wallet_name,
            biometric_type,
            proof_key,
            settings: config.settings,
            accounts,
            wallet_address,
            wallet_type: WalletTypes::SecretKey,
            selected_account: 0,
        };
        let ftokens = match sk {
            SecretKey::Secp256k1Sha256Zilliqa(_) => {
                vec![FToken::zil()]
            }
            SecretKey::Secp256k1Keccak256Ethereum(_) => {
                vec![FToken::eth()]
            }
        };

        Ok(Self {
            storage: config.storage,
            data,
            ftokens,
        })
    }

    pub fn from_bip39_words(params: Bip39Params) -> Result<Self, WalletErrors> {
        let cipher_entropy = params
            .config
            .keychain
            .encrypt(
                params.mnemonic.to_entropy(),
                &params.config.settings.crypto.cipher_orders,
            )
            .map_err(WalletErrors::EncryptKeyChainErrors)?;
        let mut combined = [0u8; SHA256_SIZE];
        let mnemonic_seed = params.mnemonic.to_seed_normalized(params.passphrase);
        let cipher_proof = params
            .config
            .keychain
            .make_proof(params.proof, &params.config.settings.crypto.cipher_orders)
            .map_err(WalletErrors::KeyChainMakeCipherProofError)?;
        let proof_key = safe_storage_save(&cipher_proof, Arc::clone(&params.config.storage))?;
        drop(cipher_proof);
        let cipher_entropy_key =
            safe_storage_save(&cipher_entropy, Arc::clone(&params.config.storage))?;

        combined[..N_BYTES_HASH].copy_from_slice(&mnemonic_seed[..N_BYTES_HASH]);
        combined[N_BYTES_HASH..].copy_from_slice(&N_SALT);

        let mut hasher = Sha256::new();
        hasher.update(combined);

        let wallet_address: [u8; SHA256_SIZE] = hasher.finalize().into();
        let wallet_address = hex::encode(wallet_address);
        let mut accounts: Vec<account::Account> = Vec::with_capacity(params.indexes.len());

        for index in params.indexes {
            let (bip49, name) = index;
            let hd_account = account::Account::from_hd(&mnemonic_seed, name.to_owned(), bip49)
                .or(Err(WalletErrors::InvalidBip39Account))?;

            accounts.push(hd_account);
        }

        let ftokens = match accounts[0].pub_key {
            PubKey::Secp256k1Sha256Zilliqa(_) => {
                vec![FToken::zil()]
            }
            PubKey::Secp256k1Keccak256Ethereum(_) => {
                vec![FToken::eth()]
            }
            _ => unreachable!(),
        };
        let data = WalletData {
            network: params.network,
            wallet_name: params.wallet_name,
            biometric_type: params.biometric_type,
            proof_key,
            settings: params.config.settings,
            wallet_address,
            accounts,
            wallet_type: WalletTypes::SecretPhrase((
                cipher_entropy_key,
                !params.passphrase.is_empty(),
            )),
            selected_account: 0,
        };

        Ok(Self {
            storage: params.config.storage,
            data,
            ftokens,
        })
    }

    pub fn reveal_keypair(
        &self,
        account_index: usize,
        seed_bytes: &[u8; KEY_SIZE],
        passphrase: Option<&str>,
    ) -> Result<KeyPair, WalletErrors> {
        let keychain = KeyChain::from_seed(seed_bytes).map_err(WalletErrors::KeyChainError)?;

        match self.data.wallet_type {
            WalletTypes::SecretKey => {
                let account = self
                    .data
                    .accounts
                    .get(account_index)
                    .ok_or(WalletErrors::FailToGetAccount(account_index))?;
                let storage_key = usize::to_le_bytes(account.account_type.value());
                let cipher_sk = self
                    .storage
                    .get(&storage_key)
                    .map_err(WalletErrors::FailToGetContent)?;
                let sk_bytes = keychain
                    .decrypt(cipher_sk, &self.data.settings.crypto.cipher_orders)
                    .map_err(WalletErrors::DecryptKeyChainErrors)?;
                let sk = SecretKey::from_bytes(sk_bytes.into())
                    .map_err(WalletErrors::FailParseSKBytes)?;
                let keypair =
                    KeyPair::from_secret_key(&sk).map_err(WalletErrors::FailToCreateKeyPair)?;

                Ok(keypair)
            }
            WalletTypes::SecretPhrase((_key, is_phr)) => {
                if is_phr && passphrase.is_none() {
                    return Err(WalletErrors::PassphraseIsNone);
                }

                let account = self
                    .data
                    .accounts
                    .get(account_index)
                    .ok_or(WalletErrors::FailToGetAccount(account_index))?;
                let m = self.reveal_mnemonic(seed_bytes)?;
                let seed = m.to_seed(passphrase.unwrap_or(""));
                let bip49 = account.get_bip49().map_err(WalletErrors::InvalidBip49)?;
                let keypair = KeyPair::from_bip39_seed(&seed, &bip49)
                    .map_err(WalletErrors::FailToCreateKeyPair)?;

                Ok(keypair)
            }
            _ => Err(WalletErrors::InvalidAccountType),
        }
    }

    pub fn reveal_mnemonic(&self, seed_bytes: &[u8; KEY_SIZE]) -> Result<Mnemonic, WalletErrors> {
        match self.data.wallet_type {
            WalletTypes::SecretPhrase((key, _)) => {
                let keychain =
                    KeyChain::from_seed(seed_bytes).map_err(WalletErrors::KeyChainError)?;
                let storage_key = usize::to_le_bytes(key);
                let cipher_entropy = self
                    .storage
                    .get(&storage_key)
                    .map_err(WalletErrors::FailToGetContent)?;
                let entropy = keychain
                    .decrypt(cipher_entropy, &self.data.settings.crypto.cipher_orders)
                    .map_err(WalletErrors::DecryptKeyChainErrors)?;
                // TODO: add more Languages
                let m = Mnemonic::from_entropy_in(bip39::Language::English, &entropy)
                    .map_err(|e| WalletErrors::MnemonicError(e.to_string()))?;

                Ok(m)
            }
            _ => Err(WalletErrors::InvalidAccountType),
        }
    }

    pub fn sign_message(
        &self,
        msg: &[u8],
        account_index: usize,
        seed_bytes: &[u8; KEY_SIZE],
        passphrase: Option<&str>,
    ) -> Result<Signature, WalletErrors> {
        let keypair = self.reveal_keypair(account_index, seed_bytes, passphrase)?;
        let sig = keypair
            .sign_message(msg)
            .map_err(WalletErrors::FailSignMessage)?;
        let vrify = keypair
            .verify_sig(msg, &sig)
            .map_err(WalletErrors::FailVerifySig)?;

        if !vrify {
            return Err(WalletErrors::InvalidVerifySig);
        }

        Ok(sig)
    }

    pub async fn sign_transaction(
        &self,
        tx: &TransactionRequest,
        account_index: usize,
        seed_bytes: &[u8; KEY_SIZE],
        passphrase: Option<&str>,
    ) -> Result<TransactionReceipt, WalletErrors> {
        let keypair = self.reveal_keypair(account_index, seed_bytes, passphrase)?;

        keypair
            .sign_tx(tx)
            .await
            .map_err(WalletErrors::FailToSignTransaction)
    }

    pub fn unlock(&mut self, seed_bytes: &[u8; KEY_SIZE]) -> Result<(), WalletErrors> {
        self.unlock_iternel(seed_bytes)?;

        let bytes = self.storage.get(FTOKENS_DB_KEY).unwrap_or_default();
        let ftokens: Vec<FToken> = serde_json::from_slice(&bytes).unwrap_or_default();
        let selected = self
            .data
            .accounts
            .get(self.data.selected_account)
            .ok_or(WalletErrors::FailToGetAccount(self.data.selected_account))?;

        match selected.pub_key {
            PubKey::Secp256k1Sha256Zilliqa(_) => self.ftokens = vec![FToken::zil()],
            PubKey::Secp256k1Keccak256Ethereum(_) => self.ftokens = vec![FToken::eth()],
            _ => unreachable!(),
        }

        self.ftokens.extend_from_slice(&ftokens);

        Ok(())
    }

    fn unlock_iternel(&mut self, seed_bytes: &[u8; KEY_SIZE]) -> Result<KeyChain, WalletErrors> {
        let keychain = KeyChain::from_seed(seed_bytes).map_err(WalletErrors::KeyChainError)?;

        let proof_key = usize::to_le_bytes(self.data.proof_key);
        let cipher_proof = self
            .storage
            .get(&proof_key)
            .map_err(WalletErrors::FailToGetProofFromStorage)?;

        let origin_proof = keychain
            .get_proof(&cipher_proof, &self.data.settings.crypto.cipher_orders)
            .or(Err(WalletErrors::KeyChainFailToGetProof))?;

        let proof = derive_key(&seed_bytes[..PROOF_SIZE], PROOF_SALT)
            .map_err(WalletErrors::ArgonCipherErrors)?;

        if proof != origin_proof {
            return Err(WalletErrors::ProofNotMatch);
        }

        Ok(keychain)
    }

    pub fn add_ftoken(&mut self, token: FToken) -> Result<(), WalletErrors> {
        self.ftokens.push(token);

        let ftokens: Vec<&FToken> = self.ftokens.iter().filter(|token| !token.default).collect();
        let bytes = serde_json::to_vec(&ftokens).or(Err(WalletErrors::FailToSerializeToken))?;

        self.storage
            .set(FTOKENS_DB_KEY, &bytes)
            .map_err(WalletErrors::FailtoSaveFTokensToStorage)?;
        self.storage
            .flush()
            .map_err(WalletErrors::StorageFailFlush)?;

        Ok(())
    }

    pub fn remove_ftoken(&mut self, index: usize) -> Result<(), WalletErrors> {
        self.ftokens.remove(index);

        let ftokens: Vec<&FToken> = self.ftokens.iter().filter(|token| !token.default).collect();
        let bytes = serde_json::to_vec(&ftokens).or(Err(WalletErrors::FailToSerializeToken))?;

        self.storage
            .set(FTOKENS_DB_KEY, &bytes)
            .map_err(WalletErrors::FailtoSaveFTokensToStorage)?;
        self.storage
            .flush()
            .map_err(WalletErrors::StorageFailFlush)?;

        Ok(())
    }

    pub fn save_to_storage(&self) -> Result<(), WalletErrors> {
        let json_bytes =
            serde_json::to_vec(&self.data).or(Err(WalletErrors::FailToSerializeWalletData))?;
        let key = self.key()?;

        self.storage
            .set(&key, &json_bytes)
            .map_err(WalletErrors::FailtoSaveWalletDataToStorage)?;
        self.storage
            .flush()
            .map_err(WalletErrors::StorageFailFlush)?;

        Ok(())
    }

    #[inline]
    pub fn key(&self) -> Result<[u8; SHA256_SIZE], WalletErrors> {
        hex::decode(&self.data.wallet_address)
            .or(Err(WalletErrors::InvalidWalletAddressHex))?
            .try_into()
            .or(Err(WalletErrors::InvalidWalletAddressSize))
    }
}

#[cfg(test)]
mod tests {
    use core::panic;
    use std::{collections::HashMap, sync::Arc};

    use bip39::Mnemonic;
    use cipher::{argon2::derive_key, keychain::KeyChain};
    use config::{
        argon::KEY_SIZE,
        cipher::{PROOF_SALT, PROOF_SIZE},
        sha::SHA256_SIZE,
    };
    use crypto::bip49::Bip49DerivationPath;
    use proto::{address::Address, keypair::KeyPair};
    use rand::Rng;
    use storage::LocalStorage;
    use zil_errors::wallet::WalletErrors;

    use crate::{
        ft::FToken, wallet_data::AuthMethod, wallet_types::WalletTypes, Bip39Params, Wallet,
        WalletConfig,
    };

    const MNEMONIC_STR: &str =
        "green process gate doctor slide whip priority shrug diamond crumble average help";
    const PASSWORD: &[u8] = b"Test_password";
    const PASSPHRASE: &str = "";

    #[test]
    fn test_init_from_bip39_zil() {
        let argon_seed = derive_key(PASSWORD, "").unwrap();
        let storage = LocalStorage::new(
            "com.test_write_wallet",
            "WriteTest Wallet Corp",
            "WalletWriteTest App",
        )
        .unwrap();
        let storage = Arc::new(storage);
        let keychain = KeyChain::from_seed(&argon_seed).unwrap();
        let mnemonic =
            Mnemonic::parse_in_normalized(bip39::Language::English, MNEMONIC_STR).unwrap();
        let indexes = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
            .map(|i| (Bip49DerivationPath::Zilliqa(i), format!("account {i}")));
        let proof = derive_key(&argon_seed[..PROOF_SIZE], "").unwrap();
        let wallet_config = WalletConfig {
            keychain,
            storage: Arc::clone(&storage),
            settings: Default::default(),
        };
        let wallet = Wallet::from_bip39_words(Bip39Params {
            proof: &proof,
            mnemonic: &mnemonic,
            passphrase: PASSPHRASE,
            indexes: &indexes,
            config: wallet_config,
            wallet_name: "Wllaet name".to_string(),
            biometric_type: AuthMethod::Biometric,
            network: vec![0],
        })
        .unwrap();

        wallet.save_to_storage().unwrap();

        match wallet.data.wallet_type {
            WalletTypes::SecretPhrase((_, is_phr)) => {
                assert!(!is_phr);
            }
            _ => panic!("invalid type"),
        }

        assert_eq!(wallet.data.accounts.len(), indexes.len());

        let wallet_addr: [u8; SHA256_SIZE] = hex::decode(wallet.data.wallet_address.clone())
            .unwrap()
            .try_into()
            .unwrap();

        drop(wallet);

        let res_wallet = Wallet::load_from_storage(&wallet_addr, Arc::clone(&storage)).unwrap();

        assert!(res_wallet.reveal_mnemonic(&[0u8; KEY_SIZE]).is_err());
        assert!(res_wallet.reveal_mnemonic(&argon_seed).is_ok());
    }

    #[test]
    fn test_init_from_sk() {
        let argon_seed = derive_key(PASSWORD, "").unwrap();
        let proof = derive_key(&argon_seed[..PROOF_SIZE], "").unwrap();
        let mut rng = rand::thread_rng();
        let dir = format!("/tmp/{}", rng.gen::<usize>());
        let storage = LocalStorage::from(&dir).unwrap();

        let storage = Arc::new(storage);
        let keychain = KeyChain::from_seed(&argon_seed).unwrap();
        let keypair = KeyPair::gen_keccak256().unwrap();
        let sk = keypair.get_secretkey().unwrap();
        let name = "SK Account 0";
        let wallet_config = WalletConfig {
            keychain,
            storage: Arc::clone(&storage),
            settings: Default::default(),
        };
        let wallet = Wallet::from_sk(
            &sk,
            name.to_string(),
            &proof,
            wallet_config,
            "test Name".to_string(),
            Default::default(),
            vec![0],
        )
        .unwrap();

        assert_eq!(wallet.data.accounts.len(), 1);
        assert_eq!(
            wallet.reveal_mnemonic(&argon_seed),
            Err(WalletErrors::InvalidAccountType)
        );

        let wallet_addr: [u8; SHA256_SIZE] = hex::decode(wallet.data.wallet_address.clone())
            .unwrap()
            .try_into()
            .unwrap();
        wallet.save_to_storage().unwrap();

        let w = Wallet::load_from_storage(&wallet_addr, Arc::clone(&storage)).unwrap();

        assert_eq!(w.data, wallet.data);
    }

    #[test]
    fn test_add_and_load_tokens() {
        // Setup initial wallet with secret key
        let argon_seed = derive_key(PASSWORD, PROOF_SALT).unwrap();
        let proof = derive_key(&argon_seed[..PROOF_SIZE], PROOF_SALT).unwrap();
        let mut rng = rand::thread_rng();
        let dir = format!("/tmp/{}", rng.gen::<usize>());
        let storage = LocalStorage::from(&dir).unwrap();
        let storage = Arc::new(storage);
        let keychain = KeyChain::from_seed(&argon_seed).unwrap();

        // Generate ETH keypair for test wallet
        let keypair = KeyPair::gen_keccak256().unwrap();
        let sk = keypair.get_secretkey().unwrap();

        let wallet_config = WalletConfig {
            keychain,
            storage: Arc::clone(&storage),
            settings: Default::default(),
        };

        // Create wallet
        let mut wallet = Wallet::from_sk(
            &sk,
            "Test Token Account".to_string(),
            &proof,
            wallet_config,
            "Token Test Wallet".to_string(),
            Default::default(),
            vec![0],
        )
        .unwrap();

        // Verify initial state - should only have default ETH token
        assert_eq!(wallet.ftokens.len(), 1);
        assert!(wallet.ftokens[0].default);
        assert_eq!(wallet.ftokens[0].symbol, "ETH");

        // Create custom token
        let custom_token = FToken {
            name: "Test Token".to_string(),
            symbol: "TST".to_string(),
            decimals: 18,
            addr: Address::from_zil_base16("e876b112a62f945484ede1f3ccdd6b0ac6f39382").unwrap(),
            logo: None,
            default: false,
            balances: HashMap::new(),
        };

        // Add custom token
        wallet.add_ftoken(custom_token.clone()).unwrap();

        // Verify token was added
        assert_eq!(wallet.ftokens.len(), 2);
        assert_eq!(wallet.ftokens[1].symbol, "TST");
        assert!(!wallet.ftokens[1].default);

        // Save wallet state
        let wallet_addr = wallet.key().unwrap();
        wallet.save_to_storage().unwrap();

        // Create new wallet instance from storage
        let mut loaded_wallet =
            Wallet::load_from_storage(&wallet_addr, Arc::clone(&storage)).unwrap();

        // Before unlock - should have empty token list
        assert_eq!(loaded_wallet.ftokens.len(), 0);

        // Unlock wallet - should restore tokens
        loaded_wallet.unlock(&argon_seed).unwrap();

        // Verify tokens were restored correctly
        assert_eq!(loaded_wallet.ftokens.len(), 2);

        // Verify default token
        assert!(loaded_wallet.ftokens[0].default);
        assert_eq!(loaded_wallet.ftokens[0].symbol, "ETH");

        // Verify custom token
        assert!(!loaded_wallet.ftokens[1].default);
        assert_eq!(loaded_wallet.ftokens[1].symbol, "TST");
        assert_eq!(loaded_wallet.ftokens[1].addr, custom_token.addr);
        assert_eq!(loaded_wallet.ftokens[1].decimals, custom_token.decimals);
    }

    #[test]
    fn test_multiple_custom_tokens() {
        // Setup wallet similar to previous test
        let argon_seed = derive_key(PASSWORD, PROOF_SALT).unwrap();
        let proof = derive_key(&argon_seed[..PROOF_SIZE], PROOF_SALT).unwrap();
        let mut rng = rand::thread_rng();
        let dir = format!("/tmp/{}", rng.gen::<usize>());
        let storage = LocalStorage::from(&dir).unwrap();
        let storage = Arc::new(storage);
        let keychain = KeyChain::from_seed(&argon_seed).unwrap();
        let keypair = KeyPair::gen_keccak256().unwrap();
        let sk = keypair.get_secretkey().unwrap();

        let wallet_config = WalletConfig {
            keychain,
            storage: Arc::clone(&storage),
            settings: Default::default(),
        };

        let mut wallet = Wallet::from_sk(
            &sk,
            "Multi Token Account".to_string(),
            &proof,
            wallet_config,
            "Multi Token Test Wallet".to_string(),
            Default::default(),
            vec![0],
        )
        .unwrap();

        // Add multiple custom tokens
        let tokens = vec![
            FToken {
                name: "Token 1".to_string(),
                symbol: "TK1".to_string(),
                decimals: 18,
                addr: Address::from_zil_base16("1111111111111111111111111111111111111111").unwrap(),
                logo: None,
                default: false,
                balances: HashMap::new(),
            },
            FToken {
                name: "Token 2".to_string(),
                symbol: "TK2".to_string(),
                decimals: 6,
                addr: Address::from_zil_base16("2222222222222222222222222222222222222222").unwrap(),
                logo: None,
                default: false,
                balances: HashMap::new(),
            },
            FToken {
                name: "Token 3".to_string(),
                symbol: "TK3".to_string(),
                decimals: 8,
                addr: Address::from_zil_base16("3333333333333333333333333333333333333333").unwrap(),
                logo: None,
                default: false,
                balances: HashMap::new(),
            },
        ];

        // Add all tokens
        for token in tokens.iter() {
            wallet.add_ftoken(token.clone()).unwrap();
        }

        // Verify all tokens were added (1 default + 3 custom)
        assert_eq!(wallet.ftokens.len(), 4);

        // Save and reload wallet
        let wallet_addr = wallet.key().unwrap();
        wallet.save_to_storage().unwrap();

        let mut loaded_wallet =
            Wallet::load_from_storage(&wallet_addr, Arc::clone(&storage)).unwrap();
        loaded_wallet.unlock(&argon_seed).unwrap();

        // Verify all tokens were restored
        assert_eq!(loaded_wallet.ftokens.len(), 4);

        // Verify default token
        assert!(loaded_wallet.ftokens[0].default);
        assert_eq!(loaded_wallet.ftokens[0].symbol, "ETH");

        // Verify custom tokens
        for (i, token) in tokens.iter().enumerate() {
            assert_eq!(loaded_wallet.ftokens[i + 1].name, token.name);
            assert_eq!(loaded_wallet.ftokens[i + 1].symbol, token.symbol);
            assert_eq!(loaded_wallet.ftokens[i + 1].decimals, token.decimals);
            assert_eq!(loaded_wallet.ftokens[i + 1].addr, token.addr);
            assert!(!loaded_wallet.ftokens[i + 1].default);
        }
    }

    #[test]
    fn test_remove_tokens() {
        // Setup wallet
        let argon_seed = derive_key(PASSWORD, PROOF_SALT).unwrap();
        let proof = derive_key(&argon_seed[..PROOF_SIZE], PROOF_SALT).unwrap();
        let mut rng = rand::thread_rng();
        let dir = format!("/tmp/{}", rng.gen::<usize>());
        let storage = LocalStorage::from(&dir).unwrap();
        let storage = Arc::new(storage);
        let keychain = KeyChain::from_seed(&argon_seed).unwrap();
        let keypair = KeyPair::gen_keccak256().unwrap();
        let sk = keypair.get_secretkey().unwrap();

        let wallet_config = WalletConfig {
            keychain,
            storage: Arc::clone(&storage),
            settings: Default::default(),
        };

        let mut wallet = Wallet::from_sk(
            &sk,
            "Remove Token Test Account".to_string(),
            &proof,
            wallet_config,
            "Remove Token Test Wallet".to_string(),
            Default::default(),
            vec![0],
        )
        .unwrap();

        // Add multiple custom tokens
        let tokens = vec![
            FToken {
                name: "Token 1".to_string(),
                symbol: "TK1".to_string(),
                decimals: 18,
                addr: Address::from_zil_base16("1111111111111111111111111111111111111111").unwrap(),
                logo: None,
                default: false,
                balances: HashMap::new(),
            },
            FToken {
                name: "Token 2".to_string(),
                symbol: "TK2".to_string(),
                decimals: 6,
                addr: Address::from_zil_base16("2222222222222222222222222222222222222222").unwrap(),
                logo: None,
                default: false,
                balances: HashMap::new(),
            },
            FToken {
                name: "Token 3".to_string(),
                symbol: "TK3".to_string(),
                decimals: 8,
                addr: Address::from_zil_base16("3333333333333333333333333333333333333333").unwrap(),
                logo: None,
                default: false,
                balances: HashMap::new(),
            },
        ];

        // Add all tokens
        for token in tokens.iter() {
            wallet.add_ftoken(token.clone()).unwrap();
        }

        // Initial state should have 4 tokens (1 default + 3 custom)
        assert_eq!(wallet.ftokens.len(), 4);
        assert!(wallet.ftokens[0].default); // Default ETH token
        assert_eq!(wallet.ftokens[1].symbol, "TK1");
        assert_eq!(wallet.ftokens[2].symbol, "TK2");
        assert_eq!(wallet.ftokens[3].symbol, "TK3");

        // Try to remove a custom token (Token 2)
        wallet.remove_ftoken(2).unwrap();

        // Should now have 3 tokens (1 default + 2 custom)
        assert_eq!(wallet.ftokens.len(), 3);
        assert!(wallet.ftokens[0].default); // Default ETH token should still be first
        assert_eq!(wallet.ftokens[1].symbol, "TK1");
        assert_eq!(wallet.ftokens[2].symbol, "TK3"); // TK2 should be gone

        // Save and reload wallet to verify persistence
        let wallet_addr = wallet.key().unwrap();
        wallet.save_to_storage().unwrap();

        let mut loaded_wallet =
            Wallet::load_from_storage(&wallet_addr, Arc::clone(&storage)).unwrap();
        loaded_wallet.unlock(&argon_seed).unwrap();

        // Verify state after reload
        assert_eq!(loaded_wallet.ftokens.len(), 3);
        assert!(loaded_wallet.ftokens[0].default);
        assert_eq!(loaded_wallet.ftokens[1].symbol, "TK1");
        assert_eq!(loaded_wallet.ftokens[2].symbol, "TK3");

        // Try to remove default token (should still work but token will be restored on reload)
        wallet.remove_ftoken(0).unwrap();
        assert_eq!(wallet.ftokens.len(), 2);
        assert_eq!(wallet.ftokens[0].symbol, "TK1");
        assert_eq!(wallet.ftokens[1].symbol, "TK3");

        // Save and reload again
        wallet.save_to_storage().unwrap();
        let mut loaded_wallet2 =
            Wallet::load_from_storage(&wallet_addr, Arc::clone(&storage)).unwrap();
        loaded_wallet2.unlock(&argon_seed).unwrap();

        // Default token should be restored
        assert_eq!(loaded_wallet2.ftokens.len(), 3);
        assert!(loaded_wallet2.ftokens[0].default);
        assert_eq!(loaded_wallet2.ftokens[0].symbol, "ETH");
        assert_eq!(loaded_wallet2.ftokens[1].symbol, "TK1");
        assert_eq!(loaded_wallet2.ftokens[2].symbol, "TK3");
    }
}
