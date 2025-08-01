use crate::{
    account::{self, Account},
    wallet_data::WalletData,
    wallet_types::WalletTypes,
    Result, SecretKeyParams, Wallet, WalletAddrType,
};
use proto::pubkey::PubKey;
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

use config::sha::SHA256_SIZE;
use errors::{account::AccountErrors, wallet::WalletErrors};
use std::sync::Arc;
use token::ft::FToken;

use crate::{wallet_storage::StorageOperations, Bip39Params, LedgerParams, WalletConfig};

pub trait WalletInit {
    type Error;

    fn from_ledger(
        params: LedgerParams,
        config: WalletConfig,
        ftokens: Vec<FToken>,
    ) -> std::result::Result<Self, Self::Error>
    where
        Self: Sized;

    fn from_sk(
        params: SecretKeyParams,
        config: WalletConfig,
        ftokens: Vec<FToken>,
    ) -> std::result::Result<Self, Self::Error>
    where
        Self: Sized;

    fn wallet_key_gen() -> WalletAddrType;

    fn from_bip39_words(
        params: Bip39Params,
        config: WalletConfig,
        ftokens: Vec<FToken>,
    ) -> std::result::Result<Self, Self::Error>
    where
        Self: Sized;
}

impl WalletInit for Wallet {
    type Error = WalletErrors;

    fn wallet_key_gen() -> WalletAddrType {
        let mut rng = ChaCha20Rng::from_entropy();
        let mut chacha_key = [0u8; SHA256_SIZE];

        rng.fill_bytes(&mut chacha_key);

        chacha_key
    }

    fn from_ledger(
        params: LedgerParams,
        config: WalletConfig,
        ftokens: Vec<FToken>,
    ) -> Result<Self> {
        let cipher_proof = config
            .keychain
            .make_proof(&params.proof, &config.settings.cipher_orders)?;
        let proof_key = Self::safe_storage_save(&cipher_proof, Arc::clone(&config.storage))?;

        drop(cipher_proof);

        let wallet_address: [u8; SHA256_SIZE] = Self::wallet_key_gen();
        let chain_hash = params.chain_config.hash();

        let accounts: Vec<Account> = params
            .pub_keys
            .into_iter()
            .zip(params.account_names.into_iter())
            .map(|((ledger_index, pub_key), account_name)| {
                let chain_id = match &pub_key {
                    PubKey::Secp256k1Sha256(_) => params.chain_config.chain_ids[1],
                    _ => params.chain_config.chain_id(),
                };

                Account::from_ledger(
                    pub_key,
                    account_name,
                    ledger_index as usize,
                    chain_hash,
                    chain_id,
                    params.chain_config.slip_44,
                )
            })
            .collect::<std::result::Result<Vec<account::Account>, AccountErrors>>()?;

        let data = WalletData {
            wallet_name: params.wallet_name,
            biometric_type: params.biometric_type,
            proof_key,
            settings: config.settings,
            accounts,
            wallet_type: WalletTypes::Ledger(params.ledger_id),
            selected_account: 0,
            default_chain_hash: params.chain_config.hash(),
        };
        let wallet = Self {
            storage: config.storage,
            wallet_address,
        };

        wallet.save_wallet_data(data)?;
        wallet.save_ftokens(&ftokens)?;

        Ok(wallet)
    }

    fn from_sk(
        params: SecretKeyParams,
        config: WalletConfig,
        ftokens: Vec<FToken>,
    ) -> Result<Self> {
        let sk_as_bytes = params
            .sk
            .to_bytes()
            .map_err(WalletErrors::FailToGetSKBytes)?;

        let cipher_sk = config
            .keychain
            .encrypt(sk_as_bytes.to_vec(), &config.settings.cipher_orders)
            .or(Err(WalletErrors::TryEncryptSecretKeyError))?;
        let cipher_proof = config
            .keychain
            .make_proof(&params.proof, &config.settings.cipher_orders)?;
        let proof_key = Self::safe_storage_save(&cipher_proof, Arc::clone(&config.storage))?;
        drop(cipher_proof);
        let cipher_entropy_key = Self::safe_storage_save(&cipher_sk, Arc::clone(&config.storage))?;
        let wallet_address: [u8; SHA256_SIZE] = Self::wallet_key_gen();
        // SecretKey may stores only one account.
        let account = Account::from_secret_key(
            params.sk,
            params.wallet_name.to_owned(),
            cipher_entropy_key,
            params.chain_config.hash(),
            params.chain_config.chain_id(),
            params.chain_config.slip_44,
        )?;
        let accounts: Vec<account::Account> = vec![account];
        let data = WalletData {
            wallet_name: params.wallet_name,
            biometric_type: params.biometric_type,
            proof_key,
            settings: config.settings,
            accounts,
            wallet_type: WalletTypes::SecretKey,
            selected_account: 0, // for sk account we have only one account.
            default_chain_hash: params.chain_config.hash(),
        };
        let wallet = Self {
            storage: config.storage,
            wallet_address,
        };

        wallet.save_wallet_data(data)?;
        wallet.save_ftokens(&ftokens)?;

        Ok(wallet)
    }

    fn from_bip39_words(
        params: Bip39Params,
        config: WalletConfig,
        ftokens: Vec<FToken>,
    ) -> Result<Self> {
        let mnemonic_str: Vec<u8> = params.mnemonic.to_string().as_bytes().to_vec();
        let cipher_entropy = config
            .keychain
            .encrypt(mnemonic_str, &config.settings.cipher_orders)?;
        let mnemonic_seed = params.mnemonic.to_seed(params.passphrase)?;
        let cipher_proof = config
            .keychain
            .make_proof(&params.proof, &config.settings.cipher_orders)?;
        let proof_key = Self::safe_storage_save(&cipher_proof, Arc::clone(&config.storage))?;
        drop(cipher_proof);
        let cipher_entropy_key =
            Self::safe_storage_save(&cipher_entropy, Arc::clone(&config.storage))?;
        let wallet_address: [u8; SHA256_SIZE] = Self::wallet_key_gen();
        let mut accounts: Vec<account::Account> = Vec::with_capacity(params.indexes.len());

        for index in params.indexes {
            let (bip49, name) = index;
            let hd_account = Account::from_hd(
                &mnemonic_seed,
                name.to_owned(),
                bip49,
                params.chain_config.hash(),
                params.chain_config.chain_id(),
                params.chain_config.slip_44,
            )?;

            accounts.push(hd_account);
        }

        let data = WalletData {
            wallet_name: params.wallet_name,
            biometric_type: params.biometric_type.clone(),
            proof_key,
            settings: config.settings,
            accounts,
            wallet_type: WalletTypes::SecretPhrase((
                cipher_entropy_key,
                !params.passphrase.is_empty(),
            )),
            selected_account: 0,
            default_chain_hash: params.chain_config.hash(),
        };
        let wallet = Self {
            storage: config.storage,
            wallet_address,
        };

        wallet.save_wallet_data(data)?;
        wallet.save_ftokens(&ftokens)?;

        Ok(wallet)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use cipher::{
        argon2::{derive_key, ARGON2_DEFAULT_CONFIG},
        keychain::KeyChain,
    };
    use config::{argon::KEY_SIZE, bip39::EN_WORDS, cipher::PROOF_SIZE};
    use crypto::{bip49::DerivationPath, slip44};
    use errors::wallet::WalletErrors;
    use pqbip39::mnemonic::Mnemonic;
    use proto::keypair::KeyPair;
    use rand::Rng;
    use rpc::network_config::ChainConfig;
    use storage::LocalStorage;

    use crate::{
        wallet_crypto::WalletCrypto, wallet_data::AuthMethod, wallet_init::WalletInit,
        wallet_storage::StorageOperations, wallet_types::WalletTypes, Bip39Params, SecretKeyParams,
        Wallet, WalletConfig,
    };

    const MNEMONIC_STR: &str =
        "green process gate doctor slide whip priority shrug diamond crumble average help";
    const PASSWORD: &[u8] = b"Test_password";
    const PASSPHRASE: &str = "";

    fn setup_test_storage() -> (Arc<LocalStorage>, String) {
        let mut rng = rand::thread_rng();
        let dir = format!("/tmp/{}", rng.gen::<usize>());
        let storage = LocalStorage::from(&dir).unwrap();
        let storage = Arc::new(storage);

        (storage, dir)
    }

    #[test]
    fn test_init_from_bip39_zil() {
        let (storage, _dir) = setup_test_storage();

        let argon_seed = derive_key(PASSWORD, "", &ARGON2_DEFAULT_CONFIG).unwrap();
        let keychain = KeyChain::from_seed(&argon_seed).unwrap();
        let mnemonic = Mnemonic::parse_str(&EN_WORDS, MNEMONIC_STR).unwrap();
        let indexes = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10].map(|i| {
            (
                DerivationPath::new(slip44::ZILLIQA, i),
                format!("account {i}"),
            )
        });
        let proof = derive_key(&argon_seed[..PROOF_SIZE], "", &ARGON2_DEFAULT_CONFIG).unwrap();
        let wallet_config = WalletConfig {
            keychain,
            storage: Arc::clone(&storage),
            settings: Default::default(),
        };
        let chain_config = ChainConfig::default();
        let wallet = Wallet::from_bip39_words(
            Bip39Params {
                chain_config: &chain_config,
                proof,
                mnemonic: &mnemonic,
                passphrase: PASSPHRASE,
                indexes: &indexes,
                wallet_name: "Wllaet name".to_string(),
                biometric_type: AuthMethod::Biometric,
            },
            wallet_config,
            vec![],
        )
        .unwrap();

        let data = wallet.get_wallet_data().unwrap();

        match data.wallet_type {
            WalletTypes::SecretPhrase((_, is_phr)) => {
                assert!(!is_phr);
            }
            _ => panic!("invalid type"),
        }

        assert_eq!(data.accounts.len(), indexes.len());

        let wallet_addr = wallet.wallet_address;

        drop(wallet);

        let res_wallet = Wallet::init_wallet(wallet_addr, Arc::clone(&storage)).unwrap();

        assert!(res_wallet.reveal_mnemonic(&[0u8; KEY_SIZE]).is_err());
        assert!(res_wallet.reveal_mnemonic(&argon_seed).is_ok());
    }

    #[test]
    fn test_init_from_sk() {
        let (storage, _dir) = setup_test_storage();

        let argon_seed = derive_key(PASSWORD, "", &ARGON2_DEFAULT_CONFIG).unwrap();
        let proof = derive_key(&argon_seed[..PROOF_SIZE], "", &ARGON2_DEFAULT_CONFIG).unwrap();

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
        let chain_config = ChainConfig::default();
        let wallet = Wallet::from_sk(
            SecretKeyParams {
                sk,
                proof,
                wallet_name: name.to_string(),
                biometric_type: AuthMethod::None,
                chain_config: &chain_config,
            },
            wallet_config,
            vec![],
        )
        .unwrap();
        let data = wallet.get_wallet_data().unwrap();

        assert_eq!(data.accounts.len(), 1);
        assert_eq!(
            wallet.reveal_mnemonic(&argon_seed),
            Err(WalletErrors::InvalidAccountType)
        );

        let wallet_address = wallet.wallet_address;
        let w = Wallet::init_wallet(wallet_address, Arc::clone(&storage)).unwrap();
        let w_data = w.get_wallet_data().unwrap();

        assert_eq!(w_data, data);
    }
}
