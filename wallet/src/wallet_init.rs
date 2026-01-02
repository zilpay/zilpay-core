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
    use test_data::{ANVIL_MNEMONIC, TEST_PASSWORD};

    use crate::{
        wallet_crypto::WalletCrypto, wallet_data::AuthMethod, wallet_init::WalletInit,
        wallet_storage::StorageOperations, wallet_types::WalletTypes, Bip39Params, SecretKeyParams,
        Wallet, WalletConfig,
    };

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

        let argon_seed = derive_key(TEST_PASSWORD.as_bytes(), "", &ARGON2_DEFAULT_CONFIG).unwrap();
        let keychain = KeyChain::from_seed(&argon_seed).unwrap();
        let mnemonic = Mnemonic::parse_str(&EN_WORDS, ANVIL_MNEMONIC).unwrap();
        let indexes = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10].map(|i| {
            (
                DerivationPath::new(slip44::ZILLIQA, i, DerivationPath::BIP44_PURPOSE, None),
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
    fn test_init_from_bip39_btc() {
        let (storage, _dir) = setup_test_storage();

        let argon_seed = derive_key(TEST_PASSWORD.as_bytes(), "", &ARGON2_DEFAULT_CONFIG).unwrap();
        let keychain = KeyChain::from_seed(&argon_seed).unwrap();
        let mnemonic = Mnemonic::parse_str(&EN_WORDS, ANVIL_MNEMONIC).unwrap();
        let indexes = [0, 1, 2].map(|i| {
            (
                DerivationPath::new(
                    slip44::BITCOIN,
                    i,
                    DerivationPath::BIP84_PURPOSE,
                    Some(bitcoin::Network::Bitcoin),
                ),
                format!("Bitcoin Account {i}"),
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
                wallet_name: "Bitcoin Wallet".to_string(),
                biometric_type: AuthMethod::Biometric,
            },
            wallet_config,
            vec![],
        )
        .unwrap();

        let data = wallet.get_wallet_data().unwrap();

        assert_eq!(data.accounts.len(), indexes.len());

        for account in &data.accounts {
            assert_eq!(account.slip_44, slip44::BITCOIN);
            let addr_str = account.addr.auto_format();
            assert!(addr_str.starts_with("bc1"));
        }
    }

    #[test]
    fn test_init_from_sk() {
        let (storage, _dir) = setup_test_storage();

        let argon_seed = derive_key(TEST_PASSWORD.as_bytes(), "", &ARGON2_DEFAULT_CONFIG).unwrap();
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

    #[test]
    fn test_btc_bip44_legacy_addresses() {
        let (storage, _dir) = setup_test_storage();

        let argon_seed = derive_key(TEST_PASSWORD.as_bytes(), "", &ARGON2_DEFAULT_CONFIG).unwrap();
        let keychain = KeyChain::from_seed(&argon_seed).unwrap();
        let mnemonic = Mnemonic::parse_str(&EN_WORDS, ANVIL_MNEMONIC).unwrap();

        // Create 10 BIP44 accounts (Legacy P2PKH)
        let indexes = (0..10).map(|i| {
            (
                DerivationPath::new(
                    slip44::BITCOIN,
                    i,
                    DerivationPath::BIP44_PURPOSE,
                    Some(bitcoin::Network::Bitcoin),
                ),
                format!("BIP44 Account {i}"),
            )
        }).collect::<Vec<_>>();

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
                wallet_name: "BIP44 Legacy Wallet".to_string(),
                biometric_type: AuthMethod::Biometric,
            },
            wallet_config,
            vec![],
        )
        .unwrap();

        let data = wallet.get_wallet_data().unwrap();
        assert_eq!(data.accounts.len(), 10);

        // Expected BIP44 (Legacy P2PKH) addresses
        let expected_addresses = [
            "1Ei9UmLQv4o4UJTy5r5mnGFeC9auM3W5P1",
            "14RBPsg6mBkLSJokkzeuoCkTtoeD3nK2Kz",
            "1CvVq3DvykCiuKztE29EsLzvmgbbcWQWBr",
            "1PKTCMqJj6WaxjvsJ5MS4eD9c9y4kFKBmw",
            "183tGKoJnN1CuPLKBrmA4AzdAdpjLyhuTo",
            "1MhdQzGdKV1JroUAvynhiBTiRgqz8zvY2c",
            "14UvrKCKAp8gyxixcK3kY6t7yGpwYVdavQ",
            "1Fss6gNo8HZZocBzKEYgjj32qQ71Rtn4B2",
            "1NVP7RDEromaXGthjzmb5xxLSZDptk7LvB",
            "1MV7i4aBVbjm81nwkaYcgUTDFehX2dBz4z",
        ];

        for (i, account) in data.accounts.iter().enumerate() {
            assert_eq!(account.slip_44, slip44::BITCOIN);
            let addr_str = account.addr.auto_format();
            assert_eq!(
                addr_str, expected_addresses[i],
                "Account {} address mismatch: expected {}, got {}",
                i, expected_addresses[i], addr_str
            );
        }
    }

    #[test]
    fn test_btc_bip49_nested_segwit_addresses() {
        let (storage, _dir) = setup_test_storage();

        let argon_seed = derive_key(TEST_PASSWORD.as_bytes(), "", &ARGON2_DEFAULT_CONFIG).unwrap();
        let keychain = KeyChain::from_seed(&argon_seed).unwrap();
        let mnemonic = Mnemonic::parse_str(&EN_WORDS, ANVIL_MNEMONIC).unwrap();

        // Create 10 BIP49 accounts (Nested SegWit P2SH-P2WPKH)
        let indexes = (0..10).map(|i| {
            (
                DerivationPath::new(
                    slip44::BITCOIN,
                    i,
                    DerivationPath::BIP49_PURPOSE,
                    Some(bitcoin::Network::Bitcoin),
                ),
                format!("BIP49 Account {i}"),
            )
        }).collect::<Vec<_>>();

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
                wallet_name: "BIP49 Nested SegWit Wallet".to_string(),
                biometric_type: AuthMethod::Biometric,
            },
            wallet_config,
            vec![],
        )
        .unwrap();

        let data = wallet.get_wallet_data().unwrap();
        assert_eq!(data.accounts.len(), 10);

        // Expected BIP49 (Nested SegWit P2SH-P2WPKH) addresses
        let expected_addresses = [
            "39sr5B8UAdxeoXbnpdw4frfxXwWwEChwzp",
            "37EtUYWDGFUYhF65JqZMkkiUd4dDmwHv8J",
            "3B9F7Smod2KrRVT4tzodovWhxk4YEJyr7J",
            "3A8fg1FotWaxizX9Q4rTs2Z1KHqG2zBqbV",
            "39gds78EiBNYL838TqJxR6iAYywGBo3koo",
            "35XomGq1MoMrepjCvpxcSPrt4g8trXpjwL",
            "35kJdQJWCsp3MJCtJmQQJyZJo6jCEY1wUn",
            "3KwcX3Ry4LWAtbqbwFnqrAqczCLYwz78mn",
            "34FAEktmY5jRvA52Y5puPSi26pNueBeEvu",
            "3KQtD5x8ah3P882NVS9Jd4bydbGKWWchkv",
        ];

        for (i, account) in data.accounts.iter().enumerate() {
            assert_eq!(account.slip_44, slip44::BITCOIN);
            let addr_str = account.addr.auto_format();
            assert_eq!(
                addr_str, expected_addresses[i],
                "Account {} address mismatch: expected {}, got {}",
                i, expected_addresses[i], addr_str
            );
        }
    }

    #[test]
    fn test_btc_bip84_native_segwit_addresses() {
        let (storage, _dir) = setup_test_storage();

        let argon_seed = derive_key(TEST_PASSWORD.as_bytes(), "", &ARGON2_DEFAULT_CONFIG).unwrap();
        let keychain = KeyChain::from_seed(&argon_seed).unwrap();
        let mnemonic = Mnemonic::parse_str(&EN_WORDS, ANVIL_MNEMONIC).unwrap();

        // Create 10 BIP84 accounts (Native SegWit Bech32 P2WPKH)
        let indexes = (0..10).map(|i| {
            (
                DerivationPath::new(
                    slip44::BITCOIN,
                    i,
                    DerivationPath::BIP84_PURPOSE,
                    Some(bitcoin::Network::Bitcoin),
                ),
                format!("BIP84 Account {i}"),
            )
        }).collect::<Vec<_>>();

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
                wallet_name: "BIP84 Native SegWit Wallet".to_string(),
                biometric_type: AuthMethod::Biometric,
            },
            wallet_config,
            vec![],
        )
        .unwrap();

        let data = wallet.get_wallet_data().unwrap();
        assert_eq!(data.accounts.len(), 10);

        // Expected BIP84 (Native SegWit Bech32 P2WPKH) addresses
        let expected_addresses = [
            "bc1q4qw42stdzjqs59xvlrlxr8526e3nunw7mp73te",
            "bc1qp533522veg9uyhpx3sva9vqrnfzmt262n4lsuq",
            "bc1qt3az9lwpqfvr466mezsewuzdc4d379ldv83d4c",
            "bc1qcqp7wgm6ke7zvwqnyy5a52ratfuhufw0zhpmxg",
            "bc1qrun8yxx8rtqgj366lpas72g6q85dax6zr9jvds",
            "bc1quprel4xahn7pp2quf2rakzewms7gy7uflr9sj3",
            "bc1qthm96f59e9k8rjt2c3d2ajn9ec27y2hfyeee3z",
            "bc1q2lg7fgxty72wsl295j0ghhdxdwwweu2c9ptyrp",
            "bc1qahte80k6ajvkdsv5q7vljhd9jecr8fvn7nra3k",
            "bc1qp9dt7umyhmee7lm5raau62uq4m3dfpnsvz743g",
        ];

        for (i, account) in data.accounts.iter().enumerate() {
            assert_eq!(account.slip_44, slip44::BITCOIN);
            let addr_str = account.addr.auto_format();
            assert_eq!(
                addr_str, expected_addresses[i],
                "Account {} address mismatch: expected {}, got {}",
                i, expected_addresses[i], addr_str
            );
        }
    }

    #[test]
    fn test_btc_bip86_taproot_addresses() {
        let (storage, _dir) = setup_test_storage();

        let argon_seed = derive_key(TEST_PASSWORD.as_bytes(), "", &ARGON2_DEFAULT_CONFIG).unwrap();
        let keychain = KeyChain::from_seed(&argon_seed).unwrap();
        let mnemonic = Mnemonic::parse_str(&EN_WORDS, ANVIL_MNEMONIC).unwrap();

        // Create 10 BIP86 accounts (Taproot Bech32m P2TR)
        let indexes = (0..10).map(|i| {
            (
                DerivationPath::new(
                    slip44::BITCOIN,
                    i,
                    DerivationPath::BIP86_PURPOSE,
                    Some(bitcoin::Network::Bitcoin),
                ),
                format!("BIP86 Account {i}"),
            )
        }).collect::<Vec<_>>();

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
                wallet_name: "BIP86 Taproot Wallet".to_string(),
                biometric_type: AuthMethod::Biometric,
            },
            wallet_config,
            vec![],
        )
        .unwrap();

        let data = wallet.get_wallet_data().unwrap();
        assert_eq!(data.accounts.len(), 10);

        // Expected BIP86 (Taproot Bech32m P2TR) addresses
        let expected_addresses = [
            "bc1pfzhx49qe6s5exppe5hqljg3n6587xk0w75xqr70pgdt7ygnfkssqxqjd9l",
            "bc1p0lks35d0spqsvz2t3t0kqus38wrlpmcjtvvupkfkwdrzfh6zjyps9rvd6v",
            "bc1p6f0xvqe892y0fvm2hwnmmj6fzczp7lx6tluvwhymcca4d7a45jjsgzlsdv",
            "bc1prleszyly6wky4xtse5l08klr0z7duwyj2z59j66km7j8jkvrde9qc09cx7",
            "bc1pwvm0vsxxl783w3x9psduqztqzju9hcnpf3k0gdkkm204m0cmgmts3feqlc",
            "bc1pa9pz4s6n4evtjvdnel9649kfwez357l8d2wg7aezc9gsx5m0xyas6nqzqj",
            "bc1pvn6plel4fv9ae08fxkrqxl5wj337mcv86wzaqnyj75fpe6udj8lq4u3fge",
            "bc1pfzh443ddrsxu60talwm74mjxjuwst8zaqp8u5pvna5lp6632d3rqe6w0uc",
            "bc1p3kmwqq4tzwxvf0800q02h6l9mkvhzghaw646s547ffx2xvf43r6q2fwsm0",
            "bc1p5384xp7jdxfqtskak98r2vf0th0jwuxwczsxu4ech5z2f7kaejmqpmgq9d",
        ];

        for (i, account) in data.accounts.iter().enumerate() {
            assert_eq!(account.slip_44, slip44::BITCOIN);
            let addr_str = account.addr.auto_format();
            assert_eq!(
                addr_str, expected_addresses[i],
                "Account {} address mismatch: expected {}, got {}",
                i, expected_addresses[i], addr_str
            );
        }
    }
}
