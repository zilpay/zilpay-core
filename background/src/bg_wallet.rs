use crate::{
    bg_connections::ConnectionManagement, bg_provider::ProvidersManagement,
    bg_storage::StorageManagement, device_indicators::create_wallet_device_indicator, Background,
    BackgroundLedgerParams, Result,
};
use async_trait::async_trait;
use cipher::{
    argon2::{self, Argon2Seed},
    keychain::KeyChain,
};
use config::{
    bip39::EN_WORDS,
    cipher::{PROOF_SALT, PROOF_SIZE},
    session::AuthMethod,
};
use errors::{account::AccountErrors, background::BackgroundError, wallet::WalletErrors};
use pqbip39::mnemonic::Mnemonic;
use proto::pubkey::PubKey;
use secrecy::{ExposeSecret, SecretSlice};
use session::{
    decrypt_session,
    management::{SessionManagement, SessionManager},
};
use settings::wallet_settings::WalletSettings;
use std::sync::Arc;
use wallet::{
    wallet_init::WalletInit, wallet_security::WalletSecurity, wallet_storage::StorageOperations,
    Bip39Params, LedgerParams, SecretKeyParams, Wallet, WalletConfig,
};

use crate::{BackgroundBip39Params, BackgroundSKParams};

#[async_trait]
pub trait WalletManagement {
    type Error;

    fn unlock_wallet_with_password(
        &self,
        password: &str,
        device_indicators: &[String],
        wallet_index: usize,
    ) -> std::result::Result<Argon2Seed, Self::Error>;

    async fn unlock_wallet_with_session(
        &self,
        session_cipher: Vec<u8>,
        device_indicators: &[String],
        wallet_index: usize,
    ) -> std::result::Result<Argon2Seed, Self::Error>;

    async fn add_bip39_wallet<'a>(
        &'a mut self,
        params: BackgroundBip39Params<'_>,
    ) -> std::result::Result<(), Self::Error>;

    async fn add_ledger_wallet(
        &mut self,
        params: BackgroundLedgerParams,
        wallet_settings: WalletSettings,
        device_indicators: &[String],
    ) -> std::result::Result<(), Self::Error>;

    async fn add_sk_wallet<'a>(
        &'a mut self,
        params: BackgroundSKParams<'_>,
    ) -> std::result::Result<(), Self::Error>;

    fn swap_zilliqa_chain(
        &self,
        wallet_index: usize,
        account_index: usize,
    ) -> std::result::Result<(), Self::Error>;

    fn get_wallet_by_index(&self, wallet_index: usize)
        -> std::result::Result<&Wallet, Self::Error>;
    async fn set_biometric(
        &self,
        password: &str,
        mb_session_cipher: Option<Vec<u8>>,
        device_indicators: &[String],
        wallet_index: usize,
        new_biometric_type: AuthMethod,
    ) -> std::result::Result<(), Self::Error>;

    fn delete_wallet(&mut self, wallet_index: usize) -> std::result::Result<(), Self::Error>;
}

#[async_trait]
impl WalletManagement for Background {
    type Error = BackgroundError;

    async fn set_biometric(
        &self,
        password: &str,
        mb_session_cipher: Option<Vec<u8>>,
        device_indicators: &[String],
        wallet_index: usize,
        new_biometric_type: AuthMethod,
    ) -> Result<()> {
        let argon_seed = if let Some(session_cipher) = mb_session_cipher {
            self.unlock_wallet_with_session(session_cipher, &device_indicators, wallet_index)
                .await?
        } else {
            self.unlock_wallet_with_password(password, &device_indicators, wallet_index)?
        };

        let wallet = self.get_wallet_by_index(wallet_index)?;
        let mut data = wallet.get_wallet_data()?;

        if new_biometric_type != AuthMethod::None {
            let session = SessionManager::new(
                Arc::clone(&self.storage),
                0,
                &wallet.wallet_address,
                &data.settings.cipher_orders,
            );
            let secert_bytes = SecretSlice::new(argon_seed.into());

            session.create_session(secert_bytes).await?;
        }

        data.biometric_type = new_biometric_type;
        wallet.save_wallet_data(data)?;

        Ok(())
    }

    fn unlock_wallet_with_password(
        &self,
        password: &str,
        device_indicators: &[String],
        wallet_index: usize,
    ) -> Result<Argon2Seed> {
        let wallet = self.get_wallet_by_index(wallet_index)?;
        let data = wallet.get_wallet_data()?;
        let device_indicator = device_indicators.join(":");
        let argon_seed = argon2::derive_key(
            password.as_bytes(),
            &device_indicator,
            &data.settings.argon_params.into_config(),
        )?;

        wallet.unlock(&argon_seed)?;

        Ok(argon_seed)
    }

    async fn unlock_wallet_with_session(
        &self,
        session_cipher: Vec<u8>,
        device_indicators: &[String],
        wallet_index: usize,
    ) -> Result<Argon2Seed> {
        let wallet = self.get_wallet_by_index(wallet_index)?;
        let data = wallet.get_wallet_data()?;

        if session_cipher.is_empty() {
            let session = SessionManager::new(
                Arc::clone(&self.storage),
                0,
                &wallet.wallet_address,
                &data.settings.cipher_orders,
            );
            let seed_bytes: Argon2Seed = session
                .unlock_session()
                .await?
                .expose_secret()
                .to_vec()
                .try_into()
                .map_err(|_| {
                    BackgroundError::SessionErrors(
                        errors::session::SessionErrors::InvalidDecryptSession,
                    )
                })?;

            Ok(seed_bytes)
        } else {
            let wallet_device_indicators =
                create_wallet_device_indicator(&wallet.wallet_address, device_indicators);

            let seed_bytes = decrypt_session(
                &wallet_device_indicators,
                session_cipher,
                &data.settings.cipher_orders,
                &data.settings.argon_params.into_config(),
            )
            .map_err(BackgroundError::DecryptSessionError)?;

            wallet.unlock(&seed_bytes)?;
            Ok(seed_bytes)
        }
    }

    fn swap_zilliqa_chain(&self, wallet_index: usize, account_index: usize) -> Result<()> {
        let wallet = self.get_wallet_by_index(wallet_index)?;
        let mut data = wallet.get_wallet_data()?;
        let account = data
            .accounts
            .get_mut(account_index)
            .ok_or(WalletErrors::InvalidAccountIndex(account_index))?;
        let provider = self.get_provider(account.chain_hash)?;

        match account.pub_key {
            PubKey::Secp256k1Sha256(pub_key) => {
                account.pub_key = PubKey::Secp256k1Keccak256(pub_key);
                if let Some(chain_id) = provider.config.chain_ids.first() {
                    account.chain_id = *chain_id;
                }
            }
            PubKey::Secp256k1Keccak256(pub_key) => {
                account.pub_key = PubKey::Secp256k1Sha256(pub_key);
                if let Some(chain_id) = provider.config.chain_ids.last() {
                    account.chain_id = *chain_id;
                }
            }
            _ => {
                return Err(AccountErrors::InvalidPubKeyType)?;
            }
        }

        account.addr = account.pub_key.get_addr()?;
        wallet.save_wallet_data(data)?;

        Ok(())
    }

    async fn add_bip39_wallet<'a>(&'a mut self, params: BackgroundBip39Params<'_>) -> Result<()> {
        let provider = self.get_provider(params.chain_hash)?;
        let device_indicator = params.device_indicators.join(":");
        let argon_seed = argon2::derive_key(
            params.password.as_bytes(),
            &device_indicator,
            &params.wallet_settings.argon_params.into_config(),
        )?;
        let keychain = KeyChain::from_seed(&argon_seed)?;
        let mnemonic = if params.mnemonic_check {
            Mnemonic::parse_str(&EN_WORDS, params.mnemonic_str)?
        } else {
            Mnemonic::parse_str_without_checksum(&EN_WORDS, params.mnemonic_str)?
        };
        let proof = argon2::derive_key(
            &argon_seed[..PROOF_SIZE],
            PROOF_SALT,
            &params.wallet_settings.argon_params.into_config(),
        )?;
        let mut ftokens = provider.config.ftokens.clone();
        ftokens.extend_from_slice(&params.ftokens);

        let wallet_config = WalletConfig {
            keychain,
            storage: Arc::clone(&self.storage),
            settings: params.wallet_settings,
        };
        let wallet = Wallet::from_bip39_words(
            Bip39Params {
                proof,
                mnemonic: &mnemonic,
                passphrase: params.passphrase,
                indexes: params.accounts,
                wallet_name: params.wallet_name,
                biometric_type: params.biometric_type,
                chain_config: &provider.config,
            },
            wallet_config,
            ftokens,
        )?;
        let data = wallet.get_wallet_data()?;

        if data.biometric_type != AuthMethod::None {
            let session = SessionManager::new(
                Arc::clone(&self.storage),
                0,
                &wallet.wallet_address,
                &data.settings.cipher_orders,
            );
            let secert_bytes = SecretSlice::new(argon_seed.into());

            session.create_session(secert_bytes).await?;
        }

        let mut indicators = Self::get_indicators(Arc::clone(&self.storage));

        indicators.push(wallet.wallet_address);
        self.wallets.push(wallet);
        self.save_indicators(indicators)?;
        self.storage.flush()?;

        Ok(())
    }

    async fn add_ledger_wallet(
        &mut self,
        params: BackgroundLedgerParams,
        wallet_settings: WalletSettings,
        device_indicators: &[String],
    ) -> Result<()> {
        let provider = self.get_provider(params.chain_hash)?;
        let device_indicator = device_indicators.join(":");
        let argon_seed = argon2::derive_key(
            device_indicator.as_bytes(),
            &device_indicator,
            &wallet_settings.argon_params.into_config(),
        )?;
        let keychain = KeyChain::from_seed(&argon_seed)?;
        let proof = argon2::derive_key(
            &argon_seed[..PROOF_SIZE],
            PROOF_SALT,
            &wallet_settings.argon_params.into_config(),
        )?;

        let mut ftokens = provider.config.ftokens.clone();
        ftokens.extend_from_slice(&params.ftokens);

        let wallet_config = WalletConfig {
            keychain,
            storage: Arc::clone(&self.storage),
            settings: wallet_settings,
        };
        let wallet = Wallet::from_ledger(
            LedgerParams {
                pub_keys: params.pub_keys,
                ledger_id: params.ledger_id,
                proof,
                account_names: params.account_names,
                wallet_name: params.wallet_name,
                wallet_index: params.wallet_index,
                chain_config: &provider.config,
                biometric_type: params.biometric_type,
            },
            wallet_config,
            ftokens,
        )?;
        let data = wallet.get_wallet_data()?;

        if data.biometric_type != AuthMethod::None {
            let session = SessionManager::new(
                Arc::clone(&self.storage),
                0,
                &wallet.wallet_address,
                &data.settings.cipher_orders,
            );
            let secert_bytes = SecretSlice::new(argon_seed.into());

            session.create_session(secert_bytes).await?;
        }

        let mut indicators = Self::get_indicators(Arc::clone(&self.storage));

        indicators.push(wallet.wallet_address);
        self.wallets.push(wallet);
        self.save_indicators(indicators)?;

        Ok(())
    }

    async fn add_sk_wallet<'a>(&'a mut self, params: BackgroundSKParams<'_>) -> Result<()> {
        let provider = self.get_provider(params.chain_hash)?;
        let device_indicator = params.device_indicators.join(":");
        let argon_seed = argon2::derive_key(
            params.password.as_bytes(),
            &device_indicator,
            &params.wallet_settings.argon_params.into_config(),
        )?;
        let keychain = KeyChain::from_seed(&argon_seed)?;
        let proof = argon2::derive_key(
            &argon_seed[..PROOF_SIZE],
            PROOF_SALT,
            &params.wallet_settings.argon_params.into_config(),
        )?;
        let mut ftokens = provider.config.ftokens.clone();
        ftokens.extend_from_slice(&params.ftokens);

        let wallet_config = WalletConfig {
            keychain,
            storage: Arc::clone(&self.storage),
            settings: params.wallet_settings,
        };
        let wallet = Wallet::from_sk(
            SecretKeyParams {
                sk: params.secret_key,
                proof,
                wallet_name: params.wallet_name,
                biometric_type: params.biometric_type,
                chain_config: &provider.config,
            },
            wallet_config,
            ftokens,
        )?;
        let data = wallet.get_wallet_data()?;

        if data.biometric_type != AuthMethod::None {
            let session = SessionManager::new(
                Arc::clone(&self.storage),
                0,
                &wallet.wallet_address,
                &data.settings.cipher_orders,
            );
            let secert_bytes = SecretSlice::new(argon_seed.into());

            session.create_session(secert_bytes).await?;
        }

        let mut indicators = Self::get_indicators(Arc::clone(&self.storage));

        indicators.push(wallet.wallet_address);
        self.wallets.push(wallet);
        self.save_indicators(indicators)?;

        Ok(())
    }

    fn get_wallet_by_index(&self, wallet_index: usize) -> Result<&Wallet> {
        self.wallets
            .get(wallet_index)
            .ok_or(BackgroundError::WalletNotExists(wallet_index))
    }

    fn delete_wallet(&mut self, wallet_index: usize) -> Result<()> {
        let wallet = self.get_wallet_by_index(wallet_index)?;
        let wallet_address = wallet.wallet_address;
        let mut indicators = Self::get_indicators(Arc::clone(&self.storage));

        wallet.clear_data()?;
        wallet.clear_history()?;
        wallet.clear_ftokens()?;
        self.clear_connection(wallet_index)?;

        indicators.retain(|&x| x != wallet_address);
        self.wallets.retain(|x| x.wallet_address != wallet_address);
        self.save_indicators(indicators)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests_background {
    use super::*;
    use crate::{bg_crypto::CryptoOperations, bg_provider::ProvidersManagement};
    use crypto::{bip49::DerivationPath, slip44};
    use proto::{address::Address, keypair::KeyPair};
    use rand::Rng;
    use rpc::network_config::ChainConfig;
    use wallet::wallet_account::AccountManagement;

    fn setup_test_background() -> (Background, String) {
        let mut rng = rand::thread_rng();
        let dir = format!("/tmp/{}", rng.gen::<usize>());
        let bg = Background::from_storage_path(&dir).unwrap();
        (bg, dir)
    }

    fn create_test_net_conf() -> ChainConfig {
        ChainConfig {
            ftokens: vec![],
            logo: String::new(),
            diff_block_time: 0,
            testnet: None,
            chain_ids: [1, 0],
            name: "Test Network".to_string(),
            chain: "TEST".to_string(),
            short_name: String::new(),
            rpc: vec!["https://test.network".to_string()],
            features: vec![],
            slip_44: slip44::ZILLIQA,
            ens: None,
            explorers: vec![],
            fallback_enabled: true,
        }
    }

    #[tokio::test]
    async fn test_add_more_wallets_bip39() {
        let (mut bg, dir) = setup_test_background();

        assert_eq!(bg.wallets.len(), 0);

        let password = "test_password";
        let words = Background::gen_bip39(24).unwrap();
        let net_conf = create_test_net_conf();
        let accounts = [(
            DerivationPath::new(slip44::ZILLIQA, 0, DerivationPath::BIP44_PURPOSE, None),
            "Zilliqa wallet".to_string(),
        )];

        bg.add_provider(net_conf.clone()).unwrap();
        bg.add_bip39_wallet(BackgroundBip39Params {
            password,
            mnemonic_check: true,
            chain_hash: net_conf.hash(),
            mnemonic_str: &words,
            accounts: &accounts,
            wallet_settings: Default::default(),
            passphrase: "",
            wallet_name: String::new(),
            biometric_type: Default::default(),
            device_indicators: &[String::from("apple"), String::from("0000")],
            ftokens: vec![],
        })
        .await
        .unwrap();

        assert_eq!(bg.wallets.len(), 1);

        drop(bg);

        let mut bg = Background::from_storage_path(&dir).unwrap();
        let words = Background::gen_bip39(24).unwrap();
        let password = "newPassowrd";
        let accounts = [
            (
                DerivationPath::new(slip44::ETHEREUM, 1, DerivationPath::BIP44_PURPOSE, None),
                "Eth Wallet".to_string(),
            ),
            (
                DerivationPath::new(slip44::ETHEREUM, 2, DerivationPath::BIP44_PURPOSE, None),
                "account 1".to_string(),
            ),
        ];

        bg.add_bip39_wallet(BackgroundBip39Params {
            password,
            mnemonic_check: true,
            chain_hash: net_conf.hash(),
            accounts: &accounts,
            mnemonic_str: &words,
            wallet_settings: Default::default(),
            passphrase: "",
            wallet_name: String::new(),
            device_indicators: &[String::from("apple"), String::from("43498")],
            biometric_type: Default::default(),
            ftokens: vec![],
        })
        .await
        .unwrap();

        drop(bg);

        let bg = Background::from_storage_path(&dir).unwrap();

        assert_eq!(bg.wallets.len(), 2);
    }

    #[tokio::test]
    async fn test_delete_wallet() {
        let (mut bg, dir) = setup_test_background();

        let password = "test_password";
        let words = Background::gen_bip39(24).unwrap();
        let net_conf = create_test_net_conf();
        let accounts = [(
            DerivationPath::new(slip44::ZILLIQA, 0, DerivationPath::BIP44_PURPOSE, None),
            "Zilliqa wallet".to_string(),
        )];
        let keypair = KeyPair::gen_sha256().unwrap();

        bg.add_provider(net_conf.clone()).unwrap();
        bg.add_bip39_wallet(BackgroundBip39Params {
            mnemonic_check: true,
            password,
            chain_hash: net_conf.hash(),
            mnemonic_str: &words,
            accounts: &accounts,
            wallet_settings: Default::default(),
            passphrase: "",
            wallet_name: String::new(),
            biometric_type: Default::default(),
            device_indicators: &[String::from("apple"), String::from("0000")],
            ftokens: vec![],
        })
        .await
        .unwrap();

        bg.add_sk_wallet(BackgroundSKParams {
            secret_key: keypair.get_secretkey().unwrap(),
            password,
            chain_hash: net_conf.hash(),
            wallet_settings: Default::default(),
            wallet_name: String::new(),
            biometric_type: Default::default(),
            device_indicators: &[String::from("apple"), String::from("0000")],
            ftokens: vec![],
        })
        .await
        .unwrap();

        assert_eq!(bg.wallets.len(), 2);

        assert!(bg.delete_wallet(3).is_err());

        bg.delete_wallet(0).unwrap();
        assert_eq!(bg.wallets.len(), 1);
        drop(bg);

        let bg = Background::from_storage_path(&dir).unwrap();

        assert_eq!(bg.wallets.len(), 1);
    }

    #[tokio::test]
    async fn test_generate_zilliqa_legacy_accounts() {
        let (mut bg, _dir) = setup_test_background();
        let net_conf = create_test_net_conf();
        let password = "test_password";
        let words = Background::gen_bip39(24).unwrap();

        bg.add_provider(net_conf.clone()).unwrap();

        let accounts = [(
            DerivationPath::new(slip44::ZILLIQA, 0, DerivationPath::BIP44_PURPOSE, None),
            "Zilliqa wallet".to_string(),
        )];

        bg.add_bip39_wallet(BackgroundBip39Params {
            password,
            mnemonic_check: true,
            chain_hash: net_conf.hash(),
            mnemonic_str: &words,
            accounts: &accounts,
            wallet_settings: Default::default(),
            passphrase: "",
            wallet_name: "Test Wallet".to_string(),
            biometric_type: Default::default(),
            device_indicators: &[String::from("apple"), String::from("0000")],
            ftokens: vec![],
        })
        .await
        .unwrap();

        bg.swap_zilliqa_chain(0, 0).unwrap();

        assert_eq!(bg.wallets.len(), 1);

        let wallet = bg.get_wallet_by_index(0).unwrap();
        let argon_seed = bg
            .unlock_wallet_with_password(
                password,
                &[String::from("apple"), String::from("0000")],
                0,
            )
            .unwrap();

        if let Address::Secp256k1Sha256(_) = wallet
            .get_wallet_data()
            .unwrap()
            .get_selected_account()
            .unwrap()
            .addr
        {
            assert!(true);
        } else {
            panic!("address should convert to legacy mode");
        }

        for i in 1..20 {
            let bip49 =
                DerivationPath::new(slip44::ZILLIQA, i, DerivationPath::BIP44_PURPOSE, None);
            wallet
                .add_next_bip39_account(
                    format!("Zilliqa account {}", i),
                    &bip49,
                    "",
                    &argon_seed,
                    &net_conf,
                )
                .unwrap();

            bg.swap_zilliqa_chain(0, i).unwrap();
        }

        let data = wallet.get_wallet_data().unwrap();

        for acc in &data.accounts {
            assert!(
                matches!(acc.addr, Address::Secp256k1Sha256(_)),
                "address should be in legacy mode"
            );
        }

        for (i, _) in data.accounts.iter().enumerate() {
            bg.swap_zilliqa_chain(0, i).unwrap();
        }

        let data = wallet.get_wallet_data().unwrap();

        for acc in &data.accounts {
            assert!(
                matches!(acc.addr, Address::Secp256k1Keccak256(_)),
                "address should be in evm mode"
            );
        }
    }

    #[tokio::test]
    async fn test_add_bitcoin_sk_wallet() {
        use test_data::{gen_btc_testnet_conf, gen_device_indicators, TEST_PASSWORD};

        let (mut bg, _dir) = setup_test_background();
        let btc_conf = gen_btc_testnet_conf();
        let device_indicators = gen_device_indicators("test_device");
        let keypair =
            KeyPair::gen_bitcoin(bitcoin::Network::Testnet, bitcoin::AddressType::P2wpkh).unwrap();

        bg.add_provider(btc_conf.clone()).unwrap();

        bg.add_sk_wallet(BackgroundSKParams {
            secret_key: keypair.get_secretkey().unwrap(),
            password: TEST_PASSWORD,
            chain_hash: btc_conf.hash(),
            wallet_settings: Default::default(),
            wallet_name: "Bitcoin Wallet".to_string(),
            biometric_type: Default::default(),
            device_indicators: &device_indicators,
            ftokens: vec![],
        })
        .await
        .unwrap();

        assert_eq!(bg.wallets.len(), 1);

        let wallet = bg.get_wallet_by_index(0).unwrap();
        let data = wallet.get_wallet_data().unwrap();

        assert_eq!(data.wallet_name, "Bitcoin Wallet");
        assert_eq!(data.accounts.len(), 1);
        assert!(matches!(
            data.get_selected_account().unwrap().addr,
            Address::Secp256k1Bitcoin(_)
        ));

        drop(bg);

        let bg = Background::from_storage_path(&_dir).unwrap();
        assert_eq!(bg.wallets.len(), 1);

        let wallet = bg.get_wallet_by_index(0).unwrap();
        let restored_data = wallet.get_wallet_data().unwrap();

        assert_eq!(restored_data.wallet_name, "Bitcoin Wallet");
        assert!(matches!(
            restored_data.get_selected_account().unwrap().addr,
            Address::Secp256k1Bitcoin(_)
        ));
    }
}
