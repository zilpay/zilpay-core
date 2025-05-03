use crate::{
    bg_connections::ConnectionManagement, bg_provider::ProvidersManagement,
    bg_storage::StorageManagement, device_indicators::create_wallet_device_indicator, Background,
    BackgroundLedgerParams, Result,
};
use bip39::Mnemonic;
use cipher::{argon2, keychain::KeyChain};
use config::{
    cipher::{PROOF_SALT, PROOF_SIZE},
    sha::SHA512_SIZE,
};
use errors::{account::AccountErrors, background::BackgroundError, wallet::WalletErrors};
use proto::pubkey::PubKey;
use session::{decrypt_session, encrypt_session};
use settings::wallet_settings::WalletSettings;
use std::sync::Arc;
use wallet::{
    wallet_data::AuthMethod, wallet_init::WalletInit, wallet_security::WalletSecurity,
    wallet_storage::StorageOperations, Bip39Params, LedgerParams, SecretKeyParams, Wallet,
    WalletConfig,
};

use crate::{BackgroundBip39Params, BackgroundSKParams};

pub trait WalletManagement {
    type Error;

    fn unlock_wallet_with_password(
        &self,
        password: &str,
        device_indicators: &[String],
        wallet_index: usize,
    ) -> std::result::Result<[u8; SHA512_SIZE], Self::Error>;

    fn unlock_wallet_with_session(
        &self,
        session_cipher: Vec<u8>,
        device_indicators: &[String],
        wallet_index: usize,
    ) -> std::result::Result<[u8; SHA512_SIZE], Self::Error>;

    fn add_bip39_wallet(
        &mut self,
        params: BackgroundBip39Params,
    ) -> std::result::Result<Vec<u8>, Self::Error>;

    fn add_ledger_wallet(
        &mut self,
        params: BackgroundLedgerParams,
        wallet_settings: WalletSettings,
        device_indicators: &[String],
    ) -> std::result::Result<Vec<u8>, Self::Error>;

    fn add_sk_wallet(
        &mut self,
        params: BackgroundSKParams,
    ) -> std::result::Result<Vec<u8>, Self::Error>;

    fn swap_zilliqa_chain(
        &self,
        wallet_index: usize,
        account_index: usize,
    ) -> std::result::Result<(), Self::Error>;

    fn get_wallet_by_index(&self, wallet_index: usize)
        -> std::result::Result<&Wallet, Self::Error>;
    fn set_biometric(
        &self,
        password: &str,
        mb_session_cipher: Option<Vec<u8>>,
        device_indicators: &[String],
        wallet_index: usize,
        new_biometric_type: AuthMethod,
    ) -> std::result::Result<Option<Vec<u8>>, Self::Error>;

    fn delete_wallet(&mut self, wallet_index: usize) -> std::result::Result<(), Self::Error>;
}

impl WalletManagement for Background {
    type Error = BackgroundError;

    fn set_biometric(
        &self,
        password: &str,
        mb_session_cipher: Option<Vec<u8>>,
        device_indicators: &[String],
        wallet_index: usize,
        new_biometric_type: AuthMethod,
    ) -> Result<Option<Vec<u8>>> {
        let argon_seed = if let Some(session_cipher) = mb_session_cipher {
            self.unlock_wallet_with_session(session_cipher, &device_indicators, wallet_index)?
        } else {
            self.unlock_wallet_with_password(password, &device_indicators, wallet_index)?
        };

        let wallet = self.get_wallet_by_index(wallet_index)?;
        let mut data = wallet.get_wallet_data()?;
        let session = if new_biometric_type != AuthMethod::None {
            let wallet_device_indicators =
                create_wallet_device_indicator(&wallet.wallet_address, device_indicators);

            let gen_session = encrypt_session(
                &wallet_device_indicators,
                &argon_seed,
                &data.settings.cipher_orders,
                &data.settings.argon_params.into_config(),
            )
            .map_err(BackgroundError::CreateSessionError)?;

            Some(gen_session)
        } else {
            None
        };

        data.biometric_type = new_biometric_type;
        wallet.save_wallet_data(data)?;

        Ok(session)
    }

    fn unlock_wallet_with_password(
        &self,
        password: &str,
        device_indicators: &[String],
        wallet_index: usize,
    ) -> Result<[u8; SHA512_SIZE]> {
        let wallet = self.get_wallet_by_index(wallet_index)?;
        let data = wallet.get_wallet_data()?;
        let device_indicator = device_indicators.join(":");
        let argon_seed = argon2::derive_key(
            password.as_bytes(),
            &device_indicator,
            &data.settings.argon_params.into_config(),
        )
        .map_err(BackgroundError::ArgonPasswordHashError)?;

        wallet.unlock(&argon_seed)?;

        Ok(argon_seed)
    }

    fn unlock_wallet_with_session(
        &self,
        session_cipher: Vec<u8>,
        device_indicators: &[String],
        wallet_index: usize,
    ) -> Result<[u8; SHA512_SIZE]> {
        let wallet = self.get_wallet_by_index(wallet_index)?;
        let data = wallet.get_wallet_data()?;
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

    fn add_bip39_wallet(&mut self, params: BackgroundBip39Params) -> Result<Vec<u8>> {
        let provider = self.get_provider(params.chain_hash)?;
        let device_indicator = params.device_indicators.join(":");
        let argon_seed = argon2::derive_key(
            params.password.as_bytes(),
            &device_indicator,
            &params.wallet_settings.argon_params.into_config(),
        )
        .map_err(BackgroundError::ArgonPasswordHashError)?;
        let keychain = KeyChain::from_seed(&argon_seed)?;
        let mnemonic = if params.mnemonic_check {
            Mnemonic::parse_in_normalized(bip39::Language::English, params.mnemonic_str)
                .map_err(|e| BackgroundError::FailParseMnemonicWords(e.to_string()))?
        } else {
            Mnemonic::parse_in_normalized_without_checksum_check(
                bip39::Language::English,
                params.mnemonic_str,
            )
            .map_err(|e| BackgroundError::FailParseMnemonicWords(e.to_string()))?
        };
        let proof = argon2::derive_key(
            &argon_seed[..PROOF_SIZE],
            PROOF_SALT,
            &params.wallet_settings.argon_params.into_config(),
        )
        .map_err(BackgroundError::ArgonCreateProofError)?;
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
        let wallet_device_indicators =
            create_wallet_device_indicator(&wallet.wallet_address, params.device_indicators);

        let session = if data.biometric_type == AuthMethod::None {
            Vec::with_capacity(0)
        } else {
            encrypt_session(
                &wallet_device_indicators,
                &argon_seed,
                &data.settings.cipher_orders,
                &data.settings.argon_params.into_config(),
            )
            .map_err(BackgroundError::CreateSessionError)?
        };
        let mut indicators = Self::get_indicators(Arc::clone(&self.storage));

        indicators.push(wallet.wallet_address);
        self.wallets.push(wallet);
        self.save_indicators(indicators)?;
        self.storage.flush()?;

        Ok(session)
    }

    fn add_ledger_wallet(
        &mut self,
        params: BackgroundLedgerParams,
        wallet_settings: WalletSettings,
        device_indicators: &[String],
    ) -> Result<Vec<u8>> {
        let provider = self.get_provider(params.chain_hash)?;
        let device_indicator = device_indicators.join(":");
        let argon_seed = argon2::derive_key(
            device_indicator.as_bytes(),
            &device_indicator,
            &wallet_settings.argon_params.into_config(),
        )
        .map_err(BackgroundError::ArgonPasswordHashError)?;
        let keychain = KeyChain::from_seed(&argon_seed)?;
        let proof = argon2::derive_key(
            &argon_seed[..PROOF_SIZE],
            PROOF_SALT,
            &wallet_settings.argon_params.into_config(),
        )
        .map_err(BackgroundError::ArgonCreateProofError)?;

        let mut ftokens = provider.config.ftokens.clone();
        ftokens.extend_from_slice(&params.ftokens);

        let wallet_config = WalletConfig {
            keychain,
            storage: Arc::clone(&self.storage),
            settings: wallet_settings,
        };
        let options = &wallet_config.settings.cipher_orders.clone();
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
        let device_indicators =
            create_wallet_device_indicator(&wallet.wallet_address, device_indicators);
        let session = encrypt_session(
            &device_indicators,
            &argon_seed,
            options,
            &data.settings.argon_params.into_config(),
        )
        .map_err(BackgroundError::CreateSessionError)?;
        let mut indicators = Self::get_indicators(Arc::clone(&self.storage));

        indicators.push(wallet.wallet_address);
        self.wallets.push(wallet);
        self.save_indicators(indicators)?;

        Ok(session)
    }

    fn add_sk_wallet(&mut self, params: BackgroundSKParams) -> Result<Vec<u8>> {
        let provider = self.get_provider(params.chain_hash)?;
        // TODO: check this device_indicators is right or not.
        let device_indicator = params.device_indicators.join(":");
        let argon_seed = argon2::derive_key(
            params.password.as_bytes(),
            &device_indicator,
            &params.wallet_settings.argon_params.into_config(),
        )
        .map_err(BackgroundError::ArgonPasswordHashError)?;
        let keychain = KeyChain::from_seed(&argon_seed)?;
        let proof = argon2::derive_key(
            &argon_seed[..PROOF_SIZE],
            PROOF_SALT,
            &params.wallet_settings.argon_params.into_config(),
        )
        .map_err(BackgroundError::ArgonCreateProofError)?;
        let mut ftokens = provider.config.ftokens.clone();
        ftokens.extend_from_slice(&params.ftokens);

        let wallet_config = WalletConfig {
            keychain,
            storage: Arc::clone(&self.storage),
            settings: params.wallet_settings,
        };
        let options = &wallet_config.settings.cipher_orders.clone();
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

        let wallet_device_indicators =
            create_wallet_device_indicator(&wallet.wallet_address, params.device_indicators);
        let session = if data.biometric_type == AuthMethod::None {
            Vec::new()
        } else {
            encrypt_session(
                &wallet_device_indicators,
                &argon_seed,
                options,
                &data.settings.argon_params.into_config(),
            )
            .map_err(BackgroundError::CreateSessionError)?
        };
        let mut indicators = Self::get_indicators(Arc::clone(&self.storage));

        indicators.push(wallet.wallet_address);
        self.wallets.push(wallet);
        self.save_indicators(indicators)?;

        Ok(session)
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
    use proto::keypair::KeyPair;
    use rand::Rng;
    use rpc::network_config::{ChainConfig, Explorer};

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
            features: vec![155, 1559],
            slip_44: slip44::ZILLIQA,
            ens: None,
            explorers: vec![Explorer {
                name: "TestExplorer".to_string(),
                url: "https://test.explorer".to_string(),
                icon: None,
                standard: 3091,
            }],
            fallback_enabled: true,
        }
    }

    #[test]
    fn test_add_more_wallets_bip39() {
        let (mut bg, dir) = setup_test_background();

        assert_eq!(bg.wallets.len(), 0);

        let password = "test_password";
        let words = Background::gen_bip39(24).unwrap();
        let net_conf = create_test_net_conf();
        let accounts = [(
            DerivationPath::new(slip44::ZILLIQA, 0),
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
        .unwrap();

        assert_eq!(bg.wallets.len(), 1);

        drop(bg);

        let mut bg = Background::from_storage_path(&dir).unwrap();
        let words = Background::gen_bip39(24).unwrap();
        let password = "newPassowrd";
        let accounts = [
            (
                DerivationPath::new(slip44::ETHEREUM, 1),
                "Eth Wallet".to_string(),
            ),
            (
                DerivationPath::new(slip44::ETHEREUM, 2),
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
        .unwrap();

        drop(bg);

        let bg = Background::from_storage_path(&dir).unwrap();

        assert_eq!(bg.wallets.len(), 2);
    }

    #[test]
    fn test_delete_wallet() {
        let (mut bg, dir) = setup_test_background();

        let password = "test_password";
        let words = Background::gen_bip39(24).unwrap();
        let net_conf = create_test_net_conf();
        let accounts = [(
            DerivationPath::new(slip44::ZILLIQA, 0),
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
        .unwrap();

        assert_eq!(bg.wallets.len(), 2);

        assert!(bg.delete_wallet(3).is_err());

        bg.delete_wallet(0).unwrap();
        assert_eq!(bg.wallets.len(), 1);
        drop(bg);

        let bg = Background::from_storage_path(&dir).unwrap();

        assert_eq!(bg.wallets.len(), 1);
    }
}
