use crate::{
    bg_storage::StorageManagement, device_indicators::create_wallet_device_indicator, Background,
    BackgroundLedgerParams, Result,
};
use bip39::Mnemonic;
use cipher::{argon2, keychain::KeyChain};
use config::{
    cipher::{PROOF_SALT, PROOF_SIZE},
    sha::SHA512_SIZE,
};
use errors::background::BackgroundError;
use session::{decrypt_session, encrypt_session};
use settings::wallet_settings::WalletSettings;
use std::sync::Arc;
use wallet::{
    wallet_data::AuthMethod, wallet_init::WalletInit, wallet_security::WalletSecurity,
    wallet_storage::StorageOperations, wallet_types::WalletTypes, Bip39Params, LedgerParams,
    SecretKeyParams, Wallet, WalletConfig,
};

use crate::{BackgroundBip39Params, BackgroundSKParams};

/// Manages wallet operations including unlocking and creation
pub trait WalletManagement {
    type Error;

    /// Unlocks a wallet using password authentication
    ///
    /// * `password` - User password
    /// * `device_indicators` - Device-specific identifiers
    /// * `wallet_index` - Index of the wallet to unlock
    fn unlock_wallet_with_password(
        &self,
        password: &str,
        device_indicators: &[String],
        wallet_index: usize,
    ) -> std::result::Result<[u8; SHA512_SIZE], Self::Error>;

    /// Unlocks a wallet using an existing session
    ///
    /// * `session_cipher` - Encrypted session data
    /// * `device_indicators` - Device-specific identifiers
    /// * `wallet_index` - Index of the wallet to unlock
    fn unlock_wallet_with_session(
        &self,
        session_cipher: Vec<u8>,
        device_indicators: &[String],
        wallet_index: usize,
    ) -> std::result::Result<[u8; SHA512_SIZE], Self::Error>;

    /// Creates a new BIP39 wallet
    fn add_bip39_wallet(
        &mut self,
        params: BackgroundBip39Params,
    ) -> std::result::Result<Vec<u8>, Self::Error>;

    /// Creates a new Ledger wallet
    fn add_ledger_wallet(
        &mut self,
        params: BackgroundLedgerParams,
        wallet_settings: WalletSettings,
        device_indicators: &[String],
    ) -> std::result::Result<Vec<u8>, Self::Error>;

    /// Creates a new wallet from secret key
    fn add_sk_wallet(
        &mut self,
        params: BackgroundSKParams,
    ) -> std::result::Result<Vec<u8>, Self::Error>;

    /// Retrieves a wallet by its index
    fn get_wallet_by_index(&self, wallet_index: usize)
        -> std::result::Result<&Wallet, Self::Error>;

    fn delete_wallet(&mut self, wallet_index: usize) -> std::result::Result<(), Self::Error>;
}

impl WalletManagement for Background {
    type Error = BackgroundError;

    fn unlock_wallet_with_password(
        &self,
        password: &str,
        device_indicators: &[String],
        wallet_index: usize,
    ) -> Result<[u8; SHA512_SIZE]> {
        let wallet = self.get_wallet_by_index(wallet_index)?;
        let data = wallet.get_wallet_data().unwrap();
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

    fn add_bip39_wallet(&mut self, params: BackgroundBip39Params) -> Result<Vec<u8>> {
        if self.providers.get(params.provider).is_none() {
            return Err(BackgroundError::ProviderNotExists(params.provider));
        }

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
        let wallet = Wallet::from_bip39_words(
            Bip39Params {
                proof,
                mnemonic: &mnemonic,
                passphrase: params.passphrase,
                indexes: params.accounts,
                wallet_name: params.wallet_name,
                biometric_type: params.biometric_type,
                provider_index: params.provider,
            },
            wallet_config,
            params.ftokens,
        )?;
        let data = wallet.get_wallet_data().unwrap();
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
        if self.providers.get(params.provider_index).is_none() {
            return Err(BackgroundError::ProviderNotExists(params.provider_index));
        }

        if self.wallets.iter().any(|w| {
            if let Ok(data) = w.get_wallet_data() {
                matches!(data.wallet_type, WalletTypes::Ledger(id) if id == params.ledger_id)
            } else {
                false
            }
        }) {
            return Err(BackgroundError::LedgerIdExists(
                String::from_utf8(params.ledger_id).unwrap_or_default(),
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
        let wallet = Wallet::from_ledger(
            LedgerParams {
                pub_key: params.pub_key,
                ledger_id: params.ledger_id,
                proof,
                account_name: params.account_name,
                wallet_name: params.wallet_name,
                wallet_index: params.wallet_index,
                provider_index: params.provider_index,
                biometric_type: params.biometric_type,
            },
            wallet_config,
            params.ftokens,
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
        if self.providers.get(params.provider).is_none() {
            return Err(BackgroundError::ProviderNotExists(params.provider));
        }

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
            SecretKeyParams {
                sk: params.secret_key,
                proof,
                wallet_name: params.wallet_name,
                biometric_type: params.biometric_type,
                provider_index: params.provider,
            },
            wallet_config,
            params.ftokens,
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
        let wallet_address = self.get_wallet_by_index(wallet_index)?.wallet_address;
        let mut indicators = Self::get_indicators(Arc::clone(&self.storage));

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
    use crypto::bip49::{Bip49DerivationPath, ETH_PATH, ZIL_PATH};
    use proto::keypair::KeyPair;
    use rand::Rng;
    use rpc::network_config::{Bip44Network, NetworkConfig};

    fn setup_test_background() -> (Background, String) {
        let mut rng = rand::thread_rng();
        let dir = format!("/tmp/{}", rng.gen::<usize>());
        let bg = Background::from_storage_path(&dir).unwrap();
        (bg, dir)
    }

    #[test]
    fn test_add_more_wallets_bip39() {
        let (mut bg, dir) = setup_test_background();

        assert_eq!(bg.wallets.len(), 0);

        let password = "test_password";
        let words = Background::gen_bip39(24).unwrap();
        let accounts = [(
            Bip49DerivationPath::Zilliqa((0, ZIL_PATH.to_string())),
            "Zilliqa wallet".to_string(),
        )];
        let net_conf = NetworkConfig::new(
            "",
            0,
            vec!["".to_string()],
            Bip44Network::Zilliqa(ZIL_PATH.to_string()),
            String::from("TST"),
            None,
        );

        bg.add_provider(net_conf).unwrap();
        bg.add_bip39_wallet(BackgroundBip39Params {
            password,
            provider: 0,
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
                Bip49DerivationPath::Ethereum((1, ETH_PATH.to_string())),
                "Eth Wallet".to_string(),
            ),
            (
                Bip49DerivationPath::Ethereum((2, ETH_PATH.to_string())),
                "account 1".to_string(),
            ),
        ];

        bg.add_bip39_wallet(BackgroundBip39Params {
            password,
            provider: 0,
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
        let accounts = [(
            Bip49DerivationPath::Zilliqa((0, ZIL_PATH.to_string())),
            "Zilliqa wallet".to_string(),
        )];
        let keypair = KeyPair::gen_sha256().unwrap();
        let net_conf = NetworkConfig::new(
            "",
            0,
            vec!["".to_string()],
            Bip44Network::Zilliqa(ZIL_PATH.to_string()),
            String::from("TST"),
            None,
        );

        bg.add_provider(net_conf).unwrap();
        bg.add_bip39_wallet(BackgroundBip39Params {
            password,
            provider: 0,
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
            provider: 0,
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
