use std::sync::Arc;

use crate::{
    bg_storage::StorageManagement, device_indicators::create_wallet_device_indicator, Background,
    Result,
};

use bip39::Mnemonic;
use cipher::{argon2, keychain::KeyChain};
use config::{
    cipher::{PROOF_SALT, PROOF_SIZE},
    sha::SHA512_SIZE,
};
use session::{decrypt_session, encrypt_session};
use settings::wallet_settings::WalletSettings;
use wallet::{
    traits::{StorageOperations, WalletInit, WalletSecurity},
    wallet_data::AuthMethod,
    wallet_types::WalletTypes,
    Bip39Params, LedgerParams, Wallet, WalletConfig,
};
use zil_errors::background::BackgroundError;

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
        &mut self,
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
        &mut self,
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
        params: LedgerParams,
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

        wallet.unlock(&argon_seed)?;

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

        wallet.unlock(&seed_bytes)?;

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
        })?;
        let wallet_device_indicators =
            create_wallet_device_indicator(&wallet.data.wallet_address, params.device_indicators);

        let session = if wallet.data.biometric_type == AuthMethod::None {
            Vec::with_capacity(0)
        } else {
            encrypt_session(
                &wallet_device_indicators,
                &argon_seed,
                &wallet.data.settings.cipher_orders,
                &wallet.data.settings.argon_params.into_config(),
            )
            .map_err(BackgroundError::CreateSessionError)?
        };

        wallet.save_to_storage()?;

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
        let wallet = Wallet::from_ledger(params, &proof, wallet_config)?;

        let device_indicators =
            create_wallet_device_indicator(&wallet.data.wallet_address, device_indicators);
        let session = encrypt_session(
            &device_indicators,
            &argon_seed,
            options,
            &wallet.data.settings.argon_params.into_config(),
        )
        .map_err(BackgroundError::CreateSessionError)?;

        wallet.save_to_storage()?;

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
        )?;

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

        wallet.save_to_storage()?;
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

#[cfg(test)]
mod tests_background {
    use super::*;
    use crate::bg_crypto::CryptoOperations;
    use crypto::bip49::Bip49DerivationPath;
    use rand::Rng;
    use std::collections::HashSet;

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
        let accounts = [(Bip49DerivationPath::Ethereum(0), "Name".to_string())];

        bg.add_bip39_wallet(BackgroundBip39Params {
            password,
            providers: HashSet::new(),
            mnemonic_str: &words,
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

        bg.add_bip39_wallet(BackgroundBip39Params {
            password,
            providers: HashSet::new(),
            mnemonic_str: &words,
            accounts: &accounts,
            wallet_settings: Default::default(),
            passphrase: "",
            wallet_name: String::new(),
            biometric_type: Default::default(),
            device_indicators: &[String::from("apple"), String::from("1102")],
        })
        .unwrap();

        let password = "test_password";
        let accounts = [
            (Bip49DerivationPath::Ethereum(1), "Name".to_string()),
            (Bip49DerivationPath::Ethereum(2), "account 1".to_string()),
        ];

        bg.add_bip39_wallet(BackgroundBip39Params {
            password,
            providers: HashSet::new(),
            accounts: &accounts,
            mnemonic_str: &words,
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
}
