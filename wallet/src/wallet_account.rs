use crate::{
    account, account_type::AccountType, wallet_storage::StorageOperations,
    wallet_types::WalletTypes, Result, Wallet,
};
use bip39::Mnemonic;
use cipher::{argon2::Argon2Seed, keychain::KeyChain};
use crypto::bip49::Bip49DerivationPath;
use proto::pubkey::PubKey;
use zil_errors::wallet::WalletErrors;

/// Account management functionalities
pub trait AccountManagement {
    type Error;

    /// Adds a new hardware wallet account
    fn add_ledger_account(
        &mut self,
        name: String,
        pub_key: &PubKey,
        index: usize,
    ) -> std::result::Result<(), Self::Error>;

    /// Creates the next account in BIP39 derivation path
    fn add_next_bip39_account(
        &mut self,
        name: String,
        bip49: &Bip49DerivationPath,
        passphrase: &str,
        seed_bytes: &Argon2Seed,
    ) -> std::result::Result<(), Self::Error>;

    /// Changes the currently active account
    fn select_account(&mut self, account_index: usize) -> std::result::Result<(), Self::Error>;
}

impl AccountManagement for Wallet {
    type Error = WalletErrors;

    fn add_ledger_account(&mut self, name: String, pub_key: &PubKey, index: usize) -> Result<()> {
        let has_account = self
            .data
            .accounts
            .iter()
            .any(|account| account.account_type.value() == index);

        if self.data.wallet_type.code() != AccountType::Ledger(0).code() {
            return Err(WalletErrors::InvalidAccountType);
        }

        if has_account {
            return Err(WalletErrors::ExistsAccount(index));
        }

        let ledger_account = account::Account::from_ledger(pub_key, name, index)
            .map_err(WalletErrors::InvalidLedgerAccount)?;

        self.data.accounts.push(ledger_account);
        self.save_to_storage()?;

        Ok(())
    }

    fn add_next_bip39_account(
        &mut self,
        name: String,
        bip49: &Bip49DerivationPath,
        passphrase: &str,
        seed_bytes: &Argon2Seed,
    ) -> Result<()> {
        match self.data.wallet_type {
            WalletTypes::SecretPhrase((key, _)) => {
                let keychain =
                    KeyChain::from_seed(seed_bytes).map_err(WalletErrors::KeyChainError)?;
                let storage_key = usize::to_le_bytes(key);
                let cipher_entropy = self.storage.get(&storage_key)?;
                let entropy = keychain
                    .decrypt(cipher_entropy, &self.data.settings.cipher_orders)
                    .map_err(WalletErrors::DecryptKeyChainErrors)?;
                // TODO: add more Languages
                let m = Mnemonic::from_entropy_in(bip39::Language::English, &entropy)
                    .map_err(|e| WalletErrors::MnemonicError(e.to_string()))?;
                let mnemonic_seed = m.to_seed_normalized(passphrase);
                let has_account = self
                    .data
                    .accounts
                    .iter()
                    .any(|account| account.account_type.value() == bip49.get_index());

                if has_account {
                    return Err(WalletErrors::ExistsAccount(bip49.get_index()));
                }

                let hd_account = account::Account::from_hd(&mnemonic_seed, name.to_owned(), bip49)
                    .or(Err(WalletErrors::InvalidBip39Account))?;

                self.data.accounts.push(hd_account);
                self.save_to_storage()?;

                Ok(())
            }
            _ => Err(WalletErrors::InvalidAccountType),
        }
    }

    fn select_account(&mut self, account_index: usize) -> Result<()> {
        if self.data.accounts.is_empty() {
            return Err(WalletErrors::NoAccounts);
        }

        if account_index >= self.data.accounts.len() {
            return Err(WalletErrors::InvalidAccountIndex(account_index));
        }

        self.data.selected_account = account_index;
        self.save_to_storage()?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        wallet_account::AccountManagement, wallet_data::AuthMethod, wallet_init::WalletInit,
        wallet_storage::StorageOperations, Bip39Params, Wallet, WalletConfig,
    };
    use bip39::Mnemonic;
    use cipher::{
        argon2::{derive_key, ARGON2_DEFAULT_CONFIG},
        keychain::KeyChain,
    };
    use config::cipher::PROOF_SIZE;
    use crypto::bip49::Bip49DerivationPath;
    use rand::Rng;
    use std::sync::Arc;
    use storage::LocalStorage;
    use zil_errors::wallet::WalletErrors;

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
    fn test_select_account() {
        // Setup initial wallet with bip39 for multiple accounts
        let argon_seed = derive_key(PASSWORD, "", &ARGON2_DEFAULT_CONFIG).unwrap();
        let (storage, _dir) = setup_test_storage();

        let keychain = KeyChain::from_seed(&argon_seed).unwrap();
        let mnemonic =
            Mnemonic::parse_in_normalized(bip39::Language::English, MNEMONIC_STR).unwrap();

        // Create wallet with 3 accounts
        let indexes = [0, 1, 2].map(|i| (Bip49DerivationPath::Zilliqa(i), format!("account {i}")));

        let proof = derive_key(&argon_seed[..PROOF_SIZE], "", &ARGON2_DEFAULT_CONFIG).unwrap();
        let wallet_config = WalletConfig {
            keychain,
            storage: Arc::clone(&storage),
            settings: Default::default(),
        };

        let mut wallet = Wallet::from_bip39_words(
            Bip39Params {
                proof,
                mnemonic: &mnemonic,
                passphrase: PASSPHRASE,
                indexes: &indexes,
                wallet_name: "Select Account Test Wallet".to_string(),
                biometric_type: AuthMethod::Biometric,
                provider_index: 0,
            },
            wallet_config,
            vec![],
        )
        .unwrap();

        // Test 1: Initial state should have account 0 selected
        assert_eq!(wallet.data.selected_account, 0);

        // Test 2: Successfully select valid account indices
        assert!(wallet.select_account(1).is_ok());
        assert_eq!(wallet.data.selected_account, 1);

        assert!(wallet.select_account(2).is_ok());
        assert_eq!(wallet.data.selected_account, 2);

        assert!(wallet.select_account(0).is_ok());
        assert_eq!(wallet.data.selected_account, 0);

        // Test 3: Try to select invalid index (out of bounds)
        assert!(matches!(
            wallet.select_account(3),
            Err(WalletErrors::InvalidAccountIndex(3))
        ));
        assert_eq!(wallet.data.selected_account, 0); // Should remain unchanged

        // Test 4: Try to select index way out of bounds
        assert!(matches!(
            wallet.select_account(999),
            Err(WalletErrors::InvalidAccountIndex(999))
        ));
        assert_eq!(wallet.data.selected_account, 0); // Should remain unchanged

        // Test 5: Verify persistence after selection
        wallet.select_account(1).unwrap();
        let wallet_addr = wallet.data.wallet_address;
        wallet.save_to_storage().unwrap();

        let loaded_wallet = Wallet::load_from_storage(&wallet_addr, Arc::clone(&storage)).unwrap();
        assert_eq!(loaded_wallet.data.selected_account, 1);
    }
}
