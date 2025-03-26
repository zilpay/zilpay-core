use crate::{
    account::Account, account_type::AccountType, wallet_storage::StorageOperations,
    wallet_types::WalletTypes, Result, Wallet,
};
use bip39::Mnemonic;
use cipher::{argon2::Argon2Seed, keychain::KeyChain};
use crypto::bip49::DerivationPath;
use errors::wallet::WalletErrors;
use proto::pubkey::PubKey;
use rpc::network_config::ChainConfig;

pub trait AccountManagement {
    type Error;

    fn add_ledger_account(
        &self,
        name: String,
        pub_key: PubKey,
        index: usize,
        chain: &ChainConfig,
    ) -> std::result::Result<(), Self::Error>;
    fn add_next_bip39_account(
        &self,
        name: String,
        bip49: &DerivationPath,
        passphrase: &str,
        seed_bytes: &Argon2Seed,
        chain: &ChainConfig,
    ) -> std::result::Result<(), Self::Error>;
    fn select_account(&self, account_index: usize) -> std::result::Result<(), Self::Error>;
    fn delete_account(&self, account_index: usize) -> std::result::Result<(), Self::Error>;
}

impl AccountManagement for Wallet {
    type Error = WalletErrors;

    fn delete_account(&self, account_index: usize) -> Result<()> {
        let mut data = self.get_wallet_data()?;

        if account_index == 0 || data.accounts.get(account_index).is_none() {
            return Err(WalletErrors::InvalidAccountIndex(account_index));
        }

        data.accounts.remove(account_index);
        data.selected_account = data.accounts.len() - 1;
        self.save_wallet_data(data)?;

        Ok(())
    }

    fn add_ledger_account(
        &self,
        name: String,
        pub_key: PubKey,
        index: usize,
        chain: &ChainConfig,
    ) -> Result<()> {
        let mut data = self.get_wallet_data()?;
        let has_account = data
            .accounts
            .iter()
            .any(|account| account.account_type.value() == index);

        if data.wallet_type.code() != AccountType::Ledger(0).code() {
            return Err(WalletErrors::InvalidAccountType);
        }

        if has_account {
            return Err(WalletErrors::ExistsAccount(index));
        }

        let ledger_account = Account::from_ledger(
            pub_key,
            name,
            index,
            chain.hash(),
            chain.chain_id(),
            chain.slip_44,
        )?;

        data.accounts.push(ledger_account);
        self.save_wallet_data(data)?;

        Ok(())
    }

    fn add_next_bip39_account(
        &self,
        name: String,
        bip49: &DerivationPath,
        passphrase: &str,
        seed_bytes: &Argon2Seed,
        chain: &ChainConfig,
    ) -> Result<()> {
        let mut data = self.get_wallet_data()?;

        match data.wallet_type {
            WalletTypes::SecretPhrase((key, _)) => {
                let keychain =
                    KeyChain::from_seed(seed_bytes).map_err(WalletErrors::KeyChainError)?;
                let storage_key = usize::to_le_bytes(key);
                let cipher_entropy = self.storage.get(&storage_key)?;
                let entropy = keychain.decrypt(cipher_entropy, &data.settings.cipher_orders)?;
                // TODO: add more Languages
                let m = Mnemonic::from_entropy_in(bip39::Language::English, &entropy)
                    .map_err(|e| WalletErrors::MnemonicError(e.to_string()))?;
                let mnemonic_seed = m.to_seed_normalized(passphrase);
                let has_account = data
                    .accounts
                    .iter()
                    .any(|account| account.account_type.value() == bip49.get_index());

                if has_account {
                    return Err(WalletErrors::ExistsAccount(bip49.get_index()));
                }

                let hd_account = Account::from_hd(
                    &mnemonic_seed,
                    name,
                    bip49,
                    chain.hash(),
                    chain.chain_id(),
                    chain.slip_44,
                )?;

                data.accounts.push(hd_account);
                self.save_wallet_data(data)?;

                Ok(())
            }
            _ => Err(WalletErrors::InvalidAccountType),
        }
    }

    fn select_account(&self, account_index: usize) -> Result<()> {
        let mut data = self.get_wallet_data()?;

        if data.accounts.is_empty() {
            return Err(WalletErrors::NoAccounts);
        }

        if account_index >= data.accounts.len() {
            return Err(WalletErrors::InvalidAccountIndex(account_index));
        }

        data.selected_account = account_index;
        self.save_wallet_data(data)?;

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
    use crypto::{bip49::DerivationPath, slip44};
    use errors::wallet::WalletErrors;
    use rand::Rng;
    use rpc::network_config::ChainConfig;
    use std::sync::Arc;
    use storage::LocalStorage;

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
        let indexes = [0, 1, 2].map(|i| {
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
                proof,
                mnemonic: &mnemonic,
                passphrase: PASSPHRASE,
                indexes: &indexes,
                wallet_name: "Select Account Test Wallet".to_string(),
                biometric_type: AuthMethod::Biometric,
                chain_config: &chain_config,
            },
            wallet_config,
            vec![],
        )
        .unwrap();
        let data = wallet.get_wallet_data().unwrap();

        // Test 1: Initial state should have account 0 selected
        assert_eq!(data.selected_account, 0);

        // Test 2: Successfully select valid account indices
        assert!(wallet.select_account(1).is_ok());
        let data = wallet.get_wallet_data().unwrap();
        assert_eq!(data.selected_account, 1);

        assert!(wallet.select_account(2).is_ok());
        let data = wallet.get_wallet_data().unwrap();
        assert_eq!(data.selected_account, 2);

        assert!(wallet.select_account(0).is_ok());
        let data = wallet.get_wallet_data().unwrap();
        assert_eq!(data.selected_account, 0);

        // Test 3: Try to select invalid index (out of bounds)
        assert!(matches!(
            wallet.select_account(3),
            Err(WalletErrors::InvalidAccountIndex(3))
        ));
        let data = wallet.get_wallet_data().unwrap();
        assert_eq!(data.selected_account, 0); // Should remain unchanged

        // Test 4: Try to select index way out of bounds
        assert!(matches!(
            wallet.select_account(999),
            Err(WalletErrors::InvalidAccountIndex(999))
        ));
        let data = wallet.get_wallet_data().unwrap();
        assert_eq!(data.selected_account, 0); // Should remain unchanged

        // Test 5: Verify persistence after selection
        wallet.select_account(1).unwrap();

        let wallet_addr = wallet.wallet_address;
        let loaded_wallet = Wallet::init_wallet(wallet_addr, Arc::clone(&storage)).unwrap();
        let data = loaded_wallet.get_wallet_data().unwrap();

        assert_eq!(data.selected_account, 1);
    }
}
