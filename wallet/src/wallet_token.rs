use crate::{Result, Wallet};
use config::storage::FTOKENS_DB_KEY;
use token::ft::FToken;
use zil_errors::wallet::WalletErrors;

/// Token handling operations
pub trait TokenManagement {
    type Error;

    /// Registers a new fungible token in the wallet
    fn add_ftoken(&mut self, token: FToken) -> std::result::Result<(), Self::Error>;

    /// Removes a fungible token from the wallet
    fn remove_ftoken(&mut self, index: usize) -> std::result::Result<(), Self::Error>;
}

impl TokenManagement for Wallet {
    type Error = WalletErrors;

    fn add_ftoken(&mut self, token: FToken) -> Result<()> {
        self.ftokens.push(token);

        let ftokens: Vec<&FToken> = self.ftokens.iter().filter(|token| !token.default).collect();
        let bytes = bincode::serialize(&ftokens)
            .map_err(|e| WalletErrors::TokenSerdeError(e.to_string()))?;

        self.storage.set(FTOKENS_DB_KEY, &bytes)?;
        self.storage.flush()?;

        Ok(())
    }

    fn remove_ftoken(&mut self, index: usize) -> Result<()> {
        if self.ftokens.get(index).is_none() {
            return Err(WalletErrors::TokenNotExists(index));
        }

        self.ftokens.remove(index);

        let ftokens: Vec<&FToken> = self.ftokens.iter().filter(|token| !token.default).collect();
        let bytes = bincode::serialize(&ftokens)
            .map_err(|e| WalletErrors::TokenSerdeError(e.to_string()))?;

        self.storage.set(FTOKENS_DB_KEY, &bytes)?;
        self.storage.flush()?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use alloy::primitives::map::HashMap;
    use cipher::{argon2::derive_key, keychain::KeyChain};
    use config::cipher::{PROOF_SALT, PROOF_SIZE};
    use proto::{address::Address, keypair::KeyPair};
    use rand::Rng;
    use settings::wallet_settings::WalletSettings;
    use storage::LocalStorage;
    use token::ft::FToken;

    use crate::{
        wallet_init::WalletInit, wallet_security::WalletSecurity,
        wallet_storage::StorageOperations, wallet_token::TokenManagement, Wallet, WalletConfig,
    };

    const PASSWORD: &[u8] = b"Test_password";

    fn setup_test_storage() -> (Arc<LocalStorage>, String) {
        let mut rng = rand::thread_rng();
        let dir = format!("/tmp/{}", rng.gen::<usize>());
        let storage = LocalStorage::from(&dir).unwrap();
        let storage = Arc::new(storage);

        (storage, dir)
    }

    #[test]
    fn test_add_and_load_tokens() {
        let (storage, _dir) = setup_test_storage();

        let settings = WalletSettings::default();
        let argon_seed =
            derive_key(PASSWORD, PROOF_SALT, &settings.argon_params.into_config()).unwrap();
        let proof = derive_key(
            &argon_seed[..PROOF_SIZE],
            PROOF_SALT,
            &settings.argon_params.into_config(),
        )
        .unwrap();
        let keychain = KeyChain::from_seed(&argon_seed).unwrap();

        // Generate ETH keypair for test wallet
        let keypair = KeyPair::gen_keccak256().unwrap();
        let sk = keypair.get_secretkey().unwrap();

        let wallet_config = WalletConfig {
            keychain,
            settings,
            storage: Arc::clone(&storage),
        };

        // Create wallet
        let mut wallet = Wallet::from_sk(
            &sk,
            "Test Token Account".to_string(),
            &proof,
            wallet_config,
            "Token Test Wallet".to_string(),
            Default::default(),
            0,
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
            native: false,
            balances: HashMap::new(),
        };

        // Add custom token
        wallet.add_ftoken(custom_token.clone()).unwrap();

        // Verify token was added
        assert_eq!(wallet.ftokens.len(), 2);
        assert_eq!(wallet.ftokens[1].symbol, "TST");
        assert!(!wallet.ftokens[1].default);

        // Save wallet state
        let wallet_addr = wallet.data.wallet_address;
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
        let (storage, _dir) = setup_test_storage();

        let settings = WalletSettings::default();
        let argon_seed =
            derive_key(PASSWORD, PROOF_SALT, &settings.argon_params.into_config()).unwrap();
        let proof = derive_key(
            &argon_seed[..PROOF_SIZE],
            PROOF_SALT,
            &settings.argon_params.into_config(),
        )
        .unwrap();
        let keychain = KeyChain::from_seed(&argon_seed).unwrap();
        let keypair = KeyPair::gen_keccak256().unwrap();
        let sk = keypair.get_secretkey().unwrap();

        let wallet_config = WalletConfig {
            keychain,
            settings,
            storage: Arc::clone(&storage),
        };

        let mut wallet = Wallet::from_sk(
            &sk,
            "Multi Token Account".to_string(),
            &proof,
            wallet_config,
            "Multi Token Test Wallet".to_string(),
            Default::default(),
            0,
        )
        .unwrap();

        // Add multiple custom tokens
        let tokens = vec![
            FToken {
                name: "Token 1".to_string(),
                symbol: "TK1".to_string(),
                decimals: 18,
                addr: Address::from_zil_base16("1111111111111111111111111111111111111111").unwrap(),
                native: true,
                logo: None,
                default: false,
                balances: HashMap::new(),
            },
            FToken {
                name: "Token 2".to_string(),
                symbol: "TK2".to_string(),
                decimals: 6,
                addr: Address::from_zil_base16("2222222222222222222222222222222222222222").unwrap(),
                native: true,
                logo: None,
                default: false,
                balances: HashMap::new(),
            },
            FToken {
                name: "Token 3".to_string(),
                symbol: "TK3".to_string(),
                decimals: 8,
                native: true,
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
        let wallet_addr = wallet.data.wallet_address;
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
        let (storage, _dir) = setup_test_storage();

        let settings = WalletSettings::default();
        let argon_seed =
            derive_key(PASSWORD, PROOF_SALT, &settings.argon_params.into_config()).unwrap();
        let proof = derive_key(
            &argon_seed[..PROOF_SIZE],
            PROOF_SALT,
            &settings.argon_params.into_config(),
        )
        .unwrap();
        let keychain = KeyChain::from_seed(&argon_seed).unwrap();
        let keypair = KeyPair::gen_keccak256().unwrap();
        let sk = keypair.get_secretkey().unwrap();

        let wallet_config = WalletConfig {
            keychain,
            settings,
            storage: Arc::clone(&storage),
        };

        let mut wallet = Wallet::from_sk(
            &sk,
            "Remove Token Test Account".to_string(),
            &proof,
            wallet_config,
            "Remove Token Test Wallet".to_string(),
            Default::default(),
            0,
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
                native: true,
                balances: HashMap::new(),
            },
            FToken {
                name: "Token 2".to_string(),
                symbol: "TK2".to_string(),
                decimals: 6,
                addr: Address::from_zil_base16("2222222222222222222222222222222222222222").unwrap(),
                logo: None,
                default: false,
                native: true,
                balances: HashMap::new(),
            },
            FToken {
                name: "Token 3".to_string(),
                symbol: "TK3".to_string(),
                decimals: 8,
                addr: Address::from_zil_base16("3333333333333333333333333333333333333333").unwrap(),
                logo: None,
                native: true,
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
        let wallet_addr = wallet.data.wallet_address;
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
