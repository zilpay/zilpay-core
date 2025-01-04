use crate::{Result, WalletAddrType};
use async_trait::async_trait;
use cipher::argon2::Argon2Seed;
use config::storage::{HISTORY_TXNS_DB_KEY, REQ_TXNS_DB_KEY};
use proto::tx::{TransactionReceipt, TransactionRequest};
use zil_errors::wallet::WalletErrors;

use crate::{wallet_crypto::WalletCrypto, Wallet};

/// Transaction handling capabilities
#[async_trait]
pub trait WalletTransaction {
    type Error;

    /// Signs a blockchain transaction request
    async fn sign_transaction(
        &self,
        req_tx_index: usize,
        account_index: usize,
        seed_bytes: &Argon2Seed,
        passphrase: Option<&str>,
    ) -> std::result::Result<TransactionReceipt, Self::Error>;

    fn update_request_transactions(&self) -> std::result::Result<(), Self::Error>;
    fn update_history(&self) -> std::result::Result<(), Self::Error>;

    fn add_request_transaction(
        &mut self,
        tx: TransactionRequest,
    ) -> std::result::Result<(), Self::Error>;
    fn remove_request_transaction(&mut self, index: usize) -> std::result::Result<(), Self::Error>;
    fn clear_request_transaction(&mut self) -> std::result::Result<(), Self::Error>;
    fn clear_history(&mut self) -> std::result::Result<(), Self::Error>;

    fn sync_request_transactions(&mut self) -> std::result::Result<(), Self::Error>;
    fn sync_history_transactions(&mut self) -> std::result::Result<(), Self::Error>;

    fn get_db_history_key(key: &WalletAddrType) -> Vec<u8>;
    fn get_db_request_transactions_key(key: &WalletAddrType) -> Vec<u8>;
}

#[async_trait]
impl WalletTransaction for Wallet {
    type Error = WalletErrors;

    #[inline]
    fn update_request_transactions(&self) -> Result<()> {
        let key = Self::get_db_request_transactions_key(&self.data.wallet_address);
        let bytes = bincode::serialize(&self.request_txns)
            .map_err(|e| WalletErrors::TokenSerdeError(e.to_string()))?;

        self.storage.set(&key, &bytes)?;
        self.storage.flush()?;

        Ok(())
    }

    #[inline]
    fn update_history(&self) -> Result<()> {
        let key = Self::get_db_history_key(&self.data.wallet_address);
        let bytes = bincode::serialize(&self.history)
            .map_err(|e| WalletErrors::TokenSerdeError(e.to_string()))?;

        self.storage.set(&key, &bytes)?;
        self.storage.flush()?;

        Ok(())
    }

    fn add_request_transaction(&mut self, tx: TransactionRequest) -> Result<()> {
        self.request_txns.push(tx);
        self.update_request_transactions()?;

        Ok(())
    }

    fn remove_request_transaction(&mut self, index: usize) -> Result<()> {
        let mb_token = self.request_txns.get(index);

        if mb_token.is_none() {
            return Err(WalletErrors::TxNotExists(index));
        }

        self.request_txns.remove(index);
        self.update_request_transactions()?;

        Ok(())
    }

    fn clear_request_transaction(&mut self) -> Result<()> {
        if self.request_txns.is_empty() {
            return Ok(());
        }

        self.request_txns = Vec::with_capacity(0);
        self.update_request_transactions()?;

        Ok(())
    }

    fn clear_history(&mut self) -> Result<()> {
        if self.history.is_empty() {
            return Ok(());
        }

        self.history = Vec::with_capacity(0);
        self.update_history()?;

        Ok(())
    }

    fn sync_request_transactions(&mut self) -> Result<()> {
        let key = Self::get_db_request_transactions_key(&self.data.wallet_address);
        let request_transactions = self.storage.get(&key)?;

        self.request_txns = bincode::deserialize(&request_transactions).unwrap_or_default();

        Ok(())
    }

    fn sync_history_transactions(&mut self) -> Result<()> {
        let key = Self::get_db_history_key(&self.data.wallet_address);
        let history = self.storage.get(&key)?;

        self.history = bincode::deserialize(&history).unwrap_or_default();

        Ok(())
    }

    async fn sign_transaction(
        &self,
        req_tx_index: usize,
        account_index: usize,
        seed_bytes: &Argon2Seed,
        passphrase: Option<&str>,
    ) -> Result<TransactionReceipt> {
        let req_tx = self
            .request_txns
            .get(req_tx_index)
            .ok_or(WalletErrors::TransactionRequestNotExists(req_tx_index))?;

        let keypair = self.reveal_keypair(account_index, seed_bytes, passphrase)?;

        keypair
            .sign_tx(req_tx.clone())
            .await
            .map_err(WalletErrors::FailToSignTransaction)
    }

    #[inline]
    fn get_db_history_key(key: &WalletAddrType) -> Vec<u8> {
        [key, HISTORY_TXNS_DB_KEY].concat()
    }

    #[inline]
    fn get_db_request_transactions_key(key: &WalletAddrType) -> Vec<u8> {
        [key, REQ_TXNS_DB_KEY].concat()
    }
}

#[cfg(test)]
mod tests_wallet_transactions {
    use alloy::primitives::U256;
    use cipher::{
        argon2::{derive_key, Argon2Seed},
        keychain::KeyChain,
    };
    use config::{
        address::ADDR_LEN,
        cipher::{PROOF_SALT, PROOF_SIZE},
    };
    use proto::{
        address::Address,
        keypair::KeyPair,
        tx::TransactionRequest,
        zil_tx::{ZILTransactionMetadata, ZILTransactionRequest},
    };
    use rand::Rng;
    use settings::wallet_settings::WalletSettings;
    use std::{collections::HashMap, sync::Arc};
    use storage::LocalStorage;
    use token::ft::FToken;
    use tokio;

    use crate::{
        wallet_data::AuthMethod, wallet_init::WalletInit, wallet_security::WalletSecurity,
        wallet_storage::StorageOperations, SecretKeyParams, Wallet, WalletConfig,
    };

    use super::WalletTransaction;

    const PASSWORD: &[u8] = b"Test_password";

    fn gen_zil_token() -> FToken {
        FToken {
            provider_index: 0,
            default: true,
            name: "Zilliqa".to_string(),
            symbol: "ZIL".to_string(),
            decimals: 12,
            addr: Address::Secp256k1Sha256Zilliqa([0u8; ADDR_LEN]),
            logo: None,
            balances: HashMap::new(),
            native: true,
        }
    }

    fn setup_test_storage() -> (Arc<LocalStorage>, String) {
        let mut rng = rand::thread_rng();
        let dir = format!("/tmp/{}", rng.gen::<usize>());
        let storage = LocalStorage::from(&dir).unwrap();
        let storage = Arc::new(storage);

        (storage, dir)
    }

    fn setup_wallet(storage: Arc<LocalStorage>) -> (Wallet, Argon2Seed) {
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
        let wallet = Wallet::from_sk(
            SecretKeyParams {
                sk,
                proof,
                wallet_name: "Test ZIlliqa Account".to_string(),
                biometric_type: AuthMethod::None,
                provider_index: 0,
            },
            wallet_config,
            vec![gen_zil_token()],
        )
        .unwrap();

        (wallet, argon_seed)
    }

    #[tokio::test]
    async fn test_add_req_txns() {
        let (storage, _dir) = setup_test_storage();
        let (mut wallet, argon_seed) = setup_wallet(Arc::clone(&storage));

        wallet.save_to_storage().unwrap();

        let key_pair = KeyPair::gen_sha256().unwrap();
        let zil_addr = key_pair.get_addr().unwrap();

        const NUMBER_TXNS: usize = 10;
        for index in 0..NUMBER_TXNS {
            let token = wallet.ftokens.first().unwrap();
            let tx_req = TransactionRequest::Zilliqa(ZILTransactionRequest {
                metadata: ZILTransactionMetadata {
                    hash: None,
                    info: None,
                    title: None,
                    icon: None,
                    token_info: Some((U256::ZERO, token.decimals, token.symbol.clone())),
                },
                chain_id: 42,
                nonce: index as u64,
                gas_price: 2000 * 10u128.pow(6),
                gas_limit: 100000,
                to_addr: zil_addr.clone(),
                amount: 10u128.pow(12),
                code: Vec::with_capacity(0),
                data: Vec::with_capacity(0),
            });

            wallet.add_request_transaction(tx_req).unwrap();
        }

        assert_eq!(wallet.request_txns.len(), NUMBER_TXNS);

        let wallet_addr = wallet.data.wallet_address;

        drop(wallet);

        let mut wallet = Wallet::load_from_storage(&wallet_addr, Arc::clone(&storage)).unwrap();

        assert_eq!(wallet.request_txns.len(), 0);

        wallet.unlock(&argon_seed).unwrap();

        assert_eq!(wallet.request_txns.len(), NUMBER_TXNS);

        for index in 0..NUMBER_TXNS {
            let transaction_receipt = wallet
                .sign_transaction(index, 0, &argon_seed, None)
                .await
                .unwrap();

            assert!(transaction_receipt.verify().unwrap());

            wallet.history.push(transaction_receipt.try_into().unwrap());
        }

        wallet.update_history().unwrap();
        wallet.clear_request_transaction().unwrap();

        assert_eq!(wallet.request_txns.len(), 0);
        assert_eq!(wallet.history.len(), NUMBER_TXNS);

        drop(wallet);

        let mut wallet = Wallet::load_from_storage(&wallet_addr, storage).unwrap();

        assert_eq!(wallet.history.len(), 0);

        wallet.unlock(&argon_seed).unwrap();

        assert_eq!(wallet.history.len(), NUMBER_TXNS);
    }
}
