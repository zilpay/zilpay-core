use crate::Result;
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
        tx: TransactionRequest,
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

    fn get_db_history_key(&self) -> Vec<u8>;
    fn get_db_request_transactions_key(&self) -> Vec<u8>;
}

#[async_trait]
impl WalletTransaction for Wallet {
    type Error = WalletErrors;

    #[inline]
    fn update_request_transactions(&self) -> Result<()> {
        let key = self.get_db_request_transactions_key();
        let bytes = bincode::serialize(&self.request_txns)
            .map_err(|e| WalletErrors::TokenSerdeError(e.to_string()))?;

        self.storage.set(&key, &bytes)?;
        self.storage.flush()?;

        Ok(())
    }

    #[inline]
    fn update_history(&self) -> Result<()> {
        let key = self.get_db_history_key();
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
        let key = self.get_db_request_transactions_key();
        let request_transactions = self.storage.get(&key)?;

        self.request_txns = bincode::deserialize(&request_transactions).unwrap_or_default();

        Ok(())
    }

    fn sync_history_transactions(&mut self) -> Result<()> {
        let key = self.get_db_history_key();
        let history = self.storage.get(&key)?;

        self.history = bincode::deserialize(&history).unwrap_or_default();

        Ok(())
    }

    async fn sign_transaction(
        &self,
        tx: TransactionRequest,
        account_index: usize,
        seed_bytes: &Argon2Seed,
        passphrase: Option<&str>,
    ) -> Result<TransactionReceipt> {
        let keypair = self.reveal_keypair(account_index, seed_bytes, passphrase)?;

        keypair
            .sign_tx(tx)
            .await
            .map_err(WalletErrors::FailToSignTransaction)
    }

    #[inline]
    fn get_db_history_key(&self) -> Vec<u8> {
        [&self.data.wallet_address, HISTORY_TXNS_DB_KEY].concat()
    }

    #[inline]
    fn get_db_request_transactions_key(&self) -> Vec<u8> {
        [&self.data.wallet_address, REQ_TXNS_DB_KEY].concat()
    }
}
