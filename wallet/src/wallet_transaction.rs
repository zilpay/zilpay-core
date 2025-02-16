use crate::{wallet_storage::StorageOperations, Result, WalletAddrType};
use async_trait::async_trait;
use cipher::argon2::Argon2Seed;
use config::storage::HISTORY_TXNS_DB_KEY;
use errors::wallet::WalletErrors;
use proto::tx::{TransactionReceipt, TransactionRequest};

use crate::{wallet_crypto::WalletCrypto, Wallet};

#[async_trait]
pub trait WalletTransaction {
    type Error;

    async fn sign_transaction(
        &self,
        req_tx: TransactionRequest,
        account_index: usize,
        seed_bytes: &Argon2Seed,
        passphrase: Option<&str>,
    ) -> std::result::Result<TransactionReceipt, Self::Error>;

    fn clear_history(&mut self) -> std::result::Result<(), Self::Error>;

    fn get_db_history_key(key: &WalletAddrType) -> Vec<u8>;
}

#[async_trait]
impl WalletTransaction for Wallet {
    type Error = WalletErrors;

    fn clear_history(&mut self) -> Result<()> {
        let mut history = self.get_history()?;

        if history.is_empty() {
            return Ok(());
        }

        history = Vec::with_capacity(0);
        self.add_history(&history)?;

        Ok(())
    }

    async fn sign_transaction(
        &self,
        req_tx: TransactionRequest,
        account_index: usize,
        seed_bytes: &Argon2Seed,
        passphrase: Option<&str>,
    ) -> Result<TransactionReceipt> {
        let keypair = self.reveal_keypair(account_index, seed_bytes, passphrase)?;

        Ok(req_tx.clone().sign(&keypair).await?)
    }

    #[inline]
    fn get_db_history_key(key: &WalletAddrType) -> Vec<u8> {
        [key, HISTORY_TXNS_DB_KEY].concat()
    }
}

#[cfg(test)]
mod tests_wallet_transactions {}
