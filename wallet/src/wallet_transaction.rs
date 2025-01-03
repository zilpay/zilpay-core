use crate::Result;
use async_trait::async_trait;
use cipher::argon2::Argon2Seed;
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
}

#[async_trait]
impl WalletTransaction for Wallet {
    type Error = WalletErrors;

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
}
