use crate::{bg_wallet::WalletManagement, Result};
use async_trait::async_trait;
use errors::background::BackgroundError;
use wallet::wallet_storage::StorageOperations;

use crate::Background;

#[async_trait]
pub trait RatesManagement {
    type Error;

    async fn update_rates(&self, wallet_index: usize)
        -> std::result::Result<Vec<f64>, Self::Error>;
}

#[async_trait]
impl RatesManagement for Background {
    type Error = BackgroundError;

    async fn update_rates(&self, wallet_index: usize) -> Result<Vec<f64>> {
        let wallet = self.get_wallet_by_index(wallet_index)?;
        let ftokens = wallet.get_ftokens()?;

        Ok(Vec::new())
    }
}
