use crate::{bg_provider::ProvidersManagement, bg_wallet::WalletManagement, Background, Result};
use async_trait::async_trait;
use errors::background::BackgroundError;
use tokio::spawn;
use wallet::wallet_storage::StorageOperations;

pub enum JobMessage {
    Block,
}

#[async_trait]
pub trait WorkerManager {
    type Error;

    async fn start_history_job<CB>(
        &self,
        wallet_index: usize,
        cb_job: CB,
    ) -> std::result::Result<(), Self::Error>
    where
        CB: Fn(JobMessage) + Sync + Send;
}

#[async_trait]
impl WorkerManager for Background {
    type Error = BackgroundError;

    async fn start_history_job<CB>(&self, wallet_index: usize, cb_job: CB) -> Result<()>
    where
        CB: Fn(JobMessage) + Sync + Send,
    {
        let wallet = self.get_wallet_by_index(wallet_index)?;
        let chain = {
            let data = wallet.get_wallet_data()?;
            let account = data.get_selected_account()?;

            self.get_provider(account.chain_hash)?
        };

        let handle = spawn(async move { loop {} });

        handle
            .await
            .map_err(|e| BackgroundError::WorkerError(e.to_string()))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests_background_worker {}
