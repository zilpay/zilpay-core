use std::{sync::Arc, thread::sleep, time::Duration};

use crate::{bg_provider::ProvidersManagement, bg_wallet::WalletManagement, Background, Result};
use async_trait::async_trait;
use errors::background::BackgroundError;
use tokio::spawn;
use wallet::wallet_storage::StorageOperations;

pub enum JobMessage {
    Block,
    Error(String),
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
        CB: Fn(JobMessage) + Sync + Send + 'static;
}

#[async_trait]
impl WorkerManager for Background {
    type Error = BackgroundError;

    async fn start_history_job<CB>(&self, wallet_index: usize, cb_job: CB) -> Result<()>
    where
        CB: Fn(JobMessage) + Sync + Send + 'static,
    {
        const ERR_SECS: Duration = Duration::from_secs(10);
        let wallet = self.get_wallet_by_index(wallet_index)?;
        let wallet_arc = Arc::new(wallet);

        let handle = tokio::spawn({
            let wallet_clone = Arc::clone(&wallet_arc);
            async move {
                loop {
                    let data = match wallet_clone.get_wallet_data() {
                        Ok(data) => data,
                        Err(e) => {
                            cb_job(JobMessage::Error(e.to_string()));
                            tokio::time::sleep(ERR_SECS).await;
                            continue;
                        }
                    };

                    // Process the data and call cb if needed
                }
            }
        });

        handle
            .await
            .map_err(|e| BackgroundError::WorkerError(e.to_string()))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests_background_worker {}
