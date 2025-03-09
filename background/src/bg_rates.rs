use crate::{bg_wallet::WalletManagement, Result};
use async_trait::async_trait;
use errors::background::BackgroundError;
use wallet::wallet_storage::StorageOperations;

use crate::Background;

#[async_trait]
pub trait RatesManagement {
    type Error;

    async fn update_rates(&self, wallet_index: usize) -> std::result::Result<(), Self::Error>;
}

#[async_trait]
impl RatesManagement for Background {
    type Error = BackgroundError;

    async fn update_rates(&self, wallet_index: usize) -> Result<()> {
        let wallet = self.get_wallet_by_index(wallet_index)?;
        let data = wallet.get_wallet_data()?;
        let mut ftokens = wallet.get_ftokens()?;

        if let Some(vs_currency) = data.settings.features.currency_convert {
            data.settings
                .rates_api_options
                .request(&mut ftokens, &vs_currency.to_lowercase())
                .await?;

            wallet.save_ftokens(&ftokens)?;
        }

        Ok(())
    }
}
