use crate::Result;
use async_trait::async_trait;
use config::storage::CURRENCIES_RATES_DB_KEY;
use serde_json::{json, Value};
use errors::background::BackgroundError;

use crate::Background;

/// Manages currency exchange rates
#[async_trait]
pub trait RatesManagement {
    type Error;

    /// Updates current exchange rates
    async fn update_rates(&self) -> std::result::Result<Value, Self::Error>;

    /// Retrieves current exchange rates
    fn get_rates(&self) -> Value;
}

#[async_trait]
impl RatesManagement for Background {
    type Error = BackgroundError;

    async fn update_rates(&self) -> Result<Value> {
        // TODO: remake this method with timestamp and struct.
        // let rates = fetch_rates()
        //     .await
        //     .map_err(BackgroundError::NetworkErrors)?;
        // let bytes =
        //     serde_json::to_vec(&json!([])).or(Err(BackgroundError::FailToSerializeRates))?;

        // self.storage
        //     .set(CURRENCIES_RATES_DB_KEY, &bytes)
        //     .map_err(BackgroundError::FailToWriteIndicatorsWallet)?;
        // self.storage
        //     .flush()
        //     .map_err(BackgroundError::LocalStorageFlushError)?;

        Ok(json!([]))
    }

    fn get_rates(&self) -> Value {
        let bytes = self
            .storage
            .get(CURRENCIES_RATES_DB_KEY)
            .unwrap_or_default();

        if bytes.is_empty() {
            // TODO: remake it with struct and timestamp.
            return json!([]);
        }

        serde_json::from_slice(&bytes).unwrap_or(json!([]))
    }
}
