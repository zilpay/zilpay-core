use crate::Result;
use config::provider::ZILPAY_RATES_SCILLA_API;
use reqwest;
use serde_json::Value;
use zil_errors::network::NetworkErrors;

pub async fn fetch_rates() -> Result<Value> {
    let client = reqwest::Client::new();

    let response = client
        .get(ZILPAY_RATES_SCILLA_API)
        .send()
        .await
        .map_err(|e| match e.status() {
            Some(status) => NetworkErrors::HttpError(status.as_u16(), e.to_string()),
            None => NetworkErrors::HttpNetworkError(e.to_string()),
        })?;

    if !response.status().is_success() {
        return Err(NetworkErrors::HttpError(
            response.status().as_u16(),
            format!("API request failed: {}", response.status()),
        ));
    }

    response
        .json::<Value>()
        .await
        .map_err(|e| NetworkErrors::ParseHttpError(e.to_string()))
}

pub fn get_rate(rates: &Value, currency: &str) -> Option<f64> {
    rates[currency]
        .as_f64()
        .or_else(|| rates[currency].as_str().and_then(|s| s.parse().ok()))
}
