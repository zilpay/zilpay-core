use crate::Result;
use errors::token_quotes::TokenQuotesError;
use reqwest::Client;
use serde_json::Value;

const MAIN_API: &str = "https://api.zilpay.io/api/v1";

pub async fn zilpay_get_tokens(limit: u32, offset: u32) -> Result<Value> {
    let params = format!("?limit={}&offset={}&type=1", limit, offset);
    let url = format!("{}/tokens{}", MAIN_API, params);

    let client = Client::new();
    let res = client
        .get(&url)
        .send()
        .await
        .map_err(|e| TokenQuotesError::ApiRequestError(e.to_string()))?;
    let json: Value = res
        .json()
        .await
        .map_err(|e| TokenQuotesError::ApiRequestError(e.to_string()))?;

    Ok(json)
}

#[cfg(test)]
mod zilpay_get_tokens_tests {
    use crate::zilliqa_tokens::zilpay_get_tokens;
    use tokio;

    #[tokio::test]
    async fn test_get_tokens() {
        let limit = 40;
        let offset = 0;
        let result = zilpay_get_tokens(limit, offset).await.unwrap();

        assert!(result.is_object());
        assert!(result.get("count").is_some());
        assert!(result.get("list").is_some());

        let count = result.get("count").unwrap().as_u64().unwrap();
        assert!(count > 0);

        let list = result.get("list").unwrap().as_array().unwrap();
        assert!(!list.is_empty());

        let first_token = &list[0];
        assert!(first_token.get("bech32").is_some());
        assert!(first_token.get("base16").is_some());
        assert!(first_token.get("scope").is_some());
        assert!(first_token.get("name").is_some());
        assert!(first_token.get("symbol").is_some());
        assert!(first_token.get("token_type").is_some());
        assert!(first_token.get("decimals").is_some());
        assert!(first_token.get("listed").is_some());
        assert!(first_token.get("status").is_some());
    }

    #[tokio::test]
    async fn test_get_tokens_with_different_limit_offset() {
        let limit = 10;
        let offset = 5;
        let result = zilpay_get_tokens(limit, offset).await.unwrap();

        assert!(result.is_object());
        let list = result.get("list").unwrap().as_array().unwrap();
        assert!(list.len() <= limit as usize);
    }

    #[tokio::test]
    async fn test_get_tokens_empty_response() {
        let limit = 10;
        let offset = 1000;
        let result = zilpay_get_tokens(limit, offset).await.unwrap();

        assert!(result.is_object());
        let list = result.get("list").unwrap().as_array().unwrap();
        assert!(list.is_empty());
    }
}
