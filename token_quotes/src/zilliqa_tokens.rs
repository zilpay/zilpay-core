use crate::Result;
use errors::token_quotes::TokenQuotesError;
use proto::address::Address;
use reqwest::Client;
use serde_json::Value;
use token::ft::FToken;

const MAIN_API: &str = "https://api.zilpay.io/api/v1";

pub async fn zilpay_get_tokens(limit: u32, offset: u32) -> Result<Vec<FToken>> {
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

    let api_tokens: Vec<serde_json::Value> = json["list"]
        .as_array()
        .ok_or_else(|| {
            TokenQuotesError::ParseResponseError(
                "Invalid list format".to_string(),
                json.to_string(),
            )
        })?
        .clone();

    let tokens: Vec<FToken> = api_tokens
        .into_iter()
        .map(|token| FToken {
            name: token["name"].as_str().unwrap_or_default().to_string(),
            symbol: token["symbol"].as_str().unwrap_or_default().to_string(),
            decimals: token["decimals"].as_u64().unwrap_or(0) as u8,
            addr: Address::from_zil_bech32(token["bech32"].as_str().unwrap_or_default())
                .unwrap_or_else(|_| Address::Secp256k1Sha256([0u8; 20])),
            logo: None,
            balances: Default::default(),
            default: false,
            native: false,
            chain_hash: 0,
            rate: 0.0,
        })
        .collect();

    Ok(tokens)
}

#[cfg(test)]
mod zilpay_get_tokens_tests {
    use super::*;
    use tokio;

    #[tokio::test]
    async fn test_get_tokens_basic() {
        let limit = 40;
        let offset = 0;
        let tokens = zilpay_get_tokens(limit, offset).await.unwrap();

        assert!(!tokens.is_empty(), "Token list should not be empty");
        let token = &tokens[0];

        assert!(!token.name.is_empty(), "Token name should not be empty");
        assert!(!token.symbol.is_empty(), "Token symbol should not be empty");
        assert!(token.decimals > 0, "Token decimals should be positive");
        assert!(
            matches!(token.addr, Address::Secp256k1Sha256(_)),
            "Token address should be Secp256k1Sha256"
        );
    }

    #[tokio::test]
    async fn test_get_tokens_pagination() {
        let limit = 5;
        let offset = 10;
        let tokens = zilpay_get_tokens(limit, offset).await.unwrap();

        assert!(
            tokens.len() <= limit as usize,
            "Token list length should respect limit"
        );
        if !tokens.is_empty() {
            let token = &tokens[0];
            assert!(!token.name.is_empty(), "Token name should not be empty");
            assert!(token.rate == 0.0, "Token rate should be initialized to 0.0");
        }
    }

    #[tokio::test]
    async fn test_get_tokens_empty() {
        let limit = 10;
        let offset = 10000; // Large offset to get empty response
        let tokens = zilpay_get_tokens(limit, offset).await.unwrap();

        assert!(
            tokens.is_empty(),
            "Token list should be empty for large offset"
        );
    }

    #[tokio::test]
    async fn test_get_tokens_default_values() {
        let limit = 1;
        let offset = 0;
        let tokens = zilpay_get_tokens(limit, offset).await.unwrap();

        assert_eq!(tokens.len(), 1, "Should return one token");
        let token = &tokens[0];

        assert_eq!(token.logo, None, "Logo should be None");
        assert!(token.balances.is_empty(), "Balances should be empty");
        assert_eq!(token.default, false, "Default should be false");
        assert_eq!(token.native, false, "Native should be false");
        assert_eq!(token.chain_hash, 0, "Chain hash should be 0");
    }
}
