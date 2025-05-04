use crate::Result;
use errors::token_quotes::TokenQuotesError;
use proto::address::Address;
use reqwest::Client;
use serde_json::Value;
use token::ft::FToken;

pub async fn coingecko_get_tokens(chain_name: &str) -> Result<Vec<FToken>> {
    let url = format!("https://tokens.coingecko.com/{}/all.json", chain_name);

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

    let api_tokens: Vec<serde_json::Value> = json["tokens"]
        .as_array()
        .ok_or_else(|| {
            TokenQuotesError::ParseResponseError(
                "Invalid tokens format".to_string(),
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
            addr: Address::from_eth_address(token["address"].as_str().unwrap_or_default())
                .unwrap_or_else(|_| Address::Secp256k1Keccak256([0u8; 20])),
            logo: token["logoURI"].as_str().map(String::from),
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
mod coingecko_get_tokens_tests {
    use super::*;
    use tokio;

    #[tokio::test]
    async fn test_get_tokens_basic() {
        let tokens = coingecko_get_tokens("base").await.unwrap();
        assert!(!tokens.is_empty());
        let token = &tokens[0];
        assert!(!token.name.is_empty());
        assert!(!token.symbol.is_empty());
        assert!(token.decimals > 0);
        assert!(matches!(token.addr, Address::Secp256k1Keccak256(_)));
    }

    #[tokio::test]
    async fn test_get_tokens_chain() {
        let tokens = coingecko_get_tokens("ethereum").await.unwrap();
        assert!(!tokens.is_empty());
        let token = &tokens[0];
        assert!(!token.name.is_empty());
        assert!(token.rate == 0.0);
    }

    #[tokio::test]
    async fn test_get_tokens_default_values() {
        let tokens = coingecko_get_tokens("base").await.unwrap();
        assert!(!tokens.is_empty());
        let token = &tokens[0];
        assert!(token.balances.is_empty());
        assert_eq!(token.default, false);
        assert_eq!(token.native, false);
        assert_eq!(token.chain_hash, 0);
    }
}
