use crate::Result;
use errors::token_quotes::TokenQuotesError;
use reqwest::Client;
use serde_json::Value;
use token::ft::FToken;

const API_URL_COINGECKO: &str = "https://api.coingecko.com/api/v3/simple/price";

fn build_url(ids: &[String], vs_currencies: &[&str]) -> String {
    let ids_joined = ids.join(",");
    let vs_currencies_joined = vs_currencies.join(",");
    format!(
        "{}?ids={}&vs_currencies={}",
        API_URL_COINGECKO, ids_joined, vs_currencies_joined
    )
}

pub async fn get_coingecko_rates(ftokens: &mut [FToken], vs_currency: &str) -> Result<()> {
    let ids: Vec<String> = ftokens
        .iter()
        .map(|t| t.name.to_lowercase().replace(" ", "-"))
        .collect();
    let url = build_url(&ids, &[vs_currency]);
    let json_value: Value = {
        let client = Client::new();
        let response = client
            .get(&url)
            .send()
            .await
            .map_err(|e| TokenQuotesError::ApiRequestError(e.to_string()))?
            .text()
            .await
            .map_err(|e| TokenQuotesError::ApiRequestError(e.to_string()))?;

        serde_json::from_str(&response).map_err(|e| {
            TokenQuotesError::ParseResponseError(e.to_string(), response.to_string())
        })?
    };

    for (index, key) in ids.iter().enumerate() {
        let rate = json_value
            .get(key)
            .and_then(|v| v.get(vs_currency))
            .and_then(|rate| rate.as_number())
            .and_then(|rate| rate.as_f64())
            .unwrap_or(-1.0);

        ftokens[index].rates.insert(vs_currency.to_string(), rate);
    }

    Ok(())
}

#[cfg(test)]
mod coingecko_tests {
    use proto::address::Address;
    use std::collections::HashMap;

    use super::*;

    #[tokio::test]
    async fn test_get_coingecko_rates() {
        let mut tokens = vec![
            FToken {
                rates: HashMap::new(),
                symbol: "ARB".to_string(),
                name: "Arbitrum".to_string(),
                decimals: 18,
                addr: Address::Secp256k1Keccak256(Address::ZERO),
                logo: None,
                balances: Default::default(),
                default: false,
                native: false,
                chain_hash: 0,
            },
            FToken {
                rates: HashMap::new(),
                name: "Wrapped Ether".to_string(),
                symbol: "WETH".to_string(),
                decimals: 18,
                addr: Address::Secp256k1Keccak256(Address::ZERO),
                logo: None,
                balances: Default::default(),
                default: false,
                native: false,
                chain_hash: 0,
            },
        ];
        get_coingecko_rates(&mut tokens, "rub").await.unwrap();

        assert!(*tokens[0].rates.get("rub").unwrap() > 0.0);
        assert!(*tokens[1].rates.get("rub").unwrap() > 0.0);
    }

    #[test]
    fn test_build_url() {
        // Test 1: Single ID and single currency
        let ids = vec!["bitcoin".to_string()];
        let vs_currencies = ["usd"];
        let expected =
            "https://api.coingecko.com/api/v3/simple/price?ids=bitcoin&vs_currencies=usd";
        assert_eq!(build_url(&ids, &vs_currencies), expected);

        // Test 2: Multiple IDs and single currency
        let ids = vec!["bitcoin".to_string(), "ethereum".to_string()];
        let vs_currencies = ["usd"];
        let expected =
            "https://api.coingecko.com/api/v3/simple/price?ids=bitcoin,ethereum&vs_currencies=usd";
        assert_eq!(build_url(&ids, &vs_currencies), expected);

        // Test 3: Single ID and multiple currencies
        let ids = vec!["bitcoin".to_string()];
        let vs_currencies = ["usd", "eur"];
        let expected =
            "https://api.coingecko.com/api/v3/simple/price?ids=bitcoin&vs_currencies=usd,eur";
        assert_eq!(build_url(&ids, &vs_currencies), expected);

        // Test 4: Multiple IDs and multiple currencies
        let ids = vec!["bitcoin".to_string(), "ethereum".to_string()];
        let vs_currencies = ["usd", "eur"];
        let expected = "https://api.coingecko.com/api/v3/simple/price?ids=bitcoin,ethereum&vs_currencies=usd,eur";
        assert_eq!(build_url(&ids, &vs_currencies), expected);

        // Test 5: ID with special characters (hyphen)
        let ids = vec!["bitcoin-cash".to_string()];
        let vs_currencies = ["usd"];
        let expected =
            "https://api.coingecko.com/api/v3/simple/price?ids=bitcoin-cash&vs_currencies=usd";
        assert_eq!(build_url(&ids, &vs_currencies), expected);
    }
}
