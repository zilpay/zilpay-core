use crate::{provider::NetworkProvider, zil_stake_parse::EvmPool};
use async_trait::async_trait;
use errors::network::NetworkErrors;

#[async_trait]
pub trait ZilliqaStakeing {
    async fn get_zq2_providers(&self) -> std::result::Result<Vec<EvmPool>, NetworkErrors>;
}

#[async_trait]
impl ZilliqaStakeing for NetworkProvider {
    async fn get_zq2_providers(&self) -> std::result::Result<Vec<EvmPool>, NetworkErrors> {
        let url = "https://api.zilpay.io/api/v1/stake/pools";
        let client = reqwest::Client::new();
        let response = client.get(url).send().await.map_err(|e| match e.status() {
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
            .json::<Vec<EvmPool>>()
            .await
            .map_err(|e| NetworkErrors::ParseHttpError(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rpc::network_config::ChainConfig;

    fn create_zilliqa_config() -> ChainConfig {
        ChainConfig {
            ftokens: vec![],
            logo: String::new(),
            diff_block_time: 0,
            testnet: None,
            chain_ids: [1, 0],
            name: "Zilliqa".to_string(),
            chain: "ZIL".to_string(),
            short_name: String::new(),
            rpc: vec!["https://api.zilliqa.com".to_string()],
            features: vec![],
            slip_44: 313,
            ens: None,
            explorers: vec![],
            fallback_enabled: true,
        }
    }

    #[tokio::test]
    async fn test_request_zil_staking_pools() {
        let net_conf = create_zilliqa_config();
        let provider = NetworkProvider::new(net_conf);
        let pools = provider.get_zq2_providers().await.unwrap();
        assert!(!pools.is_empty());
        assert!(pools.iter().any(|p| p.name == "Moonlet"));
        assert!(pools
            .iter()
            .any(|p| p.name == "Amazing Pool - Avely and ZilPay"));
    }
}
