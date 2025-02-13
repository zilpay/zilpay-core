use async_trait::async_trait;
use errors::rpc::RpcError;
use serde::de::DeserializeOwned;
use serde_json::Value;
use std::{fmt::Debug, time::Duration};

use crate::common::{JsonRPC, NetworkConfigTrait, Result, RpcMethod};

pub struct RpcProvider<'a, N>
where
    N: NetworkConfigTrait,
{
    pub network: &'a N,
}

impl<'a, N> RpcProvider<'a, N>
where
    N: NetworkConfigTrait,
{
    pub fn new(network: &'a N) -> Self {
        Self { network }
    }

    pub fn build_payload<M: RpcMethod>(params: Value, method: M) -> Value {
        serde_json::json!({
            "id": 1,
            "jsonrpc": "2.0",
            "method": method.as_str(),
            "params": params
        })
    }
}

#[async_trait]
impl<'a, N> JsonRPC for RpcProvider<'a, N>
where
    N: NetworkConfigTrait + Send + Sync,
{
    fn get_nodes(&self) -> &[String] {
        self.network.nodes()
    }

    async fn req<SR>(&self, payloads: &[Value]) -> Result<SR>
    where
        SR: DeserializeOwned + Debug,
    {
        const TIME_OUT_SEC: u64 = 5;
        let client = reqwest::Client::new();
        let mut error = RpcError::NetworkDown;
        let mut k = 0;

        for url in self.get_nodes() {
            k += 1;
            let res = match client
                .post(url)
                .timeout(Duration::from_secs(TIME_OUT_SEC))
                .json(&payloads)
                .send()
                .await
            {
                Ok(response) => response,
                Err(_) => {
                    if error == RpcError::BadRequest && k == Self::MAX_ERROR {
                        break;
                    } else if error == RpcError::BadRequest {
                        continue;
                    } else {
                        error = RpcError::BadRequest;
                        continue;
                    }
                }
            };

            match res.json().await {
                Ok(json) => {
                    return Ok(json);
                }
                Err(e) => {
                    if error == RpcError::InvalidJson(e.to_string()) && k == Self::MAX_ERROR {
                        break;
                    } else if error == RpcError::InvalidJson(e.to_string()) {
                        continue;
                    } else {
                        error = RpcError::InvalidJson(e.to_string());
                        continue;
                    }
                }
            }
        }

        Err(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        methods::{EvmMethods, ZilMethods},
        network_config::{ChainConfig, Explorer},
        zil_interfaces::{GetBalanceRes, ResultRes},
    };
    use serde_json::json;

    const ZERO_ADDR: &str = "0000000000000000000000000000000000000000";

    fn create_zilliqa_config() -> ChainConfig {
        ChainConfig {
            diff_block_time: 0,
            testnet: None,
            chain_ids: [1, 0],
            name: "Zilliqa".to_string(),
            chain: "ZIL".to_string(),
            short_name: String::new(),
            rpc: vec!["https://api.zilliqa.com".to_string()],
            features: vec![155],
            slip_44: 313,
            ens: None,
            explorers: vec![Explorer {
                name: "ViewBlock".to_string(),
                url: "https://viewblock.io/zilliqa".to_string(),
                icon: None,
                standard: 3091,
            }],
            fallback_enabled: true,
        }
    }

    fn create_eth_config() -> ChainConfig {
        ChainConfig {
            diff_block_time: 0,
            chain_ids: [11155111, 0],
            testnet: None,
            name: "Ethereum Mainnet".to_string(),
            chain: "ETH".to_string(),
            short_name: String::new(),
            rpc: vec![
                "https://rpc.sepolia.org".to_string(),
                "https://rpc2.sepolia.org".to_string(),
                "https://rpc.sepolia.online".to_string(),
                "https://www.sepoliarpc.space".to_string(),
                "https://rpc.bordel.wtf/sepolia".to_string(),
                "https://rpc-sepolia.rockx.com".to_string(),
            ],
            features: vec![155, 1559],
            slip_44: 60,
            ens: None,
            explorers: vec![],
            fallback_enabled: true,
        }
    }

    fn create_bsc_config() -> ChainConfig {
        ChainConfig {
            diff_block_time: 0,
            testnet: None,
            chain_ids: [56, 0],
            name: "Binance Smart Chain".to_string(),
            chain: "BSC".to_string(),
            short_name: String::new(),
            rpc: vec!["https://bsc-dataseed.binance.org".to_string()],
            features: vec![155, 1559],
            slip_44: 60,
            ens: None,
            explorers: vec![Explorer {
                name: "bscscan".to_string(),
                url: "https://bscscan.com".to_string(),
                icon: None,
                standard: 3091,
            }],
            fallback_enabled: true,
        }
    }

    #[tokio::test]
    async fn test_get_balance_scilla() {
        let net_conf = create_zilliqa_config();
        let zil: RpcProvider<ChainConfig> = RpcProvider::new(&net_conf);
        let payloads = vec![RpcProvider::<ChainConfig>::build_payload(
            json!([ZERO_ADDR]),
            ZilMethods::GetBalance,
        )];

        let res: Vec<ResultRes<GetBalanceRes>> = zil.req(&payloads).await.unwrap();

        assert_eq!(res.len(), 1);
        assert!(res[0].result.is_some());
        assert!(res[0].error.is_none());
    }

    #[tokio::test]
    async fn test_get_balance_bsc() {
        let net_conf = create_bsc_config();
        let bsc: RpcProvider<ChainConfig> = RpcProvider::new(&net_conf);
        let payloads = vec![RpcProvider::<ChainConfig>::build_payload(
            json!(["0x0000000000000000000000000000000000000000", "latest"]),
            EvmMethods::GetBalance,
        )];

        let res: Vec<ResultRes<String>> = bsc.req(&payloads).await.unwrap();

        assert_eq!(res.len(), 1);
        assert!(res[0].result.is_some());
        assert!(res[0].error.is_none());
    }

    #[test]
    fn test_build_payload() {
        let payload = RpcProvider::<ChainConfig>::build_payload(
            json!(["param1", "param2"]),
            EvmMethods::GetBalance,
        );

        assert_eq!(payload["jsonrpc"], "2.0");
        assert_eq!(payload["id"], 1);
        assert_eq!(payload["method"], EvmMethods::GetBalance.as_str());
        assert!(payload["params"].is_array());
        assert_eq!(payload["params"][0], "param1");
        assert_eq!(payload["params"][1], "param2");
    }

    #[tokio::test]
    async fn test_network_error_handling() {
        let mut config = create_bsc_config();
        config.rpc = vec!["https://invalid.url.com".to_string()];

        let provider: RpcProvider<ChainConfig> = RpcProvider::new(&config);
        let payloads = vec![RpcProvider::<ChainConfig>::build_payload(
            json!(["0x0000000000000000000000000000000000000000", "latest"]),
            EvmMethods::GetBalance,
        )];

        let result: Result<Vec<ResultRes<String>>> = provider.req(&payloads).await;
        assert!(result.is_err());
        match result {
            Err(RpcError::BadRequest) => (),
            _ => panic!("Expected BadRequest error"),
        }
    }

    #[tokio::test]
    async fn test_network_much_req() {
        let config = create_eth_config();
        let provider: RpcProvider<ChainConfig> = RpcProvider::new(&config);
        let payloads = vec![RpcProvider::<ChainConfig>::build_payload(
            json!(["0x246C5881E3F109B2aF170F5C773EF969d3da581B", "latest"]),
            EvmMethods::GetBalance,
        )];

        let result: Result<Vec<ResultRes<String>>> = provider.req(&payloads).await;

        dbg!(&result);
    }
}
