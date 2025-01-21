use async_trait::async_trait;
use errors::rpc::RpcError;
use serde::de::DeserializeOwned;
use serde_json::Value;
use std::fmt::Debug;

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
        let client = reqwest::Client::new();
        let mut error = RpcError::NetworkDown;
        let mut k = 0;

        for url in self.get_nodes() {
            let res = match client.post(url).json(&payloads).send().await {
                Ok(response) => response,
                Err(_) => {
                    if error == RpcError::BadRequest && k == Self::MAX_ERROR {
                        break;
                    } else if error == RpcError::BadRequest {
                        k += 1;
                        continue;
                    } else {
                        error = RpcError::BadRequest;
                        k = 1;
                        continue;
                    }
                }
            };

            match res.json().await {
                Ok(json) => return Ok(json),
                Err(e) => {
                    if error == RpcError::InvalidJson(e.to_string()) && k == Self::MAX_ERROR {
                        break;
                    } else if error == RpcError::InvalidJson(e.to_string()) {
                        k += 1;
                        continue;
                    } else {
                        error = RpcError::InvalidJson(e.to_string());
                        k = 1;
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
            testnet: None,
            name: "Zilliqa".to_string(),
            chain: "ZIL".to_string(),
            short_name: String::new(),
            rpc: vec!["https://api.zilliqa.com".to_string()],
            features: vec![155],
            chain_id: 1,
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

    fn create_bsc_config() -> ChainConfig {
        ChainConfig {
            testnet: None,
            name: "Binance Smart Chain".to_string(),
            chain: "BSC".to_string(),
            short_name: String::new(),
            rpc: vec!["https://bsc-dataseed.binance.org".to_string()],
            features: vec![155, 1559],
            chain_id: 56,
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
        // Используем неверный URL для тестирования обработки ошибок
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
}
