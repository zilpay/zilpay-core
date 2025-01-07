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
        network_config::{Bip44Network, NetworkConfig},
        zil_interfaces::{GetBalanceRes, ResultRes},
    };
    use crypto::bip49::{ETH_PATH, ZIL_PATH};
    use serde_json::json;

    const ZERO_ADDR: &str = "0000000000000000000000000000000000000000";

    #[tokio::test]
    async fn test_get_balance_scilla() {
        let net_conf = NetworkConfig::new(
            "Zilliqa",
            1,
            vec!["https://api.zilliqa.com".to_string()],
            Bip44Network::Zilliqa(ZIL_PATH.to_string()),
        );
        let zil: RpcProvider<NetworkConfig> = RpcProvider::new(&net_conf);
        let payloads = vec![RpcProvider::<NetworkConfig>::build_payload(
            json!([ZERO_ADDR]),
            ZilMethods::GetBalance,
        )];

        let res: Vec<ResultRes<GetBalanceRes>> = zil.req(&payloads).await.unwrap();

        assert!(res.len() == 1);
        assert!(res[0].result.is_some());
        assert!(res[0].error.is_none());
    }

    #[tokio::test]
    async fn test_get_balance_bsc() {
        let net_conf = NetworkConfig::new(
            "Binance-smart-chain",
            56,
            vec!["https://bsc-dataseed.binance.org".to_string()],
            Bip44Network::Evm(ETH_PATH.to_string()),
        );
        let zil: RpcProvider<NetworkConfig> = RpcProvider::new(&net_conf);
        let payloads = vec![RpcProvider::<NetworkConfig>::build_payload(
            json!(["0x0000000000000000000000000000000000000000", "latest"]),
            EvmMethods::GetBalance,
        )];

        let res: Vec<ResultRes<String>> = zil.req(&payloads).await.unwrap();

        assert!(res.len() == 1);
        assert!(res[0].result.is_some());
        assert!(res[0].error.is_none());
    }
}
