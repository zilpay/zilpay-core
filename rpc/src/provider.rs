use async_trait::async_trait;
use serde::de::DeserializeOwned;
use serde_json::Value;
use std::fmt::Debug;
use std::marker::PhantomData;
use zil_errors::rpc::RpcError;

use crate::common::{JsonRPC, NetworkConfigTrait, Result, RpcMethod};

pub struct RpcProvider<N, M>
where
    N: NetworkConfigTrait,
    M: RpcMethod,
{
    pub network: N,
    _method: PhantomData<M>,
}

impl<N, M> RpcProvider<N, M>
where
    N: NetworkConfigTrait,
    M: RpcMethod,
{
    pub fn new(network: N) -> Self {
        Self {
            network,
            _method: PhantomData,
        }
    }

    pub fn build_payload(params: Value, method: M) -> Value {
        serde_json::json!({
            "id": 1,
            "jsonrpc": "2.0",
            "method": method.to_string(),
            "params": params
        })
    }
}

#[async_trait]
impl<N, M> JsonRPC for RpcProvider<N, M>
where
    N: NetworkConfigTrait + Send + Sync,
    M: RpcMethod + Send + Sync,
{
    type Method = M;

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
                Err(_) => {
                    if error == RpcError::InvalidJson && k == Self::MAX_ERROR {
                        break;
                    } else if error == RpcError::InvalidJson {
                        k += 1;
                        continue;
                    } else {
                        error = RpcError::InvalidJson;
                        k = 1;
                        continue;
                    }
                }
            }
        }

        Err(error)
    }
}
