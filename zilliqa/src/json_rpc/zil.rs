use crate::json_rpc::zil_methods::ZilMethods;
use config::contracts::STAKEING;
use config::MAIN_URL;
use reqwest;
use serde::de::DeserializeOwned;
use serde_json::{json, Value};
use zil_errors::ZilliqaErrors;

#[derive(Debug)]
pub struct ZilliqaJsonRPC {
    pub nodes: Vec<String>,
}

impl Default for ZilliqaJsonRPC {
    fn default() -> Self {
        Self::new()
    }
}

impl ZilliqaJsonRPC {
    pub fn new() -> Self {
        let nodes = vec![MAIN_URL.to_string()];
        ZilliqaJsonRPC { nodes }
    }

    pub fn from_vec(nodes: Vec<String>) -> Self {
        ZilliqaJsonRPC { nodes }
    }

    pub async fn bootstrap(node_url: &str) -> Result<Self, ZilliqaErrors> {
        let client = reqwest::Client::new();
        let payload = json!({
            "id": "1",
            "jsonrpc": "2.0",
            "method": ZilMethods::GetSmartContractSubState.to_string(),
            "params": [STAKEING, "ssnlist", []]
        });

        let response: Value = client
            .post(node_url)
            .json(&payload)
            .send()
            .await
            .map_err(|_| ZilliqaErrors::BadRequest)?
            .json()
            .await
            .map_err(|_| ZilliqaErrors::FailToParseResponse)?;
        let result = response
            .get("result")
            .ok_or(ZilliqaErrors::FailToParseResponse)?
            .get("ssnlist")
            .ok_or(ZilliqaErrors::FailToParseResponse)?;
        let mut nodes: Vec<String> = result
            .as_object()
            .ok_or(ZilliqaErrors::FailToParseResponse)?
            .keys()
            .filter_map(|addr| {
                result
                    .get(addr)
                    .and_then(|obj| obj.get("arguments"))
                    .and_then(|arr| arr.as_array())
                    .and_then(|arr| arr.get(5))
                    .and_then(|v| v.as_str())
                    .map(|url| url.to_string())
            })
            .collect();

        nodes.push(node_url.to_string());
        Ok(Self { nodes })
    }

    pub async fn req<'a, SR>(&self, payloads: Vec<Value>) -> Result<SR, ZilliqaErrors<'a>>
    where
        SR: DeserializeOwned + std::fmt::Debug,
    {
        const MAX_ERROR: usize = 5;
        let client = reqwest::Client::new();
        let mut error: ZilliqaErrors = ZilliqaErrors::NetowrkIsDown;
        let mut k = 0;
        let mut handle_error = |e: String, zil_err: fn(String) -> ZilliqaErrors<'a>| -> bool {
            let new_error = zil_err(e.to_string());
            if new_error == error && k == MAX_ERROR {
                false
            } else if new_error == error && k != MAX_ERROR {
                error = new_error;
                k += 1;
                true
            } else {
                error = new_error;
                k = 1;
                true
            }
        };

        for url in self.nodes.iter() {
            let res = match client.post::<&str>(url).json(&payloads).send().await {
                Ok(response) => response,
                Err(e) => {
                    if handle_error(e.to_string(), ZilliqaErrors::InvalidRPCReq) {
                        break;
                    }

                    continue;
                }
            };
            let res: SR = match res.json().await {
                Ok(json) => json,
                Err(e) => {
                    if handle_error(e.to_string(), ZilliqaErrors::InvalidJson) {
                        break;
                    }

                    continue;
                }
            };

            return Ok(res);
        }

        Err(error)
    }

    pub fn build_payload(params: Value, method: ZilMethods) -> Value {
        json!({
            "id": 1,
            "jsonrpc": "2.0",
            "method": method.to_string(),
            "params": params
        })
    }
}

#[cfg(test)]
mod tests {
    use core::panic;

    use super::ZilliqaJsonRPC;
    use crate::json_rpc::{
        zil_interfaces::{CreateTransactionRes, GetBalanceRes, ResultRes},
        zil_methods::ZilMethods,
    };
    use proto::{
        keypair::KeyPair,
        secret_key::SecretKey,
        tx::{TransactionReceipt, TransactionRequest},
        zil_tx::{ScillaGas, ZILTransactionRequest, ZilAmount},
    };
    use serde_json::json;
    use tokio;

    const MAIN_NEN: &str = "https://api.zilliqa.com";
    const TEST_NET: &str = "https://dev-api.zilliqa.com/";

    #[tokio::test]
    async fn test_bootstrap() {
        let zil = ZilliqaJsonRPC::bootstrap(MAIN_NEN).await.unwrap();

        assert!(zil.nodes.len() > 1);
    }

    #[tokio::test]
    async fn test_transaction() {
        const CHAIN_ID: u16 = 333;

        let zil = ZilliqaJsonRPC::from_vec(vec![TEST_NET.to_string()]);
        let secret_key_1_bytes: [u8; 32] = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 1,
        ];
        let secret_key_2_bytes: [u8; 32] = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 2,
        ];
        let secret_keys = [
            SecretKey::Secp256k1Sha256Zilliqa(secret_key_1_bytes),
            SecretKey::Secp256k1Sha256Zilliqa(secret_key_2_bytes),
        ];
        let keypairs = secret_keys
            .iter()
            .map(|x| KeyPair::from_secret_key(x).unwrap())
            .collect::<Vec<KeyPair>>();
        println!("Got a keypair!");

        const ONE_ZIL: u128 = 1_000_000_000_000u128;

        println!(
            "Sending 1 ZIL from {0} to {1}",
            keypairs[0].get_addr().unwrap(),
            keypairs[1].get_addr().unwrap()
        );
        let nonce = {
            let bal_addr = keypairs[0]
                .get_addr()
                .unwrap()
                .to_eth_checksummed()
                .unwrap();
            let bal_payload = vec![ZilliqaJsonRPC::build_payload(
                json!([bal_addr]),
                ZilMethods::GetBalance,
            )];
            let resvec: Vec<ResultRes<GetBalanceRes>> = zil.req(bal_payload).await.unwrap();
            println!("Bal {0:?}", resvec[0]);
            resvec[0].result.as_ref().map_or(0, |v| v.nonce)
        };
        let txn = TransactionRequest::Zilliqa(ZILTransactionRequest {
            nonce: nonce + 1,
            chain_id: CHAIN_ID,
            gas_price: ZilAmount::from_raw(2000000000),
            gas_limit: ScillaGas(1000),
            to_addr: keypairs[1].get_addr().unwrap(),
            amount: ZilAmount::from_raw(ONE_ZIL),
            code: String::new(),
            data: String::new(),
        });

        let signed = txn.sign(&keypairs[0]).await.unwrap();

        match signed {
            TransactionReceipt::Zilliqa(tx) => {
                dbg!(serde_json::to_string(&tx).unwrap());
                let payloads = vec![ZilliqaJsonRPC::build_payload(
                    json!([tx]),
                    ZilMethods::CreateTransaction,
                )];
                let res: Vec<ResultRes<CreateTransactionRes>> = zil.req(payloads).await.unwrap();
                println!("{res:?}");
            }
            _ => panic!("fail test"),
        }
    }

    #[tokio::test]
    async fn test_get_balance() {
        let zil = ZilliqaJsonRPC::new();
        let addr = "7793a8e8c09d189d4d421ce5bc5b3674656c5ac1";
        let payloads = vec![ZilliqaJsonRPC::build_payload(
            json!([addr]),
            ZilMethods::GetBalance,
        )];

        let res: Vec<ResultRes<GetBalanceRes>> = zil.req(payloads).await.unwrap();

        assert!(res.len() == 1);
        assert!(res[0].result.is_some());
        assert!(res[0].error.is_none());
    }
}
