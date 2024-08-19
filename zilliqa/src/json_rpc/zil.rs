use crate::json_rpc::zil_methods::ZilMethods;
use config::contracts::STAKEING;
use reqwest;
use serde_json::{json, Value};
use zil_errors::ZilliqaErrors;

#[derive(Debug)]
pub struct ZilliqaJsonRPC {
    pub nodes: Vec<String>,
}

impl ZilliqaJsonRPC {
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
            .or(Err(ZilliqaErrors::BadRequest))?
            .json()
            .await
            .or(Err(ZilliqaErrors::FailToParseResponse))?;
        let result = response
            .get("result")
            .ok_or(ZilliqaErrors::FailToParseResponse)?
            .get("ssnlist")
            .ok_or(ZilliqaErrors::FailToParseResponse)?;
        let nodes: Vec<String> = result
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

        Ok(Self { nodes })
    }

    pub async fn reqwest(&self, payloads: Vec<Value>) -> Result<(), ZilliqaErrors> {
        let client = reqwest::Client::new();

        for url in self.nodes.iter() {
            let res: Value = client
                .post::<&str>(url)
                .json(&payloads)
                .send()
                .await
                .or(Err(ZilliqaErrors::BadRequest))?
                .json()
                .await
                .or(Err(ZilliqaErrors::FailToParseResponse))?;

            dbg!(res);
        }

        Ok(())
    }

    pub fn build_payload(params: Value, method: ZilMethods) -> Value {
        json!({
            "id": "1",
            "jsonrpc": "2.0",
            "method": method.to_string(),
            "params": params
        })
    }
}

#[cfg(test)]
mod tests {
    use super::ZilliqaJsonRPC;
    use crate::json_rpc::zil_methods::ZilMethods;
    use config::contracts::STAKEING;
    use serde_json::{json, Value};
    use tokio;

    #[tokio::test]
    async fn test_bootstrap() {
        let default_url = "https://api.zilliqa.com";
        let res = ZilliqaJsonRPC::bootstrap(default_url).await.unwrap();
        let payloads = vec![ZilliqaJsonRPC::build_payload(
            json!({
                "params": [STAKEING, "ssnlist", []],
            }),
            ZilMethods::GetSmartContractSubState,
        )];

        res.reqwest(payloads).await.unwrap();
    }
}
