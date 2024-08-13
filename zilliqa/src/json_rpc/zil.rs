use std::error::Error;

use crate::json_rpc::zil_methods::ZilMethods;
use reqwest;
use serde_json::{json, Value};
use zil_errors::ZilliqaErrors;

#[derive(Debug)]
pub struct ZilliqaJsonRPC<'a> {
    pub nodes: Vec<&'a str>,
}

impl<'a> ZilliqaJsonRPC<'a> {
    pub fn from_vec(nodes: Vec<&'a str>) -> Self {
        ZilliqaJsonRPC { nodes }
    }

    pub async fn bootstrap(node_url: &str) -> Result<(), Box<dyn std::error::Error>> {
        let client = reqwest::Client::new();
        let payload = json!({
            "id": "1",
            "jsonrpc": "2.0",
            "method": ZilMethods::GetSmartContractSubState.to_string(),
            "params": ["a7C67D49C82c7dc1B73D231640B2e4d0661D37c1", "ssnlist", []]
        });
        let response: Value = client
            .post(node_url)
            .json(&payload)
            .send()
            .await?
            .json()
            .await?;
        let result = response.get("result");
        // map(|v| v.get("ssnlist"));

        dbg!(&result);

        // let res = response["result"]["balance"]
        //     .as_str()
        //     .unwrap_or("0")
        //     .to_string();
        //
        // dbg!(res);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::ZilliqaJsonRPC;
    use tokio;

    #[tokio::test]
    async fn test_bootstrap() {
        let default_url = "https://api.zilliqa.com";
        let rpc = ZilliqaJsonRPC::bootstrap(default_url).await;
    }
}
