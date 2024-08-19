use crate::json_rpc::zil_methods::ZilMethods;
use config::contracts::STAKEING;
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

    pub async fn bootstrap(node_url: &str) -> Result<Vec<String>, ZilliqaErrors> {
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
        let keys: Vec<String> = result
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

        Ok(keys)
    }

    fn build_payload(&self, params: Value, method: ZilMethods) -> Value {
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
    use tokio;

    #[tokio::test]
    async fn test_bootstrap() {
        let default_url = "https://api.zilliqa.com";
        let res = ZilliqaJsonRPC::bootstrap(default_url).await.unwrap();

        dbg!(res);
    }
}
