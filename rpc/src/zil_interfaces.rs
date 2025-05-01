use errors::token::TokenError;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ResultRes<T> {
    pub id: u64,
    pub jsonrpc: String,
    pub result: Option<T>,
    pub error: Option<ErrorRes>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ErrorRes {
    pub code: i16,
    pub message: String,
    pub data: Option<Value>,
}

impl std::fmt::Display for ErrorRes {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "JSON-RPC error (code: {}): {}", self.code, self.message)?;
        if let Some(data) = &self.data {
            write!(f, ", data: {}", data)?;
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct GetBalanceRes {
    pub balance: String,
    pub nonce: u64,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CreateTransactionRes {
    #[serde(rename = "Info")]
    pub info: String,
    #[serde(rename = "TranID")]
    pub tranid: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct GetTokenInitItem {
    #[serde(rename = "type")]
    pub item_type: String,
    pub value: String,
    pub vname: String,
}

impl TryFrom<&Value> for GetTokenInitItem {
    type Error = TokenError;

    fn try_from(value: &Value) -> Result<Self, Self::Error> {
        Ok(GetTokenInitItem {
            item_type: value
                .get("type")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
            value: value
                .get("value")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
            vname: value
                .get("vname")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
        })
    }
}
