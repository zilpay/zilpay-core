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
