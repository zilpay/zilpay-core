use crate::status::TransactionStatus;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TokenInfo {
    pub value: f64,
    pub symbol: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HistoricalTransaction {
    pub id: String,
    pub amount: f64, // in native token
    pub sender: String,
    pub recipient: String,
    pub teg: Option<String>,
    pub status: TransactionStatus,
    pub confirmed: bool,
    pub timestamp: u64,
    pub fee: f64, // in native token
    pub icon: String,
    pub title: String,
    pub nonce: u64,
    pub token_info: Option<TokenInfo>,
}
