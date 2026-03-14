use serde::{Deserialize, Deserializer, Serialize};

fn deserialize_hex_to_vec<'de, D>(deserializer: D) -> std::result::Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    let s: String = Deserialize::deserialize(deserializer)?;
    alloy::hex::decode(&s).map_err(serde::de::Error::custom)
}

#[derive(Debug, Clone, Deserialize)]
pub struct BlockHeader {
    pub raw_data: Option<BlockHeaderRawData>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BlockHeaderRawData {
    pub number: i64,
    pub timestamp: i64,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct BlockResponse {
    #[serde(
        default,
        alias = "blockID",
        deserialize_with = "deserialize_hex_to_vec"
    )]
    pub blockid: Vec<u8>,
    pub block_header: Option<BlockHeader>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ChainParameter {
    pub key: String,
    #[serde(default)]
    pub value: i64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ChainParamsResponse {
    #[serde(alias = "chainParameter")]
    pub chain_parameter: Vec<ChainParameter>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct TriggerResult {
    #[serde(default)]
    pub code: Option<String>,
    #[serde(default)]
    pub message: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct TriggerContractResponse {
    #[serde(default)]
    pub result: Option<TriggerResult>,
    #[serde(default)]
    pub energy_used: i64,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct BroadcastResponse {
    #[serde(default)]
    pub result: Option<bool>,
    #[serde(default)]
    pub message: String,
    #[serde(default)]
    pub Error: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TransactionReceiptData {
    pub result: i32,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct TransactionInfoResponse {
    #[serde(default, deserialize_with = "deserialize_hex_to_vec")]
    pub id: Vec<u8>,
    #[serde(default)]
    pub block_number: i64,
    #[serde(default)]
    pub fee: i64,
    #[serde(default)]
    pub receipt: Option<TransactionReceiptData>,
    #[serde(default)]
    pub result: i32,
    #[serde(default)]
    pub contract_result: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct NumberMessage {
    pub num: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct TriggerSmartContractRequest {
    pub owner_address: String,
    pub contract_address: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub data: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub call_value: Option<i64>,
}
