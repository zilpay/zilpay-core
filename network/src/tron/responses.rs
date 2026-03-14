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
    #[serde(default, alias = "Error")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TransactionReceiptData {
    #[serde(deserialize_with = "deserialize_receipt_result")]
    pub result: i32,
}

fn deserialize_receipt_result<'de, D>(deserializer: D) -> std::result::Result<i32, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;

    let value = serde_json::Value::deserialize(deserializer)?;
    match value {
        serde_json::Value::Number(n) => n
            .as_i64()
            .map(|v| v as i32)
            .ok_or_else(|| D::Error::custom("Invalid number")),
        serde_json::Value::String(s) => match s.as_str() {
            "SUCCESS" => Ok(0),
            "REVERT" => Ok(1),
            "OUT_OF_ENERGY" => Ok(2),
            _ => Ok(0),
        },
        _ => Ok(0),
    }
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
    #[serde(default, deserialize_with = "deserialize_receipt_result")]
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

#[derive(Debug, Clone, Deserialize, Default)]
pub struct AccountNetResponse {
    #[serde(default, rename = "freeNetUsed")]
    pub free_net_used: i64,
    #[serde(default, rename = "freeNetLimit")]
    pub free_net_limit: i64,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct AccountResourceResponse {
    #[serde(default, rename = "freeNetUsed")]
    pub free_net_used: i64,
    #[serde(default, rename = "freeNetLimit")]
    pub free_net_limit: i64,
    #[serde(default, rename = "NetUsed")]
    pub net_used: i64,
    #[serde(default, rename = "NetLimit")]
    pub net_limit: i64,
    #[serde(default, rename = "EnergyUsed")]
    pub energy_used: i64,
    #[serde(default, rename = "EnergyLimit")]
    pub energy_limit: i64,
}
