use serde::Deserialize;
use serde_json::Value;

#[derive(Debug, Deserialize)]
pub struct TokenAmount {
    pub amount: String,
    pub decimals: u8,
}

#[derive(Debug, Deserialize)]
pub struct ParsedTokenAccountInfo {
    #[serde(rename = "tokenAmount")]
    pub token_amount: TokenAmount,
}

#[derive(Debug, Deserialize)]
pub struct ParsedData<T> {
    pub parsed: T,
}

#[derive(Debug, Deserialize)]
pub struct TokenAccountValue {
    pub data: ParsedData<ParsedTokenAccountData>,
}

#[derive(Debug, Deserialize)]
pub struct ParsedTokenAccountData {
    pub info: ParsedTokenAccountInfo,
}

#[derive(Debug, Deserialize)]
pub struct TokenAccountEntry {
    pub account: TokenAccountValue,
}

#[derive(Debug, Deserialize)]
pub struct MintInfo {
    pub decimals: u8,
}

#[derive(Debug, Deserialize)]
pub struct ParsedMintData {
    pub info: MintInfo,
}

#[derive(Debug, Deserialize)]
pub struct AccountInfoValue {
    pub data: ParsedData<ParsedMintData>,
}

#[derive(Debug, Deserialize)]
pub struct SolanaContext {
    pub slot: u64,
}

#[derive(Debug, Deserialize)]
pub struct SolanaValueResponse<T> {
    pub context: SolanaContext,
    pub value: T,
}

#[derive(Debug, Deserialize)]
pub struct SolanaResultRes<T> {
    pub result: Option<T>,
    pub error: Option<SolanaErrorRes>,
}

#[derive(Debug, Deserialize)]
pub struct SolanaErrorRes {
    pub code: i64,
    pub message: String,
}

#[derive(Debug, Deserialize)]
pub struct BlockhashValue {
    pub blockhash: String,
    #[serde(rename = "lastValidBlockHeight")]
    pub last_valid_block_height: u64,
}

#[derive(Debug, Deserialize)]
pub struct SolanaTransactionMeta {
    pub err: Option<Value>,
    pub fee: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub struct SolanaGetTransactionResult {
    #[serde(rename = "blockTime")]
    pub block_time: Option<i64>,
    pub meta: Option<SolanaTransactionMeta>,
    pub slot: Option<u64>,
}
