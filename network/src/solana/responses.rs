use serde::Deserialize;
use serde_json::Value;

#[derive(Debug, Deserialize)]
pub struct TokenAmount {
    pub amount: String,
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
pub struct SolanaValueResponse<T> {
    pub value: T,
}

#[derive(Debug, Deserialize)]
pub struct BlockhashValue {
    pub blockhash: String,
}

#[derive(Debug, Deserialize)]
pub struct SolanaTransactionMeta {
    pub err: Option<Value>,
    pub fee: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub struct SolanaGetTransactionResult {
    pub meta: Option<SolanaTransactionMeta>,
    pub slot: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub struct SolanaAccountInfo {
    pub owner: String,
    pub space: u64,
}
