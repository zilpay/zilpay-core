use crate::{address::AddressError, token::TokenError, zilliqa::ZilliqaNetErrors};
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum NetworkErrors {
    #[error("Network {0}")]
    RPCError(String),

    #[error("Fail to crate function from ABI, Error: {0}")]
    ABIError(String),

    #[error("Failed to fetch nodes: {0}")]
    FetchNodes(ZilliqaNetErrors),

    #[error("Failed to make request: {0}")]
    Request(ZilliqaNetErrors),

    #[error("Http state: {0}, message {1}")]
    HttpError(u16, String),

    #[error("Network error: {0}")]
    HttpNetworkError(String),

    #[error("Http json parse error: {0}")]
    ParseHttpError(String),

    #[error("Token parse error: {0}")]
    TokenParseError(TokenError),

    #[error("Invalid response: {0}")]
    InvalidResponse(ZilliqaNetErrors),

    #[error("invalid contract data (init)")]
    InvalidContractInit,

    #[error("Parse response error")]
    ResponseParseError,

    #[error("Invalid EVM address: {0}")]
    InvalidETHAddress(AddressError),

    #[error("Invalid Zilliqa address: {0}")]
    InvalidZilAddress(AddressError),
}
