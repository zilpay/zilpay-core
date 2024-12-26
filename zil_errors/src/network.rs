use crate::{address::AddressError, rpc::RpcError, token::TokenError};
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum NetworkErrors {
    #[error("Network {0}")]
    RPCError(String),

    #[error("Fail to crate function from ABI, Error: {0}")]
    ABIError(String),

    #[error("Failed to make request: {0}")]
    Request(RpcError),

    #[error("Http state: {0}, message {1}")]
    HttpError(u16, String),

    #[error("Network error: {0}")]
    HttpNetworkError(String),

    #[error("Http json parse error: {0}")]
    ParseHttpError(String),

    #[error("Token parse error: {0}")]
    TokenParseError(TokenError),

    #[error("Invalid response: {0}")]
    InvalidResponse(RpcError),

    #[error("invalid contract data (init)")]
    InvalidContractInit,

    #[error("Parse response error")]
    ResponseParseError,

    #[error("Invalid EVM address: {0}")]
    InvalidETHAddress(AddressError),

    #[error("Invalid Zilliqa address: {0}")]
    InvalidZilAddress(AddressError),
}
