use crate::{address::AddressError, token::TokenError, zilliqa::ZilliqaNetErrors};
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum NetworkErrors {
    #[error("Failed to fetch nodes: {0}")]
    FetchNodes(ZilliqaNetErrors),

    #[error("Failed to make request: {0}")]
    Request(ZilliqaNetErrors),

    #[error("Token parse error: {0}")]
    TokenParseError(TokenError),

    #[error("Invalid response: {0}")]
    InvalidResponse(ZilliqaNetErrors),

    #[error("invalid contract data (init)")]
    InvalidContractInit,

    #[error("Parse response error")]
    ResponseParseError,

    #[error("Invalid address: {0}")]
    InvalidAddress(AddressError),
}
