use thiserror::Error;

use crate::address::AddressError;

#[derive(Debug, Error, PartialEq)]
pub enum TokenError {
    #[error("Invalid token contract data")]
    InvalidContractData,

    #[error("Network error: {0}")]
    NetworkError(String),

    #[error("Invalid contract address: {0}")]
    InvalidContractAddress(AddressError),

    #[error("ABI Error: {0}")]
    ABIError(String),

    #[error("Invalid field value for {field}: {value}")]
    InvalidFieldValue { field: String, value: String },

    #[error("invalid contract data (init)")]
    InvalidContractInit,

    #[error("Token parse error")]
    TokenParseError,
}
