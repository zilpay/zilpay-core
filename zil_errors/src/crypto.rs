use crate::keypair::PubKeyError;
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SignatureError {
    #[error("Invalid signature length")]
    InvalidLength,
    #[error("Failed to parse signature")]
    FailParseSignature,
    #[error("Failed to convert into public key: {0}")]
    FailIntoPubKey(#[from] PubKeyError),
    #[error("Failed to parse recovery information: {0}")]
    FailParseRecover(String),
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SchorrError {
    #[error("Invalid signature try")]
    InvalidSignTry,
}
