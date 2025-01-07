use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum Bip329Errors {
    #[error("Hmac512 error: {0}")]
    HmacError(String),
    #[error("Invalid derivation path: {0}")]
    InvalidPath(String),
    #[error("Invalid private key: {0}")]
    InvalidKey(String),
    #[error("Invalid child number: {0}")]
    InvalidChild(String),
}
