use crate::{cipher::CipherErrors, keychain::KeyChainErrors};
use thiserror::Error;

#[derive(Debug, Error, PartialEq)]
pub enum SessionErrors {
    #[error("Fail hashing with argon: {0}")]
    ArgonError(CipherErrors),

    #[error("fail crate keychain: {0}")]
    KeychainError(KeyChainErrors),

    #[error("Invalid seed decryption")]
    InvalidDecryptSession,

    #[error("Session has expired")]
    SessionExpired,

    #[error("Session not found")]
    SessionNotFound,
}
