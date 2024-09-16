use crate::{cipher::AesGCMErrors, keychain::KeyChainErrors};
use ntrulp::ntru::std_error::CipherError;
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SessionErrors {
    #[error("Derive key error NTRUP")]
    DeriveKeyError(CipherError),
    #[error("Encrypt session error: {0}")]
    EncryptSessionError(#[from] AesGCMErrors),
    #[error("Decrypt session error: {0}")]
    DecryptSessionError(AesGCMErrors),
    #[error("Invalid cipher key size")]
    InvalidCipherKeySize,
    #[error("Session not enabled")]
    SessionNotEnabled,
    #[error("Invalid seed: {0}")]
    InvalidSeed(#[from] KeyChainErrors),
}
