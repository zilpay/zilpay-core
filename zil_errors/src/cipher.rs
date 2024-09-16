use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CipherErrors {
    #[error("Argon key derivation error: {0}")]
    ArgonKeyDerivingError(String),
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AesGCMErrors {
    #[error("Encryption error: {0}")]
    EncryptError(String),
    #[error("Decryption error: {0}")]
    DecryptError(String),
}
