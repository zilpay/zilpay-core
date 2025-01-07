use thiserror::Error;

#[derive(Debug, Error, PartialEq)]
pub enum CipherErrors {
    #[error("Argon key derivation error: {0}")]
    ArgonKeyDerivingError(argon2::Error),

    #[error("Argon hash is not valid size!")]
    Argon2HashSizeNotValid,

    #[error("Invalid enum code")]
    InvalidTypeCode,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AesGCMErrors {
    #[error("Encryption error: {0}")]
    EncryptError(String),

    #[error("Decryption error: {0}")]
    DecryptError(String),
}
