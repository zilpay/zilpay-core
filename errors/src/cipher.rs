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

#[derive(Debug, Error, PartialEq, Eq)]
pub enum KuznechikErrors {
    #[error("Kuznechik encryption error")]
    EncryptError,

    #[error("Kuznechik decryption error")]
    DecryptError,

    #[error("Invalid ciphertext length for Kuznechik decryption")]
    InvalidCiphertextLength,

    #[error("Data length is not a multiple of block size")]
    InvalidDataLength,

    #[error("Invalid PKCS#7 padding")]
    InvalidPadding,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CyberErrors {
    #[error("Invalid public key format")]
    InvalidPublicKey,

    #[error("Invalid secret key format")]
    InvalidSecretKey,

    #[error("Invalid input parameters")]
    InvalidInput,

    #[error("Ciphertext length is too short")]
    InvalidCiphertextLength,

    #[error("Seed length is insufficient for key generation")]
    InvalidSeedLength,

    #[error("Failed to decapsulate the shared secret")]
    DecapsulationError,

    #[error("Error generating random bytes")]
    RandomGenerationError,

    #[error("Encryption error: {0}")]
    EncryptionError(String),

    #[error("Decryption error: {0}")]
    DecryptionError(String),
}
