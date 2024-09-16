use crate::{address::AddressError, keypair::KeyPairError, LocalStorageError};
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AccountErrors {
    #[error("Invalid secret key bytes: {0}")]
    InvalidSecretKeyBytes(KeyPairError),
    #[error("Invalid secret key: {0}")]
    InvalidSecretKey(KeyPairError),
    #[error("Invalid public key: {0}")]
    InvalidPubKey(KeyPairError),
    #[error("Invalid address: {0}")]
    InvalidAddress(KeyPairError),
    #[error("Error converting address from public key: {0}")]
    AddrFromPubKeyError(#[from] AddressError),
    #[error("Failed to save cipher: {0}")]
    FailToSaveCipher(#[from] LocalStorageError),
    #[error("Invalid seed: {0}")]
    InvalidSeed(KeyPairError),
    #[error("Invalid secret bytes")]
    InvalidSecretBytes,
    #[error("Invalid account type code")]
    InvalidAccountTypeCode,
    #[error("Not enough bytes to create from bytes")]
    FromBytesErrorNotEnoughBytes,
}
