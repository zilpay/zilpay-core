use crate::{
    address::AddressError,
    keypair::{KeyPairError, PubKeyError},
    LocalStorageError,
};
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AccountErrors {
    #[error("Failed to get address from public key: {0}")]
    PubKeyError(PubKeyError),

    #[error("Invalid public key type")]
    InvalidPubKeyType,

    #[error("Invalid account type: {0}")]
    InvalidAccountType(String),

    #[error("Failed to deserialize: {0}")]
    FailedToDeserialize(String),

    #[error("Failed to serialize: {0}")]
    FailedToSerialize(String),

    #[error("Invalid secret key bytes: {0}")]
    InvalidSecretKeyBytes(KeyPairError),

    #[error("Invalid secret key: {0}")]
    InvalidSecretKey(KeyPairError),

    #[error("Invalid public key: {0}")]
    InvalidPubKey(KeyPairError),

    #[error("Invalid address: {0}")]
    InvalidAddress(KeyPairError),

    #[error("Failed to convert address from public key: {0}")]
    AddrFromPubKeyError(#[from] AddressError),

    #[error("Failed to save cipher: {0}")]
    FailedToSaveCipher(#[from] LocalStorageError),

    #[error("Invalid seed: {0}")]
    InvalidSeed(KeyPairError),

    #[error("Invalid secret bytes")]
    InvalidSecretBytes,

    #[error("AccountType serde error: {0}")]
    AccountTypeSerdeError(String),

    #[error("Account serde error: {0}")]
    AccountSerdeError(String),

    #[error("Insufficient bytes for creation")]
    FromBytesErrorNotEnoughBytes,

    #[error("Invalid account type value")]
    InvalidAccountTypeValue,
}
