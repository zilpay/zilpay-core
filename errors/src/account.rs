use crate::{
    address::AddressError,
    keypair::{KeyPairError, PubKeyError},
    LocalStorageError,
};
use bincode::ErrorKind;
use thiserror::Error;

#[derive(Debug, Error, PartialEq)]
pub enum AccountErrors {
    #[error("Invalid public key type")]
    InvalidPubKeyType,

    #[error("Invalid account type: {0}")]
    InvalidAccountType(String),

    #[error("Failed to deserialize: {0}")]
    FailedToDeserialize(String),

    #[error("Failed to serialize: {0}")]
    FailedToSerialize(String),

    #[error("Invalid secret key: {0}")]
    InvalidSecretKey(KeyPairError),

    #[error("Failed to convert address from public key: {0}")]
    AddrFromPubKeyError(#[from] AddressError),

    #[error("Failed to save cipher: {0}")]
    FailedToSaveCipher(#[from] LocalStorageError),

    #[error("Invalid secret bytes")]
    InvalidSecretBytes,

    #[error("AccountType serde error: {0}")]
    AccountTypeSerdeError(String),

    #[error("Insufficient bytes for creation")]
    FromBytesErrorNotEnoughBytes,

    #[error("Invalid account type value")]
    InvalidAccountTypeValue,

    #[error("Bincode Error: {0}")]
    BincodeError(String),

    #[error("PubKey Error: {0}")]
    PubKeyError(PubKeyError),

    #[error("KeyPair Error: {0}")]
    KeyPairError(KeyPairError),
}

impl From<Box<ErrorKind>> for AccountErrors {
    fn from(value: Box<ErrorKind>) -> Self {
        AccountErrors::BincodeError(value.to_string())
    }
}

impl From<PubKeyError> for AccountErrors {
    fn from(value: PubKeyError) -> Self {
        AccountErrors::PubKeyError(value)
    }
}

impl From<KeyPairError> for AccountErrors {
    fn from(value: KeyPairError) -> Self {
        AccountErrors::KeyPairError(value)
    }
}
