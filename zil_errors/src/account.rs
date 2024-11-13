use crate::{
    address::AddressError,
    keypair::{KeyPairError, PubKeyError},
    LocalStorageError,
};
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AccountErrors {
    #[error("Fail to get address form pub_key: {0}")]
    PubKeyError(PubKeyError),
    #[error("Invalid PubKey type")]
    InvalidPubKeyType,
    #[error("Invalid Account type: {0}")]
    InvalidAccountType(String),
    #[error("Fail to deserialize json")]
    FailToDeserialize,
    #[error("Fail to serialize json")]
    FailToSerialize,
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
    #[error("Invalide account type value")]
    InvalidAccountTypeValue,
}
