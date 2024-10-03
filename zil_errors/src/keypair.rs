use crate::{
    address::AddressError,
    crypto::{SchorrError, SignatureError},
};
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum KeyPairError {
    #[error("Extended private key derivation error")]
    ExtendedPrivKeyDeriveError,
    #[error("Schorr error: {0}")]
    SchorrError(#[from] SchorrError),
    #[error("Invalid length")]
    InvalidLength,
    #[error("Invalid secret key")]
    InvalidSecretKey,
    #[error("Invalid entropy")]
    InvalidEntropy,
    #[error("Invalid public key")]
    InvalidPublicKey,
    #[error("Invalid key type")]
    InvalidKeyType,
    #[error("Address parse error: {0}")]
    AddressParseError(#[from] AddressError),
    #[error("Ethers invalid secret key: {0}")]
    EthersInvalidSecretKey(String),
    #[error("Ethers invalid sign: {0}")]
    EthersInvalidSign(String),
    #[error("Invalid signature: {0}")]
    InvalidSignature(#[from] SignatureError),
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SecretKeyError {
    #[error("Secret key slice error")]
    SecretKeySliceError,
    #[error("Invalid hex")]
    InvalidHex,
    #[error("Invalid length")]
    InvalidLength,
    #[error("Invalid key type")]
    InvalidKeyType,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PubKeyError {
    #[error("Invalid length")]
    InvalidLength,
    #[error("Invalid key type")]
    InvalidKeyType,
    #[error("Invalid hex")]
    InvalidHex,
    #[error("Invalid verifying key")]
    InvalidPubKey,
    #[error("Failed to convert into public key")]
    FailIntoPubKey,
    #[error("Not implemented")]
    NotImpl,
}
