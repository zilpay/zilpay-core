use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AddressError {
    #[error("Invalid hex Address")]
    InvalidHex,
    #[error("Invalid address length")]
    InvalidLength,
    #[error("Invalid key type")]
    InvalidKeyType,
    #[error("Invalid public key")]
    InvalidPubKey,
    #[error("Invalid Secp256k1Sha256 type")]
    InvalidSecp256k1Sha256Type,
    #[error("Invalid address bytes for Bech32")]
    InvalidAddressBytesForBech32,
    #[error("Invalid Base16 address")]
    InvalidBase16Address,
    #[error("Invalid verifying key")]
    InvalidVerifyingKey,
    #[error("Invalid address size")]
    InvalidAddressSize,
    #[error("Invalid HRP (Human-Readable Part)")]
    InvalidHRP,
    #[error("Invalid Bech32 length")]
    InvalidBech32Len,
    #[error("Not implemented")]
    NotImpl,
}
