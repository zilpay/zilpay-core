use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AddressError {
    #[error("invalid eth address: {0}")]
    InvalidETHAddress(String),

    #[error("Invalid VerifyingKey {0}")]
    InvalidVerifyingKey(String),

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

    #[error("Invalid address size")]
    InvalidAddressSize,

    #[error("Invalid HRP (Human-Readable Part)")]
    InvalidHRP,

    #[error("Invalid Bech32 length")]
    InvalidBech32Len,

    #[error("Invalid Base58 encoding")]
    InvalidBase58,

    #[error("Invalid checksum")]
    InvalidChecksum,

    #[error("Invalid version byte")]
    InvalidVersion,

    #[error("Invalid address type for this operation")]
    InvalidAddressType,

    #[error("Bech32 error: {0}")]
    Bech32Error(String),

    #[error("Invalid HRP")]
    InvalidHrp,

    #[error("Not implemented")]
    NotImpl,
}
