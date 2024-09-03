use ntrulp::{ntru::errors::NTRUErrors, poly::errors::KemErrors, random::RandomErrors};
use std::array::TryFromSliceError;

#[derive(Debug, PartialEq, Eq)]
pub enum ZilliqaErrors<'a> {
    Schnorr(&'a str),
    BadRequest,
    FailToParseResponse,
    NetowrkIsDown,
    InvalidPayload,
    InvalidRPCReq(String),
    InvalidJson(String),
    TryInitLocalStorageError(LocalStorageError),
}

#[derive(Debug, PartialEq, Eq)]
pub enum EvmErrors {
    InvalidSecretKey(String),
    InvalidSign(String),
}

#[derive(Debug, PartialEq, Eq)]
pub enum CipherErrors {
    ArgonKeyDerivingError(String),
}

#[derive(Debug, PartialEq, Eq)]
pub enum AesGCMErrors {
    EncryptError(String),
    DecryptError(String),
}

#[derive(Debug)]
pub enum NTRUPErrors<'a> {
    EncryptError(NTRUErrors<'a>),
    DecryptError(NTRUErrors<'a>),
    KeySliceError,
    KeyGenError(RandomErrors),
    ComputeKeyError(KemErrors),
}

#[derive(Debug)]
pub enum KeyChainErrors<'a> {
    NTRUPrimeError(NTRUPErrors<'a>),
    NTRUPrimeImportKeyError,
    Argon2CipherErrors(CipherErrors),
    AESKeySliceError(TryFromSliceError),
    AESEncryptError(AesGCMErrors),
    NTRUPrimeEncryptError(NTRUPErrors<'a>),
    AESDecryptError(AesGCMErrors),
    NTRUPrimeDecryptError(NTRUPErrors<'a>),
}

#[derive(Debug)]
pub enum SessionErrors<'a> {
    DeriveKeyError(CipherErrors),
    EncryptSessionError(AesGCMErrors),
    DecryptSessionError(AesGCMErrors),
    InvalidCipherKeySize,
    SessionNotEnabled,
    InvalidSeed(KeyChainErrors<'a>),
}

#[derive(Debug, PartialEq, Eq)]
pub enum LocalStorageError {
    StoragePathError,
    StorageAccessError(String),
    FailToloadBytesTree,
    FailToCreateFile,
    FailToWriteFile,
    StorageDataNotFound,
    StorageWriteError,
    StorageTimeWentBackwards,
    PayloadVersionParseError,
    PayloadParseError,
    InsufficientBytes,
    PayloadLengthError,
    InvalidBytesSizeOverflow,
}

#[derive(Debug)]
pub enum WalletErrors {
    Bip39NotValid(String),
    KeyChainErrors,
    MnemonicError(String),
    SKSliceError,
    KeyChainSliceError,
    InvalidBip39Account,
    InvalidSecretKeyAccount,
    FailToSaveCipher(LocalStorageError),
    FailToGetContent(LocalStorageError),
    TryEncryptSecretKeyError,
    InvalidAccountType,
    DisabledSessions,
}

#[derive(Debug)]
pub enum AccountErrors {
    InvalidSecretKeyBytes(KeyPairError),
    InvalidSecretKey(KeyPairError),
    InvalidPubKey(KeyPairError),
    InvalidAddress(KeyPairError),
    FailToSaveCipher(LocalStorageError),
    InvalidSeed(KeyPairError),
    InvalidSecretBytes,
}

#[derive(Debug)]
pub enum KeyPairError {
    ExtendedPrivKeyDeriveError,
    SchorrError(SchorrError),

    // New
    InvalidLength,
    InvalidSecretKey,
    InvalidEntropy,
    InvalidPublicKey,
    InvalidKeyType,
    AddressParseError(AddressError),
    EthersInvalidSecretKey(String),
    EthersInvalidSign(String),
    InvalidSignature(SignatureError),
}

#[derive(Debug)]
pub enum SchorrError {
    InvalidSignTry,
}

#[derive(Debug)]
pub enum AddressError {
    InvalidLength,
    InvalidKeyType,
    InvalidPubKey,
    InvalidSecp256k1Sha256Type,
    InvalidAddressBytesForBech32,
    InvalidBase16Address,
    InvalidVerifyingKey,
    InvalidAddressSize,
}

#[derive(Debug, PartialEq, Eq)]
pub enum SecretKeyError {
    SecretKeySliceError,
    InvalidHex,
    InvalidLength,
    InvalidKeyType,
}

#[derive(Debug, PartialEq, Eq)]
pub enum PubKeyError {
    InvalidLength,
    InvalidKeyType,
    InvalidHex,
    InvalidVerifyingKey,
    InvalidPubKey,
    FailIntoPubKey,
}

#[derive(Debug, PartialEq, Eq)]
pub enum SignatureError {
    InvalidLength,
    FailParseSignature,
    FailIntoPubKey(PubKeyError),
    FailParseRecover(String),
}
