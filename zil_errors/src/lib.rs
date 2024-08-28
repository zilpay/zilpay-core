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
    StorageDataBroken,
    StorageHashsumError,
    StorageWriteError,
    StorageTimeWentBackwards,
}

#[derive(Debug)]
pub enum WalletErrors {
    Bip39NotValid(String),
    KeyChainErrors,
    KeyChainSliceError,
}

#[derive(Debug)]
pub enum AccountErrors {
    InvalidSecretKeyBytes(KeyPairError),
}

#[derive(Debug)]
pub enum KeyPairError {
    ExtendedPrivKeyDeriveError,
    InvalidEntropy,
    InvalidSecretKey,
    SchorrError(SchorrError),
}

#[derive(Debug)]
pub enum SchorrError {
    InvalidSignTry,
}

#[derive(Debug)]
pub enum AddressError {
    InvalidPubKey,
}

#[derive(Debug, PartialEq, Eq)]
pub enum PubKeyError {
    InvalidLength,
    InvalidKeyType,
    InvalidHex,
}
