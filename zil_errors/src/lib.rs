use std::array::TryFromSliceError;

use ntrulp::{ntru::errors::NTRUErrors, poly::errors::KemErrors, random::RandomErrors};

#[derive(Debug, PartialEq, Eq)]
pub enum ZilliqaErrors<'a> {
    Schnorr(&'a str),
    InvalidPubKey,
    InvalidSecretKey,
    InvalidSignTry,
    InvalidEntropy,
    BadRequest,
    FailToParseResponse,
    NetowrkIsDown,
    InvalidPayload,
    InvalidRPCReq(String),
    InvalidJson(String),
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
