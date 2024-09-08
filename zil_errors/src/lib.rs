use std::array::TryFromSliceError;

pub mod ntru;

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
pub enum KeyChainErrors {
    NTRUPrimeError,
    NTRUPrimeImportKeyError,
    Argon2CipherErrors(CipherErrors),
    AESKeySliceError(TryFromSliceError),
    AESEncryptError(AesGCMErrors),
    NTRUPrimeEncryptError,
    AESDecryptError(AesGCMErrors),
    NTRUPrimeDecryptError,
    FailSlicedProofCipher,
}

#[derive(Debug)]
pub enum SessionErrors {
    DeriveKeyError(CipherErrors),
    EncryptSessionError(AesGCMErrors),
    DecryptSessionError(AesGCMErrors),
    InvalidCipherKeySize,
    SessionNotEnabled,
    InvalidSeed(KeyChainErrors),
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

#[derive(Debug, PartialEq, Eq)]
pub enum WalletErrors {
    Bip39NotValid(String),
    KeyChainErrors,
    MnemonicError(String),
    ArgonCipherErrors(CipherErrors),
    SKSliceError,
    KeyChainSliceError,
    InvalidBip39Account,
    InvalidSecretKeyAccount,
    FailToSaveCipher(LocalStorageError),
    FailToGetContent(LocalStorageError),
    TryEncryptSecretKeyError,
    InvalidAccountType,
    DisabledSessions,
    UnlockSessionError,
    KeyChainMakeCipherProofError,
    FailToGetProofFromStorage(LocalStorageError),
    SessionDecryptError,
    KeyChainFailToGetProof,
    ProofNotMatch,
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
