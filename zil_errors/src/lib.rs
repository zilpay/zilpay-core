use keychain::KeyChainErrors;

pub mod keychain;
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

#[derive(Debug, PartialEq, Eq)]
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
    SessionDecryptKeychainError(SessionErrors),
    Bip39NotValid(String),
    DecryptKeyChainErrors(KeyChainErrors),
    EncryptKeyChainErrors(KeyChainErrors),
    MnemonicError(String),
    ArgonCipherErrors(CipherErrors),
    InvalidBip39Account,
    InvalidSecretKeyAccount,
    FailToSaveCipher(LocalStorageError),
    FailToGetContent(LocalStorageError),
    TryEncryptSecretKeyError,
    InvalidAccountType,
    DisabledSessions,
    UnlockSessionError,
    KeyChainMakeCipherProofError(KeyChainErrors),
    FailToGetProofFromStorage(LocalStorageError),
    SessionDecryptError,
    KeyChainFailToGetProof,
    ProofNotMatch,
}

#[derive(Debug, PartialEq, Eq)]
pub enum AccountErrors {
    InvalidSecretKeyBytes(KeyPairError),
    InvalidSecretKey(KeyPairError),
    InvalidPubKey(KeyPairError),
    InvalidAddress(KeyPairError),
    AddrFromPubKeyError(AddressError),
    FailToSaveCipher(LocalStorageError),
    InvalidSeed(KeyPairError),
    InvalidSecretBytes,
    InvalidAccountTypeCode,
    FromBytesErrorNotEnoughBytes,
}

#[derive(Debug, PartialEq, Eq)]
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

#[derive(Debug, PartialEq, Eq)]
pub enum SchorrError {
    InvalidSignTry,
}

#[derive(Debug, PartialEq, Eq)]
pub enum AddressError {
    InvalidLength,
    InvalidKeyType,
    InvalidPubKey,
    InvalidSecp256k1Sha256Type,
    InvalidAddressBytesForBech32,
    InvalidBase16Address,
    InvalidVerifyingKey,
    InvalidAddressSize,
    InvalidHRP,
    InvalidBech32Len,
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
