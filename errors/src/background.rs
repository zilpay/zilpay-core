use pqbip39::errors::Bip39Error;
use thiserror::Error;

use crate::{
    account::AccountErrors,
    cipher::CipherErrors,
    keychain::KeyChainErrors,
    keypair::{KeyPairError, PubKeyError, SecretKeyError},
    network::NetworkErrors,
    session::SessionErrors,
    storage::LocalStorageError,
    token::TokenError,
    tx::TransactionErrors,
    wallet::WalletErrors,
};
use bincode::ErrorKind;

#[derive(Debug, Error, PartialEq)]
pub enum BackgroundError {
    #[error("LocalStorageError error: {0}")]
    LocalStorageError(LocalStorageError),

    #[error("Fail, network error: {0}")]
    NetworkErrors(NetworkErrors),

    #[error("Provider is not exists with chain id: {0}")]
    ProviderNotExists(u64),

    #[error("Provider depends of : {0}")]
    ProviderDepends(String),

    #[error("Failed to serialize networks")]
    FailToSerializeNetworks,

    #[error("Failed to decrypt session: {0}")]
    DecryptSessionError(SessionErrors),

    #[error("Failed to create session: {0}")]
    CreateSessionError(SessionErrors),

    #[error("failt to serialize address book")]
    FailToSerializeAddressBook,

    #[error("Failed to serialize rates!")]
    FailToSerializeRates,

    #[error("Ledger ID already exists")]
    LedgerIdExists(String),

    #[error("Wallet not found with index: {0}")]
    WalletNotExists(usize),

    #[error("Failed to generate key pair: {0}")]
    FailToGenKeyPair(KeyPairError),

    #[error("Connection with such domain already exits: {0}")]
    ConnectionAlreadyExists(String),

    #[error("connection not found: {0}")]
    ConnectionNotFound(String),

    #[error("such address {0}, already exists")]
    AddressAlreadyExists(String),

    #[error("Fail to serialize connections error: {0}")]
    FailToSerializeConnections(String),

    #[error("Invalid BIP39 word count: {0}")]
    InvalidWordCount(u8),

    #[error("Deserialize TypedData error: {0}")]
    FailDeserializeTypedData(String),

    #[error("Argon2 password hashing error: {0}")]
    ArgonPasswordHashError(CipherErrors),

    #[error("Argon2 proof creation error: {0}")]
    ArgonCreateProofError(CipherErrors),

    #[error("Worker error: {0}")]
    WorkerError(String),

    #[error("wallet error: {0}")]
    WalletError(WalletErrors),

    #[error("Transaction error: {0}")]
    TransactionErrors(TransactionErrors),

    #[error("Token error: {0}")]
    TokenError(TokenError),

    #[error("Account Error: {0}")]
    AccountErrors(AccountErrors),

    #[error("PubKey Error: {0}")]
    PubKeyError(PubKeyError),

    #[error("keypair Error: {0}")]
    KeyPairError(KeyPairError),

    #[error("unable verify transaction")]
    TransactionInvalidSig,

    #[error("Bincode Error: {0}")]
    BincodeError(String),

    #[error("keychain error: {0}")]
    KeyChainErrors(KeyChainErrors),

    #[error("Invalid backup signature")]
    InvalidBackupSignature,

    #[error("Invalid backup format")]
    InvalidBackupFormat,

    #[error("Unsupported backup version: {0}")]
    UnsupportedBackupVersion(u8),

    #[error("SecretKey error: {0}")]
    SecretKeyError(SecretKeyError),

    #[error("Bip39 error: {0}")]
    Bip39Error(Bip39Error),
}

impl From<SecretKeyError> for BackgroundError {
    fn from(error: SecretKeyError) -> Self {
        BackgroundError::SecretKeyError(error)
    }
}

impl From<LocalStorageError> for BackgroundError {
    fn from(error: LocalStorageError) -> Self {
        BackgroundError::LocalStorageError(error)
    }
}

impl From<KeyPairError> for BackgroundError {
    fn from(error: KeyPairError) -> Self {
        BackgroundError::KeyPairError(error)
    }
}

impl From<PubKeyError> for BackgroundError {
    fn from(error: PubKeyError) -> Self {
        BackgroundError::PubKeyError(error)
    }
}

impl From<AccountErrors> for BackgroundError {
    fn from(error: AccountErrors) -> Self {
        BackgroundError::AccountErrors(error)
    }
}

impl From<TransactionErrors> for BackgroundError {
    fn from(error: TransactionErrors) -> Self {
        BackgroundError::TransactionErrors(error)
    }
}

impl From<TokenError> for BackgroundError {
    fn from(error: TokenError) -> Self {
        BackgroundError::TokenError(error)
    }
}

impl From<NetworkErrors> for BackgroundError {
    fn from(error: NetworkErrors) -> Self {
        BackgroundError::NetworkErrors(error)
    }
}

impl From<KeyChainErrors> for BackgroundError {
    fn from(error: KeyChainErrors) -> Self {
        BackgroundError::KeyChainErrors(error)
    }
}

impl From<WalletErrors> for BackgroundError {
    fn from(error: WalletErrors) -> Self {
        BackgroundError::WalletError(error)
    }
}

impl From<Box<ErrorKind>> for BackgroundError {
    fn from(error: Box<ErrorKind>) -> Self {
        BackgroundError::BincodeError(error.to_string())
    }
}

impl From<Bip39Error> for BackgroundError {
    fn from(error: Bip39Error) -> Self {
        BackgroundError::Bip39Error(error)
    }
}
