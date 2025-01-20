use thiserror::Error;

use crate::{
    cipher::CipherErrors, keychain::KeyChainErrors, keypair::KeyPairError, network::NetworkErrors,
    session::SessionErrors, storage::LocalStorageError, tx::TransactionErrors,
    wallet::WalletErrors,
};

#[derive(Debug, Error, PartialEq)]
pub enum BackgroundError {
    #[error("LocalStorageError error: {0}")]
    LocalStorageError(LocalStorageError),

    #[error("Fail, network error: {0}")]
    NetworkErrors(NetworkErrors),

    #[error("Provider is not exists with chain id: {0}")]
    ProviderNotExists(u128),

    #[error("Provider already exists with chainid: {0}")]
    ProviderAlreadyExists(u128),

    #[error("Default provider cannot be removed: {0}")]
    ProviderIsDefault(usize),

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

    #[error("Failed to generate BIP39 words from entropy: {0}")]
    FailToGenBip39FromEntropy(String),

    #[error("Argon2 password hashing error: {0}")]
    ArgonPasswordHashError(CipherErrors),

    #[error("Argon2 proof creation error: {0}")]
    ArgonCreateProofError(CipherErrors),

    #[error("Failed to create keychain from Argon2 seed: {0}")]
    FailCreateKeychain(KeyChainErrors),

    #[error("Failed to parse mnemonic words: {0}")]
    FailParseMnemonicWords(String),

    #[error("wallet error: {0}")]
    WalletError(WalletErrors),

    #[error("TransactionErrors error: {0}")]
    TransactionErrors(TransactionErrors),

    #[error("unable verify transaction")]
    TransactionInvalidSig,
}

impl From<LocalStorageError> for BackgroundError {
    fn from(error: LocalStorageError) -> Self {
        BackgroundError::LocalStorageError(error)
    }
}

impl From<TransactionErrors> for BackgroundError {
    fn from(error: TransactionErrors) -> Self {
        BackgroundError::TransactionErrors(error)
    }
}

impl From<NetworkErrors> for BackgroundError {
    fn from(error: NetworkErrors) -> Self {
        BackgroundError::NetworkErrors(error)
    }
}

impl From<WalletErrors> for BackgroundError {
    fn from(error: WalletErrors) -> Self {
        BackgroundError::WalletError(error)
    }
}
