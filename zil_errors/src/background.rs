use thiserror::Error;

use crate::{
    cipher::CipherErrors, keychain::KeyChainErrors, keypair::KeyPairError, network::NetworkErrors,
    session::SessionErrors, storage::LocalStorageError, wallet::WalletErrors,
};

#[derive(Debug, Error, PartialEq)]
pub enum BackgroundError {
    #[error("Fail, network error: {0}")]
    NetworkErrors(NetworkErrors),

    #[error("Network provider does not exist with ID: {0}")]
    NetworkProviderNotExists(u64),

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

    #[error("Failed to unlock wallet: {0}")]
    FailUnlockWallet(WalletErrors),

    #[error("Wallet not found with index: {0}")]
    WalletNotExists(usize),

    #[error("Storage flush error: {0}")]
    LocalStorageFlushError(LocalStorageError),

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

    #[error("Failed to initialize storage: {0}")]
    TryInitLocalStorageError(LocalStorageError),

    #[error("Failed to write wallet indicators to DB: {0}")]
    FailToWriteIndicatorsWallet(LocalStorageError),

    #[error("Failed to write address book to DB: {0}")]
    FailToWriteIndicatorsAddressBook(LocalStorageError),

    #[error("Failed to write address book to DB: {0}")]
    FailToWriteIndicatorsConnections(LocalStorageError),

    #[error("Failed to load wallet from storage: {0}")]
    TryLoadWalletError(WalletErrors),

    #[error("Failed to write selected wallet: {0}")]
    FailWriteSelectedWallet(LocalStorageError),

    #[error("Argon2 password hashing error: {0}")]
    ArgonPasswordHashError(CipherErrors),

    #[error("Argon2 proof creation error: {0}")]
    ArgonCreateProofError(CipherErrors),

    #[error("Failed to create keychain from Argon2 seed: {0}")]
    FailCreateKeychain(KeyChainErrors),

    #[error("Failed to parse mnemonic words: {0}")]
    FailParseMnemonicWords(String),

    #[error("Failed to initialize wallet: {0}")]
    FailToInitWallet(WalletErrors),

    #[error("Failed to save wallet data: {0}")]
    FailToSaveWallet(WalletErrors),
}
