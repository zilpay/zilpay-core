use thiserror::Error;

use crate::{
    cipher::CipherErrors, keychain::KeyChainErrors, keypair::KeyPairError, session::SessionErrors,
    storage::LocalStorageError, wallet::WalletErrors,
};

#[derive(Debug, Error, PartialEq, Eq)]
pub enum BackgroundError {
    #[error("Network provider is not exists with id: {0}")]
    NetworkProviderNotExists(usize),
    #[error("Token is not valid")]
    InvalidToken,
    #[error("Such token already exists")]
    TokenAlreadyExists,
    #[error("Fail to serialize networks")]
    FailToSerializeNetworks,
    #[error("Fail to serialize token")]
    FailToSerializeToken,
    #[error("such Ledger id already exists.")]
    LedgerIdExists,
    #[error("Fail to decrypt session: {0}")]
    DecryptSessionError(SessionErrors),
    #[error("Fail unlock wallet, error: {0}")]
    FailUnlockWallet(WalletErrors),
    #[error("No wallet with index: {0}")]
    WalletNotExists(usize),
    #[error("Fail flush Error: {0}")]
    LocalStorageFlushError(LocalStorageError),
    #[error("fail gen key pair: {0}")]
    FailToGenKeyPair(KeyPairError),
    #[error("Invalid bip39 count size: {0}")]
    InvalidWordCount(u8),
    #[error("Fail to generate bip39 words from entropy: {0}")]
    FailtToGenBip39FromEntropy(String),
    #[error("Failt to init  storage: {0}")]
    TryInitLocalStorageError(LocalStorageError),
    #[error("Fail to write db indicators: {0}")]
    FailToWriteIndicatorsWallet(LocalStorageError),
    #[error("Fail to laod wallet from storage: {0}")]
    TryLoadWalletError(WalletErrors),
    #[error("Fail to write selected wallet: {0}")]
    FailWriteSelectedWallet(LocalStorageError),
    #[error("Argon hashing password error: {0}")]
    ArgonPasswordHashError(CipherErrors),
    #[error("Argon create proof error: {0}")]
    ArgonCreateProofError(CipherErrors),
    #[error("Fail to create session: {0}")]
    CreateSessionError(SessionErrors),
    #[error("Fail to create keychain from argon seed: {0}")]
    FailCreateKeychain(KeyChainErrors),
    #[error("Fail to parse mnemonic words: {0}")]
    FailParseMnemonicWords(String),
    #[error("Fail to init wallet: {0}")]
    FailToInitWallet(WalletErrors),
    #[error("Fail to save wallet data: {0}")]
    FailToSaveWallet(WalletErrors),
}
