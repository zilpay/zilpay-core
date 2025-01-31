use crate::{
    account::AccountErrors,
    cipher::CipherErrors,
    keychain::KeyChainErrors,
    keypair::{KeyPairError, SecretKeyError},
    storage::LocalStorageError,
    tx::TransactionErrors,
};
use bincode::ErrorKind;
use thiserror::Error;

#[derive(Debug, Error, PartialEq)]
pub enum WalletErrors {
    #[error("No accounts available in wallet")]
    NoAccounts,

    #[error("Invalid account index: {0}. Selected index must be less than number of accounts")]
    InvalidAccountIndex(usize),

    #[error("Account with index ({0}) already exists")]
    ExistsAccount(usize),

    #[error("Account with index ({0}) not exists")]
    NotExistsAccount(usize),

    #[error("fail create argon2: {0}")]
    ArgonCipherErrors(CipherErrors),

    #[error("Token doesn't extists: {0}")]
    TokenNotExists(usize),

    #[error("request tx doesn't extists: {0}")]
    TxNotExists(usize),

    #[error("Token is default flag: {0}")]
    DefaultTokenRemove(usize),

    #[error("This token already exists {0}")]
    TokenAlreadyExists(String),

    #[error("TransactionRequest with index {0} doesn't exists")]
    TransactionRequestNotExists(usize),

    #[error("Try encrypt secret key error")]
    TryEncryptSecretKeyError,

    #[error("Keychain failed to get proof")]
    KeyChainFailToGetProof,

    #[error("Invalid signature verify")]
    InvalidVerifySig,

    #[error("Fail to get SK bytes: {0}")]
    FailToGetSKBytes(SecretKeyError),

    #[error("BIP39 not valid: {0}")]
    Bip39NotValid(String),

    #[error("passphrase is None")]
    PassphraseIsNone,

    #[error("fail to load mnemonic from entropy: {0}")]
    FailLoadMnemonicFromEntropy(String),

    #[error("Fail to get account by index: {0}")]
    FailToGetAccount(usize),

    #[error("fail to find provider with hash: {0}")]
    ProviderNotExist(u64),

    #[error("Mnemonic error: {0}")]
    MnemonicError(String),

    #[error("Invalid account type")]
    InvalidAccountType,

    #[error("LocalStorage error: {0}")]
    LocalStorageError(LocalStorageError),

    #[error("Failed to get proof from storage: {0}")]
    FailToGetProofFromStorage(LocalStorageError),

    #[error("invalid hex wallet type")]
    InvalidHexToWalletType,

    #[error("WalletType serialize error: {0}")]
    WalletTypeSerialize(String),

    #[error("WalletType deserialize error: {0}")]
    WalletTypeDeserialize(String),

    #[error("Proof does not match")]
    ProofNotMatch,

    #[error("Transaction Error: {0}")]
    TransactionErrors(TransactionErrors),

    #[error("Bincode Error: {0}")]
    BincodeError(String),

    #[error("KeyChain Error: {0}")]
    KeyChainError(KeyChainErrors),

    #[error("Account Error: {0}")]
    AccountErrors(AccountErrors),

    #[error("SecretKey Error: {0}")]
    SecretKeyError(SecretKeyError),

    #[error("KeyPair Error: {0}")]
    KeyPairError(KeyPairError),
}

impl From<LocalStorageError> for WalletErrors {
    fn from(error: LocalStorageError) -> Self {
        WalletErrors::LocalStorageError(error)
    }
}

impl From<KeyPairError> for WalletErrors {
    fn from(error: KeyPairError) -> Self {
        WalletErrors::KeyPairError(error)
    }
}

impl From<AccountErrors> for WalletErrors {
    fn from(error: AccountErrors) -> Self {
        WalletErrors::AccountErrors(error)
    }
}

impl From<SecretKeyError> for WalletErrors {
    fn from(error: SecretKeyError) -> Self {
        WalletErrors::SecretKeyError(error)
    }
}

impl From<KeyChainErrors> for WalletErrors {
    fn from(error: KeyChainErrors) -> Self {
        WalletErrors::KeyChainError(error)
    }
}

impl From<Box<ErrorKind>> for WalletErrors {
    fn from(error: Box<ErrorKind>) -> Self {
        WalletErrors::BincodeError(error.to_string())
    }
}

impl From<TransactionErrors> for WalletErrors {
    fn from(error: TransactionErrors) -> Self {
        WalletErrors::TransactionErrors(error)
    }
}
