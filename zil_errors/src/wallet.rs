use crate::{
    account::AccountErrors,
    cipher::CipherErrors,
    keychain::KeyChainErrors,
    keypair::{KeyPairError, SecretKeyError},
    storage::LocalStorageError,
};
use thiserror::Error;

#[derive(Debug, Error, PartialEq)]
pub enum WalletErrors {
    #[error("No accounts available in wallet")]
    NoAccounts,

    #[error("Invalid account index: {0}. Selected index must be less than number of accounts")]
    InvalidAccountIndex(usize),

    #[error("Invalid Ledger account: {0}")]
    InvalidLedgerAccount(AccountErrors),

    #[error("Account with index ({0}) already exists")]
    ExistsAccount(usize),

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

    #[error("fail create keychain: {0}")]
    KeyChainError(KeyChainErrors),

    #[error("Decrypt keychain error: {0}")]
    DecryptKeyChainErrors(#[from] KeyChainErrors),

    #[error("Encrypt keychain error: {0}")]
    EncryptKeyChainErrors(KeyChainErrors),

    #[error("Keychain make cipher proof error: {0}")]
    KeyChainMakeCipherProofError(KeyChainErrors),

    #[error("Keychain failed to get proof")]
    KeyChainFailToGetProof,

    #[error("Invalid signature verify")]
    InvalidVerifySig,

    #[error("Fail to verify sig error: {0}")]
    FailVerifySig(KeyPairError),

    #[error("Failt to sign transaction: {0}")]
    FailToSignTransaction(KeyPairError),

    #[error("Fail to sign mesage: {0}")]
    FailSignMessage(KeyPairError),

    #[error("Fail to load key pair form seed: {0}")]
    FailToCreateKeyPair(KeyPairError),

    // Secret key related errors
    #[error("Fail convert bytes to sk: {0}")]
    FailParseSKBytes(SecretKeyError),

    #[error("Fail to get SK bytes: {0}")]
    FailToGetSKBytes(SecretKeyError),

    #[error("Invalid secret key account")]
    InvalidSecretKeyAccount,

    #[error("Invalid bip49: {0}")]
    InvalidBip49(AccountErrors),

    #[error("BIP39 not valid: {0}")]
    Bip39NotValid(String),

    #[error("Invalid BIP39 account")]
    InvalidBip39Account,

    #[error("passphrase is None")]
    PassphraseIsNone,

    #[error("fail to load mnemonic from entropy: {0}")]
    FailLoadMnemonicFromEntropy(String),

    #[error("Fail to get account by index: {0}")]
    FailToGetAccount(usize),

    #[error("Mnemonic error: {0}")]
    MnemonicError(String),

    #[error("Invalid account type")]
    InvalidAccountType,

    #[error("Fail to deserialize wallet data error: {0}")]
    FailToDeserializeWalletData(String),

    #[error("Fail to serialize wallet data error: {0}")]
    FailToSerializeWalletData(String),

    #[error("Failed to serialize token data error: {0}")]
    TokenSerdeError(String),

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
}

impl From<LocalStorageError> for WalletErrors {
    fn from(error: LocalStorageError) -> Self {
        WalletErrors::LocalStorageError(error)
    }
}
