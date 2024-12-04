use crate::{
    account::AccountErrors,
    cipher::CipherErrors,
    keychain::KeyChainErrors,
    keypair::{KeyPairError, SecretKeyError},
    storage::LocalStorageError,
};
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum WalletErrors {
    #[error("Invalid Ledger account: {0}")]
    InvalidLedgerAccount(AccountErrors),

    #[error("Account with index ({0}) already exists")]
    ExistsAccount(usize),

    #[error("fail create argon2: {0}")]
    ArgonCipherErrors(CipherErrors),

    #[error("Token doesn't extistsL {0}")]
    TokenNotExists(usize),

    #[error("Fail to flush and save data, error: {0}")]
    StorageFailFlush(LocalStorageError),

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

    #[error("Fail to deserialize wallet data")]
    FailToDeserializeWalletData,

    #[error("Fail to serialize wallet data")]
    FailToSerializeWalletData,

    #[error("Failed to serialize token data")]
    FailToSerializeToken,

    #[error("Fail to save wallet data to storage: {0}")]
    FailtoSaveWalletDataToStorage(LocalStorageError),

    #[error("Fail to save FT tokens to storage, error: {0}")]
    FailtoSaveFTokensToStorage(LocalStorageError),

    #[error("Fail to load data from storage: {0}")]
    FailToLoadWalletData(LocalStorageError),

    #[error("Failed to save cipher: {0}")]
    FailToSaveCipher(#[from] LocalStorageError),

    #[error("Failed to get content: {0}")]
    FailToGetContent(LocalStorageError),

    #[error("Failed to get proof from storage: {0}")]
    FailToGetProofFromStorage(LocalStorageError),

    #[error("Invalid size str of wallet address")]
    InvalidWalletAddressSize,

    #[error("Invalid hex str of wallet address")]
    InvalidWalletAddressHex,

    #[error("invalid hex wallet type")]
    InvalidHexToWalletType,

    #[error("Invalid Wallet type value")]
    InvalidWalletTypeValue,

    #[error("Unknown type: {0}")]
    UnknownWalletType(u8),

    #[error("Proof does not match")]
    ProofNotMatch,
}
