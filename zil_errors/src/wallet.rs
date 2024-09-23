use crate::{
    account::AccountErrors,
    cipher::CipherErrors,
    keychain::KeyChainErrors,
    keypair::{KeyPairError, SecretKeyError},
    session::SessionErrors,
    storage::LocalStorageError,
};
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum WalletErrors {
    #[error("Invalid signature verify")]
    InvalidVerifySig,
    #[error("Fail to verify sig error: {0}")]
    FailVerifySig(KeyPairError),
    #[error("Fail to sign mesage: {0}")]
    FailSignMessage(KeyPairError),
    #[error("passphrase is None")]
    PassphraseIsNone,
    #[error("Fail to load key pair form seed: {0}")]
    FailToCreateKeyPair(KeyPairError),
    #[error("Invalid bip49: {0}")]
    InvalidBip49(AccountErrors),
    #[error("Fail convert bytes to sk: {0}")]
    FailParseSKBytes(SecretKeyError),
    #[error("fail to load mnemonic from entropy: {0}")]
    FailLoadMnemonicFromEntropy(String),
    #[error("Fail to get SK bytes: {0}")]
    FailToGetSKBytes(SecretKeyError),
    #[error("Fail to get account by index: {0}")]
    FailToGetAccount(usize),
    #[error("Fail to deserialize wallet data")]
    FailToDeserializeWalletData,
    #[error("Fail to serialize wallet data")]
    FailToSerializeWalletData,
    #[error("Fail to save wallet data to storage: {0}")]
    FailtoSaveWalletDataToStorage(LocalStorageError),
    #[error("Fail to load data from storage: {0}")]
    FailToLoadWalletData(LocalStorageError),
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
    #[error("Session decrypt keychain error: {0}")]
    SessionDecryptKeychainError(#[from] SessionErrors),
    #[error("BIP39 not valid: {0}")]
    Bip39NotValid(String),
    #[error("Decrypt keychain error: {0}")]
    DecryptKeyChainErrors(#[from] KeyChainErrors),
    #[error("Encrypt keychain error: {0}")]
    EncryptKeyChainErrors(KeyChainErrors),
    #[error("Mnemonic error: {0}")]
    MnemonicError(String),
    #[error("Argon cipher error: {0}")]
    ArgonCipherErrors(CipherErrors),
    #[error("Invalid BIP39 account")]
    InvalidBip39Account,
    #[error("Invalid secret key account")]
    InvalidSecretKeyAccount,
    #[error("Failed to save cipher: {0}")]
    FailToSaveCipher(#[from] LocalStorageError),
    #[error("Failed to get content: {0}")]
    FailToGetContent(LocalStorageError),
    #[error("Try encrypt secret key error")]
    TryEncryptSecretKeyError,
    #[error("Invalid account type")]
    InvalidAccountType,
    #[error("Disabled sessions")]
    DisabledSessions,
    #[error("Unlock session error")]
    UnlockSessionError,
    #[error("Keychain make cipher proof error: {0}")]
    KeyChainMakeCipherProofError(KeyChainErrors),
    #[error("Failed to get proof from storage: {0}")]
    FailToGetProofFromStorage(LocalStorageError),
    #[error("Session decrypt error")]
    SessionDecryptError,
    #[error("Keychain failed to get proof")]
    KeyChainFailToGetProof,
    #[error("Proof does not match")]
    ProofNotMatch,
}
