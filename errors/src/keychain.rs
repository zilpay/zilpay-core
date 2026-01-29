use crate::cipher::{CipherErrors, CyberErrors, KuznechikErrors};
use crate::{cipher::AesGCMErrors, ntru::NTRULPCipherErrors};
use ntrulp::key::kem_error::KemErrors;
use thiserror::Error;

#[derive(Debug, Error, PartialEq)]
pub enum KeyChainErrors {
    #[error("NTRU Prime cipher error")]
    NTRULPCipherErrors(NTRULPCipherErrors),

    #[error("NTRU Prime public key import error")]
    NTRUPrimePubKeyImportError(KemErrors),

    #[error("Argon2 cipher error")]
    Argon2CipherErrors(CipherErrors),

    #[error("AES key slice error")]
    AESKeySliceError,

    #[error("AES error: {0}")]
    AesGCMErrors(AesGCMErrors),

    #[error("NTRU Prime encrypt error")]
    NTRUPrimeEncryptError(NTRULPCipherErrors),

    #[error("NTRU Prime decrypt error")]
    NTRUPrimeDecryptError(NTRULPCipherErrors),

    #[error("Failed to slice proof cipher")]
    FailSlicedProofCipher,

    #[error("Kuznechik errors: {0}")]
    KuznechikErrors(KuznechikErrors),

    #[error("Cyber errors: {0}")]
    CyberErrors(CyberErrors),

    #[error("Apple Keychain Error: {0}")]
    AppleKeychainError(String),

    #[error("Android Keychain Error: {0}")]
    AndroidKeychain(String),

    #[error("Keyring Error: {0}")]
    KeyringError(String),

    #[error("Platform Not Supported")]
    PlatformNotSupported,
}

impl From<AesGCMErrors> for KeyChainErrors {
    fn from(error: AesGCMErrors) -> Self {
        KeyChainErrors::AesGCMErrors(error)
    }
}

impl From<KuznechikErrors> for KeyChainErrors {
    fn from(error: KuznechikErrors) -> Self {
        KeyChainErrors::KuznechikErrors(error)
    }
}

impl From<NTRULPCipherErrors> for KeyChainErrors {
    fn from(error: NTRULPCipherErrors) -> Self {
        KeyChainErrors::NTRULPCipherErrors(error)
    }
}
impl From<CyberErrors> for KeyChainErrors {
    fn from(error: CyberErrors) -> Self {
        KeyChainErrors::CyberErrors(error)
    }
}
