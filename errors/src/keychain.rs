use crate::cipher::CipherErrors;
use crate::{cipher::AesGCMErrors, ntru::NTRULPCipherErrors};
use ntrulp::key::kem_error::KemErrors;
use thiserror::Error;

#[derive(Debug, Error, PartialEq)]
pub enum KeyChainErrors {
    #[error("NTRU Prime cipher error")]
    NTRUPrimeCipherError(NTRULPCipherErrors),

    #[error("NTRU Prime public key import error")]
    NTRUPrimePubKeyImportError(KemErrors),

    #[error("Argon2 cipher error")]
    Argon2CipherErrors(CipherErrors),

    #[error("AES key slice error")]
    AESKeySliceError,

    #[error("AES encrypt error: {0}")]
    AESEncryptError(#[from] AesGCMErrors),

    #[error("NTRU Prime encrypt error")]
    NTRUPrimeEncryptError(NTRULPCipherErrors),

    #[error("AES decrypt error: {0}")]
    AESDecryptError(AesGCMErrors),

    #[error("NTRU Prime decrypt error")]
    NTRUPrimeDecryptError(NTRULPCipherErrors),

    #[error("Failed to slice proof cipher")]
    FailSlicedProofCipher,
}
