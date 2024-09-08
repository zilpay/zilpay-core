use crate::AesGCMErrors;
use crate::{ntru::NTRULPCipherErrors, CipherErrors};
use ntrulp::key::kem_error::KemErrors;

#[derive(Debug, PartialEq, Eq)]
pub enum KeyChainErrors {
    NTRUPrimeCipherError(NTRULPCipherErrors),
    NTRUPrimePubKeyImportError(KemErrors),
    Argon2CipherErrors(CipherErrors),
    AESKeySliceError,
    AESEncryptError(AesGCMErrors),
    NTRUPrimeEncryptError(NTRULPCipherErrors),
    AESDecryptError(AesGCMErrors),
    NTRUPrimeDecryptError(NTRULPCipherErrors),
    FailSlicedProofCipher,
}
