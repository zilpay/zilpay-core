use ntrulp::key::kem_error::KemErrors as NTRUKemError;
use ntrulp::ntru::std_error::CipherError as NTRUCipherError;
use ntrulp::rng::RandomErrors as NTRURandomErrors;

#[derive(Debug, PartialEq, Eq)]
pub enum NTRULPCipherErrors {
    InvalidSeedPQBytesSize,
    FailToInitF(NTRURandomErrors),
    ComputePubKeyError(NTRUKemError),
    EncryptError(NTRUCipherError),
    DecryptError(NTRUCipherError),
}
