use thiserror::Error;

use crate::{address::AddressError, crypto::SignatureError, keypair::PubKeyError};

#[derive(Debug, Error, PartialEq)]
pub enum TransactionErrors {
    #[error("PubKeyError error: {0}")]
    PubKeyError(PubKeyError),

    #[error("SignatureError error: {0}")]
    SignatureError(SignatureError),

    #[error("AddressError error: {0}")]
    AddressError(AddressError),

    #[error("Invalid tx hash")]
    InvalidTxHash,
}

impl From<PubKeyError> for TransactionErrors {
    fn from(error: PubKeyError) -> Self {
        TransactionErrors::PubKeyError(error)
    }
}

impl From<AddressError> for TransactionErrors {
    fn from(error: AddressError) -> Self {
        TransactionErrors::AddressError(error)
    }
}

impl From<SignatureError> for TransactionErrors {
    fn from(error: SignatureError) -> Self {
        TransactionErrors::SignatureError(error)
    }
}
