use thiserror::Error;

use crate::{
    address::AddressError,
    crypto::SignatureError,
    keypair::{KeyPairError, PubKeyError},
};

#[derive(Debug, Error, PartialEq)]
pub enum TransactionErrors {
    #[error("PubKeyError error: {0}")]
    PubKeyError(PubKeyError),

    #[error("address error: {0}")]
    AddressError(AddressError),

    #[error("InvalidHash")]
    InvalidHash,

    #[error("Not tranasction with hash: {0}")]
    NoTxWithHash(String),

    #[error("Fail to encode rlp")]
    EncodeTxRlpError,

    #[error("Fail to build typed tx")]
    BuildErrorTypedTx,

    #[error("Fail to build eth raw sig")]
    BuildErrorEthSig,

    #[error("Invalid transaction")]
    InvalidTransaction,

    #[error("Invalid transaction convert: {0}")]
    ConvertTxError(String),

    #[error("SignatureError error: {0}")]
    SignatureError(SignatureError),

    #[error("Invalid tx hash")]
    InvalidTxHash,

    #[error("KeyPair error: {0}")]
    KeyPairError(KeyPairError),

    #[error("Invalid transaction ID")]
    InvalidTxId,

    #[error("Invalid address")]
    InvalidAddress,

    #[error("Invalid input index")]
    InvalidInputIndex,

    #[error("Invalid secret key")]
    InvalidSecretKey,

    #[error("Sighash computation failed")]
    SighashComputationFailed,

    #[error("Invalid public key")]
    InvalidPublicKey,

    #[error("Invalid signature")]
    InvalidSignature,

    #[error("Missing UTXO amounts for Bitcoin transaction signing")]
    MissingUtxoAmounts,
}

impl From<PubKeyError> for TransactionErrors {
    fn from(error: PubKeyError) -> Self {
        TransactionErrors::PubKeyError(error)
    }
}

impl From<KeyPairError> for TransactionErrors {
    fn from(error: KeyPairError) -> Self {
        TransactionErrors::KeyPairError(error)
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
