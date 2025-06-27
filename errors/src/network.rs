use crate::{
    address::AddressError, keypair::PubKeyError, rpc::RpcError, storage::LocalStorageError,
    token::TokenError, tx::TransactionErrors,
};
use thiserror::Error;

#[derive(Debug, Error, PartialEq)]
pub enum NetworkErrors {
    #[error("jsonRPC: {0}")]
    RPCError(String),

    #[error("Failed to make request: {0}")]
    Request(RpcError),

    #[error("EIP{0} is not suporting")]
    EIPNotSupporting(u16),

    #[error("Fail to save/read from storage err: {0}")]
    Storage(LocalStorageError),

    #[error("Token iternel error: {0}")]
    Token(TokenError),

    #[error("Http state: {0}, message {1}")]
    HttpError(u16, String),

    #[error("Network error: {0}")]
    HttpNetworkError(String),

    #[error("Http json parse error: {0}")]
    ParseHttpError(String),

    #[error("Invalid response: {0}")]
    InvalidResponse(RpcError),

    #[error("Transaction Error: {0}")]
    TransactionErrors(TransactionErrors),

    #[error("PubKey Error: {0}")]
    PubKeyError(PubKeyError),

    #[error("Address Error: {0}")]
    AddressError(AddressError),

    #[error("Parse response error")]
    ResponseParseError,

    #[error("Invalid bip49: {0}")]
    InvlaidPathBip49(String),

    #[error("Invalid bip44Network type")]
    InvlaidPathBip49Type,

    #[error("Invlid chain config")]
    InvlaidChainConfig,
}

impl From<PubKeyError> for NetworkErrors {
    fn from(error: PubKeyError) -> Self {
        NetworkErrors::PubKeyError(error)
    }
}

impl From<TransactionErrors> for NetworkErrors {
    fn from(error: TransactionErrors) -> Self {
        NetworkErrors::TransactionErrors(error)
    }
}

impl From<AddressError> for NetworkErrors {
    fn from(error: AddressError) -> Self {
        NetworkErrors::AddressError(error)
    }
}

impl From<TokenError> for NetworkErrors {
    fn from(error: TokenError) -> Self {
        NetworkErrors::Token(error)
    }
}

impl From<RpcError> for NetworkErrors {
    fn from(error: RpcError) -> Self {
        NetworkErrors::Request(error)
    }
}

impl From<LocalStorageError> for NetworkErrors {
    fn from(error: LocalStorageError) -> Self {
        NetworkErrors::Storage(error)
    }
}
