use crate::{rpc::RpcError, storage::LocalStorageError, token::TokenError};
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum NetworkErrors {
    #[error("jsonRPC: {0}")]
    RPCError(String),

    #[error("Failed to make request: {0}")]
    Request(RpcError),

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

    #[error("Parse response error")]
    ResponseParseError,
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
