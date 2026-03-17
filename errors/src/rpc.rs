use bincode::ErrorKind;
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RpcError {
    #[error("Bad request: {0}")]
    BadRequest(String),

    #[error("Invalid JSON response: parse: {0}")]
    InvalidJson(String),

    #[error("Network is down")]
    NetworkDown,

    #[error("Node is not exists: {0}")]
    NodeNotExits(usize),

    #[error("Default Node unremovable")]
    DefaultNodeUnremovable,

    #[error("Duplicate node: {0}")]
    DuplicateNode(String),

    #[error("")]
    BincodeError(String),
}

impl From<Box<ErrorKind>> for RpcError {
    fn from(value: Box<ErrorKind>) -> Self {
        RpcError::BincodeError(value.to_string())
    }
}

impl From<rmp_serde::encode::Error> for RpcError {
    fn from(error: rmp_serde::encode::Error) -> Self {
        RpcError::BincodeError(error.to_string())
    }
}

impl From<rmp_serde::decode::Error> for RpcError {
    fn from(error: rmp_serde::decode::Error) -> Self {
        RpcError::BincodeError(error.to_string())
    }
}
