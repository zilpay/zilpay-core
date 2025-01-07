use bincode::ErrorKind;
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RpcError {
    #[error("Bad request")]
    BadRequest,

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
