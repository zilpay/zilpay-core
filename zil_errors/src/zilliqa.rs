use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ZilliqaNetErrors {
    #[error("Bad request")]
    BadRequest,

    #[error("Failed to parse response")]
    FailToParseResponse,

    #[error("Network is down")]
    NetowrkIsDown,

    #[error("Invalid payload")]
    InvalidPayload,

    #[error("Invalid RPC request: {0}")]
    InvalidRPCReq(String),

    #[error("Invalid JSON: {0}")]
    InvalidJson(String),

    #[error("Fail to fetch nodes")]
    FetchNodesError,

    #[error("Connection error: {0}")]
    ConnectionError(String),

    #[error("Invalid URL provided: {0}")]
    InvalidUrl(String),

    #[error("Request failed: {0}")]
    RequestFailed(String),

    #[error("Response parsing failed: {0}")]
    ParseError(String),

    #[error("Invalid response received")]
    InvalidResponse,
}
