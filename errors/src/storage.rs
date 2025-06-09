use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum LocalStorageError {
    #[error("Storage path error")]
    StoragePathError,

    #[error("Storage access error: {0}")]
    StorageAccessError(String),

    #[error("Failed to load bytes tree")]
    FailToloadBytesTree,

    #[error("Failed to create file")]
    FailToCreateFile,

    #[error("Failed to write file")]
    FailToWriteFile,

    #[error("Storage data not found")]
    StorageDataNotFound,

    #[error("Storage write error: {0}")]
    StorageWriteError(String),

    #[error("Storage time went backwards")]
    StorageTimeWentBackwards,

    #[error("Payload version parse error")]
    PayloadVersionParseError,

    #[error("Payload parse error")]
    PayloadParseError,

    #[error("Insufficient bytes")]
    InsufficientBytes,

    #[error("Payload length error")]
    PayloadLengthError,

    #[error("Invalid bytes size overflow")]
    InvalidBytesSizeOverflow,
}
