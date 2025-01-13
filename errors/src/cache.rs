use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CacheError {
    #[error("Create Dir error: {0}")]
    CreateDirError(String),

    #[error("write file error: {0}")]
    WriteFileError(String),

    #[error("Reqwest error: {0}")]
    ReqwestError(String),

    #[error("download file error, status is: {0}")]
    DownloadFileError(u16),

    #[error("Unknown content: {0}")]
    UnknownContent(String),

    #[error("Read file Error: {0}")]
    ReadFileError(String),

    #[error("Unknown image format")]
    UnknownImageFormat,
}
