use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum TokenError {
    #[error("Invalid token contract data")]
    InvalidContractData,

    #[error("Missing required field: {0}")]
    MissingField(String),

    #[error("Invalid field value for {field}: {value}")]
    InvalidFieldValue { field: String, value: String },
}
