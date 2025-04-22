use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum IntlErrors {
    #[error("Invalid decimals: {0}")]
    InvalidDecimals(i64),

    #[error("Fail to parse str: {0}, error: {1}")]
    BigDecimalParseError(String, String),
}
