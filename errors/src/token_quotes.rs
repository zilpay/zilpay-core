use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum TokenQuotesError {
    #[error("API request error: {0}")]
    ApiRequestError(String),

    #[error("Response parsing error: {0}, content: {1}")]
    ParseResponseError(String, String),
}
