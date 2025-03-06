use errors::token::TokenError;

pub type Result<T> = std::result::Result<T, TokenError>;

pub mod ft;
pub mod token_type;
