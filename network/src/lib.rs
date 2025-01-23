use errors::network::NetworkErrors;

pub type Result<T> = std::result::Result<T, NetworkErrors>;

pub mod common;
pub mod gas_parse;
pub mod nonce_parser;
pub mod provider;
pub mod rates;
pub mod tx_parse;
