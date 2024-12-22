use zil_errors::network::NetworkErrors;

pub type Result<T> = std::result::Result<T, NetworkErrors>;

pub mod provider;
pub mod rates;
pub mod token;
