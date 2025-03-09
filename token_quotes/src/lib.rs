use coingecko::get_coingecko_rates;
use errors::token_quotes::TokenQuotesError;
use serde::{Deserialize, Serialize};
use token::ft::FToken;

pub type Result<T> = std::result::Result<T, TokenQuotesError>;

#[derive(Debug, Deserialize, Serialize, PartialEq, Clone, Default)]
pub enum TokenQuotesAPIOptions {
    None,
    #[default]
    Coingecko,
}

impl TokenQuotesAPIOptions {
    pub async fn request(&self, ftokens: &mut [FToken], vs_currency: &str) -> Result<()> {
        match self {
            TokenQuotesAPIOptions::None => Ok(()),
            TokenQuotesAPIOptions::Coingecko => get_coingecko_rates(ftokens, vs_currency).await,
        }
    }
}

impl std::fmt::Display for TokenQuotesAPIOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TokenQuotesAPIOptions::None => write!(f, "None"),
            TokenQuotesAPIOptions::Coingecko => write!(f, "Coingecko"),
        }
    }
}

pub mod coingecko;
