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
    pub fn from_code(value: u8) -> Self {
        match value {
            0 => Self::None,
            1 => Self::Coingecko,
            _ => Self::None,
        }
    }

    pub async fn request(&self, ftokens: &mut [FToken], vs_currency: &str) -> Result<bool> {
        match self {
            TokenQuotesAPIOptions::None => Ok(false),
            TokenQuotesAPIOptions::Coingecko => get_coingecko_rates(ftokens, vs_currency).await,
        }
    }

    pub fn code(&self) -> u8 {
        match self {
            Self::None => 0,
            Self::Coingecko => 1,
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
