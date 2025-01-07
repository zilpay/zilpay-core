use alloy::primitives::U256;
use config::address::ADDR_LEN;
use errors::wallet::WalletErrors;
use proto::address::Address;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FToken {
    pub name: String,
    pub symbol: String,
    pub decimals: u8,
    pub addr: Address,
    pub logo: Option<String>,
    pub balances: HashMap<usize, U256>,
    pub default: bool,
    pub native: bool,
    pub provider_index: usize,
}

impl FToken {
    pub fn from_bytes(encoded: &[u8]) -> Result<Self, WalletErrors> {
        let decoded: Self = bincode::deserialize(encoded)?;

        Ok(decoded)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, WalletErrors> {
        let encoded: Vec<u8> = bincode::serialize(&self)?;

        Ok(encoded)
    }

    pub fn zil(provider_index: usize) -> Self {
        FToken {
            provider_index,
            default: true,
            name: "Zilliqa".to_string(),
            symbol: "ZIL".to_string(),
            decimals: 12,
            addr: Address::Secp256k1Sha256Zilliqa([0u8; ADDR_LEN]),
            logo: None, // TODO: add logo
            balances: HashMap::new(),
            native: true,
        }
    }

    pub fn zlp(provider_index: usize) -> Self {
        FToken {
            provider_index,
            default: true,
            name: "ZilPay wallet".to_string(),
            symbol: "ZLP".to_string(),
            decimals: 18,
            addr: Address::from_zil_bech32("zil1l0g8u6f9g0fsvjuu74ctyla2hltefrdyt7k5f4").unwrap(),
            logo: None, // TODO: add logo
            balances: HashMap::new(),
            native: false,
        }
    }

    pub fn eth(provider_index: usize) -> Self {
        FToken {
            provider_index,
            default: true,
            name: "Ethereum".to_string(),
            symbol: "ETH".to_string(),
            decimals: 18,
            addr: Address::Secp256k1Keccak256Ethereum([0u8; ADDR_LEN]),
            logo: None, // TODO: add logo
            balances: HashMap::new(),
            native: true,
        }
    }
}
