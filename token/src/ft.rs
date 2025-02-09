use alloy::primitives::U256;
use config::address::ADDR_LEN;
use errors::wallet::WalletErrors;
use proto::address::Address;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum FtokenBalances {
    U64(u64),
    U128(u128),
    U256(U256),
}

impl FtokenBalances {
    pub fn get_num(&self) -> U256 {
        match &self {
            Self::U64(v) => U256::from(*v),
            Self::U128(v) => U256::from(*v),
            Self::U256(v) => *v,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FToken {
    pub name: String,
    pub symbol: String,
    pub decimals: u8,
    pub addr: Address,
    pub logo: Option<String>,
    pub balances: HashMap<usize, FtokenBalances>,
    pub default: bool,
    pub native: bool,
    pub chain_hash: u64,
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

    pub fn zil(chain_hash: u64) -> Self {
        FToken {
            chain_hash,
            default: true,
            name: "Zilliqa".to_string(),
            symbol: "ZIL".to_string(),
            decimals: 12,
            addr: Address::Secp256k1Sha256([0u8; ADDR_LEN]),
            logo: None,
            balances: HashMap::new(),
            native: true,
        }
    }

    pub fn zlp(chain_hash: u64) -> Self {
        FToken {
            chain_hash,
            default: true,
            name: "ZilPay wallet".to_string(),
            symbol: "ZLP".to_string(),
            decimals: 18,
            addr: Address::from_zil_bech32("zil1l0g8u6f9g0fsvjuu74ctyla2hltefrdyt7k5f4").unwrap(),
            logo: None,
            balances: HashMap::new(),
            native: false,
        }
    }

    pub fn eth(chain_hash: u64) -> Self {
        FToken {
            chain_hash,
            default: true,
            name: "Ethereum".to_string(),
            symbol: "ETH".to_string(),
            decimals: 18,
            addr: Address::Secp256k1Keccak256([0u8; ADDR_LEN]),
            logo: None,
            balances: HashMap::new(),
            native: true,
        }
    }
}
