use std::collections::HashMap;

use alloy::primitives::U256;
use config::address::ADDR_LEN;
use config::provider::{ETHEREUM_ITERNEL_ID, ZILLIQA_ITERNEL_ID};
use proto::address::Address;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FToken {
    pub net_id: usize,
    pub name: String,
    pub symbol: String,
    pub decimals: u8,
    pub addr: Address,
    pub logo: Option<String>,
    pub balances: HashMap<Address, U256>,
    pub default: bool,
    pub native: bool,
}

impl FToken {
    pub fn zil() -> Self {
        FToken {
            default: true,
            name: "Zilliqa".to_string(),
            symbol: "ZIL".to_string(),
            decimals: 12,
            addr: Address::Secp256k1Sha256Zilliqa([0u8; ADDR_LEN]),
            logo: None, // TODO: add logo
            balances: HashMap::new(),
            native: true,
            net_id: ZILLIQA_ITERNEL_ID,
        }
    }

    pub fn zlp() -> Self {
        FToken {
            default: true,
            name: "ZilPay wallet".to_string(),
            symbol: "ZLP".to_string(),
            decimals: 18,
            addr: Address::from_zil_bech32("zil1l0g8u6f9g0fsvjuu74ctyla2hltefrdyt7k5f4").unwrap(),
            logo: None, // TODO: add logo
            balances: HashMap::new(),
            native: false,
            net_id: ZILLIQA_ITERNEL_ID,
        }
    }

    pub fn eth() -> Self {
        FToken {
            default: true,
            name: "Ethereum".to_string(),
            symbol: "ETH".to_string(),
            decimals: 18,
            addr: Address::Secp256k1Keccak256Ethereum([0u8; ADDR_LEN]),
            logo: None, // TODO: add logo
            balances: HashMap::new(),
            native: true,
            net_id: ETHEREUM_ITERNEL_ID,
        }
    }
}
