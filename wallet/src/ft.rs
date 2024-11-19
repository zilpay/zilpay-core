use std::collections::HashMap;

use alloy::primitives::U256;
use proto::address::Address;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FToken {
    pub name: String,
    pub symbol: String,
    pub decimals: u8,
    pub total_supply: U256,
    pub addr: Address,
    pub logo: Option<String>,
    pub balances: HashMap<Address, U256>,
}
