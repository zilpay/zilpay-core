use alloy::primitives::U256;
use config::address::ADDR_LEN;
use errors::wallet::WalletErrors;
use proto::address::Address;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use storage::codec::Codec;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FToken {
    pub name: String,
    pub symbol: String,
    pub decimals: u8,
    pub addr: Address,
    pub logo: Option<String>,
    pub balances: HashMap<usize, U256>,
    pub default: bool,
    pub native: bool,
    pub chain_hash: u64,
    pub rate: f64,
}

impl Codec for FToken {}

impl FToken {
    pub fn from_bytes(encoded: &[u8]) -> Result<Self, WalletErrors> {
        <Self as Codec>::from_bytes(encoded).map_err(|e| WalletErrors::BincodeError(e.to_string()))
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, WalletErrors> {
        Codec::to_bytes(self).map_err(|e| WalletErrors::BincodeError(e.to_string()))
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
            rate: 0f64,
            native: true,
        }
    }

    pub fn zlp(chain_hash: u64) -> Self {
        FToken {
            rate: 0f64,
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
            rate: 0f64,
            native: true,
        }
    }

    pub fn bitcoin_network(&self) -> Option<bitcoin::Network> {
        if !self.native {
            return None;
        }
        self.addr.get_bitcoin_network().ok()
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_bitcoin_network_mainnet() {
        let token = test_data::gen_btc_mainnet_token();
        assert_eq!(token.bitcoin_network(), Some(bitcoin::Network::Bitcoin));
    }

    #[test]
    fn test_bitcoin_network_testnet() {
        let token = test_data::gen_btc_token();
        assert_eq!(token.bitcoin_network(), Some(bitcoin::Network::Testnet));
    }

    #[test]
    fn test_bitcoin_network_regtest() {
        let token = test_data::gen_btc_regtest_token();
        assert_eq!(token.bitcoin_network(), Some(bitcoin::Network::Regtest));
    }

    #[test]
    fn test_bitcoin_network_non_native() {
        let token = test_data::gen_btc_mainnet_token();
        let mut non_native = token;
        non_native.native = false;
        assert_eq!(non_native.bitcoin_network(), None);
    }

    #[test]
    fn test_bitcoin_network_non_btc_address() {
        let token = test_data::gen_zil_token();
        assert_eq!(token.bitcoin_network(), None);
    }
}
