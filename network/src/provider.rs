use std::collections::HashMap;

use crate::common::Provider;
use crate::token::{
    build_token_requests, process_eth_balance_response, process_eth_metadata_response,
    process_zil_balance_response, process_zil_metadata_response, MetadataField, RequestType,
};
use crate::Result;
use alloy::primitives::U256;
use crypto::xor_hash::xor_hash;
use proto::address::Address;
use rpc::common::JsonRPC;
use rpc::network_config::NetworkConfig;
use rpc::provider::RpcProvider;
use rpc::zil_interfaces::ResultRes;
use serde_json::Value;
use wallet::ft::FToken;
use zil_errors::network::NetworkErrors;

pub struct NetworkProvider {
    config: NetworkConfig,
}

impl Provider for NetworkProvider {
    fn get_network_id(&self) -> u64 {
        let name = &self.config.network_name;
        let chain_id = self.config.chain_id;

        xor_hash(name, chain_id)
    }
}

impl NetworkProvider {
    pub fn new(config: NetworkConfig) -> Self {
        Self { config }
    }

    pub async fn fetch_nodes_list(&mut self) -> Result<()> {
        // TODO: make server ZilPay which track nodes and makes ranking.
        Ok(())
    }

    pub fn update_balances(&self, tokens: &mut [FToken], accounts: &[&Address]) -> Result<()> {
        Ok(())
    }

    pub async fn ftoken_meta(&self, contract: Address, accounts: &[&Address]) -> Result<FToken> {
        let requests = build_token_requests(&contract, accounts, false)?;
        let provider: RpcProvider<NetworkConfig> = RpcProvider::new(&self.config);
        let responses: Vec<ResultRes<Value>> = provider
            .req(
                &requests
                    .iter()
                    .map(|(req, _)| req.clone())
                    .collect::<Vec<_>>(),
            )
            .await
            .map_err(NetworkErrors::Request)?;

        match contract {
            Address::Secp256k1Sha256Zilliqa(_) => {
                let (name, symbol, decimals) = process_zil_metadata_response(
                    responses[0]
                        .result
                        .as_ref()
                        .ok_or(NetworkErrors::InvalidContractInit)?,
                )?;

                let mut balances: HashMap<usize, U256> = HashMap::new();

                for (i, (_, req_type)) in requests.iter().enumerate().skip(1) {
                    if let RequestType::Balance(account) = req_type {
                        let balance = process_zil_balance_response(&responses[i], account, false);

                        if let Some(account_index) =
                            accounts.iter().position(|&addr| addr == *account)
                        {
                            balances.insert(account_index, balance);
                        }
                    }
                }

                Ok(FToken {
                    balances,
                    name,
                    symbol,
                    decimals,
                    addr: contract,
                    logo: None,
                    default: false,
                    native: false,
                    net_id: self.get_network_id(),
                })
            }
            Address::Secp256k1Keccak256Ethereum(_) => {
                let mut metadata_iter = responses.iter();
                let name = process_eth_metadata_response(
                    metadata_iter
                        .next()
                        .ok_or(NetworkErrors::InvalidContractInit)?,
                    &MetadataField::Name,
                )?;
                let symbol = process_eth_metadata_response(
                    metadata_iter
                        .next()
                        .ok_or(NetworkErrors::InvalidContractInit)?,
                    &MetadataField::Symbol,
                )?;
                let decimals: u8 = process_eth_metadata_response(
                    metadata_iter
                        .next()
                        .ok_or(NetworkErrors::InvalidContractInit)?,
                    &MetadataField::Decimals,
                )?
                .parse()
                .map_err(|_| NetworkErrors::InvalidContractInit)?;

                let mut balances: HashMap<usize, U256> = HashMap::new();
                for ((_, req_type), response) in requests.iter().zip(responses.iter()).skip(3) {
                    if let RequestType::Balance(account) = req_type {
                        let balance = process_eth_balance_response(response)?;

                        if let Some(account_index) =
                            accounts.iter().position(|&addr| addr == *account)
                        {
                            balances.insert(account_index, balance);
                        }
                    }
                }

                Ok(FToken {
                    balances,
                    name,
                    symbol,
                    decimals,
                    addr: contract,
                    logo: None,
                    default: false,
                    native: false,
                    net_id: self.get_network_id(),
                })
            }
        }
    }
}

#[cfg(test)]
mod tests_network {
    use super::*;
    use alloy::primitives::U256;
    use config::address::ADDR_LEN;
    use tokio;

    #[tokio::test]
    async fn test_get_ftoken_meta_bsc() {
        let net_conf = NetworkConfig::new(
            "Binance-smart-chain",
            56,
            vec!["https://bsc-dataseed.binance.org".to_string()],
        );
        let provider = NetworkProvider::new(net_conf);

        let token_addr =
            Address::from_eth_address("0x55d398326f99059fF775485246999027B3197955").unwrap();
        let account = [
            &Address::from_eth_address("0x55d398326f99059fF775485246999027B3197955").unwrap(),
            &Address::Secp256k1Keccak256Ethereum([0u8; ADDR_LEN]),
        ];
        let ftoken = provider.ftoken_meta(token_addr, &account).await.unwrap();

        assert!(*ftoken.balances.get(&0).unwrap() > U256::from(0));
        assert!(*ftoken.balances.get(&1).unwrap() == U256::from(0));

        assert_eq!(&ftoken.name, "Tether USD");
        assert_eq!(&ftoken.symbol, "USDT");
        assert_eq!(ftoken.decimals, 18u8);
    }

    #[tokio::test]
    async fn test_get_ftoken_meta_zil_legacy() {
        let net_conf = NetworkConfig::new(
            "Zilliqa(Legacy)",
            1,
            vec!["https://api.zilliqa.com".to_string()],
        );

        let provider = NetworkProvider::new(net_conf);

        let token_addr =
            Address::from_zil_bech32("zil1sxx29cshups269ahh5qjffyr58mxjv9ft78jqy").unwrap();
        let account = [
            &Address::from_zil_bech32("zil1gkwt95a67lnpe774lcmz72y6ay4jh2asmmjw6u").unwrap(),
            &Address::Secp256k1Sha256Zilliqa([0u8; ADDR_LEN]),
        ];
        let ftoken = provider.ftoken_meta(token_addr, &account).await.unwrap();

        assert!(*ftoken.balances.get(&0).unwrap() > U256::from(0));
        assert!(*ftoken.balances.get(&1).unwrap() == U256::from(0));

        assert_eq!(&ftoken.name, "Zilliqa-bridged USDT token");
        assert_eq!(&ftoken.symbol, "zUSDT");
        assert_eq!(ftoken.decimals, 6u8);
    }
}
