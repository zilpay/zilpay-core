use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::sync::Arc;

use crate::common::Provider;
use crate::Result;
use alloy::primitives::U256;
use config::storage::NETWORK_DB_KEY;
use crypto::xor_hash::xor_hash;
use proto::address::Address;
use rpc::common::JsonRPC;
use rpc::network_config::NetworkConfig;
use rpc::provider::RpcProvider;
use rpc::zil_interfaces::ResultRes;
use serde_json::Value;
use storage::LocalStorage;
use token::ft::FToken;
use token::ft_parse::{
    build_token_requests, process_eth_balance_response, process_eth_metadata_response,
    process_zil_balance_response, process_zil_metadata_response, MetadataField, RequestType,
};
use zil_errors::network::NetworkErrors;
use zil_errors::token::TokenError;

#[derive(Debug)]
pub struct NetworkProvider {
    pub config: NetworkConfig,
}

impl Hash for NetworkProvider {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.get_network_id().hash(state);
    }
}

impl PartialEq for NetworkProvider {
    fn eq(&self, other: &Self) -> bool {
        self.get_network_id() == other.get_network_id()
    }
}

impl Eq for NetworkProvider {}

impl Provider for NetworkProvider {
    fn get_network_id(&self) -> u64 {
        let name = &self.config.network_name;
        let chain_id = self.config.chain_id;

        xor_hash(name, chain_id)
    }

    fn load_network_configs(storage: Arc<LocalStorage>) -> HashSet<Self> {
        let bytes = storage.get(NETWORK_DB_KEY).unwrap_or_default();

        if bytes.is_empty() {
            return HashSet::with_capacity(1);
        }

        let configs: Vec<NetworkConfig> =
            bincode::deserialize(&bytes).unwrap_or(Vec::with_capacity(1));
        let mut providers = HashSet::with_capacity(configs.len());

        for config in configs {
            providers.insert(NetworkProvider::new(config));
        }

        providers
    }

    fn save_network_configs(providers: &HashSet<Self>, storage: Arc<LocalStorage>) -> Result<()> {
        let as_vec: Vec<_> = providers.iter().map(|v| &v.config).collect();
        let bytes =
            bincode::serialize(&as_vec).map_err(|e| NetworkErrors::RPCError(e.to_string()))?;

        storage
            .set(NETWORK_DB_KEY, &bytes)
            .map_err(NetworkErrors::Storage)?;

        Ok(())
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

    pub async fn update_balances(
        &self,
        tokens: &mut [FToken],
        accounts: &[&Address],
    ) -> Result<()> {
        let total_requests = tokens.iter().fold(0, |acc, token| match token.addr {
            Address::Secp256k1Sha256Zilliqa(_) => acc + accounts.len(),
            Address::Secp256k1Keccak256Ethereum(_) => acc + accounts.len(),
        });

        if total_requests == 0 {
            return Ok(());
        }

        let mut all_requests = Vec::with_capacity(total_requests);
        let mut request_mapping = Vec::with_capacity(total_requests);

        for (token_idx, token) in tokens.iter().enumerate() {
            let requests = build_token_requests(&token.addr, accounts, token.native)?;

            for (req, req_type) in requests {
                if let RequestType::Balance(account) = req_type {
                    request_mapping.push((token_idx, account));
                    all_requests.push(req);
                }
            }
        }

        let provider: RpcProvider<NetworkConfig> = RpcProvider::new(&self.config);
        let responses = provider
            .req::<Vec<ResultRes<Value>>>(&all_requests)
            .await
            .map_err(NetworkErrors::Request)?;

        for ((token_idx, account), response) in request_mapping.iter().zip(responses.iter()) {
            match tokens[*token_idx].addr {
                Address::Secp256k1Sha256Zilliqa(_) => {
                    let balance =
                        process_zil_balance_response(response, account, tokens[*token_idx].native);

                    if let Some(account_index) = accounts.iter().position(|&addr| addr == *account)
                    {
                        tokens[*token_idx].balances.insert(account_index, balance);
                    }
                }
                Address::Secp256k1Keccak256Ethereum(_) => {
                    let balance = process_eth_balance_response(response)?;

                    if let Some(account_index) = accounts.iter().position(|&addr| addr == *account)
                    {
                        tokens[*token_idx].balances.insert(account_index, balance);
                    }
                }
            }
        }

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
                        .ok_or(TokenError::InvalidContractInit)?,
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
                })
            }
            Address::Secp256k1Keccak256Ethereum(_) => {
                let mut metadata_iter = responses.iter();
                let name = process_eth_metadata_response(
                    metadata_iter
                        .next()
                        .ok_or(TokenError::InvalidContractInit)?,
                    &MetadataField::Name,
                )?;
                let symbol = process_eth_metadata_response(
                    metadata_iter
                        .next()
                        .ok_or(TokenError::InvalidContractInit)?,
                    &MetadataField::Symbol,
                )?;
                let decimals: u8 = process_eth_metadata_response(
                    metadata_iter
                        .next()
                        .ok_or(TokenError::InvalidContractInit)?,
                    &MetadataField::Decimals,
                )?
                .parse()
                .map_err(|_| TokenError::InvalidContractInit)?;

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
    use rand::Rng;
    use tokio;

    fn setup_temp_storage() -> Arc<LocalStorage> {
        let mut rng = rand::thread_rng();
        let dir = format!("/tmp/{}", rng.gen::<usize>());

        let storage = LocalStorage::from(&dir).unwrap();
        Arc::new(storage)
    }

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

    #[tokio::test]
    async fn test_update_balance_scilla() {
        let net_conf = NetworkConfig::new(
            "Zilliqa(Legacy)",
            1,
            vec!["https://api.zilliqa.com".to_string()],
        );
        let provider = NetworkProvider::new(net_conf);
        let mut tokens = vec![
            FToken::zil(),
            FToken {
                name: "ZilPay token".to_string(),
                symbol: "ZLP".to_string(),
                decimals: 18,
                addr: Address::from_zil_bech32("zil1l0g8u6f9g0fsvjuu74ctyla2hltefrdyt7k5f4")
                    .unwrap(),
                native: false,
                logo: None,
                default: false,
                balances: HashMap::new(),
            },
            FToken {
                name: "Zilliqa-bridged USDT token".to_string(),
                symbol: "zUSDT".to_string(),
                decimals: 6,
                addr: Address::from_zil_bech32("zil1sxx29cshups269ahh5qjffyr58mxjv9ft78jqy")
                    .unwrap(),
                native: false,
                logo: None,
                default: false,
                balances: HashMap::new(),
            },
            FToken {
                name: "Zilliqa-bridged ETH token".to_string(),
                symbol: "zETH".to_string(),
                decimals: 18,
                addr: Address::from_zil_bech32("zil19j33tapjje2xzng7svslnsjjjgge930jx0w09v")
                    .unwrap(),
                native: false,
                logo: None,
                default: false,
                balances: HashMap::new(),
            },
        ];
        let accounts = [
            &Address::from_zil_bech32("zil1xr07v36qa4zeagg4k5tm6ummht0jrwpcu0n55d").unwrap(),
            &Address::from_zil_bech32("zil1wl38cwww2u3g8wzgutxlxtxwwc0rf7jf27zace").unwrap(),
            &Address::from_zil_bech32("zil1uxfzk4n9ef2t3f4c4939ludlvp349uwqdx32xt").unwrap(),
        ];

        provider
            .update_balances(&mut tokens, &accounts)
            .await
            .unwrap();

        assert!(tokens[0].balances.get(&0).unwrap() > &U256::from(0));
        assert!(tokens[0].balances.get(&1).unwrap() > &U256::from(0));
        assert!(tokens[0].balances.get(&2).unwrap() > &U256::from(0));

        assert!(tokens[1].balances.get(&0).unwrap() > &U256::from(0));
        assert!(tokens[1].balances.get(&1).unwrap() > &U256::from(0));
        assert!(tokens[1].balances.get(&2).unwrap() == &U256::from(0));

        assert!(tokens[2].balances.get(&0).unwrap() > &U256::from(0));
        assert!(tokens[2].balances.get(&2).unwrap() == &U256::from(0));

        assert!(tokens[3].balances.get(&0).unwrap() > &U256::from(0));
        assert!(tokens[3].balances.get(&1).unwrap() == &U256::from(0));
        assert!(tokens[3].balances.get(&2).unwrap() == &U256::from(0));
    }

    // #[tokio::test]
    // async fn test_update_balance_scilla_evm() {
    //     let net_conf = NetworkConfig::new(
    //         "Zilliqa(evm)",
    //         32770,
    //         vec!["https://api.zq2-protomainnet.zilliqa.com".to_string()],
    //     );
    //     let provider = NetworkProvider::new(net_conf);
    //     let mut tokens = vec![
    //         FToken::zil(),
    //         FToken::eth(),
    //         FToken {
    //             name: "ZilPay token".to_string(),
    //             symbol: "ZLP".to_string(),
    //             decimals: 18,
    //             addr: Address::from_zil_bech32("zil1l0g8u6f9g0fsvjuu74ctyla2hltefrdyt7k5f4")
    //                 .unwrap(),
    //             native: false,
    //             logo: None,
    //             default: false,
    //             balances: HashMap::new(),
    //             net_id: provider.get_network_id(),
    //         },
    //         FToken {
    //             name: "Zilliqa-bridged USDT token".to_string(),
    //             symbol: "zUSDT".to_string(),
    //             decimals: 6,
    //             addr: Address::from_zil_bech32("zil1sxx29cshups269ahh5qjffyr58mxjv9ft78jqy")
    //                 .unwrap(),
    //             native: false,
    //             logo: None,
    //             default: false,
    //             balances: HashMap::new(),
    //             net_id: provider.get_network_id(),
    //         },
    //         FToken {
    //             name: "Zilliqa-bridged USDT token".to_string(),
    //             symbol: "zUSDT".to_string(),
    //             decimals: 18,
    //             native: false,
    //             addr: Address::from_eth_address("0x2274005778063684fbB1BfA96a2b725dC37D75f9")
    //                 .unwrap(),
    //             logo: None,
    //             default: false,
    //             balances: HashMap::new(),
    //             net_id: provider.get_network_id(),
    //         },
    //     ];
    //     let accounts = [
    //         &Address::from_zil_bech32("zil1xr07v36qa4zeagg4k5tm6ummht0jrwpcu0n55d").unwrap(),
    //         &Address::from_zil_bech32("zil1uxfzk4n9ef2t3f4c4939ludlvp349uwqdx32xt").unwrap(),
    //         &Address::from_eth_address("0xe30161F32A019d876F082d9FF13ed451a03A2086").unwrap(),
    //         &Address::from_eth_address("0x36Eb59A9ec5A7592ded8F66e13fb603f9FD68081").unwrap(),
    //     ];

    //     provider
    //         .update_balances(&mut tokens, &accounts)
    //         .await
    //         .unwrap();

    //     assert!(tokens[0].balances.contains_key(&0));
    //     assert!(tokens[0].balances.contains_key(&1));
    //     assert!(tokens[0].balances.contains_key(&2));
    //     assert!(tokens[0].balances.contains_key(&3));

    //     assert!(tokens[1].balances.contains_key(&0));
    //     assert!(tokens[1].balances.contains_key(&1));
    //     assert!(tokens[1].balances.contains_key(&2));
    //     assert!(tokens[1].balances.contains_key(&3));

    //     assert!(tokens[2].balances.contains_key(&0));
    //     assert!(tokens[2].balances.contains_key(&1));
    //     assert!(tokens[2].balances.contains_key(&2));
    //     assert!(tokens[2].balances.contains_key(&3));

    //     assert!(tokens[3].balances.contains_key(&0));
    //     assert!(tokens[3].balances.contains_key(&1));
    //     assert!(tokens[3].balances.contains_key(&2));
    //     assert!(tokens[3].balances.contains_key(&3));

    //     assert!(tokens[4].balances.contains_key(&0));
    //     assert!(tokens[4].balances.contains_key(&1));
    //     assert!(tokens[4].balances.contains_key(&2));
    //     assert!(tokens[4].balances.contains_key(&3));
    // }

    #[test]
    fn test_empty_storage() {
        let storage = setup_temp_storage();
        let providers = NetworkProvider::load_network_configs(storage);
        assert!(providers.is_empty());
    }

    #[test]
    fn test_save_and_load_single_network() {
        let storage = setup_temp_storage();

        // Create a test network config
        let config =
            NetworkConfig::new("Test Network", 1, vec!["https://test.network".to_string()]);

        let mut providers = HashSet::new();
        providers.insert(NetworkProvider::new(config.clone()));

        // Save to storage
        NetworkProvider::save_network_configs(&providers, Arc::clone(&storage)).unwrap();

        // Load from storage
        let loaded_providers = NetworkProvider::load_network_configs(Arc::clone(&storage));

        assert_eq!(providers.len(), loaded_providers.len());
        assert!(loaded_providers
            .iter()
            .any(|p| p.config.network_name == "Test Network"));
        assert!(loaded_providers.iter().any(|p| p.config.chain_id == 1));
    }

    #[test]
    fn test_save_and_load_multiple_networks() {
        let storage = setup_temp_storage();

        let mut providers = HashSet::new();

        // Create multiple test network configs
        let configs = vec![
            NetworkConfig::new(
                "Test Network 1",
                1,
                vec!["https://test1.network".to_string()],
            ),
            NetworkConfig::new(
                "Test Network 2",
                2,
                vec!["https://test2.network".to_string()],
            ),
            NetworkConfig::new(
                "Test Network 3",
                3,
                vec!["https://test3.network".to_string()],
            ),
        ];

        for config in configs {
            providers.insert(NetworkProvider::new(config));
        }

        // Save to storage
        NetworkProvider::save_network_configs(&providers, Arc::clone(&storage)).unwrap();

        // Load from storage
        let loaded_providers = NetworkProvider::load_network_configs(Arc::clone(&storage));

        assert_eq!(providers.len(), loaded_providers.len());
        assert_eq!(loaded_providers.len(), 3);

        // Verify each network was loaded correctly
        for provider in &loaded_providers {
            assert!(providers.contains(provider));
        }
    }

    #[test]
    fn test_update_networks() {
        let storage = setup_temp_storage();

        // Initial network
        let mut providers = HashSet::new();
        providers.insert(NetworkProvider::new(NetworkConfig::new(
            "Initial Network",
            1,
            vec!["https://initial.network".to_string()],
        )));

        // Save initial state
        NetworkProvider::save_network_configs(&providers, Arc::clone(&storage)).unwrap();

        // Add new network
        providers.insert(NetworkProvider::new(NetworkConfig::new(
            "New Network",
            2,
            vec!["https://new.network".to_string()],
        )));

        // Update storage
        NetworkProvider::save_network_configs(&providers, Arc::clone(&storage)).unwrap();

        // Load and verify
        let loaded_providers = NetworkProvider::load_network_configs(Arc::clone(&storage));
        assert_eq!(loaded_providers.len(), 2);
        assert!(loaded_providers
            .iter()
            .any(|p| p.config.network_name == "Initial Network"));
        assert!(loaded_providers
            .iter()
            .any(|p| p.config.network_name == "New Network"));
    }

    #[test]
    fn test_network_equality() {
        let config1 =
            NetworkConfig::new("Test Network", 1, vec!["https://test.network".to_string()]);
        let config2 =
            NetworkConfig::new("Test Network", 1, vec!["https://different.url".to_string()]);
        let config3 = NetworkConfig::new(
            "Different Network",
            2,
            vec!["https://test.network".to_string()],
        );

        let provider1 = NetworkProvider::new(config1);
        let provider2 = NetworkProvider::new(config2);
        let provider3 = NetworkProvider::new(config3);

        // Same network ID should be equal
        assert_eq!(&provider1, &provider2);
        // Different network ID should not be equal
        assert_ne!(&provider1, &provider3);
    }
}
