use std::collections::HashMap;
use std::sync::Arc;

use crate::common::Provider;
use crate::nonce_parser::{build_nonce_request, process_nonce_response};
use crate::tx_parse::{build_tx_request, process_tx_response};
use crate::Result;
use alloy::primitives::U256;
use config::storage::NETWORK_DB_KEY;
use crypto::bip49::Bip49DerivationPath;
use errors::crypto::SignatureError;
use errors::network::NetworkErrors;
use errors::token::TokenError;
use errors::tx::TransactionErrors;
use proto::address::Address;
use proto::tx::TransactionReceipt;
use rpc::common::JsonRPC;
use rpc::network_config::{Bip44Network, NetworkConfig};
use rpc::provider::RpcProvider;
use rpc::zil_interfaces::ResultRes;
use serde_json::Value;
use storage::LocalStorage;
use token::ft::FToken;
use token::ft_parse::{
    build_token_requests, process_eth_balance_response, process_eth_metadata_response,
    process_zil_balance_response, process_zil_metadata_response, MetadataField, RequestType,
};

#[derive(Debug, PartialEq)]
pub struct NetworkProvider {
    pub config: NetworkConfig,
    pub index: usize,
}

impl NetworkProvider {
    pub fn get_bip49(&self, index: usize) -> Bip49DerivationPath {
        match &self.config.bip49 {
            Bip44Network::Evm(path) => Bip49DerivationPath::Ethereum((index, path.clone())),
            Bip44Network::Bitcoin(path) => Bip49DerivationPath::Bitcoin((index, path.clone())),
            Bip44Network::Solana(path) => Bip49DerivationPath::Solana((index, path.clone())),
            Bip44Network::Zilliqa(path) => Bip49DerivationPath::Zilliqa((index, path.clone())),
        }
    }
}

impl Provider for NetworkProvider {
    fn load_network_configs(storage: Arc<LocalStorage>) -> Vec<Self> {
        let bytes = storage.get(NETWORK_DB_KEY).unwrap_or_default();

        if bytes.is_empty() {
            return Vec::with_capacity(1);
        }

        let configs: Vec<NetworkConfig> =
            bincode::deserialize(&bytes).unwrap_or(Vec::with_capacity(1));
        let mut providers = Vec::with_capacity(configs.len());

        for (index, config) in configs.iter().enumerate() {
            providers.push(NetworkProvider::new(config.to_owned(), index));
        }

        providers
    }

    fn save_network_configs(providers: &[Self], storage: Arc<LocalStorage>) -> Result<()> {
        let as_vec: Vec<_> = providers.iter().map(|v| &v.config).collect();
        let bytes =
            bincode::serialize(&as_vec).map_err(|e| NetworkErrors::RPCError(e.to_string()))?;

        storage.set(NETWORK_DB_KEY, &bytes)?;
        storage.flush()?;

        Ok(())
    }
}

impl NetworkProvider {
    pub fn new(config: NetworkConfig, index: usize) -> Self {
        Self { config, index }
    }

    pub async fn fetch_nodes_list(&mut self) -> Result<()> {
        // TODO: make server ZilPay which track nodes and makes ranking.
        Ok(())
    }

    pub async fn broadcast_signed_transactions(
        &self,
        mut txns: Vec<TransactionReceipt>,
    ) -> Result<Vec<TransactionReceipt>> {
        let total = txns.len();
        let mut all_requests = Vec::with_capacity(total);

        for tx in &txns {
            if !tx.verify()? {
                return Err(TransactionErrors::SignatureError(
                    SignatureError::InvalidLength,
                ))?;
            }

            all_requests.push(build_tx_request(tx));
        }

        let provider: RpcProvider<NetworkConfig> = RpcProvider::new(&self.config);
        let responses = provider.req::<Vec<ResultRes<Value>>>(&all_requests).await?;
        drop(all_requests);

        for (tx, response) in txns.iter_mut().zip(responses.iter()) {
            process_tx_response(response, tx)?;
        }

        Ok(txns)
    }

    pub async fn fetch_nonce(&self, addresses: &[&Address]) -> Result<Vec<u64>> {
        let total = addresses.len();
        let mut all_requests = Vec::with_capacity(total);

        for &addr in addresses {
            let payload = build_nonce_request(addr);
            all_requests.push(payload);
        }

        let provider: RpcProvider<NetworkConfig> = RpcProvider::new(&self.config);
        let responses = provider.req::<Vec<ResultRes<Value>>>(&all_requests).await?;
        drop(all_requests);

        let mut nonce_list = Vec::with_capacity(total);

        for (&addr, response) in addresses.iter().zip(responses.iter()) {
            let value = process_nonce_response(response, addr)?;

            nonce_list.push(value);
        }

        Ok(nonce_list)
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
                    provider_index: self.index,
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
                    provider_index: self.index,
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
    use crypto::bip49::{ETH_PATH, ZIL_PATH};
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
            Bip44Network::Evm(ETH_PATH.to_string()),
            String::from("BSC"),
            None,
        );
        let provider = NetworkProvider::new(net_conf, 0);

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
            Bip44Network::Zilliqa(ZIL_PATH.to_string()),
            String::from("ZIL"),
            None,
        );
        let provider = NetworkProvider::new(net_conf, 0);

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
            Bip44Network::Zilliqa(ZIL_PATH.to_string()),
            String::from("ZIL"),
            None,
        );
        let provider = NetworkProvider::new(net_conf, 0);
        let mut tokens = vec![
            FToken::zil(0),
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
                provider_index: 0,
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
                provider_index: 0,
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
                provider_index: 0,
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

        assert!(tokens[3].balances.get(&0).unwrap() == &U256::from(0));
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
        let config = NetworkConfig::new(
            "Test Network",
            1,
            vec!["https://test.network".to_string()],
            Bip44Network::Zilliqa(ZIL_PATH.to_string()),
            String::from("TST"),
            None,
        );
        let providers = vec![NetworkProvider::new(config, 0)];

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
        // Create multiple test network configs
        let configs = [
            NetworkConfig::new(
                "Test Network 1",
                1,
                vec!["https://test1.network".to_string()],
                Bip44Network::Zilliqa(ZIL_PATH.to_string()),
                String::from("TST"),
                None,
            ),
            NetworkConfig::new(
                "Test Network 2",
                2,
                vec!["https://test2.network".to_string()],
                Bip44Network::Zilliqa(ZIL_PATH.to_string()),
                String::from("TST"),
                None,
            ),
            NetworkConfig::new(
                "Test Network 3",
                3,
                vec!["https://test3.network".to_string()],
                Bip44Network::Zilliqa(ZIL_PATH.to_string()),
                String::from("TST"),
                None,
            ),
        ];
        let providers: Vec<NetworkProvider> = configs
            .iter()
            .enumerate()
            .map(|(index, conf)| NetworkProvider::new(conf.clone(), index))
            .collect();

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
        let mut providers = Vec::new();

        providers.push(NetworkProvider::new(
            NetworkConfig::new(
                "Initial Network",
                1,
                vec!["https://initial.network".to_string()],
                Bip44Network::Zilliqa(ZIL_PATH.to_string()),
                String::from("TST"),
                None,
            ),
            0,
        ));

        // Save initial state
        NetworkProvider::save_network_configs(&providers, Arc::clone(&storage)).unwrap();

        // Add new network
        providers.push(NetworkProvider::new(
            NetworkConfig::new(
                "New Network",
                2,
                vec!["https://new.network".to_string()],
                Bip44Network::Zilliqa(ZIL_PATH.to_string()),
                String::from("TST"),
                None,
            ),
            0,
        ));

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

    #[tokio::test]
    async fn test_get_nonce_evm() {
        let net_conf = NetworkConfig::new(
            "Binance-smart-chain",
            56,
            vec!["https://bsc-dataseed.binance.org".to_string()],
            Bip44Network::Evm(ETH_PATH.to_string()),
            String::from("BSC"),
            None,
        );
        let provider = NetworkProvider::new(net_conf, 0);

        let account = [
            &Address::from_eth_address("0x2d09c57cB8EAf970dEEaf30546ec4dc3781c63cf").unwrap(),
            &Address::from_eth_address("0xBE0eB53F46cd790Cd13851d5EFf43D12404d33E8").unwrap(),
            &Address::Secp256k1Keccak256Ethereum([0u8; ADDR_LEN]),
        ];

        let nonces = provider.fetch_nonce(&account).await.unwrap();

        assert!(nonces.first().unwrap() >= &0);
        assert!(nonces.get(1).unwrap() >= &0);
        assert!(nonces.last().unwrap() == &0);
    }

    #[tokio::test]
    async fn test_get_nonce_scilla() {
        let net_conf = NetworkConfig::new(
            "Zilliqa",
            1,
            vec!["https://api.zilliqa.com".to_string()],
            Bip44Network::Zilliqa(ZIL_PATH.to_string()),
            String::from("ZIL"),
            None,
        );
        let provider = NetworkProvider::new(net_conf, 0);

        let account = [
            &Address::from_zil_bech32("zil1xjj35ymsvf9ajqhprwh6pkvejm2lm2e9y4q4ev").unwrap(),
            &Address::from_zil_bech32("zil170u0aar9fjgu3hfma00wgk6axjl29l6hhnm2ua").unwrap(),
            &Address::Secp256k1Sha256Zilliqa([0u8; ADDR_LEN]),
        ];

        let nonces = provider.fetch_nonce(&account).await.unwrap();

        assert!(nonces.first().unwrap() >= &0);
        assert!(nonces.get(1).unwrap() >= &0);
        assert!(nonces.last().unwrap() == &0);
    }
}
