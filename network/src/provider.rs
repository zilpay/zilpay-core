use std::sync::Arc;

use crate::btc::BtcOperations;
use crate::common::Provider;
use crate::evm::{EvmOperations, RequiredTxParams};
use crate::Result;
use alloy::primitives::U256;
use config::storage::NETWORK_DB_KEY_V1;
use crypto::bip49::DerivationPath;
use crypto::slip44;
use errors::network::NetworkErrors;
use errors::rpc::RpcError;
use history::transaction::HistoricalTransaction;
use proto::address::Address;
use proto::tx::{TransactionReceipt, TransactionRequest};
use rpc::common::JsonRPC;
use rpc::network_config::ChainConfig;
use rpc::provider::RpcProvider;
use serde_json::Value;
use storage::LocalStorage;
use token::ft::FToken;

#[derive(Debug, PartialEq)]
pub struct NetworkProvider {
    pub config: ChainConfig,
}

impl NetworkProvider {
    pub fn get_bip49(&self, index: usize) -> DerivationPath {
        DerivationPath::new(self.config.slip_44, index)
    }
}

impl Provider for NetworkProvider {
    fn load_network_configs(storage: Arc<LocalStorage>) -> Vec<Self> {
        let bytes = storage.get(NETWORK_DB_KEY_V1).unwrap_or_default();

        if bytes.is_empty() {
            return Vec::with_capacity(1);
        }

        let configs: Vec<ChainConfig> =
            bincode::deserialize(&bytes).unwrap_or(Vec::with_capacity(1));
        let mut providers = Vec::with_capacity(configs.len());

        for config in configs.iter() {
            providers.push(NetworkProvider::new(config.to_owned()));
        }

        providers
    }

    fn save_network_configs(providers: &[Self], storage: Arc<LocalStorage>) -> Result<()> {
        let as_vec: Vec<_> = providers.iter().map(|v| &v.config).collect();
        let bytes =
            bincode::serialize(&as_vec).map_err(|e| NetworkErrors::RPCError(e.to_string()))?;

        storage.set(NETWORK_DB_KEY_V1, &bytes)?;
        storage.flush()?;

        Ok(())
    }
}

impl NetworkProvider {
    pub fn new(config: ChainConfig) -> Self {
        Self { config }
    }

    pub async fn proxy_req(&self, payload_str: String) -> Result<Value> {
        let payload =
            serde_json::from_str(&payload_str).map_err(|e| RpcError::InvalidJson(e.to_string()))?;
        let provider: RpcProvider<ChainConfig> = RpcProvider::new(&self.config);

        let response = provider
            .req::<Value>(payload)
            .await
            .map_err(NetworkErrors::Request)?;

        Ok(response)
    }

    pub async fn get_current_block_number(&self) -> Result<u64> {
        match self.config.slip_44 {
            slip44::ETHEREUM | slip44::ZILLIQA => self.evm_get_current_block_number().await,
            slip44::BITCOIN => self.btc_get_current_block_number().await,
            _ => Err(NetworkErrors::RPCError(format!(
                "Unsupported network: {}",
                self.config.name
            ))),
        }
    }

    pub async fn estimate_block_time(&self, address: &Address) -> Result<u64> {
        match self.config.slip_44 {
            slip44::ETHEREUM | slip44::ZILLIQA => self.evm_estimate_block_time(address).await,
            slip44::BITCOIN => self.btc_estimate_block_time().await,
            _ => Err(NetworkErrors::RPCError(format!(
                "Unsupported network: {}",
                self.config.name
            ))),
        }
    }

    pub async fn update_transactions_receipt(
        &self,
        txns: &mut [&mut HistoricalTransaction],
    ) -> Result<()> {
        match self.config.slip_44 {
            slip44::ETHEREUM | slip44::ZILLIQA => self.evm_update_transactions_receipt(txns).await,
            slip44::BITCOIN => self.btc_update_transactions_receipt(txns).await,
            _ => Err(NetworkErrors::RPCError(format!(
                "Unsupported network: {}",
                self.config.name
            ))),
        }
    }

    pub async fn estimate_params_batch(
        &self,
        tx: &TransactionRequest,
        sender: &Address,
        block_count: u64,
        percentiles: Option<&[f64]>,
    ) -> Result<RequiredTxParams> {
        match self.config.slip_44 {
            slip44::ETHEREUM | slip44::ZILLIQA => {
                self.evm_estimate_params_batch(tx, sender, block_count, percentiles)
                    .await
            }
            slip44::BITCOIN => {
                self.btc_estimate_params_batch(tx, sender, block_count, percentiles)
                    .await
            }
            _ => Err(NetworkErrors::RPCError(format!(
                "Unsupported network: {}",
                self.config.slip_44
            ))),
        }
    }

    pub async fn estimate_gas(&self, tx: &TransactionRequest) -> Result<U256> {
        match self.config.slip_44 {
            slip44::ETHEREUM | slip44::ZILLIQA => self.evm_estimate_gas(tx).await,
            slip44::BITCOIN => self.btc_estimate_gas(tx).await,
            _ => Err(NetworkErrors::RPCError(format!(
                "Unsupported network: {}",
                self.config.slip_44
            ))),
        }
    }

    pub async fn broadcast_signed_transactions(
        &self,
        txns: Vec<TransactionReceipt>,
    ) -> Result<Vec<TransactionReceipt>> {
        match self.config.slip_44 {
            slip44::ETHEREUM | slip44::ZILLIQA => {
                self.evm_broadcast_signed_transactions(txns).await
            }
            slip44::BITCOIN => self.btc_broadcast_signed_transactions(txns).await,
            _ => Err(NetworkErrors::RPCError(format!(
                "Unsupported network: {}",
                self.config.name
            ))),
        }
    }

    pub async fn fetch_nonce(&self, addresses: &[&Address]) -> Result<Vec<u64>> {
        match self.config.slip_44 {
            slip44::ETHEREUM | slip44::ZILLIQA => self.evm_fetch_nonce(addresses).await,
            slip44::BITCOIN => self.btc_fetch_nonce(addresses).await,
            _ => Err(NetworkErrors::RPCError(format!(
                "Unsupported network: {}",
                self.config.slip_44
            ))),
        }
    }

    pub async fn update_balances(
        &self,
        tokens: Vec<&mut FToken>,
        accounts: &[&Address],
    ) -> Result<()> {
        match self.config.slip_44 {
            slip44::ETHEREUM | slip44::ZILLIQA => self.evm_update_balances(tokens, accounts).await,
            slip44::BITCOIN => self.btc_update_balances(tokens, accounts).await,
            _ => Err(NetworkErrors::RPCError(format!(
                "Unsupported network: {}",
                self.config.name
            ))),
        }
    }

    pub async fn ftoken_meta(&self, contract: Address, accounts: &[&Address]) -> Result<FToken> {
        match self.config.slip_44 {
            slip44::ETHEREUM | slip44::ZILLIQA => self.evm_ftoken_meta(contract, accounts).await,
            slip44::BITCOIN => self.btc_ftoken_meta(contract, accounts).await,
            _ => Err(NetworkErrors::RPCError(format!(
                "Unsupported network: {}",
                self.config.name
            ))),
        }
    }

    #[inline]
    pub(crate) fn parse_str_to_u256(value: &str) -> Option<U256> {
        if value.starts_with("0x") {
            U256::from_str_radix(value.trim_start_matches("0x"), 16).ok()
        } else {
            U256::from_str_radix(value, 10).ok()
        }
    }
}

#[cfg(test)]
mod tests_network {
    use crate::evm::generate_erc20_transfer_data;

    use super::*;
    use alloy::{
        primitives::{map::HashMap, U256},
        rpc::types::TransactionInput,
    };
    use config::address::ADDR_LEN;
    use history::status::TransactionStatus;
    use proto::{tx::ETHTransactionRequest, zil_tx::ZILTransactionRequest};
    use rand::Rng;
    use test_data::{
        gen_anvil_net_conf, gen_bsc_testnet_conf, gen_eth_mainnet_conf, gen_zil_testnet_conf,
    };
    use tokio;

    fn setup_temp_storage() -> Arc<LocalStorage> {
        let mut rng = rand::thread_rng();
        let dir = format!("/tmp/{}", rng.gen::<usize>());

        let storage = LocalStorage::from(&dir).unwrap();
        Arc::new(storage)
    }

    fn create_mainnet_zilliqa_config() -> ChainConfig {
        ChainConfig {
            ftokens: vec![],
            logo: String::new(),
            diff_block_time: 0,
            testnet: None,
            chain_ids: [1, 1],
            name: "Zilliqa".to_string(),
            chain: "ZIL".to_string(),
            short_name: String::new(),
            rpc: vec![
                "https://api.zilliqa.com".to_string(),
                "https://ssn.zilpay.io".to_string(),
            ],
            features: vec![],
            slip_44: 313,
            ens: None,
            explorers: vec![],
            fallback_enabled: true,
        }
    }

    #[tokio::test]
    async fn test_get_ftoken_meta_bsc() {
        let net_conf = gen_bsc_testnet_conf();
        let provider = NetworkProvider::new(net_conf);

        let token_addr =
            Address::from_eth_address("0xFa60D973F7642B748046464e165A65B7323b0DEE").unwrap();
        let account = [
            &Address::from_eth_address("0x55d398326f99059fF775485246999027B3197955").unwrap(),
            &Address::Secp256k1Keccak256([0u8; ADDR_LEN]),
        ];
        let ftoken = provider.ftoken_meta(token_addr, &account).await.unwrap();

        assert!(*ftoken.balances.get(&0).unwrap() > U256::from(0));
        assert!(*ftoken.balances.get(&1).unwrap() == U256::from(0));

        assert_eq!(&ftoken.name, "PancakeSwap Token");
        assert_eq!(&ftoken.symbol, "Cake");
        assert_eq!(ftoken.decimals, 18u8);
    }

    #[tokio::test]
    async fn test_get_ftoken_meta_zil_legacy() {
        let net_conf = create_mainnet_zilliqa_config();
        let provider = NetworkProvider::new(net_conf);

        let token_addr =
            Address::from_zil_bech32("zil1l0g8u6f9g0fsvjuu74ctyla2hltefrdyt7k5f4").unwrap();
        let account = [
            &Address::from_zil_bech32("zil1gkwt95a67lnpe774lcmz72y6ay4jh2asmmjw6u").unwrap(),
            &Address::Secp256k1Sha256([0u8; ADDR_LEN]),
        ];
        let ftoken = provider.ftoken_meta(token_addr, &account).await.unwrap();

        assert!(*ftoken.balances.get(&0).unwrap() > U256::from(0));
        assert!(*ftoken.balances.get(&1).unwrap() == U256::from(0));

        assert_eq!(&ftoken.name, "ZilPay wallet");
        assert_eq!(&ftoken.symbol, "ZLP");
        assert_eq!(ftoken.decimals, 18u8);
    }

    #[tokio::test]
    async fn test_update_balance_scilla() {
        let net_conf = create_mainnet_zilliqa_config();
        let provider = NetworkProvider::new(net_conf);
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
                chain_hash: 0,
                rate: 0f64,
            },
            FToken {
                rate: 0f64,
                name: "Zilliqa-bridged USDT token".to_string(),
                symbol: "zUSDT".to_string(),
                decimals: 6,
                addr: Address::from_zil_bech32("zil1sxx29cshups269ahh5qjffyr58mxjv9ft78jqy")
                    .unwrap(),
                native: false,
                logo: None,
                default: false,
                balances: HashMap::new(),
                chain_hash: 0,
            },
            FToken {
                rate: 0f64,
                name: "Zilliqa-bridged ETH token".to_string(),
                symbol: "zETH".to_string(),
                decimals: 18,
                addr: Address::from_zil_bech32("zil19j33tapjje2xzng7svslnsjjjgge930jx0w09v")
                    .unwrap(),
                native: false,
                logo: None,
                default: false,
                balances: HashMap::new(),
                chain_hash: 0,
            },
        ];
        let accounts = [
            &Address::from_zil_bech32("zil1xr07v36qa4zeagg4k5tm6ummht0jrwpcu0n55d").unwrap(),
            &Address::from_zil_bech32("zil1wl38cwww2u3g8wzgutxlxtxwwc0rf7jf27zace").unwrap(),
            &Address::from_zil_bech32("zil1uxfzk4n9ef2t3f4c4939ludlvp349uwqdx32xt").unwrap(),
        ];
        let tokens_refs: Vec<&mut FToken> = tokens.iter_mut().collect();

        provider
            .update_balances(tokens_refs, &accounts)
            .await
            .unwrap();

        assert!(*tokens[0].balances.get(&0).unwrap() > U256::from(0));
        assert!(*tokens[0].balances.get(&1).unwrap() > U256::from(0));
        assert!(*tokens[0].balances.get(&2).unwrap() > U256::from(0));

        assert!(*tokens[1].balances.get(&0).unwrap() > U256::from(0));
        assert!(*tokens[1].balances.get(&1).unwrap() > U256::from(0));
        assert!(*tokens[1].balances.get(&2).unwrap() == U256::from(0));

        assert!(*tokens[2].balances.get(&0).unwrap() > U256::from(0));
        assert!(*tokens[2].balances.get(&2).unwrap() == U256::from(0));

        assert!(*tokens[3].balances.get(&0).unwrap() == U256::from(0));
        assert!(*tokens[3].balances.get(&1).unwrap() == U256::from(0));
        assert!(*tokens[3].balances.get(&2).unwrap() == U256::from(0));
    }

    #[test]
    fn test_empty_storage() {
        let storage = setup_temp_storage();
        let providers = NetworkProvider::load_network_configs(storage);
        assert!(providers.is_empty());
    }

    #[test]
    fn test_save_and_load_single_network() {
        let storage = setup_temp_storage();
        let config = gen_zil_testnet_conf();
        let providers = vec![NetworkProvider::new(config)];

        NetworkProvider::save_network_configs(&providers, Arc::clone(&storage)).unwrap();

        let loaded_providers = NetworkProvider::load_network_configs(Arc::clone(&storage));

        assert_eq!(providers.len(), loaded_providers.len());
        assert!(loaded_providers
            .iter()
            .any(|p| p.config.name == "Zilliqa(testnet)"));
        assert!(loaded_providers.iter().any(|p| p.config.chain_id() == 333));
    }

    #[test]
    fn test_save_and_load_multiple_networks() {
        let storage = setup_temp_storage();

        let base_config = gen_zil_testnet_conf();
        let configs = [
            ChainConfig {
                name: "Test Network 1".to_string(),
                chain_ids: [1, 0],
                ..base_config.clone()
            },
            ChainConfig {
                name: "Test Network 2".to_string(),
                chain_ids: [2, 0],
                ..base_config.clone()
            },
            ChainConfig {
                name: "Test Network 3".to_string(),
                chain_ids: [3, 0],
                ..base_config.clone()
            },
        ];

        let providers: Vec<NetworkProvider> = configs
            .iter()
            .map(|conf| NetworkProvider::new(conf.clone()))
            .collect();

        NetworkProvider::save_network_configs(&providers, Arc::clone(&storage)).unwrap();

        let loaded_providers = NetworkProvider::load_network_configs(Arc::clone(&storage));

        assert_eq!(providers.len(), loaded_providers.len());
        assert_eq!(loaded_providers.len(), 3);

        for provider in &loaded_providers {
            assert!(providers.contains(provider));
        }
    }

    #[test]
    fn test_update_networks() {
        let storage = setup_temp_storage();
        let base_config = gen_zil_testnet_conf();

        let mut providers = vec![NetworkProvider::new(ChainConfig {
            name: "Initial Network".to_string(),
            chain_ids: [1, 0],
            ..base_config.clone()
        })];

        NetworkProvider::save_network_configs(&providers, Arc::clone(&storage)).unwrap();

        providers.push(NetworkProvider::new(ChainConfig {
            name: "New Network".to_string(),
            chain_ids: [2, 0],
            ..base_config.clone()
        }));

        NetworkProvider::save_network_configs(&providers, Arc::clone(&storage)).unwrap();

        let loaded_providers = NetworkProvider::load_network_configs(Arc::clone(&storage));
        assert_eq!(loaded_providers.len(), 2);
        assert!(loaded_providers
            .iter()
            .any(|p| p.config.name == "Initial Network"));
        assert!(loaded_providers
            .iter()
            .any(|p| p.config.name == "New Network"));
    }

    #[tokio::test]
    async fn test_get_nonce_anvil() {
        let net_conf = gen_anvil_net_conf();
        let provider = NetworkProvider::new(net_conf);

        let account = [
            &Address::from_eth_address("0x2d09c57cB8EAf970dEEaf30546ec4dc3781c63cf").unwrap(),
            &Address::from_eth_address("0xBE0eB53F46cd790Cd13851d5EFf43D12404d33E8").unwrap(),
            &Address::Secp256k1Keccak256([0u8; ADDR_LEN]),
        ];

        let nonces = provider.fetch_nonce(&account).await.unwrap();

        assert!(nonces.first().unwrap() >= &0);
        assert!(nonces.get(1).unwrap() >= &0);
        assert!(nonces.last().unwrap() == &0);
    }

    #[tokio::test]
    async fn test_get_nonce_scilla() {
        let net_conf = create_mainnet_zilliqa_config();
        let provider = NetworkProvider::new(net_conf);

        let account = [
            &Address::from_zil_bech32("zil1xjj35ymsvf9ajqhprwh6pkvejm2lm2e9y4q4ev").unwrap(),
            &Address::from_zil_bech32("zil170u0aar9fjgu3hfma00wgk6axjl29l6hhnm2ua").unwrap(),
            &Address::Secp256k1Sha256([0u8; ADDR_LEN]),
        ];

        let nonces = provider.fetch_nonce(&account).await.unwrap();

        assert!(nonces.first().unwrap() >= &0);
        assert!(nonces.get(1).unwrap() >= &0);
        assert!(nonces.last().unwrap() == &12);
    }

    #[tokio::test]
    async fn test_estimate_gas_payment_anvil() {
        let net_conf = gen_anvil_net_conf();
        let provider = NetworkProvider::new(net_conf);

        let recipient =
            Address::from_eth_address("0x246C5881E3F109B2aF170F5C773EF969d3da581B").unwrap();
        let payment_request = ETHTransactionRequest {
            to: Some(recipient.to_alloy_addr().into()),
            value: Some(U256::from(10u128)),
            max_fee_per_gas: Some(2_000_000_000),
            max_priority_fee_per_gas: Some(1_000_000_000),
            nonce: Some(0),
            gas: None,
            chain_id: Some(provider.config.chain_id()),
            ..Default::default()
        };
        let tx_request = TransactionRequest::Ethereum((payment_request, Default::default()));
        let estimated_gas = provider.estimate_gas(&tx_request).await.unwrap();

        assert_eq!("21000", estimated_gas.to_string());
    }

    #[tokio::test]
    async fn test_estimate_gas_token_transfer() {
        let net_conf = gen_bsc_testnet_conf();
        let provider = NetworkProvider::new(net_conf);

        let token_address =
            Address::from_eth_address("0x524bC91Dc82d6b90EF29F76A3ECAaBAffFD490Bc").unwrap();
        let recipient =
            Address::from_eth_address("0x246C5881E3F109B2aF170F5C773EF969d3da581B").unwrap();
        let from = Address::from_eth_address("0x451806FE45D9231eb1db3584494366edF05CB4AB").unwrap();
        let amount = U256::from(100u64);
        let transfer_data = generate_erc20_transfer_data(&recipient, amount).unwrap();
        let token_transfer_request = ETHTransactionRequest {
            from: Some(from.to_alloy_addr().into()),
            to: Some(token_address.to_alloy_addr().into()),
            value: Some(U256::ZERO),
            max_fee_per_gas: Some(2_000_000_000),
            max_priority_fee_per_gas: Some(1_000_000_000),
            nonce: Some(0),
            gas: None,
            chain_id: Some(provider.config.chain_id()),
            input: TransactionInput::new(transfer_data.into()),
            ..Default::default()
        };

        let tx_request = TransactionRequest::Ethereum((token_transfer_request, Default::default()));
        let estimated_gas = provider.estimate_gas(&tx_request).await.unwrap();

        assert!(estimated_gas > U256::from(0));
    }

    #[tokio::test]
    async fn test_calc_fee_eth_batch() {
        let net_conf = gen_eth_mainnet_conf();
        let provider = NetworkProvider::new(net_conf);
        let token_address =
            Address::from_eth_address("0x524bC91Dc82d6b90EF29F76A3ECAaBAffFD490Bc").unwrap();
        let recipient =
            Address::from_eth_address("0x246C5881E3F109B2aF170F5C773EF969d3da581B").unwrap();
        let from = Address::from_eth_address("0x451806FE45D9231eb1db3584494366edF05CB4AB").unwrap();
        let amount = U256::from(100u64);
        let transfer_data = generate_erc20_transfer_data(&recipient, amount).unwrap();
        let token_transfer_request = ETHTransactionRequest {
            from: Some(from.to_alloy_addr().into()),
            to: Some(token_address.to_alloy_addr().into()),
            value: Some(U256::ZERO),
            max_fee_per_gas: Some(2_000_000_000),
            max_priority_fee_per_gas: Some(1_000_000_000),
            nonce: Some(0),
            gas: None,
            chain_id: Some(provider.config.chain_id()),
            input: TransactionInput::new(transfer_data.into()),
            ..Default::default()
        };
        let tx_request = TransactionRequest::Ethereum((token_transfer_request, Default::default()));

        let fee = provider
            .estimate_params_batch(&tx_request, &from, 4, None)
            .await
            .unwrap();

        assert_ne!(fee.gas_price, U256::from(0));
        assert_ne!(fee.max_priority_fee, U256::from(0));
        assert_ne!(fee.tx_estimate_gas, U256::from(0));
        assert_ne!(fee.blob_base_fee, U256::from(0));
        assert_ne!(fee.fee_history.max_fee, U256::from(0));
        assert_ne!(fee.fee_history.priority_fee, U256::from(0));
    }

    #[tokio::test]
    async fn test_get_tx_params_payment() {
        let net_conf = gen_eth_mainnet_conf();
        let provider = NetworkProvider::new(net_conf);
        let recipient =
            Address::from_eth_address("0x451806FE45D9231eb1db3584494366edF05CB4AB").unwrap();
        let from = Address::from_eth_address("0x451806FE45D9231eb1db3584494366edF05CB4AB").unwrap();
        let amount = U256::from(100u64);
        let token_transfer_request = ETHTransactionRequest {
            from: Some(from.to_alloy_addr().into()),
            to: Some(recipient.to_alloy_addr().into()),
            value: Some(amount),
            chain_id: Some(provider.config.chain_id()),
            gas: None,
            nonce: None,
            transaction_type: Some(0x02),
            input: TransactionInput::default(),
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
            gas_price: None,
            max_fee_per_blob_gas: None,
            blob_versioned_hashes: None,
            sidecar: None,
            access_list: None,
            authorization_list: None,
        };
        let tx_request = TransactionRequest::Ethereum((token_transfer_request, Default::default()));

        let fee = provider
            .estimate_params_batch(&tx_request, &from, 4, None)
            .await
            .unwrap();

        assert_ne!(fee.gas_price, U256::from(0));
        assert_ne!(fee.max_priority_fee, U256::from(0));
        assert_eq!(fee.tx_estimate_gas, U256::from(21000));
        assert_ne!(fee.blob_base_fee, U256::from(0));
        assert_ne!(fee.fee_history.max_fee, U256::from(0));
        assert_ne!(fee.fee_history.priority_fee, U256::from(0));

        let block_diff_time = provider.estimate_block_time(&recipient).await.unwrap();
        assert!(block_diff_time > 10 && block_diff_time < 18);
    }

    #[tokio::test]
    async fn test_calc_fee_bsc_batch() {
        let net_conf = gen_bsc_testnet_conf();
        let provider = NetworkProvider::new(net_conf);
        let recipient =
            Address::from_eth_address("0x246C5881E3F109B2aF170F5C773EF969d3da581B").unwrap();
        let from = Address::from_eth_address("0x7b501c7944185130DD4aD73293e8Aa84eFfDcee7").unwrap();
        let token_transfer_request = ETHTransactionRequest {
            from: Some(from.to_alloy_addr().into()),
            to: Some(recipient.to_alloy_addr().into()),
            value: Some(U256::ZERO),
            max_fee_per_gas: Some(2_000_000_000),
            max_priority_fee_per_gas: Some(1_000_000_000),
            nonce: Some(0),
            gas: None,
            chain_id: Some(provider.config.chain_id()),
            ..Default::default()
        };
        let tx_request = TransactionRequest::Ethereum((token_transfer_request, Default::default()));

        let fee = provider
            .estimate_params_batch(&tx_request, &from, 4, None)
            .await
            .unwrap();

        assert_ne!(fee.gas_price, U256::from(0));

        let block_diff_time = provider.estimate_block_time(&recipient).await.unwrap();
        assert!(block_diff_time >= 1 && block_diff_time < 5);
    }

    #[tokio::test]
    async fn test_get_tx_prams_scilla() {
        let net_conf = create_mainnet_zilliqa_config();
        let provider = NetworkProvider::new(net_conf);

        let to = Address::from_zil_bech32("zil1xjj35ymsvf9ajqhprwh6pkvejm2lm2e9y4q4ev").unwrap();
        let from = Address::from_zil_bech32("zil170u0aar9fjgu3hfma00wgk6axjl29l6hhnm2ua").unwrap();
        let zil_tx = ZILTransactionRequest {
            chain_id: provider.config.chain_id() as u16,
            nonce: 1,
            gas_price: 2000 * 10u128.pow(6),
            gas_limit: 100000,
            to_addr: to,
            amount: 10u128.pow(12),
            code: Vec::with_capacity(0),
            data: Vec::with_capacity(0),
        };
        let tx_req = TransactionRequest::Zilliqa((zil_tx, Default::default()));
        let params = provider
            .estimate_params_batch(&tx_req, &from, 4, None)
            .await
            .unwrap();

        assert_eq!(params.gas_price, U256::from(2000000016));
        assert!(params.nonce > 74310);

        let block_diff_time = provider.estimate_block_time(&from).await.unwrap();
        assert!(block_diff_time > 1 && block_diff_time < 18);
    }

    #[tokio::test]
    async fn test_tx_receipt_evm() {
        let net_conf = gen_eth_mainnet_conf();
        let provider = NetworkProvider::new(net_conf);
        let tx_hash = "0xbee2eb00d77c45be11e037efe8459ae5b61f36af1483d705ee89e9d40a1f3715";
        let mut tx_history = HistoricalTransaction {
            metadata: proto::tx::TransactionMetadata {
                chain_hash: provider.config.hash(),
                hash: Some(tx_hash.to_string()),
                ..Default::default()
            },
            evm: Some(
                serde_json::json!({
                    "transactionHash": tx_hash,
                })
                .to_string(),
            ),
            ..Default::default()
        };
        let mut list_txns = vec![&mut tx_history];

        provider
            .update_transactions_receipt(&mut list_txns)
            .await
            .unwrap();

        let evm = list_txns.first().unwrap().get_evm().unwrap();
        let gas_used = evm
            .get("gasUsed")
            .and_then(|v| v.as_str())
            .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok());
        assert_eq!(gas_used, Some(21000));
        let block_number = evm
            .get("blockNumber")
            .and_then(|v| v.as_str())
            .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok());
        assert_eq!(block_number, Some(21855983));
        assert_eq!(
            evm.get("transactionHash").and_then(|v| v.as_str()),
            Some(tx_hash)
        );
        assert_eq!(
            list_txns.first().unwrap().status,
            TransactionStatus::Success
        );
    }

    #[tokio::test]
    async fn test_tx_receipt_scilla() {
        let net_conf = create_mainnet_zilliqa_config();
        let provider = NetworkProvider::new(net_conf);
        let tx_hash = "0x1d8cc783b73c2771e52ee3b6744c3a2a48b63cdfb160549f91523ce30baf8854";
        let mut tx_history = HistoricalTransaction {
            metadata: proto::tx::TransactionMetadata {
                chain_hash: provider.config.hash(),
                hash: Some(tx_hash.to_string()),
                ..Default::default()
            },
            scilla: Some(
                serde_json::json!({
                    "hash": tx_hash,
                })
                .to_string(),
            ),
            ..Default::default()
        };
        let mut list_txns = vec![&mut tx_history];

        provider
            .update_transactions_receipt(&mut list_txns)
            .await
            .unwrap();

        let scilla = list_txns[0].get_scilla().unwrap();
        assert_eq!(scilla.get("amount").and_then(|v| v.as_str()), Some("0"));
        assert_eq!(list_txns[0].status, TransactionStatus::Success);
        assert_eq!(
            scilla.get("gasLimit").and_then(|v| v.as_str()),
            Some("5000")
        );
        assert_eq!(
            scilla.get("gasPrice").and_then(|v| v.as_str()),
            Some("2000000016")
        );
        assert_eq!(scilla.get("nonce").and_then(|v| v.as_str()), Some("1175"));
        assert!(list_txns[0].scilla.is_some());
    }

    #[tokio::test]
    async fn test_get_block_number_scilla() {
        let net_conf = gen_zil_testnet_conf();
        let provider = NetworkProvider::new(net_conf);

        let block_number = provider.get_current_block_number().await.unwrap();
        assert!(block_number != 0);
    }

    #[tokio::test]
    async fn test_get_block_number_anvil() {
        let net_conf = gen_anvil_net_conf();
        let provider = NetworkProvider::new(net_conf);

        let _block_number = provider.get_current_block_number().await.unwrap();
    }
}
