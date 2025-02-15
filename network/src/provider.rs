use std::collections::HashMap;
use std::sync::Arc;

use crate::block_parse::{build_last_block_header_request, process_get_timestampt_block_response};
use crate::common::Provider;
use crate::gas_parse::{
    build_batch_gas_request, build_fee_history_request, json_rpc_error,
    process_parse_fee_history_request, GasFeeHistory, RequiredTxParams, EIP1559, EIP4844,
    SCILLA_EIP,
};
use crate::nonce_parser::{build_nonce_request, process_nonce_response};
use crate::tx_parse::{
    build_payload_tx_receipt, build_send_signed_tx_request, process_tx_receipt_response,
    process_tx_send_response,
};
use crate::Result;
use alloy::primitives::U256;
use config::storage::NETWORK_DB_KEY;
use crypto::bip49::DerivationPath;
use errors::crypto::SignatureError;
use errors::network::NetworkErrors;
use errors::token::TokenError;
use errors::tx::TransactionErrors;
use history::transaction::HistoricalTransaction;
use proto::address::Address;
use proto::tx::{TransactionReceipt, TransactionRequest};
use rpc::common::JsonRPC;
use rpc::methods::{EvmMethods, ZilMethods};
use rpc::network_config::ChainConfig;
use rpc::provider::RpcProvider;
use rpc::zil_interfaces::ResultRes;
use serde_json::{json, Value};
use storage::LocalStorage;
use token::ft::FToken;
use token::ft_parse::{
    build_token_requests, process_eth_balance_response, process_eth_metadata_response,
    process_zil_balance_response, process_zil_metadata_response, MetadataField, RequestType,
};

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
        let bytes = storage.get(NETWORK_DB_KEY).unwrap_or_default();

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

        storage.set(NETWORK_DB_KEY, &bytes)?;
        storage.flush()?;

        Ok(())
    }
}

impl NetworkProvider {
    pub fn new(config: ChainConfig) -> Self {
        Self { config }
    }

    pub async fn estimate_block_time(&self, address: &Address) -> Result<u64> {
        let provider: RpcProvider<ChainConfig> = RpcProvider::new(&self.config);
        let payload = build_last_block_header_request(address, None);
        let response = provider
            .req::<Vec<ResultRes<Value>>>(&[payload])
            .await
            .map_err(NetworkErrors::Request)?;
        let (last_blocknumber, last_timestamp) = {
            let response = response.first().ok_or(NetworkErrors::ResponseParseError)?;

            process_get_timestampt_block_response(&response, address)
        };
        let payload = build_last_block_header_request(address, Some(last_blocknumber - 1));
        let response = provider
            .req::<Vec<ResultRes<Value>>>(&[payload])
            .await
            .map_err(NetworkErrors::Request)?;
        let (_, early_timestamp) = {
            let response = response.first().ok_or(NetworkErrors::ResponseParseError)?;

            process_get_timestampt_block_response(&response, address)
        };

        Ok(last_timestamp - early_timestamp)
    }

    pub async fn get_transactions_receipt(&self, txns: &mut [HistoricalTransaction]) -> Result<()> {
        let mut requests: Vec<Value> = Vec::with_capacity(txns.len());

        for tx in txns.iter() {
            requests.push(build_payload_tx_receipt(&tx));
        }

        let provider: RpcProvider<ChainConfig> = RpcProvider::new(&self.config);
        let responses = provider
            .req::<Vec<ResultRes<Value>>>(&requests)
            .await
            .map_err(NetworkErrors::Request)?;

        for (index, res) in responses.into_iter().enumerate() {
            // process_tx_receipt_response(res, &txns[index])?;
            if let Some(tx) = txns.get_mut(index) {
                process_tx_receipt_response(res, tx)?;
            }
        }

        Ok(())
    }

    pub async fn estimate_params_batch(
        &self,
        tx: &TransactionRequest,
        sender: &Address,
        block_count: u64,
        percentiles: Option<&[f64]>,
    ) -> Result<RequiredTxParams> {
        let default_percentiles = [25.0, 50.0, 75.0];
        let percentiles_to_use = percentiles.unwrap_or(&default_percentiles);
        let requests = build_batch_gas_request(
            tx,
            block_count,
            &percentiles_to_use,
            &self.config.features,
            sender,
        )?;

        let provider: RpcProvider<ChainConfig> = RpcProvider::new(&self.config);
        let response = provider
            .req::<Vec<ResultRes<Value>>>(&requests)
            .await
            .map_err(NetworkErrors::Request)?;

        let nonce = response
            .first()
            .and_then(|res| process_nonce_response(&res, sender).ok())
            .unwrap_or_default();

        let gas_price_response = response
            .get(1)
            .and_then(|res| res.result.as_ref())
            .and_then(|result| result.as_str())
            .and_then(|gas_str| Self::parse_str_to_u256(&gas_str))
            .unwrap_or_default();
        let tx_estimate_gas_response = response
            .get(2)
            .and_then(|res| res.result.as_ref())
            .and_then(|result| result.as_str())
            .and_then(|gas_str| Self::parse_str_to_u256(&gas_str))
            .unwrap_or_default();

        let (max_priority_fee_per_gas_response, fee_history_response) =
            if self.config.features.contains(&EIP1559) {
                let max_priority_fee_per_gas_response = response
                    .get(3)
                    .and_then(|res| res.result.as_ref())
                    .and_then(|result| result.as_str())
                    .and_then(|gas_str| Self::parse_str_to_u256(&gas_str))
                    .unwrap_or_default();

                let fee_history_response = response
                    .get(4)
                    .and_then(|res| res.result.as_ref())
                    .and_then(|result| process_parse_fee_history_request(result).ok())
                    .unwrap_or_default();

                (max_priority_fee_per_gas_response, fee_history_response)
            } else {
                (U256::ZERO, GasFeeHistory::default())
            };

        let blob_base_fee = if self.config.features.contains(&EIP4844) {
            response
                .first()
                .and_then(|res| res.result.as_ref())
                .and_then(|result| result.as_str())
                .and_then(|gas_str| Self::parse_str_to_u256(&gas_str))
                .unwrap_or_default()
        } else {
            U256::ZERO
        };

        Ok(RequiredTxParams {
            blob_base_fee,
            nonce,
            max_priority_fee: max_priority_fee_per_gas_response,
            gas_price: gas_price_response,
            fee_history: fee_history_response,
            tx_estimate_gas: tx_estimate_gas_response,
        })
    }

    pub async fn get_fee_history(
        &self,
        block_count: u64,
        percentiles: Option<&[f64]>,
    ) -> Result<GasFeeHistory> {
        if !self.config.features.contains(&EIP1559) {
            return Err(NetworkErrors::EIPNotSupporting(EIP1559));
        }

        let default_percentiles = [25.0, 50.0, 75.0];
        let percentiles_to_use = percentiles.unwrap_or(&default_percentiles);
        let request = build_fee_history_request(block_count, percentiles_to_use);

        let provider: RpcProvider<ChainConfig> = RpcProvider::new(&self.config);
        let response = provider
            .req::<Vec<ResultRes<Value>>>(&[request])
            .await
            .map_err(NetworkErrors::Request)?;
        let response = response.first().ok_or(NetworkErrors::ResponseParseError)?;

        if let Some(error) = &response.error {
            json_rpc_error(error)?;
        }

        let result = response
            .result
            .as_ref()
            .ok_or(NetworkErrors::ResponseParseError)?;

        process_parse_fee_history_request(result)
    }

    pub async fn get_gas_price(&self) -> Result<U256> {
        let request = if self.config.features.contains(&SCILLA_EIP) {
            RpcProvider::<ChainConfig>::build_payload(json!([]), ZilMethods::GetMinimumGasPrice)
        } else if self.config.features.contains(&EIP1559) {
            RpcProvider::<ChainConfig>::build_payload(json!([]), EvmMethods::MaxPriorityFeePerGas)
        } else {
            RpcProvider::<ChainConfig>::build_payload(json!([]), EvmMethods::GasPrice)
        };

        let provider: RpcProvider<ChainConfig> = RpcProvider::new(&self.config);
        let response = provider
            .req::<Vec<ResultRes<String>>>(&[request])
            .await
            .map_err(NetworkErrors::Request)?;
        let response = response.first().ok_or(NetworkErrors::ResponseParseError)?;

        if let Some(error) = &response.error {
            json_rpc_error(error)?;
        }

        let price_str = response
            .result
            .as_ref()
            .ok_or(NetworkErrors::ResponseParseError)?;

        U256::from_str_radix(price_str.trim_start_matches("0x"), 16)
            .map_err(|_| NetworkErrors::ResponseParseError)
    }

    pub async fn estimate_gas(&self, tx: &TransactionRequest) -> Result<U256> {
        match tx {
            TransactionRequest::Ethereum((tx, _metadata)) => {
                let tx_object = serde_json::to_value(&tx)
                    .map_err(|e| TransactionErrors::ConvertTxError(e.to_string()))?;

                let request = RpcProvider::<ChainConfig>::build_payload(
                    json!([tx_object]),
                    EvmMethods::EstimateGas,
                );

                let provider: RpcProvider<ChainConfig> = RpcProvider::new(&self.config);
                let response = provider
                    .req::<Vec<ResultRes<String>>>(&[request])
                    .await
                    .map_err(NetworkErrors::Request)?;
                let response = response.first().ok_or(NetworkErrors::ResponseParseError)?;

                if let Some(error) = &response.error {
                    json_rpc_error(error)?;
                }

                let gas_str = response
                    .result
                    .as_ref()
                    .ok_or(NetworkErrors::ResponseParseError)?;

                U256::from_str_radix(gas_str.trim_start_matches("0x"), 16)
                    .map_err(|_| NetworkErrors::ResponseParseError)
            }
            TransactionRequest::Zilliqa(_) => Err(NetworkErrors::RPCError(
                "Zilliqa network doesn't support gas estimation".to_string(),
            )),
        }
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

            all_requests.push(build_send_signed_tx_request(tx));
        }

        let provider: RpcProvider<ChainConfig> = RpcProvider::new(&self.config);
        let responses = provider.req::<Vec<ResultRes<Value>>>(&all_requests).await?;
        drop(all_requests);

        for (tx, response) in txns.iter_mut().zip(responses.iter()) {
            process_tx_send_response(response, tx)?;
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

        let provider: RpcProvider<ChainConfig> = RpcProvider::new(&self.config);
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
            Address::Secp256k1Sha256(_) => acc + accounts.len(),
            Address::Secp256k1Keccak256(_) => acc + accounts.len(),
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

        let provider: RpcProvider<ChainConfig> = RpcProvider::new(&self.config);
        let responses = provider
            .req::<Vec<ResultRes<Value>>>(&all_requests)
            .await
            .map_err(NetworkErrors::Request)?;

        for ((token_idx, account), response) in request_mapping.iter().zip(responses.iter()) {
            match tokens[*token_idx].addr {
                Address::Secp256k1Sha256(_) => {
                    let balance =
                        process_zil_balance_response(response, account, tokens[*token_idx].native);

                    if let Some(account_index) = accounts.iter().position(|&addr| addr == *account)
                    {
                        tokens[*token_idx]
                            .balances
                            .insert(account_index, U256::from(balance));
                    }
                }
                Address::Secp256k1Keccak256(_) => {
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
        let provider: RpcProvider<ChainConfig> = RpcProvider::new(&self.config);
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
            Address::Secp256k1Sha256(_) => {
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
                            balances.insert(account_index, U256::from(balance));
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
                    chain_hash: self.config.hash(),
                })
            }
            Address::Secp256k1Keccak256(_) => {
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
                    chain_hash: self.config.hash(),
                })
            }
        }
    }

    #[inline]
    fn parse_str_to_u256(value: &str) -> Option<U256> {
        if value.starts_with("0x") {
            U256::from_str_radix(value.trim_start_matches("0x"), 16).ok()
        } else {
            U256::from_str_radix(value, 10).ok()
        }
    }
}

#[cfg(test)]
mod tests_network {
    use super::*;
    use alloy::{primitives::U256, rpc::types::TransactionInput};
    use config::address::ADDR_LEN;
    use proto::{tx::ETHTransactionRequest, zil_tx::ZILTransactionRequest};
    use rand::Rng;
    use rpc::network_config::Explorer;
    use token::ft_parse::generate_erc20_transfer_data;
    use tokio;

    fn setup_temp_storage() -> Arc<LocalStorage> {
        let mut rng = rand::thread_rng();
        let dir = format!("/tmp/{}", rng.gen::<usize>());

        let storage = LocalStorage::from(&dir).unwrap();
        Arc::new(storage)
    }

    fn create_bsc_config() -> ChainConfig {
        ChainConfig {
            diff_block_time: 0,
            testnet: None,
            chain_ids: [56, 0],
            name: "Binance-smart-chain".to_string(),
            chain: "BSC".to_string(),
            short_name: String::new(),
            rpc: vec!["https://bsc-dataseed.binance.org".to_string()],
            features: vec![155],
            slip_44: 60,
            ens: None,
            explorers: vec![Explorer {
                name: "BscScan".to_string(),
                url: "https://bscscan.com".to_string(),
                icon: None,
                standard: 3091,
            }],
            fallback_enabled: true,
        }
    }

    fn create_zilliqa_config() -> ChainConfig {
        ChainConfig {
            diff_block_time: 0,
            testnet: None,
            chain_ids: [1, 0],
            name: "Zilliqa".to_string(),
            chain: "ZIL".to_string(),
            short_name: String::new(),
            rpc: vec!["https://api.zilliqa.com".to_string()],
            features: vec![SCILLA_EIP],
            slip_44: 313,
            ens: None,
            explorers: vec![],
            fallback_enabled: true,
        }
    }

    #[tokio::test]
    async fn test_get_ftoken_meta_bsc() {
        let net_conf = create_bsc_config();
        let provider = NetworkProvider::new(net_conf);

        let token_addr =
            Address::from_eth_address("0x55d398326f99059fF775485246999027B3197955").unwrap();
        let account = [
            &Address::from_eth_address("0x55d398326f99059fF775485246999027B3197955").unwrap(),
            &Address::Secp256k1Keccak256([0u8; ADDR_LEN]),
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
        let net_conf = create_zilliqa_config();
        let provider = NetworkProvider::new(net_conf);

        let token_addr =
            Address::from_zil_bech32("zil1sxx29cshups269ahh5qjffyr58mxjv9ft78jqy").unwrap();
        let account = [
            &Address::from_zil_bech32("zil1gkwt95a67lnpe774lcmz72y6ay4jh2asmmjw6u").unwrap(),
            &Address::Secp256k1Sha256([0u8; ADDR_LEN]),
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
        let net_conf = create_zilliqa_config();
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
                chain_hash: 0,
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
                chain_hash: 0,
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
        let config = create_zilliqa_config();
        let providers = vec![NetworkProvider::new(config)];

        NetworkProvider::save_network_configs(&providers, Arc::clone(&storage)).unwrap();

        let loaded_providers = NetworkProvider::load_network_configs(Arc::clone(&storage));

        assert_eq!(providers.len(), loaded_providers.len());
        assert!(loaded_providers.iter().any(|p| p.config.name == "Zilliqa"));
        assert!(loaded_providers.iter().any(|p| p.config.chain_id() == 1));
    }

    #[test]
    fn test_save_and_load_multiple_networks() {
        let storage = setup_temp_storage();

        let base_config = create_zilliqa_config();
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
        let base_config = create_zilliqa_config();

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
    async fn test_get_nonce_evm() {
        let net_conf = create_bsc_config();
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
        let net_conf = create_zilliqa_config();
        let provider = NetworkProvider::new(net_conf);

        let account = [
            &Address::from_zil_bech32("zil1xjj35ymsvf9ajqhprwh6pkvejm2lm2e9y4q4ev").unwrap(),
            &Address::from_zil_bech32("zil170u0aar9fjgu3hfma00wgk6axjl29l6hhnm2ua").unwrap(),
            &Address::Secp256k1Sha256([0u8; ADDR_LEN]),
        ];

        let nonces = provider.fetch_nonce(&account).await.unwrap();

        assert!(nonces.first().unwrap() >= &0);
        assert!(nonces.get(1).unwrap() >= &0);
        assert!(nonces.last().unwrap() == &0);
    }

    #[tokio::test]
    async fn test_get_gas_price() {
        let net_conf = create_bsc_config();
        let provider = NetworkProvider::new(net_conf);

        let gas_price = provider.get_gas_price().await.unwrap();

        assert_eq!("1000000000", gas_price.to_string());
    }

    #[tokio::test]
    async fn test_estimate_gas_payment() {
        let net_conf = create_bsc_config();
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
    async fn test_estimate_gas_token_transfer_error() {
        let net_conf = create_bsc_config();
        let provider = NetworkProvider::new(net_conf);

        let token_address =
            Address::from_eth_address("0x55d398326f99059fF775485246999027B3197955").unwrap();
        let recipient =
            Address::from_eth_address("0x246C5881E3F109B2aF170F5C773EF969d3da581B").unwrap();
        let amount = U256::from(1000000000000000000u64);
        let transfer_data = generate_erc20_transfer_data(&recipient, amount).unwrap();
        let token_transfer_request = ETHTransactionRequest {
            from: Some(recipient.to_alloy_addr().into()),
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
        let estimated_gas = provider.estimate_gas(&tx_request).await;

        assert_eq!(
            estimated_gas,
            Err(NetworkErrors::RPCError(
                "JSON-RPC error (code: -32000): insufficient funds for transfer".to_string()
            ))
        );
    }

    #[tokio::test]
    async fn test_estimate_gas_token_transfer() {
        let net_conf = create_bsc_config();
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
    async fn test_get_fee_history_eth() {
        let net_conf = ChainConfig {
            diff_block_time: 0,
            testnet: None,
            chain_ids: [56, 0],
            name: "Ethereum".to_string(),
            chain: "ETH".to_string(),
            short_name: String::new(),
            rpc: vec!["https://ethereum-rpc.publicnode.com".to_string()],
            features: vec![155, 1559, 4844],
            slip_44: 60,
            ens: None,
            explorers: vec![],
            fallback_enabled: true,
        };
        let provider = NetworkProvider::new(net_conf);

        let GasFeeHistory {
            max_fee,
            priority_fee,
            base_fee,
        } = provider.get_fee_history(4, None).await.unwrap();
        assert!(max_fee > U256::ZERO);
        assert!(priority_fee > U256::ZERO);
        assert!(base_fee > U256::ZERO);

        let custom_percentiles = [10.0, 50.0, 90.0];
        let fee2 = provider
            .get_fee_history(4, Some(&custom_percentiles))
            .await
            .unwrap();

        assert!(fee2.max_fee > U256::ZERO);
        assert!(fee2.priority_fee > U256::ZERO);
        assert!(max_fee > priority_fee);
        assert!(fee2.max_fee > fee2.priority_fee);

        let single_fee = provider.get_fee_history(1, None).await.unwrap();

        assert!(single_fee.max_fee > U256::ZERO);
        assert!(single_fee.priority_fee > U256::ZERO);

        println!("Default (4 blocks):");
        println!("  max_fee: {}", max_fee);
        println!("  priority_fee: {}", priority_fee);
        println!("\nCustom percentiles (4 blocks):");
        println!("  max_fee: {}", fee2.max_fee);
        println!("  priority_fee: {}", fee2.priority_fee);
        println!("\nSingle block:");
        println!("  max_fee: {}", single_fee.max_fee);
        println!("  priority_fee: {}", single_fee.priority_fee);
    }

    #[tokio::test]
    async fn test_calc_fee_eth_batch() {
        let net_conf = ChainConfig {
            diff_block_time: 0,
            testnet: None,
            chain_ids: [56, 0],
            name: "Ethereum".to_string(),
            chain: "ETH".to_string(),
            short_name: String::new(),
            rpc: vec!["https://ethereum-rpc.publicnode.com".to_string()],
            features: vec![155, 1559, 4844],
            slip_44: 60,
            ens: None,
            explorers: vec![],
            fallback_enabled: true,
        };
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
        let net_conf = ChainConfig {
            diff_block_time: 0,
            testnet: None,
            chain_ids: [1, 0],
            name: "Ethereum".to_string(),
            chain: "ETH".to_string(),
            short_name: String::new(),
            rpc: vec!["https://rpc.mevblocker.io".to_string()],
            features: vec![155, 1559, 4844],
            slip_44: 60,
            ens: None,
            explorers: vec![],
            fallback_enabled: true,
        };
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
        let net_conf = ChainConfig {
            diff_block_time: 0,
            testnet: None,
            chain_ids: [97, 0],
            name: "Smart chain Testnet".to_string(),
            chain: "BNB".to_string(),
            short_name: String::new(),
            rpc: vec!["https://data-seed-prebsc-1-s1.binance.org:8545/".to_string()],
            features: vec![155, 1559, 4844],
            slip_44: 60,
            ens: None,
            explorers: vec![],
            fallback_enabled: true,
        };
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
        assert_eq!(fee.nonce, 0);
        assert_ne!(fee.max_priority_fee, U256::from(0));
        assert_ne!(fee.tx_estimate_gas, U256::from(0));
        assert_ne!(fee.fee_history.max_fee, U256::from(0));
        assert_ne!(fee.fee_history.priority_fee, U256::from(0));

        let block_diff_time = provider.estimate_block_time(&recipient).await.unwrap();
        assert_eq!(block_diff_time, 3);
    }

    #[tokio::test]
    async fn test_get_tx_prams_scilla() {
        let net_conf = create_zilliqa_config();
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

        assert_eq!(params.gas_price, U256::from(2000000000));
        assert!(params.nonce > 66519);

        let block_diff_time = provider.estimate_block_time(&from).await.unwrap();
        assert!(block_diff_time > 30 && block_diff_time < 40);
    }

    #[tokio::test]
    async fn test_tx_receipt() {
        let net_conf = ChainConfig {
            diff_block_time: 0,
            testnet: None,
            chain_ids: [1, 0],
            name: "Ethereum".to_string(),
            chain: "ETH".to_string(),
            short_name: String::new(),
            rpc: vec!["https://rpc.mevblocker.io".to_string()],
            features: vec![155, 1559, 4844],
            slip_44: 60,
            ens: None,
            explorers: vec![],
            fallback_enabled: true,
        };
        let provider = NetworkProvider::new(net_conf);
        let tx_history = HistoricalTransaction {
            transaction_hash: String::from(
                "0x0e79c48a5a972a9fdadd0db0cbf9ff046f048da5ea2a456d8b97cfa212ce4eb3",
            ),
            ..Default::default()
        };
        let mut list_txns = vec![tx_history];

        provider
            .get_transactions_receipt(&mut list_txns)
            .await
            .unwrap();
    }
}
