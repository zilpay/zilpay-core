mod block_parse;
mod ft_parse;
mod gas_parse;
mod nonce_parser;
mod tx_parse;

pub use self::ft_parse::generate_erc20_transfer_data;
pub use self::gas_parse::{GasFeeHistory, RequiredTxParams};

use self::block_parse::{build_last_block_header_request, process_get_timestampt_block_response};
use self::ft_parse::{
    build_token_requests, process_eth_balance_response, process_eth_metadata_response,
    process_zil_balance_response, process_zil_metadata_response, MetadataField, RequestType,
};
use self::gas_parse::{
    build_batch_gas_request, process_parse_fee_history_request, EIP1559, EIP4844,
};
use self::nonce_parser::process_nonce_response;
use self::tx_parse::{
    build_payload_tx_receipt, build_send_signed_tx_request, process_tx_receipt_response,
    process_tx_send_response,
};
use crate::provider::NetworkProvider;
use crate::Result;
use alloy::primitives::U256;
use async_trait::async_trait;
use errors::crypto::SignatureError;
use errors::network::NetworkErrors;
use errors::token::TokenError;
use errors::tx::TransactionErrors;
use history::transaction::HistoricalTransaction;
use proto::address::Address;
use proto::tx::{TransactionReceipt, TransactionRequest};
use rpc::common::JsonRPC;
use rpc::methods::EvmMethods;
use rpc::network_config::ChainConfig;
use rpc::provider::RpcProvider;
use rpc::zil_interfaces::ResultRes;
use serde_json::{json, Value};
use std::collections::HashMap;
use token::ft::FToken;

#[async_trait]
pub trait EvmOperations {
    async fn evm_get_current_block_number(&self) -> Result<u64>;
    async fn evm_estimate_params_batch(
        &self,
        tx: &TransactionRequest,
        sender: &Address,
        block_count: u64,
        percentiles: Option<&[f64]>,
    ) -> Result<RequiredTxParams>;
    async fn evm_estimate_block_time(&self, address: &Address) -> Result<u64>;
    async fn evm_update_transactions_receipt(
        &self,
        txns: &mut [&mut HistoricalTransaction],
    ) -> Result<()>;
    async fn evm_broadcast_signed_transactions(
        &self,
        txns: Vec<TransactionReceipt>,
    ) -> Result<Vec<TransactionReceipt>>;
    async fn evm_update_balances(
        &self,
        tokens: Vec<&mut FToken>,
        accounts: &[&Address],
    ) -> Result<()>;
    async fn evm_ftoken_meta(&self, contract: Address, accounts: &[&Address]) -> Result<FToken>;
}

#[async_trait]
impl EvmOperations for NetworkProvider {
    async fn evm_get_current_block_number(&self) -> Result<u64> {
        let provider: RpcProvider<ChainConfig> = RpcProvider::new(&self.config);
        let payload = RpcProvider::<ChainConfig>::build_payload(json!([]), EvmMethods::BlockNumber);
        let response = provider
            .req::<ResultRes<Value>>(payload)
            .await
            .map_err(NetworkErrors::Request)?;
        let block_number = response
            .result
            .as_ref()
            .and_then(|result| result.as_str())
            .and_then(|block_str| u64::from_str_radix(&block_str.trim_start_matches("0x"), 16).ok())
            .ok_or(NetworkErrors::ResponseParseError)?;

        Ok(block_number)
    }

    async fn evm_estimate_params_batch(
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
            .req::<Vec<ResultRes<Value>>>(requests.into())
            .await
            .map_err(NetworkErrors::Request)?;

        if response.iter().all(|res| res.error.is_some()) {
            let all_errors = response
                .into_iter()
                .filter_map(|res| res.error.map(|e| e.to_string()))
                .collect::<Vec<String>>()
                .join(", ");
            return Err(NetworkErrors::RPCError(all_errors));
        }

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

        let tx_estimate_gas_response = response.get(2);

        if let Some(errors) = tx_estimate_gas_response.and_then(|res| res.error.as_ref()) {
            let error = errors.to_string();
            return Err(NetworkErrors::RPCError(error));
        }

        let tx_estimate_gas_response = tx_estimate_gas_response
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
                (U256::ZERO, Default::default())
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
            slow: 0,
            market: 0,
            fast: 0,
            current: 0,
        })
    }

    async fn evm_estimate_block_time(&self, address: &Address) -> Result<u64> {
        let provider: RpcProvider<ChainConfig> = RpcProvider::new(&self.config);
        let payload = build_last_block_header_request(address, None);
        let response = provider
            .req::<ResultRes<Value>>(payload)
            .await
            .map_err(NetworkErrors::Request)?;
        let (last_blocknumber, last_timestamp) =
            { process_get_timestampt_block_response(&response, address) };
        let payload = build_last_block_header_request(address, Some(last_blocknumber - 1));
        let response = provider
            .req::<ResultRes<Value>>(payload)
            .await
            .map_err(NetworkErrors::Request)?;
        let (_, early_timestamp) = { process_get_timestampt_block_response(&response, address) };

        Ok(last_timestamp - early_timestamp + 1)
    }

    async fn evm_update_transactions_receipt(
        &self,
        txns: &mut [&mut HistoricalTransaction],
    ) -> Result<()> {
        let mut requests: Vec<Value> = Vec::with_capacity(txns.len());

        for tx in txns.iter() {
            requests.push(build_payload_tx_receipt(&tx));
        }

        let provider: RpcProvider<ChainConfig> = RpcProvider::new(&self.config);
        let responses = provider
            .req::<Vec<ResultRes<Value>>>(requests.into())
            .await
            .map_err(NetworkErrors::Request)?;

        for (index, res) in responses.into_iter().enumerate() {
            if let Some(tx) = txns.get_mut(index) {
                process_tx_receipt_response(res, tx)?;
            }
        }

        Ok(())
    }

    async fn evm_broadcast_signed_transactions(
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
        let responses = provider
            .req::<Vec<ResultRes<Value>>>(all_requests.into())
            .await?;

        for (tx, response) in txns.iter_mut().zip(responses.iter()) {
            process_tx_send_response(response, tx)?;
        }

        Ok(txns)
    }

    async fn evm_update_balances(
        &self,
        mut tokens: Vec<&mut FToken>,
        accounts: &[&Address],
    ) -> Result<()> {
        let total_requests = tokens.iter().fold(0, |acc, _| acc + accounts.len());

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
            .req::<Vec<ResultRes<Value>>>(all_requests.into())
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
                Address::Secp256k1Bitcoin(_) => {
                    dbg!(&response);
                    // TODO: fix it.
                }
            }
        }

        Ok(())
    }

    async fn evm_ftoken_meta(&self, contract: Address, accounts: &[&Address]) -> Result<FToken> {
        let requests = build_token_requests(&contract, accounts, false)?;
        let provider: RpcProvider<ChainConfig> = RpcProvider::new(&self.config);
        let responses: Vec<ResultRes<Value>> = provider
            .req(
                requests
                    .iter()
                    .map(|(req, _)| req.clone())
                    .collect::<Vec<_>>()
                    .into(),
            )
            .await
            .map_err(NetworkErrors::Request)?;

        match contract {
            Address::Secp256k1Bitcoin(_) => {
                return Err(NetworkErrors::EIPNotSupporting(0));
            }
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
                    rate: 0f64,
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
                    rate: 0f64,
                })
            }
        }
    }
}
