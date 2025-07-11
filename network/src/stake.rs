use crate::{
    provider::NetworkProvider,
    zil_stake_parse::{
        assemble_evm_final_output, build_claim_reward_request, build_claim_unstake_request,
        build_evm_pools_requests, build_initial_core_requests, build_stake_request,
        build_unstake_request, process_avely_stake, process_evm_pending_withdrawals,
        process_evm_pools_results, process_pending_withdrawals, process_scilla_stakes, EvmPoolV2,
        FinalOutput,
    },
};
use alloy::primitives::U256;
use async_trait::async_trait;
use config::contracts::{SCILLA_STAKE_PROXY, ST_ZIL_CONTRACT};
use errors::network::NetworkErrors;
use proto::{
    address::Address,
    pubkey::PubKey,
    tx::{TransactionMetadata, TransactionRequest},
    zil_tx::ZILTransactionRequest,
};
use rpc::{
    common::JsonRPC, network_config::ChainConfig, provider::RpcProvider, zil_interfaces::ResultRes,
};
use serde_json::{json, Value};
use std::collections::HashMap;

#[async_trait]
pub trait ZilliqaStakeing {
    async fn get_zq2_providers(&self) -> Result<Vec<EvmPoolV2>, NetworkErrors>;
    async fn get_all_stakes(&self, pub_key: &PubKey) -> Result<Vec<FinalOutput>, NetworkErrors>;
    fn build_tx_scilla_claim(
        &self,
        stake: &FinalOutput,
    ) -> Result<TransactionRequest, NetworkErrors>;
    fn build_tx_scilla_init_unstake(
        &self,
        stake: &FinalOutput,
    ) -> Result<TransactionRequest, NetworkErrors>;
    fn build_tx_scilla_complete_withdrawal(&self) -> Result<TransactionRequest, NetworkErrors>;
    fn build_tx_scilla_withdraw_stake_avely(
        &self,
        stake: &FinalOutput,
    ) -> Result<TransactionRequest, NetworkErrors>;
    fn build_tx_scilla_complete_withdrawal_avely(
        &self,
    ) -> Result<TransactionRequest, NetworkErrors>;

    fn build_tx_evm_stake_request(
        &self,
        amount: U256,
        provider: &Address,
        from: &Address,
    ) -> Result<TransactionRequest, NetworkErrors>;
    fn build_tx_evm_unstake_request(
        &self,
        amount_to_unstake: U256,
        provider: &Address,
        from: &Address,
    ) -> Result<TransactionRequest, NetworkErrors>;
    fn build_tx_claim_unstake_request(
        &self,
        provider: &Address,
        from: &Address,
    ) -> Result<TransactionRequest, NetworkErrors>;
    fn build_tx_build_claim_reward_request(
        &self,
        provider: &Address,
        from: &Address,
    ) -> Result<TransactionRequest, NetworkErrors>;
}

#[async_trait]
impl ZilliqaStakeing for NetworkProvider {
    fn build_tx_evm_stake_request(
        &self,
        amount: U256,
        provider: &Address,
        from: &Address,
    ) -> Result<TransactionRequest, NetworkErrors> {
        let mut tx =
            build_stake_request(amount, provider.to_alloy_addr()).from(from.to_alloy_addr());

        tx.chain_id = Some(self.config.chain_ids[0]);

        let metdata = TransactionMetadata {
            chain_hash: self.config.hash(),
            ..Default::default()
        };
        let req_tx = TransactionRequest::Ethereum((tx, metdata));

        Ok(req_tx)
    }

    fn build_tx_evm_unstake_request(
        &self,
        amount_to_unstake: U256,
        provider: &Address,
        from: &Address,
    ) -> Result<TransactionRequest, NetworkErrors> {
        let mut tx = build_unstake_request(amount_to_unstake, provider.to_alloy_addr())
            .from(from.to_alloy_addr());

        tx.chain_id = Some(self.config.chain_ids[0]);

        let metdata = TransactionMetadata {
            chain_hash: self.config.hash(),
            ..Default::default()
        };
        let req_tx = TransactionRequest::Ethereum((tx, metdata));

        Ok(req_tx)
    }

    fn build_tx_claim_unstake_request(
        &self,
        provider: &Address,
        from: &Address,
    ) -> Result<TransactionRequest, NetworkErrors> {
        let mut tx =
            build_claim_unstake_request(provider.to_alloy_addr()).from(from.to_alloy_addr());

        tx.chain_id = Some(self.config.chain_ids[0]);

        let metdata = TransactionMetadata {
            chain_hash: self.config.hash(),
            ..Default::default()
        };
        let req_tx = TransactionRequest::Ethereum((tx, metdata));

        Ok(req_tx)
    }

    fn build_tx_build_claim_reward_request(
        &self,
        provider: &Address,
        from: &Address,
    ) -> Result<TransactionRequest, NetworkErrors> {
        let mut tx =
            build_claim_reward_request(provider.to_alloy_addr()).from(from.to_alloy_addr());

        tx.chain_id = Some(self.config.chain_ids[0]);

        let metdata = TransactionMetadata {
            chain_hash: self.config.hash(),
            ..Default::default()
        };
        let req_tx = TransactionRequest::Ethereum((tx, metdata));

        Ok(req_tx)
    }

    fn build_tx_scilla_withdraw_stake_avely(
        &self,
        stake: &FinalOutput,
    ) -> Result<TransactionRequest, NetworkErrors> {
        let params = json!({
          "_tag": "WithdrawTokensAmt",
          "params": [
            {
              "vname": "amount",
              "type": "Uint128",
              "value": stake.deleg_amt.to_string()
            }
          ]
        });
        let contract = Address::from_zil_base16(ST_ZIL_CONTRACT)?;
        let zil_tx = ZILTransactionRequest {
            chain_id: self.config.chain_ids[1] as u16,
            nonce: 0,
            gas_price: 2000000050,
            gas_limit: 5000,
            to_addr: contract,
            amount: 0,
            code: vec![],
            data: params.to_string().into_bytes(),
        };
        let metdata = TransactionMetadata {
            chain_hash: self.config.hash(),
            ..Default::default()
        };
        let req_tx = TransactionRequest::Zilliqa((zil_tx, metdata));

        Ok(req_tx)
    }

    fn build_tx_scilla_complete_withdrawal_avely(
        &self,
    ) -> Result<TransactionRequest, NetworkErrors> {
        let params = json!({
          "_tag": "CompleteWithdrawal",
          "params": []
        });
        let contract = Address::from_zil_base16(ST_ZIL_CONTRACT)?;
        let zil_tx = ZILTransactionRequest {
            chain_id: self.config.chain_ids[1] as u16,
            nonce: 0,
            gas_price: 2000000050,
            gas_limit: 5000,
            to_addr: contract,
            amount: 0,
            code: vec![],
            data: params.to_string().into_bytes(),
        };
        let metdata = TransactionMetadata {
            chain_hash: self.config.hash(),
            ..Default::default()
        };
        let req_tx = TransactionRequest::Zilliqa((zil_tx, metdata));

        Ok(req_tx)
    }

    fn build_tx_scilla_complete_withdrawal(&self) -> Result<TransactionRequest, NetworkErrors> {
        let params = json!({
            "_tag": "CompleteWithdrawal",
            "params": []
        });
        let contract = Address::from_zil_base16(SCILLA_STAKE_PROXY)?;
        let zil_tx = ZILTransactionRequest {
            chain_id: self.config.chain_ids[1] as u16,
            nonce: 0,
            gas_price: 2000000050,
            gas_limit: 5000,
            to_addr: contract,
            amount: 0,
            code: vec![],
            data: params.to_string().into_bytes(),
        };
        let metdata = TransactionMetadata {
            chain_hash: self.config.hash(),
            ..Default::default()
        };
        let req_tx = TransactionRequest::Zilliqa((zil_tx, metdata));

        Ok(req_tx)
    }

    fn build_tx_scilla_init_unstake(
        &self,
        stake: &FinalOutput,
    ) -> Result<TransactionRequest, NetworkErrors> {
        let params = json!({
          "_tag": "WithdrawStakeAmt",
          "params": [
            {
              "vname": "ssnaddr",
              "type": "ByStr20",
              "value": stake.address
            },
            {
              "vname": "amt",
              "type": "Uint128",
              "value": stake.deleg_amt.to_string()
            }
          ]
        });
        let contract = Address::from_zil_base16(SCILLA_STAKE_PROXY)?;
        let zil_tx = ZILTransactionRequest {
            chain_id: self.config.chain_ids[1] as u16,
            nonce: 0,
            gas_price: 2000000050,
            gas_limit: 5000,
            to_addr: contract,
            amount: 0,
            code: vec![],
            data: params.to_string().into_bytes(),
        };
        let metdata = TransactionMetadata {
            chain_hash: self.config.hash(),
            ..Default::default()
        };
        let req_tx = TransactionRequest::Zilliqa((zil_tx, metdata));

        Ok(req_tx)
    }

    fn build_tx_scilla_claim(
        &self,
        stake: &FinalOutput,
    ) -> Result<TransactionRequest, NetworkErrors> {
        let params = json!({
            "_tag": "WithdrawStakeRewards",
            "params": [
                {
                    "vname": "ssnaddr",
                    "type": "ByStr20",
                    "value": stake.address
                }
            ]
        });
        let contract = Address::from_zil_base16(SCILLA_STAKE_PROXY)?;
        let zil_tx = ZILTransactionRequest {
            chain_id: self.config.chain_ids[1] as u16,
            nonce: 0,
            gas_price: 2000000050,
            gas_limit: 100000,
            to_addr: contract,
            amount: 0,
            code: vec![],
            data: params.to_string().into_bytes(),
        };
        let metdata = TransactionMetadata {
            chain_hash: self.config.hash(),
            ..Default::default()
        };
        let req_tx = TransactionRequest::Zilliqa((zil_tx, metdata));

        Ok(req_tx)
    }

    async fn get_zq2_providers(&self) -> Result<Vec<EvmPoolV2>, NetworkErrors> {
        let url = "https://api.zilpay.io/api/v2/stake/pools";
        let client = reqwest::Client::new();
        let response = client.get(url).send().await.map_err(|e| match e.status() {
            Some(status) => NetworkErrors::HttpError(status.as_u16(), e.to_string()),
            None => NetworkErrors::HttpNetworkError(e.to_string()),
        })?;

        if !response.status().is_success() {
            return Err(NetworkErrors::HttpError(
                response.status().as_u16(),
                format!("API request failed: {}", response.status()),
            ));
        }

        response
            .json::<Vec<EvmPoolV2>>()
            .await
            .map_err(|e| NetworkErrors::ParseHttpError(e.to_string()))
    }

    async fn get_all_stakes(&self, pub_key: &PubKey) -> Result<Vec<FinalOutput>, NetworkErrors> {
        let scilla_user_address = PubKey::Secp256k1Sha256(pub_key.as_bytes())
            .get_addr()?
            .get_zil_check_sum_addr()?
            .to_lowercase();
        let evm_user_address = PubKey::Secp256k1Keccak256(pub_key.as_bytes()).get_addr()?;
        let evm_pools = self.get_zq2_providers().await?;

        let (core_reqs, core_ids, next_id) = build_initial_core_requests(1, &scilla_user_address);
        let (evm_reqs, evm_req_map, _next_id) =
            build_evm_pools_requests(&evm_pools, &evm_user_address, next_id);

        let all_requests: Vec<Value> = core_reqs.into_iter().chain(evm_reqs).collect();
        let provider: RpcProvider<ChainConfig> = RpcProvider::new(&self.config);

        let all_results_json = provider.req::<Value>(all_requests.into()).await?;
        let all_results: Vec<ResultRes<Value>> = serde_json::from_value(all_results_json)
            .map_err(|e| NetworkErrors::ParseHttpError(e.to_string()))?;

        let results_by_id: HashMap<u64, ResultRes<Value>> =
            all_results.into_iter().map(|res| (res.id, res)).collect();

        let mut final_output: Vec<FinalOutput> = Vec::new();

        let total_network_stake_response = results_by_id.get(&core_ids.total_network_stake);
        let total_network_stake = total_network_stake_response
            .and_then(|res| res.result.as_ref())
            .and_then(|val| val.as_str())
            .and_then(|s| U256::from_str_radix(s.trim_start_matches("0x"), 16).ok())
            .unwrap_or_default();

        let (temp_evm_user_data, temp_evm_pool_stats) =
            process_evm_pools_results(&results_by_id, &evm_req_map);
        let mut evm_stakes = assemble_evm_final_output(
            &evm_pools,
            &temp_evm_user_data,
            &temp_evm_pool_stats,
            total_network_stake,
        );

        if let Some(avely_stake) = process_avely_stake(
            results_by_id.get(&core_ids.st_zil_balance).as_ref(),
            &scilla_user_address,
        ) {
            final_output.push(avely_stake);
        }

        let ssn_result = results_by_id.get(&core_ids.ssn_list);
        let reward_cycle_result = results_by_id.get(&core_ids.reward_cycle);
        let withdraw_cycle_result = results_by_id.get(&core_ids.withdraw_cycle);

        if let (Some(ssn), Some(reward), Some(withdraw)) =
            (ssn_result, reward_cycle_result, withdraw_cycle_result)
        {
            let scilla_stakes =
                process_scilla_stakes(self, ssn, reward, withdraw, &scilla_user_address).await?;
            final_output.extend(scilla_stakes);
        }

        let blockchain_info_result = results_by_id.get(&core_ids.blockchain_info);

        let current_block = blockchain_info_result
            .and_then(|res| res.result.as_ref())
            .and_then(|r| {
                serde_json::from_value::<crate::zil_stake_parse::BlockchainInfo>(r.clone()).ok()
            })
            .and_then(|info| info.num_tx_blocks.parse::<u64>().ok())
            .unwrap_or(0);

        let evm_pending_withdrawals_map =
            process_evm_pending_withdrawals(&results_by_id, &evm_req_map, current_block);

        for pool_output in &mut evm_stakes {
            pool_output.current_block = Some(current_block);

            if let Some(withdrawals) = evm_pending_withdrawals_map.get(
                &pool_output
                    .address
                    .parse::<alloy::primitives::Address>()
                    .unwrap_or_default(),
            ) {
                pool_output.pending_withdrawals = withdrawals.clone();
            }
        }

        final_output.extend(evm_stakes);

        let withdrawal_pending_result = results_by_id.get(&core_ids.withdrawal_pending);
        let unbonded_withdrawal_result = results_by_id.get(&core_ids.unbonded_withdrawal);

        let pending_withdrawals = process_pending_withdrawals(
            withdrawal_pending_result.as_ref(),
            unbonded_withdrawal_result.as_ref(),
            blockchain_info_result.as_ref(),
            &scilla_user_address,
        );
        final_output.extend(pending_withdrawals);

        Ok(final_output)
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;
    use rpc::network_config::ChainConfig;

    fn create_zilliqa_config() -> ChainConfig {
        ChainConfig {
            ftokens: vec![],
            logo: String::new(),
            diff_block_time: 0,
            testnet: None,
            chain_ids: [1, 0],
            name: "Zilliqa".to_string(),
            chain: "ZIL".to_string(),
            short_name: String::new(),
            rpc: vec!["https://api.zilliqa.com".to_string()],
            features: vec![],
            slip_44: 313,
            ens: None,
            explorers: vec![],
            fallback_enabled: true,
        }
    }

    #[tokio::test]
    async fn test_request_zil_staking_pools() {
        let net_conf = create_zilliqa_config();
        let provider = NetworkProvider::new(net_conf);
        let pools = provider.get_zq2_providers().await.unwrap();
        assert!(!pools.is_empty());
        assert!(pools.iter().any(|p| p.name == "Moonlet"));
        assert!(pools
            .iter()
            .any(|p| p.name == "Amazing Pool - Avely and ZilPay"));
    }

    #[tokio::test]
    async fn test_get_all_stakes_orchestration() {
        let pubkey = PubKey::from_str(
            "000269c1a51cbc0d3e86468fdbe2cdd7f4cae98df1278a205e4cfb7631373944532f",
        )
        .unwrap();

        let net_conf = create_zilliqa_config();
        let provider = NetworkProvider::new(net_conf);
        let result = provider.get_all_stakes(&pubkey).await;
        let final_output = result.unwrap();

        assert!(!final_output.is_empty(), "Should return some staking data");

        println!("{:#?}", final_output);
    }
}
