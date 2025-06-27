use crate::{
    provider::NetworkProvider,
    zil_stake_parse::{
        assemble_evm_final_output, build_evm_pools_requests, build_initial_core_requests,
        process_avely_stake, process_evm_pools_results, process_scilla_stakes, EvmPool,
        FinalOutput,
    },
};
use alloy::primitives::U256;
use async_trait::async_trait;
use errors::network::NetworkErrors;
use proto::address::Address;
use rpc::{
    common::JsonRPC, network_config::ChainConfig, provider::RpcProvider, zil_interfaces::ResultRes,
};
use serde_json::Value;
use std::collections::HashMap;

#[async_trait]
pub trait ZilliqaStakeing {
    async fn get_zq2_providers(&self) -> Result<Vec<EvmPool>, NetworkErrors>;

    async fn get_all_stakes(
        &self,
        scilla_user_address: &str,
        evm_user_address: &Address,
    ) -> Result<Vec<FinalOutput>, NetworkErrors>;
}

#[async_trait]
impl ZilliqaStakeing for NetworkProvider {
    async fn get_zq2_providers(&self) -> Result<Vec<EvmPool>, NetworkErrors> {
        let url = "https://api.zilpay.io/api/v1/stake/pools";
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
            .json::<Vec<EvmPool>>()
            .await
            .map_err(|e| NetworkErrors::ParseHttpError(e.to_string()))
    }

    async fn get_all_stakes(
        &self,
        scilla_user_address: &str,
        evm_user_address: &Address,
    ) -> Result<Vec<FinalOutput>, NetworkErrors> {
        let evm_pools = self.get_zq2_providers().await?;

        let (core_reqs, core_ids, next_id) = build_initial_core_requests(1, scilla_user_address);
        let (evm_reqs, evm_req_map, _next_id) =
            build_evm_pools_requests(&evm_pools, evm_user_address, next_id);

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
        let evm_stakes = assemble_evm_final_output(
            &evm_pools,
            &temp_evm_user_data,
            &temp_evm_pool_stats,
            total_network_stake,
        );
        final_output.extend(evm_stakes);

        if let Some(avely_stake) = process_avely_stake(
            results_by_id.get(&core_ids.st_zil_balance).as_ref(),
            scilla_user_address,
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
                process_scilla_stakes(self, ssn, reward, withdraw, scilla_user_address).await?;
            final_output.extend(scilla_stakes);
        }

        final_output.sort_by(|a, b| {
            b.deleg_amt
                .cmp(&a.deleg_amt)
                .then_with(|| a.name.cmp(&b.name))
        });

        Ok(final_output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proto::address::Address;
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
        let scilla_user_address = "0x77e27c39ce572283b848e2cdf32cce761e34fa49";
        let evm_user_address =
            Address::from_eth_address("0xb1fE20CD2b856BA1a4e08afb39dfF5C80f0cBbCa").unwrap();

        let net_conf = create_zilliqa_config();
        let provider = NetworkProvider::new(net_conf);

        let result = provider
            .get_all_stakes(scilla_user_address, &evm_user_address)
            .await;

        assert!(result.is_ok(), "Function should execute without errors");
        let final_output = result.unwrap();

        assert!(!final_output.is_empty(), "Should return some staking data");

        if final_output.len() > 1 {
            assert!(final_output[0].deleg_amt >= final_output[1].deleg_amt);
        }

        println!("{:#?}", final_output);
    }
}
