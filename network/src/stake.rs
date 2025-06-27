use crate::provider::NetworkProvider;
use alloy::primitives::{utils::format_units, U256};
use async_trait::async_trait;
use errors::network::NetworkErrors;
use rpc::{
    common::JsonRPC, methods::EvmMethods, methods::ZilMethods, network_config::ChainConfig,
    provider::RpcProvider, zil_interfaces::ResultRes,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{collections::HashMap, str::FromStr};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Pool {
    pub address: String,
    pub token_address: String,
    pub name: String,
    pub pool_type: String,
    pub token_decimals: u32,
    pub token_symbol: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FinalOutput {
    name: String,
    url: String,
    address: String,
    token_address: Option<String>,
    deleg_amt: String,
    rewards: String,
    tvl: Option<String>,
    vote_power: Option<f64>,
    apr: Option<f64>,
    tag: String,
}

#[derive(Debug, Clone, Default)]
struct EvmPoolStats {
    tvl: Option<U256>,
    pool_stake: Option<U256>,
    commission_num: Option<U256>,
    commission_den: Option<U256>,
}

enum RequestType {
    ScillaSsnList,
    ScillaRewardCycle,
    ScillaWithdrawCycle,
    AvelyStZilBalance,
    EvmTotalStake,
    EvmDelegAmt(String),
    EvmRewards(String),
    EvmPoolTvl(String),
    EvmPoolStake(String),
    EvmPoolCommission(String),
    ScillaDelegAmt,
    ScillaDirectDeposit,
    ScillaBuffDeposit,
    ScillaDelegStakePerCycle,
    ScillaStakeSsnPerCycle,
}

#[derive(Clone)]
struct SSNode {
    name: String,
    url: String,
    address: String,
    last_reward_cycle: u64,
    last_withdraw_cycle_deleg: u64,
}

struct ScillaStakedNode {
    node: SSNode,
    deleg_amt: U256,
    rewards: U256,
}

const SCILLA_USER_ADDRESS: &str = "0x77e27c39ce572283b848e2cdf32cce761e34fa49";
const EVM_USER_ADDRESS: &str = "0xb1fE20CD2b856BA1a4e08afb39dfF5C80f0cBbCa";
const SCILLA_GZIL_CONTRACT: &str = "a7C67D49C82c7dc1B73D231640B2e4d0661D37c1";
const ST_ZIL_CONTRACT: &str = "e6f14afc8739a4ead0a542c07d3ff978190e3b92";
const DEPOSIT_ADDRESS: &str = "0x00000000005a494c4445504f53495450524f5859";

#[async_trait]
pub trait ZilliqaStakeing {
    async fn get_zq2_providers(&self) -> std::result::Result<Vec<Pool>, NetworkErrors>;
    async fn get_all_stakes(&self) -> Result<Vec<FinalOutput>, NetworkErrors>;
}

fn hex_to_u256(hex: &str) -> U256 {
    if hex == "0x" {
        return U256::ZERO;
    }
    U256::from_str_radix(hex.trim_start_matches("0x"), 16).unwrap_or_default()
}

fn build_eth_call_payload(to: &str, data: &str) -> Value {
    RpcProvider::<ChainConfig>::build_payload(
        json!([{ "to": to, "data": data }, "latest"]),
        EvmMethods::Call,
    )
}

fn build_from_eth_call_payload(to: &str, data: &str, from: &str) -> Value {
    RpcProvider::<ChainConfig>::build_payload(
        json!([{ "to": to, "data": data, "from": from }, "latest"]),
        EvmMethods::Call,
    )
}

fn get_reward_need_cycle_list(last_withdraw_cycle: u64, last_reward_cycle: u64) -> Vec<u64> {
    if last_reward_cycle <= last_withdraw_cycle {
        return Vec::new();
    }
    (last_withdraw_cycle + 1..=last_reward_cycle).collect()
}

fn combine_buff_direct(
    reward_list: &[u64],
    direct_deposit_map: &HashMap<String, String>,
    buffer_deposit_map: &HashMap<String, String>,
    deleg_stake_per_cycle_map: &HashMap<String, String>,
) -> HashMap<u64, U256> {
    let mut result_map = HashMap::new();
    for &cycle in reward_list {
        let c1 = cycle - 1;
        let c2 = cycle - 2;

        let hist_amt = deleg_stake_per_cycle_map
            .get(&c1.to_string())
            .and_then(|s| U256::from_str(s).ok())
            .unwrap_or_default();
        let dir_amt = direct_deposit_map
            .get(&c1.to_string())
            .and_then(|s| U256::from_str(s).ok())
            .unwrap_or_default();
        let buf_amt = buffer_deposit_map
            .get(&c2.to_string())
            .and_then(|s| U256::from_str(s).ok())
            .unwrap_or_default();

        let total_amt_tmp = hist_amt.saturating_add(dir_amt).saturating_add(buf_amt);
        let previous_cycle_amt = result_map.get(&c1).cloned().unwrap_or_default();
        let total_amt = total_amt_tmp.saturating_add(previous_cycle_amt);
        result_map.insert(cycle, total_amt);
    }
    result_map
}

fn calculate_rewards(
    delegate_per_cycle: &HashMap<u64, U256>,
    need_list: &[u64],
    stake_ssn_per_cycle_map: &HashMap<String, (U256, U256)>,
) -> U256 {
    let mut result_rewards = U256::ZERO;
    if stake_ssn_per_cycle_map.is_empty() {
        return result_rewards;
    }

    for &cycle in need_list {
        if let Some(cycle_info) = stake_ssn_per_cycle_map.get(&cycle.to_string()) {
            let total_stake = cycle_info.0;
            let total_rewards = cycle_info.1;

            if let Some(deleg_amt) = delegate_per_cycle.get(&cycle) {
                if !total_stake.is_zero() {
                    let reward = (*deleg_amt)
                        .saturating_mul(total_rewards)
                        .checked_div(total_stake)
                        .unwrap_or(U256::ZERO);
                    result_rewards = result_rewards.saturating_add(reward);
                }
            }
        }
    }
    result_rewards
}

#[async_trait]
impl ZilliqaStakeing for NetworkProvider {
    async fn get_zq2_providers(&self) -> std::result::Result<Vec<Pool>, NetworkErrors> {
        // This is a specific API endpoint, not a generic JSON-RPC one.
        // It's better to leave it as is, since RpcProvider is for JSON-RPC.
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
            .json::<Vec<Pool>>()
            .await
            .map_err(|e| NetworkErrors::ParseHttpError(e.to_string()))
    }

    async fn get_all_stakes(&self) -> Result<Vec<FinalOutput>, NetworkErrors> {
        let pools = self.get_zq2_providers().await?;
        let mut requests: Vec<(Value, RequestType)> = Vec::new();

        // Build all initial requests
        requests.push((
            RpcProvider::<ChainConfig>::build_payload(
                json!([SCILLA_GZIL_CONTRACT, "ssnlist", []]),
                ZilMethods::GetSmartContractSubState,
            ),
            RequestType::ScillaSsnList,
        ));
        requests.push((
            RpcProvider::<ChainConfig>::build_payload(
                json!([SCILLA_GZIL_CONTRACT, "lastrewardcycle", []]),
                ZilMethods::GetSmartContractSubState,
            ),
            RequestType::ScillaRewardCycle,
        ));
        requests.push((
            RpcProvider::<ChainConfig>::build_payload(
                json!([
                    SCILLA_GZIL_CONTRACT,
                    "last_withdraw_cycle_deleg",
                    [SCILLA_USER_ADDRESS]
                ]),
                ZilMethods::GetSmartContractSubState,
            ),
            RequestType::ScillaWithdrawCycle,
        ));
        requests.push((
            RpcProvider::<ChainConfig>::build_payload(
                json!([
                    ST_ZIL_CONTRACT,
                    "balances",
                    [SCILLA_USER_ADDRESS.to_lowercase()]
                ]),
                ZilMethods::GetSmartContractSubState,
            ),
            RequestType::AvelyStZilBalance,
        ));
        requests.push((
            build_eth_call_payload(DEPOSIT_ADDRESS, "0xb69ef8a8"),
            RequestType::EvmTotalStake,
        ));

        for pool in &pools {
            if pool.pool_type == "LIQUID" {
                requests.push((
                    build_eth_call_payload(
                        &pool.token_address,
                        &format!(
                            "0x70a08231000000000000000000000000{}",
                            EVM_USER_ADDRESS.trim_start_matches("0x")
                        ),
                    ),
                    RequestType::EvmDelegAmt(pool.address.clone()),
                ));
                requests.push((
                    build_eth_call_payload(&pool.token_address, "0x18160ddd"),
                    RequestType::EvmPoolTvl(pool.address.clone()),
                ));
            } else {
                requests.push((
                    build_from_eth_call_payload(&pool.address, "0x8af53883", EVM_USER_ADDRESS),
                    RequestType::EvmDelegAmt(pool.address.clone()),
                ));
                requests.push((
                    build_from_eth_call_payload(&pool.address, "0x0158a786", EVM_USER_ADDRESS),
                    RequestType::EvmRewards(pool.address.clone()),
                ));
                requests.push((
                    build_eth_call_payload(&pool.address, "0xed8c72a8"),
                    RequestType::EvmPoolTvl(pool.address.clone()),
                ));
            }
            requests.push((
                build_eth_call_payload(&pool.address, "0xad5c4648"),
                RequestType::EvmPoolStake(pool.address.clone()),
            ));
            requests.push((
                build_eth_call_payload(&pool.address, "0x2e8932e1"),
                RequestType::EvmPoolCommission(pool.address.clone()),
            ));
        }

        // Use the RpcProvider from the network config, as requested.
        let rpc_payloads: Vec<Value> = requests.iter().map(|(p, _)| p.clone()).collect();
        let provider: RpcProvider<ChainConfig> = RpcProvider::new(&self.config);
        let responses = provider
            .req::<Vec<ResultRes<Value>>>(rpc_payloads.into())
            .await
            .map_err(NetworkErrors::Request)?;

        // Process responses...
        let mut final_output: Vec<FinalOutput> = Vec::new();
        let mut temp_evm_user_data: HashMap<String, (U256, U256)> = HashMap::new();
        let mut temp_evm_pool_stats: HashMap<String, EvmPoolStats> = HashMap::new();
        let mut total_network_stake = U256::ZERO;
        let mut scilla_ssn_list: Vec<SSNode> = Vec::new();
        let mut last_reward_cycle = 0;

        for (i, response) in responses.iter().enumerate() {
            let req_type = &requests[i].1;
            if response.error.is_some() {
                continue;
            }
            if let Some(result) = &response.result {
                match req_type {
                    RequestType::EvmTotalStake => {
                        total_network_stake = hex_to_u256(result.as_str().unwrap_or("0x"));
                    }
                    RequestType::EvmDelegAmt(id) => {
                        let amt = hex_to_u256(result.as_str().unwrap_or("0x"));
                        if !amt.is_zero() {
                            temp_evm_user_data.entry(id.clone()).or_default().0 = amt;
                        }
                    }
                    RequestType::EvmRewards(id) => {
                        temp_evm_user_data.entry(id.clone()).or_default().1 =
                            hex_to_u256(result.as_str().unwrap_or("0x"));
                    }
                    RequestType::EvmPoolTvl(id) => {
                        temp_evm_pool_stats.entry(id.clone()).or_default().tvl =
                            Some(hex_to_u256(result.as_str().unwrap_or("0x")));
                    }
                    RequestType::EvmPoolStake(id) => {
                        temp_evm_pool_stats
                            .entry(id.clone())
                            .or_default()
                            .pool_stake = Some(hex_to_u256(result.as_str().unwrap_or("0x")));
                    }
                    RequestType::EvmPoolCommission(id) => {
                        let data = result.as_str().unwrap_or("0x").trim_start_matches("0x");
                        if data.len() == 128 {
                            let (num, den) = data.split_at(64);
                            let stats = temp_evm_pool_stats.entry(id.clone()).or_default();
                            stats.commission_num = Some(hex_to_u256(&format!("0x{}", num)));
                            stats.commission_den = Some(hex_to_u256(&format!("0x{}", den)));
                        }
                    }
                    RequestType::AvelyStZilBalance => {
                        if let Some(balance) = result
                            .get("balances")
                            .and_then(|b| b.get(&SCILLA_USER_ADDRESS.to_lowercase()))
                            .and_then(|b| b.as_str())
                        {
                            if balance != "0" {
                                final_output.push(FinalOutput {
                                    name: "stZIL (Avely Finance)".to_string(),
                                    url: "https://avely.fi/".to_string(),
                                    address: ST_ZIL_CONTRACT.to_string(),
                                    token_address: None,
                                    deleg_amt: balance.to_string(),
                                    rewards: "0".to_string(),
                                    tvl: None,
                                    vote_power: None,
                                    apr: None,
                                    tag: "avely".to_string(),
                                });
                            }
                        }
                    }
                    RequestType::ScillaRewardCycle => {
                        last_reward_cycle = result["lastrewardcycle"]
                            .as_str()
                            .unwrap_or("0")
                            .parse()
                            .unwrap_or(0);
                    }
                    RequestType::ScillaSsnList => {
                        if let Some(ssnlist_val) = result.get("ssnlist") {
                            let mut last_withdraw_nodes: HashMap<String, u64> = HashMap::new();
                            if let Some(withdraw_response) = responses.get(2) {
                                if let Some(res) = &withdraw_response.result {
                                    if let Some(cycle_map) = res
                                        .get("last_withdraw_cycle_deleg")
                                        .and_then(|m| m.get(SCILLA_USER_ADDRESS))
                                    {
                                        last_withdraw_nodes =
                                            serde_json::from_value(cycle_map.clone())
                                                .unwrap_or_default();
                                    }
                                }
                            }

                            if let Some(ssnlist_map) = ssnlist_val.as_object() {
                                scilla_ssn_list = ssnlist_map
                                    .iter()
                                    .map(|(key, value)| {
                                        let args = value["arguments"].as_array().unwrap();
                                        SSNode {
                                            address: key.clone(),
                                            name: args[3].as_str().unwrap().to_string(),
                                            url: args[5].as_str().unwrap().to_string(),
                                            last_reward_cycle,
                                            last_withdraw_cycle_deleg: *last_withdraw_nodes
                                                .get(key)
                                                .unwrap_or(&0),
                                        }
                                    })
                                    .collect();
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        for pool in &pools {
            let user_data = temp_evm_user_data.get(&pool.address);
            let pool_stats = temp_evm_pool_stats.get(&pool.address);
            let deleg_amt = user_data.map(|(amt, _)| *amt).unwrap_or(U256::ZERO);
            let has_delegation = !deleg_amt.is_zero();
            let has_tvl = pool_stats
                .and_then(|s| s.tvl)
                .map_or(false, |tvl| !tvl.is_zero());

            if has_delegation || has_tvl {
                let mut output_entry = FinalOutput {
                    name: pool.name.clone(),
                    url: "".to_string(),
                    address: pool.address.clone(),
                    token_address: Some(pool.token_address.clone()),
                    deleg_amt: deleg_amt.to_string(),
                    rewards: user_data
                        .map(|(_, r)| r.to_string())
                        .unwrap_or_else(|| "0".to_string()),
                    tvl: None,
                    vote_power: None,
                    apr: None,
                    tag: "evm".to_string(),
                };
                if let Some(stats) = pool_stats {
                    if let Some(tvl) = stats.tvl {
                        output_entry.tvl =
                            Some(format_units(tvl, pool.token_decimals as u8).unwrap_or_default());
                    }

                    if let (Some(pool_stake), Some(commission_den)) =
                        (stats.pool_stake, stats.commission_den)
                    {
                        if !total_network_stake.is_zero() && !commission_den.is_zero() {
                            let total_stake_f = format_units(total_network_stake, 18)
                                .unwrap_or_default()
                                .parse::<f64>()
                                .unwrap_or(1.0);
                            let pool_stake_f = format_units(pool_stake, 18)
                                .unwrap_or_default()
                                .parse::<f64>()
                                .unwrap_or(0.0);
                            let vp = (pool_stake_f / total_stake_f) * 100.0;
                            output_entry.vote_power = Some((vp * 10000.0).round() / 10000.0);

                            let commission_num_f = stats
                                .commission_num
                                .map(|v| {
                                    format_units(v, 18)
                                        .unwrap_or_default()
                                        .parse::<f64>()
                                        .unwrap_or(0.0)
                                })
                                .unwrap_or(0.0);
                            let commission_den_f = format_units(commission_den, 18)
                                .unwrap_or_default()
                                .parse::<f64>()
                                .unwrap_or(1.0);
                            let commission = commission_num_f / commission_den_f;
                            let rewards_per_year_in_zil = 446760000.0; // 51000.0 * 24.0 * 365.0;
                            let delegator_year_reward = (vp / 100.0) * rewards_per_year_in_zil;
                            let delegator_reward_for_share =
                                delegator_year_reward * (1.0 - commission);

                            if pool_stake_f > 0.0 {
                                let apr = (delegator_reward_for_share / pool_stake_f) * 100.0;
                                output_entry.apr = Some((apr * 10000.0).round() / 10000.0);
                            }
                        }
                    }
                }
                final_output.push(output_entry);
            }
        }

        if !scilla_ssn_list.is_empty() {
            let mut deleg_amt_requests = Vec::new();
            for (_i, node) in scilla_ssn_list.iter().enumerate() {
                deleg_amt_requests.push((
                    RpcProvider::<ChainConfig>::build_payload(
                        json!([
                            SCILLA_GZIL_CONTRACT,
                            "ssn_deleg_amt",
                            [node.address, SCILLA_USER_ADDRESS]
                        ]),
                        ZilMethods::GetSmartContractSubState,
                    ),
                    RequestType::ScillaDelegAmt,
                ));
            }

            let deleg_rpc_payloads: Vec<Value> =
                deleg_amt_requests.iter().map(|(p, _)| p.clone()).collect();
            let deleg_responses = provider
                .req::<Vec<ResultRes<Value>>>(deleg_rpc_payloads.into())
                .await
                .map_err(NetworkErrors::Request)?;

            let mut staked_scilla_nodes: Vec<ScillaStakedNode> = Vec::new();

            for (i, res) in deleg_responses.iter().enumerate() {
                if let Some(result) = &res.result {
                    if let Some(delegations) = result
                        .get("ssn_deleg_amt")
                        .and_then(|d| d.get(&scilla_ssn_list[i].address))
                        .and_then(|d| d.get(SCILLA_USER_ADDRESS))
                    {
                        if let Some(amount_str) = delegations.as_str() {
                            let amount = U256::from_str(amount_str).unwrap_or_default();
                            if !amount.is_zero() {
                                staked_scilla_nodes.push(ScillaStakedNode {
                                    node: scilla_ssn_list[i].clone(),
                                    deleg_amt: amount,
                                    rewards: U256::ZERO,
                                });
                            }
                        }
                    }
                }
            }

            if !staked_scilla_nodes.is_empty() {
                let mut reward_data_requests = Vec::new();
                for (_i, staked_node) in staked_scilla_nodes.iter().enumerate() {
                    let scilla_user_addr_lower = SCILLA_USER_ADDRESS.to_lowercase();
                    reward_data_requests.push((
                        RpcProvider::<ChainConfig>::build_payload(
                            json!([
                                SCILLA_GZIL_CONTRACT,
                                "direct_deposit_deleg",
                                [
                                    scilla_user_addr_lower.clone(),
                                    staked_node.node.address.clone()
                                ]
                            ]),
                            ZilMethods::GetSmartContractSubState,
                        ),
                        RequestType::ScillaDirectDeposit,
                    ));
                    reward_data_requests.push((
                        RpcProvider::<ChainConfig>::build_payload(
                            json!([
                                SCILLA_GZIL_CONTRACT,
                                "buff_deposit_deleg",
                                [
                                    scilla_user_addr_lower.clone(),
                                    staked_node.node.address.clone()
                                ]
                            ]),
                            ZilMethods::GetSmartContractSubState,
                        ),
                        RequestType::ScillaBuffDeposit,
                    ));
                    reward_data_requests.push((
                        RpcProvider::<ChainConfig>::build_payload(
                            json!([
                                SCILLA_GZIL_CONTRACT,
                                "deleg_stake_per_cycle",
                                [
                                    scilla_user_addr_lower.clone(),
                                    staked_node.node.address.clone()
                                ]
                            ]),
                            ZilMethods::GetSmartContractSubState,
                        ),
                        RequestType::ScillaDelegStakePerCycle,
                    ));
                    reward_data_requests.push((
                        RpcProvider::<ChainConfig>::build_payload(
                            json!([
                                SCILLA_GZIL_CONTRACT,
                                "stake_ssn_per_cycle",
                                [staked_node.node.address.clone()]
                            ]),
                            ZilMethods::GetSmartContractSubState,
                        ),
                        RequestType::ScillaStakeSsnPerCycle,
                    ));
                }

                // Chunking requests to avoid hitting RPC limits
                let mut handles = Vec::new();
                for chunk in reward_data_requests.chunks(25) {
                    let config = self.config.clone();
                    let chunk: Vec<_> = chunk.iter().map(|(p, _)| p.clone()).collect();
                    let handle = tokio::spawn(async move {
                        let provider = RpcProvider::new(&config);
                        provider.req::<Vec<ResultRes<Value>>>(chunk.into()).await
                    });
                    handles.push(handle);
                }

                let mut flattened_responses = Vec::new();
                for handle in handles {
                    match handle.await {
                        Ok(rpc_result) => match rpc_result {
                            Ok(responses_chunk) => flattened_responses.extend(responses_chunk),
                            Err(rpc_err) => return Err(NetworkErrors::Request(rpc_err)),
                        },
                        Err(join_err) => {
                            return Err(NetworkErrors::RPCError(format!(
                                "Task join error: {}",
                                join_err
                            )))
                        }
                    }
                }

                for (i, node) in staked_scilla_nodes.iter_mut().enumerate() {
                    let scilla_user_addr_lower = SCILLA_USER_ADDRESS.to_lowercase();
                    let direct_res = &flattened_responses[i * 4];
                    let buff_res = &flattened_responses[i * 4 + 1];
                    let deleg_cycle_res = &flattened_responses[i * 4 + 2];
                    let stake_ssn_cycle_res = &flattened_responses[i * 4 + 3];

                    let direct_deposit_deleg_map: HashMap<String, String> = direct_res
                        .result
                        .as_ref()
                        .and_then(|r| r.get("direct_deposit_deleg"))
                        .and_then(|d| d.get(&scilla_user_addr_lower))
                        .and_then(|d| d.get(&node.node.address))
                        .and_then(|m| serde_json::from_value(m.clone()).ok())
                        .unwrap_or_default();
                    let buffer_deposit_deleg_map: HashMap<String, String> = buff_res
                        .result
                        .as_ref()
                        .and_then(|r| r.get("buff_deposit_deleg"))
                        .and_then(|d| d.get(&scilla_user_addr_lower))
                        .and_then(|d| d.get(&node.node.address))
                        .and_then(|m| serde_json::from_value(m.clone()).ok())
                        .unwrap_or_default();
                    let deleg_stake_per_cycle_map: HashMap<String, String> = deleg_cycle_res
                        .result
                        .as_ref()
                        .and_then(|r| r.get("deleg_stake_per_cycle"))
                        .and_then(|d| d.get(&scilla_user_addr_lower))
                        .and_then(|d| d.get(&node.node.address))
                        .and_then(|m| serde_json::from_value(m.clone()).ok())
                        .unwrap_or_default();
                    let stake_ssn_per_cycle_map: HashMap<String, (U256, U256)> =
                        stake_ssn_cycle_res
                            .result
                            .as_ref()
                            .and_then(|r| r.get("stake_ssn_per_cycle"))
                            .and_then(|d| d.get(&node.node.address))
                            .and_then(|m| {
                                if let Some(map) = m.as_object() {
                                    let mut new_map = HashMap::new();
                                    for (k, v) in map {
                                        if let Some(arr) =
                                            v.get("arguments").and_then(|a| a.as_array())
                                        {
                                            if arr.len() == 2 {
                                                let val1 = arr[0]
                                                    .as_str()
                                                    .and_then(|s| U256::from_str(s).ok())
                                                    .unwrap_or_default();
                                                let val2 = arr[1]
                                                    .as_str()
                                                    .and_then(|s| U256::from_str(s).ok())
                                                    .unwrap_or_default();
                                                new_map.insert(k.clone(), (val1, val2));
                                            }
                                        }
                                    }
                                    Some(new_map)
                                } else {
                                    None
                                }
                            })
                            .unwrap_or_default();

                    let reward_need_list = get_reward_need_cycle_list(
                        node.node.last_withdraw_cycle_deleg,
                        node.node.last_reward_cycle,
                    );
                    if !reward_need_list.is_empty() {
                        let delegate_per_cycle = combine_buff_direct(
                            &reward_need_list,
                            &direct_deposit_deleg_map,
                            &buffer_deposit_deleg_map,
                            &deleg_stake_per_cycle_map,
                        );
                        node.rewards = calculate_rewards(
                            &delegate_per_cycle,
                            &reward_need_list,
                            &stake_ssn_per_cycle_map,
                        );
                    }
                }

                for sn in staked_scilla_nodes {
                    final_output.push(FinalOutput {
                        name: sn.node.name,
                        url: sn.node.url,
                        address: sn.node.address,
                        token_address: None,
                        deleg_amt: sn.deleg_amt.to_string(),
                        rewards: sn.rewards.to_string(),
                        tvl: None,
                        vote_power: None,
                        apr: None,
                        tag: "scilla".to_string(),
                    });
                }
            }
        }

        final_output.sort_by(|a, b| {
            let a_amt = U256::from_str(&a.deleg_amt).unwrap_or_default();
            let b_amt = U256::from_str(&b.deleg_amt).unwrap_or_default();
            b_amt.cmp(&a_amt).then_with(|| a.name.cmp(&b.name))
        });

        Ok(final_output)
    }
}

#[cfg(test)]
mod tests {
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

        let _ = provider.get_zq2_providers().await.unwrap();
    }

    #[tokio::test]
    async fn test_get_all_stakes() {
        let net_conf = create_zilliqa_config();
        let provider = NetworkProvider::new(net_conf);

        let list = provider.get_all_stakes().await.unwrap();

        dbg!(&list);

        // Should not panic and return a list of staking pools
        assert!(!list.is_empty());
        println!("Fetched {} staking pools.", list.len());
    }
}
