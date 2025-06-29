use crate::provider::NetworkProvider;
use alloy::{
    hex,
    primitives::{utils::format_units, Address as AlloyAddress, TxKind, U256},
    sol,
    sol_types::SolCall,
};
use config::contracts::{DEPOSIT_ADDRESS, SCILLA_GZIL_CONTRACT, ST_ZIL_CONTRACT};
use errors::network::NetworkErrors;
use proto::{address::Address, tx::ETHTransactionRequest};
use rpc::{
    methods::{EvmMethods, ZilMethods},
    network_config::ChainConfig,
    provider::RpcProvider,
    zil_interfaces::ResultRes,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;

sol! {
    function getFutureTotalStake() external view returns (uint256);
    function balanceOf(address account) external view returns (uint256 balance);
    function totalSupply() external view returns (uint256);
    function getDelegatedAmount() external view returns (uint256);
    function rewards() external view returns (uint256);
    function getDelegatedTotal() external view returns (uint256);
    function getStake() external view returns (uint256);
    function getCommission() external view returns (uint256, uint256);
    function getPendingClaims() external view returns (uint256[2][] memory claims);

    function stake() external payable;
    function unstake(uint256 shares) external;
    function claim() external;
    function withdrawAllRewards() external;
    function stakeRewards() external;
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum StakingPoolType {
    LIQUID,
    NORMAL,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EvmPool {
    pub token_address: AlloyAddress,
    pub pool_type: StakingPoolType,
    pub address: AlloyAddress,
    pub name: String,
    pub token_decimals: u8,
    pub token_symbol: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct CycleInfo {
    pub total_stake: U256,
    pub total_rewards: U256,
}

#[derive(Debug)]
pub struct InitialCoreIds {
    pub ssn_list: u64,
    pub reward_cycle: u64,
    pub withdraw_cycle: u64,
    pub st_zil_balance: u64,
    pub total_network_stake: u64,
    pub withdrawal_pending: u64,
    pub blockchain_info: u64,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct BlockchainInfo {
    pub num_tx_blocks: String,
}

#[derive(Deserialize)]
struct ScillaCycleInfoJson {
    arguments: (String, String),
}

#[derive(Debug, Clone, PartialEq)]
pub enum EvmRequestType {
    DelegAmt,
    Rewards,
    PoolStake,
    Commission,
    Tvl,
    PendingWithdrawal,
}

#[derive(Debug, Clone)]
pub struct EvmRequestInfo {
    pub pool: EvmPool,
    pub req_type: EvmRequestType,
}

#[derive(Debug, Deserialize, Clone, PartialEq)]
pub struct SsnDeleg {
    pub argtypes: Vec<serde_json::Value>,
    pub arguments: Vec<serde_json::Value>,
    pub constructor: String,
}

#[derive(Debug, Clone)]
pub struct SSNode {
    pub address: String,
    pub last_reward_cycle: u64,
    pub last_withdraw_cycle_deleg: u64,
    pub name: String,
    pub url: String,
}

#[derive(Debug)]
pub struct ScillaStakedNode {
    pub node: SSNode,
    pub deleg_amt: U256,
    pub rewards: U256,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct FinalOutput {
    pub name: String,
    pub url: String,
    pub address: String,
    pub token_address: Option<String>,
    pub deleg_amt: U256,
    pub rewards: U256,
    pub tvl: Option<u128>,
    pub vote_power: Option<f64>,
    pub apr: Option<f64>,
    pub commission: Option<f64>,
    pub tag: String,
    pub withdrawal_block: Option<u64>,
    pub current_block: Option<u64>,
}

#[derive(Debug, Default, Clone)]
pub struct EvmUserData {
    pub deleg_amt: U256,
    pub rewards: U256,
}

#[derive(Debug, Default, Clone)]
pub struct EvmPoolStats {
    pub tvl: Option<U256>,
    pub pool_stake: Option<U256>,
    pub commission_num: Option<U256>,
    pub commission_den: Option<U256>,
}

pub type EvmRequestMap = HashMap<u64, EvmRequestInfo>;

pub fn build_stake_request(amount: U256, delegator_address: AlloyAddress) -> ETHTransactionRequest {
    let stake_call = stakeCall {};
    let to = TxKind::Call(delegator_address);
    let req_tx = ETHTransactionRequest {
        value: Some(amount),
        to: Some(to),
        input: stake_call.abi_encode().into(),
        ..Default::default()
    };

    return req_tx;
}

pub fn build_unstake_request(
    amount_to_unstake: U256,
    provider: AlloyAddress,
) -> ETHTransactionRequest {
    let unstake_call = unstakeCall {
        shares: amount_to_unstake,
    };
    let to = TxKind::Call(provider);
    let req_tx = ETHTransactionRequest {
        input: unstake_call.abi_encode().into(),
        to: Some(to),
        ..Default::default()
    };

    return req_tx;
}

pub fn build_claim_unstake_request(delegator_address: AlloyAddress) -> ETHTransactionRequest {
    let claim_call = claimCall {};
    let to = TxKind::Call(delegator_address);
    let req_tx = ETHTransactionRequest {
        input: claim_call.abi_encode().into(),
        to: Some(to),
        ..Default::default()
    };

    return req_tx;
}

pub fn build_claim_reward_request(delegator_address: AlloyAddress) -> ETHTransactionRequest {
    let withdraw_rewards_call = withdrawAllRewardsCall {};
    let to = TxKind::Call(delegator_address);
    let req_tx = ETHTransactionRequest {
        input: withdraw_rewards_call.abi_encode().into(),
        to: Some(to),
        ..Default::default()
    };

    return req_tx;
}

pub fn get_reward_need_cycle_list(last_withdraw_cycle: u64, last_reward_cycle: u64) -> Vec<u64> {
    if last_reward_cycle <= last_withdraw_cycle {
        return Vec::new();
    }
    (last_withdraw_cycle + 1..=last_reward_cycle).collect()
}

pub fn combine_buff_direct(
    reward_list: &[u64],
    direct_deposit_map: &HashMap<u64, U256>,
    buffer_deposit_map: &HashMap<u64, U256>,
    deleg_stake_per_cycle_map: &HashMap<u64, U256>,
) -> HashMap<u64, U256> {
    let mut result_map = HashMap::new();
    let zero = U256::from(0);

    for &cycle in reward_list {
        let c1_key = if cycle >= 1 { Some(cycle - 1) } else { None };
        let c2_key = if cycle >= 2 { Some(cycle - 2) } else { None };

        let hist_amt = c1_key
            .and_then(|k| deleg_stake_per_cycle_map.get(&k))
            .unwrap_or(&zero);
        let dir_amt = c1_key
            .and_then(|k| direct_deposit_map.get(&k))
            .unwrap_or(&zero);
        let buf_amt = c2_key
            .and_then(|k| buffer_deposit_map.get(&k))
            .unwrap_or(&zero);

        let total_amt_tmp = dir_amt + buf_amt + hist_amt;

        let previous_cycle_amt = c1_key.and_then(|k| result_map.get(&k)).unwrap_or(&zero);
        let total_amt = total_amt_tmp + previous_cycle_amt;

        result_map.insert(cycle, total_amt);
    }

    result_map
}

pub fn calculate_rewards(
    delegate_per_cycle: &HashMap<u64, U256>,
    need_list: &[u64],
    stake_ssn_per_cycle_map: &HashMap<u64, CycleInfo>,
) -> U256 {
    let mut result_rewards = U256::from(0);
    let zero = U256::from(0);

    for &cycle in need_list {
        if let Some(cycle_info) = stake_ssn_per_cycle_map.get(&cycle) {
            if let Some(deleg_amt) = delegate_per_cycle.get(&cycle) {
                if cycle_info.total_stake > zero {
                    let reward_for_cycle =
                        (deleg_amt * &cycle_info.total_rewards) / &cycle_info.total_stake;
                    result_rewards += reward_for_cycle;
                }
            }
        }
    }

    result_rewards
}

pub fn build_initial_core_requests(
    mut start_id: u64,
    scilla_user_address: &str,
) -> (Vec<Value>, InitialCoreIds, u64) {
    let ssn_list_id = start_id;
    start_id += 1;
    let reward_cycle_id = start_id;
    start_id += 1;
    let withdraw_cycle_id = start_id;
    start_id += 1;
    let st_zil_balance_id = start_id;
    start_id += 1;
    let total_network_stake_id = start_id;
    start_id += 1;
    let withdrawal_pending_id = start_id;
    start_id += 1;
    let blockchain_info_id = start_id;
    start_id += 1;

    let ids = InitialCoreIds {
        ssn_list: ssn_list_id,
        reward_cycle: reward_cycle_id,
        withdraw_cycle: withdraw_cycle_id,
        st_zil_balance: st_zil_balance_id,
        total_network_stake: total_network_stake_id,
        withdrawal_pending: withdrawal_pending_id,
        blockchain_info: blockchain_info_id,
    };

    let scilla_user_address_lower = scilla_user_address.to_lowercase();
    let get_future_total_stake_call = getFutureTotalStakeCall {};

    let requests = vec![
        RpcProvider::<ChainConfig>::build_payload(
            json!([SCILLA_GZIL_CONTRACT, "ssnlist", []]),
            ZilMethods::GetSmartContractSubState,
        )
        .with_id(ssn_list_id),
        RpcProvider::<ChainConfig>::build_payload(
            json!([SCILLA_GZIL_CONTRACT, "lastrewardcycle", []]),
            ZilMethods::GetSmartContractSubState,
        )
        .with_id(reward_cycle_id),
        RpcProvider::<ChainConfig>::build_payload(
            json!([
                SCILLA_GZIL_CONTRACT,
                "last_withdraw_cycle_deleg",
                [scilla_user_address]
            ]),
            ZilMethods::GetSmartContractSubState,
        )
        .with_id(withdraw_cycle_id),
        RpcProvider::<ChainConfig>::build_payload(
            json!([ST_ZIL_CONTRACT, "balances", [scilla_user_address_lower]]),
            ZilMethods::GetSmartContractSubState,
        )
        .with_id(st_zil_balance_id),
        RpcProvider::<ChainConfig>::build_payload(
            json!([{
                "to": DEPOSIT_ADDRESS,
                "data": hex::encode_prefixed(get_future_total_stake_call.abi_encode())
            }, "latest"]),
            EvmMethods::Call,
        )
        .with_id(total_network_stake_id),
        RpcProvider::<ChainConfig>::build_payload(
            json!([
                SCILLA_GZIL_CONTRACT,
                "withdrawal_pending",
                [scilla_user_address]
            ]),
            ZilMethods::GetSmartContractSubState,
        )
        .with_id(withdrawal_pending_id),
        RpcProvider::<ChainConfig>::build_payload(json!([]), ZilMethods::GetBlockchainInfo)
            .with_id(blockchain_info_id),
    ];

    (requests, ids, start_id)
}

pub fn process_pending_withdrawals(
    withdrawal_pending_result: Option<&&ResultRes<Value>>,
    blockchain_info_result: Option<&&ResultRes<Value>>,
    scilla_user_address: &str,
) -> Vec<FinalOutput> {
    let current_block = blockchain_info_result
        .and_then(|res| res.result.as_ref())
        .and_then(|r| serde_json::from_value::<BlockchainInfo>(r.clone()).ok())
        .and_then(|info| info.num_tx_blocks.parse::<u64>().ok())
        .unwrap_or(0);

    let scilla_user_address_lower = scilla_user_address.to_lowercase();
    let withdrawals: HashMap<String, String> = withdrawal_pending_result
        .and_then(|res| res.result.as_ref())
        .and_then(|r| r.get("withdrawal_pending"))
        .and_then(|wp| wp.get(&scilla_user_address_lower))
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();

    let mut withdrawal_block: Option<u64> = None;
    let mut claimable_amount = U256::ZERO;

    for (block_str, amount_str) in withdrawals {
        if let (Ok(block), Ok(amount)) = (block_str.parse::<u64>(), amount_str.parse::<U256>()) {
            withdrawal_block = Some(block);
            claimable_amount = amount;
        }
    }

    let mut outputs = Vec::new();

    if claimable_amount > U256::ZERO {
        outputs.push(FinalOutput {
            withdrawal_block,
            current_block: Some(current_block),
            name: "Pending Withdrawal (Claimable)".to_string(),
            address: SCILLA_GZIL_CONTRACT.to_string(),
            deleg_amt: claimable_amount,
            tag: "withdrawal".to_string(),
            ..Default::default()
        });
    }

    outputs
}

pub fn assemble_evm_final_output(
    pools: &[EvmPool],
    user_data: &HashMap<AlloyAddress, EvmUserData>,
    pool_stats: &HashMap<AlloyAddress, EvmPoolStats>,
    total_network_stake: U256,
) -> Vec<FinalOutput> {
    let mut final_output: Vec<FinalOutput> = Vec::new();

    for pool in pools {
        let user_entry = user_data.get(&pool.address).cloned().unwrap_or_default();
        let stats_entry = pool_stats.get(&pool.address);

        let tvl_is_zero = stats_entry.and_then(|s| s.tvl).unwrap_or(U256::ZERO) <= U256::ZERO;
        if user_entry.deleg_amt <= U256::ZERO && tvl_is_zero {
            continue;
        }

        let mut output_entry = FinalOutput {
            name: pool.name.clone(),
            url: "".to_string(),
            address: format!("{:#x}", pool.address),
            token_address: Some(format!("{:#x}", pool.token_address)),
            deleg_amt: user_entry.deleg_amt,
            rewards: user_entry.rewards,
            tag: "evm".to_string(),
            ..Default::default()
        };

        if let Some(stats) = stats_entry {
            if let Some(tvl) = stats.tvl {
                output_entry.tvl = tvl.to_string().parse().ok();
            }

            if let (Some(pool_stake), Some(commission_num), Some(commission_den)) =
                (stats.pool_stake, stats.commission_num, stats.commission_den)
            {
                if total_network_stake > U256::ZERO {
                    let vp_ratio_float = f64::from(pool_stake) / f64::from(total_network_stake);
                    output_entry.vote_power =
                        Some((vp_ratio_float * 100.0 * 10000.0).round() / 10000.0);
                    if commission_den > U256::ZERO {
                        let rewards_per_year_in_zil = 51000.0 * 24.0 * 365.0;

                        let commission_ratio_float =
                            f64::from(commission_num) / f64::from(commission_den);
                        output_entry.commission =
                            Some((commission_ratio_float * 100.0 * 10000.0).round() / 10000.0);

                        let delegator_year_reward = vp_ratio_float * rewards_per_year_in_zil;
                        let delegator_reward_for_share =
                            delegator_year_reward * (1.0 - commission_ratio_float);

                        let pool_stake_in_zil: f64 = format_units(pool_stake, 18)
                            .unwrap_or_default()
                            .parse()
                            .unwrap_or_default();

                        if pool_stake_in_zil > 0.0 {
                            let apr = (delegator_reward_for_share / pool_stake_in_zil) * 100.0;
                            output_entry.apr = Some((apr * 10000.0).round() / 10000.0);
                        } else {
                            output_entry.apr = Some(0.0);
                        }
                    } else {
                        output_entry.commission = Some(0.0);
                        output_entry.apr = Some(0.0);
                    }
                } else {
                    output_entry.vote_power = Some(0.0);
                    output_entry.commission = Some(0.0);
                    output_entry.apr = Some(0.0);
                }
            }
        }
        final_output.push(output_entry);
    }

    final_output
}

pub async fn process_scilla_stakes(
    provider: &NetworkProvider,
    ssn_result: &ResultRes<Value>,
    reward_cycle_result: &ResultRes<Value>,
    withdraw_cycle_result: &ResultRes<Value>,
    scilla_user_address: &str,
) -> Result<Vec<FinalOutput>, NetworkErrors> {
    let ssn_list_val = ssn_result
        .result
        .as_ref()
        .and_then(|r| r.get("ssnlist"))
        .ok_or(NetworkErrors::ResponseParseError)?;

    let ssn_raw_map: HashMap<String, SsnDeleg> = serde_json::from_value(ssn_list_val.clone())
        .map_err(|e| NetworkErrors::ParseHttpError(format!("Failed to parse ssn_list: {}", e)))?;

    let last_reward_cycle_str = reward_cycle_result
        .result
        .as_ref()
        .and_then(|r| r.get("lastrewardcycle"))
        .and_then(|c| c.as_str())
        .ok_or(NetworkErrors::ResponseParseError)?;
    let last_reward_cycle = last_reward_cycle_str
        .parse::<u64>()
        .map_err(|_| NetworkErrors::ResponseParseError)?;

    let last_withdraw_nodes: HashMap<String, u64> = withdraw_cycle_result
        .result
        .as_ref()
        .and_then(|r| r.get("last_withdraw_cycle_deleg"))
        .and_then(|d| d.get(scilla_user_address))
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();

    let all_ssn_nodes: Vec<SSNode> = ssn_raw_map
        .into_iter()
        .filter_map(|(key, val)| {
            let name_val = val.arguments.get(3)?;
            let url_val = val.arguments.get(5)?;

            let name = name_val.as_str()?.to_string();
            let url = url_val.as_str()?.to_string();

            Some(SSNode {
                name,
                url,
                last_withdraw_cycle_deleg: *last_withdraw_nodes.get(&key).unwrap_or(&0),
                address: key,
                last_reward_cycle,
            })
        })
        .collect();

    let deleg_amt_requests: Vec<Value> = all_ssn_nodes
        .iter()
        .enumerate()
        .map(|(i, node)| {
            RpcProvider::<ChainConfig>::build_payload(
                json!([
                    SCILLA_GZIL_CONTRACT,
                    "ssn_deleg_amt",
                    [node.address, scilla_user_address]
                ]),
                ZilMethods::GetSmartContractSubState,
            )
            .with_id(i as u64)
        })
        .collect();

    let deleg_amt_results: Vec<ResultRes<Value>> = provider
        .proxy_req(json!(deleg_amt_requests).to_string())
        .await?
        .as_array()
        .ok_or(NetworkErrors::ResponseParseError)?
        .iter()
        .map(|v| serde_json::from_value(v.clone()))
        .collect::<Result<_, _>>()
        .map_err(|e| NetworkErrors::ParseHttpError(e.to_string()))?;

    let mut staked_scilla_nodes: Vec<ScillaStakedNode> = Vec::new();
    for res in deleg_amt_results {
        let node = &all_ssn_nodes[res.id as usize];
        if let Some(delegations) = res
            .result
            .as_ref()
            .and_then(|r| r.get("ssn_deleg_amt"))
            .and_then(|d| d.get(&node.address))
            .and_then(|a| a.get(scilla_user_address))
        {
            if let Some(amount_str) = delegations.as_str() {
                if let Ok(amount_qa) = amount_str.parse::<U256>() {
                    if amount_qa > U256::ZERO {
                        staked_scilla_nodes.push(ScillaStakedNode {
                            node: node.clone(),
                            deleg_amt: amount_qa,
                            rewards: U256::ZERO,
                        });
                    }
                }
            }
        }
    }

    if staked_scilla_nodes.is_empty() {
        return Ok(Vec::new());
    }

    let scilla_user_address_lower = scilla_user_address.to_lowercase();
    let reward_data_requests: Vec<Value> = staked_scilla_nodes
        .iter()
        .enumerate()
        .flat_map(|(i, staked_node)| {
            vec![
                RpcProvider::<ChainConfig>::build_payload(
                    json!([
                        SCILLA_GZIL_CONTRACT,
                        "direct_deposit_deleg",
                        [&scilla_user_address_lower, &staked_node.node.address]
                    ]),
                    ZilMethods::GetSmartContractSubState,
                )
                .with_id((i * 4 + 1) as u64),
                RpcProvider::<ChainConfig>::build_payload(
                    json!([
                        SCILLA_GZIL_CONTRACT,
                        "buff_deposit_deleg",
                        [&scilla_user_address_lower, &staked_node.node.address]
                    ]),
                    ZilMethods::GetSmartContractSubState,
                )
                .with_id((i * 4 + 2) as u64),
                RpcProvider::<ChainConfig>::build_payload(
                    json!([
                        SCILLA_GZIL_CONTRACT,
                        "deleg_stake_per_cycle",
                        [&scilla_user_address_lower, &staked_node.node.address]
                    ]),
                    ZilMethods::GetSmartContractSubState,
                )
                .with_id((i * 4 + 3) as u64),
                RpcProvider::<ChainConfig>::build_payload(
                    json!([
                        SCILLA_GZIL_CONTRACT,
                        "stake_ssn_per_cycle",
                        [&staked_node.node.address]
                    ]),
                    ZilMethods::GetSmartContractSubState,
                )
                .with_id((i * 4 + 4) as u64),
            ]
        })
        .collect();

    let reward_data_results: Vec<ResultRes<Value>> = provider
        .proxy_req(json!(reward_data_requests).to_string())
        .await?
        .as_array()
        .ok_or(NetworkErrors::ResponseParseError)?
        .iter()
        .map(|v| serde_json::from_value(v.clone()))
        .collect::<Result<_, _>>()
        .map_err(|e| NetworkErrors::ParseHttpError(e.to_string()))?;

    let reward_results_by_id: HashMap<u64, ResultRes<Value>> =
        reward_data_results.into_iter().map(|r| (r.id, r)).collect();

    for (i, staked_node) in staked_scilla_nodes.iter_mut().enumerate() {
        let direct_res = reward_results_by_id.get(&((i * 4 + 1) as u64));
        let buff_res = reward_results_by_id.get(&((i * 4 + 2) as u64));
        let deleg_cycle_res = reward_results_by_id.get(&((i * 4 + 3) as u64));
        let stake_ssn_cycle_res = reward_results_by_id.get(&((i * 4 + 4) as u64));

        let direct_map: HashMap<u64, U256> = direct_res
            .and_then(|res| res.result.as_ref())
            .and_then(|r| r.get("direct_deposit_deleg"))
            .and_then(|d| d.get(&scilla_user_address_lower))
            .and_then(|a| a.get(&staked_node.node.address))
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default();
        let buffer_map: HashMap<u64, U256> = buff_res
            .and_then(|res| res.result.as_ref())
            .and_then(|r| r.get("buff_deposit_deleg"))
            .and_then(|d| d.get(&scilla_user_address_lower))
            .and_then(|a| a.get(&staked_node.node.address))
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default();
        let deleg_cycle_map: HashMap<u64, U256> = deleg_cycle_res
            .and_then(|res| res.result.as_ref())
            .and_then(|r| r.get("deleg_stake_per_cycle"))
            .and_then(|d| d.get(&scilla_user_address_lower))
            .and_then(|a| a.get(&staked_node.node.address))
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default();
        let stake_ssn_map_raw: HashMap<String, ScillaCycleInfoJson> = stake_ssn_cycle_res
            .and_then(|res| res.result.as_ref())
            .and_then(|r| r.get("stake_ssn_per_cycle"))
            .and_then(|d| d.get(&staked_node.node.address))
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default();
        let stake_ssn_map: HashMap<u64, CycleInfo> = stake_ssn_map_raw
            .into_iter()
            .filter_map(|(cycle_str, data)| {
                let cycle = cycle_str.parse::<u64>().ok()?;
                let total_stake = data.arguments.0.parse().ok()?;
                let total_rewards = data.arguments.1.parse().ok()?;
                Some((
                    cycle,
                    CycleInfo {
                        total_stake,
                        total_rewards,
                    },
                ))
            })
            .collect();

        let reward_need_list = get_reward_need_cycle_list(
            staked_node.node.last_withdraw_cycle_deleg,
            staked_node.node.last_reward_cycle,
        );
        if !reward_need_list.is_empty() {
            let delegate_per_cycle = combine_buff_direct(
                &reward_need_list,
                &direct_map,
                &buffer_map,
                &deleg_cycle_map,
            );
            staked_node.rewards =
                calculate_rewards(&delegate_per_cycle, &reward_need_list, &stake_ssn_map);
        }
    }

    Ok(staked_scilla_nodes
        .into_iter()
        .map(|sn| FinalOutput {
            name: sn.node.name,
            url: sn.node.url,
            address: sn.node.address,
            deleg_amt: sn.deleg_amt,
            rewards: sn.rewards,
            tag: "scilla".to_string(),
            ..Default::default()
        })
        .collect())
}

pub fn build_evm_pools_requests(
    pools: &[EvmPool],
    evm_user_address: &Address,
    mut start_id: u64,
) -> (Vec<Value>, EvmRequestMap, u64) {
    let mut requests = Vec::new();
    let mut evm_request_map = EvmRequestMap::new();
    let build_payload = RpcProvider::<ChainConfig>::build_payload;
    let alloy_evm_user_addr = evm_user_address.to_alloy_addr();

    for pool in pools {
        let deleg_amt_id = start_id;
        start_id += 1;
        let deleg_amt_req = if pool.pool_type == StakingPoolType::LIQUID {
            let balance_of_call = balanceOfCall {
                account: alloy_evm_user_addr,
            };
            build_payload(
                json!([{ "to": pool.token_address, "data": hex::encode_prefixed(balance_of_call.abi_encode()) }, "latest"]),
                EvmMethods::Call,
            )
        } else {
            let get_delegated_amount_call = getDelegatedAmountCall {};
            build_payload(
                json!([{ "to": pool.address, "data": hex::encode_prefixed(get_delegated_amount_call.abi_encode()), "from": evm_user_address.to_string() }, "latest"]),
                EvmMethods::Call,
            )
        };
        requests.push(deleg_amt_req.with_id(deleg_amt_id));
        evm_request_map.insert(
            deleg_amt_id,
            EvmRequestInfo {
                pool: pool.clone(),
                req_type: EvmRequestType::DelegAmt,
            },
        );

        if pool.pool_type == StakingPoolType::NORMAL {
            let rewards_id = start_id;
            start_id += 1;
            let rewards_call = rewardsCall {};
            let rewards_req = build_payload(
                json!([{ "to": pool.address, "data": hex::encode_prefixed(rewards_call.abi_encode()), "from": evm_user_address.to_string() }, "latest"]),
                EvmMethods::Call,
            );
            requests.push(rewards_req.with_id(rewards_id));
            evm_request_map.insert(
                rewards_id,
                EvmRequestInfo {
                    pool: pool.clone(),
                    req_type: EvmRequestType::Rewards,
                },
            );
        }

        let tvl_id = start_id;
        start_id += 1;
        let tvl_req = if pool.pool_type == StakingPoolType::LIQUID {
            let total_supply_call = totalSupplyCall {};
            build_payload(
                json!([{ "to": pool.token_address, "data": hex::encode_prefixed(total_supply_call.abi_encode()) }, "latest"]),
                EvmMethods::Call,
            )
        } else {
            let get_delegated_total_call = getDelegatedTotalCall {};
            build_payload(
                json!([{ "to": pool.address, "data": hex::encode_prefixed(get_delegated_total_call.abi_encode()) }, "latest"]),
                EvmMethods::Call,
            )
        };
        requests.push(tvl_req.with_id(tvl_id));
        evm_request_map.insert(
            tvl_id,
            EvmRequestInfo {
                pool: pool.clone(),
                req_type: EvmRequestType::Tvl,
            },
        );

        let pool_stake_id = start_id;
        start_id += 1;
        let get_stake_call = getStakeCall {};
        let pool_stake_req = build_payload(
            json!([{ "to": pool.address, "data": hex::encode_prefixed(get_stake_call.abi_encode()) }, "latest"]),
            EvmMethods::Call,
        );
        requests.push(pool_stake_req.with_id(pool_stake_id));
        evm_request_map.insert(
            pool_stake_id,
            EvmRequestInfo {
                pool: pool.clone(),
                req_type: EvmRequestType::PoolStake,
            },
        );

        let commission_id = start_id;
        start_id += 1;
        let get_commission_call = getCommissionCall {};
        let commission_req = build_payload(
            json!([{ "to": pool.address, "data": hex::encode_prefixed(get_commission_call.abi_encode()) }, "latest"]),
            EvmMethods::Call,
        );
        requests.push(commission_req.with_id(commission_id));
        evm_request_map.insert(
            commission_id,
            EvmRequestInfo {
                pool: pool.clone(),
                req_type: EvmRequestType::Commission,
            },
        );

        let pending_withdrawal_id = start_id;
        start_id += 1;
        let get_pending_claims_call = getPendingClaimsCall {};
        let pending_withdrawal_req = build_payload(
            json!([{ "to": pool.address, "data": hex::encode_prefixed(get_pending_claims_call.abi_encode()), "from": evm_user_address.to_string() }, "latest"]),
            EvmMethods::Call,
        );
        requests.push(pending_withdrawal_req.with_id(pending_withdrawal_id));
        evm_request_map.insert(
            pending_withdrawal_id,
            EvmRequestInfo {
                pool: pool.clone(),
                req_type: EvmRequestType::PendingWithdrawal,
            },
        );
    }

    (requests, evm_request_map, start_id)
}

pub fn process_avely_stake(
    st_zil_result: Option<&&ResultRes<Value>>,
    scilla_user_address: &str,
) -> Option<FinalOutput> {
    let scilla_user_address_lower = scilla_user_address.to_lowercase();
    let st_zil_balance = st_zil_result
        .and_then(|res| res.result.as_ref())
        .and_then(|r| r.get("balances"))
        .and_then(|b| b.get(&scilla_user_address_lower))
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse().ok())
        .unwrap_or_default();

    if st_zil_balance > U256::ZERO {
        Some(FinalOutput {
            name: "stZIL (Avely Finance)".to_string(),
            url: "https://avely.fi/".to_string(),
            address: ST_ZIL_CONTRACT.to_string(),
            deleg_amt: st_zil_balance,
            rewards: U256::ZERO,
            tag: "avely".to_string(),
            token_address: None,
            tvl: None,
            vote_power: None,
            apr: None,
            commission: None,
            ..Default::default()
        })
    } else {
        None
    }
}

pub fn process_evm_pools_results(
    results_by_id: &HashMap<u64, ResultRes<Value>>,
    evm_request_map: &EvmRequestMap,
) -> (
    HashMap<AlloyAddress, EvmUserData>,
    HashMap<AlloyAddress, EvmPoolStats>,
) {
    let mut temp_evm_user_data = HashMap::new();
    let mut temp_evm_pool_stats = HashMap::new();

    for (id, res) in results_by_id {
        let req_info = match evm_request_map.get(id) {
            Some(info) => info,
            None => continue,
        };

        if res.error.is_some() {
            continue;
        }

        if req_info.req_type == EvmRequestType::PendingWithdrawal {
            continue;
        }

        let result_str = match res.result.as_ref().and_then(|r| r.as_str()) {
            Some(s) if s != "0x" => s,
            _ => continue,
        };

        let bytes = match hex::decode(result_str.trim_start_matches("0x")) {
            Ok(b) => b,
            Err(_) => continue,
        };

        let pool_address = req_info.pool.address;
        let user_data: &mut EvmUserData = temp_evm_user_data.entry(pool_address).or_default();
        let pool_stats: &mut EvmPoolStats = temp_evm_pool_stats.entry(pool_address).or_default();

        match req_info.req_type {
            EvmRequestType::DelegAmt => {
                let decoded_amt = if req_info.pool.pool_type == StakingPoolType::LIQUID {
                    balanceOfCall::abi_decode_returns(&bytes)
                        .ok()
                        .map(|decoded| decoded)
                } else {
                    getDelegatedAmountCall::abi_decode_returns(&bytes)
                        .ok()
                        .map(|decoded| decoded)
                };
                if let Some(amt) = decoded_amt {
                    user_data.deleg_amt = amt;
                }
            }
            EvmRequestType::Rewards => {
                if let Ok(decoded) = rewardsCall::abi_decode_returns(&bytes) {
                    user_data.rewards = decoded;
                }
            }
            EvmRequestType::Tvl => {
                let decoded_tvl = if req_info.pool.pool_type == StakingPoolType::LIQUID {
                    totalSupplyCall::abi_decode_returns(&bytes)
                        .ok()
                        .map(|decoded| decoded)
                } else {
                    getDelegatedTotalCall::abi_decode_returns(&bytes)
                        .ok()
                        .map(|decoded| decoded)
                };
                if let Some(tvl) = decoded_tvl {
                    pool_stats.tvl = Some(tvl);
                }
            }
            EvmRequestType::PoolStake => {
                if let Ok(decoded) = getStakeCall::abi_decode_returns(&bytes) {
                    pool_stats.pool_stake = Some(decoded);
                }
            }
            EvmRequestType::Commission => {
                let decoded_commission = getCommissionCall::abi_decode_returns(&bytes);
                if let Ok(decoded) = decoded_commission {
                    pool_stats.commission_num = Some(decoded._0);
                    pool_stats.commission_den = Some(decoded._1);
                } else {
                    pool_stats.commission_num = Some(U256::ZERO);
                    pool_stats.commission_den = Some(U256::from(1));
                }
            }
            EvmRequestType::PendingWithdrawal => {}
        }
    }

    (temp_evm_user_data, temp_evm_pool_stats)
}

pub fn process_evm_pending_withdrawals(
    results_by_id: &HashMap<u64, ResultRes<Value>>,
    evm_request_map: &EvmRequestMap,
    current_block: u64,
) -> Vec<FinalOutput> {
    let mut final_outputs = Vec::new();

    for (id, res) in results_by_id {
        let req_info = match evm_request_map.get(id) {
            Some(info) => info,
            None => continue,
        };

        if req_info.req_type != EvmRequestType::PendingWithdrawal {
            continue;
        }

        if res.error.is_some() {
            continue;
        }

        let result_str = match res.result.as_ref().and_then(|r| r.as_str()) {
            Some(s) if s != "0x" => s,
            _ => continue,
        };

        let bytes = match hex::decode(result_str.trim_start_matches("0x")) {
            Ok(b) => b,
            Err(_) => continue,
        };

        if let Ok(decoded) = getPendingClaimsCall::abi_decode_returns(&bytes) {
            for claim in decoded {
                let withdrawal_block = claim[0].to::<u64>();
                let amount = claim[1];

                if amount > U256::ZERO {
                    let is_claimable = withdrawal_block <= current_block;
                    let name = if is_claimable {
                        format!("Pending Withdrawal from {} (Claimable)", req_info.pool.name)
                    } else {
                        format!("Pending Withdrawal from {}", req_info.pool.name)
                    };
                    final_outputs.push(FinalOutput {
                        name,
                        url: "".to_string(),
                        address: format!("{:#x}", req_info.pool.address),
                        deleg_amt: amount,
                        tag: "withdrawalEVM".to_string(),
                        withdrawal_block: Some(withdrawal_block),
                        current_block: Some(current_block),
                        ..Default::default()
                    });
                }
            }
        }
    }
    final_outputs
}

trait WithId {
    fn with_id(self, id: u64) -> Self;
}

impl WithId for Value {
    fn with_id(mut self, id: u64) -> Self {
        if let Some(obj) = self.as_object_mut() {
            obj.insert("id".to_string(), json!(id));
        }
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn get_proto_mainnet_pools() -> Vec<EvmPool> {
        vec![
            EvmPool {
                address: AlloyAddress::from_str("0xA0572935d53e14C73eBb3de58d319A9Fe51E1FC8")
                    .unwrap(),
                token_address: AlloyAddress::ZERO,
                name: "Moonlet".to_string(),
                pool_type: StakingPoolType::NORMAL,
                token_decimals: 18,
                token_symbol: "ZIL".to_string(),
            },
            EvmPool {
                address: AlloyAddress::from_str("0x2Abed3a598CBDd8BB9089c09A9202FD80C55Df8c")
                    .unwrap(),
                token_address: AlloyAddress::from_str("0xD8B61fed51b9037A31C2Bf0a5dA4B717AF0C0F78")
                    .unwrap(),
                name: "AtomicWallet".to_string(),
                pool_type: StakingPoolType::LIQUID,
                token_decimals: 18,
                token_symbol: "SHARK".to_string(),
            },
            EvmPool {
                address: AlloyAddress::from_str("0xB9d689c64b969ad9eDd1EDDb50be42E217567fd3")
                    .unwrap(),
                token_address: AlloyAddress::ZERO,
                name: "CEX.IO".to_string(),
                pool_type: StakingPoolType::NORMAL,
                token_decimals: 18,
                token_symbol: "ZIL".to_string(),
            },
            EvmPool {
                address: AlloyAddress::from_str("0xe0C095DBE85a8ca75de4749B5AEe0D18100a3C39")
                    .unwrap(),
                token_address: AlloyAddress::from_str("0x7B213b5AEB896bC290F0cD8B8720eaF427098186")
                    .unwrap(),
                name: "PlunderSwap".to_string(),
                pool_type: StakingPoolType::LIQUID,
                token_decimals: 18,
                token_symbol: "pZIL".to_string(),
            },
            EvmPool {
                address: AlloyAddress::from_str("0xC0247d13323F1D06b6f24350Eea03c5e0Fbf65ed")
                    .unwrap(),
                token_address: AlloyAddress::from_str("0x2c51C97b22E73AfD33911397A20Aa5176e7Ab951")
                    .unwrap(),
                name: "Luganodes".to_string(),
                pool_type: StakingPoolType::LIQUID,
                token_decimals: 18,
                token_symbol: "LNZIL".to_string(),
            },
            EvmPool {
                address: AlloyAddress::from_str("0x8A0dEd57ABd3bc50A600c94aCbEcEf62db5f4D32")
                    .unwrap(),
                token_address: AlloyAddress::ZERO,
                name: "DTEAM".to_string(),
                pool_type: StakingPoolType::NORMAL,
                token_decimals: 18,
                token_symbol: "ZIL".to_string(),
            },
            EvmPool {
                address: AlloyAddress::from_str("0x3b1Cd55f995a9A8A634fc1A3cEB101e2baA636fc")
                    .unwrap(),
                token_address: AlloyAddress::ZERO,
                name: "Shardpool".to_string(),
                pool_type: StakingPoolType::NORMAL,
                token_decimals: 18,
                token_symbol: "ZIL".to_string(),
            },
            EvmPool {
                address: AlloyAddress::from_str("0x66a2bb4AD6999966616B2ad209833260F8eA07C8")
                    .unwrap(),
                token_address: AlloyAddress::from_str("0xA1Adc08C12c684AdB28B963f251d6cB1C6a9c0c1")
                    .unwrap(),
                name: "Encapsulate".to_string(),
                pool_type: StakingPoolType::LIQUID,
                token_decimals: 18,
                token_symbol: "encapZIL".to_string(),
            },
            EvmPool {
                address: AlloyAddress::from_str("0xe59D98b887e6D40F52f7Cc8d5fb4CF0F9Ed7C98B")
                    .unwrap(),
                token_address: AlloyAddress::from_str("0xf564DF9BeB417FB50b38A58334CA7607B36D3BFb")
                    .unwrap(),
                name: "Amazing Pool - Avely and ZilPay".to_string(),
                pool_type: StakingPoolType::LIQUID,
                token_decimals: 18,
                token_symbol: "stZIL".to_string(),
            },
            EvmPool {
                address: AlloyAddress::from_str("0xd090424684a9108229b830437b490363eB250A58")
                    .unwrap(),
                token_address: AlloyAddress::from_str("0xE10575244f8E8735d71ed00287e9d1403f03C960")
                    .unwrap(),
                name: "PathrockNetwork".to_string(),
                pool_type: StakingPoolType::LIQUID,
                token_decimals: 18,
                token_symbol: "zLST".to_string(),
            },
            EvmPool {
                address: AlloyAddress::from_str("0x33cDb55D7fD68d0Da1a3448F11bCdA5fDE3426B3")
                    .unwrap(),
                token_address: AlloyAddress::ZERO,
                name: "BlackNodes".to_string(),
                pool_type: StakingPoolType::NORMAL,
                token_decimals: 18,
                token_symbol: "ZIL".to_string(),
            },
            EvmPool {
                address: AlloyAddress::from_str("0x35118Af4Fc43Ce58CEcBC6Eeb21D0C1Eb7E28Bd3")
                    .unwrap(),
                token_address: AlloyAddress::from_str("0x245E6AB0d092672B18F27025385f98E2EC3a3275")
                    .unwrap(),
                name: "Lithium Digital".to_string(),
                pool_type: StakingPoolType::LIQUID,
                token_decimals: 18,
                token_symbol: "litZil".to_string(),
            },
            EvmPool {
                address: AlloyAddress::from_str("0x62269F615E1a3E36f96dcB7fDDF8B823737DD618")
                    .unwrap(),
                token_address: AlloyAddress::from_str("0x770a35A5A95c2107860E9F74c1845e20289cbfe6")
                    .unwrap(),
                name: "TorchWallet.io".to_string(),
                pool_type: StakingPoolType::LIQUID,
                token_decimals: 18,
                token_symbol: "tZIL".to_string(),
            },
            EvmPool {
                address: AlloyAddress::from_str("0xa45114E92E26B978F0B37cF19E66634f997250f9")
                    .unwrap(),
                token_address: AlloyAddress::ZERO,
                name: "Stakefish".to_string(),
                pool_type: StakingPoolType::NORMAL,
                token_decimals: 18,
                token_symbol: "ZIL".to_string(),
            },
            EvmPool {
                address: AlloyAddress::from_str("0x02376bA9e0f98439eA9F76A582FBb5d20E298177")
                    .unwrap(),
                token_address: AlloyAddress::ZERO,
                name: "AlphaZIL (former Ezil)".to_string(),
                pool_type: StakingPoolType::NORMAL,
                token_decimals: 18,
                token_symbol: "ZIL".to_string(),
            },
        ]
    }

    #[test]
    fn test_process_pending_withdrawals() {
        let scilla_user_address = "0x77e27c39ce572283b848e2cdf32cce761e34fa49";
        let scilla_user_address_lower = scilla_user_address.to_lowercase();
        let withdrawal_json = json!({
            "withdrawal_pending": {
                scilla_user_address_lower: {
                    "4944395": "100000000000000",
                    "5000000": "200000000000000"
                }
            }
        });
        let blockchain_info_json = json!({
            "NumTxBlocks": "4944537"
        });

        let withdrawal_res = ResultRes {
            id: 1,
            jsonrpc: "2.0".to_string(),
            result: Some(withdrawal_json),
            error: None,
        };
        let blockchain_info_res = ResultRes {
            id: 2,
            jsonrpc: "2.0".to_string(),
            result: Some(blockchain_info_json),
            error: None,
        };

        let output = process_pending_withdrawals(
            Some(&&withdrawal_res),
            Some(&&blockchain_info_res),
            scilla_user_address,
        );

        assert_eq!(output.len(), 2);
        let claimable = output
            .iter()
            .find(|o| o.name.contains("Claimable"))
            .unwrap();
        let unclaimable = output
            .iter()
            .find(|o| o.name.contains("Unclaimable"))
            .unwrap();

        assert_eq!(
            claimable.deleg_amt,
            U256::from_str("100000000000000").unwrap()
        );
        assert_eq!(claimable.tag, "withdrawal");
        assert_eq!(claimable.address, SCILLA_GZIL_CONTRACT);

        assert_eq!(
            unclaimable.deleg_amt,
            U256::from_str("200000000000000").unwrap()
        );
        assert_eq!(unclaimable.tag, "withdrawal");
    }

    #[test]
    fn test_process_evm_pools_results_with_real_data() {
        let pools = get_proto_mainnet_pools();
        let evm_user_address =
            Address::from_eth_address("0xb1fE20CD2b856BA1a4e08afb39dfF5C80f0cBbCa").unwrap();

        let (_requests, req_map, _next_id) = build_evm_pools_requests(&pools, &evm_user_address, 5);

        let mut mock_results: HashMap<u64, ResultRes<Value>> = HashMap::new();

        let raw_data = [(
            41,
            "0x000000000000000000000000000000000000000000084595161401484a000000",
        )];
        for (id, result) in raw_data {
            mock_results.insert(
                id,
                ResultRes {
                    id,
                    jsonrpc: "2.0".to_string(),
                    result: Some(json!(result)),
                    error: None,
                },
            );
        }

        let (user_data, _pool_stats) = process_evm_pools_results(&mock_results, &req_map);

        let amazing_pool_addr =
            AlloyAddress::from_str("0xe59D98b887e6D40F52f7Cc8d5fb4CF0F9Ed7C98B").unwrap();
        let amazing_pool_user = user_data.get(&amazing_pool_addr).unwrap();

        assert_eq!(
            amazing_pool_user.deleg_amt,
            U256::from_str("10000000000000000000000000").unwrap()
        );
        assert_eq!(amazing_pool_user.rewards, U256::ZERO);

        let moonlet_addr =
            AlloyAddress::from_str("0xA0572935d53e14C73eBb3de58d319A9Fe51E1FC8").unwrap();

        let moonlet_user = user_data.get(&moonlet_addr).cloned().unwrap_or_default();
        assert_eq!(moonlet_user.deleg_amt, U256::ZERO);
        assert_eq!(moonlet_user.rewards, U256::ZERO);
    }

    #[test]
    fn test_assemble_evm_final_output_with_real_data() {
        let pools = get_proto_mainnet_pools();
        let total_network_stake = U256::from_str("630535302503909246899505609").unwrap();

        let mut user_data = HashMap::new();
        user_data.insert(
            AlloyAddress::from_str("0xe59D98b887e6D40F52f7Cc8d5fb4CF0F9Ed7C98B").unwrap(),
            EvmUserData {
                deleg_amt: U256::from_str("10000000000000000000000000").unwrap(),
                rewards: U256::ZERO,
            },
        );

        let mut pool_stats = HashMap::new();
        pool_stats.insert(
            AlloyAddress::from_str("0xA0572935d53e14C73eBb3de58d319A9Fe51E1FC8").unwrap(),
            EvmPoolStats {
                tvl: Some(U256::from_str("10237287493646143508392206").unwrap()),
                pool_stake: Some(U256::from_str("10237287493646143508392206").unwrap()),
                commission_num: Some(U256::from(800)),
                commission_den: Some(U256::from(10000)),
            },
        );
        pool_stats.insert(
            AlloyAddress::from_str("0x2Abed3a598CBDd8BB9089c09A9202FD80C55Df8c").unwrap(),
            EvmPoolStats {
                tvl: Some(U256::from_str("10034888021342446971735205").unwrap()),
                pool_stake: Some(U256::from_str("10508052748385519195925337").unwrap()),
                commission_num: Some(U256::from(800)),
                commission_den: Some(U256::from(10000)),
            },
        );
        pool_stats.insert(
            AlloyAddress::from_str("0xB9d689c64b969ad9eDd1EDDb50be42E217567fd3").unwrap(),
            EvmPoolStats {
                tvl: Some(U256::from_str("21946110000000000000000000").unwrap()),
                pool_stake: Some(U256::from_str("21946110000000000000000000").unwrap()),
                commission_num: Some(U256::from(800)),
                commission_den: Some(U256::from(10000)),
            },
        );
        pool_stats.insert(
            AlloyAddress::from_str("0xe0C095DBE85a8ca75de4749B5AEe0D18100a3C39").unwrap(),
            EvmPoolStats {
                tvl: Some(U256::from_str("11672633461235654575276049").unwrap()),
                pool_stake: Some(U256::from_str("13287312536846802617691049").unwrap()),
                commission_num: Some(U256::from(800)),
                commission_den: Some(U256::from(10000)),
            },
        );
        pool_stats.insert(
            AlloyAddress::from_str("0xC0247d13323F1D06b6f24350Eea03c5e0Fbf65ed").unwrap(),
            EvmPoolStats {
                tvl: Some(U256::from_str("11005021076167994104091571").unwrap()),
                pool_stake: Some(U256::from_str("11259881828752700222853569").unwrap()),
                commission_num: Some(U256::from(1000)),
                commission_den: Some(U256::from(10000)),
            },
        );
        pool_stats.insert(
            AlloyAddress::from_str("0x8A0dEd57ABd3bc50A600c94aCbEcEf62db5f4D32").unwrap(),
            EvmPoolStats {
                tvl: Some(U256::from_str("10012398000000000000000000").unwrap()),
                pool_stake: Some(U256::from_str("10012398000000000000000000").unwrap()),
                commission_num: Some(U256::from(1000)),
                commission_den: Some(U256::from(10000)),
            },
        );
        pool_stats.insert(
            AlloyAddress::from_str("0x3b1Cd55f995a9A8A634fc1A3cEB101e2baA636fc").unwrap(),
            EvmPoolStats {
                tvl: Some(U256::from_str("10024751000000000000000000").unwrap()),
                pool_stake: Some(U256::from_str("10024751000000000000000000").unwrap()),
                commission_num: Some(U256::from(1000)),
                commission_den: Some(U256::from(10000)),
            },
        );
        pool_stats.insert(
            AlloyAddress::from_str("0x66a2bb4AD6999966616B2ad209833260F8eA07C8").unwrap(),
            EvmPoolStats {
                tvl: Some(U256::from_str("10016872167542680756663733").unwrap()),
                pool_stake: Some(U256::from_str("10312028053449932803340906").unwrap()),
                commission_num: Some(U256::from(800)),
                commission_den: Some(U256::from(10000)),
            },
        );
        pool_stats.insert(
            AlloyAddress::from_str("0xe59D98b887e6D40F52f7Cc8d5fb4CF0F9Ed7C98B").unwrap(),
            EvmPoolStats {
                tvl: Some(U256::from_str("20693380675539100961364497").unwrap()),
                pool_stake: Some(U256::from_str("21602479861384281430978136").unwrap()),
                commission_num: Some(U256::from(800)),
                commission_den: Some(U256::from(10000)),
            },
        );
        pool_stats.insert(
            AlloyAddress::from_str("0xd090424684a9108229b830437b490363eB250A58").unwrap(),
            EvmPoolStats {
                tvl: Some(U256::from_str("10000299874698857153672725").unwrap()),
                pool_stake: Some(U256::from_str("10000300000000000000000000").unwrap()),
                commission_num: Some(U256::from(1000)),
                commission_den: Some(U256::from(10000)),
            },
        );
        pool_stats.insert(
            AlloyAddress::from_str("0x33cDb55D7fD68d0Da1a3448F11bCdA5fDE3426B3").unwrap(),
            EvmPoolStats {
                tvl: Some(U256::from_str("10009995000000000000000000").unwrap()),
                pool_stake: Some(U256::from_str("10009995000000000000000000").unwrap()),
                commission_num: Some(U256::from(670)),
                commission_den: Some(U256::from(10000)),
            },
        );
        pool_stats.insert(
            AlloyAddress::from_str("0x35118Af4Fc43Ce58CEcBC6Eeb21D0C1Eb7E28Bd3").unwrap(),
            EvmPoolStats {
                tvl: Some(U256::from_str("10000487380928487718028066").unwrap()),
                pool_stake: Some(U256::from_str("10290079859948883024222433").unwrap()),
                commission_num: Some(U256::from(1000)),
                commission_den: Some(U256::from(10000)),
            },
        );
        pool_stats.insert(
            AlloyAddress::from_str("0x62269F615E1a3E36f96dcB7fDDF8B823737DD618").unwrap(),
            EvmPoolStats {
                tvl: Some(U256::from_str("10240697410747595477291763").unwrap()),
                pool_stake: Some(U256::from_str("10542298122494984096102119").unwrap()),
                commission_num: Some(U256::from(800)),
                commission_den: Some(U256::from(10000)),
            },
        );
        pool_stats.insert(
            AlloyAddress::from_str("0xa45114E92E26B978F0B37cF19E66634f997250f9").unwrap(),
            EvmPoolStats {
                tvl: Some(U256::from_str("10000628000000000000000000").unwrap()),
                pool_stake: Some(U256::from_str("10000628000000000000000000").unwrap()),
                commission_num: Some(U256::from(1000)),
                commission_den: Some(U256::from(10000)),
            },
        );
        pool_stats.insert(
            AlloyAddress::from_str("0x02376bA9e0f98439eA9F76A582FBb5d20E298177").unwrap(),
            EvmPoolStats {
                tvl: Some(U256::from_str("10501300000000000000000000").unwrap()),
                pool_stake: Some(U256::from_str("10501300000000000000000000").unwrap()),
                commission_num: Some(U256::from(800)),
                commission_den: Some(U256::from(10000)),
            },
        );

        let final_output =
            assemble_evm_final_output(&pools, &user_data, &pool_stats, total_network_stake);

        assert_eq!(final_output.len(), 15);

        let moonlet_output = final_output.iter().find(|p| p.name == "Moonlet").unwrap();
        assert_eq!(moonlet_output.deleg_amt, U256::ZERO);
        assert!((moonlet_output.commission.unwrap() - 8.0).abs() < 1e-4);
        assert!((moonlet_output.vote_power.unwrap() - 1.6235).abs() < 1e-4);

        let amazing_output = final_output
            .iter()
            .find(|p| p.name == "Amazing Pool - Avely and ZilPay")
            .unwrap();
        assert_eq!(
            amazing_output.deleg_amt,
            U256::from_str("10000000000000000000000000").unwrap()
        );
        assert!((amazing_output.commission.unwrap() - 8.0).abs() < 1e-4);
        assert!((amazing_output.vote_power.unwrap() - 3.4260).abs() < 1e-4);
    }

    #[test]
    fn test_build_initial_core_requests() {
        let scilla_user_address = "0x77e27c39ce572283b848e2cdf32cce761e34fa49";
        let (requests, ids, next_id) = build_initial_core_requests(1, scilla_user_address);

        assert_eq!(requests.len(), 7);
        assert_eq!(next_id, 8);

        assert_eq!(ids.ssn_list, 1);
        assert_eq!(ids.reward_cycle, 2);
        assert_eq!(ids.withdraw_cycle, 3);
        assert_eq!(ids.st_zil_balance, 4);
        assert_eq!(ids.total_network_stake, 5);
        assert_eq!(ids.withdrawal_pending, 6);
        assert_eq!(ids.blockchain_info, 7);

        let req1 = &requests[0];
        assert_eq!(req1["id"], 1);
        assert_eq!(req1["method"], "GetSmartContractSubState");
        assert_eq!(req1["params"], json!([SCILLA_GZIL_CONTRACT, "ssnlist", []]));

        let req3 = &requests[2];
        assert_eq!(req3["id"], 3);
        assert_eq!(req3["method"], "GetSmartContractSubState");
        assert_eq!(
            req3["params"],
            json!([
                SCILLA_GZIL_CONTRACT,
                "last_withdraw_cycle_deleg",
                [scilla_user_address]
            ])
        );

        let req5 = &requests[4];
        let get_future_total_stake_call = getFutureTotalStakeCall {};
        assert_eq!(req5["id"], 5);
        assert_eq!(req5["method"], "eth_call");
        assert_eq!(req5["params"][0]["to"], json!(DEPOSIT_ADDRESS.to_string()));
        assert_eq!(
            req5["params"][0]["data"],
            json!(hex::encode_prefixed(
                get_future_total_stake_call.abi_encode()
            ))
        );

        let req6 = &requests[5];
        assert_eq!(req6["id"], 6);
        assert_eq!(req6["method"], "GetSmartContractSubState");
        assert_eq!(
            req6["params"],
            json!([
                SCILLA_GZIL_CONTRACT,
                "withdrawal_pending",
                [scilla_user_address]
            ])
        );

        let req7 = &requests[6];
        assert_eq!(req7["id"], 7);
        assert_eq!(req7["method"], "GetBlockchainInfo");
        assert_eq!(req7["params"], json!([]));
    }

    #[test]
    fn test_build_evm_pools_requests() {
        let pools = get_proto_mainnet_pools();
        let evm_user_address =
            Address::from_eth_address("0xb1fE20CD2b856BA1a4e08afb39dfF5C80f0cBbCa").unwrap();
        let (requests, req_map, next_id) = build_evm_pools_requests(&pools, &evm_user_address, 1);

        assert_eq!(requests.len(), 67);
        assert_eq!(req_map.len(), 67);
        assert_eq!(next_id, 68);

        let moonlet_info = req_map.get(&1).unwrap();
        assert_eq!(moonlet_info.pool.name, "Moonlet");
        match moonlet_info.req_type {
            EvmRequestType::DelegAmt => (),
            _ => panic!("Incorrect request type"),
        }

        let moonlet_deleg_req = requests.iter().find(|r| r["id"] == 1).unwrap();
        assert_eq!(moonlet_deleg_req["method"], "eth_call");
        assert_eq!(
            moonlet_deleg_req["params"][0]["to"].as_str().unwrap(),
            "0xa0572935d53e14c73ebb3de58d319a9fe51e1fc8"
        );
        let get_delegated_amount_call = getDelegatedAmountCall {};
        assert_eq!(
            moonlet_deleg_req["params"][0]["data"],
            json!(hex::encode_prefixed(get_delegated_amount_call.abi_encode()))
        );

        let atomic_info = req_map.get(&6).unwrap();
        assert_eq!(atomic_info.pool.name, "AtomicWallet");
        match atomic_info.req_type {
            EvmRequestType::DelegAmt => (),
            _ => panic!("Incorrect request type"),
        }

        let atomic_deleg_req = requests.iter().find(|r| r["id"] == 6).unwrap();
        let balance_of_call = balanceOfCall {
            account: evm_user_address.to_alloy_addr(),
        };
        assert_eq!(
            atomic_deleg_req["params"][0]["to"].as_str().unwrap(),
            "0xd8b61fed51b9037a31c2bf0a5da4b717af0c0f78"
        );
        assert_eq!(
            atomic_deleg_req["params"][0]["data"],
            json!(hex::encode_prefixed(balance_of_call.abi_encode()))
        );

        let moonlet_commission_req = requests.iter().find(|r| r["id"] == 5).unwrap();
        let get_commission_call = getCommissionCall {};
        assert_eq!(
            moonlet_commission_req["params"][0]["data"],
            json!(hex::encode_prefixed(get_commission_call.abi_encode()))
        );
    }

    #[test]
    fn test_reward_calculation_matches_ts_logic() {
        let last_withdraw = 100;
        let last_reward = 105;

        let mut direct_map = HashMap::new();
        direct_map.insert(100, U256::from(1000));
        direct_map.insert(101, U256::from(500));

        let mut buffer_map = HashMap::new();
        buffer_map.insert(99, U256::from(200));
        buffer_map.insert(100, U256::from(300));

        let mut deleg_map = HashMap::new();
        deleg_map.insert(100, U256::from(10000));
        deleg_map.insert(101, U256::from(11000));
        deleg_map.insert(102, U256::from(12000));

        let mut ssn_stake_map = HashMap::new();
        ssn_stake_map.insert(
            101,
            CycleInfo {
                total_stake: U256::from(1_000_000),
                total_rewards: U256::from(50000),
            },
        );
        ssn_stake_map.insert(
            102,
            CycleInfo {
                total_stake: U256::from(1_100_000),
                total_rewards: U256::from(55000),
            },
        );
        ssn_stake_map.insert(
            103,
            CycleInfo {
                total_stake: U256::from(1_200_000),
                total_rewards: U256::from(60000),
            },
        );
        ssn_stake_map.insert(
            104,
            CycleInfo {
                total_stake: U256::from(1_300_000),
                total_rewards: U256::from(65000),
            },
        );
        ssn_stake_map.insert(
            105,
            CycleInfo {
                total_stake: U256::from(1_400_000),
                total_rewards: U256::from(70000),
            },
        );

        let ts_stake_101 = U256::from(10000) + U256::from(1000) + U256::from(200);
        let ts_stake_102 = U256::from(11000) + U256::from(500) + U256::from(300) + ts_stake_101;
        let ts_stake_103 = U256::from(12000) + U256::from(0) + U256::from(0) + ts_stake_102;
        let ts_stake_104 = U256::from(0) + U256::from(0) + U256::from(0) + ts_stake_103;
        let ts_stake_105 = U256::from(0) + U256::from(0) + U256::from(0) + ts_stake_104;

        let reward_101 = (ts_stake_101 * U256::from(50000)) / U256::from(1_000_000);
        let reward_102 = (ts_stake_102 * U256::from(55000)) / U256::from(1_100_000);
        let reward_103 = (ts_stake_103 * U256::from(60000)) / U256::from(1_200_000);
        let reward_104 = (ts_stake_104 * U256::from(65000)) / U256::from(1_300_000);
        let reward_105 = (ts_stake_105 * U256::from(70000)) / U256::from(1_400_000);

        let total_rewards_ts = reward_101 + reward_102 + reward_103 + reward_104 + reward_105;

        let reward_cycles = get_reward_need_cycle_list(last_withdraw, last_reward);
        let stake_per_cycle =
            combine_buff_direct(&reward_cycles, &direct_map, &buffer_map, &deleg_map);
        let total_rewards_rust =
            calculate_rewards(&stake_per_cycle, &reward_cycles, &ssn_stake_map);

        assert_eq!(reward_cycles, vec![101, 102, 103, 104, 105]);

        assert_eq!(*stake_per_cycle.get(&101).unwrap(), ts_stake_101);
        assert_eq!(*stake_per_cycle.get(&102).unwrap(), ts_stake_102);
        assert_eq!(*stake_per_cycle.get(&103).unwrap(), ts_stake_103);
        assert_eq!(*stake_per_cycle.get(&104).unwrap(), ts_stake_104);
        assert_eq!(*stake_per_cycle.get(&105).unwrap(), ts_stake_105);

        assert_eq!(
            total_rewards_rust, total_rewards_ts,
            "The final reward calculation must match the TypeScript logic"
        );
    }
}
