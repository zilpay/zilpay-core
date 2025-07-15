use crate::stake::FinalOutput;
use crate::{
    provider::NetworkProvider,
    stake::{LPToken, PendingWithdrawal},
};
use alloy::{
    hex,
    primitives::{utils::format_units, Address as AlloyAddress, TxKind, U256},
    sol,
    sol_types::SolCall,
};
use config::contracts::{
    DEPOSIT_ADDRESS, SCILLA_GZIL_CONTRACT, SCILLA_STAKE_PROXY, ST_ZIL_CONTRACT,
};
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
    function getPrice() external view returns (uint256);

    function stake() external payable;
    function unstake(uint256 shares) external;
    function claim() external;
    function withdrawAllRewards() external;
    function stakeRewards() external;
}

#[derive(Deserialize, Debug)]
struct WithdrawalUnbonded {
    pub arguments: (String, String),
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EvmPoolV2 {
    pub address: AlloyAddress,
    pub token: Option<LPToken>,
    pub name: String,
    pub hide: bool,
    pub uptime: u8,
    pub can_stake: bool,
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
    pub unbonded_withdrawal: u64,
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum EvmRequestType {
    DelegAmt,
    Rewards,
    PoolStake,
    Commission,
    Tvl,
    PendingWithdrawal,
    Price,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EvmRequestInfo {
    pub pool: EvmPoolV2,
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
    pub price: Option<U256>,
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
    let unbonded_withdrawal_id = start_id;
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
        unbonded_withdrawal: unbonded_withdrawal_id,
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
            json!([
                ST_ZIL_CONTRACT,
                "withdrawal_unbonded",
                [scilla_user_address]
            ]),
            ZilMethods::GetSmartContractSubState,
        )
        .with_id(unbonded_withdrawal_id),
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
    unbonded_withdrawal_result: Option<&&ResultRes<Value>>,
    blockchain_info_result: Option<&&ResultRes<Value>>,
    scilla_user_address: &str,
) -> Vec<FinalOutput> {
    let current_block = blockchain_info_result
        .and_then(|res| res.result.as_ref())
        .and_then(|r| serde_json::from_value::<BlockchainInfo>(r.clone()).ok())
        .and_then(|info| info.num_tx_blocks.parse::<u64>().ok())
        .unwrap_or(0);

    let scilla_user_address_lower = scilla_user_address.to_lowercase();
    let mut outputs = Vec::new();

    let withdrawals: HashMap<String, String> = withdrawal_pending_result
        .and_then(|res| res.result.as_ref())
        .and_then(|r| r.get("withdrawal_pending"))
        .and_then(|wp| wp.get(&scilla_user_address_lower))
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();

    for (block_str, amount_str) in withdrawals {
        if let (Ok(block), Ok(amount)) = (block_str.parse::<u64>(), amount_str.parse::<U256>()) {
            if amount > U256::ZERO {
                outputs.push(FinalOutput {
                    current_block: Some(current_block),
                    name: "Pending Withdrawal (Claimable)".to_string(),
                    address: SCILLA_STAKE_PROXY.to_string(),
                    tag: "scilla".to_string(),
                    pending_withdrawals: vec![PendingWithdrawal {
                        amount,
                        withdrawal_block: block,
                        claimable: true,
                    }],
                    ..Default::default()
                });
            }
        }
    }

    let unbonded_withdrawal: Option<WithdrawalUnbonded> = unbonded_withdrawal_result
        .and_then(|res| res.result.as_ref())
        .and_then(|r| r.get("withdrawal_unbonded"))
        .and_then(|wu| wu.get(&scilla_user_address_lower))
        .and_then(|v| serde_json::from_value(v.clone()).ok());

    if let Some(unbonded) = unbonded_withdrawal {
        let zil = unbonded.arguments.1.parse::<U256>().unwrap_or_default();
        let st_zil = unbonded.arguments.0.parse::<U256>().unwrap_or_default();

        if zil > U256::ZERO {
            outputs.push(FinalOutput {
                name: "Avely Claim".to_string(),
                address: ST_ZIL_CONTRACT.to_string(),
                tag: "scilla".to_string(),
                rewards: st_zil,
                pending_withdrawals: vec![PendingWithdrawal {
                    amount: zil,
                    withdrawal_block: 0,
                    claimable: true,
                }],
                ..Default::default()
            });
        }
    }

    outputs
}

pub fn assemble_evm_final_output(
    pools: &[EvmPoolV2],
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
            address: format!("{:#x}", pool.address),
            token: pool.token.clone(),
            deleg_amt: user_entry.deleg_amt,
            rewards: user_entry.rewards,
            tag: "evm".to_string(),
            hide: pool.hide,
            uptime: pool.uptime,
            can_stake: pool.can_stake,
            ..Default::default()
        };

        if let Some(stats) = stats_entry {
            if let Some(tvl) = stats.tvl {
                output_entry.tvl = tvl.to_string().parse().ok();
            }

            if let Some(price_u256) = stats.price {
                let price_f64: f64 = format_units(price_u256, 18)
                    .unwrap_or_default()
                    .parse()
                    .unwrap_or_default();
                output_entry.price = Some(price_f64);
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
            address: sn.node.address,
            deleg_amt: sn.deleg_amt,
            rewards: sn.rewards,
            tag: "scilla".to_string(),
            ..Default::default()
        })
        .collect())
}

pub fn build_evm_pools_requests(
    pools: &[EvmPoolV2],
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
        let deleg_amt_req = if pool.token.is_some() {
            let balance_of_call = balanceOfCall {
                account: alloy_evm_user_addr,
            };
            build_payload(
                json!([{ "to": pool.token.clone().unwrap().address, "data": hex::encode_prefixed(balance_of_call.abi_encode()) }, "latest"]),
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

        if pool.token.is_none() {
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

        if pool.token.is_some() {
            let price_id = start_id;
            start_id += 1;
            let get_price_call = getPriceCall {};
            let price_req = build_payload(
                json!([{ "to": pool.address, "data": hex::encode_prefixed(get_price_call.abi_encode()) }, "latest"]),
                EvmMethods::Call,
            );
            requests.push(price_req.with_id(price_id));
            evm_request_map.insert(
                price_id,
                EvmRequestInfo {
                    pool: pool.clone(),
                    req_type: EvmRequestType::Price,
                },
            );
        }

        let tvl_id = start_id;
        start_id += 1;
        let tvl_req = if pool.token.is_some() {
            let total_supply_call = totalSupplyCall {};
            build_payload(
                json!([{ "to": pool.token.clone().unwrap().address, "data": hex::encode_prefixed(total_supply_call.abi_encode()) }, "latest"]),
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
            name: "Avely Finance".to_string(),
            address: ST_ZIL_CONTRACT.to_string(),
            deleg_amt: st_zil_balance,
            rewards: U256::ZERO,
            tag: "scilla".to_string(),
            token: None,
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
                let decoded_amt = if req_info.pool.token.is_some() {
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
            EvmRequestType::Price => {
                if let Ok(decoded) = getPriceCall::abi_decode_returns(&bytes) {
                    pool_stats.price = Some(decoded);
                }
            }
            EvmRequestType::Tvl => {
                let decoded_tvl = if req_info.pool.token.is_some() {
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
) -> HashMap<AlloyAddress, Vec<PendingWithdrawal>> {
    let mut withdrawals_by_pool: HashMap<AlloyAddress, Vec<PendingWithdrawal>> = HashMap::new();

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
                    let pending_withdrawal = PendingWithdrawal {
                        amount,
                        withdrawal_block,
                        claimable: withdrawal_block <= current_block,
                    };
                    withdrawals_by_pool
                        .entry(req_info.pool.address)
                        .or_default()
                        .push(pending_withdrawal);
                }
            }
        }
    }
    withdrawals_by_pool
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
