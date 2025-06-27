use crate::provider::NetworkProvider;
use alloy::{
    hex,
    primitives::{Address as AlloyAddress, U256},
    sol,
    sol_types::SolCall,
};
use async_trait::async_trait;
use config::contracts::{DEPOSIT_ADDRESS, SCILLA_GZIL_CONTRACT, ST_ZIL_CONTRACT};
use errors::network::NetworkErrors;
use proto::address::Address;
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
    pub token_decimals: u32,
    pub token_symbol: String,
}

#[derive(Clone, Debug)]
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
}

#[derive(Debug, Clone)]
pub enum EvmRequestType {
    DelegAmt,
    Rewards,
    PoolStake,
    Commission,
    Tvl,
}

#[derive(Debug, Clone)]
pub struct EvmRequestInfo {
    pub pool: EvmPool,
    pub req_type: EvmRequestType,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FinalOutput {
    pub name: String,
    pub url: String,
    pub address: String,
    pub token_address: Option<String>,
    pub deleg_amt: U256,
    pub rewards: U256,
    pub tvl: Option<String>,
    pub vote_power: Option<f64>,
    pub apr: Option<f64>,
    pub commission: Option<f64>,
    pub tag: String,
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

fn get_reward_need_cycle_list(last_withdraw_cycle: u64, last_reward_cycle: u64) -> Vec<u64> {
    if last_reward_cycle <= last_withdraw_cycle {
        return Vec::new();
    }
    (last_withdraw_cycle + 1..=last_reward_cycle).collect()
}

fn combine_buff_direct(
    reward_list: &[u64],
    direct_deposit_map: &HashMap<u64, U256>,
    buffer_deposit_map: &HashMap<u64, U256>,
    deleg_stake_per_cycle_map: &HashMap<u64, U256>,
) -> HashMap<u64, U256> {
    let mut result_map = HashMap::new();
    let zero = U256::from(0);

    for &cycle in reward_list {
        let c1 = cycle - 1;
        let c2 = cycle - 2;

        let hist_amt = deleg_stake_per_cycle_map.get(&c1).unwrap_or(&zero);
        let dir_amt = direct_deposit_map.get(&c1).unwrap_or(&zero);
        let buf_amt = buffer_deposit_map.get(&c2).unwrap_or(&zero);

        let total_amt_tmp = dir_amt + buf_amt + hist_amt;
        let previous_cycle_amt = result_map.get(&c1).unwrap_or(&zero);
        let total_amt = total_amt_tmp + previous_cycle_amt;

        result_map.insert(cycle, total_amt);
    }

    result_map
}

fn calculate_rewards(
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

fn build_initial_core_requests(
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

    let ids = InitialCoreIds {
        ssn_list: ssn_list_id,
        reward_cycle: reward_cycle_id,
        withdraw_cycle: withdraw_cycle_id,
        st_zil_balance: st_zil_balance_id,
        total_network_stake: total_network_stake_id,
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
    ];

    (requests, ids, start_id)
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
    }

    (requests, evm_request_map, start_id)
}

fn process_avely_stake(
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
        })
    } else {
        None
    }
}

fn process_evm_pools_results(
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
                if let Ok(decoded) = getCommissionCall::abi_decode_returns(&bytes) {
                    pool_stats.commission_num = Some(decoded._0);
                    pool_stats.commission_den = Some(decoded._1);
                }
            }
        }
    }

    (temp_evm_user_data, temp_evm_pool_stats)
}

#[async_trait]
pub trait ZilliqaStakeing {
    async fn get_zq2_providers(&self) -> std::result::Result<Vec<EvmPool>, NetworkErrors>;
}

#[async_trait]
impl ZilliqaStakeing for NetworkProvider {
    async fn get_zq2_providers(&self) -> std::result::Result<Vec<EvmPool>, NetworkErrors> {
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
    use rpc::network_config::ChainConfig;
    use std::str::FromStr;

    fn get_proto_mainnet_pools() -> Vec<EvmPool> {
        vec![
            EvmPool {
                token_symbol: "shit".to_string(),
                address: AlloyAddress::from_str("0xA0572935d53e14C73eBb3de58d319A9Fe51E1FC8")
                    .unwrap(),
                token_address: AlloyAddress::from_str("0x0000000000000000000000000000000000000000")
                    .unwrap(),
                name: "Moonlet".to_string(),
                pool_type: StakingPoolType::NORMAL,
                token_decimals: 18,
            },
            EvmPool {
                token_decimals: 18,
                token_symbol: "shit".to_string(),
                address: AlloyAddress::from_str("0x2Abed3a598CBDd8BB9089c09A9202FD80C55Df8c")
                    .unwrap(),
                token_address: AlloyAddress::from_str("0xD8B61fed51b9037A31C2Bf0a5dA4B717AF0C0F78")
                    .unwrap(),
                name: "AtomicWallet".to_string(),
                pool_type: StakingPoolType::LIQUID,
            },
        ]
    }

    #[test]
    fn test_build_initial_core_requests() {
        let scilla_user_address = "0x77e27c39ce572283b848e2cdf32cce761e34fa49";
        let (requests, ids, next_id) = build_initial_core_requests(1, scilla_user_address);

        assert_eq!(requests.len(), 5);
        assert_eq!(next_id, 6);

        assert_eq!(ids.ssn_list, 1);
        assert_eq!(ids.reward_cycle, 2);
        assert_eq!(ids.withdraw_cycle, 3);
        assert_eq!(ids.st_zil_balance, 4);
        assert_eq!(ids.total_network_stake, 5);

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
    }

    #[test]
    fn test_build_evm_pools_requests() {
        let pools = get_proto_mainnet_pools();
        let evm_user_address =
            Address::from_eth_address("0xb1fE20CD2b856BA1a4e08afb39dfF5C80f0cBbCa").unwrap();
        let (requests, req_map, next_id) = build_evm_pools_requests(&pools, &evm_user_address, 1);

        assert_eq!(requests.len(), 9); // 5 for NORMAL, 4 for LIQUID
        assert_eq!(req_map.len(), 9);
        assert_eq!(next_id, 10);

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

        let ts_stake_101 = U256::from(10000) + U256::from(1000) + U256::from(200); // 11200
        let ts_stake_102 = U256::from(11000) + U256::from(500) + U256::from(300) + ts_stake_101; // 23000
        let ts_stake_103 = U256::from(12000) + U256::from(0) + U256::from(0) + ts_stake_102; // 35000
        let ts_stake_104 = U256::from(0) + U256::from(0) + U256::from(0) + ts_stake_103; // 35000
        let ts_stake_105 = U256::from(0) + U256::from(0) + U256::from(0) + ts_stake_104; // 35000

        let reward_101 = (ts_stake_101 * U256::from(50000)) / U256::from(1_000_000); // 560
        let reward_102 = (ts_stake_102 * U256::from(55000)) / U256::from(1_100_000); // 1150
        let reward_103 = (ts_stake_103 * U256::from(60000)) / U256::from(1_200_000); // 1750
        let reward_104 = (ts_stake_104 * U256::from(65000)) / U256::from(1_300_000); // 1750
        let reward_105 = (ts_stake_105 * U256::from(70000)) / U256::from(1_400_000); // 1750

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
