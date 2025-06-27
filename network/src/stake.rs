use crate::provider::NetworkProvider;
use alloy::primitives::{map::HashMap, utils::format_units, U256};
use async_trait::async_trait;
use errors::network::NetworkErrors;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Pool {
    pub address: String,
    pub token_address: String,
    pub name: String,
    pub pool_type: String,
    pub token_decimals: u32,
    pub token_symbol: String,
}

#[derive(Clone, Debug)]
pub struct CycleInfo {
    pub total_stake: U256,
    pub total_rewards: U256,
}

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
        // Find the cycle information for the SSN
        if let Some(cycle_info) = stake_ssn_per_cycle_map.get(&cycle) {
            // Find the user's delegated amount for that cycle
            if let Some(deleg_amt) = delegate_per_cycle.get(&cycle) {
                // Ensure total_stake is not zero to prevent division by zero errors.
                if cycle_info.total_stake > zero {
                    // Perform the reward calculation: (deleg_amt * total_rewards) / total_stake
                    let reward_for_cycle =
                        (deleg_amt * &cycle_info.total_rewards) / &cycle_info.total_stake;
                    result_rewards += reward_for_cycle;
                }
            }
        }
    }

    result_rewards
}

#[async_trait]
pub trait ZilliqaStakeing {
    async fn get_zq2_providers(&self) -> std::result::Result<Vec<Pool>, NetworkErrors>;
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

        let pools = provider.get_zq2_providers().await.unwrap();

        // dbg!(&pools);
    }

    #[test]
    fn test_reward_calculation_matches_ts_logic() {
        // --- 1. Setup test data ---
        let last_withdraw = 100;
        let last_reward = 105;

        let mut direct_map = HashMap::new();
        direct_map.insert(100, U256::from(1000));
        direct_map.insert(101, U256::from(500));

        let mut buffer_map = HashMap::new();
        buffer_map.insert(99, U256::from(200)); // for cycle 101
        buffer_map.insert(100, U256::from(300)); // for cycle 102

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

        // --- 2. Calculate expected results (mirroring TS logic) ---
        let ts_stake_101 = U256::from(10000) + U256::from(1000) + U256::from(200) + U256::from(0); // 11200
        let ts_stake_102 = U256::from(11000) + U256::from(500) + U256::from(300) + ts_stake_101; // 23000
        let ts_stake_103 = U256::from(12000) + U256::from(0) + U256::from(0) + ts_stake_102; // 35000
        let ts_stake_104 = U256::from(0) + U256::from(0) + U256::from(0) + ts_stake_103; // 35000
        let ts_stake_105 = U256::from(0) + U256::from(0) + U256::from(0) + ts_stake_104; // 35000

        let reward_101 = (ts_stake_101 * U256::from(50000)) / U256::from(1_000_000); // 560
        let reward_102 = (ts_stake_102 * U256::from(55000)) / U256::from(1_100_000); // 1150
        let reward_103 = (ts_stake_103 * U256::from(60000)) / U256::from(1_200_000); // 1750
        let reward_104 = (ts_stake_104 * U256::from(65000)) / U256::from(1_300_000); // 1750
        let reward_105 = (ts_stake_105 * U256::from(70000)) / U256::from(1_400_000); // 1750

        let total_rewards_ts = reward_101 + reward_102 + reward_103 + reward_104 + reward_105; // Expected: 6960

        // --- 3. Run the Rust functions ---
        let reward_cycles = get_reward_need_cycle_list(last_withdraw, last_reward);
        let stake_per_cycle =
            combine_buff_direct(&reward_cycles, &direct_map, &buffer_map, &deleg_map);
        let total_rewards_rust =
            calculate_rewards(&stake_per_cycle, &reward_cycles, &ssn_stake_map);

        // --- 4. Assertions ---
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
