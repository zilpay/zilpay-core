use std::collections::HashMap;

use alloy::primitives::U256;
use async_trait::async_trait;
use config::contracts::{SCILLA_STAKE_PROXY, ST_ZIL_CONTRACT};
use errors::network::NetworkErrors;
use proto::{
    address::Address,
    tx::{TransactionMetadata, TransactionRequest},
    zil_tx::ZILTransactionRequest,
};
use serde_json::{json, Value};

use crate::{provider::NetworkProvider, stake::FinalOutput};

#[derive(Debug, Default)]
struct RewardCalculationData {
    last_reward_cycle: u64,
    last_withdraw_cycle_map: Value,
    stake_ssn_per_cycle_maps: HashMap<String, Value>,
    direct_deposit_maps: HashMap<String, Value>,
    buff_deposit_maps: HashMap<String, Value>,
}

#[async_trait]
pub trait ZilliqaScillaStakeing {
    fn build_tx_scilla_claim(
        &self,
        stake: &FinalOutput,
    ) -> Result<TransactionRequest, NetworkErrors>;
    fn build_tx_scilla_init_unstake(
        &self,
        stake: &FinalOutput,
    ) -> Result<TransactionRequest, NetworkErrors>;
    fn build_tx_scilla_complete_withdrawal(
        &self,
        contract: Address,
    ) -> Result<TransactionRequest, NetworkErrors>;
    fn build_tx_scilla_withdraw_stake_avely(
        &self,
        stake: &FinalOutput,
    ) -> Result<TransactionRequest, NetworkErrors>;
}

#[async_trait]
impl ZilliqaScillaStakeing for NetworkProvider {
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

    fn build_tx_scilla_complete_withdrawal(
        &self,
        contract: Address,
    ) -> Result<TransactionRequest, NetworkErrors> {
        let params = json!({
            "_tag": "CompleteWithdrawal",
            "params": []
        });
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
}

fn calculate_rewards(
    normalized_address: &str,
    user_deposits: &HashMap<String, String>,
    reward_data: &RewardCalculationData,
) -> HashMap<String, U256> {
    let mut rewards_by_ssn = HashMap::new();
    let zero_bigint = U256::ZERO;

    for ssn_address in user_deposits.keys() {
        let mut total_ssn_reward = U256::ZERO;

        let last_withdraw_cycle_str = reward_data
            .last_withdraw_cycle_map
            .get("last_withdraw_cycle_deleg")
            .and_then(|m| m.get(normalized_address))
            .and_then(|m| m.get(ssn_address))
            .and_then(|v| v.as_str())
            .unwrap_or("0");

        let last_withdraw_cycle: u64 = last_withdraw_cycle_str.parse().unwrap_or(0);

        if last_withdraw_cycle >= reward_data.last_reward_cycle {
            rewards_by_ssn.insert(ssn_address.clone(), U256::ZERO);
            continue;
        }

        let ssn_cycle_info_map = reward_data
            .stake_ssn_per_cycle_maps
            .get(ssn_address)
            .and_then(|v| v.get("stake_ssn_per_cycle"))
            .and_then(|m| m.get(ssn_address));

        let direct_map = reward_data
            .direct_deposit_maps
            .get(ssn_address)
            .and_then(|v| {
                v.pointer(&format!(
                    "/direct_deposit_deleg/{}/{}",
                    normalized_address, ssn_address
                ))
            });

        let buff_map = reward_data
            .buff_deposit_maps
            .get(ssn_address)
            .and_then(|v| {
                v.pointer(&format!(
                    "/buff_deposit_deleg/{}/{}",
                    normalized_address, ssn_address
                ))
            });

        let mut deleg_stake_per_cycle_map = HashMap::new();

        for cycle in 1..=reward_data.last_reward_cycle {
            let c1 = cycle.saturating_sub(1);
            let c2 = cycle.saturating_sub(2);

            let dir_amt = direct_map
                .and_then(|m| m.get(c1.to_string()))
                .and_then(|v| v.as_str())
                .and_then(|s| s.parse().ok())
                .unwrap_or(U256::ZERO);
            let buf_amt = buff_map
                .and_then(|m| m.get(c2.to_string()))
                .and_then(|v| v.as_str())
                .and_then(|s| s.parse().ok())
                .unwrap_or(U256::ZERO);
            let last_amt = deleg_stake_per_cycle_map
                .get(&c1)
                .unwrap_or(&zero_bigint)
                .clone();

            deleg_stake_per_cycle_map.insert(cycle, last_amt + dir_amt + buf_amt);
        }

        for cycle in (last_withdraw_cycle + 1)..=reward_data.last_reward_cycle {
            if let Some(cycle_info) = ssn_cycle_info_map.and_then(|m| m.get(cycle.to_string())) {
                let total_stake_for_cycle_str = cycle_info
                    .get("arguments")
                    .and_then(|a| a.get(0))
                    .and_then(|v| v.as_str())
                    .unwrap_or("0");
                let total_rewards_for_cycle_str = cycle_info
                    .get("arguments")
                    .and_then(|a| a.get(1))
                    .and_then(|v| v.as_str())
                    .unwrap_or("0");

                let total_stake_for_cycle = total_stake_for_cycle_str.parse().unwrap_or(U256::ZERO);
                let total_rewards_for_cycle =
                    total_rewards_for_cycle_str.parse().unwrap_or(U256::ZERO);

                if let Some(deleg_stake_for_cycle) = deleg_stake_per_cycle_map.get(&cycle) {
                    if !deleg_stake_for_cycle.is_zero() && !total_stake_for_cycle.is_zero() {
                        total_ssn_reward += (deleg_stake_for_cycle * total_rewards_for_cycle)
                            / &total_stake_for_cycle;
                    }
                }
            }
        }
        rewards_by_ssn.insert(ssn_address.clone(), total_ssn_reward);
    }

    rewards_by_ssn
}
