use alloy::{
    hex,
    primitives::{Address as AlloyAddress, TxKind},
    sol,
    sol_types::SolCall,
};
use async_trait::async_trait;
use errors::network::NetworkErrors;
use proto::{
    address::Address,
    tx::{ETHTransactionRequest, TransactionMetadata, TransactionRequest},
    U256,
};
use rpc::{methods::EvmMethods, network_config::ChainConfig, provider::RpcProvider};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    provider::NetworkProvider,
    stake::{FinalOutput, LPToken, PendingWithdrawal, ZilValidator},
};

sol! {
    struct Validator {
        bytes blsPubKey;
        uint256 futureStake;
        address rewardAddress;
        address controlAddress;
        uint256 pendingWithdrawals;
        uint8 status;
    }

    struct PendingClaim {
        uint256 blockNumber;
        uint256 amount;
    }

    interface BaseDelegation {
        function decodedVersion() external view returns (uint24, uint24, uint24);
        function owner() external view returns (address);
        function getStake() external view returns (uint256);
        function getRewards() external view returns (uint256);
        function getCommission() external view returns (uint256, uint256);
        function getCommissionReceiver() external view returns (address);
        function unbondingPeriod() external view returns (uint256);
        function validators() external view returns (Validator[]);
        function getClaimable() external view returns (uint256);
        function getPendingClaims() external view returns (PendingClaim[]);
    }

    interface LiquidDelegation {
        function getLST() external view returns (address);
        function getPrice() external view returns (uint256);
    }

    interface NonLiquidDelegation {
        function getDelegatedTotal() external view returns (uint256);
        function getDelegatedAmount() external view returns (uint256);
        function rewards() external view returns (uint256);
    }

    interface LST {
        function balanceOf(address account) external view returns (uint256);
    }

    function stake() external payable;
    function unstake(uint256 shares) external;
    function claim() external;
    function withdrawAllRewards() external;
    function stakeRewards() external;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PoolMethod {
    DecodedVersion,
    GetStake,
    GetRewards,
    GetCommission,
    UnbondingPeriod,
    Validators,
    GetClaimable,
    GetPendingClaims,
    GetPrice,
    GetDelegatedAmount,
    Rewards,
    BalanceOf,
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

#[async_trait]
pub trait ZilliqaEVMStakeing {
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

impl ZilliqaEVMStakeing for NetworkProvider {
    fn build_tx_evm_stake_request(
        &self,
        amount: U256,
        provider: &Address,
        from: &Address,
    ) -> Result<TransactionRequest, NetworkErrors> {
        let stake_call = stakeCall {};
        let to = TxKind::Call(provider.to_alloy_addr());
        let mut tx = ETHTransactionRequest {
            value: Some(amount),
            to: Some(to),
            input: stake_call.abi_encode().into(),
            ..Default::default()
        }
        .from(from.to_alloy_addr());

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
        let unstake_call = unstakeCall {
            shares: amount_to_unstake,
        };
        let to = TxKind::Call(provider.to_alloy_addr());
        let mut tx = ETHTransactionRequest {
            input: unstake_call.abi_encode().into(),
            to: Some(to),
            ..Default::default()
        }
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
        let claim_call = claimCall {};
        let to = TxKind::Call(provider.to_alloy_addr());
        let mut tx = ETHTransactionRequest {
            input: claim_call.abi_encode().into(),
            to: Some(to),
            ..Default::default()
        }
        .from(from.to_alloy_addr());

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
        let withdraw_rewards_call = withdrawAllRewardsCall {};
        let to = TxKind::Call(provider.to_alloy_addr());
        let mut tx = ETHTransactionRequest {
            input: withdraw_rewards_call.abi_encode().into(),
            to: Some(to),
            ..Default::default()
        }
        .from(from.to_alloy_addr());

        tx.chain_id = Some(self.config.chain_ids[0]);

        let metdata = TransactionMetadata {
            chain_hash: self.config.hash(),
            ..Default::default()
        };
        let req_tx = TransactionRequest::Ethereum((tx, metdata));

        Ok(req_tx)
    }
}

pub async fn get_zq2_providers() -> Result<Vec<EvmPoolV2>, NetworkErrors> {
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

fn process_decoded(
    data: &mut FinalOutput,
    method: PoolMethod,
    decoded: Value,
    pool: &EvmPoolV2,
    is_liquid: bool,
) {
    match method {
        PoolMethod::DecodedVersion => {
            if let Value::Array(arr) = decoded {
                if arr.len() == 3 {
                    let maj = arr[0].as_u64().unwrap_or(0);
                    let min = arr[1].as_u64().unwrap_or(0);
                    let pat = arr[2].as_u64().unwrap_or(0);

                    data.version = Some(format!("{}.{}.{}", maj, min, pat));
                }
            }
        }
        PoolMethod::GetStake => {
            if let Value::String(s) = &decoded {
                data.total_stake = s.parse().ok();
            }
        }
        PoolMethod::GetRewards => {
            if let Value::String(s) = &decoded {
                data.total_rewards = s.parse().ok();
            }
        }
        PoolMethod::GetCommission => {
            if let Value::Array(arr) = decoded {
                data.commission = arr
                    .get(0)
                    .and_then(|fee| fee.as_f64())
                    .and_then(|fee| Some(fee / 100.0));
            }
        }
        PoolMethod::UnbondingPeriod => {
            if let Value::String(s) = &decoded {
                data.unbonding_period = s.parse().ok();
            }
        }
        PoolMethod::Validators => {
            if let Value::Array(arr) = decoded {
                for validator in arr {
                    let future_stake: U256 = validator
                        .get("futureStake")
                        .and_then(|v| v.as_str())
                        .and_then(|v| v.parse().ok())
                        .unwrap_or_default();
                    let pending_withdrawals: U256 = validator
                        .get("pendingWithdrawals")
                        .and_then(|v| v.as_str())
                        .and_then(|v| v.parse().ok())
                        .unwrap_or_default();
                    let status: bool = validator
                        .get("status")
                        .and_then(|v| v.as_number())
                        .and_then(|v| v.as_u64())
                        .and_then(|v| Some(v == 0))
                        .unwrap_or(false);
                    let reward_address: String = validator
                        .get("rewardAddress")
                        .and_then(|v| v.as_str())
                        .and_then(|v| Some(v.to_string()))
                        .unwrap_or_default();
                    data.validators.push(ZilValidator {
                        future_stake,
                        pending_withdrawals,
                        reward_address,
                        status,
                    });
                }
            }
        }
        PoolMethod::GetPrice => {
            if let Some(lst) = &mut data.token {
                if let Value::String(s) = &decoded {
                    let wei: U256 = s.parse().unwrap_or_default();
                    let price = f64::from(wei) / 10_f64.powf(18.0);

                    lst.price = Some(price);
                }
            }
        }
        PoolMethod::GetClaimable => {
            if let Value::String(s) = &decoded {
                data.claimable_amount = s.parse().unwrap_or_default();
            }
        }
        PoolMethod::GetPendingClaims => {
            if let Value::Array(arr) = &decoded {
                for pending_claims in arr {
                    let amount: U256 = pending_claims
                        .get("amount")
                        .and_then(|v| v.as_str())
                        .and_then(|str| str.parse().ok())
                        .unwrap_or_default();
                    let withdrawal_block: u64 = pending_claims
                        .get("blockNumber")
                        .and_then(|v| v.as_str())
                        .and_then(|str| str.parse().ok())
                        .unwrap_or_default();

                    data.pending_withdrawals.push(PendingWithdrawal {
                        amount,
                        withdrawal_block,
                        claimable: false,
                    });
                }
            }
        }
        PoolMethod::GetDelegatedAmount => {
            if !is_liquid {
                if let Value::String(s) = &decoded {
                    data.deleg_amt = s.parse().unwrap_or_default();
                }
            }
        }
        PoolMethod::Rewards => {
            if let Value::String(s) = &decoded {
                data.rewards = s.parse().unwrap_or_default();
            }
        }
        PoolMethod::BalanceOf => {
            if is_liquid {
                if let Value::String(s) = &decoded {
                    data.deleg_amt = s.parse().unwrap_or_default();
                }
            }
        }
    }
}
