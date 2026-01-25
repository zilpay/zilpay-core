use std::collections::HashMap;

use alloy::{
    hex,
    primitives::{utils::format_units, Address as AlloyAddress, TxKind},
    sol,
    sol_types::SolCall,
};
use async_trait::async_trait;
use config::contracts::DEPOSIT_ADDRESS;
use errors::network::NetworkErrors;
use proto::{
    address::Address,
    tx::{ETHTransactionRequest, TransactionMetadata, TransactionRequest},
    U256,
};
use rpc::{
    common::JsonRPC, methods::EvmMethods, network_config::ChainConfig, provider::RpcProvider,
    zil_interfaces::ResultRes,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use super::stake::{FinalOutput, LPToken, PendingWithdrawal, ZilValidator};
use crate::provider::NetworkProvider;

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
    function getFutureTotalStake() external view returns (uint256);
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
    BlockNumber,
    GetFutureTotalStake,
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

    async fn fetch_evm_stake(&self, addr: &Address) -> Result<Vec<FinalOutput>, NetworkErrors>;
}

#[async_trait]
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
            from: Some(from.to_alloy_addr()),
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
            from: Some(from.to_alloy_addr()),
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

    async fn fetch_evm_stake(&self, addr: &Address) -> Result<Vec<FinalOutput>, NetworkErrors> {
        let pools_res = get_zq2_providers().await?;
        let provider: RpcProvider<ChainConfig> = RpcProvider::new(&self.config);

        let mut calls: Vec<Value> = Vec::new();
        let mut call_map: HashMap<usize, (usize, PoolMethod)> = HashMap::new();
        let mut call_id = 0;
        let mut current_block: Option<u64> = None;
        let mut total_network_stake = U256::ZERO;

        calls.push(RpcProvider::<ChainConfig>::build_payload(
            json!([]),
            EvmMethods::BlockNumber,
        ));
        call_map.insert(call_id, (0, PoolMethod::BlockNumber));
        call_id += 1;

        let get_future_total_stake_call = getFutureTotalStakeCall {};
        calls.push(RpcProvider::<ChainConfig>::build_payload(
            json!([{
                "to": DEPOSIT_ADDRESS,
                "data": hex::encode_prefixed(get_future_total_stake_call.abi_encode())
            }, "latest"]),
            EvmMethods::Call,
        ));
        call_map.insert(call_id, (0, PoolMethod::GetFutureTotalStake));
        call_id += 1;

        for (pool_idx, pool) in pools_res.iter().enumerate() {
            let is_liquid = pool.token.is_some();

            let base_methods = vec![
                PoolMethod::DecodedVersion,
                PoolMethod::GetStake,
                PoolMethod::GetRewards,
                PoolMethod::GetCommission,
                PoolMethod::UnbondingPeriod,
                PoolMethod::Validators,
            ];

            for method in base_methods {
                let calldata = get_calldata(method, is_liquid)?;
                calls.push(RpcProvider::<ChainConfig>::build_payload(
                    json!([{
                        "to": pool.address,
                        "data": hex::encode_prefixed(&calldata)},
                        "latest"
                    ]),
                    EvmMethods::Call,
                ));
                call_map.insert(call_id, (pool_idx, method));
                call_id += 1;
            }

            if is_liquid {
                let method = PoolMethod::GetPrice;
                let calldata = get_calldata(method, is_liquid)?;
                calls.push(RpcProvider::<ChainConfig>::build_payload(
                    json!([{
                        "to": pool.address,
                        "data": hex::encode_prefixed(&calldata)},
                        "latest"
                    ]),
                    EvmMethods::Call,
                ));
                call_map.insert(call_id, (pool_idx, method));
                call_id += 1;
            } else {
                let method = PoolMethod::GetDelegatedAmount;
                let calldata = get_calldata(method, is_liquid)?;
                let user_addr = addr.to_alloy_addr();
                calls.push(RpcProvider::<ChainConfig>::build_payload(
                    json!([{
                        "from": user_addr,
                        "to": pool.address,
                        "data": hex::encode_prefixed(&calldata)},
                        "latest"
                    ]),
                    EvmMethods::Call,
                ));
                call_map.insert(call_id, (pool_idx, method));
                call_id += 1;
            }

            let user_addr = addr.to_alloy_addr();
            for method in [PoolMethod::GetClaimable, PoolMethod::GetPendingClaims] {
                let calldata = get_calldata(method, is_liquid)?;
                calls.push(RpcProvider::<ChainConfig>::build_payload(
                    json!([{
                        "from": user_addr,
                        "to": pool.address,
                        "data": hex::encode_prefixed(&calldata)},
                        "latest"
                    ]),
                    EvmMethods::Call,
                ));
                call_map.insert(call_id, (pool_idx, method));
                call_id += 1;
            }

            if !is_liquid {
                let method = PoolMethod::Rewards;
                let calldata = get_calldata(method, is_liquid)?;
                calls.push(RpcProvider::<ChainConfig>::build_payload(
                    json!([{
                        "from": user_addr,
                        "to": pool.address,
                        "data": hex::encode_prefixed(&calldata)},
                        "latest"
                    ]),
                    EvmMethods::Call,
                ));
                call_map.insert(call_id, (pool_idx, method));
                call_id += 1;
            } else if let Some(ref token) = pool.token {
                let calldata = LST::balanceOfCall { account: user_addr }.abi_encode();
                calls.push(RpcProvider::<ChainConfig>::build_payload(
                    json!([{
                        "to": token.address,
                        "data": hex::encode_prefixed(&calldata)},
                        "latest"
                    ]),
                    EvmMethods::Call,
                ));
                call_map.insert(call_id, (pool_idx, PoolMethod::BalanceOf));
                call_id += 1;
            }
        }

        if calls.is_empty() {
            return Ok(Vec::new());
        }

        let batch_res = provider
            .req::<Vec<ResultRes<Value>>>(calls.into())
            .await
            .map_err(NetworkErrors::Request)?;

        let mut pools_data: Vec<FinalOutput> = pools_res
            .into_iter()
            .map(|pool| FinalOutput {
                name: pool.name,
                address: pool.address.to_string(),
                token: pool.token,
                hide: pool.hide,
                uptime: pool.uptime,
                can_stake: pool.can_stake,
                tag: "evm".to_string(),
                ..Default::default()
            })
            .collect();

        for (idx, res) in batch_res.iter().enumerate() {
            if let Some(err) = &res.error {
                return Err(NetworkErrors::RPCError(err.message.to_string()));
            }

            let result = res
                .result
                .as_ref()
                .and_then(|v| v.as_str())
                .map(|r| hex::decode(&r).ok())
                .unwrap_or(None);

            if let Some(&(pool_idx, method)) = call_map.get(&idx) {
                if method == PoolMethod::BlockNumber {
                    if let Some(bytes_result) = result {
                        let block_number = u64::from_be_bytes({
                            let mut arr = [0u8; 8];
                            arr[5..].copy_from_slice(&bytes_result);
                            arr
                        });
                        current_block = Some(block_number);
                    }
                    continue;
                } else if method == PoolMethod::GetFutureTotalStake {
                    if let Some(bytes_result) = result {
                        if let Ok(decoded) =
                            getFutureTotalStakeCall::abi_decode_returns(&bytes_result)
                        {
                            total_network_stake = decoded;
                        }
                    }
                    continue;
                } else if let Some(bytes_result) = result {
                    pools_data[pool_idx].current_block = current_block;
                    pools_data[pool_idx].total_network_stake = Some(total_network_stake);
                    let is_liquid = pools_data[pool_idx].token.is_some();
                    if let Ok(decoded) = decode_result(method, &bytes_result, is_liquid) {
                        process_decoded(&mut pools_data[pool_idx], method, decoded, is_liquid);
                    }
                }
            }
        }

        Ok(pools_data
            .into_iter()
            .filter(|pd| {
                pd.total_stake.is_some() || pd.deleg_amt > U256::ZERO || pd.rewards > U256::ZERO
            })
            .collect())
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

fn process_decoded(data: &mut FinalOutput, method: PoolMethod, decoded: Value, is_liquid: bool) {
    match method {
        PoolMethod::BlockNumber => {}
        PoolMethod::GetFutureTotalStake => {}
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
                let commission_num = arr
                    .get(0)
                    .and_then(|fee| fee.as_str())
                    .and_then(|fee| fee.parse().ok())
                    .unwrap_or_default();
                let commission_den: U256 = arr
                    .get(1)
                    .and_then(|fee| fee.as_str())
                    .and_then(|fee| fee.parse().ok())
                    .unwrap_or_default();

                data.commission = Some(f64::from(commission_num) / 100.0);
                data.apr = calculate_apr(
                    data.total_stake.unwrap_or_default(),
                    commission_num,
                    commission_den,
                    data.total_network_stake.unwrap_or_default(),
                );
                data.vote_power = calculate_vote_power(
                    data.total_stake.unwrap_or_default(),
                    data.total_network_stake.unwrap_or_default(),
                );
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
                    let price = format_units(wei, 18)
                        .unwrap_or_default()
                        .parse()
                        .unwrap_or_default();

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
                        claimable: data
                            .current_block
                            .and_then(|current_block_number| {
                                Some(current_block_number > withdrawal_block)
                            })
                            .unwrap_or(false),
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

fn get_calldata(method: PoolMethod, is_liquid: bool) -> Result<Vec<u8>, NetworkErrors> {
    let calldata = match method {
        PoolMethod::DecodedVersion => BaseDelegation::decodedVersionCall {}.abi_encode(),
        PoolMethod::GetStake => BaseDelegation::getStakeCall {}.abi_encode(),
        PoolMethod::GetRewards => BaseDelegation::getRewardsCall {}.abi_encode(),
        PoolMethod::GetCommission => BaseDelegation::getCommissionCall {}.abi_encode(),
        PoolMethod::UnbondingPeriod => BaseDelegation::unbondingPeriodCall {}.abi_encode(),
        PoolMethod::Validators => BaseDelegation::validatorsCall {}.abi_encode(),
        PoolMethod::GetClaimable => BaseDelegation::getClaimableCall {}.abi_encode(),
        PoolMethod::GetPendingClaims => BaseDelegation::getPendingClaimsCall {}.abi_encode(),
        PoolMethod::GetPrice if is_liquid => LiquidDelegation::getPriceCall {}.abi_encode(),
        PoolMethod::GetDelegatedAmount if !is_liquid => {
            NonLiquidDelegation::getDelegatedAmountCall {}.abi_encode()
        }
        PoolMethod::Rewards if !is_liquid => NonLiquidDelegation::rewardsCall {}.abi_encode(),
        _ => {
            return Err(NetworkErrors::ParseHttpError(
                "Invalid method or type".to_string(),
            ))
        }
    };
    Ok(calldata)
}

fn decode_result(method: PoolMethod, data: &[u8], is_liquid: bool) -> Result<Value, NetworkErrors> {
    let decoded = match method {
        PoolMethod::DecodedVersion => {
            let ret = BaseDelegation::decodedVersionCall::abi_decode_returns(data)
                .map_err(|e| NetworkErrors::ParseHttpError(e.to_string()))?;
            json!([ret._0, ret._1, ret._2])
        }
        PoolMethod::GetStake => {
            let ret = BaseDelegation::getStakeCall::abi_decode_returns(data)
                .map_err(|e| NetworkErrors::ParseHttpError(e.to_string()))?;
            json!(ret.to_string())
        }
        PoolMethod::GetRewards => {
            let ret = BaseDelegation::getRewardsCall::abi_decode_returns(data)
                .map_err(|e| NetworkErrors::ParseHttpError(e.to_string()))?;
            json!(ret.to_string())
        }
        PoolMethod::GetCommission => {
            let ret = BaseDelegation::getCommissionCall::abi_decode_returns(data)
                .map_err(|e| NetworkErrors::ParseHttpError(e.to_string()))?;
            json!([ret._0.to_string(), ret._1.to_string()])
        }
        PoolMethod::UnbondingPeriod => {
            let ret = BaseDelegation::unbondingPeriodCall::abi_decode_returns(data)
                .map_err(|e| NetworkErrors::ParseHttpError(e.to_string()))?;
            json!(ret.to_string())
        }
        PoolMethod::Validators => {
            let ret = BaseDelegation::validatorsCall::abi_decode_returns(data)
                .map_err(|e| NetworkErrors::ParseHttpError(e.to_string()))?;
            let mut arr: Vec<Value> = Vec::new();
            for v in ret {
                arr.push(json!({
                    "blsPubKey": hex::encode(v.blsPubKey),
                    "futureStake": v.futureStake.to_string(),
                    "rewardAddress": v.rewardAddress.to_string(),
                    "controlAddress": v.controlAddress.to_string(),
                    "pendingWithdrawals": v.pendingWithdrawals.to_string(),
                    "status": v.status as u64
                }));
            }
            json!(arr)
        }
        PoolMethod::GetClaimable => {
            let ret = BaseDelegation::getClaimableCall::abi_decode_returns(data)
                .map_err(|e| NetworkErrors::ParseHttpError(e.to_string()))?;
            json!(ret.to_string())
        }
        PoolMethod::GetPendingClaims => {
            let ret = BaseDelegation::getPendingClaimsCall::abi_decode_returns(data)
                .map_err(|e| NetworkErrors::ParseHttpError(e.to_string()))?;
            let mut arr: Vec<Value> = Vec::new();
            for c in ret {
                arr.push(json!({
                    "blockNumber": c.blockNumber.to_string(),
                    "amount": c.amount.to_string()
                }));
            }
            json!(arr)
        }
        PoolMethod::GetPrice if is_liquid => {
            let ret = LiquidDelegation::getPriceCall::abi_decode_returns(data)
                .map_err(|e| NetworkErrors::ParseHttpError(e.to_string()))?;
            json!(ret.to_string())
        }
        PoolMethod::GetDelegatedAmount if !is_liquid => {
            let ret = NonLiquidDelegation::getDelegatedAmountCall::abi_decode_returns(data)
                .map_err(|e| NetworkErrors::ParseHttpError(e.to_string()))?;
            json!(ret.to_string())
        }
        PoolMethod::Rewards if !is_liquid => {
            let ret = NonLiquidDelegation::rewardsCall::abi_decode_returns(data)
                .map_err(|e| NetworkErrors::ParseHttpError(e.to_string()))?;
            json!(ret.to_string())
        }
        PoolMethod::BalanceOf if is_liquid => {
            let ret = LST::balanceOfCall::abi_decode_returns(data)
                .map_err(|e| NetworkErrors::ParseHttpError(e.to_string()))?;
            json!(ret.to_string())
        }
        _ => {
            return Err(NetworkErrors::ParseHttpError(
                "Invalid method or type".to_string(),
            ))
        }
    };
    Ok(decoded)
}

fn calculate_vote_power(pool_stake: U256, total_network_stake: U256) -> Option<f64> {
    if total_network_stake == U256::ZERO {
        return Some(0.0);
    }

    let vp_ratio_float = f64::from(pool_stake) / f64::from(total_network_stake);

    Some((vp_ratio_float * 100.0 * 10000.0).round() / 10000.0)
}

fn calculate_apr(
    pool_stake: U256,
    commission_num: U256,
    commission_den: U256,
    total_network_stake: U256,
) -> Option<f64> {
    if total_network_stake == U256::ZERO || commission_den == U256::ZERO {
        return Some(0.0);
    }

    let vp_ratio_float = f64::from(pool_stake) / f64::from(total_network_stake);
    let rewards_per_year_in_zil = 51000.0 * 24.0 * 365.0;
    let commission_ratio_float = f64::from(commission_num) / f64::from(commission_den);
    let delegator_year_reward = vp_ratio_float * rewards_per_year_in_zil;
    let delegator_reward_for_share = delegator_year_reward * (1.0 - commission_ratio_float);

    let pool_stake_in_zil: f64 = format_units(pool_stake, 18)
        .unwrap_or_default()
        .parse()
        .unwrap_or_default();

    if pool_stake_in_zil == 0.0 {
        return Some(0.0);
    }

    let apr = (delegator_reward_for_share / pool_stake_in_zil) * 100.0;
    Some((apr * 10000.0).round() / 10000.0)
}
