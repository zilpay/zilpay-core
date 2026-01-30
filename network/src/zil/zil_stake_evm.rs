use std::collections::HashMap;

use alloy::{
    hex,
    primitives::{utils::format_units, Address as AlloyAddress, TxKind},
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
use rpc::{
    common::JsonRPC, methods::EvmMethods, network_config::ChainConfig, provider::RpcProvider,
    zil_interfaces::ResultRes,
};
use serde::Deserialize;
use serde_json::{json, Value};

use super::stake::{FinalOutput, LPToken, PendingWithdrawal};
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
    GetClaimable,
    GetPendingClaims,
    GetDelegatedAmount,
    BalanceOf,
    BlockNumber,
}

#[derive(Debug, Deserialize)]
struct ApiPoolResponse {
    pool_name: String,
    pool_address: String,
    total_stake_raw: String,
    total_rewards_raw: String,
    #[serde(deserialize_with = "deserialize_lst_price")]
    lst_price_raw: Option<U256>,
    commission: u64,
    future_total_stake: String,
    user_rewards: String,
    token_symbol: Option<String>,
    token_address: Option<String>,
    unbonding_period: u64,
    avg_block_time_ms: u64,
    lst_price_change_percent: String,
    apr: f64,
}

fn deserialize_lst_price<'de, D>(deserializer: D) -> Result<Option<U256>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::Deserialize;

    #[derive(Deserialize)]
    #[serde(untagged)]
    enum LstPrice {
        Number(u64),
        String(String),
    }

    let value = Option::<LstPrice>::deserialize(deserializer)?;
    match value {
        Some(LstPrice::Number(n)) => {
            if n == 0 {
                Ok(None)
            } else {
                Ok(Some(U256::from(n)))
            }
        }
        Some(LstPrice::String(s)) => s.parse().map(Some).map_err(serde::de::Error::custom),
        None => Ok(None),
    }
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
        let api_pools = get_stake_history().await?;
        let provider: RpcProvider<ChainConfig> = RpcProvider::new(&self.config);
        let user_addr = addr.to_alloy_addr();

        let mut calls: Vec<Value> = Vec::new();
        let mut call_map: HashMap<usize, (usize, PoolMethod)> = HashMap::new();
        let mut call_id = 0;

        calls.push(RpcProvider::<ChainConfig>::build_payload(
            json!([]),
            EvmMethods::BlockNumber,
        ));
        call_map.insert(call_id, (0, PoolMethod::BlockNumber));
        call_id += 1;

        for (pool_idx, pool) in api_pools.iter().enumerate() {
            let pool_address = pool
                .pool_address
                .parse::<AlloyAddress>()
                .map_err(|_| NetworkErrors::ParseHttpError("Invalid pool address".to_string()))?;
            let is_liquid = pool.token_address.is_some();

            for method in [PoolMethod::GetClaimable, PoolMethod::GetPendingClaims] {
                let calldata = get_calldata(method, is_liquid)?;
                calls.push(RpcProvider::<ChainConfig>::build_payload(
                    json!([{
                        "from": user_addr,
                        "to": pool_address,
                        "data": hex::encode_prefixed(&calldata)
                    }, "latest"]),
                    EvmMethods::Call,
                ));
                call_map.insert(call_id, (pool_idx, method));
                call_id += 1;
            }

            if is_liquid {
                if let Some(ref token_address) = pool.token_address {
                    let token_addr = token_address
                        .parse::<AlloyAddress>()
                        .map_err(|_| {
                            NetworkErrors::ParseHttpError("Invalid token address".to_string())
                        })?;
                    let calldata = LST::balanceOfCall { account: user_addr }.abi_encode();
                    calls.push(RpcProvider::<ChainConfig>::build_payload(
                        json!([{
                            "to": token_addr,
                            "data": hex::encode_prefixed(&calldata)
                        }, "latest"]),
                        EvmMethods::Call,
                    ));
                    call_map.insert(call_id, (pool_idx, PoolMethod::BalanceOf));
                    call_id += 1;
                }
            } else {
                let calldata = get_calldata(PoolMethod::GetDelegatedAmount, is_liquid)?;
                calls.push(RpcProvider::<ChainConfig>::build_payload(
                    json!([{
                        "from": user_addr,
                        "to": pool_address,
                        "data": hex::encode_prefixed(&calldata)
                    }, "latest"]),
                    EvmMethods::Call,
                ));
                call_map.insert(call_id, (pool_idx, PoolMethod::GetDelegatedAmount));
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

        let mut pools_data: Vec<FinalOutput> = api_pools
            .iter()
            .map(|pool| {
                let token = if let (Some(symbol), Some(address)) =
                    (&pool.token_symbol, &pool.token_address)
                {
                    address.parse::<AlloyAddress>().ok().map(|addr| {
                        let price = pool.lst_price_raw.and_then(|p| {
                            format_units(p, 18)
                                .ok()
                                .and_then(|s| s.parse::<f64>().ok())
                        });

                        LPToken {
                            name: pool.pool_name.clone(),
                            symbol: symbol.clone(),
                            decimals: 18,
                            address: addr,
                            price,
                        }
                    })
                } else {
                    None
                };

                FinalOutput {
                    name: pool.pool_name.clone(),
                    address: pool.pool_address.clone(),
                    token,
                    total_stake: pool.total_stake_raw.parse().ok(),
                    total_rewards: pool.total_rewards_raw.parse().ok(),
                    commission: Some(pool.commission as f64 / 100.0),
                    unbonding_period: Some(pool.unbonding_period),
                    avg_block_time_ms: Some(pool.avg_block_time_ms),
                    lst_price_change_percent: pool.lst_price_change_percent.parse::<f32>().ok(),
                    apr: Some(pool.apr),
                    total_network_stake: pool.future_total_stake.parse().ok(),
                    rewards: pool.user_rewards.parse().unwrap_or_default(),
                    tag: "evm".to_string(),
                    ..Default::default()
                }
            })
            .collect();

        let mut current_block: Option<u64> = None;

        for (idx, res) in batch_res.iter().enumerate() {
            if let Some(err) = &res.error {
                return Err(NetworkErrors::RPCError(err.message.to_string()));
            }

            let result = res
                .result
                .as_ref()
                .and_then(|v| v.as_str())
                .and_then(|r| hex::decode(r).ok());

            if let Some(&(pool_idx, method)) = call_map.get(&idx) {
                if method == PoolMethod::BlockNumber {
                    if let Some(bytes_result) = result {
                        let block_number = u64::from_be_bytes({
                            let mut arr = [0u8; 8];
                            let len = bytes_result.len();
                            if len >= 3 {
                                arr[5..].copy_from_slice(&bytes_result[len - 3..]);
                            }
                            arr
                        });
                        current_block = Some(block_number);
                    }
                    continue;
                }

                if let Some(bytes_result) = result {
                    pools_data[pool_idx].current_block = current_block;
                    let is_liquid = pools_data[pool_idx].token.is_some();
                    if let Ok(decoded) = decode_result(method, &bytes_result, is_liquid) {
                        process_decoded(&mut pools_data[pool_idx], method, decoded);
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

async fn get_stake_history() -> Result<Vec<ApiPoolResponse>, NetworkErrors> {
    let url = "https://stake.zilpay.io/stake/history";
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
        .json::<Vec<ApiPoolResponse>>()
        .await
        .map_err(|e| NetworkErrors::ParseHttpError(e.to_string()))
}

fn process_decoded(data: &mut FinalOutput, method: PoolMethod, decoded: Value) {
    match method {
        PoolMethod::BlockNumber => {}
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
                            .map(|current_block_number| current_block_number > withdrawal_block)
                            .unwrap_or(false),
                    });
                }
            }
        }
        PoolMethod::GetDelegatedAmount => {
            if let Value::String(s) = &decoded {
                data.deleg_amt = s.parse().unwrap_or_default();
            }
        }
        PoolMethod::BalanceOf => {
            if let Value::String(s) = &decoded {
                data.deleg_amt = s.parse().unwrap_or_default();
            }
        }
    }
}

fn get_calldata(method: PoolMethod, is_liquid: bool) -> Result<Vec<u8>, NetworkErrors> {
    let calldata = match method {
        PoolMethod::GetClaimable => BaseDelegation::getClaimableCall {}.abi_encode(),
        PoolMethod::GetPendingClaims => BaseDelegation::getPendingClaimsCall {}.abi_encode(),
        PoolMethod::GetDelegatedAmount if !is_liquid => {
            NonLiquidDelegation::getDelegatedAmountCall {}.abi_encode()
        }
        PoolMethod::BalanceOf if is_liquid => {
            return Err(NetworkErrors::ParseHttpError(
                "BalanceOf should not use this function".to_string(),
            ))
        }
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
        PoolMethod::GetDelegatedAmount if !is_liquid => {
            let ret = NonLiquidDelegation::getDelegatedAmountCall::abi_decode_returns(data)
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

