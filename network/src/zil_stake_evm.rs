use alloy::{
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
use serde::{Deserialize, Serialize};

use crate::{provider::NetworkProvider, stake::LPToken};

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
