use crate::evm::RequiredTxParams;
use crate::provider::NetworkProvider;
use crate::Result;
use alloy::primitives::U256;
use async_trait::async_trait;
use errors::network::NetworkErrors;
use history::transaction::HistoricalTransaction;
use proto::address::Address;
use proto::tx::{TransactionReceipt, TransactionRequest};
use token::ft::FToken;

#[async_trait]
pub trait BtcOperations {
    async fn btc_get_current_block_number(&self) -> Result<u64>;
    async fn btc_estimate_params_batch(
        &self,
        tx: &TransactionRequest,
        sender: &Address,
        block_count: u64,
        percentiles: Option<&[f64]>,
    ) -> Result<RequiredTxParams>;
    async fn btc_estimate_gas(&self, tx: &TransactionRequest) -> Result<U256>;
    async fn btc_fetch_nonce(&self, addresses: &[&Address]) -> Result<Vec<u64>>;
    async fn btc_estimate_block_time(&self, address: &Address) -> Result<u64>;
    async fn btc_update_transactions_receipt(
        &self,
        txns: &mut [&mut HistoricalTransaction],
    ) -> Result<()>;
    async fn btc_broadcast_signed_transactions(
        &self,
        txns: Vec<TransactionReceipt>,
    ) -> Result<Vec<TransactionReceipt>>;
    async fn btc_update_balances(
        &self,
        tokens: Vec<&mut FToken>,
        accounts: &[&Address],
    ) -> Result<()>;
    async fn btc_ftoken_meta(&self, contract: Address, accounts: &[&Address]) -> Result<FToken>;
}

#[async_trait]
impl BtcOperations for NetworkProvider {
    async fn btc_get_current_block_number(&self) -> Result<u64> {
        Err(NetworkErrors::RPCError(
            "Bitcoin support not yet implemented".to_string(),
        ))
    }

    async fn btc_estimate_params_batch(
        &self,
        _tx: &TransactionRequest,
        _sender: &Address,
        _block_count: u64,
        _percentiles: Option<&[f64]>,
    ) -> Result<RequiredTxParams> {
        Err(NetworkErrors::RPCError(
            "Bitcoin support not yet implemented".to_string(),
        ))
    }

    async fn btc_estimate_gas(&self, _tx: &TransactionRequest) -> Result<U256> {
        Err(NetworkErrors::RPCError(
            "Bitcoin support not yet implemented".to_string(),
        ))
    }

    async fn btc_fetch_nonce(&self, _addresses: &[&Address]) -> Result<Vec<u64>> {
        Err(NetworkErrors::RPCError(
            "Bitcoin support not yet implemented".to_string(),
        ))
    }

    async fn btc_estimate_block_time(&self, _address: &Address) -> Result<u64> {
        Err(NetworkErrors::RPCError(
            "Bitcoin support not yet implemented".to_string(),
        ))
    }

    async fn btc_update_transactions_receipt(
        &self,
        _txns: &mut [&mut HistoricalTransaction],
    ) -> Result<()> {
        Err(NetworkErrors::RPCError(
            "Bitcoin support not yet implemented".to_string(),
        ))
    }

    async fn btc_broadcast_signed_transactions(
        &self,
        _txns: Vec<TransactionReceipt>,
    ) -> Result<Vec<TransactionReceipt>> {
        Err(NetworkErrors::RPCError(
            "Bitcoin support not yet implemented".to_string(),
        ))
    }

    async fn btc_update_balances(
        &self,
        _tokens: Vec<&mut FToken>,
        _accounts: &[&Address],
    ) -> Result<()> {
        Err(NetworkErrors::RPCError(
            "Bitcoin support not yet implemented".to_string(),
        ))
    }

    async fn btc_ftoken_meta(&self, _contract: Address, _accounts: &[&Address]) -> Result<FToken> {
        Err(NetworkErrors::RPCError(
            "Bitcoin support not yet implemented".to_string(),
        ))
    }
}
