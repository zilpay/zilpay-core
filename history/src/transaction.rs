use std::{
    fmt,
    time::{SystemTime, UNIX_EPOCH},
};

use crate::status::TransactionStatus;
use alloy::{
    consensus::{Transaction, TxType},
    primitives::{TxKind, U256},
};
use errors::tx::TransactionErrors;
use proto::{address::Address, pubkey::PubKey, tx::TransactionReceipt};
use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq)]
pub enum ChainType {
    #[default]
    EVM,
    Scilla,
}

impl fmt::Display for ChainType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ChainType::EVM => write!(f, "EVM"),
            ChainType::Scilla => write!(f, "Scilla"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TokenInfo {
    pub value: U256,
    pub symbol: String,
    pub decimals: u8,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq)]
pub struct HistoricalTransaction {
    pub transaction_hash: String,
    pub amount: U256, // in native token
    pub sender: String,
    pub recipient: String,
    pub contract_address: Option<String>,
    pub status: TransactionStatus,
    pub status_code: Option<u8>,
    pub timestamp: u64,
    pub block_number: Option<u128>,
    pub gas_used: Option<u128>,
    pub gas_limit: Option<u128>,
    pub gas_price: Option<u128>,
    pub blob_gas_used: Option<u128>,
    pub blob_gas_price: Option<u128>,
    pub effective_gas_price: Option<u128>,
    pub fee: u128, // in native token
    pub icon: Option<String>,
    pub title: Option<String>,
    pub nonce: u128,
    pub token_info: Option<TokenInfo>,
    pub chain_type: ChainType,
    pub chain_hash: u64,
}

impl TryFrom<TransactionReceipt> for HistoricalTransaction {
    type Error = TransactionErrors;

    fn try_from(receipt: TransactionReceipt) -> Result<Self, Self::Error> {
        match receipt {
            TransactionReceipt::Zilliqa((zil_receipt, metadata)) => Ok(HistoricalTransaction {
                contract_address: if zil_receipt.data.is_empty() {
                    None
                } else {
                    Some(Address::Secp256k1Sha256(zil_receipt.to_addr).auto_format())
                },
                status_code: None,
                gas_price: Some(u128::from_be_bytes(zil_receipt.gas_price)),
                gas_limit: Some(zil_receipt.gas_limit as u128),
                chain_hash: metadata.chain_hash,
                chain_type: ChainType::Scilla,
                block_number: None,
                transaction_hash: metadata.hash.ok_or(TransactionErrors::InvalidTxHash)?,
                amount: U256::from(u128::from_be_bytes(zil_receipt.amount)),
                sender: PubKey::Secp256k1Sha256(zil_receipt.pub_key)
                    .get_addr()?
                    .auto_format(),
                recipient: Address::Secp256k1Sha256(zil_receipt.to_addr).auto_format(),
                status: TransactionStatus::Pending,
                timestamp: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
                fee: u128::from_be_bytes(zil_receipt.gas_price) * (zil_receipt.gas_limit as u128),
                icon: metadata.icon,
                title: metadata.title,
                nonce: zil_receipt.nonce as u128,
                token_info: metadata
                    .token_info
                    .map(|(value, decimals, symbol)| TokenInfo {
                        value,
                        symbol,
                        decimals,
                    }),
                gas_used: None,
                blob_gas_used: None,
                blob_gas_price: None,
                effective_gas_price: None,
            }),
            TransactionReceipt::Ethereum((tx, metadata)) => {
                let effective_gas_price = match tx.tx_type() {
                    TxType::Legacy | TxType::Eip2930 => tx.gas_price().unwrap_or_default(),
                    TxType::Eip1559 | TxType::Eip4844 | TxType::Eip7702 => {
                        let max_fee = tx.max_fee_per_gas();
                        let priority_fee = tx.max_priority_fee_per_gas().unwrap_or_default();
                        max_fee.min(priority_fee)
                    }
                };

                let fee = effective_gas_price * tx.gas_limit() as u128;

                Ok(HistoricalTransaction {
                    block_number: None,
                    status_code: None,
                    contract_address: None,
                    gas_limit: Some(tx.gas_limit() as u128),
                    gas_price: tx.gas_price(),
                    chain_hash: metadata.chain_hash,
                    chain_type: ChainType::EVM,
                    transaction_hash: metadata.hash.ok_or(TransactionErrors::InvalidTxHash)?,
                    amount: tx.value(),
                    sender: tx.recover_signer().unwrap_or_default().to_string(),
                    recipient: match tx.kind() {
                        TxKind::Call(addr) => addr.to_string(),
                        TxKind::Create => Address::Secp256k1Keccak256(Address::ZERO).auto_format(),
                    },
                    fee,
                    status: TransactionStatus::Pending,
                    timestamp: SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs(),
                    icon: metadata.icon,
                    title: metadata.title,
                    gas_used: None,
                    blob_gas_used: None,
                    blob_gas_price: None,
                    effective_gas_price: None,
                    nonce: tx.nonce() as u128,
                    token_info: metadata
                        .token_info
                        .map(|(value, decimals, symbol)| TokenInfo {
                            value,
                            symbol,
                            decimals,
                        }),
                })
            }
        }
    }
}
