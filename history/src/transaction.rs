use crate::status::TransactionStatus;
use alloy::{
    consensus::{Transaction, TxType},
    primitives::{TxKind, U256},
};
use errors::tx::TransactionErrors;
use proto::{address::Address, pubkey::PubKey, tx::TransactionReceipt};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TokenInfo {
    pub value: U256,
    pub symbol: String,
    pub decimals: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HistoricalTransaction {
    pub id: String,
    pub amount: U256, // in native token
    pub sender: String,
    pub recipient: String,
    pub teg: Option<String>,
    pub status: TransactionStatus,
    pub confirmed: Option<u128>,
    pub timestamp: u64,
    pub fee: u128, // in native token
    pub icon: Option<String>,
    pub title: Option<String>,
    pub nonce: u64,
    pub token_info: Option<TokenInfo>,
}

impl TryFrom<TransactionReceipt> for HistoricalTransaction {
    type Error = TransactionErrors;

    fn try_from(receipt: TransactionReceipt) -> Result<Self, Self::Error> {
        match receipt {
            TransactionReceipt::Zilliqa((zil_receipt, metadata)) => Ok(HistoricalTransaction {
                id: metadata.hash.ok_or(TransactionErrors::InvalidTxHash)?,
                amount: U256::from(u128::from_be_bytes(zil_receipt.amount)),
                sender: PubKey::Secp256k1Sha256Zilliqa(zil_receipt.pub_key)
                    .get_addr()?
                    .auto_format(),
                recipient: Address::Secp256k1Sha256Zilliqa(zil_receipt.to_addr).auto_format(),
                teg: None,
                status: TransactionStatus::Pending,
                confirmed: None,
                timestamp: 0,
                fee: u128::from_be_bytes(zil_receipt.gas_price) * (zil_receipt.gas_limit as u128),
                icon: metadata.icon,
                title: metadata.title,
                nonce: zil_receipt.nonce,
                token_info: metadata
                    .token_info
                    .map(|(value, decimals, symbol)| TokenInfo {
                        value,
                        symbol,
                        decimals,
                    }),
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
                    id: metadata.hash.ok_or(TransactionErrors::InvalidTxHash)?,
                    amount: tx.value(),
                    sender: tx.recover_signer().unwrap_or_default().to_string(),
                    recipient: match tx.kind() {
                        TxKind::Call(addr) => addr.to_string(),
                        TxKind::Create => {
                            Address::Secp256k1Keccak256Ethereum(Address::ZERO).auto_format()
                        }
                    },
                    fee,
                    teg: None,
                    status: TransactionStatus::Pending,
                    confirmed: None,
                    timestamp: 0,
                    icon: metadata.icon,
                    title: metadata.title,
                    nonce: tx.nonce(),
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
