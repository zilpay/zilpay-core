use crate::status::TransactionStatus;
use alloy::{
    consensus::Transaction,
    primitives::{TxKind, U256},
};
use proto::{address::Address, tx::TransactionReceipt};
use serde::{Deserialize, Serialize};
use zil_errors::tx::TransactionErrors;

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
    pub confirmed: bool,
    pub timestamp: u64,
    pub fee: u128, // in native token
    pub icon: String,
    pub title: String,
    pub nonce: u64,
    pub token_info: Option<TokenInfo>,
}

impl TryFrom<TransactionReceipt> for HistoricalTransaction {
    type Error = TransactionErrors;

    fn try_from(receipt: TransactionReceipt) -> Result<Self, Self::Error> {
        match receipt {
            TransactionReceipt::Zilliqa(zil_receipt) => Ok(HistoricalTransaction {
                id: zil_receipt.hash.unwrap_or_default(),
                amount: zil_receipt.amount.get_256(),
                sender: zil_receipt.pub_key.clone(),
                recipient: zil_receipt.to_addr,
                teg: None,
                status: TransactionStatus::Pending,
                confirmed: false,
                timestamp: 0,
                fee: zil_receipt.gas_price.get() * (zil_receipt.gas_limit.0 as u128),
                icon: zil_receipt.icon.unwrap_or_else(|| "zilliqa".to_string()),
                title: zil_receipt
                    .title
                    .unwrap_or_else(|| "Zilliqa Transaction".to_string()),
                nonce: zil_receipt.nonce,
                token_info: zil_receipt
                    .token_info
                    .map(|(value, decimals, symbol)| TokenInfo {
                        value,
                        symbol,
                        decimals,
                    }),
            }),
            TransactionReceipt::Ethereum(tx) => {
                Ok(HistoricalTransaction {
                    id: tx.tx_hash().to_string(),
                    amount: tx.value(),
                    sender: tx.recover_signer().unwrap_or_default().to_string(),
                    recipient: match tx.kind() {
                        TxKind::Call(addr) => addr.to_string(),
                        TxKind::Create => {
                            Address::Secp256k1Keccak256Ethereum(Address::ZERO).auto_format()
                        }
                    },
                    fee: 0, // TODO: calc gas fee for all EIPs.
                    teg: None,
                    status: TransactionStatus::Pending, // TODO: detect from eth tx.
                    confirmed: false,
                    timestamp: 0,
                    icon: String::new(),  // TODO: make wrapper for tx.
                    title: String::new(), // TODO: make a wrapper for tx evm
                    nonce: tx.nonce(),
                    token_info: None, // TODO: make a wrapper for tx evm
                })
            }
        }
    }
}
