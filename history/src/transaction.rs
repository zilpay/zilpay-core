use crate::status::TransactionStatus;
use alloy::{
    consensus::Transaction,
    primitives::{TxKind, U256},
};
use proto::{address::Address, pubkey::PubKey, tx::TransactionReceipt};
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
                confirmed: false,
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
                    fee: 0, // TODO: calc gas fee for all EIPs.
                    teg: None,
                    status: TransactionStatus::Pending, // TODO: detect from eth tx.
                    confirmed: false,
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
