use std::{
    fmt::{Display, Formatter},
    ops::Sub,
    str::FromStr,
};

use crate::zq1_proto::{Code, Data, Nonce, ProtoTransactionCoreInfo};
use crypto::schnorr::PublicKey;
use serde::{Deserialize, Serialize};

pub const EVM_GAS_PER_SCILLA_GAS: u64 = 420;

impl ScillaGas {
    pub fn checked_sub(self, rhs: ScillaGas) -> Option<ScillaGas> {
        Some(ScillaGas(self.0.checked_sub(rhs.0)?))
    }
}

impl Sub for ScillaGas {
    type Output = ScillaGas;

    fn sub(self, rhs: Self) -> Self::Output {
        self.checked_sub(rhs).expect("scilla gas underflow")
    }
}

// impl From<EvmGas> for ScillaGas {
//     fn from(gas: EvmGas) -> Self {
//         ScillaGas(gas.0 / EVM_GAS_PER_SCILLA_GAS)
//     }
// }

impl Display for ScillaGas {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl FromStr for ScillaGas {
    type Err = <u64 as FromStr>::Err;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(u64::from_str(s)?))
    }
}

/// A quantity of Scilla gas. This is the currency used to pay for [TxZilliqa] transactions. When EVM gas is converted
/// to Scilla gas, the quantity is rounded down.
#[derive(Debug, Copy, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(transparent)]
pub struct ScillaGas(pub u64);

/// A wrapper for ZIL amounts in the Zilliqa API. These are represented in units of (10^-12) ZILs, rather than (10^-18)
/// like in the rest of our code. The implementations of [Serialize], [Deserialize], [Display] and [FromStr] represent
/// the amount in units of (10^-12) ZILs, so this type can be used in the Zilliqa API layer.
#[derive(Debug, Copy, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(transparent)]
pub struct ZilAmount(u128);

impl ZilAmount {
    /// Construct a [ZilAmount] from an amount in (10^-18) ZILs. The value will be truncated and rounded down.
    pub fn from_amount(amount: u128) -> ZilAmount {
        ZilAmount(amount / 10u128.pow(6))
    }

    // Construct a [ZilAmount] from an amount in (10^-12) ZILs.
    pub fn from_raw(amount: u128) -> ZilAmount {
        ZilAmount(amount)
    }

    /// Get the ZIL amount in units of (10^-18) ZILs.
    pub fn get(self) -> u128 {
        self.0.checked_mul(10u128.pow(6)).expect("amount overflow")
    }

    /// Return the memory representation of this amount as a big-endian byte array.
    pub fn to_be_bytes(self) -> [u8; 16] {
        self.0.to_be_bytes()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TxZilliqa {
    pub chain_id: u16,
    pub nonce: u64,
    pub gas_price: ZilAmount,
    pub gas_limit: ScillaGas,
    pub to_addr: Address,
    pub amount: ZilAmount,
    pub code: String,
    pub data: String,
}

fn encode_zilliqa_transaction(txn: TxZilliqa, pub_key: PublicKey) -> Vec<u8> {
    let oneof8 = (!txn.code.is_empty()).then_some(Code::Code(txn.code.into_bytes()));
    let oneof9 = (!txn.data.is_empty()).then_some(Data::Data(txn.data.into_bytes()));
    let proto = ProtoTransactionCoreInfo {
        version: (((txn.chain_id) as u32) << 16) | 0x0001,
        toaddr: txn.to_addr.as_slice().to_vec(),
        senderpubkey: Some(pub_key.to_sec1_bytes().into()),
        amount: Some((txn.amount).to_be_bytes().to_vec().into()),
        gasprice: Some((txn.gas_price).to_be_bytes().to_vec().into()),
        gaslimit: txn.gas_limit.0,
        oneof2: Some(Nonce::Nonce(txn.nonce)),
        oneof8,
        oneof9,
    };

    prost::Message::encode_to_vec(&proto)
}
