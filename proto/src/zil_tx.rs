use std::{
    fmt::{Display, Formatter},
    ops::Sub,
    str::FromStr,
};

use crate::pubkey::PubKey;
use crate::{
    address::Address,
    zq1_proto::{Code, Data, Nonce, ProtoTransactionCoreInfo},
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub const EVM_GAS_PER_SCILLA_GAS: u64 = 420;

pub fn version_from_chainid(chain_id: u16) -> u32 {
    ((chain_id as u32) << 16) | 0x0001
}

pub fn encode_zilliqa_transaction(txn: &ZILTransactionRequest, pub_key: &PubKey) -> Vec<u8> {
    let oneof8 = (!txn.code.is_empty()).then_some(Code::Code(txn.code.clone().into_bytes()));
    let oneof9 = (!txn.data.is_empty()).then_some(Data::Data(txn.data.clone().into_bytes()));
    let proto = ProtoTransactionCoreInfo {
        version: version_from_chainid(txn.chain_id),
        toaddr: txn.to_addr.addr_bytes().to_vec(),
        senderpubkey: Some(pub_key.as_ref().to_vec().into()),
        amount: Some((txn.amount).to_be_bytes().to_vec().into()),
        gasprice: Some((txn.gas_price).to_be_bytes().to_vec().into()),
        gaslimit: txn.gas_limit.0,
        oneof2: Some(Nonce::Nonce(txn.nonce)),
        oneof8,
        oneof9,
    };

    prost::Message::encode_to_vec(&proto)
}

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
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct ScillaGas(pub u64);

impl Serialize for ScillaGas {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0.to_string())
    }
}

impl<'de> Deserialize<'de> for ScillaGas {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let value = s.parse().map_err(serde::de::Error::custom)?;

        Ok(ScillaGas(value))
    }
}

/// A wrapper for ZIL amounts in the Zilliqa API. These are represented in units of (10^-12) ZILs, rather than (10^-18)
/// like in the rest of our code. The implementations of [Serialize], [Deserialize], [Display] and [FromStr] represent
/// the amount in units of (10^-12) ZILs, so this type can be used in the Zilliqa API layer.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Default)]
pub struct ZilAmount(pub u128);

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

impl Serialize for ZilAmount {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0.to_string())
    }
}

impl<'de> Deserialize<'de> for ZilAmount {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let value: u128 = s.parse().map_err(serde::de::Error::custom)?;

        Ok(ZilAmount::from_raw(value))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ZILTransactionRequest {
    pub chain_id: u16,
    pub nonce: u64,
    pub gas_price: ZilAmount,
    pub gas_limit: ScillaGas,
    pub to_addr: Address,
    pub amount: ZilAmount,
    pub code: String,
    pub data: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ZILTransactionReceipt {
    pub version: u32,
    pub nonce: u64,
    #[serde(default, rename = "gasPrice")]
    pub gas_price: ZilAmount,
    #[serde(default, rename = "gasLimit")]
    pub gas_limit: ScillaGas,
    #[serde(default, rename = "toAddr")]
    pub to_addr: String,
    pub amount: ZilAmount,
    #[serde(default, rename = "pubKey")]
    pub pub_key: String,
    pub code: String,
    pub data: String,
    pub signature: String,
    pub priority: bool,
}
