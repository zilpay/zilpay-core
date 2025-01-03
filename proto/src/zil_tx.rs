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
use alloy::primitives::U256;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zil_errors::address::AddressError;

pub const EVM_GAS_PER_SCILLA_GAS: u64 = 420;

pub fn version_from_chainid(chain_id: u16) -> u32 {
    ((chain_id as u32) << 16) | 0x0001
}

pub fn chainid_from_version(version: u32) -> u16 {
    (version >> 16) as u16
}

pub fn encode_zilliqa_transaction(txn: &ZILTransactionRequest, pub_key: &PubKey) -> Vec<u8> {
    let oneof8 = (!txn.code.is_empty()).then(|| Code::Code(txn.code.as_bytes().to_vec()));
    let oneof9 = (!txn.data.is_empty()).then(|| Data::Data(txn.data.as_bytes().to_vec()));
    let proto = ProtoTransactionCoreInfo {
        version: version_from_chainid(txn.chain_id),
        toaddr: txn.to_addr.addr_bytes().to_vec(),
        senderpubkey: Some(pub_key.as_ref().to_vec().into()),
        amount: Some(txn.amount.to_be_bytes().to_vec().into()),
        gasprice: Some(txn.gas_price.to_be_bytes().to_vec().into()),
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

    pub fn get_256(self) -> U256 {
        U256::from(self.0)
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
    // meta fields
    pub icon: Option<String>,
    pub title: Option<String>,
    // amount, decimals, symbol
    pub token_info: Option<(U256, u8, String)>,

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
    // meta fields
    #[serde(skip_serializing)]
    pub hash: Option<String>,
    #[serde(skip_serializing)]
    pub icon: Option<String>,
    #[serde(skip_serializing)]
    pub title: Option<String>,
    // amount, decimals, symbol
    #[serde(skip_serializing)]
    pub token_info: Option<(U256, u8, String)>,

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

impl TryFrom<ZILTransactionReceipt> for ZILTransactionRequest {
    type Error = AddressError;

    fn try_from(receipt: ZILTransactionReceipt) -> Result<Self, Self::Error> {
        Ok(Self {
            icon: None,
            title: None,
            token_info: None,
            chain_id: chainid_from_version(receipt.version),
            nonce: receipt.nonce,
            gas_price: receipt.gas_price,
            gas_limit: receipt.gas_limit,
            to_addr: Address::from_zil_base16(&receipt.to_addr)?,
            amount: receipt.amount,
            code: receipt.code,
            data: receipt.data,
        })
    }
}

#[cfg(test)]
mod tests_tx_encode {
    use crate::{keypair::KeyPair, secret_key::SecretKey};

    use super::*;

    const CHAIN_ID: u16 = 42;
    const SHOULD_BE_BYTES: &str = "088180a80110011a14ebd8b370dddb636faf641040d2181c55190840fb22230a2103150a7f37063b134cde30070431a69148d60b252f4c7b38de33d813d329a7b7da2a120a100000000000000000000000000000000032120a100000000000000000000000000000000038a08d06";

    #[test]
    fn test_chainid_version() {
        let version = version_from_chainid(CHAIN_ID);
        assert_eq!(version, 2752513);
        let chain_id = chainid_from_version(version);
        assert_eq!(chain_id, CHAIN_ID);
    }

    #[test]
    fn test_encode_zilliqa_transaction() {
        let sk = SecretKey::from_str(
            "00e93c035175b08613c4b0251ca92cd007026ca032ba53bafa3c839838f8b52d04",
        )
        .unwrap();
        let key_pair = KeyPair::from_secret_key(sk).unwrap();
        let zil_addr = key_pair.get_addr().unwrap();
        let zil_pub_key = key_pair.get_pubkey().unwrap();
        let tx_req = ZILTransactionRequest {
            icon: None,
            title: None,
            token_info: None,
            chain_id: CHAIN_ID,
            nonce: 1,
            gas_price: ZilAmount::from_amount(2000),
            gas_limit: ScillaGas(100000),
            to_addr: zil_addr,
            amount: ZilAmount::from_amount(1),
            code: String::with_capacity(0),
            data: String::with_capacity(0),
        };
        let tx_bytes = encode_zilliqa_transaction(&tx_req, &zil_pub_key);

        assert_eq!(hex::encode(&tx_bytes), SHOULD_BE_BYTES);

        let tx_recipt = ZILTransactionReceipt {
            icon: tx_req.icon.clone(),
            title: tx_req.title.clone(),
            token_info: tx_req.token_info.clone(),
            hash: None,
            version: version_from_chainid(CHAIN_ID),
            nonce: tx_req.nonce,
            gas_price: tx_req.gas_price,
            gas_limit: tx_req.gas_limit,
            to_addr: tx_req.to_addr.get_zil_base16().unwrap(),
            amount: tx_req.amount,
            pub_key: zil_pub_key.as_hex_str(),
            code: tx_req.code.clone(),
            data: tx_req.data.clone(),
            signature: hex::encode(tx_bytes),
            priority: false,
        };
        let restored_req_tx: ZILTransactionRequest = tx_recipt.try_into().unwrap();
        let tx_bytes = encode_zilliqa_transaction(&restored_req_tx, &zil_pub_key);

        assert_eq!(hex::encode(&tx_bytes), SHOULD_BE_BYTES);
        assert_eq!(&restored_req_tx, &tx_req);
    }
}
