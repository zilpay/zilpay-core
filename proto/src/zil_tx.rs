use crate::{address::Address, zq1_proto::chainid_from_version};
use config::{address::ADDR_LEN, key::PUB_KEY_SIZE, sha::SHA512_SIZE};
use serde::{Deserialize, Serialize, Serializer};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ZILTransactionRequest {
    pub chain_id: u16,
    pub nonce: u64,
    pub gas_price: u128,
    pub gas_limit: u64,
    pub to_addr: Address,
    pub amount: u128,
    pub code: Vec<u8>,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ZILTransactionReceipt {
    pub version: u32,
    pub nonce: u64,
    pub gas_price: [u8; std::mem::size_of::<u128>()],
    pub gas_limit: u64,
    pub to_addr: [u8; ADDR_LEN],
    pub amount: [u8; std::mem::size_of::<u128>()],
    pub pub_key: [u8; PUB_KEY_SIZE],
    pub code: Vec<u8>,
    pub data: Vec<u8>,
    pub signature: [u8; SHA512_SIZE],
    pub priority: bool,
}

impl Serialize for ZILTransactionReceipt {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeStruct;

        let mut state = serializer.serialize_struct("ZILTransactionReceipt", 11)?;

        state.serialize_field("version", &self.version)?;
        state.serialize_field("nonce", &self.nonce)?;

        let gas_price = u128::from_be_bytes(self.gas_price);
        let amount = u128::from_be_bytes(self.amount);

        state.serialize_field("gasPrice", &gas_price.to_string())?;
        state.serialize_field("gasLimit", &self.gas_limit.to_string())?;
        state.serialize_field(
            "toAddr",
            &Address::Secp256k1Sha256Zilliqa(self.to_addr)
                .get_zil_check_sum_addr()
                .unwrap_or_default(),
        )?;
        state.serialize_field("amount", &amount.to_string())?;
        state.serialize_field("pubKey", &hex::encode(self.pub_key))?;

        let code = String::from_utf8(self.code.clone()).map_err(serde::ser::Error::custom)?;
        let data = String::from_utf8(self.data.clone()).map_err(serde::ser::Error::custom)?;

        state.serialize_field("code", &code)?;
        state.serialize_field("data", &data)?;

        state.serialize_field("signature", &hex::encode(self.signature))?;
        state.serialize_field("priority", &self.priority)?;

        state.end()
    }
}

impl From<ZILTransactionReceipt> for ZILTransactionRequest {
    fn from(receipt: ZILTransactionReceipt) -> Self {
        Self {
            chain_id: chainid_from_version(receipt.version),
            nonce: receipt.nonce,
            gas_price: u128::from_be_bytes(receipt.gas_price),
            gas_limit: receipt.gas_limit,
            to_addr: Address::Secp256k1Sha256Zilliqa(receipt.to_addr),
            amount: u128::from_be_bytes(receipt.amount),
            code: receipt.code,
            data: receipt.data,
        }
    }
}

impl From<&ZILTransactionReceipt> for ZILTransactionRequest {
    fn from(receipt: &ZILTransactionReceipt) -> Self {
        Self {
            chain_id: chainid_from_version(receipt.version),
            nonce: receipt.nonce,
            gas_price: u128::from_be_bytes(receipt.gas_price),
            gas_limit: receipt.gas_limit,
            to_addr: Address::Secp256k1Sha256Zilliqa(receipt.to_addr),
            amount: u128::from_be_bytes(receipt.amount),
            code: receipt.code.clone(),
            data: receipt.data.clone(),
        }
    }
}

#[cfg(test)]
mod tests_tx_encode {
    use std::str::FromStr;

    use crate::{
        keypair::KeyPair,
        secret_key::SecretKey,
        zq1_proto::{create_proto_tx, version_from_chainid},
    };

    use super::*;

    const CHAIN_ID: u16 = 42;
    const SHOULD_BE_BYTES: &str = "088180a80110011a14ebd8b370dddb636faf641040d2181c55190840fb22230a2103150a7f37063b134cde30070431a69148d60b252f4c7b38de33d813d329a7b7da2a120a100000000000000000000000000000000032120a100000000000000000000000000000000038a08d06";

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
            chain_id: CHAIN_ID,
            nonce: 1,
            gas_price: 2000 / 10u128.pow(6),
            gas_limit: 100000,
            to_addr: zil_addr,
            amount: 1 / 10u128.pow(6),
            code: Vec::new(),
            data: Vec::new(),
        };

        let tx_bytes = create_proto_tx(&tx_req, &zil_pub_key).encode_proto_bytes();
        assert_eq!(hex::encode(&tx_bytes), SHOULD_BE_BYTES);

        let tx_receipt = ZILTransactionReceipt {
            version: version_from_chainid(CHAIN_ID),
            nonce: tx_req.nonce,
            gas_price: tx_req.gas_price.to_be_bytes(),
            gas_limit: tx_req.gas_limit,
            to_addr: *tx_req.to_addr.addr_bytes(),
            amount: tx_req.amount.to_be_bytes(),
            pub_key: zil_pub_key.as_bytes(),
            code: tx_req.code.clone(),
            data: tx_req.data.clone(),
            signature: (&tx_bytes[..SHA512_SIZE]).try_into().unwrap(),
            priority: false,
        };

        let restored_req_tx = ZILTransactionRequest::from(tx_receipt);
        let tx_bytes = create_proto_tx(&restored_req_tx, &zil_pub_key).encode_proto_bytes();

        assert_eq!(hex::encode(&tx_bytes), SHOULD_BE_BYTES);
        assert_eq!(&restored_req_tx, &tx_req);
    }
}
