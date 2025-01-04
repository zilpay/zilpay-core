use crate::{pubkey::PubKey, zil_tx::ZILTransactionRequest};

#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ByteArray {
    #[prost(bytes = "vec", tag = "1")]
    pub data: Vec<u8>,
}

impl From<[u8; 16]> for ByteArray {
    fn from(data: [u8; 16]) -> Self {
        ByteArray {
            data: data.to_vec(),
        }
    }
}

impl From<[u8; 20]> for ByteArray {
    fn from(data: [u8; 20]) -> Self {
        ByteArray {
            data: data.to_vec(),
        }
    }
}

impl From<[u8; 33]> for ByteArray {
    fn from(data: [u8; 33]) -> Self {
        ByteArray {
            data: data.to_vec(),
        }
    }
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct ProtoTransactionCoreInfo {
    #[prost(uint32, tag = "1")]
    pub version: u32,
    #[prost(bytes = "vec", tag = "3")]
    pub toaddr: Vec<u8>,
    #[prost(message, optional, tag = "4")]
    pub senderpubkey: Option<ByteArray>,
    #[prost(message, optional, tag = "5")]
    pub amount: Option<ByteArray>,
    #[prost(message, optional, tag = "6")]
    pub gasprice: Option<ByteArray>,
    #[prost(uint64, tag = "7")]
    pub gaslimit: u64,
    #[prost(oneof = "Nonce", tags = "2")]
    pub oneof2: Option<Nonce>,
    #[prost(oneof = "Code", tags = "8")]
    pub oneof8: Option<Code>,
    #[prost(oneof = "Data", tags = "9")]
    pub oneof9: Option<Data>,
}

#[derive(Clone, PartialEq, prost::Oneof)]
pub enum Nonce {
    #[prost(uint64, tag = "2")]
    Nonce(u64),
}

#[derive(Clone, PartialEq, prost::Oneof)]
pub enum Code {
    #[prost(bytes, tag = "8")]
    Code(Vec<u8>),
}

#[derive(Clone, PartialEq, prost::Oneof)]
pub enum Data {
    #[prost(bytes, tag = "9")]
    Data(Vec<u8>),
}

pub fn create_proto_tx(txn: &ZILTransactionRequest, pub_key: &PubKey) -> ProtoTransactionCoreInfo {
    ProtoTransactionCoreInfo {
        version: version_from_chainid(txn.chain_id),
        toaddr: txn.to_addr.addr_bytes().to_vec(),
        senderpubkey: Some(pub_key.as_bytes().into()),
        amount: Some(txn.amount.to_be_bytes().into()),
        gasprice: Some(txn.gas_price.to_be_bytes().into()),
        gaslimit: txn.gas_limit,
        oneof2: Some(Nonce::Nonce(txn.nonce)),
        oneof8: (!txn.code.is_empty()).then(|| Code::Code(txn.code.clone())),
        oneof9: (!txn.data.is_empty()).then(|| Data::Data(txn.data.clone())),
    }
}

#[inline]
pub fn version_from_chainid(chain_id: u16) -> u32 {
    ((chain_id as u32) << 16) | 0x0001
}

#[inline]
pub fn chainid_from_version(version: u32) -> u16 {
    (version >> 16) as u16
}

impl ProtoTransactionCoreInfo {
    #[inline]
    pub fn encode_proto_bytes(&self) -> Vec<u8> {
        prost::Message::encode_to_vec(self)
    }
}

#[cfg(test)]
mod tests_tx_encode_proto_zil {
    use super::*;
    const CHAIN_ID: u16 = 42;

    #[test]
    fn test_chainid_version() {
        let version = version_from_chainid(CHAIN_ID);
        assert_eq!(version, 2752513);
        let chain_id = chainid_from_version(version);
        assert_eq!(chain_id, CHAIN_ID);
    }
}
