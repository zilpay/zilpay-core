use crate::address::Address;
use crate::keypair::KeyPair;
use crate::pubkey::PubKey;
use crate::signature::Signature;
use crate::zil_tx::{ZILTransactionReceipt, ZILTransactionRequest};
use crate::zq1_proto::{create_proto_tx, version_from_chainid};
use alloy::consensus::{SignableTransaction, TxEip4844Variant, TxEnvelope, TypedTransaction};
use alloy::network::TransactionBuilder;
use alloy::primitives::{TxKind, U256};
use alloy::signers::Signature as EthersSignature;
use config::sha::SHA512_SIZE;
use crypto::schnorr::sign as zil_sign;
use errors::crypto::SignatureError;
use errors::keypair::KeyPairError;
use errors::tx::TransactionErrors;
use k256::SecretKey as K256SecretKey;
use serde::{Deserialize, Serialize};

pub type ETHTransactionRequest = alloy::rpc::types::eth::request::TransactionRequest;

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct TransactionMetadata {
    pub chain_hash: u64,
    pub hash: Option<String>,
    pub info: Option<String>,
    pub icon: Option<String>,
    pub title: Option<String>,
    pub signer: Option<PubKey>,
    pub token_info: Option<(U256, u8, String)>,
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Serialize)]
pub enum TransactionReceipt {
    Zilliqa((ZILTransactionReceipt, TransactionMetadata)), // ZILLIQA
    Ethereum((TxEnvelope, TransactionMetadata)),           // Ethereum
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum TransactionRequest {
    Zilliqa((ZILTransactionRequest, TransactionMetadata)), // ZILLIQA
    Ethereum((ETHTransactionRequest, TransactionMetadata)), // Ethereum
}

impl TransactionReceipt {
    pub fn verify(&self) -> Result<bool, TransactionErrors> {
        match self {
            Self::Zilliqa((tx, _meta)) => {
                let pub_key = PubKey::Secp256k1Sha256(tx.pub_key);
                let sig: Signature = Signature::SchnorrSecp256k1Sha256(tx.signature);
                let bytes = create_proto_tx(&tx.into(), &pub_key).encode_proto_bytes();
                let verify = sig.verify(&bytes, &pub_key)?;

                Ok(verify)
            }

            Self::Ethereum((tx, metadata)) => {
                let pub_key = metadata
                    .signer
                    .as_ref()
                    .ok_or(KeyPairError::InvalidPublicKey)?;

                if let Ok(signer) = tx.recover_signer() {
                    let addr = pub_key.get_addr()?.to_alloy_addr();

                    Ok(addr == signer)
                } else {
                    Ok(false)
                }
            }
        }
    }

    #[inline]
    pub fn hash(&self) -> Option<&str> {
        match self {
            Self::Zilliqa((_tx, metadata)) => metadata.hash.as_deref(),
            Self::Ethereum((_tx, meta)) => meta.hash.as_deref(),
        }
    }

    #[inline]
    pub fn get_mut_metadata(&mut self) -> &mut TransactionMetadata {
        match self {
            Self::Zilliqa((_tx, ref mut metadata)) => metadata,
            Self::Ethereum((_tx, ref mut metadata)) => metadata,
        }
    }

    #[inline]
    pub fn get_metadata(&self) -> &TransactionMetadata {
        match self {
            Self::Zilliqa((_tx, ref metadata)) => metadata,
            Self::Ethereum((_tx, ref metadata)) => metadata,
        }
    }
}

impl TransactionRequest {
    pub async fn sign(self, keypair: &KeyPair) -> Result<TransactionReceipt, TransactionErrors> {
        match self {
            TransactionRequest::Zilliqa((tx, metadata)) => {
                let pub_key = keypair.get_pubkey()?;
                let bytes = create_proto_tx(&tx, &pub_key).encode_proto_bytes();
                let secret_key = K256SecretKey::from_slice(&keypair.get_sk_bytes())
                    .or(Err(KeyPairError::InvalidSecretKey))?;
                let signature = zil_sign(&bytes, &secret_key)
                    .map_err(|e| KeyPairError::EthersInvalidSign(e.to_string()))?;
                let signature = signature.to_bytes().into();
                let tx = ZILTransactionReceipt {
                    signature,
                    to_addr: *tx.to_addr.addr_bytes(),
                    pub_key: pub_key.as_bytes(),
                    version: version_from_chainid(tx.chain_id),
                    nonce: tx.nonce,
                    gas_price: tx.gas_price.to_be_bytes(),
                    gas_limit: tx.gas_limit,
                    amount: tx.amount.to_be_bytes(),
                    code: tx.code,
                    data: tx.data,
                    priority: false,
                };

                Ok(TransactionReceipt::Zilliqa((tx, metadata)))
            }
            TransactionRequest::Ethereum((tx, mut metadata)) => {
                let wallet = keypair.get_local_eth_wallet()?;
                let tx_envelope = tx
                    .clone()
                    .build(&wallet)
                    .await
                    .map_err(|e| KeyPairError::FailToSignTx(e.to_string()))?;
                let pub_key_bytes = keypair.get_pubkey_bytes();

                metadata.signer = Some(PubKey::Secp256k1Keccak256(*pub_key_bytes));

                Ok(TransactionReceipt::Ethereum((tx_envelope, metadata)))
            }
        }
    }

    pub fn to_rlp_encode(self, pub_key: &PubKey) -> Result<Vec<u8>, TransactionErrors> {
        match self {
            TransactionRequest::Zilliqa((tx, _metadata)) => {
                let proto_buf = create_proto_tx(&tx, pub_key).encode_proto_bytes();

                Ok(proto_buf)
            }
            TransactionRequest::Ethereum((tx, _)) => {
                let mut capacity = 0;

                capacity += 9;

                if tx.nonce.is_some() {
                    capacity += 9;
                }
                if tx.gas.is_some() {
                    capacity += 9;
                }
                if let Some(TxKind::Call(_)) = tx.to {
                    capacity += 21;
                }
                if tx.value.is_some() {
                    capacity += 33;
                }
                if tx.chain_id.is_some() {
                    capacity += 9;
                }
                if let Some(input) = &tx.input.input {
                    capacity += 9 + input.len();
                }
                if let Some(data) = &tx.input.data {
                    capacity += 9 + data.len();
                }
                if tx.max_fee_per_gas.is_some() {
                    capacity += 17;
                }
                if tx.max_priority_fee_per_gas.is_some() {
                    capacity += 17;
                }

                let mut rlp_bytes = Vec::with_capacity(capacity);

                tx.build_consensus_tx()
                    .map_err(|_| TransactionErrors::EncodeTxRlpError)?
                    .encode_for_signing(&mut rlp_bytes);

                Ok(rlp_bytes)
            }
        }
    }

    pub fn with_signature(
        self,
        signature_bytes: Vec<u8>,
        pub_key: &PubKey,
    ) -> Result<TransactionReceipt, TransactionErrors> {
        match self {
            TransactionRequest::Ethereum((tx, metadata)) => {
                let sig = EthersSignature::from_raw(&signature_bytes)
                    .map_err(|_| TransactionErrors::BuildErrorEthSig)?;
                let typed_tx = tx
                    .build_typed_tx()
                    .map_err(|_| TransactionErrors::BuildErrorTypedTx)?;
                let signed_tx = match typed_tx {
                    TypedTransaction::Legacy(tx) => TxEnvelope::Legacy(tx.into_signed(sig)),
                    TypedTransaction::Eip2930(tx) => TxEnvelope::Eip2930(tx.into_signed(sig)),
                    TypedTransaction::Eip1559(tx) => TxEnvelope::Eip1559(tx.into_signed(sig)),
                    TypedTransaction::Eip4844(TxEip4844Variant::TxEip4844(_)) => {
                        return Err(TransactionErrors::BuildErrorTypedTx);
                    }
                    TypedTransaction::Eip4844(TxEip4844Variant::TxEip4844WithSidecar(tx)) => {
                        TxEnvelope::Eip4844(tx.into_signed(sig).into())
                    }
                    TypedTransaction::Eip7702(tx) => TxEnvelope::Eip7702(tx.into_signed(sig)),
                };

                Ok(TransactionReceipt::Ethereum((signed_tx, metadata)))
            }
            TransactionRequest::Zilliqa((tx, metadata)) => {
                let signature: [u8; SHA512_SIZE] = signature_bytes
                    .try_into()
                    .map_err(|_| SignatureError::InvalidLength)?;
                let signed_tx = ZILTransactionReceipt {
                    signature,
                    to_addr: *tx.to_addr.addr_bytes(),
                    pub_key: pub_key.as_bytes(),
                    version: version_from_chainid(tx.chain_id),
                    nonce: tx.nonce,
                    gas_price: tx.gas_price.to_be_bytes(),
                    gas_limit: tx.gas_limit,
                    amount: tx.amount.to_be_bytes(),
                    code: tx.code,
                    data: tx.data,
                    priority: false,
                };

                Ok(TransactionReceipt::Zilliqa((signed_tx, metadata)))
            }
        }
    }

    pub fn to(&self) -> Address {
        match self {
            TransactionRequest::Zilliqa((tx, _)) => tx.to_addr.clone(),
            TransactionRequest::Ethereum((tx, _)) => {
                if let Some(tx_kind) = tx.to {
                    match tx_kind {
                        TxKind::Call(addr) => Address::from_eth_address(&addr.to_string()).unwrap(),
                        TxKind::Create => Address::Secp256k1Keccak256(Address::ZERO),
                    }
                } else {
                    Address::Secp256k1Keccak256(Address::ZERO)
                }
            }
        }
    }

    pub fn set_icon(&mut self, icon: String) {
        match self {
            TransactionRequest::Zilliqa((_, metadata)) => {
                metadata.icon = Some(icon);
            }
            TransactionRequest::Ethereum((_, metadata)) => {
                metadata.icon = Some(icon);
            }
        }
    }
}

#[cfg(test)]
mod tests_tx {
    use super::*;
    use crate::{address::Address, keypair::KeyPair};
    use alloy::{
        consensus::BlobTransactionSidecar,
        primitives::B256,
        rpc::types::{AccessList, AccessListItem, Authorization},
    };
    use tokio;

    const CHAIN_ID: u16 = 42;

    #[tokio::test]
    async fn test_sign_verify_zil_tx() {
        let key_pair = KeyPair::gen_sha256().unwrap();
        let zil_addr = key_pair.get_addr().unwrap();
        let zil_tx = ZILTransactionRequest {
            chain_id: CHAIN_ID,
            nonce: 1,
            gas_price: 2000 * 10u128.pow(6),
            gas_limit: 100000,
            to_addr: zil_addr,
            amount: 10u128.pow(12),
            code: Vec::with_capacity(0),
            data: Vec::with_capacity(0),
        };
        let tx_req = TransactionRequest::Zilliqa((zil_tx, Default::default()));
        let tx_res = tx_req.sign(&key_pair).await.unwrap();
        let veify = tx_res.verify();

        assert!(veify.is_ok());
        assert!(veify.unwrap());
    }

    #[tokio::test]
    async fn test_sign_verify_eth_tx_eip1559() {
        let key_pair = KeyPair::gen_keccak256().unwrap();
        let eth_addr =
            Address::from_eth_address("0x70997970c51812dc3a010c7d01b50e0d17dc79c8").unwrap();

        let max_prio_fee = 987;
        let eip1559_request = ETHTransactionRequest {
            to: Some(eth_addr.to_alloy_addr().into()),
            max_fee_per_gas: Some(1234),
            max_priority_fee_per_gas: Some(max_prio_fee),
            nonce: Some(57),
            gas: Some(123456),
            ..Default::default()
        };
        let tx_req = TransactionRequest::Ethereum((eip1559_request, Default::default()));
        let tx_res = tx_req.sign(&key_pair).await.unwrap();
        let veify = tx_res.verify();

        assert!(veify.is_ok());
        assert!(veify.unwrap());
    }

    #[tokio::test]
    async fn test_sign_verify_eth_tx_eip2930() {
        let key_pair = KeyPair::gen_keccak256().unwrap();
        let eth_addr =
            Address::from_eth_address("0x70997970c51812dc3a010c7d01b50e0d17dc79c8").unwrap();

        let access_list = AccessList(vec![AccessListItem {
            address: eth_addr.to_alloy_addr(),
            storage_keys: vec![B256::from([1u8; 32])],
        }]);

        let eip2930_request = ETHTransactionRequest {
            to: Some(eth_addr.to_alloy_addr().into()),
            gas_price: Some(1234),
            nonce: Some(57),
            gas: Some(123456),
            chain_id: Some(1),
            access_list: Some(access_list),
            transaction_type: Some(1),
            ..Default::default()
        };
        let tx_req = TransactionRequest::Ethereum((eip2930_request, Default::default()));
        let tx_res = tx_req.sign(&key_pair).await.unwrap();
        let verify = tx_res.verify();

        assert!(verify.is_ok());
        assert!(verify.unwrap());
    }

    #[tokio::test]
    async fn test_sign_verify_eth_tx_eip4844() {
        let key_pair = KeyPair::gen_keccak256().unwrap();
        let eth_addr =
            Address::from_eth_address("0x70997970c51812dc3a010c7d01b50e0d17dc79c8").unwrap();

        let storage_key = B256::from([2u8; 32]);
        let versioned_hash = B256::from([3u8; 32]);

        let access_list = AccessList(vec![AccessListItem {
            address: eth_addr.to_alloy_addr(),
            storage_keys: vec![storage_key],
        }]);

        let blob_versioned_hashes = vec![versioned_hash];

        let sidecar = BlobTransactionSidecar {
            blobs: vec![[0u8; 131072].into()],
            commitments: vec![[0u8; 48].into()],
            proofs: vec![[0u8; 48].into()],
        };

        let eip4844_request = ETHTransactionRequest {
            to: Some(eth_addr.to_alloy_addr().into()),
            max_fee_per_gas: Some(1234),
            max_priority_fee_per_gas: Some(987),
            max_fee_per_blob_gas: Some(100000),
            nonce: Some(57),
            gas: Some(123456),
            chain_id: Some(1),
            access_list: Some(access_list),
            blob_versioned_hashes: Some(blob_versioned_hashes),
            transaction_type: Some(3),
            sidecar: Some(sidecar),
            ..Default::default()
        };
        let tx_req = TransactionRequest::Ethereum((eip4844_request, Default::default()));
        let tx_res = tx_req.sign(&key_pair).await.unwrap();
        let verify = tx_res.verify();

        assert!(verify.is_ok());
        assert!(verify.unwrap());
    }

    #[tokio::test]
    async fn test_sign_verify_eth_tx_eip7702() {
        let key_pair = KeyPair::gen_keccak256().unwrap();
        let eth_addr =
            Address::from_eth_address("0x70997970c51812dc3a010c7d01b50e0d17dc79c8").unwrap();

        let access_list = AccessList(vec![AccessListItem {
            address: eth_addr.to_alloy_addr(),
            storage_keys: vec![B256::from([5u8; 32])],
        }]);

        let auth = Authorization {
            chain_id: U256::from(1),
            address: eth_addr.to_alloy_addr(),
            nonce: 1u64,
        };
        let auth_sig = alloy::primitives::Signature::test_signature();
        let authorization_list = vec![auth.into_signed(auth_sig)];

        let eip7702_request = ETHTransactionRequest {
            to: Some(eth_addr.to_alloy_addr().into()),
            max_fee_per_gas: Some(1234),
            max_priority_fee_per_gas: Some(987),
            nonce: Some(57),
            gas: Some(123456),
            chain_id: Some(1),
            access_list: Some(access_list),
            authorization_list: Some(authorization_list),
            transaction_type: Some(4),
            ..Default::default()
        };
        let tx_req = TransactionRequest::Ethereum((eip7702_request, Default::default()));
        let tx_res = tx_req.sign(&key_pair).await.unwrap();
        let verify = tx_res.verify();

        assert!(verify.is_ok());
        assert!(verify.unwrap());
    }
}
