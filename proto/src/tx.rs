use crate::keypair::KeyPair;
use crate::pubkey::PubKey;
use crate::signature::Signature;
use crate::zil_tx::{ZILTransactionReceipt, ZILTransactionRequest};
use crate::zq1_proto::{create_proto_tx, version_from_chainid};
use alloy::consensus::TxEnvelope;
use alloy::network::TransactionBuilder;
use alloy::rpc::types::TransactionRequest as ETHTransactionRequest;
use crypto::schnorr::sign as zil_sign;
use k256::SecretKey as K256SecretKey;
use serde::{Deserialize, Serialize};
use zil_errors::keypair::KeyPairError;
use zil_errors::tx::TransactionErrors;

#[derive(Debug, Clone, PartialEq, Serialize)]
pub enum TransactionReceipt {
    Zilliqa(ZILTransactionReceipt), // ZILLIQA
    Ethereum(TxEnvelope),           // Ethereum
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum TransactionRequest {
    Zilliqa(ZILTransactionRequest),  // ZILLIQA
    Ethereum(ETHTransactionRequest), // Ethereum
}

impl TransactionReceipt {
    pub fn verify(&self) -> Result<bool, TransactionErrors> {
        match self {
            Self::Zilliqa(tx) => {
                let pub_key = PubKey::Secp256k1Sha256Zilliqa(tx.pub_key);
                let sig: Signature = Signature::SchnorrSecp256k1Sha256(tx.signature);
                let bytes = create_proto_tx(&tx.into(), &pub_key).encode_proto_bytes();
                let verify = sig.verify(&bytes, &pub_key)?;

                Ok(verify)
            }

            Self::Ethereum(_tx) => unreachable!(),
        }
    }

    #[inline]
    pub fn hash(&self) -> Option<&str> {
        match self {
            Self::Zilliqa(tx) => tx.metadata.hash.as_deref(),
            Self::Ethereum(_tx) => todo!(),
        }
    }
}

impl TransactionRequest {
    pub async fn sign(self, keypair: &KeyPair) -> Result<TransactionReceipt, TransactionErrors> {
        match self {
            TransactionRequest::Zilliqa(tx) => {
                let pub_key = keypair.get_pubkey()?;
                let bytes = create_proto_tx(&tx, &pub_key).encode_proto_bytes();
                let secret_key = K256SecretKey::from_slice(&keypair.get_sk_bytes())
                    .or(Err(KeyPairError::InvalidSecretKey))?;
                let signature = zil_sign(&bytes, &secret_key)
                    .map_err(|e| KeyPairError::EthersInvalidSign(e.to_string()))?;
                let signature = signature.to_bytes().into();

                Ok(TransactionReceipt::Zilliqa(ZILTransactionReceipt {
                    metadata: tx.metadata,
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
                }))
            }
            TransactionRequest::Ethereum(tx) => {
                let wallet = keypair.get_local_eth_wallet()?;
                let tx_envelope = tx
                    .clone()
                    .build(&wallet)
                    .await
                    .map_err(|e| KeyPairError::FailToSignTx(e.to_string()))?;

                Ok(TransactionReceipt::Ethereum(tx_envelope))
            }
        }
    }

    pub fn json(&self) -> Result<String, serde_json::Error> {
        match self {
            Self::Zilliqa(tx) => serde_json::to_string(tx),
            Self::Ethereum(tx) => serde_json::to_string(tx),
        }
    }
}

#[cfg(test)]
mod tests_tx {
    use super::*;
    use crate::keypair::KeyPair;
    use tokio;

    const CHAIN_ID: u16 = 42;

    #[tokio::test]
    async fn test_sign_verify_zil_tx() {
        let key_pair = KeyPair::gen_sha256().unwrap();
        let zil_addr = key_pair.get_addr().unwrap();
        let tx_req = TransactionRequest::Zilliqa(ZILTransactionRequest {
            metadata: Default::default(),
            chain_id: CHAIN_ID,
            nonce: 1,
            gas_price: 2000 * 10u128.pow(6),
            gas_limit: 100000,
            to_addr: zil_addr,
            amount: 10u128.pow(12),
            code: Vec::with_capacity(0),
            data: Vec::with_capacity(0),
        });
        let tx_res = tx_req.sign(&key_pair).await.unwrap();
        let veify = tx_res.verify();

        assert!(veify.is_ok());
        assert!(veify.unwrap());
    }
}
