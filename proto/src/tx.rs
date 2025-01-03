use crate::keypair::KeyPair;
use crate::pubkey::PubKey;
use crate::signature::Signature;
use crate::zil_tx::{
    encode_zilliqa_transaction, version_from_chainid, ZILTransactionReceipt, ZILTransactionRequest,
};
use alloy::consensus::TxEnvelope;
use alloy::network::TransactionBuilder;
use alloy::rpc::types::TransactionRequest as ETHTransactionRequest;
use crypto::schnorr::sign as zil_sign;
use k256::SecretKey as K256SecretKey;
use zil_errors::keypair::KeyPairError;
use zil_errors::tx::TransactionErrors;

#[derive(Debug, PartialEq, Eq)]
pub enum TransactionReceipt {
    Zilliqa(ZILTransactionReceipt), // ZILLIQA
    Ethereum(TxEnvelope),           // Ethereum
}

#[derive(Debug, PartialEq, Eq)]
pub enum TransactionRequest {
    Zilliqa(ZILTransactionRequest),  // ZILLIQA
    Ethereum(ETHTransactionRequest), // Ethereum
}

impl TransactionReceipt {
    pub fn verify(&self) -> Result<bool, TransactionErrors> {
        match self {
            Self::Zilliqa(tx) => {
                let pub_key = PubKey::from_33_bytes_zil_hex(&tx.pub_key)?;
                let sig: Signature = Signature::from_hex(&tx.signature)?;
                let req_tx: ZILTransactionRequest = tx.clone().try_into()?;
                let bytes = encode_zilliqa_transaction(&req_tx, &pub_key);
                let verify = sig.verify(&bytes, &pub_key)?;

                Ok(verify)
            }

            Self::Ethereum(_tx) => unreachable!(),
        }
    }
}

impl TransactionRequest {
    pub async fn sign(self, keypair: &KeyPair) -> Result<TransactionReceipt, KeyPairError> {
        match self {
            TransactionRequest::Zilliqa(tx) => {
                let pub_key = keypair.get_pubkey()?;
                let pub_key_hex = pub_key.as_hex_str();
                let bytes = encode_zilliqa_transaction(&tx, &pub_key);
                let secret_key = K256SecretKey::from_slice(&keypair.get_sk_bytes())
                    .or(Err(KeyPairError::InvalidSecretKey))?;
                let signature = zil_sign(&bytes, &secret_key)
                    .map_err(|e| KeyPairError::EthersInvalidSign(e.to_string()))?;
                let signature = hex::encode(signature.to_bytes());
                // let to_addr = tx.to_addr.to_eth_checksummed()?; // TODO: maybe need change to zil base16
                let to_addr = tx.to_addr.get_zil_base16()?;

                Ok(TransactionReceipt::Zilliqa(ZILTransactionReceipt {
                    signature,
                    to_addr,
                    pub_key: pub_key_hex,
                    version: version_from_chainid(tx.chain_id),
                    nonce: tx.nonce,
                    gas_price: tx.gas_price,
                    gas_limit: tx.gas_limit,
                    amount: tx.amount,
                    code: tx.code,
                    data: tx.data,
                    priority: false, // TODO: no more use in ZILLiqa chain
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
    use crate::{
        keypair::KeyPair,
        zil_tx::{ScillaGas, ZilAmount},
    };
    use tokio;

    const CHAIN_ID: u16 = 42;

    #[tokio::test]
    async fn test_sign_verify_zil_tx() {
        let key_pair = KeyPair::gen_sha256().unwrap();
        let zil_addr = key_pair.get_addr().unwrap();
        let tx_req = TransactionRequest::Zilliqa(ZILTransactionRequest {
            chain_id: CHAIN_ID,
            nonce: 1,
            gas_price: ZilAmount::from_amount(2000),
            gas_limit: ScillaGas(100000),
            to_addr: zil_addr,
            amount: ZilAmount::from_amount(1),
            code: String::with_capacity(0),
            data: String::with_capacity(0),
        });
        let tx_res = tx_req.sign(&key_pair).await.unwrap();
        let veify = tx_res.verify();

        assert!(veify.is_ok());
        assert!(veify.unwrap());
    }
}
