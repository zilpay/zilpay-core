use crate::keypair::KeyPair;
use crate::pubkey::PubKey;
use crate::signature::Signature;
use crate::zil_tx::{
    encode_zilliqa_transaction, version_from_chainid, ZILTransactionReceipt, ZILTransactionRequest,
};
use alloy::consensus::TxEnvelope;
use alloy::network::TransactionBuilder;
use alloy::rpc::types::TransactionRequest as ETHTransactionRequest;
use config::sha::SHA512_SIZE;
use crypto::schnorr::sign as zil_sign;
use k256::SecretKey as K256SecretKey;
use zil_errors::keypair::KeyPairError;

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
    pub fn verify(&self) -> bool {
        match self {
            Self::Zilliqa(tx) => {
                let pub_key = match PubKey::from_hex(&tx.pub_key) {
                    Ok(pk) => pk,
                    Err(_) => return false,
                };
                let sig_bytes: [u8; SHA512_SIZE] = hex::decode(&tx.signature)
                    .unwrap_or_default()
                    .try_into()
                    .unwrap_or([0u8; SHA512_SIZE]);
                let sig = Signature::SchnorrSecp256k1Sha256(sig_bytes);
                // TODO: make convert bytes.
                // let bytes = encode_zilliqa_transaction(tx, &pub_key);

                // sig.verify(&bytes, &pub_key).unwrap_or(false)
                //
                false
            }
            Self::Ethereum(tx) => unreachable!(),
        }
    }
}

impl TransactionRequest {
    pub async fn sign(&self, keypair: &KeyPair) -> Result<TransactionReceipt, KeyPairError> {
        match self {
            TransactionRequest::Zilliqa(tx) => {
                let pub_key = keypair.get_pubkey()?;
                let bytes = encode_zilliqa_transaction(tx, &pub_key);
                let secret_key = keypair
                    .get_secretkey()?
                    .to_bytes()
                    .map_err(KeyPairError::SecretKeyError)?;
                let secret_key = K256SecretKey::from_slice(&secret_key)
                    .or(Err(KeyPairError::InvalidSecretKey))?;
                let signature = zil_sign(&bytes, &secret_key)
                    .map_err(|e| KeyPairError::EthersInvalidSign(e.to_string()))?;
                let signature = hex::encode(signature.to_bytes());
                let to_addr = tx.to_addr.to_eth_checksummed()?;

                Ok(TransactionReceipt::Zilliqa(ZILTransactionReceipt {
                    signature,
                    to_addr,
                    pub_key: hex::encode(pub_key.as_bytes()),
                    version: version_from_chainid(tx.chain_id),
                    nonce: tx.nonce,
                    gas_price: tx.gas_price,
                    gas_limit: tx.gas_limit,
                    amount: tx.amount,
                    code: tx.code.clone(),
                    data: tx.data.clone(),
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
