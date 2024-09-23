use crate::keypair::KeyPair;
use crate::zil_tx::{encode_zilliqa_transaction, ZILTransactionReceipt, ZILTransactionRequest};
use crypto::schnorr::sign as zil_sign;
use ethers::types::TransactionRequest as ETHTransactionRequest;
use k256::SecretKey as K256SecretKey;
use zil_errors::keypair::KeyPairError;

#[derive(Debug, PartialEq, Eq)]
pub enum TransactionReceipt {
    Zilliqa(ZILTransactionReceipt),  // ZILLIQA
    Ethereum(ETHTransactionRequest), // Ethereum
}

#[derive(Debug, PartialEq, Eq)]
pub enum TransactionRequest {
    Zilliqa(ZILTransactionRequest),  // ZILLIQA
    Ethereum(ETHTransactionRequest), // Ethereum
}

impl TransactionRequest {
    pub fn sign(&self, keypair: &KeyPair) -> Result<TransactionReceipt, KeyPairError> {
        match self {
            TransactionRequest::Zilliqa(tx) => {
                let pub_key = keypair.get_pubkey()?;
                let bytes = encode_zilliqa_transaction(tx, pub_key);
                let secret_key = keypair.get_secretkey()?.to_vec();
                let secret_key = K256SecretKey::from_slice(&secret_key)
                    .or(Err(KeyPairError::InvalidSecretKey))?;
                let signature = zil_sign(&bytes, &secret_key)
                    .map_err(|e| KeyPairError::EthersInvalidSign(e.to_string()))?;
                let signature = hex::encode(signature.to_bytes());

                Ok(TransactionReceipt::Zilliqa(ZILTransactionReceipt {
                    signature,
                    chain_id: tx.chain_id,
                    nonce: tx.nonce,
                    gas_price: tx.gas_price,
                    gas_limit: tx.gas_limit,
                    to_addr: tx.to_addr.clone(),
                    amount: tx.amount,
                    code: tx.code.clone(),
                    data: tx.data.clone(),
                }))
            }
            TransactionRequest::Ethereum(tx) => {
                unimplemented!()
            }
        }
    }
}

#[cfg(test)]
mod tests_transaction_request {
    use super::*;

    #[test]
    fn test_sign_zil() {}
}
