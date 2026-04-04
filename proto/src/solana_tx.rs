use crate::{keypair::KeyPair, signature::Signature};
use errors::keypair::KeyPairError;
use serde::{Deserialize, Serialize};

type Result<T> = std::result::Result<T, KeyPairError>;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SolanaTransaction {
    #[serde(with = "hex::serde")]
    pub message: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SolanaTransactionReceipt {
    #[serde(with = "hex::serde")]
    pub message: Vec<u8>,
    #[serde(with = "hex::serde")]
    pub signature: Vec<u8>,
}

impl SolanaTransaction {
    pub fn sign(&self, keypair: &KeyPair) -> Result<SolanaTransactionReceipt> {
        let sig = keypair.sign_message(&self.message)?;

        let sig_bytes = match sig {
            Signature::Ed25519Solana(bytes) => bytes.to_vec(),
            _ => return Err(KeyPairError::InvalidEd25519Solana),
        };

        Ok(SolanaTransactionReceipt {
            message: self.message.clone(),
            signature: sig_bytes,
        })
    }
}

impl SolanaTransactionReceipt {
    pub fn encode(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(1 + self.signature.len() + self.message.len());
        result.push(0x01);
        result.extend_from_slice(&self.signature);
        result.extend_from_slice(&self.message);
        result
    }

    pub fn tx_id(&self) -> String {
        bs58::encode(&self.signature).into_string()
    }

    pub fn verify(&self, keypair: &KeyPair) -> Result<bool> {
        let pk = keypair.get_pubkey()?;
        let sig_bytes: [u8; 64] = self
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| KeyPairError::InvalidEd25519Solana)?;
        let sig = Signature::Ed25519Solana(sig_bytes);
        sig.verify(&self.message, &pk)
            .map_err(KeyPairError::InvalidSignature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keypair::KeyPair;

    #[test]
    fn test_solana_tx_sign_and_encode() {
        let keypair = KeyPair::gen_solana().unwrap();
        let message = vec![1u8, 2, 3, 4, 5, 6, 7, 8];
        let tx = SolanaTransaction { message: message.clone() };

        let receipt = tx.sign(&keypair).unwrap();

        assert_eq!(receipt.message, message);
        assert_eq!(receipt.signature.len(), 64);

        let encoded = receipt.encode();
        assert_eq!(encoded[0], 0x01);
        assert_eq!(&encoded[1..65], receipt.signature.as_slice());
        assert_eq!(&encoded[65..], message.as_slice());
    }

    #[test]
    fn test_solana_tx_id() {
        let keypair = KeyPair::gen_solana().unwrap();
        let tx = SolanaTransaction { message: vec![0u8; 32] };
        let receipt = tx.sign(&keypair).unwrap();

        let tx_id = receipt.tx_id();
        assert!(!tx_id.is_empty());
        let decoded = bs58::decode(&tx_id).into_vec().unwrap();
        assert_eq!(decoded, receipt.signature);
    }

    #[test]
    fn test_solana_tx_verify() {
        let keypair = KeyPair::gen_solana().unwrap();
        let tx = SolanaTransaction { message: b"test solana transaction".to_vec() };
        let receipt = tx.sign(&keypair).unwrap();

        assert!(receipt.verify(&keypair).unwrap());
    }

    #[test]
    fn test_solana_tx_verify_wrong_keypair() {
        let keypair1 = KeyPair::gen_solana().unwrap();
        let keypair2 = KeyPair::gen_solana().unwrap();
        let tx = SolanaTransaction { message: b"test message".to_vec() };
        let receipt = tx.sign(&keypair1).unwrap();

        assert!(!receipt.verify(&keypair2).unwrap());
    }

    #[test]
    fn test_solana_tx_serde_roundtrip() {
        let keypair = KeyPair::gen_solana().unwrap();
        let tx = SolanaTransaction { message: vec![0xde, 0xad, 0xbe, 0xef] };
        let receipt = tx.sign(&keypair).unwrap();

        let json = serde_json::to_string(&receipt).unwrap();
        let recovered: SolanaTransactionReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(receipt, recovered);
    }
}
