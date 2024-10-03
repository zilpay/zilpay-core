use alloy::signers::k256;
use alloy::signers::Signature as EthersSignature;
use config::sha::{ECDSAS_ECP256K1_KECCAK256_SIZE, SHA256_SIZE, SHA512_SIZE};
use crypto::schnorr;
use k256::ecdsa::Signature as SchnorrSignature;
use k256::PublicKey as K256PublicKey;
use zil_errors::crypto::SignatureError;

use crate::pubkey::PubKey;

#[derive(Debug, PartialEq, Eq)]
pub enum Signature {
    SchnorrSecp256k1Sha256([u8; SHA512_SIZE]), // Zilliqa
    ECDSASecp256k1Keccak256([u8; ECDSAS_ECP256K1_KECCAK256_SIZE]), // Ethereum
}

impl Signature {
    pub fn verify(&self, msg_bytes: &[u8], pk: &PubKey) -> Result<bool, SignatureError> {
        match self {
            Signature::SchnorrSecp256k1Sha256(sig) => {
                let sig = SchnorrSignature::from_slice(sig)
                    .or(Err(SignatureError::FailParseSignature))?;
                let pk: K256PublicKey = pk.try_into().map_err(SignatureError::FailIntoPubKey)?;
                let verify = schnorr::verify(msg_bytes, pk, sig);

                Ok(verify.is_some())
            }
            Signature::ECDSASecp256k1Keccak256(sig) => {
                let signature = EthersSignature::from_bytes_and_parity(&sig[..64], sig[64] as u64)
                    .or(Err(SignatureError::FailParseSignature))?;
                let signer_address = pk
                    .get_bytes_addr()
                    .map_err(SignatureError::FailIntoPubKey)?;
                let recovered_address = signature
                    .recover_address_from_msg(msg_bytes)
                    .map_err(|e| SignatureError::FailParseRecover(e.to_string()))?;

                Ok(recovered_address == signer_address)
            }
        }
    }
}

impl TryFrom<&[u8]> for Signature {
    type Error = SignatureError;

    fn try_from(sig_bytes: &[u8]) -> Result<Self, Self::Error> {
        if sig_bytes.len() == SHA256_SIZE {
            let buf: [u8; SHA512_SIZE] = sig_bytes
                .try_into()
                .or(Err(SignatureError::InvalidLength))?;

            Ok(Signature::SchnorrSecp256k1Sha256(buf))
        } else if sig_bytes.len() == ECDSAS_ECP256K1_KECCAK256_SIZE {
            let buf: [u8; ECDSAS_ECP256K1_KECCAK256_SIZE] = sig_bytes
                .try_into()
                .or(Err(SignatureError::InvalidLength))?;

            Ok(Signature::ECDSASecp256k1Keccak256(buf))
        } else {
            Err(SignatureError::InvalidLength)
        }
    }
}

impl TryFrom<EthersSignature> for Signature {
    type Error = SignatureError;

    fn try_from(eth_sig: EthersSignature) -> Result<Self, Self::Error> {
        let sig_bytes: [u8; ECDSAS_ECP256K1_KECCAK256_SIZE] = eth_sig.into();

        Ok(Signature::ECDSASecp256k1Keccak256(sig_bytes))
    }
}

impl TryFrom<SchnorrSignature> for Signature {
    type Error = SignatureError;

    fn try_from(sig: SchnorrSignature) -> Result<Self, Self::Error> {
        let sig_bytes: [u8; SHA512_SIZE] = sig.to_bytes().into();

        Ok(Signature::SchnorrSecp256k1Sha256(sig_bytes))
    }
}
