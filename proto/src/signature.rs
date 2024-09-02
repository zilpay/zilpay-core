use config::sha::{ECDSAS_ECP256K1_KECCAK256_SIZE, SHA512_SIZE};
use crypto::schnorr;
use ethers::core::types::Signature as EthersSignature;
use k256::ecdsa::Signature as SchnorrSignature;
use k256::PublicKey as K256PublicKey;
use zil_errors::SignatureError;

use crate::pubkey::PubKey;

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
            Signature::ECDSASecp256k1Keccak256(sig) => Ok(true),
        }
    }
}

impl TryFrom<EthersSignature> for Signature {
    type Error = SignatureError;

    fn try_from(eth_sig: EthersSignature) -> Result<Self, Self::Error> {
        let sig_bytes: [u8; ECDSAS_ECP256K1_KECCAK256_SIZE] = eth_sig
            .try_into()
            .map_err(|_| SignatureError::InvalidLength)?;

        Ok(Signature::ECDSASecp256k1Keccak256(sig_bytes))
    }
}

impl TryFrom<SchnorrSignature> for Signature {
    type Error = SignatureError;

    fn try_from(sig: SchnorrSignature) -> Result<Self, Self::Error> {
        let sig_bytes: [u8; SHA512_SIZE] = sig
            .to_bytes()
            .try_into()
            .map_err(|_| SignatureError::InvalidLength)?;

        Ok(Signature::SchnorrSecp256k1Sha256(sig_bytes))
    }
}
