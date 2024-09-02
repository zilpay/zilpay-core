use config::sha::{ECDSAS_ECP256K1_KECCAK256_SIZE, SHA512_SIZE};
use ethers::core::types::Signature as EthersSignature;
use k256::ecdsa::Signature as ZilSignature;
use zil_errors::SignatureError;

pub enum Signature {
    SchnorrSecp256k1Sha256([u8; SHA512_SIZE]), // Zilliqa
    ECDSASecp256k1Keccak256([u8; ECDSAS_ECP256K1_KECCAK256_SIZE]), // Ethereum
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

impl TryFrom<ZilSignature> for Signature {
    type Error = SignatureError;

    fn try_from(sig: ZilSignature) -> Result<Self, Self::Error> {
        let sig_bytes: [u8; SHA512_SIZE] = sig
            .to_bytes()
            .try_into()
            .map_err(|_| SignatureError::InvalidLength)?;

        Ok(Signature::SchnorrSecp256k1Sha256(sig_bytes))
    }
}
