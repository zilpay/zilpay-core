use hmac_drbg::HmacDRBG;
use k256::{
    ecdsa::{signature::Signer, Signature},
    elliptic_curve::scalar::IsHigh,
    ProjectivePoint, PublicKey, Scalar, SecretKey,
};
use rand_core::OsRng;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use sha2::{Digest, Sha256};

use zil_errors::ZilliqaErrors;

const PUBKEY_COMPRESSED_SIZE_BYTES: usize = 33;
const ALG: &[u8] = b"Schnorr+SHA256  ";
const ALG_LEN: usize = 16;
const ENT_LEN: usize = 32;

pub struct Schnorr {
    private_key: SecretKey,
    public_key: PublicKey,
}

impl Schnorr {
    pub fn new(private_key: &[u8]) -> Result<Self, ZilliqaErrors> {
        let private_key = SecretKey::from_slice(private_key)
            .or(Err(ZilliqaErrors::Schnorr("Invalid Private Key")))?;
        let secp = Secp256k1::new();

        Ok(Self {
            private_key,
            public_key,
        })
    }
}
