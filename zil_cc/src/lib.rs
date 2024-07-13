use k256::{
    ecdsa::{signature::Signer, Signature, SigningKey},
    elliptic_curve::scalar::IsHigh,
    ProjectivePoint, Scalar,
};

const PUBKEY_COMPRESSED_SIZE_BYTES: usize = 33;
const ALG: &[u8] = b"Schnorr+SHA256  ";
const ALG_LEN: usize = 16;
const ENT_LEN: usize = 32;

pub struct SchnorrControl {
    private_key: SigningKey,
    public_key: ProjectivePoint,
}
