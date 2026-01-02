use config::sha::SHA256_SIZE;
use errors::bip32::Bip329Errors;
use hmac::{Hmac, Mac};
use k256::{
    elliptic_curve::{bigint::U256, scalar::FromUintUnchecked},
    SecretKey,
};
use sha2::Sha512;
use std::str::FromStr;

const HARDENED_BIT: u32 = 1 << 31;
const BITCOIN_SEED: &[u8] = b"Bitcoin seed";

type Result<T> = std::result::Result<T, Bip329Errors>;

#[derive(Clone, Debug)]
struct ChildNumber(u32);

impl ChildNumber {
    fn is_hardened(&self) -> bool {
        self.0 & HARDENED_BIT == HARDENED_BIT
    }

    fn to_bytes(&self) -> [u8; 4] {
        self.0.to_be_bytes()
    }
}

impl FromStr for ChildNumber {
    type Err = Bip329Errors;

    fn from_str(s: &str) -> Result<Self> {
        let (num_str, hardened) = if let Some(stripped) = s.strip_suffix('\'') {
            (stripped, true)
        } else {
            (s, false)
        };

        let index: u32 = num_str.parse().map_err(|e| {
            Bip329Errors::InvalidChild(format!("Failed to parse child number: {}", e))
        })?;

        if index >= HARDENED_BIT {
            return Err(Bip329Errors::InvalidChild(
                "Child number too large".to_string(),
            ));
        }

        Ok(ChildNumber(if hardened {
            index | HARDENED_BIT
        } else {
            index
        }))
    }
}

fn derive_master_key(seed: &[u8]) -> Result<(SecretKey, [u8; SHA256_SIZE])> {
    let mut hmac = Hmac::<Sha512>::new_from_slice(BITCOIN_SEED)
        .map_err(|e| Bip329Errors::HmacError(e.to_string()))?;

    hmac.update(seed);

    let result = hmac.finalize().into_bytes();
    let (key_bytes, chain_code) = result.split_at(32);

    let mut chain_code_arr = [0u8; SHA256_SIZE];
    chain_code_arr.copy_from_slice(chain_code);

    Ok((
        SecretKey::from_slice(key_bytes).map_err(|e| Bip329Errors::InvalidKey(e.to_string()))?,
        chain_code_arr,
    ))
}

pub fn derive_private_key(seed: &[u8], path: &str) -> Result<SecretKey> {
    if !path.starts_with("m/") {
        return Err(Bip329Errors::InvalidPath(
            "Path must start with 'm/'".to_string(),
        ));
    }

    let path_parts: Vec<&str> = path[2..].split('/').collect();
    let (mut key, mut chain_code) = derive_master_key(seed)?;

    for part in path_parts {
        if part.is_empty() {
            continue;
        }

        let child_number = ChildNumber::from_str(part)?;
        let (child_key, child_chain) = derive_child_key(&key, &chain_code, &child_number)?;
        key = child_key;
        chain_code = child_chain;
    }

    Ok(key)
}

fn derive_child_key(
    parent_key: &SecretKey,
    chain_code: &[u8; SHA256_SIZE],
    child: &ChildNumber,
) -> Result<(SecretKey, [u8; SHA256_SIZE])> {
    let mut hmac = Hmac::<Sha512>::new_from_slice(chain_code)
        .map_err(|e| Bip329Errors::HmacError(e.to_string()))?;

    if child.is_hardened() {
        hmac.update(&[0]);
        hmac.update(&parent_key.to_bytes());
    } else {
        hmac.update(&parent_key.public_key().to_sec1_bytes());
    }

    hmac.update(&child.to_bytes());

    let result = hmac.finalize().into_bytes();
    let (child_key, new_chain_code) = result.split_at(32);

    let child_scalar = U256::from_be_slice(child_key);
    let child_sk = k256::Scalar::from_uint_unchecked(child_scalar);

    let key_bytes = parent_key.to_bytes();
    let parent_scalar = U256::from_be_slice(&key_bytes);
    let parent_sk = k256::Scalar::from_uint_unchecked(parent_scalar);

    let sum = child_sk + parent_sk;
    let result = sum.to_bytes();

    let mut chain_code_arr = [0u8; 32];
    chain_code_arr.copy_from_slice(new_chain_code);

    Ok((
        SecretKey::from_slice(&result).map_err(|e| Bip329Errors::InvalidKey(e.to_string()))?,
        chain_code_arr,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use config::bip39::EN_WORDS;
    use crypto::bip49::DerivationPath;
    use pqbip39::mnemonic::Mnemonic;

    #[test]
    fn bip39_to_address() {
        use crypto::slip44;

        let phrase = "panda eyebrow bullet gorilla call smoke muffin taste mesh discover soft ostrich alcohol speed nation flash devote level hobby quick inner drive ghost inside";
        let expected_secret_key = b"\xff\x1e\x68\xeb\x7b\xf2\xf4\x86\x51\xc4\x7e\xf0\x17\x7e\xb8\x15\x85\x73\x22\x25\x7c\x58\x94\xbb\x4c\xfd\x11\x76\xc9\x98\x93\x14";
        let mnemonic = Mnemonic::parse_str(&EN_WORDS, phrase).unwrap();
        let seed = mnemonic.to_seed("").unwrap();

        let derivation_path =
            DerivationPath::new(slip44::ETHEREUM, 0, DerivationPath::BIP44_PURPOSE, None);
        let account = derive_private_key(&seed, &derivation_path.get_path()).unwrap();

        assert_eq!(
            expected_secret_key.to_vec(),
            account.to_bytes().to_vec(),
            "Secret key is invalid"
        );
    }

    #[test]
    fn bip39_to_btc_bip44_legacy() {
        use crate::address::Address;
        use crate::keypair::KeyPair;
        use crate::secret_key::SecretKey;
        use crypto::slip44;

        let phrase = "test test test test test test test test test test test junk";
        let mnemonic = Mnemonic::parse_str(&EN_WORDS, phrase).unwrap();
        let seed = mnemonic.to_seed("").unwrap();

        let derivation_path = DerivationPath::new(
            slip44::BITCOIN,
            0,
            DerivationPath::BIP44_PURPOSE,
            Some(bitcoin::Network::Bitcoin),
        );
        let btc_secret_key = derive_private_key(&seed, &derivation_path.get_path()).unwrap();

        let sk_bytes = btc_secret_key.to_bytes();
        let keypair = KeyPair::from_secret_key(SecretKey::Secp256k1Bitcoin((
            sk_bytes.into(),
            bitcoin::Network::Bitcoin,
            bitcoin::AddressType::P2pkh,
        )))
        .unwrap();

        let address = keypair.get_addr().unwrap();

        assert!(
            matches!(address, Address::Secp256k1Bitcoin(_)),
            "Address should be Bitcoin type"
        );

        let p2pkh_address = address.auto_format();
        assert!(
            p2pkh_address.starts_with('1'),
            "P2PKH address should start with '1'"
        );

        println!("BIP44 P2PKH Address: {}", p2pkh_address);
        println!("Public Key: {}", hex::encode(keypair.get_pubkey_bytes()));
    }

    #[test]
    fn bip39_to_btc_bip84_native_segwit() {
        use crate::address::Address;
        use crate::keypair::KeyPair;
        use crate::secret_key::SecretKey;
        use crypto::slip44;

        let phrase = "test test test test test test test test test test test junk";
        let mnemonic = Mnemonic::parse_str(&EN_WORDS, phrase).unwrap();
        let seed = mnemonic.to_seed("").unwrap();

        let derivation_path = DerivationPath::new(
            slip44::BITCOIN,
            0,
            DerivationPath::BIP84_PURPOSE,
            Some(bitcoin::Network::Bitcoin),
        );
        let btc_secret_key = derive_private_key(&seed, &derivation_path.get_path()).unwrap();

        let sk_bytes = btc_secret_key.to_bytes();
        let keypair = KeyPair::from_secret_key(SecretKey::Secp256k1Bitcoin((
            sk_bytes.into(),
            bitcoin::Network::Bitcoin,
            bitcoin::AddressType::P2wpkh,
        )))
        .unwrap();

        let address = keypair.get_addr().unwrap();

        assert!(
            matches!(address, Address::Secp256k1Bitcoin(_)),
            "Address should be Bitcoin type"
        );

        let bech32_address = address.auto_format();
        assert!(
            bech32_address.starts_with("bc1"),
            "Bech32 address should start with 'bc1'"
        );

        let expected_bech32 = "bc1q4qw42stdzjqs59xvlrlxr8526e3nunw7mp73te";

        println!("BIP84 Native SegWit Address: {}", bech32_address);
        println!("Expected: {}", expected_bech32);
        println!("Public Key: {}", hex::encode(keypair.get_pubkey_bytes()));

        assert_eq!(
            bech32_address, expected_bech32,
            "Native SegWit address does not match expected value"
        );
    }
}
