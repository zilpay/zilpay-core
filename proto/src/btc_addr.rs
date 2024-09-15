use config::{address::BTC_ADDR_SIZE, key::PUB_KEY_SIZE};
use ripemd::{Digest as _, Ripemd160};
use sha2::Sha256;

pub fn public_key_to_bitcoin_address(
    public_key: &[u8; PUB_KEY_SIZE],
    ver: u8,
) -> [u8; BTC_ADDR_SIZE] {
    let sha256_result = Sha256::digest(public_key);
    let ripemd160_result = Ripemd160::digest(sha256_result);
    let mut address_bytes = [0u8; BTC_ADDR_SIZE];

    address_bytes[0] = ver;
    address_bytes[1..21].copy_from_slice(&ripemd160_result);

    let checksum = Sha256::digest(Sha256::digest(&address_bytes[..21]));

    address_bytes[21..].copy_from_slice(&checksum[..4]);

    address_bytes
}

#[cfg(test)]
mod tests_btc_addr {
    // use super::*;
    // use bech32::{hrp, segwit, Bech32m, Hrp};
    //
    // #[test]
    // fn test_convert_from_pk() {
    //     let pk: [u8; PUB_KEY_SIZE] =
    //         hex::decode("03150a7f37063b134cde30070431a69148d60b252f4c7b38de33d813d329a7b7da")
    //             .unwrap()
    //             .try_into()
    //             .unwrap();
    //     let value = public_key_to_bitcoin_address(&pk, 0x00);
    //
    //     let hrp = Hrp::parse("bc").unwrap();
    //     let string = bech32::encode::<Bech32m>(hrp, &value).unwrap();
    //
    //     // dbg!(string);
    // }
}
