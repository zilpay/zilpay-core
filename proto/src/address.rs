use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zil_errors::AddressError;

pub const CHARSET: &str = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
pub const HRP: &str = "zil";
pub const GENERATOR: [u32; 5] = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
pub const ADDR_LEN: usize = 20;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AddressTypes {
    ZIL,
    EVM,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Address {
    pub addr_type: AddressTypes,
    pub value: [u8; ADDR_LEN],
}

impl Address {
    pub fn from_zil_base16(addr: &str) -> Option<Self> {
        let mb_bytes = hex::decode(addr).ok()?;
        let value = mb_bytes.try_into().ok()?;
        let addr_type = AddressTypes::ZIL;

        Some(Self { value, addr_type })
    }

    pub fn from_zil_pub_key(pub_key: &[u8]) -> Result<Address, AddressError> {
        let mut hasher = Sha256::new();
        hasher.update(pub_key);
        let hash = hasher.finalize();
        let hash_slice = &hash[12..];
        let value: [u8; ADDR_LEN] = hash_slice.try_into().or(Err(AddressError::InvalidPubKey))?;
        let addr_type = AddressTypes::ZIL;

        Ok(Self { addr_type, value })
    }

    pub fn from_zil_bech32_address(address: &str) -> Option<Address> {
        let (hrp, data) = match decode(address) {
            Some(addr) => addr,
            None => return None,
        };
        if hrp != HRP {
            return None;
        }
        let buf = match convert_bits(&data, 5, 8, false) {
            Some(buf) => buf,
            None => return None,
        };
        let addr_type = AddressTypes::ZIL;

        buf.try_into().ok().map(|value| Self { addr_type, value })
    }

    pub fn to_zil_bech32(&self) -> Option<String> {
        convert_bits(&self.value, 8, 5, true).map(|addrbz| encode(HRP, &addrbz))
    }
}

fn verify_checksum(hrp: &str, data: &[u8]) -> bool {
    let values = [&hrp_expand(hrp)[..], data].concat();
    polymod(&values) == 1
}

fn decode(bech_string: &str) -> Option<(String, Vec<u8>)> {
    let mut has_lower = false;
    let mut has_upper = false;

    for c in bech_string.chars() {
        let code = c as u32;

        if code < 33 || code > 126 {
            return None;
        }
        if code >= 97 && code <= 122 {
            has_lower = true;
        }
        if code >= 65 && code <= 90 {
            has_upper = true;
        }
    }

    if has_lower && has_upper {
        return None;
    }
    let bech_string = bech_string.to_lowercase();
    let pos = bech_string.rfind('1').unwrap_or(0);
    if pos < 1 || pos + 7 > bech_string.len() || bech_string.len() > 90 {
        return None;
    }
    let hrp = bech_string[..pos].to_string();
    let mut data = Vec::new();
    for c in bech_string[pos + 1..].chars() {
        let d = CHARSET.find(c).unwrap_or(0);
        data.push(d as u8);
    }
    if !verify_checksum(&hrp, &data) {
        return None;
    }
    Some((hrp, data[..data.len() - 6].to_vec()))
}

fn polymod(values: &[u8]) -> u32 {
    let mut chk: u32 = 1;
    for p in values {
        let top = chk >> 25;
        chk = ((chk & 0x1ffffff) << 5) ^ (*p as u32);
        for i in 0..5 {
            if ((top >> i) & 1) == 1 {
                chk ^= GENERATOR[i];
            }
        }
    }
    chk
}

fn hrp_expand(hrp: &str) -> Vec<u8> {
    let mut ret = Vec::new();
    for p in 0..hrp.len() {
        ret.push(hrp.as_bytes()[p] >> 5);
    }
    ret.push(0);
    for p in 0..hrp.len() {
        ret.push(hrp.as_bytes()[p] & 31);
    }
    ret
}

fn create_checksum(hrp: &str, data: &[u8]) -> Vec<u8> {
    let mut values: Vec<u8> = Vec::new();
    values.extend(hrp_expand(hrp));
    values.extend(data);
    values.extend(vec![0; 6]);
    let polymod = polymod(&values) ^ 1;
    let mut ret = Vec::new();
    for p in 0..6 {
        ret.push(((polymod >> (5 * (5 - p))) & 31) as u8);
    }
    ret
}

fn encode(hrp: &str, data: &[u8]) -> String {
    let checksum = create_checksum(hrp, data);
    let combined = [&data[..], &checksum[..]].concat();
    let mut ret = String::from(hrp) + "1"; // hrp is zil so it is zil1.
    for p in 0..combined.len() {
        let idx = combined[p] as usize;
        let value = CHARSET.chars().nth(idx);
        match value {
            Some(v) => ret.push(v),
            None => continue,
        }
    }
    ret
}

fn convert_bits(data: &[u8], from_width: u32, to_width: u32, pad: bool) -> Option<Vec<u8>> {
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut ret = Vec::new();
    let maxv = (1 << to_width) - 1;

    for value in data {
        if (*value as u32) >> from_width != 0 {
            return None;
        }
        acc = (acc << from_width) | (*value as u32);
        bits += from_width;
        while bits >= to_width {
            bits -= to_width;
            ret.push(((acc >> bits) & maxv) as u8);
        }
    }
    if pad {
        if bits > 0 {
            ret.push(((acc << (to_width - bits)) & maxv) as u8);
        }
    } else if bits >= from_width || (acc << (to_width - bits)) & maxv != 0 {
        return None;
    }

    Some(ret)
}

#[cfg(test)]
mod tests {
    use super::{convert_bits, create_checksum, decode, encode, hrp_expand, polymod};
    use crate::address::{Address, AddressTypes};

    #[test]
    fn test_polymod() {
        let bytes: [u8; 16] = [
            65, 29, 177, 250, 15, 49, 136, 8, 34, 192, 119, 116, 123, 146, 130, 62,
        ];
        let res = polymod(&bytes);
        assert_eq!(98216235, res);
    }

    #[test]
    fn test_hrp_expand() {
        let test_str = "test";
        let res = hrp_expand(test_str);
        let should: Vec<u8> = vec![3, 3, 3, 3, 0, 20, 5, 19, 20];
        assert_eq!(should, res);
    }

    #[test]
    fn test_create_checksum() {
        let hrp = "test";
        let data: Vec<u8> = vec![255, 64, 0, 0, 0, 2];
        let res = create_checksum(hrp, &data);
        let should: Vec<u8> = vec![2, 14, 10, 20, 25, 19];
        assert_eq!(res, should);
    }

    #[test]
    fn test_encode() {
        let hrp = "test";
        let data = vec![128, 0, 64, 32];
        let res = encode(hrp, &data);
        let should = "test1qep0uve";
        assert_eq!(should, res);
    }

    #[test]
    fn test_convert_bits() {
        let byte_vec = hex::decode("7793a8e8c09d189d4d421ce5bc5b3674656c5ac1").unwrap();
        let addr_bz = convert_bits(&byte_vec, 8, 5, true).unwrap();
        let shoud = "0e1e091a111a060013140c091a130a020313121b181619160e11121618161601";
        assert_eq!(hex::encode(addr_bz), shoud);
    }

    #[test]
    fn test_decode() {
        let bech32 = "zil1w7f636xqn5vf6n2zrnjmckekw3jkckkpyrd6z8";
        let (hrp, data) = decode(bech32).unwrap();
        assert_eq!(hrp, "zil");
        assert_eq!(
            hex::encode(data),
            "0e1e091a111a060013140c091a130a020313121b181619160e11121618161601"
        );
    }

    #[test]
    fn test_from_bech32_address() {
        let bech32 = "zil1w7f636xqn5vf6n2zrnjmckekw3jkckkpyrd6z8";
        let base16_buff = Address::from_zil_bech32_address(bech32).unwrap();
        let base16 = hex::encode(base16_buff.value);

        assert_eq!(base16, "7793a8e8c09d189d4d421ce5bc5b3674656c5ac1");
        assert_eq!(base16_buff.addr_type, AddressTypes::ZIL);

        let base16_buff =
            Address::from_zil_bech32_address("zi21w7f636xqn5vf6n2zrnjmckekw3jkckkpyrd6z8");

        assert_eq!(base16_buff, None);
    }

    #[test]
    fn test_to_bech32_address() {
        let bech32 = "zil1w7f636xqn5vf6n2zrnjmckekw3jkckkpyrd6z8";
        let addr = Address::from_zil_base16("7793a8e8c09d189d4d421ce5bc5b3674656c5ac1").unwrap();

        assert_eq!(bech32, addr.to_zil_bech32().unwrap());
        assert_eq!(addr.addr_type, AddressTypes::ZIL);
    }

    #[test]
    fn test_addr_from_pubkey() {
        let pubkey =
            hex::decode("03150a7f37063b134cde30070431a69148d60b252f4c7b38de33d813d329a7b7da")
                .unwrap();
        let addr = Address::from_zil_pub_key(&pubkey).unwrap();

        assert_eq!(addr.addr_type, AddressTypes::ZIL);

        assert_eq!(
            addr.to_zil_bech32().unwrap(),
            "zil1a0vtxuxamd3kltmyzpqdyxqu25vsss8mp58jtu"
        );
    }
}
