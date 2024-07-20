use sha2::{Digest, Sha256};

pub const CHARSET: &str = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
pub const HRP: &str = "zil";
pub const GENERATOR: [u32; 5] = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

#[derive(Debug)]
pub struct Address([u8; 20]);

impl Address {
    pub fn from_zil_pub_key(pub_key: &[u8]) -> Option<[u8; 20]> {
        let mut hasher = Sha256::new();
        hasher.update(pub_key);
        let hash = hasher.finalize();
        let hash_slice = &hash[12..];

        match hash_slice.try_into() {
            Ok(value) => Some(value),
            Err(_) => None,
        }
    }

    pub fn from_bech32_address(address: &str) -> Option<Vec<u8>> {
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

        Some(buf)
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
