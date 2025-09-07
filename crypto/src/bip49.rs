use std::fmt;

use errors::bip32::Bip329Errors;

#[derive(Debug, Clone, Copy)]
pub struct DerivationPath {
    pub slip44: u32,
    pub index: usize,
}

pub fn split_path(path: &str) -> Result<Vec<u32>, Bip329Errors> {
    if path.is_empty() {
        return Ok(Vec::new());
    }

    path.split('/')
        .filter(|s| !s.is_empty())
        .map(|component| {
            let (numeric_part, is_hardened) = if let Some(stripped) = component.strip_suffix('\'') {
                (stripped, true)
            } else {
                (component, false)
            };

            let mut value = numeric_part
                .parse::<u32>()
                .map_err(|_| Bip329Errors::InvalidComponent(component.to_string()))?;

            if is_hardened {
                value = value.wrapping_add(0x80000000);
            }

            Ok(value)
        })
        .collect()
}

pub fn components_to_derivation_path(components: &[u32]) -> Vec<u8> {
    let mut buffer = Vec::with_capacity(1 + components.len() * 4);

    buffer.push(components.len() as u8);

    for component in components {
        buffer.extend_from_slice(&component.to_be_bytes());
    }

    buffer
}

impl DerivationPath {
    pub fn new(slip44: u32, index: usize) -> Self {
        Self { slip44, index }
    }

    pub fn get_path(&self) -> String {
        format!("m/44'/{}'/{}'/{}/{}", self.slip44, 0, 0, self.index)
    }

    pub fn get_base_path(&self) -> String {
        format!("m/44'/{}'/{}'/{}/", self.slip44, 0, 0)
    }

    pub fn get_index(&self) -> usize {
        self.index
    }
}

impl fmt::Display for DerivationPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.get_path())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::slip44;

    #[test]
    fn test_ethereum_path() {
        let eth_path = DerivationPath::new(slip44::ETHEREUM, 0);
        assert_eq!(eth_path.get_path(), "m/44'/60'/0'/0/0");
        assert_eq!(eth_path.get_base_path(), "m/44'/60'/0'/0/");
    }

    #[test]
    fn test_zilliqa_path() {
        let zil_path = DerivationPath::new(slip44::ZILLIQA, 0);
        assert_eq!(zil_path.get_path(), "m/44'/313'/0'/0/0");
        assert_eq!(zil_path.get_base_path(), "m/44'/313'/0'/0/");
    }

    #[test]
    fn test_different_indexes() {
        let eth_path = DerivationPath::new(slip44::ETHEREUM, 5);
        assert_eq!(eth_path.get_path(), "m/44'/60'/0'/0/5");
        assert_eq!(eth_path.get_index(), 5);
    }

    #[test]
    fn test_display() {
        let eth_path = DerivationPath::new(slip44::ETHEREUM, 0);
        assert_eq!(eth_path.to_string(), "m/44'/60'/0'/0/0");
    }

    #[test]
    fn test_split_path_logic() {
        assert_eq!(
            split_path("44'/60'/123/456/789").unwrap(),
            vec![
                44u32.wrapping_add(0x80000000),
                60u32.wrapping_add(0x80000000),
                123,
                456,
                789,
            ]
        );

        assert_eq!(
            split_path("44'/60'/0'/0/0").unwrap(),
            vec![
                44u32.wrapping_add(0x80000000),
                60u32.wrapping_add(0x80000000),
                0u32.wrapping_add(0x80000000),
                0,
                0,
            ]
        );

        assert_eq!(split_path("0/1/2").unwrap(), vec![0, 1, 2]);

        assert_eq!(split_path("").unwrap(), vec![]);

        assert_eq!(
            split_path("44'//60'").unwrap(),
            vec![
                44u32.wrapping_add(0x80000000),
                60u32.wrapping_add(0x80000000),
            ]
        );

        let err = split_path("44'/abc/0").unwrap_err();
        assert_eq!(err, Bip329Errors::InvalidComponent("abc".to_string()));

        let err = split_path("4294967296").unwrap_err();
        assert_eq!(
            err,
            Bip329Errors::InvalidComponent("4294967296".to_string())
        );
    }

    #[test]
    fn test_components_to_derivation_path() {
        let components_eth = vec![
            44u32.wrapping_add(0x80000000), // 44'
            60u32.wrapping_add(0x80000000), // 60'
            0u32.wrapping_add(0x80000000),  // 0'
            0,
            0,
        ];
        let buffer_eth = components_to_derivation_path(&components_eth);
        let expected_hex_eth = "058000002c8000003c800000000000000000000000";
        assert_eq!(
            hex::encode(buffer_eth),
            expected_hex_eth,
            "Standard ETH path failed"
        );

        let components_empty: Vec<u32> = vec![];
        let buffer_empty = components_to_derivation_path(&components_empty);
        let expected_hex_empty = "00";
        assert_eq!(
            hex::encode(buffer_empty),
            expected_hex_empty,
            "Empty path failed"
        );

        let components_non_hardened = vec![0, 1, 2];
        let buffer_non_hardened = components_to_derivation_path(&components_non_hardened);
        let expected_hex_non_hardened = "03000000000000000100000002";
        assert_eq!(
            hex::encode(buffer_non_hardened),
            expected_hex_non_hardened,
            "Non-hardened path failed"
        );

        let components_single_hardened = vec![123u32.wrapping_add(0x80000000)];
        let buffer_single_hardened = components_to_derivation_path(&components_single_hardened);
        let expected_hex_single_hardened = "018000007b";
        assert_eq!(
            hex::encode(buffer_single_hardened),
            expected_hex_single_hardened,
            "Single hardened path failed"
        );
    }
}
