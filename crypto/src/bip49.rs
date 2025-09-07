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
}
