use std::fmt;

#[derive(Debug, Clone, Copy)]
pub struct DerivationPath {
    pub slip44: u32,
    pub index: usize,
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
}
