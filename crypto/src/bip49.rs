#[derive(Debug)]
pub enum Bip49DerivationPath {
    Zilliqa(usize),
    Ethereum(usize),
}

impl<'a> Bip49DerivationPath {
    pub const ZIL_PATH: &'a str = "m/44'/313'/0'/0/";
    pub const ETH_PATH: &'a str = "m/44'/60'/0'/0/";

    pub fn get_path(&self) -> String {
        match self {
            Bip49DerivationPath::Zilliqa(index) => format!("{}{}", Self::ZIL_PATH, index),
            Bip49DerivationPath::Ethereum(index) => format!("{}{}", Self::ETH_PATH, index),
        }
    }

    pub fn get_index(&self) -> usize {
        match self {
            Bip49DerivationPath::Zilliqa(i) => *i,
            Bip49DerivationPath::Ethereum(i) => *i,
        }
    }
}
