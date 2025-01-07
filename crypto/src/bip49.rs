pub const ZIL_PATH: &str = "m/44'/313'/0'/0/";
pub const ETH_PATH: &str = "m/44'/60'/0'/0/";

#[derive(Debug)]
pub enum Bip49DerivationPath<'a> {
    Zilliqa((usize, &'a str)),
    Ethereum((usize, &'a str)),
}

impl<'a> Bip49DerivationPath<'a> {
    pub fn get_path(&self) -> String {
        match self {
            Bip49DerivationPath::Zilliqa((index, path)) => format!("{}{}", path, index),
            Bip49DerivationPath::Ethereum((index, path)) => format!("{}{}", path, index),
        }
    }

    pub fn get_index(&self) -> usize {
        match self {
            Bip49DerivationPath::Zilliqa((i, _)) => *i,
            Bip49DerivationPath::Ethereum((i, _)) => *i,
        }
    }
}
