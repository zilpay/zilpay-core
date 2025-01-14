pub const ZIL_PATH: &str = "m/44'/313'/0'/0/";
pub const ETH_PATH: &str = "m/44'/60'/0'/0/";

#[derive(Debug)]
pub enum Bip49DerivationPath {
    Zilliqa((usize, String)),
    Ethereum((usize, String)),
    Bitcoin((usize, String)),
    Solana((usize, String)),
}

impl Bip49DerivationPath {
    pub fn get_path(&self) -> String {
        match self {
            Bip49DerivationPath::Zilliqa((index, path)) => format!("{}{}", path, index),
            Bip49DerivationPath::Ethereum((index, path)) => format!("{}{}", path, index),
            Bip49DerivationPath::Bitcoin((index, path)) => format!("{}{}", path, index),
            Bip49DerivationPath::Solana((index, path)) => format!("{}{}", path, index),
        }
    }

    pub fn get_index(&self) -> usize {
        match self {
            Bip49DerivationPath::Zilliqa((i, _)) => *i,
            Bip49DerivationPath::Ethereum((i, _)) => *i,
            Bip49DerivationPath::Bitcoin((i, _)) => *i,
            Bip49DerivationPath::Solana((i, _)) => *i,
        }
    }
}
