use bincode::{ToBytes, ToVecBytes};
use config::SYS_SIZE;
use config::{address::ADDR_LEN, sha::SHA512_SIZE};
use crypto::bip49::Bip49DerivationPath;
use num256::uint256::Uint256;
use proto::address::Address;
use proto::keypair::KeyPair;
use proto::pubkey::PubKey;
use proto::secret_key::SecretKey;
use std::{collections::HashMap, io::Empty};
use zil_errors::AccountErrors;

#[derive(Debug)]
pub enum AccountType {
    Ledger(usize),     // Ledger index
    Bip39HD(usize),    // HD key bip39 index
    PrivateKey(usize), // A storage key for cipher secret key
}

impl ToBytes<{ SYS_SIZE + 1 }> for AccountType {
    type Error = AccountErrors;

    fn to_bytes(&self) -> Result<[u8; SYS_SIZE + 1], Self::Error> {
        let mut res: [u8; SYS_SIZE + 1] = [0u8; SYS_SIZE + 1];

        match self {
            AccountType::Ledger(v) => {
                res[0] = 0;
                res[1..].copy_from_slice(&v.to_ne_bytes());
            }
            AccountType::Bip39HD(v) => {
                res[0] = 1;
                res[1..].copy_from_slice(&v.to_ne_bytes());
            }
            AccountType::PrivateKey(v) => {
                res[0] = 2;
                res[1..].copy_from_slice(&v.to_ne_bytes());
            }
        };

        Ok(res)
    }
}

#[derive(Debug)]
pub struct Account {
    pub name: String,
    pub account_type: AccountType,
    pub addr: Address,
    pub pub_key: PubKey,
    pub ft_map: HashMap<[u8; ADDR_LEN], Uint256>, // map with ft token address > balance
    pub nft_map: HashMap<[u8; ADDR_LEN], Empty>,  // TODO: add struct for NFT tokens
}

impl Account {
    pub fn from_secret_key(
        sk: &SecretKey,
        name: String,
        key: usize,
    ) -> Result<Self, AccountErrors> {
        let keypair = KeyPair::from_secret_key(sk).map_err(AccountErrors::InvalidSecretKeyBytes)?;
        let pub_key = keypair.get_pubkey().map_err(AccountErrors::InvalidPubKey)?;
        let addr = keypair.get_addr().map_err(AccountErrors::InvalidAddress)?;
        let account_type = AccountType::PrivateKey(key);

        Ok(Self {
            account_type,
            addr,
            pub_key,
            name,
            ft_map: HashMap::new(),
            nft_map: HashMap::new(),
        })
    }

    pub fn from_hd(
        mnemonic_seed: &[u8; SHA512_SIZE],
        name: String,
        bip49: &Bip49DerivationPath,
    ) -> Result<Self, AccountErrors> {
        let keypair =
            KeyPair::from_bip39_seed(mnemonic_seed, bip49).map_err(AccountErrors::InvalidSeed)?;
        let pub_key = keypair.get_pubkey().map_err(AccountErrors::InvalidPubKey)?;
        let addr = keypair.get_addr().map_err(AccountErrors::InvalidAddress)?;
        let account_type = AccountType::Bip39HD(bip49.get_index());

        Ok(Self {
            account_type,
            addr,
            pub_key,
            name,
            ft_map: HashMap::new(),
            nft_map: HashMap::new(),
        })
    }
}

impl ToVecBytes for Account {
    fn to_bytes(&self) -> Vec<u8> {
        let name_bytes = self.name.as_bytes();

        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_zil_sk() {
        let sk: SecretKey = "00e93c035175b08613c4b0251ca92cd007026ca032ba53bafa3c839838f8b52d04"
            .parse()
            .unwrap();
        let name = "Account 0";
        let acc = Account::from_secret_key(&sk, name.to_string(), 0).unwrap();

        // dbg!(acc);
    }
}
