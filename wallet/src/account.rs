use bincode::{ToBytes, ToVecBytes};
use config::{address::ADDR_LEN, sha::SHA512_SIZE, SYS_SIZE};
use crypto::bip49::Bip49DerivationPath;
use num256::uint256::Uint256;
use proto::address::Address;
use proto::keypair::KeyPair;
use proto::pubkey::PubKey;
use proto::secret_key::SecretKey;
use std::{collections::HashMap, io::Empty};
use zil_errors::AccountErrors;

use crate::account_type::AccountType;

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
        // this unwrap never call.
        let type_bytes = self.account_type.to_bytes().unwrap();
        let addr_bytes = self.addr.to_bytes();

        let mut bytes_ft_map = Vec::new();
        let len = self.ft_map.len() as u64;

        bytes_ft_map.extend_from_slice(&len.to_le_bytes());

        for (key, value) in &self.ft_map {
            bytes_ft_map.extend_from_slice(key);
            bytes_ft_map.extend_from_slice(&value.to_le_bytes());
        }

        dbg!(&bytes_ft_map);

        bytes_ft_map
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    #[test]
    fn test_from_zil_sk() {
        let sk: SecretKey = "00e93c035175b08613c4b0251ca92cd007026ca032ba53bafa3c839838f8b52d04"
            .parse()
            .unwrap();
        let name = "Account 0";
        let mut acc = Account::from_secret_key(&sk, name.to_string(), 0).unwrap();

        acc.ft_map
            .insert(*acc.addr.addr_bytes(), Uint256::from_str("42").unwrap());

        acc.to_bytes();
    }
}
