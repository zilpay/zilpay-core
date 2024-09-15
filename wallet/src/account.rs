use bincode::{FromBytes, ToBytes, ToVecBytes};
use config::{
    address::ADDR_LEN,
    key::PUB_KEY_SIZE,
    sha::{SHA256_SIZE, SHA512_SIZE},
    SYS_SIZE,
};
use crypto::bip49::Bip49DerivationPath;
use num256::uint256::Uint256;
use proto::address::Address;
use proto::keypair::KeyPair;
use proto::pubkey::PubKey;
use proto::secret_key::SecretKey;
use std::collections::HashMap;
use zil_errors::AccountErrors;

use crate::account_type::AccountType;

#[derive(Debug, PartialEq, Eq)]
pub struct Account {
    pub name: String,
    pub account_type: AccountType,
    pub addr: Address,
    pub pub_key: PubKey,
    pub ft_map: HashMap<[u8; ADDR_LEN], Uint256>, // map with ft token address > balance
    pub nft_map: HashMap<[u8; ADDR_LEN], u8>,     // TODO: add struct for NFT tokens
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

impl FromBytes for Account {
    type Error = &'static str;
    fn from_bytes(bytes: std::borrow::Cow<[u8]>) -> Result<Self, Self::Error> {
        let mut offset = 0;

        if bytes.len() < SYS_SIZE * 3 {
            return Err("Invalid Bytes sys * 3");
        }

        let name_len = usize::from_be_bytes(
            bytes[offset..offset + SYS_SIZE]
                .try_into()
                .or(Err("invalid name size"))?,
        );
        offset += SYS_SIZE;

        let ft_map_len = usize::from_be_bytes(
            bytes[offset..offset + SYS_SIZE]
                .try_into()
                .or(Err("invalid ft map size"))?,
        );
        offset += SYS_SIZE;

        let nft_map_len = usize::from_be_bytes(
            bytes[offset..offset + SYS_SIZE]
                .try_into()
                .or(Err("invalid nft map size"))?,
        );
        offset += SYS_SIZE;

        if offset + name_len > bytes.len() {
            return Err("invalid name size > bytes");
        }

        let name =
            String::from_utf8(bytes[offset..offset + name_len].to_vec()).or(Err("invalid name"))?;
        offset += name_len;

        if offset + 1 > bytes.len() {
            return Err("invalid bytes size");
        }

        let account_type = AccountType::from_bytes(
            &bytes[offset..offset + 1 + SYS_SIZE]
                .try_into()
                .or(Err("invlaid account type size"))?,
        )
        .or(Err("invalid account type"))?;
        offset += 1 + SYS_SIZE;

        if offset + PUB_KEY_SIZE + 1 > bytes.len() {
            return Err("invlaid pup key size");
        }

        let mut pub_key = [0u8; PUB_KEY_SIZE + 1];
        pub_key.copy_from_slice(&bytes[offset..offset + PUB_KEY_SIZE + 1]);
        offset += PUB_KEY_SIZE + 1;
        let pub_key: PubKey = pub_key.into();
        let addr = Address::from_pubkey(&pub_key).map_err(|_| "invlaid addr")?;

        let mut ft_map = HashMap::new();
        for _ in 0..ft_map_len {
            if offset + ADDR_LEN + SHA256_SIZE > bytes.len() {
                return Err("invlaid ft map addr + value size");
            }
            let mut addr = [0u8; ADDR_LEN];
            addr.copy_from_slice(&bytes[offset..offset + ADDR_LEN]);
            offset += ADDR_LEN;
            let value = Uint256::from_be_bytes(
                bytes[offset..offset + SHA256_SIZE]
                    .try_into()
                    .or(Err("invalid ft map value size"))?,
            );
            offset += SHA256_SIZE;
            ft_map.insert(addr, value);
        }

        let mut nft_map = HashMap::new();
        for _ in 0..nft_map_len {
            if offset + ADDR_LEN + 1 > bytes.len() {
                return Err("invalid nft map size");
            }
            let mut addr = [0u8; ADDR_LEN];
            addr.copy_from_slice(&bytes[offset..offset + ADDR_LEN]);
            offset += ADDR_LEN;
            offset += 1;
            nft_map.insert(addr, 0);
        }

        Ok(Self {
            name,
            account_type,
            addr,
            pub_key,
            ft_map,
            nft_map,
        })
    }
}

impl ToVecBytes for Account {
    fn to_bytes(&self) -> Vec<u8> {
        let name_len = self.name.len();
        let ft_map_len = self.ft_map.len();
        let nft_map_len = self.nft_map.len();

        let mut bytes_ft_map: Vec<u8> = Vec::with_capacity(ft_map_len * (ADDR_LEN + SHA256_SIZE));

        for (addr, value) in &self.ft_map {
            let mut bytes = [0u8; ADDR_LEN + SHA256_SIZE];

            bytes[..ADDR_LEN].copy_from_slice(addr);
            bytes[ADDR_LEN..].copy_from_slice(&value.to_be_bytes());

            bytes_ft_map.extend_from_slice(&bytes);
        }

        let mut bytes_nft_map: Vec<u8> = Vec::new();

        // TODO: value should be a struct
        for (addr, _) in &self.nft_map {
            let mut bytes = [0u8; ADDR_LEN + 1];

            bytes[..ADDR_LEN].copy_from_slice(addr);
            bytes[ADDR_LEN..].copy_from_slice(&[0]);

            bytes_nft_map.extend_from_slice(&bytes);
        }

        let name_bytes = self.name.as_bytes();
        // this unwrap never call.
        let type_bytes = self.account_type.to_bytes().unwrap();
        // should't call unwrap()
        let pk_bytes: [u8; PUB_KEY_SIZE + 1] = self.pub_key.to_bytes().unwrap();

        let mut bytes: Vec<u8> = vec![
            0u8;
            SYS_SIZE * 3
                + bytes_nft_map.len()
                + bytes_ft_map.len()
                + name_bytes.len()
                + type_bytes.len()
                + pk_bytes.len()
        ];

        let mut offset = 0;

        bytes[offset..offset + SYS_SIZE].copy_from_slice(&name_len.to_be_bytes());
        offset += SYS_SIZE;

        bytes[offset..offset + SYS_SIZE].copy_from_slice(&ft_map_len.to_be_bytes());
        offset += SYS_SIZE;

        bytes[offset..offset + SYS_SIZE].copy_from_slice(&nft_map_len.to_be_bytes());
        offset += SYS_SIZE;

        bytes[offset..offset + name_bytes.len()].copy_from_slice(name_bytes);
        offset += name_bytes.len();

        bytes[offset..offset + type_bytes.len()].copy_from_slice(&type_bytes);
        offset += type_bytes.len();

        bytes[offset..offset + pk_bytes.len()].copy_from_slice(&pk_bytes);
        offset += pk_bytes.len();

        bytes[offset..offset + bytes_ft_map.len()].copy_from_slice(&bytes_ft_map);
        offset += bytes_ft_map.len();

        bytes[offset..].copy_from_slice(&bytes_nft_map);

        bytes
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
        acc.ft_map
            .insert([33u8; ADDR_LEN], Uint256::from_str("69").unwrap());

        acc.nft_map.insert(*acc.addr.addr_bytes(), 0);

        let buf = acc.to_bytes();
        let res = Account::from_bytes(buf.into()).unwrap();

        assert_eq!(res.pub_key, acc.pub_key);
        assert_eq!(res.addr, acc.addr);
        assert_eq!(res.ft_map, acc.ft_map);
        assert_eq!(res.nft_map, acc.nft_map);
        assert_eq!(res, acc);
    }
}
