use crate::account_type::AccountType;
use config::sha::SHA512_SIZE;
use crypto::bip49::DerivationPath;
use errors::account::AccountErrors;
use proto::address::Address;
use proto::keypair::KeyPair;
use proto::pubkey::PubKey;
use proto::secret_key::SecretKey;
use serde::{Deserialize, Serialize};

type Result<T> = std::result::Result<T, AccountErrors>;

#[derive(Debug, PartialEq, Eq, Deserialize, Serialize, Clone)]
pub struct Account {
    pub name: String,
    pub account_type: AccountType,
    pub addr: Address,
    pub pub_key: PubKey,
    pub chain_hash: u64,
    pub chain_id: u64,
    pub slip_44: u32,
}

impl Account {
    pub fn from_bytes(encoded: &[u8]) -> Result<Self> {
        let decoded: Self = bincode::deserialize(encoded)?;

        Ok(decoded)
    }

    pub fn from_ledger(
        pub_key: PubKey,
        name: String,
        index: usize,
        chain_hash: u64,
        chain_id: u64,
        slip_44: u32,
    ) -> Result<Self> {
        let addr = pub_key.get_addr()?;
        let account_type = AccountType::Ledger(index);

        Ok(Self {
            slip_44,
            chain_hash,
            chain_id,
            account_type,
            addr,
            name,
            pub_key,
        })
    }

    pub fn from_secret_key(
        sk: SecretKey,
        name: String,
        storage_key: usize,
        chain_hash: u64,
        chain_id: u64,
        slip_44: u32,
    ) -> Result<Self> {
        let keypair = KeyPair::from_secret_key(sk)?;
        let pub_key = keypair.get_pubkey()?;
        let addr = keypair.get_addr()?;
        let account_type = AccountType::PrivateKey(storage_key);

        Ok(Self {
            chain_hash,
            chain_id,
            account_type,
            addr,
            pub_key,
            name,
            slip_44,
        })
    }

    pub fn from_hd(
        mnemonic_seed: &[u8; SHA512_SIZE],
        name: String,
        bip49: &DerivationPath,
        chain_hash: u64,
        chain_id: u64,
        slip_44: u32,
    ) -> Result<Self> {
        let keypair = KeyPair::from_bip39_seed(mnemonic_seed, bip49)?;
        let pub_key = keypair.get_pubkey()?;
        let addr = keypair.get_addr()?;
        let account_type = AccountType::Bip39HD(bip49.get_index());

        Ok(Self {
            chain_hash,
            chain_id,
            account_type,
            addr,
            pub_key,
            name,
            slip_44,
        })
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let encoded: Vec<u8> = bincode::serialize(&self)?;

        Ok(encoded)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use config::{address::ADDR_LEN, bip39::EN_WORDS};
    use crypto::slip44;
    use pqbip39::mnemonic::Mnemonic;
    use rand::RngCore;

    #[test]
    fn test_from_zil_sk_ser() {
        let mut rng = rand::thread_rng();

        let sk: SecretKey = "00e93c035175b08613c4b0251ca92cd007026ca032ba53bafa3c839838f8b52d04"
            .parse()
            .unwrap();
        let name = "Account 0";
        let acc = Account::from_secret_key(sk, name.to_string(), 0, 0, 1, slip44::ZILLIQA).unwrap();

        for _ in 0..100 {
            let mut nft_addr = [0u8; ADDR_LEN];
            let mut ft_addr = [0u8; ADDR_LEN];

            rng.fill_bytes(&mut nft_addr);
            rng.fill_bytes(&mut ft_addr);
        }

        let buf = acc.to_bytes().unwrap();
        let res = Account::from_bytes(&buf).unwrap();

        assert_eq!(res.pub_key, acc.pub_key);
        assert_eq!(res.addr, acc.addr);
        assert_eq!(res, acc);
    }

    #[test]
    fn test_init_from_bip39() {
        let mut rng = rand::thread_rng();

        let mnemonic_str =
            "green process gate doctor slide whip priority shrug diamond crumble average help";
        let name = "Account 0";
        let m = Mnemonic::parse_str(&EN_WORDS, mnemonic_str).unwrap();
        let bip49 = DerivationPath::new(slip44::ZILLIQA, 0);
        let seed = m.to_seed("").unwrap();
        let acc = Account::from_hd(&seed, name.to_owned(), &bip49, 0, 1, slip44::ZILLIQA).unwrap();

        for _ in 0..100 {
            let mut nft_addr = [0u8; ADDR_LEN];
            let mut ft_addr = [0u8; ADDR_LEN];

            rng.fill_bytes(&mut nft_addr);
            rng.fill_bytes(&mut ft_addr);
        }

        let buf = acc.to_bytes().unwrap();
        let res = Account::from_bytes(&buf).unwrap();

        assert_eq!(res.pub_key, acc.pub_key);
        assert_eq!(res.addr, acc.addr);
        assert_eq!(res, acc);
    }
}
