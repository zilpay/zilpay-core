use crate::account_type::AccountType;
use config::sha::SHA512_SIZE;
use crypto::bip49::Bip49DerivationPath;
use proto::address::Address;
use proto::keypair::KeyPair;
use proto::pubkey::PubKey;
use proto::secret_key::SecretKey;
use serde::{Deserialize, Serialize};
use errors::account::AccountErrors;

type Result<T> = std::result::Result<T, AccountErrors>;

#[derive(Debug, PartialEq, Eq, Deserialize, Serialize, Clone)]
pub struct Account {
    pub name: String,
    pub account_type: AccountType,
    pub addr: Address,
    pub pub_key: PubKey,
}

impl Account {
    pub fn from_bytes(encoded: &[u8]) -> Result<Self> {
        let decoded: Self = bincode::deserialize(encoded)
            .map_err(|e| AccountErrors::AccountSerdeError(e.to_string()))?;

        Ok(decoded)
    }

    pub fn from_ledger(pub_key: &PubKey, name: String, index: usize) -> Result<Self> {
        let addr = pub_key.get_addr().map_err(AccountErrors::PubKeyError)?;
        let account_type = AccountType::Ledger(index);

        Ok(Self {
            account_type,
            addr,
            name,
            pub_key: pub_key.to_owned(),
        })
    }

    pub fn from_secret_key(sk: SecretKey, name: String, key: usize) -> Result<Self> {
        let keypair = KeyPair::from_secret_key(sk).map_err(AccountErrors::InvalidSecretKeyBytes)?;
        let pub_key = keypair.get_pubkey().map_err(AccountErrors::InvalidPubKey)?;
        let addr = keypair.get_addr().map_err(AccountErrors::InvalidAddress)?;
        let account_type = AccountType::PrivateKey(key);

        Ok(Self {
            account_type,
            addr,
            pub_key,
            name,
        })
    }

    pub fn from_hd(
        mnemonic_seed: &[u8; SHA512_SIZE],
        name: String,
        bip49: &Bip49DerivationPath,
    ) -> Result<Self> {
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
        })
    }

    pub fn get_bip49(&self) -> Result<Bip49DerivationPath> {
        match &self.account_type {
            AccountType::Bip39HD(v) => match &self.pub_key {
                PubKey::Secp256k1Sha256Zilliqa(_) => Ok(Bip49DerivationPath::Zilliqa(*v)),
                PubKey::Secp256k1Keccak256Ethereum(_) => Ok(Bip49DerivationPath::Ethereum(*v)),
                _ => Err(AccountErrors::InvalidPubKeyType),
            },
            _ => Err(AccountErrors::InvalidAccountType(
                self.account_type.to_string(),
            )),
        }
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let encoded: Vec<u8> = bincode::serialize(&self)
            .map_err(|e| AccountErrors::AccountSerdeError(e.to_string()))?;

        Ok(encoded)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bip39::Mnemonic;
    use config::address::ADDR_LEN;
    use rand::RngCore;

    #[test]
    fn test_from_zil_sk_ser() {
        let mut rng = rand::thread_rng();

        let sk: SecretKey = "00e93c035175b08613c4b0251ca92cd007026ca032ba53bafa3c839838f8b52d04"
            .parse()
            .unwrap();
        let name = "Account 0";
        let acc = Account::from_secret_key(sk, name.to_string(), 0).unwrap();

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
        let m = Mnemonic::parse_normalized(mnemonic_str).unwrap();
        let bip49 = Bip49DerivationPath::Zilliqa(0);
        let seed = m.to_seed("");
        let acc = Account::from_hd(&seed, name.to_owned(), &bip49).unwrap();

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
