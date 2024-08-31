use cipher::keychain::{CipherOrders, KeyChain};
use crypto::keypair::{KeyPair, SECRET_KEY_SIZE};
use num256::uint256::Uint256;
use proto::address::Address;
use proto::pubkey::PubKey;
use proto::zil_address::ADDR_LEN;
use rand::{Rng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::{collections::HashMap, io::Empty};
use storage::LocalStorage;
use zil_errors::AccountErrors;

pub const CIPHER_SK_SIZE: usize = 2578;

#[derive(Debug)]
pub enum AccountType {
    Ledger(usize),     // Ledger index
    Bip39HD(usize),    // HD key bip39 index
    PrivateKey(usize), // A storage key for cipher secret key
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
    // pub fn generate<'a>() -> Result<Self, ZilliqaErrors<'a>> {
    //     let keypair = KeyPair::generate()?;
    //
    //     Self {}
    // }

    pub fn from_zil_sk<'a, 'b>(
        sk: [u8; SECRET_KEY_SIZE],
        name: String,
        keychain: &'a KeyChain,
        storage: &'a LocalStorage,
    ) -> Result<Self, AccountErrors<'b>> {
        let keypair =
            KeyPair::from_secret_key_bytes(sk).map_err(AccountErrors::InvalidSecretKeyBytes)?;
        let addr = Address::from_zil_pub_key(&keypair.pub_key)
            .map_err(AccountErrors::AddressParseError)?;

        // TODO: move options to settings.
        let options = [CipherOrders::AESGCM256, CipherOrders::NTRUP1277];

        let cipher_sk: [u8; CIPHER_SK_SIZE] = keychain
            .encrypt(sk.to_vec(), &options)
            .map_err(AccountErrors::TryEncryptSecretKeyError)?
            .try_into()
            .or(Err(AccountErrors::SKSliceError))?;
        let pub_key = PubKey::Secp256k1Sha256(keypair.pub_key);
        let mut rng = ChaCha20Rng::from_entropy();
        let num_storage_key: usize = rng.r#gen();
        let account_type = AccountType::PrivateKey(num_storage_key);

        storage.set(&key, cipher_sk);

        Ok(Self {
            account_type,
            addr,
            pub_key,
            name,
            ft_map: HashMap::new(),
            nft_map: HashMap::new(),
        })
    }

    pub fn from_hd() {}
}

#[cfg(test)]
mod tests {
    use cipher::argon2::derive_key;

    use super::*;

    #[test]
    fn test_from_zil_sk() {
        let sk_bytes: [u8; SECRET_KEY_SIZE] =
            hex::decode("e93c035175b08613c4b0251ca92cd007026ca032ba53bafa3c839838f8b52d04")
                .unwrap()
                .try_into()
                .unwrap();
        let name = "Account 0";
        let password = b"Test_password";
        let argon_seed = derive_key(password).unwrap();
        let keychain = KeyChain::from_seed(argon_seed).unwrap();
        let acc = Account::from_zil_sk(sk_bytes, name.to_string(), &keychain).unwrap();

        dbg!(acc);
    }
}
