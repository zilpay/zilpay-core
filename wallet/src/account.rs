use crypto::keypair::{KeyPair, PUB_KEY_SIZE, SECRET_KEY_SIZE};
use num256::uint256::Uint256;
use proto::address::{Address, ADDR_LEN};
use std::{collections::HashMap, io::Empty};
use zil_errors::AccountErrors;

#[derive(Debug)]
pub enum AccountType {
    Ledger(usize),  // Ledger index
    Bip39HD(usize), // HD key bip39 index
    PrivateKey,
}

#[derive(Debug)]
pub struct Account {
    pub name: String,
    pub account_type: AccountType,
    pub addr: Address,
    pub pub_key: [u8; PUB_KEY_SIZE],
    pub ft_map: HashMap<[u8; ADDR_LEN], Uint256>, // map with ft token address > balance
    pub nft_map: HashMap<[u8; ADDR_LEN], Empty>,  // TODO: add struct for NFT tokens
    pub cipher_sk: Vec<u8>,                       // know how much bytes
}

impl Account {
    // pub fn generate<'a>() -> Result<Self, ZilliqaErrors<'a>> {
    //     let keypair = KeyPair::generate()?;
    //
    //     Self {}
    // }

    pub fn from_sk<'a>(sk: [u8; SECRET_KEY_SIZE], name: String) -> Result<(), AccountErrors<'a>> {
        let account_type = AccountType::PrivateKey;
        let keypair =
            KeyPair::from_secret_key_bytes(sk).map_err(AccountErrors::InvalidSecretKeyBytes)?;
        let addr = Address::from_zil_pub_key(pub_key);

        Ok(())
    }

    pub fn from_hd() {}
}

#[cfg(test)]
mod tests {}
