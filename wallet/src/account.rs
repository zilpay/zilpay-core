use crypto::keypair::{KeyPair, PUB_KEY_SIZE, SECRET_KEY_SIZE};
use num256::uint256::Uint256;
use proto::address::{Address, ADDR_LEN};
use std::{collections::HashMap, io::Empty};
use zil_errors::ZilliqaErrors;

#[derive(Debug)]
pub struct Account {
    // session: &
    pub name: String,
    pub hd_index: usize,
    pub addr: Address,
    pub pub_key: [u8; PUB_KEY_SIZE],
    pub ft_map: HashMap<[u8; ADDR_LEN], Uint256>, // map with ft token address > balance
    pub nft_map: HashMap<[u8; ADDR_LEN], Empty>,  // TODO: add struct for NFT tokens
    pub cipher_key_pair: Vec<u8>,                 // know how much bytes
}

impl Account {
    // pub fn generate<'a>() -> Result<Self, ZilliqaErrors<'a>> {
    //     let keypair = KeyPair::generate()?;
    //
    //     Self {}
    // }

    pub fn from_sk(sk: [u8; SECRET_KEY_SIZE], name: String) {}

    pub fn from_hd() {}
}

#[cfg(test)]
mod tests {}
