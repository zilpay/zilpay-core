use bincode::ToBytes;
use cipher::keychain::KeyChain;
use config::{address::ADDR_LEN, sha::SHA512_SIZE};
use crypto::bip49::Bip49DerivationPath;
use num256::uint256::Uint256;
use proto::address::Address;
use proto::keypair::KeyPair;
use proto::pubkey::PubKey;
use proto::secret_key::SecretKey;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use settings::wallet_settings::WalletSettings;
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

    pub fn from_secret_key<'a>(
        sk: &SecretKey,
        name: String,
        keychain: &'a KeyChain,
        storage: &'a LocalStorage,
        settings: &'a WalletSettings,
    ) -> Result<Self, AccountErrors<'a>> {
        let keypair = KeyPair::from_secret_key(sk).map_err(AccountErrors::InvalidSecretKeyBytes)?;
        let cipher_sk: [u8; CIPHER_SK_SIZE] = keychain
            .encrypt(sk.to_vec(), &settings.crypto.cipher_orders)
            .map_err(AccountErrors::TryEncryptSecretKeyError)?
            .try_into()
            .or(Err(AccountErrors::SKSliceError))?;
        let pub_key = keypair.get_pubkey().map_err(AccountErrors::InvalidPubKey)?;
        let addr = keypair.get_addr().map_err(AccountErrors::InvalidAddress)?;
        let mut rng = ChaCha20Rng::from_entropy();
        let num_storage_key = rng.r#gen();
        let account_type = AccountType::PrivateKey(num_storage_key);
        let num_storage_key_bytes = usize::to_le_bytes(num_storage_key);

        storage
            .set(&num_storage_key_bytes, &cipher_sk)
            .map_err(AccountErrors::FailToSaveCipher)?;

        Ok(Self {
            account_type,
            addr,
            pub_key,
            name,
            ft_map: HashMap::new(),
            nft_map: HashMap::new(),
        })
    }

    pub fn from_hd<'a>(
        mnemonic_seed: &[u8; SHA512_SIZE],
        bip49: &Bip49DerivationPath,
    ) -> Result<(), AccountErrors<'a>> {
        let keypair =
            KeyPair::from_bip39_seed(mnemonic_seed, bip49).map_err(AccountErrors::InvalidSeed)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use cipher::argon2::derive_key;

    use super::*;

    #[test]
    fn test_from_zil_sk() {
        let sk: SecretKey = "00e93c035175b08613c4b0251ca92cd007026ca032ba53bafa3c839838f8b52d04"
            .parse()
            .unwrap();
        let name = "Account 0";
        let password = b"Test_password";
        let argon_seed = derive_key(password).unwrap();

        let keychain = KeyChain::from_seed(argon_seed).unwrap();
        let storage =
            LocalStorage::new("com.test_write", "WriteTest Corp", "WriteTest App").unwrap();

        let acc = Account::from_secret_key(
            &sk,
            name.to_string(),
            &keychain,
            &storage,
            &Default::default(),
        )
        .unwrap();

        dbg!(acc);
    }
}
