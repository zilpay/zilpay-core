use crate::Result;
use bip39::{Language, Mnemonic};
use proto::keypair::KeyPair;
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use zil_errors::background::BackgroundError;

use crate::Background;

/// Provides cryptographic operations for wallet management
pub trait CryptoOperations {
    type Error;

    /// Generates a BIP39 mnemonic phrase with specified word count
    ///
    /// * `count` - Number of words (12, 15, 18, 21, or 24)
    fn gen_bip39(count: u8) -> std::result::Result<String, Self::Error>;

    /// Finds invalid words in a BIP39 mnemonic phrase
    ///
    /// * `words` - Vector of words to validate
    /// * `lang` - BIP39 language for validation
    fn find_invalid_bip39_words(words: &[String], lang: Language) -> Vec<usize>;

    /// Generates a new cryptographic key pair
    fn gen_keypair() -> std::result::Result<(String, String), Self::Error>;
}

impl CryptoOperations for Background {
    type Error = BackgroundError;

    fn gen_bip39(count: u8) -> Result<String> {
        if ![12, 15, 18, 21, 24].contains(&count) {
            return Err(BackgroundError::InvalidWordCount(count));
        }

        let entropy_bits = (count as usize * 11) - (count as usize / 3);
        let entropy_bytes = (entropy_bits + 7) / 8;
        let mut rng = ChaCha20Rng::from_entropy();
        let mut entropy = vec![0u8; entropy_bytes];

        rng.fill_bytes(&mut entropy);

        let m = Mnemonic::from_entropy_in(Language::English, &entropy)
            .map_err(|e| BackgroundError::FailToGenBip39FromEntropy(e.to_string()))?;

        Ok(m.to_string())
    }

    fn find_invalid_bip39_words(words: &[String], lang: Language) -> Vec<usize> {
        let word_list = lang.word_list();

        words
            .iter()
            .enumerate()
            .filter(|(_, word)| !word_list.contains(&word.as_str()))
            .map(|(index, _)| index)
            .collect()
    }

    fn gen_keypair() -> Result<(String, String)> {
        let (pub_key, secret_key) =
            KeyPair::gen_keys_bytes().map_err(BackgroundError::FailToGenKeyPair)?;

        Ok((hex::encode(secret_key), hex::encode(pub_key)))
    }
}

#[cfg(test)]
mod tests_background {
    use crate::{bg_crypto::CryptoOperations, Background};
    use bip39::Language;
    use config::key::{PUB_KEY_SIZE, SECRET_KEY_SIZE};
    use zil_errors::background::BackgroundError;

    #[test]
    fn test_bip39_words_exists() {
        let words: Vec<String> =
            "area scale vital sell radio pattern not_exits_word mean similar picnic grain gain"
                .split(" ")
                .map(|v| v.to_string())
                .collect();

        let not_exists_ids = Background::find_invalid_bip39_words(&words, Language::English);

        assert_eq!(not_exists_ids, vec![6])
    }

    #[test]
    fn test_bip39_gen() {
        let words = Background::gen_bip39(12).unwrap();
        assert_eq!(words.split(" ").collect::<Vec<&str>>().len(), 12);

        let words = Background::gen_bip39(15).unwrap();
        assert_eq!(words.split(" ").collect::<Vec<&str>>().len(), 15);

        let words = Background::gen_bip39(18).unwrap();
        assert_eq!(words.split(" ").collect::<Vec<&str>>().len(), 18);

        let words = Background::gen_bip39(21).unwrap();
        assert_eq!(words.split(" ").collect::<Vec<&str>>().len(), 21);

        let words = Background::gen_bip39(24).unwrap();
        assert_eq!(words.split(" ").collect::<Vec<&str>>().len(), 24);

        assert_eq!(
            Background::gen_bip39(33 /* wrong number */),
            Err(BackgroundError::InvalidWordCount(33))
        );
    }

    #[test]
    fn test_keypair_gen() {
        let (sk, pk) = Background::gen_keypair().unwrap();

        assert_eq!(hex::decode(sk).unwrap().len(), SECRET_KEY_SIZE);
        assert_eq!(hex::decode(pk).unwrap().len(), PUB_KEY_SIZE);
    }
}
