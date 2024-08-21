use config::sha::{SHA256_SIZE, SHA512_SIZE};
use ntrulp::{
    key::{priv_key::PrivKey, pub_key::PubKey},
    ntru,
    poly::{r3::R3, rq::Rq},
    random::{random_small, short_random},
};
use rand::SeedableRng;
use rand_chacha::ChaChaRng;
use std::sync::Arc;
use zil_errors::NTRUPErrors;

pub fn ntru_keys_from_seed<'a>(
    seed_bytes: &[u8; SHA512_SIZE],
) -> Result<(PubKey, PrivKey), NTRUPErrors<'a>> {
    let seed_pq: [u8; SHA256_SIZE] = seed_bytes[..SHA256_SIZE]
        .try_into()
        .or(Err(NTRUPErrors::KeySliceError))?;
    let mut pq_rng = ChaChaRng::from_seed(seed_pq);
    let f: Rq = Rq::from(short_random(&mut pq_rng).map_err(NTRUPErrors::KeyGenError)?);

    let mut g: R3;
    let sk = loop {
        let r = random_small(&mut pq_rng);
        g = R3::from(r);

        match PrivKey::compute(&f, &g) {
            Ok(s) => break s,
            Err(_) => continue,
        };
    };
    let pk = PubKey::compute(&f, &g).map_err(NTRUPErrors::ComputeKeyError)?;

    Ok((pk, sk))
}

pub fn ntru_encrypt<'a>(pk: &Arc<PubKey>, plaintext: Vec<u8>) -> Result<Vec<u8>, NTRUPErrors<'a>> {
    let num_threads = num_cpus::get();
    let mut pq_rng = ChaChaRng::from_entropy();
    let plaintext = Arc::new(plaintext);

    ntru::cipher::parallel_bytes_encrypt(&mut pq_rng, &plaintext, pk, num_threads)
        .map_err(NTRUPErrors::EncryptError)
}

pub fn ntru_decrypt<'a>(
    sk: &Arc<PrivKey>,
    ciphertext: Vec<u8>,
) -> Result<Vec<u8>, NTRUPErrors<'a>> {
    let num_threads = num_cpus::get();
    let ciphertext = Arc::new(ciphertext);

    ntru::cipher::parallel_bytes_decrypt(&ciphertext, sk, num_threads)
        .map_err(NTRUPErrors::DecryptError)
}

#[cfg(test)]
mod tests {
    use super::{ntru_keys_from_seed, SHA512_SIZE};
    use crate::ntrup::{ntru_decrypt, ntru_encrypt};
    use rand::RngCore;
    use std::sync::Arc;

    #[test]
    fn test_encrypt_and_decrypt() {
        let mut rng = rand::thread_rng();
        let mut password = [0u8; 2000];
        let mut plaintext = vec![0u8; 255];
        let mut seed = [0u8; SHA512_SIZE];

        rng.fill_bytes(&mut password);
        rng.fill_bytes(&mut seed);
        rng.fill_bytes(&mut plaintext);

        let (pk, sk) = ntru_keys_from_seed(&seed).unwrap();
        let ciphertext = ntru_encrypt(&Arc::new(pk), plaintext.to_vec()).unwrap();
        let res = ntru_decrypt(&Arc::new(sk), ciphertext).unwrap();

        assert_eq!(res, plaintext);
    }
}
