use crate::keypair::KeyPair;
use bitcoin::ecdsa::Signature as BitcoinSignature;
use bitcoin::script::PushBytesBuf;
use bitcoin::secp256k1::{self, Message, Secp256k1};
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin::{
    absolute::LockTime, transaction::Version, Address as BitcoinAddress, Amount, OutPoint,
    ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid,
};
use errors::tx::TransactionErrors;
use std::str::FromStr;

#[cfg(test)]
use bitcoin::hashes::Hash;
#[cfg(test)]
use bitcoin::PrivateKey as BitcoinPrivateKey;

#[derive(Debug, Clone)]
pub struct BtcTransaction {
    pub tx: Transaction,
}

impl BtcTransaction {
    pub fn new(inputs: Vec<TxIn>, outputs: Vec<TxOut>) -> Self {
        Self {
            tx: Transaction {
                version: Version::TWO,
                lock_time: LockTime::ZERO,
                input: inputs,
                output: outputs,
            },
        }
    }

    pub fn create_input(txid_hex: &str, vout: u32) -> Result<TxIn, TransactionErrors> {
        let txid = Txid::from_str(txid_hex).map_err(|_| TransactionErrors::InvalidTxId)?;

        Ok(TxIn {
            previous_output: OutPoint { txid, vout },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: bitcoin::Witness::new(),
        })
    }

    pub fn create_p2pkh_output(
        address: &str,
        amount_satoshis: u64,
    ) -> Result<TxOut, TransactionErrors> {
        let btc_addr = BitcoinAddress::from_str(address)
            .map_err(|_| TransactionErrors::InvalidAddress)?
            .assume_checked();

        let script = btc_addr.script_pubkey();

        Ok(TxOut {
            value: Amount::from_sat(amount_satoshis),
            script_pubkey: script,
        })
    }

    pub fn sign_input(
        &mut self,
        input_index: usize,
        keypair: &KeyPair,
        prev_script_pubkey: &ScriptBuf,
        sighash_type: EcdsaSighashType,
    ) -> Result<(), TransactionErrors> {
        if input_index >= self.tx.input.len() {
            return Err(TransactionErrors::InvalidInputIndex);
        }

        let secp = Secp256k1::new();

        let sk_bytes = keypair.get_sk_bytes();
        let secret_key = secp256k1::SecretKey::from_slice(&sk_bytes[..])
            .map_err(|_| TransactionErrors::InvalidSecretKey)?;

        let sighash_cache = SighashCache::new(&self.tx);

        let sighash = sighash_cache
            .legacy_signature_hash(input_index, prev_script_pubkey, sighash_type.to_u32())
            .map_err(|_| TransactionErrors::SighashComputationFailed)?;

        let message = Message::from_digest(*sighash.as_ref());
        let signature = secp.sign_ecdsa(&message, &secret_key);

        let bitcoin_sig = BitcoinSignature {
            signature,
            sighash_type,
        };

        let pubkey_bytes = keypair.get_pubkey_bytes();
        let public_key = secp256k1::PublicKey::from_slice(pubkey_bytes)
            .map_err(|_| TransactionErrors::InvalidPublicKey)?;

        let mut script_sig = ScriptBuf::new();

        let sig_bytes = bitcoin_sig.serialize();
        let sig_push = PushBytesBuf::try_from(sig_bytes.to_vec())
            .map_err(|_| TransactionErrors::InvalidSignature)?;
        script_sig.push_slice(sig_push);

        let pubkey_push = PushBytesBuf::try_from(public_key.serialize().to_vec())
            .map_err(|_| TransactionErrors::InvalidPublicKey)?;
        script_sig.push_slice(pubkey_push);

        self.tx.input[input_index].script_sig = script_sig;

        Ok(())
    }

    pub fn serialize(&self) -> String {
        bitcoin::consensus::encode::serialize_hex(&self.tx)
    }

    pub fn txid(&self) -> String {
        self.tx.compute_txid().to_string()
    }
}

pub fn to_satoshis(btc: f64) -> u64 {
    (btc * 100_000_000.0) as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::ScriptBuf;

    #[test]
    fn test_to_satoshis() {
        assert_eq!(to_satoshis(1.0), 100_000_000);
        assert_eq!(to_satoshis(0.5), 50_000_000);
        assert_eq!(to_satoshis(0.00000001), 1);
        assert_eq!(to_satoshis(0.3), 30_000_000);
        assert_eq!(to_satoshis(0.08), 8_000_000);
    }

    #[test]
    fn test_create_input() {
        let txin = BtcTransaction::create_input(
            "76464c2b9e2af4d63ef38a77964b3b77e629dddefc5cb9eb1a3645b1608b790f",
            0,
        )
        .unwrap();

        assert_eq!(txin.previous_output.vout, 0);
        assert_eq!(
            txin.previous_output.txid.to_string(),
            "76464c2b9e2af4d63ef38a77964b3b77e629dddefc5cb9eb1a3645b1608b790f"
        );
    }

    #[test]
    fn test_create_p2pkh_output() {
        let txout = BtcTransaction::create_p2pkh_output(
            "myPAE9HwPeKHh8FjKwBNBaHnemApo3dw6e",
            to_satoshis(0.3),
        )
        .unwrap();

        assert_eq!(txout.value.to_sat(), 30_000_000);
        assert_eq!(txout.script_pubkey.len(), 25);
    }

    #[test]
    fn test_python_script_exact_match() {
        let txin1 = BtcTransaction::create_input(
            "76464c2b9e2af4d63ef38a77964b3b77e629dddefc5cb9eb1a3645b1608b790f",
            0,
        )
        .unwrap();

        let txin2 = BtcTransaction::create_input(
            "76464c2b9e2af4d63ef38a77964b3b77e629dddefc5cb9eb1a3645b1608b790f",
            1,
        )
        .unwrap();

        let txout1 = BtcTransaction::create_p2pkh_output(
            "myPAE9HwPeKHh8FjKwBNBaHnemApo3dw6e",
            to_satoshis(0.3),
        )
        .unwrap();

        let txout2 = BtcTransaction::create_p2pkh_output(
            "mmYNBho9BWQB2dSniP1NJvnPoj5EVWw89w",
            to_satoshis(0.08),
        )
        .unwrap();

        let mut tx = BtcTransaction::new(vec![txin1, txin2], vec![txout1, txout2]);

        let unsigned_tx = tx.serialize();
        println!("\nRaw unsigned transaction:\n{}", unsigned_tx);

        let expected_unsigned = "02000000020f798b60b145361aebb95cfcdedd29e6773b4b96778af33ed6f42a9e2b4c46760000000000fdffffff0f798b60b145361aebb95cfcdedd29e6773b4b96778af33ed6f42a9e2b4c46760100000000fdffffff0280c3c901000000001976a914c3f8e5b0f8455a2b02c29c4488a550278209b66988ac00127a00000000001976a91442151d0c21442c2b038af0ad5ee64b9d6f4f4e4988ac00000000";

        assert_eq!(
            unsigned_tx, expected_unsigned,
            "Unsigned transaction must match Python output exactly"
        );

        let wif1 =
            BitcoinPrivateKey::from_wif("cTALNpTpRbbxTCJ2A5Vq88UxT44w1PE2cYqiB3n4hRvzyCev1Wwo")
                .unwrap();
        let sk1_bytes = wif1.inner.secret_bytes();
        let sk1 =
            KeyPair::from_secret_key(crate::secret_key::SecretKey::Secp256k1Bitcoin(sk1_bytes))
                .unwrap();

        let wif2 =
            BitcoinPrivateKey::from_wif("cVf3kGh6552jU2rLaKwXTKq5APHPoZqCP4GQzQirWGHFoHQ9rEVt")
                .unwrap();
        let sk2_bytes = wif2.inner.secret_bytes();
        let sk2 =
            KeyPair::from_secret_key(crate::secret_key::SecretKey::Secp256k1Bitcoin(sk2_bytes))
                .unwrap();

        let addr1_decoded = bs58::decode("n4bkvTyU1dVdzsrhWBqBw8fEMbHjJvtmJR")
            .into_vec()
            .unwrap();
        let addr1_hash: [u8; 20] = addr1_decoded[1..21].try_into().unwrap();
        let script_pubkey1 =
            ScriptBuf::new_p2pkh(&bitcoin::PubkeyHash::from_slice(&addr1_hash).unwrap());

        let addr2_decoded = bs58::decode("mmYNBho9BWQB2dSniP1NJvnPoj5EVWw89w")
            .into_vec()
            .unwrap();
        let addr2_hash: [u8; 20] = addr2_decoded[1..21].try_into().unwrap();
        let script_pubkey2 =
            ScriptBuf::new_p2pkh(&bitcoin::PubkeyHash::from_slice(&addr2_hash).unwrap());

        tx.sign_input(
            0,
            &sk1,
            &script_pubkey1,
            EcdsaSighashType::AllPlusAnyoneCanPay,
        )
        .unwrap();

        tx.sign_input(
            1,
            &sk2,
            &script_pubkey2,
            EcdsaSighashType::SinglePlusAnyoneCanPay,
        )
        .unwrap();

        let signed_tx = tx.serialize();
        println!("\nRaw signed transaction:\n{}", signed_tx);
        println!("\nTxId: {}", tx.txid());

        assert!(
            signed_tx.len() > unsigned_tx.len(),
            "Signed tx should be longer"
        );
        assert!(
            signed_tx.starts_with("02000000"),
            "Should start with version 2"
        );

        assert!(
            !tx.tx.input[0].script_sig.is_empty(),
            "Input 0 should have scriptSig"
        );
        assert!(
            !tx.tx.input[1].script_sig.is_empty(),
            "Input 1 should have scriptSig"
        );

        println!("\n✓ Transaction structure matches Python implementation");
        println!("✓ Both inputs signed successfully");
        println!("✓ Unsigned transaction matches exactly");
    }

    #[test]
    fn test_single_input_output() {
        let txin = BtcTransaction::create_input(
            "0f798b60b145361aebb95cfcdedd29e6773b4b96778af33ed6f42a9e2b4c4676",
            0,
        )
        .unwrap();

        let txout = BtcTransaction::create_p2pkh_output(
            "myPAE9HwPeKHh8FjKwBNBaHnemApo3dw6e",
            to_satoshis(0.1),
        )
        .unwrap();

        let tx = BtcTransaction::new(vec![txin], vec![txout]);
        let serialized = tx.serialize();

        assert!(serialized.starts_with("02000000"));
        assert!(!serialized.is_empty());
    }
}
