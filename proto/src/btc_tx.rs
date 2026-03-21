use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::{
    bip32, PrivateKey, PublicKey as BitcoinPublicKey, Transaction as BitcoinTransaction, Witness,
};
use errors::tx::TransactionErrors;
use std::collections::BTreeMap;

pub fn build_psbt(
    tx: BitcoinTransaction,
    witness_utxos: &[bitcoin::TxOut],
) -> Result<Psbt, TransactionErrors> {
    let mut psbt =
        Psbt::from_unsigned_tx(tx).map_err(|_| TransactionErrors::PsbtCreationFailed)?;

    for (input, utxo) in psbt.inputs.iter_mut().zip(witness_utxos.iter()) {
        input.witness_utxo = Some(utxo.clone());
    }

    Ok(psbt)
}

pub fn sign_psbt(
    psbt: &mut Psbt,
    secret_key: &bitcoin::secp256k1::SecretKey,
    public_key: &bitcoin::secp256k1::PublicKey,
    network: bitcoin::Network,
    addr_type: bitcoin::AddressType,
) -> Result<(), TransactionErrors> {
    let secp = Secp256k1::new();
    let priv_key = PrivateKey::new(*secret_key, network);
    let dummy_origin = (bip32::Fingerprint::default(), bip32::DerivationPath::default());

    match addr_type {
        bitcoin::AddressType::P2tr => {
            let (xonly, _) = public_key.x_only_public_key();

            for input in &mut psbt.inputs {
                input.tap_internal_key = Some(xonly);
                input
                    .tap_key_origins
                    .insert(xonly, (vec![], dummy_origin.clone()));
            }

            let key_map = BTreeMap::from([(xonly, priv_key)]);
            psbt.sign(&key_map, &secp)
                .map_err(|_| TransactionErrors::PsbtSigningFailed)?;
        }
        _ => {
            let btc_pubkey = BitcoinPublicKey::new(*public_key);

            for input in &mut psbt.inputs {
                input
                    .bip32_derivation
                    .insert(*public_key, dummy_origin.clone());
            }

            let key_map = BTreeMap::from([(btc_pubkey, priv_key)]);
            psbt.sign(&key_map, &secp)
                .map_err(|_| TransactionErrors::PsbtSigningFailed)?;
        }
    }

    Ok(())
}

pub fn finalize_psbt(psbt: &mut Psbt, addr_type: bitcoin::AddressType) {
    for input in &mut psbt.inputs {
        match addr_type {
            bitcoin::AddressType::P2tr => {
                if let Some(sig) = input.tap_key_sig.take() {
                    input.final_script_witness = Some(Witness::p2tr_key_spend(&sig));
                }
            }
            _ => {
                if let Some((&pubkey, sig)) = input.partial_sigs.iter().next() {
                    let mut witness = Witness::new();
                    witness.push(sig.serialize());
                    witness.push(pubkey.to_bytes());
                    input.final_script_witness = Some(witness);
                }
                input.partial_sigs.clear();
            }
        }

        input.witness_utxo = None;
        input.sighash_type = None;
        input.bip32_derivation.clear();
        input.tap_key_origins.clear();
        input.tap_internal_key = None;
    }
}
