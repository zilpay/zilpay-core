use alloy::rlp::{decode_exact, encode_list, Bytes};
use errors::tx::TransactionErrors;

pub fn safe_chunk_transaction(
    transaction_rlp: &[u8],
    derivation_path: &[u8],
    transaction_type: Option<u8>,
) -> Result<Vec<Vec<u8>>, TransactionErrors> {
    const MAX_CHUNK_SIZE: usize = 255;
    let payload = [derivation_path, transaction_rlp].concat();

    if payload.len() <= MAX_CHUNK_SIZE {
        return Ok(vec![payload]);
    }

    if transaction_type.is_some() {
        return Ok(payload
            .chunks(MAX_CHUNK_SIZE)
            .map(|chunk| chunk.to_vec())
            .collect());
    }

    // --- Legacy Transaction Logic ---

    let decoded: Vec<Bytes> =
        decode_exact(transaction_rlp).map_err(|_| TransactionErrors::EncodeTxRlpError)?;
    let vrs = &decoded[decoded.len() - 3..];

    let mut encoded_vrs_buffer = Vec::new();
    encode_list::<_, [u8]>(vrs, &mut encoded_vrs_buffer);

    let encoded_vrs_payload = &encoded_vrs_buffer[1..];

    let mut chunk_size = MAX_CHUNK_SIZE;
    let last_chunk_len = payload.len() % MAX_CHUNK_SIZE;

    if last_chunk_len != 0 && last_chunk_len <= encoded_vrs_payload.len() {
        for i in 1..=MAX_CHUNK_SIZE {
            let proposed_size = MAX_CHUNK_SIZE - i;
            if proposed_size == 0 {
                continue;
            }

            let new_last_chunk_len = payload.len() % proposed_size;
            if new_last_chunk_len == 0 || new_last_chunk_len > encoded_vrs_payload.len() {
                chunk_size = proposed_size;
                break;
            }
        }
    }

    Ok(payload
        .chunks(chunk_size)
        .map(|chunk| chunk.to_vec())
        .collect())
}

#[cfg(test)]
mod tests {
    use crate::{
        tx::{ETHTransactionRequest, TransactionRequest},
        AlloyBytes,
    };

    use super::*;
    use alloy::primitives::{Address, U256};
    use hex;

    fn get_rlp_from_request(
        tx_request: ETHTransactionRequest,
    ) -> Result<Vec<u8>, TransactionErrors> {
        let req = TransactionRequest::Ethereum((tx_request, Default::default()));
        let dummy_pk = crate::pubkey::PubKey::Secp256k1Keccak256([0; 33]);
        req.to_rlp_encode(&dummy_pk)
    }

    #[test]
    fn test_single_chunk_for_small_transaction() {
        let derivation_path_buff =
            hex::decode("058000002c8000003c800000008000000000000000").unwrap();

        let raw_tx = ETHTransactionRequest {
            to: Some(Address::ZERO.into()),
            nonce: Some(0),
            value: Some(U256::from(0)),
            gas_price: Some(1),
            gas: Some(21000),
            chain_id: Some(1),
            ..Default::default()
        };

        let rlp_buff = get_rlp_from_request(raw_tx).unwrap();

        assert!(
            rlp_buff.len() + derivation_path_buff.len() <= 255,
            "Test setup failed: Transaction is too big"
        );

        let payload = [derivation_path_buff.as_slice(), rlp_buff.as_slice()].concat();
        let chunks = safe_chunk_transaction(&rlp_buff, &derivation_path_buff, None).unwrap();

        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0], payload);
    }

    #[test]
    fn test_multiple_255b_chunks_for_typed_transaction() {
        let derivation_path_buff =
            hex::decode("058000002c8000003c800000008000000000000000").unwrap();

        let raw_tx = ETHTransactionRequest {
            to: Some(Address::ZERO.into()),
            nonce: Some(0),
            value: Some(U256::from(0)),
            gas_price: Some(1),
            gas: Some(21000),
            input: vec![0u8; 256].into(),
            chain_id: Some(1),
            transaction_type: Some(1), // EIP-2930
            ..Default::default()
        };

        let rlp_buff = get_rlp_from_request(raw_tx).unwrap();
        assert!(
            rlp_buff.len() + derivation_path_buff.len() > 255,
            "Test setup failed: Transaction is too small"
        );

        let payload = [derivation_path_buff.as_slice(), rlp_buff.as_slice()].concat();
        let chunks = safe_chunk_transaction(&rlp_buff, &derivation_path_buff, Some(1)).unwrap();

        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0].len(), 255);
        assert_eq!(chunks[0], &payload[0..255]);
        assert_eq!(chunks[1], &payload[255..]);
    }

    #[test]
    fn test_variable_chunks_for_legacy_transaction() {
        let derivation_path_buff =
            hex::decode("058000002c8000003c800000008000000000000000").unwrap();
        let data = AlloyBytes::from(vec![0u8; 458]);

        let raw_tx = ETHTransactionRequest {
            to: Some(Address::ZERO.into()),
            nonce: Some(0),
            value: Some(U256::from(0)),
            gas_price: Some(1),
            gas: Some(2),
            input: data.into(),
            chain_id: Some(127),
            ..Default::default() // Legacy transaction
        };

        let rlp_buff = get_rlp_from_request(raw_tx).unwrap();
        let payload = [derivation_path_buff.as_slice(), rlp_buff.as_slice()].concat();

        assert_eq!(
            payload.len(),
            513,
            "Test setup failed: incorrect payload length"
        );

        let chunks = safe_chunk_transaction(&rlp_buff, &derivation_path_buff, None).unwrap();

        assert_eq!(chunks.len(), 3);
        assert_eq!(chunks[0].len(), 254);
        assert_eq!(chunks[1].len(), 254);
        assert_eq!(chunks[2].len(), 5);

        assert_eq!(chunks[0], &payload[0..254]);
        assert_eq!(chunks[1], &payload[254..508]);
        assert_eq!(chunks[2], &payload[508..]);
    }

    #[test]
    fn test_legacy_transaction_chunking() {
        let derivation_path_hex = "058000002c8000003c800000008000000000000000";
        let rlp_hex = "0xf901d28086053275f90e008302924494cd205474f63234d0ff1efe65da4438167f6fb2c189055de6a779bbac0000b901a45ae401dc0000000000000000000000000000000000000000000000000000000068bd2d2100000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000e4472b43f30000000000000000000000000000000000000000000000055de6a779bbac0000000000000000000000000000000000000000000000000002d044375cf277987b0000000000000000000000000000000000000000000000000000000000000080000000000000000000000000a1b2ff03f501a4d8278cb75a9075f406a5b8c5ff0000000000000000000000000000000000000000000000000000000000000002000000000000000000000000878c5008a348a60a5b239844436a7b483fadb7f20000000000000000000000001fd09f6701a1852132a649fe9d07f2a3b991ecfa00000000000000000000000000000000000000000000000000000000";

        let derivation_path_buff =
            hex::decode(derivation_path_hex).expect("Failed to decode derivation path");
        let rlp_buff = hex::decode(&rlp_hex[2..]).expect("Failed to decode RLP");
        let payload = [derivation_path_buff.as_slice(), rlp_buff.as_slice()].concat();
        let tx_type: Option<u8> = None;
        let chunks = safe_chunk_transaction(&rlp_buff, &derivation_path_buff, tx_type).unwrap();

        assert_eq!(
            &[
                [
                    5, 128, 0, 0, 44, 128, 0, 0, 60, 128, 0, 0, 0, 128, 0, 0, 0, 0, 0, 0, 0, 249,
                    1, 210, 128, 134, 5, 50, 117, 249, 14, 0, 131, 2, 146, 68, 148, 205, 32, 84,
                    116, 246, 50, 52, 208, 255, 30, 254, 101, 218, 68, 56, 22, 127, 111, 178, 193,
                    137, 5, 93, 230, 167, 121, 187, 172, 0, 0, 185, 1, 164, 90, 228, 1, 220, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    104, 189, 45, 33, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 32, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 228, 71, 43, 67, 243, 0, 0, 0, 0, 0, 0, 0
                ]
                .to_vec(),
                [
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5, 93, 230, 167, 121, 187, 172,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
                    208, 68, 55, 92, 242, 119, 152, 123, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 128, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 161, 178, 255, 3, 245, 1, 164, 216, 39, 140, 183, 90, 144, 117,
                    244, 6, 165, 184, 197, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 135, 140, 80, 8, 163, 72, 166, 10, 91, 35, 152, 68, 67, 106, 123, 72, 63,
                    173, 183, 242, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 31, 208, 159, 103, 1, 161,
                    133, 33, 50, 166, 73, 254, 157, 7, 242, 163, 185, 145, 236, 250, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
                ]
                .to_vec(),
            ]
            .to_vec(),
            &chunks
        );

        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0].len(), 245);
        assert_eq!(chunks[1].len(), 245);

        let expected_chunk1 = &payload[0..245];
        let expected_chunk2 = &payload[245..490];

        assert_eq!(chunks[0], expected_chunk1,);
        assert_eq!(chunks[1], expected_chunk2,);
    }
}
