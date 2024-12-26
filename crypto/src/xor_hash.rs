pub fn xor_hash(network_name: &str, chain_id: u64) -> u64 {
    let mut hash: u64 = 0;

    for (i, byte) in network_name.bytes().enumerate() {
        hash ^= (byte as u64) << (i % 8 * 8);
    }

    hash ^= chain_id.rotate_left(network_name.len() as u32 % 64);

    hash
}
