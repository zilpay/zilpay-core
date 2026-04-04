use bincode;
use solana_hash::Hash;
use solana_message::legacy::Message;
use solana_pubkey::Pubkey;
use solana_system_interface::instruction::transfer as system_transfer;
use spl_associated_token_account::get_associated_token_address;
use spl_token::instruction::transfer as token_transfer;

pub fn build_sol_transfer_message(
    from: &Pubkey,
    to: &Pubkey,
    lamports: u64,
    blockhash: &[u8; 32],
) -> Vec<u8> {
    let hash = Hash::from(*blockhash);
    let ix = system_transfer(from, to, lamports);
    let msg = Message::new_with_blockhash(&[ix], Some(from), &hash);
    bincode::serialize(&msg).expect("serialize")
}

pub fn build_spl_transfer_message(
    owner: &Pubkey,
    mint: &Pubkey,
    to_wallet: &Pubkey,
    amount: u64,
    blockhash: &[u8; 32],
) -> Result<Vec<u8>, String> {
    let source_ata = get_associated_token_address(owner, mint);
    let dest_ata = get_associated_token_address(to_wallet, mint);
    let hash = Hash::from(*blockhash);
    let ix = token_transfer(
        &spl_token::id(),
        &source_ata,
        &dest_ata,
        owner,
        &[],
        amount,
    )
    .map_err(|e| e.to_string())?;
    let msg = Message::new_with_blockhash(&[ix], Some(owner), &hash);
    Ok(bincode::serialize(&msg).expect("serialize"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use solana_message::legacy::Message as SolanaMessage;

    const DEVNET_RICH_ADDRESS: &str = "vines1vzrYbzLMRdu58ou5XTby4qAqVRLmqo36NKPTg";
    const DEVNET_USDC_MINT: &str = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU";
    const DEVNET_USDC_RICH_ATA: &str = "6r6KJLTwFLnJ2czodnEQeiWfAEDw2nkCDsu4AwptU3fm";

    #[test]
    fn test_build_sol_transfer_message_roundtrip() {
        let from = Pubkey::new_unique();
        let to = Pubkey::new_unique();
        let msg = build_sol_transfer_message(&from, &to, 1_000_000, &[0u8; 32]);
        assert!(!msg.is_empty());
        let decoded: SolanaMessage = bincode::deserialize(&msg).unwrap();
        assert_eq!(decoded.account_keys.len(), 3);
    }

    #[test]
    fn test_build_spl_transfer_message_roundtrip() {
        let owner = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let to = Pubkey::new_unique();
        let msg = build_spl_transfer_message(&owner, &mint, &to, 1_000, &[0u8; 32]).unwrap();
        assert!(!msg.is_empty());
        let decoded: SolanaMessage = bincode::deserialize(&msg).unwrap();
        assert_eq!(decoded.account_keys.len(), 4);
    }

    #[test]
    fn test_known_ata_derivation() {
        let owner: Pubkey = DEVNET_RICH_ADDRESS.parse().unwrap();
        let mint: Pubkey = DEVNET_USDC_MINT.parse().unwrap();
        let ata = get_associated_token_address(&owner, &mint);
        assert_eq!(ata.to_string(), DEVNET_USDC_RICH_ATA);
    }
}
