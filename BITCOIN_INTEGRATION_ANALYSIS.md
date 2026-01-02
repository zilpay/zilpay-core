# Bitcoin Integration Analysis & Implementation Plan

## Current State Analysis

### What's Already Working ✅

1. **PubKey enum** (`proto/src/pubkey.rs`):
   - ✅ Bitcoin variant exists: `Secp256k1Bitcoin(([u8; 33], bitcoin::Network, bitcoin::AddressType))`
   - ✅ Stores network params (Bitcoin, Testnet, Testnet4, Signet, Regtest)
   - ✅ Stores address type (P2pkh, P2sh, P2wpkh, P2wsh, P2tr, P2a)
   - ✅ Proper serialization/deserialization with ByteCodec trait

2. **KeyPair enum** (`proto/src/keypair.rs`):
   - ✅ Bitcoin variant exists: `Secp256k1Bitcoin((pubkey, secretkey, network, addr_type))`
   - ✅ Has `gen_bitcoin(network, addr_type)` for random key generation
   - ✅ Has `from_secret_key()` that handles Bitcoin SecretKey
   - ✅ Has conversion methods: `to_bitcoin(network, addr_type)`
   - ✅ Extensive test coverage for Bitcoin functionality

3. **Address generation**:
   - ✅ Bitcoin addresses work correctly (see tests in keypair.rs)
   - ✅ Multiple address formats supported

4. **Slip44 constants** (`crypto/src/slip44.rs`):
   - ✅ `BITCOIN = 0` already defined

5. **DerivationPath** (`crypto/src/bip49.rs`):
   - ✅ Recently updated to include `bip` field (commit 2459bcc)
   - ✅ Has BIP constants: BIP44_PURPOSE, BIP49_PURPOSE, BIP84_PURPOSE, BIP86_PURPOSE

### Critical Gap ❌

**The main issue**: HD wallet (BIP39 mnemonic) support for Bitcoin is incomplete!

In `KeyPair::from_bip39_seed()` (proto/src/keypair.rs:146-168):
```rust
pub fn from_bip39_seed(seed: &[u8; BIP39_SEED_SIZE], bip49: &DerivationPath) -> Result<Self> {
    // ... derives the key correctly ...

    match bip49.slip44 {
        slip44::ETHEREUM | slip44::ZILLIQA => {
            Ok(Self::Secp256k1Keccak256((pub_key, secret_key)))
        }
        _ => {
            // Bitcoin would fall here and ERROR OUT!
            return Err(KeyPairError::ExtendedPrivKeyDeriveError(
                Bip329Errors::InvalidSlip44(bip49.slip44),
            ))
        }
    }
}
```

This means:
- ✅ You can create Bitcoin accounts from SecretKey (`Account::from_secret_key`)
- ✅ You can create Bitcoin accounts from Ledger (`Account::from_ledger`)
- ❌ You **CANNOT** create Bitcoin accounts from BIP39 mnemonic (`Account::from_hd`)

## The Problem

When users want to create Bitcoin accounts from a mnemonic phrase:
1. `Wallet::from_bip39_words()` is called with `Bip39Params`
2. For each index, it calls `Account::from_hd(mnemonic_seed, name, bip49, ...)`
3. `Account::from_hd()` calls `KeyPair::from_bip39_seed(mnemonic_seed, bip49)`
4. **This fails for Bitcoin** because only ETHEREUM and ZILLIQA are supported

## Proposed Solution

### Extend DerivationPath (FINAL APPROACH ⭐)

Add Bitcoin-specific network parameter to `DerivationPath`:

```rust
#[derive(Debug, Clone, Copy)]
pub struct DerivationPath {
    pub slip44: u32,
    pub bip: u32,
    pub index: usize,
    pub network: Option<bitcoin::Network>,
}
```

**Benefits**:
- Network is Optional (ETH/ZIL/BSC don't need it, only Bitcoin does)
- Address type auto-derives from BIP number (BIP44→P2pkh, BIP84→P2wpkh, etc.)
- Clean separation of concerns
- Backward compatible (Option type)
- Minimal changes needed

**Implementation steps**:

1. **Update DerivationPath struct** (`crypto/src/bip49.rs`):
   ```rust
   impl DerivationPath {
       pub fn get_address_type(&self) -> bitcoin::AddressType {
           match self.bip {
               Self::BIP44_PURPOSE => bitcoin::AddressType::P2pkh,
               Self::BIP49_PURPOSE => bitcoin::AddressType::P2sh,
               Self::BIP84_PURPOSE => bitcoin::AddressType::P2wpkh,
               Self::BIP86_PURPOSE => bitcoin::AddressType::P2tr,
               _ => bitcoin::AddressType::P2wpkh,
           }
       }

       pub fn new_bitcoin(
           index: usize,
           bip: u32,
           network: bitcoin::Network,
       ) -> Self {
           Self {
               slip44: slip44::BITCOIN,
               bip,
               index,
               network: Some(network),
           }
       }
   }
   ```

2. **Update KeyPair::from_bip39_seed** (`proto/src/keypair.rs`):
   ```rust
   pub fn from_bip39_seed(seed: &[u8; BIP39_SEED_SIZE], bip49: &DerivationPath) -> Result<Self> {
       let path = bip49.get_path();
       let secret_key = derive_private_key(seed, &path)
           .map_err(KeyPairError::ExtendedPrivKeyDeriveError)?;
       let pub_key: [u8; PUB_KEY_SIZE] = secret_key
           .public_key()
           .to_sec1_bytes()
           .to_vec()
           .try_into()
           .or(Err(KeyPairError::InvalidSecretKey))?;
       let secret_key: [u8; SECRET_KEY_SIZE] = secret_key.to_bytes().into();

       match bip49.slip44 {
           slip44::ETHEREUM | slip44::ZILLIQA => {
               Ok(Self::Secp256k1Keccak256((pub_key, secret_key)))
           }
           slip44::BITCOIN => {
               let network = bip49.network.ok_or(
                   KeyPairError::ExtendedPrivKeyDeriveError(
                       Bip329Errors::MissingBitcoinNetwork
                   )
               )?;
               let addr_type = bip49.get_address_type();
               Ok(Self::Secp256k1Bitcoin((pub_key, secret_key, network, addr_type)))
           }
           _ => {
               Err(KeyPairError::ExtendedPrivKeyDeriveError(
                   Bip329Errors::InvalidSlip44(bip49.slip44),
               ))
           }
       }
   }
   ```

3. **Update existing constructors** to preserve backward compatibility:
   ```rust
   pub fn new(slip44: u32, index: usize, bip: u32) -> Self {
       Self {
           slip44,
           index,
           bip,
           network: None,
       }
   }
   ```

### BIP Standard to Address Type Mapping

For Bitcoin, different BIP standards correspond to different address types:

| BIP Standard | Purpose | Address Type | Address Format | Example |
|--------------|---------|--------------|----------------|---------|
| BIP44 | Legacy | P2pkh | `1...` | `1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2` |
| BIP49 | Wrapped SegWit | P2sh | `3...` | `3J98t1WpEZ73CNmYviecrnyiWrnqRhWNLy` |
| BIP84 | Native SegWit | P2wpkh | `bc1q...` | `bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4` |
| BIP86 | Taproot | P2tr | `bc1p...` | `bc1p5d7rjq7g6rdk2yhzks9smlaqtedr4dekq08ge8ztwac72sfr9rusxg3297` |

### Alternative Option 2: Separate Bitcoin Derivation

Create a dedicated Bitcoin derivation structure:

```rust
pub struct BitcoinDerivationPath {
    pub bip: u32,
    pub index: usize,
    pub network: bitcoin::Network,
    pub addr_type: bitcoin::AddressType,
}
```

**Drawbacks**:
- More code duplication
- Need to update Account struct to handle multiple types
- More complex API

## Implementation Checklist

- [ ] Add `network` and `addr_type` fields to `DerivationPath` (crypto/src/bip49.rs)
- [ ] Add `new_bitcoin()` constructor to `DerivationPath`
- [ ] Add `address_type_from_bip()` helper method
- [ ] Update `KeyPair::from_bip39_seed()` to handle `slip44::BITCOIN`
- [ ] Update serialization/deserialization for `DerivationPath` if needed
- [ ] Add tests for Bitcoin HD derivation in proto/src/keypair.rs
- [ ] Add tests for Bitcoin account creation in wallet/src/account.rs
- [ ] Add integration test in wallet/src/wallet_init.rs
- [ ] Add error variants: `MissingBitcoinNetwork` to Bip329Errors

## Usage Example

After implementation, creating Bitcoin accounts would look like:

```rust
// Creating Bitcoin accounts from mnemonic
let mnemonic = Mnemonic::parse_str(&EN_WORDS, "your twelve word phrase...").unwrap();
let seed = mnemonic.to_seed("").unwrap();

// Native SegWit (BIP84)
let btc_path = DerivationPath::new_bitcoin(
    0,
    DerivationPath::BIP84_PURPOSE,
    bitcoin::Network::Bitcoin,
    bitcoin::AddressType::P2wpkh,
);

// Or let it auto-derive from BIP purpose:
let btc_path = DerivationPath {
    slip44: slip44::BITCOIN,
    bip: DerivationPath::BIP84_PURPOSE,
    index: 0,
    network: Some(bitcoin::Network::Bitcoin),
    addr_type: None, // Will auto-derive to P2wpkh from BIP84
};

let account = Account::from_hd(&seed, "Bitcoin Account 0", &btc_path, chain_hash, chain_id, slip44::BITCOIN)?;
```

## Questions to Clarify

1. **Network Selection**: Should users specify the network, or should it default to Bitcoin mainnet?
2. **Address Type Default**: Should we auto-derive from BIP, or require explicit specification?
3. **Multiple Accounts**: Should we support multiple address types per mnemonic (e.g., both legacy and SegWit)?
4. **Account Discovery**: Do we need BIP44 account discovery to find existing accounts?

## Recommendation

**Start with Option 1** (Extend DerivationPath). It's the cleanest approach that:
- Leverages existing infrastructure
- Keeps Bitcoin params together with derivation info
- Allows smart defaults while supporting explicit overrides
- Maintains backward compatibility

The implementation is straightforward and aligns with the recent BIP field addition to DerivationPath.
