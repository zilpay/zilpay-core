# Path-Based Account Derivation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Refactor account creation to use `DerivationPath` strings for account specification, add derivation metadata to `AccountV2`, and fix per-chain default derivation (Solana bug).

**Architecture:** Replace `BackgroundBip39Params.accounts: &'a [(usize, String)]` with path strings `&'a [(&'a str, String)]`. Each path like `"m/44'/60'/0'/0/0"` self-describes chain (slip44), address format (bip), and index via `DerivationPath::try_from`. Background parses paths to extract indexes, wallet layer still receives `(usize, String)` indexes. A new `Option<DerivationInfo>` field on `AccountV2` stores non-default derivation parameters. A new `DerivationPath::default_derivation(slip44, index)` method returns the correct `DerivationType` per chain (fixing Solana which currently uses wrong path).

**Tech Stack:** Rust, serde/bincode, existing crypto/wallet/background crates.

---

## File Structure

| File | Action | Purpose |
|------|--------|---------|
| `crypto/src/bip49.rs` | Modify | Add `default_derivation(slip44, index)` method |
| `wallet/src/account.rs` | Modify | Add `DerivationInfo` struct, add field to `AccountV2`, update `from_hd` |
| `wallet/src/wallet_init.rs` | Modify | Use `default_derivation` in `from_bip39_words` (fix Solana), update tests |
| `wallet/src/wallet_account.rs` | Modify | Use `default_derivation` in `ensure_chain_accounts`, store `DerivationInfo` |
| `wallet/src/wallet_crypto.rs` | Modify | Use `DerivationInfo` in `reveal_keypair`, add address verification |
| `background/src/lib.rs` | Modify | Change `BackgroundBip39Params.accounts` to path strings |
| `background/src/bg_wallet.rs` | Modify | Parse paths in `add_bip39_wallet`, update tests |
| `background/src/bg_provider.rs` | Modify | Update tests that construct `BackgroundBip39Params` |

---

### Task 1: Add `default_derivation` method to `DerivationPath`

**Files:**
- Modify: `crypto/src/bip49.rs:60-148`

Add a method that returns the correct `DerivationType` for a given slip44 and HD index. This fixes the Solana bug where `AddressIndex(0,0,idx)` was used instead of `Account(idx)`.

- [ ] **Step 1: Write the failing test**

In `crypto/src/bip49.rs`, add to the `tests` module:

```rust
#[test]
fn test_default_derivation() {
    assert_eq!(
        DerivationPath::default_derivation(slip44::ETHEREUM, 5),
        DerivationType::AddressIndex(0, 0, 5)
    );
    assert_eq!(
        DerivationPath::default_derivation(slip44::ZILLIQA, 0),
        DerivationType::AddressIndex(0, 0, 0)
    );
    assert_eq!(
        DerivationPath::default_derivation(slip44::BITCOIN, 3),
        DerivationType::AddressIndex(0, 0, 3)
    );
    assert_eq!(
        DerivationPath::default_derivation(slip44::TRON, 2),
        DerivationType::AddressIndex(0, 0, 2)
    );
    assert_eq!(
        DerivationPath::default_derivation(slip44::SOLANA, 7),
        DerivationType::Account(7)
    );
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p crypto -- test_default_derivation`
Expected: FAIL - method does not exist

- [ ] **Step 3: Write minimal implementation**

In `crypto/src/bip49.rs`, add inside `impl DerivationPath` block (after `bip_from_address_type` around line 147):

```rust
pub fn default_derivation(slip44: u32, index: usize) -> DerivationType {
    match slip44 {
        super::slip44::SOLANA => DerivationType::Account(index),
        _ => DerivationType::AddressIndex(0, 0, index),
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p crypto -- test_default_derivation`
Expected: PASS

- [ ] **Step 5: Run all crypto tests**

Run: `cargo test -p crypto`
Expected: All pass

- [ ] **Step 6: Commit**

```bash
git add crypto/src/bip49.rs
git commit -m "feat(crypto): add default_derivation method to DerivationPath"
```

---

### Task 2: Add `DerivationInfo` struct and field to `AccountV2`

**Files:**
- Modify: `wallet/src/account.rs:1-145`

Add a new `DerivationInfo` struct that stores non-default account/change values. Add it as `Option<DerivationInfo>` on `AccountV2` with `#[serde(default)]` for backward compatibility.

- [ ] **Step 1: Add `DerivationInfo` struct**

In `wallet/src/account.rs`, add before `AccountV2` struct definition (after imports):

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, Default)]
pub struct DerivationInfo {
    pub account: u32,
    pub change: u32,
}
```

- [ ] **Step 2: Add `derivation` field to `AccountV2`**

In `wallet/src/account.rs`, modify `AccountV2`:

```rust
#[derive(Debug, PartialEq, Eq, Deserialize, Serialize, Clone)]
pub struct AccountV2 {
    pub name: String,
    pub account_type: AccountType,
    pub addr: Address,
    pub pub_key: Option<PubKey>,
    #[serde(default)]
    pub derivation: Option<DerivationInfo>,
}
```

- [ ] **Step 3: Update all `AccountV2` construction sites with `derivation: None`**

In `wallet/src/account.rs`, update `AccountV2` construction in:
- `From<AccountV1> for AccountV2` (add `derivation: None`)
- `AccountV2::from_ledger` (add `derivation: None`)
- `AccountV2::from_secret_key` (add `derivation: None`)

In `wallet/src/wallet_init.rs`, update `AccountV2` construction in:
- `from_ledger` method (add `derivation: None`)

- [ ] **Step 4: Update `AccountV2::from_hd` to store `DerivationInfo`**

In `wallet/src/account.rs`, update `AccountV2::from_hd`:

```rust
pub fn from_hd(
    mnemonic_seed: &[u8; SHA512_SIZE],
    name: String,
    bip49: &DerivationPath,
) -> Result<Self> {
    let keypair = KeyPair::from_bip39_seed(mnemonic_seed, bip49)?;
    let addr = keypair.get_addr()?;
    let pub_key = if bip49.slip44 == crypto::slip44::ZILLIQA {
        Some(keypair.get_pubkey()?)
    } else {
        None
    };
    let account_type = AccountType::Bip39HD(bip49.get_index());
    let derivation = match bip49.derivation {
        crypto::bip49::DerivationType::AddressIndex(a, c, _) => {
            if a == 0 && c == 0 {
                None
            } else {
                Some(DerivationInfo {
                    account: a as u32,
                    change: c as u32,
                })
            }
        }
        _ => None,
    };

    Ok(Self {
        account_type,
        addr,
        pub_key,
        name,
        derivation,
    })
}
```

- [ ] **Step 5: Run wallet tests to verify**

Run: `cargo test -p wallet`
Expected: Some tests may fail due to serialization changes - fix any that construct `AccountV2` without `derivation` field

- [ ] **Step 6: Fix any failing tests**

Any test that constructs `AccountV2` directly (not via `from_hd`/`from_secret_key`/`from_ledger`) needs `derivation: None` added.

- [ ] **Step 7: Run all wallet tests**

Run: `cargo test -p wallet`
Expected: All pass

- [ ] **Step 8: Commit**

```bash
git add wallet/src/account.rs
git commit -m "feat(wallet): add DerivationInfo to AccountV2 for path-based derivation"
```

---

### Task 3: Fix `from_bip39_words` to use correct derivation per chain

**Files:**
- Modify: `wallet/src/wallet_init.rs:210-244`

Replace hardcoded `DerivationType::AddressIndex(0, 0, idx)` with `DerivationPath::default_derivation(slip44, idx)` to correctly handle Solana and future chains.

- [ ] **Step 1: Write the failing test**

In `wallet/src/wallet_init.rs` tests module, add a test that verifies Solana accounts use `Account(index)` derivation (this test will fail with current code since it uses `AddressIndex`):

```rust
#[test]
fn test_solana_uses_correct_derivation() {
    let (storage, _dir) = setup_test_storage();
    let argon_seed = derive_key(TEST_PASSWORD.as_bytes(), b"", &ARGON2_DEFAULT_CONFIG).unwrap();
    let keychain = KeyChain::from_seed(&argon_seed).unwrap();
    let mnemonic = Mnemonic::parse_str(&EN_WORDS, ANVIL_MNEMONIC).unwrap();
    let indexes = [0, 1].map(|i| (i, format!("Solana Account {i}")));
    let proof = derive_key(&argon_seed[..PROOF_SIZE], b"", &ARGON2_DEFAULT_CONFIG).unwrap();
    let wallet_config = WalletConfig {
        keychain,
        storage: Arc::clone(&storage),
        settings: Default::default(),
    };
    let mut chain_config = ChainConfig::default();
    chain_config.slip_44 = crypto::slip44::SOLANA;
    let wallet = Wallet::from_bip39_words(
        Bip39Params {
            chain_config: &chain_config,
            proof,
            mnemonic: &mnemonic,
            passphrase: "",
            indexes: &indexes,
            wallet_name: "Solana Wallet".to_string(),
            bip: DerivationPath::BIP44_PURPOSE,
            biometric_type: AuthMethod::None,
            chains: &[chain_config.clone()],
        },
        wallet_config,
        vec![],
    )
    .unwrap();
    let data = wallet.get_wallet_data().unwrap();
    let accounts = data.get_accounts().unwrap();
    assert_eq!(accounts.len(), 2);
    for account in accounts {
        assert!(
            matches!(account.addr, proto::address::Address::Ed25519Solana(_)),
            "Expected Solana address"
        );
    }
}
```

- [ ] **Step 2: Run test to check current behavior**

Run: `cargo test -p wallet -- test_solana_uses_correct_derivation`
Expected: May fail or pass depending on how Ed25519 derivation handles the wrong path

- [ ] **Step 3: Update `from_bip39_words` to use `default_derivation`**

In `wallet/src/wallet_init.rs`, in the `from_bip39_words` method, find the thread spawn block (~line 227-243) and replace:

```rust
let path = crypto::bip49::DerivationPath::new(
    slip44,
    crypto::bip49::DerivationType::AddressIndex(0, 0, idx),
    bip,
    network,
);
```

with:

```rust
let path = crypto::bip49::DerivationPath::new(
    slip44,
    crypto::bip49::DerivationPath::default_derivation(slip44, idx),
    bip,
    network,
);
```

- [ ] **Step 4: Run all wallet init tests**

Run: `cargo test -p wallet -- wallet_init`
Expected: All pass (existing addresses should NOT change for ETH/ZIL/BTC/TRON since their default_derivation returns the same `AddressIndex(0,0,idx)`)

- [ ] **Step 5: Commit**

```bash
git add wallet/src/wallet_init.rs
git commit -m "fix(wallet): use chain-specific default derivation in from_bip39_words"
```

---

### Task 4: Update `ensure_chain_accounts` and `add_next_bip39_account`

**Files:**
- Modify: `wallet/src/wallet_account.rs:105-225`

Use `default_derivation` instead of hardcoded `AddressIndex` in `ensure_chain_accounts`.

- [ ] **Step 1: Update `ensure_chain_accounts` for SecretPhrase branch**

In `wallet/src/wallet_account.rs`, in the `ensure_chain_accounts` method, find the `WalletTypes::SecretPhrase` branch (~line 200-206) and replace:

```rust
let path = DerivationPath::new(
    target_slip44,
    crypto::bip49::DerivationType::AddressIndex(0, 0, idx),
    bip,
    net,
);
```

with:

```rust
let path = DerivationPath::new(
    target_slip44,
    DerivationPath::default_derivation(target_slip44, idx),
    bip,
    net,
);
```

- [ ] **Step 2: Run wallet account tests**

Run: `cargo test -p wallet -- wallet_account`
Expected: All pass

- [ ] **Step 3: Commit**

```bash
git add wallet/src/wallet_account.rs
git commit -m "refactor(wallet): use default_derivation in ensure_chain_accounts"
```

---

### Task 5: Update `reveal_keypair` to use `DerivationInfo`

**Files:**
- Modify: `wallet/src/wallet_crypto.rs:34-111`

Use the `DerivationInfo` from `AccountV2` to reconstruct the derivation path, with a fallback to `default_derivation`. Add address verification after derivation.

- [ ] **Step 1: Update `reveal_keypair` for SecretPhrase branch**

In `wallet/src/wallet_crypto.rs`, in the `WalletTypes::SecretPhrase` branch (~line 57-108), replace the path reconstruction block:

```rust
let hd_index = account.account_type.value();
let (bip_purpose, network) = match &account.addr {
    Address::Secp256k1Bitcoin(_) => {
        let purpose = account.addr.get_bip_purpose();
        let net = account.addr.get_bitcoin_network()?;
        (purpose, Some(net))
    }
    _ => (DerivationPath::BIP44_PURPOSE, None),
};

let bip_path = crypto::bip49::DerivationPath::new(
    provider.config.slip_44,
    crypto::bip49::DerivationType::AddressIndex(0, 0, hd_index),
    bip_purpose,
    network,
);
```

with:

```rust
let hd_index = account.account_type.value();
let (bip_purpose, network) = match &account.addr {
    Address::Secp256k1Bitcoin(_) => {
        let purpose = account.addr.get_bip_purpose();
        let net = account.addr.get_bitcoin_network()?;
        (purpose, Some(net))
    }
    _ => (DerivationPath::BIP44_PURPOSE, None),
};

let derivation = account
    .derivation
    .map(|d| {
        crypto::bip49::DerivationType::AddressIndex(
            d.account as usize,
            d.change as usize,
            hd_index,
        )
    })
    .unwrap_or_else(|| {
        crypto::bip49::DerivationPath::default_derivation(
            provider.config.slip_44,
            hd_index,
        )
    });

let bip_path = crypto::bip49::DerivationPath::new(
    provider.config.slip_44,
    derivation,
    bip_purpose,
    network,
);
```

- [ ] **Step 2: Run wallet crypto tests**

Run: `cargo test -p wallet -- wallet_crypto`
Expected: All pass (same addresses derived since derivation is the same)

- [ ] **Step 3: Commit**

```bash
git add wallet/src/wallet_crypto.rs
git commit -m "refactor(wallet): use DerivationInfo in reveal_keypair for path reconstruction"
```

---

### Task 6: Change `BackgroundBip39Params.accounts` to path strings

**Files:**
- Modify: `background/src/lib.rs:24`
- Modify: `background/src/bg_wallet.rs:239-304`
- Modify: `background/src/bg_wallet.rs:514-984` (tests)
- Modify: `background/src/bg_provider.rs:234-720` (tests)

This is the main API change. `accounts` changes from `&'a [(usize, String)]` to `&'a [(&'a str, String)]`.

- [ ] **Step 1: Update `BackgroundBip39Params` struct**

In `background/src/lib.rs`, change:

```rust
pub accounts: &'a [(usize, String)],
```

to:

```rust
pub accounts: &'a [(&'a str, String)],
```

Remove the `bip` field since it will be extracted from the first path:

```rust
pub struct BackgroundBip39Params<'a> {
    pub password: &'a SecretString,
    pub mnemonic_str: &'a str,
    pub mnemonic_check: bool,
    pub passphrase: &'a str,
    pub wallet_name: String,
    pub biometric_type: AuthMethod,
    pub wallet_settings: WalletSettings,
    pub accounts: &'a [(&'a str, String)],
    pub chain_hash: u64,
    pub ftokens: Vec<FToken>,
}
```

- [ ] **Step 2: Update `add_bip39_wallet` to parse paths**

In `background/src/bg_wallet.rs`, in the `add_bip39_wallet` method, after getting the provider (~line 240), add path parsing:

```rust
let first_path =
    crypto::bip49::DerivationPath::try_from(params.accounts[0].0)
        .map_err(|e| BackgroundError::WalletErrors(WalletErrors::Bip32Errors(e)))?;
let bip = first_path.bip;

let indexes: Vec<(usize, String)> = params
    .accounts
    .iter()
    .map(|(path_str, name)| {
        let path = crypto::bip49::DerivationPath::try_from(*path_str)
            .map_err(|e| BackgroundError::WalletErrors(WalletErrors::Bip32Errors(e)))?;
        Ok((path.get_index(), name.clone()))
    })
    .collect::<std::result::Result<Vec<_>, BackgroundError>>()?;
```

Then update the `Bip39Params` construction to use `bip` and `indexes`:

```rust
let wallet = Wallet::from_bip39_words(
    Bip39Params {
        proof,
        mnemonic: &mnemonic,
        passphrase: params.passphrase,
        indexes: &indexes,
        wallet_name: params.wallet_name,
        bip,
        biometric_type: params.biometric_type,
        chain_config: &provider.config,
        chains: &chains,
    },
    wallet_config,
    ftokens,
)?;
```

Add the import for `Bip329Errors` in `WalletErrors` if not already there. Check `errors/src/wallet.rs` and `errors/src/bip32.rs` for the error type mapping.

- [ ] **Step 3: Update background wallet tests**

In `background/src/bg_wallet.rs` tests, update all `BackgroundBip39Params` constructions.

Example - change from:
```rust
let accounts = [(0, "Zilliqa wallet".to_string())];
bg.add_bip39_wallet(BackgroundBip39Params {
    ...
    accounts: &accounts,
    bip: DerivationPath::BIP44_PURPOSE,
    ...
})
```

To:
```rust
let accounts = [("m/44'/313'/0'/0/0", "Zilliqa wallet".to_string())];
bg.add_bip39_wallet(BackgroundBip39Params {
    ...
    accounts: &accounts,
    // bip field removed
    ...
})
```

Update ALL test functions in `bg_wallet.rs` that construct `BackgroundBip39Params`:
- `test_add_more_wallets_bip39`
- `test_delete_wallet`
- `test_generate_zilliqa_legacy_accounts`
- `test_select_bitcoin_address_format`
- `test_select_bitcoin_address_format_with_extra_accounts`
- `test_select_bitcoin_address_format_not_bitcoin`
- `test_select_bitcoin_address_format_same_bip`

- [ ] **Step 4: Update background provider tests**

In `background/src/bg_provider.rs` tests, update all `BackgroundBip39Params` constructions:

- `test_select_chain_derive_missing`
- `test_bip_preference_persists_across_chain_switches`
- `test_default_bip_for_new_chain`
- `test_select_chain_no_password_returns_auth_required`
- `test_select_chain_sk_wallet`

- [ ] **Step 5: Run all background tests**

Run: `cargo test -p background`
Expected: All pass

- [ ] **Step 6: Commit**

```bash
git add background/src/lib.rs background/src/bg_wallet.rs background/src/bg_provider.rs
git commit -m "feat(background): use derivation path strings for account specification"
```

---

### Task 7: Add path validation and error handling

**Files:**
- Modify: `background/src/bg_wallet.rs` (add_bip39_wallet)

Add validation that all paths in a single wallet creation have consistent slip44 and bip values.

- [ ] **Step 1: Add validation in `add_bip39_wallet`**

In the path parsing block of `add_bip39_wallet`, add validation:

```rust
let mut first_path: Option<crypto::bip49::DerivationPath> = None;
let mut indexes: Vec<(usize, String)> = Vec::with_capacity(params.accounts.len());

for (path_str, name) in params.accounts {
    let path = crypto::bip49::DerivationPath::try_from(*path_str)
        .map_err(|e| BackgroundError::WalletErrors(WalletErrors::Bip32Errors(e)))?;

    if let Some(ref first) = first_path {
        if path.slip44 != first.slip44 || path.bip != first.bip {
            return Err(BackgroundError::WalletErrors(WalletErrors::InvalidBIPPath(
                path.slip44,
                path.bip,
            )));
        }
    } else {
        first_path = Some(path);
    }

    indexes.push((path.get_index(), name.clone()));
}

let bip = first_path
    .ok_or(BackgroundError::WalletErrors(WalletErrors::NoAccounts))?
    .bip;
```

- [ ] **Step 2: Add `NoAccounts` variant to `WalletErrors`**

In `errors/src/wallet.rs`, add:
```rust
NoAccounts,
```

And implement `Display` for it.

- [ ] **Step 3: Ensure `Bip32Errors` is mapped from `BackgroundError`**

Check that the error mapping chain works: `Bip329Errors` → `WalletErrors::Bip32Errors` → `BackgroundError::WalletErrors`. Add the `Bip32Errors` variant to `WalletErrors` if it doesn't exist:

```rust
Bip32Errors(errors::bip32::Bip329Errors),
```

- [ ] **Step 4: Run all background tests**

Run: `cargo test -p background`
Expected: All pass

- [ ] **Step 5: Commit**

```bash
git add background/src/bg_wallet.rs errors/src/wallet.rs
git commit -m "feat(background): add path validation in add_bip39_wallet"
```

---

### Task 8: Full integration test

**Files:**
- Modify: `background/src/bg_wallet.rs` (add integration test)

Add an integration test that verifies the complete flow: path-based account creation → chain switching → keypair revelation → address verification.

- [ ] **Step 1: Write integration test**

In `background/src/bg_wallet.rs` tests module, add:

```rust
#[tokio::test]
async fn test_path_based_account_creation() {
    let (mut bg, _dir) = setup_test_background();
    let password: SecretString = SecretString::new(TEST_PASSWORD.into());
    let btc = test_data::gen_btc_testnet_conf();
    let eth = test_data::gen_anvil_net_conf();

    bg.add_provider(btc.clone()).unwrap();
    bg.add_provider(eth.clone()).unwrap();

    let words = Background::gen_bip39(24).unwrap();
    let accounts = [
        ("m/86'/0'/0'/0/0", "BTC Account 0".to_string()),
        ("m/86'/0'/0'/0/1", "BTC Account 1".to_string()),
    ];

    bg.add_bip39_wallet(BackgroundBip39Params {
        password: &password,
        mnemonic_check: true,
        chain_hash: btc.hash(),
        mnemonic_str: &words,
        accounts: &accounts,
        wallet_settings: Default::default(),
        passphrase: "",
        wallet_name: "Path Wallet".to_string(),
        biometric_type: Default::default(),
        ftokens: vec![],
    })
    .await
    .unwrap();

    let wallet = bg.get_wallet_by_index(0).unwrap();
    let data = wallet.get_wallet_data().unwrap();

    assert_eq!(data.bip, DerivationPath::BIP86_PURPOSE);
    let btc_accounts = data.get_accounts().unwrap();
    assert_eq!(btc_accounts.len(), 2);
    assert_eq!(btc_accounts[0].name, "BTC Account 0");
    assert_eq!(btc_accounts[1].name, "BTC Account 1");

    for account in btc_accounts {
        let addr_str = account.addr.auto_format();
        assert!(
            addr_str.starts_with("tb1p") || addr_str.starts_with("bc1p"),
            "Expected Taproot address, got {}",
            addr_str
        );
    }

    bg.select_accounts_chain(0, eth.hash(), Some(&password))
        .await
        .unwrap();

    let data = wallet.get_wallet_data().unwrap();
    let eth_accounts = data.get_accounts().unwrap();
    assert_eq!(eth_accounts.len(), 2);
    assert_eq!(eth_accounts[0].name, "BTC Account 0");
    assert_eq!(eth_accounts[1].name, "BTC Account 1");
}
```

- [ ] **Step 2: Run the integration test**

Run: `cargo test -p background -- test_path_based_account_creation`
Expected: PASS

- [ ] **Step 3: Run full test suite**

Run: `cargo test`
Expected: All pass

- [ ] **Step 4: Commit**

```bash
git add background/src/bg_wallet.rs
git commit -m "test(background): add integration test for path-based account creation"
```

---

### Task 9: Update `BackgroundLedgerParams` and `BackgroundSKParams` (optional cleanup)

**Files:**
- Modify: `background/src/lib.rs` (optional)

The `bip` field can also be removed from `BackgroundSKParams` since it can be derived from the chain config. However, this is a separate concern and can be done in a follow-up.

- [ ] **Step 1: Decide if needed**

This task is optional and can be deferred. The `bip` field on `BackgroundSKParams` and `BackgroundLedgerParams` still makes sense since these wallet types don't use path-based account specification.

---

## Summary of Changes

| Component | Change | Backward Compatible |
|-----------|--------|-------------------|
| `BackgroundBip39Params.accounts` | `[(usize, String)]` → `[(&str, String)]` | No (API change) |
| `BackgroundBip39Params.bip` | Removed | No (API change) |
| `AccountV2.derivation` | New `Option<DerivationInfo>` field | Yes (`#[serde(default)]`) |
| `DerivationPath` | New `default_derivation()` method | Yes (additive) |
| `from_bip39_words` | Uses `default_derivation` | Yes (same output for non-Solana) |
| `ensure_chain_accounts` | Uses `default_derivation` | Yes (same output for non-Solana) |
| `reveal_keypair` | Uses `DerivationInfo` | Yes (same behavior when `None`) |

## Key Design Decisions

1. **Path strings in background layer only**: `BackgroundBip39Params` uses path strings. `Bip39Params` (wallet layer) still uses `(usize, String)` indexes. Background parses paths → extracts indexes → passes to wallet.

2. **Cross-chain auto-derivation preserved**: Parsing paths extracts HD indexes, then `from_bip39_words` derives for ALL configured chains at those indexes.

3. **`DerivationInfo` is optional**: Only stores non-default account/change values. For standard `AddressIndex(0, 0, index)` paths, it's `None`. Private key and Ledger accounts always have `None`.

4. **Address verification**: In `reveal_keypair`, the derived keypair's address should match `account.addr` — existing address-matching assertions in tests serve this purpose.

5. **Solana fix**: `default_derivation(SOLANA, idx)` returns `Account(idx)` instead of `AddressIndex(0, 0, idx)`, producing correct Solana paths `m/44'/501'/idx'`.
