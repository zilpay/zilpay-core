use crate::{bg_provider::ProvidersManagement, bg_wallet::WalletManagement, Background, Result};
use alloy::{primitives::U256, rpc::types::TransactionInput};
use async_trait::async_trait;
use errors::{background::BackgroundError, wallet::WalletErrors};
use network::evm::generate_erc20_transfer_data;
use proto::{
    address::Address,
    tx::{ETHTransactionRequest, TransactionMetadata, TransactionRequest},
    zil_tx::ZILTransactionRequest,
};
use serde_json::json;
use token::ft::FToken;
use wallet::{account::Account, wallet_storage::StorageOperations};

#[async_trait]
pub trait TokensManagement {
    type Error;

    async fn fetch_ftoken_meta(
        &self,
        wallet_index: usize,
        contract: Address,
    ) -> std::result::Result<FToken, Self::Error>;

    async fn sync_ftokens_balances(
        &self,
        wallet_index: usize,
    ) -> std::result::Result<(), Self::Error>;

    async fn build_token_transfer(
        &self,
        token: &FToken,
        from: &Account,
        to: Address,
        amount: U256,
    ) -> std::result::Result<TransactionRequest, Self::Error>;
}

#[async_trait]
impl TokensManagement for Background {
    type Error = BackgroundError;

    async fn build_token_transfer(
        &self,
        token: &FToken,
        sender: &Account,
        to: Address,
        amount: U256,
    ) -> Result<TransactionRequest> {
        let erc20_payment = || ETHTransactionRequest {
            to: Some(to.to_alloy_addr().into()),
            value: Some(amount),
            nonce: Some(0),
            gas: Some(21000),
            from: Some(sender.addr.to_alloy_addr()),
            chain_id: Some(sender.chain_id),
            ..Default::default()
        };
        let erc20_transfer = || -> Result<ETHTransactionRequest> {
            let transfer_data = generate_erc20_transfer_data(&to, amount)?;
            let token_transfer_request = ETHTransactionRequest {
                from: Some(sender.addr.to_alloy_addr().into()),
                to: Some(token.addr.to_alloy_addr().into()),
                value: Some(U256::ZERO),
                nonce: Some(0),
                gas: Some(549755),
                chain_id: Some(sender.chain_id),
                input: TransactionInput::new(transfer_data.into()),
                ..Default::default()
            };

            Ok(token_transfer_request)
        };
        let metadata = TransactionMetadata {
            chain_hash: sender.chain_hash,
            hash: None,
            info: None,
            icon: None,
            title: None,
            signer: Some(sender.pub_key.clone()),
            token_info: Some((amount, token.decimals, token.symbol.clone())),
            btc_utxo_amounts: None,
        };
        let addr = if token.native {
            &sender.addr
        } else {
            &token.addr
        };

        match addr {
            Address::Secp256k1Bitcoin(_) => {
                if !token.native {
                    return Err(BackgroundError::TokenError(
                        errors::token::TokenError::ABIError(
                            "BTC tokens not supported yet".to_string(),
                        ),
                    ));
                }

                let amount_sat = amount.to::<u64>();
                let provider = self.get_provider(sender.chain_hash)?;

                let (tx, utxo_amounts) = crate::bg_tx::build_unsigned_btc_transaction(
                    &provider,
                    &sender.addr,
                    vec![(to, amount_sat)],
                    None,
                )
                .await?;

                let metadata = TransactionMetadata {
                    chain_hash: sender.chain_hash,
                    hash: None,
                    info: None,
                    icon: None,
                    title: None,
                    signer: Some(sender.pub_key.clone()),
                    token_info: Some((amount, token.decimals, token.symbol.clone())),
                    btc_utxo_amounts: Some(utxo_amounts),
                };

                let txn = TransactionRequest::Bitcoin((tx, metadata));

                Ok(txn)
            }
            Address::Secp256k1Keccak256(_) => {
                let transfer_request = if token.native {
                    erc20_payment()
                } else {
                    erc20_transfer()?
                };

                let txn = TransactionRequest::Ethereum((transfer_request, metadata));

                Ok(txn)
            }
            Address::Secp256k1Sha256(_) => {
                let transfer_request = if token.native {
                    ZILTransactionRequest {
                        nonce: 0,
                        chain_id: sender.chain_id as u16,
                        gas_price: 2000000000,
                        gas_limit: 50,
                        to_addr: to,
                        amount: amount.to::<u128>(),
                        code: Vec::with_capacity(0),
                        data: Vec::with_capacity(0),
                    }
                } else {
                    let base_16_to = to.get_zil_check_sum_addr()?.to_lowercase();
                    let payload = json!({
                        "_tag": "Transfer",
                        "params": [
                            { "vname": "to", "type": "ByStr20", "value": base_16_to },
                            { "vname": "amount", "type": "Uint128", "value": amount.to_string() }
                        ]
                    })
                    .to_string();
                    ZILTransactionRequest {
                        nonce: 0,
                        chain_id: sender.chain_id as u16,
                        gas_price: 2000000000,
                        gas_limit: 5000,
                        to_addr: token.addr.clone(),
                        amount: 0,
                        code: Vec::with_capacity(0),
                        data: payload.as_bytes().to_vec(),
                    }
                };
                let txn = TransactionRequest::Zilliqa((transfer_request, metadata));

                Ok(txn)
            }
        }
    }

    async fn fetch_ftoken_meta(&self, wallet_index: usize, contract: Address) -> Result<FToken> {
        let w = self.get_wallet_by_index(wallet_index)?;
        let data = w.get_wallet_data()?;
        let accounts = data
            .accounts
            .iter()
            .map(|a| &a.addr)
            .collect::<Vec<&Address>>();
        let selected = &data.accounts[data.selected_account];
        let provider = self.get_provider(selected.chain_hash)?;
        let mut token_meta = provider.ftoken_meta(contract, &accounts).await?;

        if let Some(t) = w.get_ftokens()?.into_iter().next() {
            token_meta.logo = t.logo;
        }

        Ok(token_meta)
    }

    async fn sync_ftokens_balances(&self, wallet_index: usize) -> Result<()> {
        let w = self
            .wallets
            .get(wallet_index)
            .ok_or(BackgroundError::WalletNotExists(wallet_index))?;
        let mut ftokens = w.get_ftokens()?;
        let data = w.get_wallet_data()?;

        if ftokens.is_empty() {
            return Ok(());
        }

        let selected_account = data
            .accounts
            .get(data.selected_account)
            .ok_or(WalletErrors::FailToGetAccount(data.selected_account))?;
        let addresses: Vec<&Address> = data.accounts.iter().map(|a| &a.addr).collect();
        let provider = self.get_provider(selected_account.chain_hash)?;

        let matching_tokens: Vec<&mut FToken> = ftokens
            .iter_mut()
            .filter(|token| token.chain_hash == selected_account.chain_hash)
            .collect();

        provider
            .update_balances(matching_tokens, &addresses)
            .await?;

        w.save_ftokens(&ftokens)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests_background_tokens {
    use std::collections::HashMap;

    use super::*;
    use crate::{
        bg_crypto::CryptoOperations, bg_storage::StorageManagement, BackgroundBip39Params,
    };
    use config::address::ADDR_LEN;
    use crypto::slip44;
    use rand::Rng;
    use rpc::network_config::{ChainConfig, Explorer};
    use test_data::{
        gen_device_indicators, gen_eth_account, gen_zil_account, gen_zil_testnet_conf,
        TEST_PASSWORD,
    };
    use tokio;
    use wallet::wallet_token::TokenManagement;

    const USDT_TOKEN: &str = "0x55d398326f99059fF775485246999027B3197955";

    fn setup_test_background() -> (Background, String) {
        let mut rng = rand::thread_rng();
        let dir = format!("/tmp/{}", rng.gen::<usize>());
        let bg = Background::from_storage_path(&dir).unwrap();
        (bg, dir)
    }

    fn gen_bsc_mainnet_conf() -> ChainConfig {
        ChainConfig {
            ftokens: vec![],
            logo: String::new(),
            diff_block_time: 0,
            testnet: None,
            chain_ids: [56, 0],
            name: "Binance Smart Chain".to_string(),
            chain: "BSC".to_string(),
            short_name: String::new(),
            rpc: vec!["https://bsc-dataseed.binance.org".to_string()],
            features: vec![155, 1559],
            slip_44: slip44::ETHEREUM,
            ens: None,
            explorers: vec![Explorer {
                name: "BscScan".to_string(),
                url: "https://bscscan.com".to_string(),
                icon: None,
                standard: 3091,
            }],
            fallback_enabled: true,
        }
    }

    fn gen_bsc_mainnet_token(chain_hash: u64) -> FToken {
        FToken {
            rate: 0f64,
            chain_hash,
            default: true,
            name: "Binance Smart Chain".to_string(),
            symbol: "BSC".to_string(),
            decimals: 18,
            addr: Address::Secp256k1Keccak256([0u8; ADDR_LEN]),
            logo: None,
            balances: HashMap::new(),
            native: true,
        }
    }

    #[tokio::test]
    async fn test_fetch_ftoken_meta() {
        let (mut bg, _dir) = setup_test_background();

        let words = Background::gen_bip39(24).unwrap();
        let accounts = [gen_eth_account(0, "Bsc account 1")];
        let net_config = gen_bsc_mainnet_conf();
        let device_indicators = gen_device_indicators("apple");

        bg.add_provider(net_config.clone()).unwrap();
        bg.add_bip39_wallet(BackgroundBip39Params {
            password: TEST_PASSWORD,
            mnemonic_check: true,
            chain_hash: net_config.hash(),
            mnemonic_str: &words,
            accounts: &accounts,
            wallet_settings: Default::default(),
            passphrase: "",
            wallet_name: String::new(),
            biometric_type: Default::default(),
            device_indicators: &device_indicators,
            ftokens: vec![gen_bsc_mainnet_token(net_config.hash())],
        })
        .unwrap();
        let providers = bg.get_providers();

        assert_eq!(bg.wallets.len(), 1);
        assert_eq!(providers.len(), 1);
        assert_eq!(
            bg.wallets
                .first()
                .unwrap()
                .get_wallet_data()
                .unwrap()
                .accounts
                .len(),
            1
        );

        let token_addr = Address::from_eth_address(USDT_TOKEN).unwrap();
        let meta = bg.fetch_ftoken_meta(0, token_addr).await.unwrap();

        assert_eq!(&meta.name, "Tether USD");
        assert_eq!(&meta.symbol, "USDT");
        assert_eq!(meta.decimals, 18u8);
        assert_eq!(meta.chain_hash, net_config.hash());
        assert!(!meta.default);
        assert!(!meta.native);

        assert!(meta.balances.contains_key(&0));
        assert_eq!(meta.balances.get(&0).unwrap().to::<usize>(), 0);

        bg.wallets.first_mut().unwrap().add_ftoken(meta).unwrap();

        let tokens = bg.wallets.first().unwrap().get_ftokens().unwrap();

        assert!(tokens[0].native);
        assert!(tokens[0].default);
        assert_eq!(tokens[0].chain_hash, net_config.hash());
    }

    #[tokio::test]
    async fn test_sync_ft_balances() {
        let (mut bg, _dir) = setup_test_background();

        let words = Background::gen_bip39(24).unwrap();
        let accounts = [
            gen_eth_account(0, "account 0"),
            gen_eth_account(1, "account 1"),
            gen_eth_account(2, "account 2"),
            gen_eth_account(3, "account 3"),
            gen_eth_account(4, "account 4"),
            gen_eth_account(5, "account 5"),
            gen_eth_account(6, "account 6"),
        ];
        let net_config = gen_bsc_mainnet_conf();
        let device_indicators = gen_device_indicators("test");

        bg.add_provider(net_config.clone()).unwrap();
        bg.add_bip39_wallet(BackgroundBip39Params {
            mnemonic_check: true,
            password: TEST_PASSWORD,
            chain_hash: net_config.hash(),
            mnemonic_str: &words,
            accounts: &accounts,
            wallet_settings: Default::default(),
            passphrase: "",
            wallet_name: String::new(),
            biometric_type: Default::default(),
            device_indicators: &device_indicators,
            ftokens: vec![gen_bsc_mainnet_token(net_config.hash())],
        })
        .unwrap();
        let providers = bg.get_providers();

        assert_eq!(bg.wallets.len(), 1);
        assert_eq!(providers.len(), 1);
        assert_eq!(
            bg.wallets
                .first()
                .unwrap()
                .get_wallet_data()
                .unwrap()
                .accounts
                .len(),
            7
        );

        let token_addr = Address::from_eth_address(USDT_TOKEN).unwrap();
        let meta = bg.fetch_ftoken_meta(0, token_addr).await.unwrap();

        bg.wallets.first_mut().unwrap().add_ftoken(meta).unwrap();
        bg.sync_ftokens_balances(0).await.unwrap();

        let ftokens = bg.wallets[0].get_ftokens().unwrap();

        for token in ftokens {
            assert!(token.balances.contains_key(&0));
            assert!(token.balances.contains_key(&1));
            assert!(token.balances.contains_key(&2));
            assert!(token.balances.contains_key(&3));
            assert!(token.balances.contains_key(&4));
            assert!(token.balances.contains_key(&5));
            assert!(token.balances.contains_key(&6));
        }
    }

    #[tokio::test]
    async fn test_build_token_transfer_zil() {
        let (mut bg, _dir) = setup_test_background();

        let words = Background::gen_bip39(24).unwrap();
        let accounts = [gen_zil_account(0, "Zil account 1")];
        let net_config = gen_zil_testnet_conf();
        let device_indicators = gen_device_indicators("apple");

        bg.add_provider(net_config.clone()).unwrap();

        let zlp_token = FToken::zlp(net_config.hash());

        bg.add_bip39_wallet(BackgroundBip39Params {
            password: TEST_PASSWORD,
            mnemonic_check: true,
            chain_hash: net_config.hash(),
            mnemonic_str: &words,
            accounts: &accounts,
            wallet_settings: Default::default(),
            passphrase: "",
            wallet_name: String::new(),
            biometric_type: Default::default(),
            device_indicators: &device_indicators,
            ftokens: vec![zlp_token.clone()],
        })
        .unwrap();

        let recipient = "0xEC6bB19886c9D5f5125DfC739362Bf54AA23d51F";
        let to_addr = Address::from_zil_base16(recipient).unwrap();
        let amount = U256::from(1000000000000u64);

        let wallet = bg.wallets.first().unwrap();
        let account = &wallet.get_wallet_data().unwrap().accounts[0];

        let txn_req = bg
            .build_token_transfer(&zlp_token, account, to_addr.clone(), amount)
            .await
            .unwrap();

        match txn_req {
            TransactionRequest::Zilliqa((req, _meta)) => {
                assert_eq!(req.to_addr, zlp_token.addr);
                assert_eq!(req.amount, 0);
                assert_eq!(req.gas_limit, 5000);

                let base_16_to = to_addr
                    .get_zil_check_sum_addr()
                    .unwrap_or_default()
                    .to_lowercase();
                let payload = json!({
                    "_tag": "Transfer",
                    "params": [
                        { "vname": "to", "type": "ByStr20", "value": base_16_to },
                        { "vname": "amount", "type": "Uint128", "value": amount.to_string() }
                    ]
                })
                .to_string();

                assert_eq!(req.data, payload.as_bytes().to_vec());
            }
            _ => panic!("Expected Zilliqa transaction request"),
        }
    }

    #[tokio::test]
    async fn test_build_token_transfer_btc() {
        use crate::{bg_tx::TransactionsManagement, bg_wallet::WalletManagement};
        use cipher::argon2;
        use crypto::bip49::DerivationPath;
        use crypto::slip44;
        use test_data::gen_btc_testnet_conf;
        use wallet::wallet_transaction::WalletTransaction;

        let (mut bg, _dir) = setup_test_background();
        let net_config = gen_btc_testnet_conf();

        bg.add_provider(net_config.clone()).unwrap();

        // Create Native SegWit Bech32 P2WPKH account (BIP84)
        let accounts = [(
            DerivationPath::new(
                slip44::BITCOIN,
                0,
                DerivationPath::BIP84_PURPOSE,
                Some(bitcoin::Network::Bitcoin),
            ),
            "BTC Acc 0".to_string(),
        )];
        let device_indicators = gen_device_indicators("btc_test");

        bg.add_bip39_wallet(BackgroundBip39Params {
            mnemonic_check: true,
            password: TEST_PASSWORD,
            chain_hash: net_config.hash(),
            mnemonic_str: test_data::ANVIL_MNEMONIC,
            accounts: &accounts,
            wallet_settings: Default::default(),
            passphrase: "",
            wallet_name: "BTC wallet".to_string(),
            biometric_type: Default::default(),
            device_indicators: &device_indicators,
            ftokens: vec![test_data::gen_btc_token()],
        })
        .unwrap();

        let wallet = bg.get_wallet_by_index(0).unwrap();
        bg.sync_ftokens_balances(0).await.unwrap();
        let data = wallet.get_wallet_data().unwrap();
        let account = data.accounts.first().unwrap();

        let addr_str = account.addr.auto_format();
        assert!(addr_str.starts_with("bc1q"));

        let btc_token = wallet.get_ftokens().unwrap();
        let btc_token = btc_token.first().unwrap();
        assert!(btc_token.native);
        let dest_addr = account.addr.clone();
        let amount = U256::from(1000u64); // 1000 satoshis

        // Build Bitcoin token transfer
        let txn_req = bg
            .build_token_transfer(btc_token, account, dest_addr.clone(), amount)
            .await
            .unwrap();

        // Verify it's a Bitcoin transaction request
        match &txn_req {
            TransactionRequest::Bitcoin((tx, meta)) => {
                // Verify transaction has inputs (UTXOs)
                assert!(tx.input.len() > 0, "Should have at least one input");

                // Verify transaction has outputs (destination + potentially change)
                assert!(tx.output.len() > 0, "Should have at least one output");

                // Verify metadata
                assert_eq!(meta.chain_hash, net_config.hash());
                assert!(meta.btc_utxo_amounts.is_some());
                assert_eq!(
                    meta.token_info,
                    Some((amount, btc_token.decimals, btc_token.symbol.clone()))
                );

                // Verify the first output is the destination with correct amount
                let first_output = &tx.output[0];
                assert_eq!(first_output.value.to_sat(), 1000u64);
            }
            _ => panic!("Expected Bitcoin transaction request"),
        }

        // Now test signing and broadcasting the transaction
        let device_indicator = device_indicators.join(":");
        let argon_seed = argon2::derive_key(
            TEST_PASSWORD.as_bytes(),
            &device_indicator,
            &data.settings.argon_params.into_config(),
        )
        .unwrap();

        // Sign the transaction
        let signed_tx = wallet
            .sign_transaction(txn_req, 0, &argon_seed, None)
            .await
            .unwrap();

        // Verify the signature
        assert!(signed_tx.verify().unwrap());

        // Broadcast the signed transaction
        let txns = vec![signed_tx];
        let broadcasted_txns = bg.broadcast_signed_transactions(0, 0, txns).await.unwrap();

        // Verify we got a transaction back with a hash
        assert_eq!(broadcasted_txns.len(), 1);
        let tx_hash = broadcasted_txns[0].metadata.hash.clone().unwrap();
        println!("Transaction broadcasted with hash: {}", tx_hash);

        // Check that transaction is in history
        let wallet_check = bg.get_wallet_by_index(0).unwrap();
        let history_check = wallet_check.get_history().unwrap();
        assert_eq!(history_check.len(), 1);
        println!("History length after broadcast: {}", history_check.len());
    }

    #[tokio::test]
    async fn test_build_token_transfer_btc_max_amount() {
        use crate::{bg_tx::TransactionsManagement, bg_wallet::WalletManagement};
        use cipher::argon2;
        use crypto::bip49::DerivationPath;
        use crypto::slip44;
        use network::btc::BtcOperations;
        use test_data::{gen_btc_testnet_conf, ANVIL_MNEMONIC};
        use wallet::wallet_transaction::WalletTransaction;

        let (mut bg, _dir) = setup_test_background();
        let net_config = gen_btc_testnet_conf();

        bg.add_provider(net_config.clone()).unwrap();

        let accounts = [
            (
                DerivationPath::new(
                    slip44::BITCOIN,
                    2,
                    DerivationPath::BIP84_PURPOSE,
                    Some(bitcoin::Network::Bitcoin),
                ),
                "BTC SegWit Acc 2".to_string(),
            ),
            (
                DerivationPath::new(
                    slip44::BITCOIN,
                    3,
                    DerivationPath::BIP84_PURPOSE,
                    Some(bitcoin::Network::Bitcoin),
                ),
                "BTC SegWit Acc 3".to_string(),
            ),
        ];
        let device_indicators = gen_device_indicators("btc_max_test");

        bg.add_bip39_wallet(BackgroundBip39Params {
            mnemonic_check: true,
            password: TEST_PASSWORD,
            chain_hash: net_config.hash(),
            mnemonic_str: ANVIL_MNEMONIC,
            accounts: &accounts,
            wallet_settings: Default::default(),
            passphrase: "",
            wallet_name: "BTC Max wallet".to_string(),
            biometric_type: Default::default(),
            device_indicators: &device_indicators,
            ftokens: vec![test_data::gen_btc_token()],
        })
        .unwrap();

        let wallet = bg.get_wallet_by_index(0).unwrap();
        let data = wallet.get_wallet_data().unwrap();

        assert_eq!(data.accounts.len(), 2, "Should have 2 accounts");

        let account = &data.accounts[0];
        let account_1 = &data.accounts[1];

        let addr_str = account.addr.auto_format();
        let addr_str_1 = account_1.addr.auto_format();

        assert!(
            addr_str.starts_with("bc1q"),
            "Should be SegWit address starting with bc1q, got: {}",
            addr_str
        );
        assert_eq!(
            addr_str, "bc1qt3az9lwpqfvr466mezsewuzdc4d379ldv83d4c",
            "Account 2 should match expected SegWit address"
        );
        assert_eq!(
            addr_str_1, "bc1qcqp7wgm6ke7zvwqnyy5a52ratfuhufw0zhpmxg",
            "Account 3 should match expected SegWit address"
        );

        bg.sync_ftokens_balances(0).await.unwrap();

        let wallet = bg.get_wallet_by_index(0).unwrap();
        let ftokens = wallet.get_ftokens().unwrap();
        let btc_token = ftokens.first().unwrap();

        assert!(btc_token.native, "BTC token should be native");
        assert_eq!(btc_token.symbol, "BTC", "Token symbol should be BTC");

        let balance_0 = btc_token.balances.get(&0).copied().unwrap_or(U256::ZERO);
        let balance_1 = btc_token.balances.get(&1).copied().unwrap_or(U256::ZERO);

        let provider = bg.get_provider(net_config.hash()).unwrap();

        let (from_account, from_index, to_account) = if balance_0 > U256::ZERO {
            let unspents = provider.btc_list_unspent(&account.addr).await.unwrap();
            if !unspents.is_empty() {
                (account, 0usize, account_1)
            } else if balance_1 > U256::ZERO {
                let unspents_1 = provider.btc_list_unspent(&account_1.addr).await.unwrap();
                if !unspents_1.is_empty() {
                    (account_1, 1usize, account)
                } else {
                    println!("No UTXOs available for either account, skipping test");
                    return;
                }
            } else {
                println!("No balance available in either account, skipping test");
                return;
            }
        } else if balance_1 > U256::ZERO {
            let unspents_1 = provider.btc_list_unspent(&account_1.addr).await.unwrap();
            if !unspents_1.is_empty() {
                (account_1, 1usize, account)
            } else {
                println!("No UTXOs available, skipping test");
                return;
            }
        } else {
            println!("No balance available in either account, skipping test");
            return;
        };

        let unspents = provider.btc_list_unspent(&from_account.addr).await.unwrap();
        let actual_balance: u64 = unspents.iter().map(|u| u.value).sum();
        let max_balance = U256::from(actual_balance);

        println!("Sending from account {}, balance: {} satoshis", from_index, actual_balance);

        let dest_addr = to_account.addr.clone();

        let txn_req = bg
            .build_token_transfer(btc_token, from_account, dest_addr.clone(), max_balance)
            .await
            .unwrap();

        match &txn_req {
            TransactionRequest::Bitcoin((tx, meta)) => {
                assert!(tx.input.len() > 0, "Should have at least one input");
                assert!(tx.output.len() > 0, "Should have at least one output");
                assert_eq!(meta.chain_hash, net_config.hash());
                assert!(meta.btc_utxo_amounts.is_some());
                assert_eq!(
                    meta.token_info,
                    Some((max_balance, btc_token.decimals, btc_token.symbol.clone()))
                );

                let total_output: u64 = tx.output.iter().map(|o| o.value.to_sat()).sum();
                let total_input: u64 = meta.btc_utxo_amounts.as_ref().unwrap().iter().sum();
                let fee = total_input.saturating_sub(total_output);

                println!("Total input: {} satoshis", total_input);
                println!("Total output: {} satoshis", total_output);
                println!("Fee: {} satoshis", fee);

                assert!(
                    total_output < total_input,
                    "Output should be less than input to account for fees"
                );
                assert!(
                    fee > 0,
                    "Fee should be greater than zero"
                );
                assert!(
                    total_output <= max_balance.to::<u64>(),
                    "Output should not exceed requested max balance"
                );
            }
            _ => panic!("Expected Bitcoin transaction request"),
        }

        let device_indicator = device_indicators.join(":");
        let argon_seed = argon2::derive_key(
            TEST_PASSWORD.as_bytes(),
            &device_indicator,
            &data.settings.argon_params.into_config(),
        )
        .unwrap();

        let signed_tx = wallet
            .sign_transaction(txn_req, from_index, &argon_seed, None)
            .await
            .unwrap();

        assert!(signed_tx.verify().unwrap(), "Signed transaction should be valid");

        let txns = vec![signed_tx];
        let broadcasted_txns = bg.broadcast_signed_transactions(0, from_index, txns).await.unwrap();

        assert_eq!(broadcasted_txns.len(), 1);
        let tx_hash = broadcasted_txns[0].metadata.hash.clone().unwrap();
        println!("Max amount transaction broadcasted with hash: {}", tx_hash);

        let wallet_check = bg.get_wallet_by_index(0).unwrap();
        let history_check = wallet_check.get_history().unwrap();
        assert!(
            history_check.len() > 0,
            "Transaction should be in history"
        );
    }
}
