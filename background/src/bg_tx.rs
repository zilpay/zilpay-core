use crate::{bg_provider::ProvidersManagement, bg_wallet::WalletManagement, Result};
use alloy::primitives::U256;
use alloy::{dyn_abi::TypedData, primitives::keccak256};
use async_trait::async_trait;
use cipher::argon2::Argon2Seed;
use config::sha::SHA256_SIZE;
use errors::{background::BackgroundError, tx::TransactionErrors, wallet::WalletErrors};
use history::{status::TransactionStatus, transaction::HistoricalTransaction};
use network::{btc::BtcOperations, evm::RequiredTxParams};
use proto::{
    address::Address,
    pubkey::PubKey,
    signature::Signature,
    tx::{TransactionReceipt, TransactionRequest},
};
use sha2::{Digest, Sha256};
use wallet::{wallet_crypto::WalletCrypto, wallet_storage::StorageOperations};

use crate::Background;

pub(crate) async fn build_unsigned_btc_transaction(
    provider: &network::provider::NetworkProvider,
    from_addr: &Address,
    destinations: Vec<(Address, u64)>,
    fee_rate_sat_per_vbyte: Option<u64>,
) -> std::result::Result<(bitcoin::Transaction, Vec<u64>), BackgroundError> {
    use bitcoin::{
        absolute::LockTime, transaction::Version, Amount, OutPoint, ScriptBuf, Sequence,
        Transaction, TxIn, TxOut, Witness,
    };

    let unspents = provider.btc_list_unspent(from_addr).await?;

    if unspents.is_empty() {
        return Err(BackgroundError::BincodeError(
            "No UTXOs available for this address".to_string(),
        ));
    }

    let total_output: u64 = destinations.iter().map(|(_, amount)| amount).sum();
    let estimated_vsize = (unspents.len() * 148 + destinations.len() * 34 + 10) as u64;
    let fee_rate = fee_rate_sat_per_vbyte.unwrap_or(10);
    let estimated_fee = estimated_vsize * fee_rate;
    let total_input: u64 = unspents.iter().map(|u| u.value).sum();

    if total_input < total_output + estimated_fee {
        return Err(BackgroundError::BincodeError(format!(
            "Insufficient funds: have {}, need {} (output: {}, fee: {})",
            total_input,
            total_output + estimated_fee,
            total_output,
            estimated_fee
        )));
    }

    let mut inputs = Vec::new();
    for unspent in &unspents {
        inputs.push(TxIn {
            previous_output: OutPoint {
                txid: unspent.tx_hash,
                vout: unspent.tx_pos as u32,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        });
    }

    let mut outputs = Vec::new();
    for (dest_addr, amount) in destinations {
        let btc_addr = dest_addr
            .to_bitcoin_addr()
            .map_err(|e| BackgroundError::BincodeError(e.to_string()))?;
        outputs.push(TxOut {
            value: Amount::from_sat(amount),
            script_pubkey: btc_addr.script_pubkey(),
        });
    }

    let change = total_input - total_output - estimated_fee;
    if change > 546 {
        let change_addr = from_addr
            .to_bitcoin_addr()
            .map_err(|e| BackgroundError::BincodeError(e.to_string()))?;
        outputs.push(TxOut {
            value: Amount::from_sat(change),
            script_pubkey: change_addr.script_pubkey(),
        });
    }

    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: inputs,
        output: outputs,
    };

    let utxo_amounts: Vec<u64> = unspents.iter().map(|u| u.value).collect();

    Ok((tx, utxo_amounts))
}

pub fn update_tx_from_params(
    tx: &mut TransactionRequest,
    params: RequiredTxParams,
) -> std::result::Result<(), TransactionErrors> {
    match tx {
        TransactionRequest::Zilliqa((ref mut zil_tx, _metadata)) => {
            zil_tx.nonce = params.nonce + 1;
            zil_tx.gas_price = params
                .gas_price
                .try_into()
                .map_err(|_| TransactionErrors::ConvertTxError("Gas price overflow".to_string()))?;
            zil_tx.gas_limit = params
                .tx_estimate_gas
                .try_into()
                .map_err(|_| TransactionErrors::ConvertTxError("Gas limit overflow".to_string()))?;
        }
        TransactionRequest::Ethereum((ref mut eth_tx, _metadata)) => {
            eth_tx.nonce = Some(params.nonce);
            eth_tx.gas = Some(params.tx_estimate_gas.try_into().map_err(|_| {
                TransactionErrors::ConvertTxError("Gas limit overflow".to_string())
            })?);

            let is_eip1559_supported = params.fee_history.base_fee > U256::ZERO;

            if is_eip1559_supported {
                eth_tx.max_priority_fee_per_gas =
                    Some(params.fee_history.priority_fee.try_into().map_err(|_| {
                        TransactionErrors::ConvertTxError("Priority fee overflow".to_string())
                    })?);

                eth_tx.max_fee_per_gas =
                    Some(params.fee_history.max_fee.try_into().map_err(|_| {
                        TransactionErrors::ConvertTxError("Max fee overflow".to_string())
                    })?);

                eth_tx.gas_price = None;
            } else {
                eth_tx.gas_price = Some(params.gas_price.try_into().map_err(|_| {
                    TransactionErrors::ConvertTxError("Gas price overflow".to_string())
                })?);

                eth_tx.max_fee_per_gas = None;
                eth_tx.max_priority_fee_per_gas = None;
            }
        }
        TransactionRequest::Bitcoin((ref mut btc_tx, ref metadata)) => {
            if params.current == 0 {
                return Ok(());
            }

            let fee_rate_sat_per_vbyte = params.current;
            let estimated_vsize = (btc_tx.input.len() * 148 + btc_tx.output.len() * 34 + 10) as u64;
            let new_fee = estimated_vsize * fee_rate_sat_per_vbyte;

            let total_input: u64 = metadata.btc_utxo_amounts
                .as_ref()
                .ok_or(TransactionErrors::ConvertTxError("Missing UTXO amounts".to_string()))?
                .iter()
                .sum();

            let output_count = btc_tx.output.len();
            if output_count == 0 {
                return Err(TransactionErrors::ConvertTxError("No outputs in transaction".to_string()))?;
            }

            let mut total_output: u64 = 0;
            for i in 0..output_count.saturating_sub(1) {
                total_output += btc_tx.output[i].value.to_sat();
            }

            let new_change = total_input.saturating_sub(total_output).saturating_sub(new_fee);

            if new_change >= 546 {
                btc_tx.output[output_count - 1].value = bitcoin::Amount::from_sat(new_change);
            } else if output_count > 1 {
                btc_tx.output.pop();
            } else {
                return Err(TransactionErrors::ConvertTxError("Insufficient funds for fee increase".to_string()))?;
            }
        }
    }

    Ok(())
}

#[async_trait]
pub trait TransactionsManagement {
    type Error;

    async fn broadcast_signed_transactions<'a>(
        &self,
        wallet_index: usize,
        account_index: usize,
        txns: Vec<TransactionReceipt>,
    ) -> std::result::Result<Vec<HistoricalTransaction>, Self::Error>;

    async fn check_pending_txns(
        &self,
        wallet_index: usize,
    ) -> std::result::Result<Vec<HistoricalTransaction>, Self::Error>;

    fn sign_message(
        &self,
        wallet_index: usize,
        account_index: usize,
        seed_bytes: &Argon2Seed,
        passphrase: Option<&str>,
        message: &str,
        title: Option<String>,
        icon: Option<String>,
    ) -> std::result::Result<(PubKey, Signature), Self::Error>;

    fn prepare_message(
        &self,
        wallet_index: usize,
        account_index: usize,
        message: &str,
    ) -> std::result::Result<[u8; SHA256_SIZE], Self::Error>;

    fn prepare_eip712_message(
        &self,
        typed_data_json: String,
    ) -> std::result::Result<TypedData, Self::Error>;

    async fn sign_typed_data_eip712(
        &self,
        wallet_index: usize,
        account_index: usize,
        seed_bytes: &Argon2Seed,
        passphrase: Option<&str>,
        message: &str,
        title: Option<String>,
        icon: Option<String>,
    ) -> std::result::Result<(PubKey, Signature), Self::Error>;

    async fn prepare_and_sign_btc_transaction(
        &self,
        wallet_index: usize,
        account_index: usize,
        seed_bytes: &Argon2Seed,
        passphrase: Option<&str>,
        destinations: Vec<(Address, u64)>,
        fee_rate_sat_per_vbyte: Option<u64>,
    ) -> std::result::Result<TransactionReceipt, Self::Error>;
}

#[async_trait]
impl TransactionsManagement for Background {
    type Error = BackgroundError;

    fn prepare_message(
        &self,
        wallet_index: usize,
        account_index: usize,
        message: &str,
    ) -> Result<[u8; SHA256_SIZE]> {
        let wallet = self.get_wallet_by_index(wallet_index)?;
        let wallet_data = wallet.get_wallet_data()?;
        let account = wallet_data
            .accounts
            .get(account_index)
            .ok_or(WalletErrors::InvalidAccountIndex(account_index))?;

        match account.addr {
            Address::Secp256k1Bitcoin(_) => {
                return Err(BackgroundError::BincodeError(
                    "BTC not impl yet".to_string(),
                ));
            }
            Address::Secp256k1Sha256(_) => {
                let mut hasher = Sha256::new();
                hasher.update(message.as_bytes());
                let hash = hasher.finalize();

                Ok(hash.into())
            }
            Address::Secp256k1Keccak256(_) => {
                let prefix = format!("\x19Ethereum Signed Message:\n{}", message.len());
                let full_message = format!("{}{}", prefix, message);
                let hash = keccak256(full_message.as_bytes());

                Ok(hash.0)
            }
        }
    }

    fn prepare_eip712_message(&self, typed_data_json: String) -> Result<TypedData> {
        let typed_data: TypedData = serde_json::from_str(&typed_data_json)
            .map_err(|e| BackgroundError::FailDeserializeTypedData(e.to_string()))?;

        Ok(typed_data)
    }

    async fn sign_typed_data_eip712(
        &self,
        wallet_index: usize,
        account_index: usize,
        seed_bytes: &Argon2Seed,
        passphrase: Option<&str>,
        typed_data_json: &str,
        title: Option<String>,
        icon: Option<String>,
    ) -> Result<(PubKey, Signature)> {
        let wallet = self.get_wallet_by_index(wallet_index)?;
        let data = wallet.get_wallet_data()?;
        let account = data
            .accounts
            .get(account_index)
            .ok_or(WalletErrors::InvalidAccountIndex(account_index))?;
        let key_pair = wallet.reveal_keypair(account_index, seed_bytes, passphrase)?;
        let typed_data: TypedData = serde_json::from_str(&typed_data_json.to_string())
            .map_err(|e| BackgroundError::FailDeserializeTypedData(e.to_string()))?;
        let signature = key_pair.sign_typed_data_eip712(typed_data).await?;
        let pub_key = key_pair.get_pubkey()?;

        let history_entry = HistoricalTransaction::from_signed_typed_data(
            typed_data_json,
            &signature.to_hex_prefixed(),
            &pub_key.as_hex_str(),
            &account.addr.auto_format(),
            title,
            icon,
            account.chain_hash,
        );
        wallet.add_history(&[history_entry])?;

        Ok((pub_key, signature))
    }

    fn sign_message(
        &self,
        wallet_index: usize,
        account_index: usize,
        seed_bytes: &Argon2Seed,
        passphrase: Option<&str>,
        message: &str,
        title: Option<String>,
        icon: Option<String>,
    ) -> Result<(PubKey, Signature)> {
        let wallet = self.get_wallet_by_index(wallet_index)?;
        let data = wallet.get_wallet_data()?;
        let account = data
            .accounts
            .get(account_index)
            .ok_or(WalletErrors::InvalidAccountIndex(account_index))?;

        let key_pair = wallet.reveal_keypair(account_index, seed_bytes, passphrase)?;
        let signature = match account.addr {
            Address::Secp256k1Bitcoin(_) => {
                return Err(BackgroundError::WalletError(
                    WalletErrors::InvalidHexToWalletType,
                ));
            }
            Address::Secp256k1Sha256(_) => {
                let mut hasher = Sha256::new();
                hasher.update(message.as_bytes());
                let hash = hasher.finalize();

                key_pair.sign_message(&hash)?
            }
            Address::Secp256k1Keccak256(_) => key_pair.sign_message(message.as_bytes())?,
        };
        let pub_key = key_pair.get_pubkey()?;

        let history_entry = HistoricalTransaction::from_signed_message(
            message,
            &signature.to_hex_prefixed(),
            &pub_key.as_hex_str(),
            &account.addr.auto_format(),
            title,
            icon,
            account.chain_hash,
        );
        wallet.add_history(&[history_entry])?;

        Ok((pub_key, signature))
    }

    async fn check_pending_txns(&self, wallet_index: usize) -> Result<Vec<HistoricalTransaction>> {
        let wallet = self.get_wallet_by_index(wallet_index)?;
        let data = wallet.get_wallet_data()?;
        let account = data.get_selected_account()?;
        let chain = self.get_provider(account.chain_hash)?;
        let mut history = wallet.get_history()?;

        let mut matching_transactions = Vec::with_capacity(history.len());

        for tx in history.iter_mut() {
            if tx.metadata.chain_hash == account.chain_hash
                && tx.status == TransactionStatus::Pending
            {
                matching_transactions.push(tx);
            }
        }

        if matching_transactions.is_empty() {
            return Ok(history);
        }

        chain
            .update_transactions_receipt(&mut matching_transactions)
            .await?;
        wallet.save_history(&history)?;

        Ok(history)
    }

    async fn broadcast_signed_transactions<'a>(
        &self,
        wallet_index: usize,
        account_index: usize,
        txns: Vec<TransactionReceipt>,
    ) -> Result<Vec<HistoricalTransaction>> {
        let wallet = self.get_wallet_by_index(wallet_index)?;
        let data = wallet.get_wallet_data()?;
        let selected_account =
            data.accounts
                .get(account_index)
                .ok_or(BackgroundError::WalletError(
                    errors::wallet::WalletErrors::NotExistsAccount(account_index),
                ))?;
        let provider = self.get_provider(selected_account.chain_hash)?;
        let txns = provider.broadcast_signed_transactions(txns).await?;
        let history = txns
            .into_iter()
            .map(|receipt| HistoricalTransaction::try_from(receipt))
            .collect::<std::result::Result<Vec<HistoricalTransaction>, TransactionErrors>>()?;

        wallet.add_history(&history)?;

        Ok(history)
    }

    async fn prepare_and_sign_btc_transaction(
        &self,
        wallet_index: usize,
        account_index: usize,
        seed_bytes: &Argon2Seed,
        passphrase: Option<&str>,
        destinations: Vec<(Address, u64)>,
        fee_rate_sat_per_vbyte: Option<u64>,
    ) -> Result<TransactionReceipt> {
        let wallet = self.get_wallet_by_index(wallet_index)?;
        let data = wallet.get_wallet_data()?;
        let account = data
            .accounts
            .get(account_index)
            .ok_or(WalletErrors::InvalidAccountIndex(account_index))?;

        let provider = self.get_provider(account.chain_hash)?;
        let keypair = wallet.reveal_keypair(account_index, seed_bytes, passphrase)?;

        let (tx, utxo_amounts) = build_unsigned_btc_transaction(
            &provider,
            &account.addr,
            destinations,
            fee_rate_sat_per_vbyte,
        )
        .await?;

        let metadata = proto::tx::TransactionMetadata {
            chain_hash: account.chain_hash,
            btc_utxo_amounts: Some(utxo_amounts),
            ..Default::default()
        };

        let tx_request = proto::tx::TransactionRequest::Bitcoin((tx, metadata));
        let signed_receipt = tx_request.sign(&keypair).await?;

        Ok(signed_receipt)
    }
}

#[cfg(test)]
mod tests_background_transactions {
    use super::*;
    use crate::{bg_storage::StorageManagement, bg_token::TokensManagement, BackgroundBip39Params};
    use alloy::{primitives::U256, rpc::types::TransactionRequest as ETHTransactionRequest};
    use cipher::argon2;
    use proto::{address::Address, tx::TransactionRequest, zil_tx::ZILTransactionRequest};
    use rand::Rng;
    use test_data::{
        gen_anvil_net_conf, gen_anvil_token, gen_device_indicators, gen_eth_account,
        gen_zil_account, gen_zil_testnet_conf, gen_zil_token, ANVIL_MNEMONIC, TEST_PASSWORD,
    };
    use token::ft::FToken;
    use tokio;
    use wallet::{wallet_crypto::WalletCrypto, wallet_transaction::WalletTransaction};

    fn setup_test_background() -> (Background, String) {
        let mut rng = rand::thread_rng();
        let dir = format!("/tmp/{}", rng.gen::<usize>());
        let bg = Background::from_storage_path(&dir).unwrap();
        (bg, dir)
    }

    #[tokio::test]
    async fn test_sign_and_send_zil_legacy_tx() {
        let (mut bg, _dir) = setup_test_background();
        let net_config = gen_zil_testnet_conf();

        bg.add_provider(net_config.clone()).unwrap();

        let accounts = [gen_zil_account(0, "ZIL Acc 0")];
        let device_indicators = gen_device_indicators("zil_test");

        bg.add_bip39_wallet(BackgroundBip39Params {
            mnemonic_check: true,
            password: TEST_PASSWORD,
            chain_hash: net_config.hash(),
            mnemonic_str: ANVIL_MNEMONIC,
            accounts: &accounts,
            wallet_settings: Default::default(),
            passphrase: "",
            wallet_name: String::new(),
            biometric_type: Default::default(),
            device_indicators: &device_indicators,
            ftokens: vec![FToken::zil(net_config.hash())],
        })
        .unwrap();

        bg.swap_zilliqa_chain(0, 0).unwrap();

        let providers = bg.get_providers();
        let provider = providers.first().unwrap();
        let wallet = bg.get_wallet_by_index(0).unwrap();
        let data = wallet.get_wallet_data().unwrap();
        let account = data.accounts.first().unwrap();

        let zil_tx = ZILTransactionRequest {
            nonce: 0,
            chain_id: provider.config.chain_id() as u16,
            gas_price: 2000000100,
            gas_limit: 1000,
            to_addr: Address::from_zil_bech32("zil1sctmwt3zpy8scyck0pj3glky3fkm0z8lxa4ga7")
                .unwrap(),
            amount: 1,
            code: Vec::with_capacity(0),
            data: Vec::with_capacity(0),
        };
        let tx_request = TransactionRequest::Zilliqa((zil_tx.clone(), Default::default()));

        let params = provider
            .estimate_params_batch(&tx_request, &account.addr, 1, None)
            .await
            .unwrap();
        let zil_tx = ZILTransactionRequest {
            nonce: params.nonce,
            chain_id: provider.config.chain_id() as u16,
            gas_price: 2000000100,
            gas_limit: 1000,
            to_addr: Address::from_zil_bech32("zil1sctmwt3zpy8scyck0pj3glky3fkm0z8lxa4ga7")
                .unwrap(),
            amount: 1,
            code: Vec::with_capacity(0),
            data: Vec::with_capacity(0),
        };
        let txn = TransactionRequest::Zilliqa((zil_tx, Default::default()));

        let device_indicator = device_indicators.join(":");
        let argon_seed = argon2::derive_key(
            TEST_PASSWORD.as_bytes(),
            &device_indicator,
            &data.settings.argon_params.into_config(),
        )
        .unwrap();

        let keypair = wallet.reveal_keypair(0, &argon_seed, None).unwrap();
        let txn = txn.sign(&keypair).await.unwrap();
        let txns = vec![txn];

        let txns = bg.broadcast_signed_transactions(0, 0, txns).await.unwrap();

        assert_eq!(txns.len(), 1);

        for tx in txns {
            assert!(tx.metadata.hash.is_some());
        }
    }

    #[tokio::test]
    async fn test_sign_and_verify_zil_swap_to_anvil() {
        let (mut bg, _dir) = setup_test_background();
        let zil_config = gen_zil_testnet_conf();
        let anvil_config = gen_anvil_net_conf();

        bg.add_provider(zil_config.clone()).unwrap();
        bg.add_provider(anvil_config.clone()).unwrap();

        let accounts = [gen_zil_account(0, "ZIL Acc 0")];
        let device_indicators = gen_device_indicators("zil_test");

        bg.add_bip39_wallet(BackgroundBip39Params {
            mnemonic_check: true,
            password: TEST_PASSWORD,
            chain_hash: zil_config.hash(),
            mnemonic_str: ANVIL_MNEMONIC,
            accounts: &accounts,
            wallet_settings: Default::default(),
            passphrase: "",
            wallet_name: String::new(),
            biometric_type: Default::default(),
            device_indicators: &device_indicators,
            ftokens: vec![FToken::zil(zil_config.hash())],
        })
        .unwrap();

        bg.swap_zilliqa_chain(0, 0).unwrap();
        let wallet = bg.get_wallet_by_index(0).unwrap();

        let recipient =
            Address::from_eth_address("0x246C5881E3F109B2aF170F5C773EF969d3da581B").unwrap();
        let token_transfer_request = ETHTransactionRequest {
            to: Some(recipient.to_alloy_addr().into()),
            value: Some(U256::ZERO),
            max_fee_per_gas: Some(2_000_000_000),
            max_priority_fee_per_gas: Some(1_000_000_000),
            nonce: Some(0),
            gas: Some(21000),
            chain_id: Some(anvil_config.chain_id()),
            ..Default::default()
        };
        let metadata = proto::tx::TransactionMetadata {
            chain_hash: anvil_config.hash(),
            ..Default::default()
        };
        let zilpay_trasnfer_req = TransactionRequest::Ethereum((token_transfer_request, metadata));

        let argon_seed = bg
            .unlock_wallet_with_password(&TEST_PASSWORD, &device_indicators, 0)
            .unwrap();

        bg.select_accounts_chain(0, anvil_config.hash()).unwrap();

        let data = wallet.get_wallet_data().unwrap();
        let selected_account = data.get_selected_account().unwrap();

        assert!(selected_account.addr.to_string().starts_with("0x"));

        if let PubKey::Secp256k1Keccak256(_pub_key) = selected_account.pub_key {
            // Valid Keccak256 public key
        } else {
            panic!("invalid pubkey");
        }

        let tx = wallet
            .sign_transaction(zilpay_trasnfer_req, 0, &argon_seed, None)
            .await
            .unwrap();

        assert!(tx.verify().unwrap());
    }

    #[tokio::test]
    async fn test_sign_and_send_evm_tx() {
        let (mut bg, _dir) = setup_test_background();
        let net_config = gen_anvil_net_conf();

        bg.add_provider(net_config.clone()).unwrap();
        let accounts = [gen_eth_account(0, "Anvil Acc 0")];
        let device_indicators = gen_device_indicators("testanvil");

        bg.add_bip39_wallet(BackgroundBip39Params {
            mnemonic_check: true,
            password: TEST_PASSWORD,
            chain_hash: net_config.hash(),
            mnemonic_str: ANVIL_MNEMONIC,
            accounts: &accounts,
            wallet_settings: Default::default(),
            passphrase: "",
            wallet_name: "Anvil wallet".to_string(),
            biometric_type: Default::default(),
            device_indicators: &device_indicators,
            ftokens: vec![gen_anvil_token()],
        })
        .unwrap();

        let providers = bg.get_providers();
        let provider = providers.first().unwrap();
        let wallet = bg.get_wallet_by_index(0).unwrap();
        let data = wallet.get_wallet_data().unwrap();

        let account = data.accounts.first().unwrap();
        assert_eq!(
            account.addr.to_string().to_lowercase(),
            "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"
        );

        let recipient =
            Address::from_eth_address("0x246C5881E3F109B2aF170F5C773EF969d3da581B").unwrap();
        let transfer_request = ETHTransactionRequest {
            to: Some(recipient.to_alloy_addr().into()),
            value: Some(U256::from(10u128)),
            nonce: None,
            gas: None,
            chain_id: Some(provider.config.chain_id()),
            ..Default::default()
        };
        let metadata = proto::tx::TransactionMetadata {
            chain_hash: net_config.hash(),
            ..Default::default()
        };
        let mut tx_request = TransactionRequest::Ethereum((transfer_request.clone(), metadata));

        let params = provider
            .estimate_params_batch(&tx_request, &account.addr, 1, None)
            .await
            .unwrap();

        // Use update_tx_from_params to set gas fields based on network capabilities
        super::update_tx_from_params(&mut tx_request, params).unwrap();
        let txn = tx_request;

        let device_indicator = device_indicators.join(":");
        let argon_seed = argon2::derive_key(
            TEST_PASSWORD.as_bytes(),
            &device_indicator,
            &data.settings.argon_params.into_config(),
        )
        .unwrap();

        let keypair = wallet.reveal_keypair(0, &argon_seed, None).unwrap();
        let txn = txn.sign(&keypair).await.unwrap();
        let txns = vec![txn];
        let txns = bg.broadcast_signed_transactions(0, 0, txns).await.unwrap();

        assert_eq!(txns.len(), 1);

        for tx in txns {
            assert!(tx.metadata.hash.is_some());
        }
    }

    #[tokio::test]
    async fn test_update_history_evm() {
        use test_data::anvil_accounts;
        use tokio::time::{sleep, Duration};

        let (mut bg, _dir) = setup_test_background();
        let net_config = gen_anvil_net_conf();
        let net_hash = net_config.hash();

        bg.add_provider(net_config.clone()).unwrap();

        let accounts = [gen_eth_account(0, "Anvil Acc 0")];
        let device_indicators = gen_device_indicators("testanvil");

        bg.add_bip39_wallet(BackgroundBip39Params {
            mnemonic_check: true,
            password: TEST_PASSWORD,
            chain_hash: net_hash,
            mnemonic_str: ANVIL_MNEMONIC,
            accounts: &accounts,
            wallet_settings: Default::default(),
            passphrase: "",
            wallet_name: "Anvil wallet".to_string(),
            biometric_type: Default::default(),
            device_indicators: &device_indicators,
            ftokens: vec![gen_anvil_token()],
        })
        .unwrap();

        let providers = bg.get_providers();
        let provider = providers.first().unwrap();
        let wallet = bg.get_wallet_by_index(0).unwrap();
        let data = wallet.get_wallet_data().unwrap();
        let account = data.accounts.first().unwrap();

        let recipient_0 = Address::from_eth_address(anvil_accounts::ACCOUNT_1).unwrap();
        let transfer_request_0 = ETHTransactionRequest {
            to: Some(recipient_0.to_alloy_addr().into()),
            value: Some(U256::from(100u128)),
            nonce: None,
            gas: None,
            chain_id: Some(provider.config.chain_id()),
            ..Default::default()
        };
        let metadata_0 = proto::tx::TransactionMetadata {
            chain_hash: net_hash,
            ..Default::default()
        };
        let mut tx_request_0 = TransactionRequest::Ethereum((transfer_request_0, metadata_0));

        let params_0 = provider
            .estimate_params_batch(&tx_request_0, &account.addr, 1, None)
            .await
            .unwrap();

        // Use update_tx_from_params to set gas fields based on network capabilities
        super::update_tx_from_params(&mut tx_request_0, params_0).unwrap();
        let txn_0 = tx_request_0;

        let device_indicator = device_indicators.join(":");
        let argon_seed = argon2::derive_key(
            TEST_PASSWORD.as_bytes(),
            &device_indicator,
            &data.settings.argon_params.into_config(),
        )
        .unwrap();

        let keypair = wallet.reveal_keypair(0, &argon_seed, None).unwrap();
        let txn_0 = txn_0.sign(&keypair).await.unwrap();
        let txns_0 = vec![txn_0];
        let txns_0 = bg
            .broadcast_signed_transactions(0, 0, txns_0)
            .await
            .unwrap();

        assert_eq!(txns_0.len(), 1);
        let tx_hash_0 = txns_0[0].metadata.hash.clone().unwrap();

        let wallet_check = bg.get_wallet_by_index(0).unwrap();
        let history_check = wallet_check.get_history().unwrap();
        assert_eq!(history_check.len(), 1);

        let recipient_1 = Address::from_eth_address(anvil_accounts::ACCOUNT_2).unwrap();
        let transfer_request_1 = ETHTransactionRequest {
            to: Some(recipient_1.to_alloy_addr().into()),
            value: Some(U256::from(200u128)),
            nonce: None,
            gas: None,
            chain_id: Some(provider.config.chain_id()),
            ..Default::default()
        };
        let metadata_1 = proto::tx::TransactionMetadata {
            chain_hash: net_hash,
            ..Default::default()
        };
        let mut tx_request_1 = TransactionRequest::Ethereum((transfer_request_1, metadata_1));

        let params_1 = provider
            .estimate_params_batch(&tx_request_1, &account.addr, 1, None)
            .await
            .unwrap();

        // Use update_tx_from_params to set gas fields based on network capabilities
        super::update_tx_from_params(&mut tx_request_1, params_1).unwrap();
        let txn_1 = tx_request_1;

        let keypair = wallet.reveal_keypair(0, &argon_seed, None).unwrap();
        let txn_1 = txn_1.sign(&keypair).await.unwrap();
        let txns_1 = vec![txn_1];
        let txns_1 = bg
            .broadcast_signed_transactions(0, 0, txns_1)
            .await
            .unwrap();

        assert_eq!(txns_1.len(), 1);
        let tx_hash_1 = txns_1[0].metadata.hash.clone().unwrap();

        sleep(Duration::from_secs(2)).await;

        bg.check_pending_txns(0).await.unwrap();

        let wallet = bg.get_wallet_by_index(0).unwrap();
        let history = wallet.get_history().unwrap();
        let filtered_history = history
            .into_iter()
            .filter(|t| t.metadata.chain_hash == net_hash)
            .collect::<Vec<HistoricalTransaction>>();

        assert_eq!(filtered_history.len(), 2);
        let hash_0 = filtered_history[0].metadata.hash.as_ref().unwrap();
        let hash_1 = filtered_history[1].metadata.hash.as_ref().unwrap();
        assert!(hash_0 == &tx_hash_0 || hash_1 == &tx_hash_0);
        assert!(hash_0 == &tx_hash_1 || hash_1 == &tx_hash_1);
        assert_eq!(filtered_history[0].status, TransactionStatus::Success);
        assert_eq!(filtered_history[1].status, TransactionStatus::Success);
    }

    #[tokio::test]
    async fn test_sign_message_legacy_zilliqa() {
        let (mut bg, _dir) = setup_test_background();
        let net_config = gen_zil_testnet_conf();

        bg.add_provider(net_config.clone()).unwrap();
        let accounts = [gen_zil_account(0, "ZIL Acc 0")];
        let device_indicators = gen_device_indicators("zil_test");

        bg.add_bip39_wallet(BackgroundBip39Params {
            mnemonic_check: true,
            password: TEST_PASSWORD,
            chain_hash: net_config.hash(),
            mnemonic_str: ANVIL_MNEMONIC,
            accounts: &accounts,
            wallet_settings: Default::default(),
            passphrase: "",
            wallet_name: "ZIL wallet".to_string(),
            biometric_type: Default::default(),
            device_indicators: &device_indicators,
            ftokens: vec![FToken::zil(net_config.hash())],
        })
        .unwrap();

        bg.swap_zilliqa_chain(0, 0).unwrap();

        let device_indicator = device_indicators.join(":");
        let argon_seed = argon2::derive_key(
            TEST_PASSWORD.as_bytes(),
            &device_indicator,
            &bg.get_wallet_by_index(0)
                .unwrap()
                .get_wallet_data()
                .unwrap()
                .settings
                .argon_params
                .into_config(),
        )
        .unwrap();

        let message = "Hello, Zilliqa!";
        let (pubkey, signature) = bg
            .sign_message(0, 0, &argon_seed, None, message, None, None)
            .unwrap();

        let hashed_message = Sha256::digest(message.as_bytes());
        let key_pair = bg
            .get_wallet_by_index(0)
            .unwrap()
            .reveal_keypair(0, &argon_seed, None)
            .unwrap();

        assert_eq!(pubkey.as_bytes(), *key_pair.get_pubkey_bytes());
        let is_valid = key_pair.verify_sig(&hashed_message, &signature).unwrap();

        assert!(is_valid);
    }

    #[tokio::test]
    async fn test_unckeched_seed_phrase() {
        let (mut bg, _dir) = setup_test_background();
        let net_config = gen_zil_testnet_conf();

        bg.add_provider(net_config.clone()).unwrap();
        let accounts = [gen_zil_account(0, "Zil 0")];
        let device_indicators = gen_device_indicators("test_zilliqa");

        const UNCHECKSUMED_WORD: &str =
            "sword sure throw slide garden science six destroy canvas ceiling negative black";
        bg.add_bip39_wallet(BackgroundBip39Params {
            mnemonic_check: false,
            password: TEST_PASSWORD,
            chain_hash: net_config.hash(),
            mnemonic_str: UNCHECKSUMED_WORD,
            accounts: &accounts,
            wallet_settings: Default::default(),
            passphrase: "",
            wallet_name: "Zilliqa legacy wallet".to_string(),
            biometric_type: Default::default(),
            device_indicators: &device_indicators,
            ftokens: vec![gen_zil_token()],
        })
        .unwrap();

        bg.swap_zilliqa_chain(0, 0).unwrap();

        let wallet = bg.get_wallet_by_index(0).unwrap();
        let data = wallet.get_wallet_data().unwrap();
        let device_indicator = device_indicators.join(":");
        let argon_seed = argon2::derive_key(
            TEST_PASSWORD.as_bytes(),
            &device_indicator,
            &data.settings.argon_params.into_config(),
        )
        .unwrap();
        let revealed_mnemonic = wallet.reveal_mnemonic(&argon_seed).unwrap();
        let keypair = wallet.reveal_keypair(0, &argon_seed, None).unwrap();

        assert_eq!(revealed_mnemonic.to_string(), UNCHECKSUMED_WORD);
        assert_eq!(
            "d7986cf4acc822c1a6cdc4170f5561a6cee1591c37ec6a887bb650d051e4ad71",
            hex::encode(&keypair.get_secretkey().unwrap().as_ref())
        );
        assert_eq!(
            "022b8e6855eaf04ec7bd2e01d5aaf4e46a111b509882e5456d97af60a6d1ed6f28",
            hex::encode(&keypair.get_pubkey().unwrap().as_bytes())
        );
    }

    #[tokio::test]
    async fn test_update_tx_from_params_eip1559() {
        let (mut bg, _dir) = setup_test_background();
        let net_config = gen_anvil_net_conf();

        bg.add_provider(net_config.clone()).unwrap();
        let accounts = [gen_eth_account(0, "Anvil Acc 0")];
        let device_indicators = gen_device_indicators("testanvil");

        bg.add_bip39_wallet(BackgroundBip39Params {
            mnemonic_check: true,
            password: TEST_PASSWORD,
            chain_hash: net_config.hash(),
            mnemonic_str: ANVIL_MNEMONIC,
            accounts: &accounts,
            wallet_settings: Default::default(),
            passphrase: "",
            wallet_name: "Anvil wallet".to_string(),
            biometric_type: Default::default(),
            device_indicators: &device_indicators,
            ftokens: vec![gen_anvil_token()],
        })
        .unwrap();

        let providers = bg.get_providers();
        let provider = providers.first().unwrap();
        let wallet = bg.get_wallet_by_index(0).unwrap();
        let data = wallet.get_wallet_data().unwrap();
        let account = data.accounts.first().unwrap();

        // Create a basic transaction without gas params
        let recipient =
            Address::from_eth_address("0x246C5881E3F109B2aF170F5C773EF969d3da581B").unwrap();
        let transfer_request = ETHTransactionRequest {
            to: Some(recipient.to_alloy_addr().into()),
            value: Some(U256::from(10u128)),
            nonce: None,
            gas: None,
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
            gas_price: None,
            chain_id: Some(provider.config.chain_id()),
            ..Default::default()
        };

        // Verify initial state - all gas params should be None
        assert!(transfer_request.nonce.is_none());
        assert!(transfer_request.gas.is_none());
        assert!(transfer_request.gas_price.is_none());
        assert!(transfer_request.max_fee_per_gas.is_none());
        assert!(transfer_request.max_priority_fee_per_gas.is_none());

        let metadata = proto::tx::TransactionMetadata {
            chain_hash: net_config.hash(),
            ..Default::default()
        };
        let mut tx_request = TransactionRequest::Ethereum((transfer_request.clone(), metadata));

        // Get estimated params from the network
        let params = provider
            .estimate_params_batch(&tx_request, &account.addr, 10, None)
            .await
            .unwrap();

        // Store params for verification
        let expected_nonce = params.nonce;
        let expected_gas_limit = params.tx_estimate_gas;
        let expected_gas_price = params.gas_price;
        let expected_base_fee = params.fee_history.base_fee;
        let expected_priority_fee = params.fee_history.priority_fee;
        let expected_max_fee = params.fee_history.max_fee;

        // Verify params are valid
        assert!(
            expected_gas_limit > U256::ZERO,
            "Gas limit should be estimated"
        );

        // Determine if EIP-1559 is supported
        let is_eip1559 = expected_base_fee > U256::ZERO;

        // Update the transaction with the params
        super::update_tx_from_params(&mut tx_request, params).unwrap();

        // Extract and verify the updated transaction
        if let TransactionRequest::Ethereum((updated_tx, _)) = &tx_request {
            // Verify basic fields are set
            assert_eq!(
                updated_tx.nonce,
                Some(expected_nonce),
                "Nonce should be set from params"
            );

            assert!(updated_tx.gas.is_some(), "Gas limit should be set");
            assert_eq!(
                U256::from(updated_tx.gas.unwrap()),
                expected_gas_limit,
                "Gas limit should be set from params"
            );

            if is_eip1559 {
                // Verify EIP-1559 fields
                assert!(
                    updated_tx.max_fee_per_gas.is_some(),
                    "max_fee_per_gas should be set for EIP-1559"
                );
                assert!(
                    updated_tx.max_priority_fee_per_gas.is_some(),
                    "max_priority_fee_per_gas should be set for EIP-1559"
                );

                let max_fee = updated_tx.max_fee_per_gas.unwrap();
                let priority_fee = updated_tx.max_priority_fee_per_gas.unwrap();

                // Verify correct values from fee history
                let expected_max_fee_u128: u128 = expected_max_fee.try_into().unwrap();
                let expected_priority_fee_u128: u128 = expected_priority_fee.try_into().unwrap();

                assert_eq!(
                    max_fee, expected_max_fee_u128,
                    "max_fee_per_gas should match fee_history.max_fee"
                );
                assert_eq!(
                    priority_fee, expected_priority_fee_u128,
                    "max_priority_fee_per_gas should match fee_history.priority_fee"
                );

                // Verify EIP-1559 constraint: max_fee_per_gas >= max_priority_fee_per_gas
                assert!(
                    max_fee >= priority_fee,
                    "max_fee_per_gas ({}) must be >= max_priority_fee_per_gas ({})",
                    max_fee,
                    priority_fee
                );

                // Verify max_fee calculation: base_fee * 2 + priority_fee
                let expected_max_fee_calc = expected_base_fee
                    .saturating_mul(U256::from(2))
                    .saturating_add(expected_priority_fee);
                assert_eq!(
                    U256::from(max_fee),
                    expected_max_fee_calc,
                    "max_fee should be base_fee * 2 + priority_fee"
                );

                // Verify gas_price is cleared for EIP-1559
                assert!(
                    updated_tx.gas_price.is_none(),
                    "gas_price should be None for EIP-1559 transactions"
                );
            } else {
                // Legacy mode - verify gas_price is set
                assert!(
                    updated_tx.gas_price.is_some(),
                    "gas_price should be set for legacy transactions"
                );

                let gas_price = updated_tx.gas_price.unwrap();
                let expected_gas_price_u128: u128 = expected_gas_price.try_into().unwrap();

                assert_eq!(
                    gas_price, expected_gas_price_u128,
                    "gas_price should match params.gas_price"
                );

                // Verify EIP-1559 fields are cleared for legacy
                assert!(
                    updated_tx.max_fee_per_gas.is_none(),
                    "max_fee_per_gas should be None for legacy transactions"
                );
                assert!(
                    updated_tx.max_priority_fee_per_gas.is_none(),
                    "max_priority_fee_per_gas should be None for legacy transactions"
                );
            }
        } else {
            panic!("Transaction should be Ethereum type");
        }
    }

    #[tokio::test]
    async fn test_sign_and_send_btc_tx() {
        use crypto::{bip49::DerivationPath, slip44};
        use test_data::gen_btc_testnet_conf;

        let (mut bg, _dir) = setup_test_background();
        let net_config = gen_btc_testnet_conf();

        bg.add_provider(net_config.clone()).unwrap();

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
            mnemonic_str: ANVIL_MNEMONIC,
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
        // Check sender address (Should be P2WPKH Mainnet starting with bc1q)
        assert!(addr_str.starts_with("bc1q"));

        // Retrieve argon seed
        let device_indicator = device_indicators.join(":");
        let argon_seed = argon2::derive_key(
            TEST_PASSWORD.as_bytes(),
            &device_indicator,
            &data.settings.argon_params.into_config(),
        )
        .unwrap();

        // Define destination addresses (using wallet's own address for testing)
        // In a real scenario, these would be different recipient addresses
        let dest_addr = account.addr.clone();
        let destinations = vec![
            (dest_addr.clone(), 1000u64),
            (dest_addr.clone(), 1000u64),
            (dest_addr.clone(), 1000u64),
            (dest_addr.clone(), 1000u64),
        ];

        // Prepare and sign Bitcoin transaction (auto-fetches UTXOs and builds tx)
        let signed_tx = bg
            .prepare_and_sign_btc_transaction(0, 0, &argon_seed, None, destinations, Some(10))
            .await
            .unwrap();

        // Verify the signature
        assert!(signed_tx.verify().unwrap());

        // Verify we have outputs (destinations + potentially change)
        if let TransactionReceipt::Bitcoin((signed_btc_tx, _)) = &signed_tx {
            assert!(signed_btc_tx.output.len() >= 4); // At least 4 destinations
        } else {
            panic!("Not a BTC tx");
        }

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

        // Wait for transaction to be processed
        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;

        // Update transaction status
        println!("Updating transaction status...");
        bg.check_pending_txns(0).await.unwrap();

        // Get updated history
        let wallet = bg.get_wallet_by_index(0).unwrap();
        let history = wallet.get_history().unwrap();
        let net_hash = net_config.hash();
        let filtered_history = history
            .into_iter()
            .filter(|t| t.metadata.chain_hash == net_hash)
            .collect::<Vec<HistoricalTransaction>>();

        assert_eq!(filtered_history.len(), 1);
        let btc_tx = &filtered_history[0];

        // Verify transaction hash matches
        assert_eq!(btc_tx.metadata.hash.as_ref().unwrap(), &tx_hash);

        let btc_data = btc_tx.get_btc().expect("BTC field should be present");

        assert!(btc_data.get("txid").is_some(), "txid should be present");
        assert!(
            btc_data.get("version").is_some(),
            "version should be present"
        );
        assert!(
            btc_data.get("locktime").is_some(),
            "locktime should be present"
        );
        assert!(btc_data.get("vin").is_some(), "vin should be present");
        assert!(btc_data.get("vout").is_some(), "vout should be present");

        let inputs = btc_data
            .get("vin")
            .unwrap()
            .as_array()
            .expect("vin should be array");
        let outputs = btc_data
            .get("vout")
            .unwrap()
            .as_array()
            .expect("vout should be array");
        println!(
            "Transaction has {} inputs and {} outputs",
            inputs.len(),
            outputs.len()
        );

        assert!(inputs.len() > 0, "Should have at least one input");
        assert!(
            outputs.len() >= 4,
            "Should have at least 4 outputs (destinations)"
        );

        // Verify transaction status
        println!("Transaction status: {:?}", btc_tx.status);
        assert!(
            btc_tx.status == TransactionStatus::Success
                || btc_tx.status == TransactionStatus::Pending,
            "Transaction should be either Success or Pending"
        );

        let confirmations = btc_data
            .get("confirmations")
            .and_then(|c| c.as_u64())
            .unwrap_or(0);
        println!("Transaction confirmations: {}", confirmations);
        if confirmations > 0 {
            assert_eq!(
                btc_tx.status,
                TransactionStatus::Success,
                "Transaction with confirmations should be Success"
            );
        }
    }
}
