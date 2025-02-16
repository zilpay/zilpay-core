use std::{sync::Arc, time::Duration};

use crate::{bg_provider::ProvidersManagement, bg_wallet::WalletManagement, Background, Result};
use async_trait::async_trait;
use errors::background::BackgroundError;
use wallet::wallet_storage::StorageOperations;

#[derive(Debug)]
pub enum JobMessage {
    Block(u64),
    Stop,
    Error(String),
}

#[async_trait]
pub trait WorkerManager {
    type Error;

    async fn start_block_track_job(
        &self,
        wallet_index: usize,
        worker_tx: tokio::sync::mpsc::Sender<JobMessage>,
    ) -> std::result::Result<tokio::task::JoinHandle<()>, Self::Error>;
}

#[async_trait]
impl WorkerManager for Background {
    type Error = BackgroundError;

    async fn start_block_track_job(
        &self,
        wallet_index: usize,
        worker_tx: tokio::sync::mpsc::Sender<JobMessage>,
    ) -> Result<tokio::task::JoinHandle<()>> {
        const MAX_ERRORS: u8 = 100;

        let wallet = self.get_wallet_by_index(wallet_index)?.clone();
        let chain_arc = {
            let data = wallet.get_wallet_data()?;
            let mut chain = self.get_provider(data.default_chain_hash)?;
            let account = data.get_selected_account()?;
            if chain.config.diff_block_time == 0 {
                self.update_block_diff_time(data.default_chain_hash, &account.addr)
                    .await?;
                chain = self.get_provider(data.default_chain_hash)?;
            }
            Arc::new(chain)
        };

        let handle = tokio::spawn({
            let mut error_counter: u8 = 0;
            let chain_ref = Arc::clone(&chain_arc);
            let mut last_block_number: u64 = 0;
            let mut interval =
                tokio::time::interval(Duration::from_secs(chain_ref.config.diff_block_time));

            async move {
                loop {
                    tokio::select! {
                        _ = interval.tick() => {
                            match chain_arc.get_current_block_number().await {
                                Ok(block_number) => {
                                    if block_number != last_block_number {
                                        if worker_tx.send(JobMessage::Block(block_number)).await.is_ok() {
                                            last_block_number = block_number;
                                        } else {
                                            break;
                                        }
                                    }
                                }
                                Err(e) => {
                                    if worker_tx.send(JobMessage::Error(e.to_string())).await.is_ok() {
                                        error_counter += 1;
                                    } else {
                                        break;
                                    }
                                }
                            }
                        }
                    }

                    if error_counter >= MAX_ERRORS {
                        break;
                    }
                }
            }
        });

        Ok(handle)
    }
}

#[cfg(test)]
mod tests_background_worker {
    use tokio::sync::mpsc;

    use alloy::primitives::map::HashMap;
    use config::address::ADDR_LEN;
    use crypto::{bip49::DerivationPath, slip44};
    use proto::address::Address;
    use rand::Rng;
    use rpc::network_config::ChainConfig;
    use token::ft::FToken;

    use crate::{
        bg_crypto::CryptoOperations,
        bg_provider::ProvidersManagement,
        bg_storage::StorageManagement,
        bg_wallet::WalletManagement,
        bg_worker::{JobMessage, WorkerManager},
        Background, BackgroundBip39Params,
    };

    const PASSWORD: &str = "password";

    fn setup_test_background() -> (Background, String) {
        let mut rng = rand::thread_rng();
        let dir = format!("/tmp/{}", rng.gen::<usize>());
        let bg = Background::from_storage_path(&dir).unwrap();
        (bg, dir)
    }

    fn gen_net_conf() -> ChainConfig {
        ChainConfig {
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
            explorers: vec![],
            fallback_enabled: true,
        }
    }

    fn gen_bsc_token(chain_hash: u64) -> FToken {
        FToken {
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
    async fn test_start_worker() {
        let (mut bg, _dir) = setup_test_background();

        let words = Background::gen_bip39(24).unwrap();
        let accounts = [(
            DerivationPath::new(slip44::ETHEREUM, 0),
            "Bsc account 1".to_string(),
        )];
        let net_config = gen_net_conf();

        bg.add_provider(net_config.clone()).unwrap();
        bg.add_bip39_wallet(BackgroundBip39Params {
            password: PASSWORD,
            chain_hash: net_config.hash(),
            mnemonic_str: &words,
            accounts: &accounts,
            wallet_settings: Default::default(),
            passphrase: "",
            wallet_name: String::new(),
            biometric_type: Default::default(),
            device_indicators: &[String::from("apple"), String::from("0000")],
            ftokens: vec![gen_bsc_token(net_config.hash())],
        })
        .unwrap();

        let (tx, mut rx) = mpsc::channel(10);
        let handle = bg.start_block_track_job(0, tx).await.unwrap();
        let mut k = 0u8;

        while let Some(msg) = rx.recv().await {
            match msg {
                JobMessage::Block(n) => {
                    assert!(n > 0);
                    k += 1;

                    if k > 2 {
                        handle.abort();
                    }
                }
                _ => break,
            }
        }
    }
}
