use crate::{bg_provider::ProvidersManagement, bg_wallet::WalletManagement, Result};
use async_trait::async_trait;
use proto::tx::{TransactionReceipt, TransactionRequest};
use rpc::{methods::ZilMethods, network_config::NetworkConfig, provider::RpcProvider};
use serde_json::json;
use zil_errors::background::BackgroundError;

use crate::Background;

#[async_trait]
pub trait TransactionsManagement {
    type Error;

    async fn broadcast_signed_transactions<'a>(
        &self,
        wallet_index: usize,
        txns: &'a [TransactionReceipt],
    ) -> std::result::Result<&'a [TransactionReceipt], Self::Error>;
}

#[async_trait]
impl TransactionsManagement for Background {
    type Error = BackgroundError;

    async fn broadcast_signed_transactions<'a>(
        &self,
        wallet_index: usize,
        txns: &'a [TransactionReceipt],
    ) -> Result<&'a [TransactionReceipt]> {
        let wallet = self.get_wallet_by_index(wallet_index)?;
        let provider = self.get_provider(wallet.data.provider_index)?;

        for tx in txns {
            // TODO: add check if right pubkey
            if !tx.verify()? {
                return Err(BackgroundError::TransactionInvalidSig);
            }
        }

        let build_payload = RpcProvider::<NetworkConfig>::build_payload;
        let payloads = build_payload(json!(txns), ZilMethods::CreateTransaction);

        dbg!(payloads);

        Ok(txns)
    }
}

#[cfg(test)]
mod tests_background_transactions {
    use super::*;
    use crate::{bg_storage::StorageManagement, BackgroundBip39Params};
    use cipher::argon2;
    use crypto::bip49::Bip49DerivationPath;
    use proto::{
        address::Address,
        zil_tx::{ScillaGas, ZILTransactionRequest, ZilAmount},
    };
    use rand::Rng;
    use rpc::network_config::NetworkConfig;
    use token::ft::FToken;
    use tokio;
    use wallet::wallet_crypto::WalletCrypto;

    const PASSWORD: &str = "TEst password";
    const ONE_ZIL: u128 = 1_000_000_000_000u128;

    fn setup_test_background() -> (Background, String) {
        let mut rng = rand::thread_rng();
        let dir = format!("/tmp/{}", rng.gen::<usize>());
        let bg = Background::from_storage_path(&dir).unwrap();
        (bg, dir)
    }

    fn gen_zil_net_conf() -> NetworkConfig {
        NetworkConfig::new(
            "Zilliqa(testnet)",
            333,
            vec!["https://dev-api.zilliqa.com".to_string()],
        )
    }

    #[tokio::test]
    async fn test_sign_and_send_zil_tx() {
        let (mut bg, _dir) = setup_test_background();

        bg.add_provider(gen_zil_net_conf()).unwrap();

        let words = "future slot favorite conduct please organ trick seek goat easy chapter proud"
            .to_string();
        let accounts = [(Bip49DerivationPath::Zilliqa(0), "ZIL Acc 0".to_string())];
        let device_indicators = [String::from("5435h"), String::from("0000")];

        bg.add_bip39_wallet(BackgroundBip39Params {
            password: PASSWORD,
            provider: 0,
            mnemonic_str: &words,
            accounts: &accounts,
            wallet_settings: Default::default(),
            passphrase: "",
            wallet_name: String::new(),
            biometric_type: Default::default(),
            device_indicators: &device_indicators,
            ftokens: vec![FToken::zil(0)],
        })
        .unwrap();
        let provider = bg.get_provider(0).unwrap();
        let wallet = bg.get_wallet_by_index(0).unwrap();
        let addresses: Vec<&Address> = wallet.data.accounts.iter().map(|v| &v.addr).collect();
        let nonce = *bg
            .get_provider(0)
            .unwrap()
            .fetch_nonce(&addresses)
            .await
            .unwrap()
            .first()
            .unwrap();

        let txn = TransactionRequest::Zilliqa(ZILTransactionRequest {
            title: None,
            icon: None,
            token_info: None,
            nonce: nonce + 1,
            chain_id: provider.config.chain_id as u16,
            gas_price: ZilAmount::from_raw(2000000000),
            gas_limit: ScillaGas(1000),
            to_addr: Address::from_zil_bech32("zil1sctmwt3zpy8scyck0pj3glky3fkm0z8lxa4ga7")
                .unwrap(),
            amount: ZilAmount::from_raw(1), // in QA
            code: String::new(),
            data: String::new(),
        });

        let device_indicator = device_indicators.join(":");
        let argon_seed = argon2::derive_key(
            PASSWORD.as_bytes(),
            &device_indicator,
            &wallet.data.settings.argon_params.into_config(),
        )
        .unwrap();

        let keypair = wallet.reveal_keypair(0, &argon_seed, None).unwrap();
        let txn = txn.sign(&keypair).await.unwrap();
        let txns = vec![txn];

        bg.broadcast_signed_transactions(0, &txns).await.unwrap();
    }
}
