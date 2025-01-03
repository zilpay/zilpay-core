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

    async fn broadcast_signed_transaction<'a>(
        &self,
        wallet_index: usize,
        txns: &'a [TransactionReceipt],
    ) -> std::result::Result<&'a [TransactionReceipt], Self::Error>;
}

#[async_trait]
impl TransactionsManagement for Background {
    type Error = BackgroundError;

    async fn broadcast_signed_transaction<'a>(
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
    use crate::{
        bg_crypto::CryptoOperations, bg_storage::StorageManagement, BackgroundBip39Params,
    };
    use crypto::bip49::Bip49DerivationPath;
    use proto::zil_tx::ZILTransactionRequest;
    use rand::Rng;
    use rpc::network_config::NetworkConfig;
    use token::ft::FToken;
    use tokio;

    const PASSWORD: &str = "TEst password";

    fn setup_test_background() -> (Background, String) {
        let mut rng = rand::thread_rng();
        let dir = format!("/tmp/{}", rng.gen::<usize>());
        let bg = Background::from_storage_path(&dir).unwrap();
        (bg, dir)
    }

    fn gen_zil_net_conf() -> NetworkConfig {
        NetworkConfig::new(
            "Zilliqa",
            32770,
            vec!["https://api.zq2-protomainnet.zilliqa.com".to_string()],
        )
    }

    #[tokio::test]
    async fn test_sign_and_send_zil_tx() {
        let (mut bg, _dir) = setup_test_background();

        bg.add_provider(gen_zil_net_conf()).unwrap();

        let words = Background::gen_bip39(24).unwrap();
        let accounts = [(Bip49DerivationPath::Zilliqa(0), "ZIL Acc 0".to_string())];

        bg.add_bip39_wallet(BackgroundBip39Params {
            password: PASSWORD,
            provider: 0,
            mnemonic_str: &words,
            accounts: &accounts,
            wallet_settings: Default::default(),
            passphrase: "",
            wallet_name: String::new(),
            biometric_type: Default::default(),
            device_indicators: &[String::from("5435h"), String::from("0000")],
            ftokens: vec![FToken::zil(0)],
        })
        .unwrap();

        // let nonce = {
        //     let bal_payload = vec![ZilliqaJsonRPC::build_payload(
        //         json!([bal_addr]),
        //         ZilMethods::GetBalance,
        //     )];
        //     let resvec: Vec<ResultRes<GetBalanceRes>> = zil.req(&bal_payload).await.unwrap();
        //     println!("Bal {0:?}", resvec[0]);
        //     resvec[0].result.as_ref().map_or(0, |v| v.nonce)
        // };

        // let txn = TransactionRequest::Zilliqa(ZILTransactionRequest {
        //     nonce: nonce + 1,
        //     chain_id: CHAIN_ID,
        //     gas_price: ZilAmount::from_raw(2000000000),
        //     gas_limit: ScillaGas(1000),
        //     to_addr: keypairs[1].get_addr().unwrap(),
        //     amount: ZilAmount::from_raw(ONE_ZIL),
        //     code: String::new(),
        //     data: String::new(),
        // });
    }
}
