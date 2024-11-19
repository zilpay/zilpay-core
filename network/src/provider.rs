use serde::{Deserialize, Serialize};
use wallet::{account::Account, ft::FToken};
use zil_errors::network::NetworkErrors;
use zilliqa::json_rpc::zil::ZilliqaJsonRPC;

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum NetworkProvider {
    Zilliqa(ZilliqaJsonRPC),
    Ethereum,
}

impl NetworkProvider {
    pub fn new_vec() -> Vec<Self> {
        let zil_rpc = ZilliqaJsonRPC::new();

        vec![NetworkProvider::Zilliqa(zil_rpc), NetworkProvider::Ethereum]
    }

    pub async fn update_nodes(&mut self) -> Result<(), NetworkErrors> {
        match self {
            NetworkProvider::Zilliqa(zil) => {
                zil.update_scilla_nodes()
                    .await
                    .map_err(NetworkErrors::FailToFetchNodes)?;
                zil.update_evm_nodes()
                    .await
                    .map_err(NetworkErrors::FailToFetchNodes)?;
            }
            NetworkProvider::Ethereum => {
                unreachable!()
            }
        };

        Ok(())
    }

    pub async fn get_tokens_balances(
        &self,
        tokens: &[FToken],
        accounts: &[Account],
    ) -> Result<(), NetworkErrors> {
        match self {
            NetworkProvider::Ethereum => {
                unreachable!()
            }
            NetworkProvider::Zilliqa(zil) => {}
        };

        Ok(())
    }
}
