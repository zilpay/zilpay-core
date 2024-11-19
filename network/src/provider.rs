use serde::{Deserialize, Serialize};
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

    pub async fn update_nodes(&mut self) {
        match self {
            NetworkProvider::Zilliqa(zil) => {
                // TODO: add Error hanlder
                zil.update_scilla_nodes().await;
                zil.update_evm_nodes().await;
            }
            NetworkProvider::Ethereum => {
                unreachable!()
            }
        }
    }
}
