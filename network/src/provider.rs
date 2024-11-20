use std::collections::HashMap;

use alloy::primitives::U256;
use proto::address::Address;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use wallet::{account::Account, ft::FToken};
use zil_errors::network::NetworkErrors;
use zilliqa::json_rpc::{
    zil::ZilliqaJsonRPC,
    zil_interfaces::{GetTokenInitItem, ResultRes},
};

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
                    .map_err(NetworkErrors::FetchNodes)?;
                zil.update_evm_nodes()
                    .await
                    .map_err(NetworkErrors::FetchNodes)?;
            }
            NetworkProvider::Ethereum => {
                unreachable!()
            }
        };

        Ok(())
    }

    pub async fn get_ftoken_meta(
        &self,
        addr: &Address,
        called: &Address,
    ) -> Result<FToken, NetworkErrors> {
        match self {
            NetworkProvider::Ethereum => {
                unreachable!()
            }
            NetworkProvider::Zilliqa(zil) => match addr {
                Address::Secp256k1Sha256Zilliqa(_) => {
                    let base16_caller = called
                        .get_zil_check_sum_addr()
                        .map_err(NetworkErrors::InvalidAddress)?
                        .to_lowercase();
                    let base16_contract = addr
                        .get_zil_base16()
                        .map_err(NetworkErrors::InvalidAddress)?;
                    let init_req = ZilliqaJsonRPC::build_payload(
                        json!([base16_contract]),
                        zilliqa::json_rpc::zil_methods::ZilMethods::GetSmartContractInit,
                    );
                    let balance = ZilliqaJsonRPC::build_payload(
                        json!([base16_contract, "balances", [base16_caller]]),
                        zilliqa::json_rpc::zil_methods::ZilMethods::GetSmartContractSubState,
                    );

                    let res_vec = zil
                        .req::<Vec<ResultRes<Value>>>(&[init_req, balance])
                        .await
                        .map_err(NetworkErrors::Request)?;
                    let res_init = res_vec
                        .first()
                        .ok_or(NetworkErrors::ResponseParseError)?
                        .result
                        .as_ref()
                        .ok_or(NetworkErrors::InvalidContractInit)?
                        .as_array()
                        .ok_or(NetworkErrors::InvalidContractInit)?
                        .iter()
                        .map(|v| v.try_into())
                        .collect::<Result<Vec<GetTokenInitItem>, _>>()
                        .map_err(NetworkErrors::TokenParseError)?;
                    let name = res_init
                        .iter()
                        .find(|v| v.vname == "name")
                        .ok_or(NetworkErrors::InvalidContractInit)?
                        .value
                        .clone();
                    let symbol = res_init
                        .iter()
                        .find(|v| v.vname == "symbol")
                        .ok_or(NetworkErrors::InvalidContractInit)?
                        .value
                        .clone();
                    let decimals: u8 = res_init
                        .iter()
                        .find(|v| v.vname == "decimals")
                        .ok_or(NetworkErrors::InvalidContractInit)?
                        .value
                        .clone()
                        .parse()
                        .or(Err(NetworkErrors::InvalidContractInit))?;
                    let balance: U256 = res_vec
                        .last()
                        .ok_or(NetworkErrors::ResponseParseError)?
                        .result
                        .as_ref()
                        .ok_or(NetworkErrors::ResponseParseError)?
                        .get("balances")
                        .ok_or(NetworkErrors::ResponseParseError)?
                        .get(base16_caller)
                        .ok_or(NetworkErrors::ResponseParseError)?
                        .as_str()
                        .ok_or(NetworkErrors::ResponseParseError)?
                        .parse()
                        .or(Err(NetworkErrors::ResponseParseError))?;

                    let mut balances = HashMap::new();

                    balances.insert(called.clone(), balance);

                    let ftoken = FToken {
                        balances,
                        name,
                        symbol,
                        decimals,
                        addr: addr.clone(),
                        logo: None,
                        default: false,
                    };

                    Ok(ftoken)
                }
                Address::Secp256k1Keccak256Ethereum(_) => {
                    unreachable!()
                }
            },
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use tokio;

    #[tokio::test]
    async fn test_get_ftoken_meta() {
        let zil = ZilliqaJsonRPC::new();
        let net = NetworkProvider::Zilliqa(zil);
        let token_addr =
            Address::from_zil_bech32("zil1l0g8u6f9g0fsvjuu74ctyla2hltefrdyt7k5f4").unwrap();
        let called =
            Address::from_zil_bech32("zil1gmk7xpsyxthczk202a0yavhxk56mqch0ghl02f").unwrap();

        let ftoken = net.get_ftoken_meta(&token_addr, &called).await.unwrap();

        dbg!(ftoken);
    }
}
