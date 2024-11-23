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
        contract: &Address,
        accounts: &[Address],
    ) -> Result<FToken, NetworkErrors> {
        match self {
            NetworkProvider::Ethereum => {
                unreachable!()
            }
            NetworkProvider::Zilliqa(zil) => match contract {
                Address::Secp256k1Sha256Zilliqa(_) => {
                    // Convert contract address to base16
                    let base16_contract = contract
                        .get_zil_base16()
                        .map_err(NetworkErrors::InvalidAddress)?;

                    // Build the init request
                    let init_req = ZilliqaJsonRPC::build_payload(
                        json!([base16_contract]),
                        zilliqa::json_rpc::zil_methods::ZilMethods::GetSmartContractInit,
                    );

                    // Create balance requests for each account
                    let mut all_requests = vec![init_req];

                    // Store base16 addresses to use when processing responses
                    let mut base16_accounts = Vec::with_capacity(accounts.len());

                    for account in accounts {
                        let base16_account = account
                            .get_zil_check_sum_addr()
                            .map_err(NetworkErrors::InvalidAddress)?
                            .to_lowercase();

                        let balance_req = ZilliqaJsonRPC::build_payload(
                            json!([base16_contract, "balances", [base16_account.clone()]]),
                            zilliqa::json_rpc::zil_methods::ZilMethods::GetSmartContractSubState,
                        );

                        base16_accounts.push(base16_account);
                        all_requests.push(balance_req);
                    }

                    // Make all requests
                    let res_vec = zil
                        .req::<Vec<ResultRes<Value>>>(&all_requests)
                        .await
                        .map_err(NetworkErrors::Request)?;

                    // Process init response (first response)
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

                    // Extract token metadata
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

                    // Process balance responses (skip first response which was init)
                    let mut balances = HashMap::new();

                    for ((account, base16_account), response) in accounts
                        .iter()
                        .zip(base16_accounts.iter())
                        .zip(res_vec.iter().skip(1))
                    {
                        let balance: U256 = response
                            .result
                            .as_ref()
                            .ok_or(NetworkErrors::ResponseParseError)?
                            .get("balances")
                            .ok_or(NetworkErrors::ResponseParseError)?
                            .get(base16_account)
                            .ok_or(NetworkErrors::ResponseParseError)?
                            .as_str()
                            .ok_or(NetworkErrors::ResponseParseError)?
                            .parse()
                            .or(Err(NetworkErrors::ResponseParseError))?;

                        balances.insert(account.clone(), balance);
                    }

                    let ftoken = FToken {
                        balances,
                        name,
                        symbol,
                        decimals,
                        addr: contract.clone(),
                        logo: None,
                        default: false,
                        native: false,
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
        accounts: &[Address],
    ) -> Result<(), NetworkErrors> {
        match self {
            NetworkProvider::Ethereum => {
                unreachable!()
            }
            NetworkProvider::Zilliqa(zil) => {
                let evm_ftokens = tokens
                    .iter()
                    .filter(|t| match t.addr {
                        Address::Secp256k1Sha256Zilliqa(_) => false,
                        Address::Secp256k1Keccak256Ethereum(_) => true,
                    })
                    .collect::<Vec<&FToken>>();
                let scilla_ftokens = tokens
                    .iter()
                    .filter(|t| match t.addr {
                        Address::Secp256k1Sha256Zilliqa(_) => true,
                        Address::Secp256k1Keccak256Ethereum(_) => false,
                    })
                    .collect::<Vec<&FToken>>();

                dbg!(&evm_ftokens);
                dbg!(&scilla_ftokens);
            }
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
        let account = [
            Address::from_zil_bech32("zil1gmk7xpsyxthczk202a0yavhxk56mqch0ghl02f").unwrap(),
            Address::from_zil_bech32("zil1wl38cwww2u3g8wzgutxlxtxwwc0rf7jf27zace").unwrap(),
            Address::from_zil_bech32("zil12nfykegk3gtatvc50yratrahxt662sr3yhy8c2").unwrap(),
        ];

        let ftoken = net.get_ftoken_meta(&token_addr, &account).await.unwrap();

        assert!(*ftoken.balances.get(&account[0]).unwrap() > U256::from(0));
        assert!(*ftoken.balances.get(&account[1]).unwrap() > U256::from(0));
        assert!(*ftoken.balances.get(&account[2]).unwrap() == U256::from(0));

        assert_eq!(&ftoken.name, "ZilPay wallet");
        assert_eq!(&ftoken.symbol, "ZLP");
        assert_eq!(ftoken.decimals, 18u8);
    }

    #[tokio::test]
    async fn test_fetch_accounts_tokens_balances() {
        let zil = ZilliqaJsonRPC::new();
        let net = NetworkProvider::Zilliqa(zil);
        let tokens =
            [Address::from_zil_bech32("zil1l0g8u6f9g0fsvjuu74ctyla2hltefrdyt7k5f4").unwrap()];
        // Add multiple custom tokens
        let tokens = vec![
            FToken::zil(),
            FToken {
                name: "ZilPay token".to_string(),
                symbol: "ZLP".to_string(),
                decimals: 18,
                addr: Address::from_zil_bech32("zil1l0g8u6f9g0fsvjuu74ctyla2hltefrdyt7k5f4")
                    .unwrap(),
                native: false,
                logo: None,
                default: false,
                balances: HashMap::new(),
            },
            FToken {
                name: "DMZ".to_string(),
                symbol: "DMZ".to_string(),
                decimals: 18,
                addr: Address::from_zil_bech32("zil19lr3vlpm4lufu2q94mmjvdkvmx8wdwajuntzx2")
                    .unwrap(),
                native: false,
                logo: None,
                default: false,
                balances: HashMap::new(),
            },
            FToken {
                name: "RedChillies".to_string(),
                symbol: "REDC".to_string(),
                decimals: 9,
                native: false,
                addr: Address::from_zil_bech32("zil14jmjrkvfcz2uvj3y69kl6gas34ecuf2j5ggmye")
                    .unwrap(),
                logo: None,
                default: false,
                balances: HashMap::new(),
            },
        ];
        let accounts = [
            Address::from_zil_bech32("zil1gmk7xpsyxthczk202a0yavhxk56mqch0ghl02f").unwrap(),
            Address::from_zil_bech32("zil1wl38cwww2u3g8wzgutxlxtxwwc0rf7jf27zace").unwrap(),
            Address::from_zil_bech32("zil12nfykegk3gtatvc50yratrahxt662sr3yhy8c2").unwrap(),
        ];

        let ftoken = net.get_tokens_balances(&tokens, &accounts).await.unwrap();
    }
}
