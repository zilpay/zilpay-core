use alloy::primitives::U256;
use proto::address::Address;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use wallet::ft::FToken;
use zil_errors::network::NetworkErrors;
use zilliqa::json_rpc::{zil::ZilliqaJsonRPC, zil_interfaces::ResultRes};

use crate::token::{
    build_token_requests, process_eth_balance_response, process_eth_metadata_response,
    process_zil_balance_response, process_zil_metadata_response, MetadataField, RequestType,
};

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum NetworkProvider {
    Zilliqa(ZilliqaJsonRPC),
    Ethereum,
}

impl std::fmt::Display for NetworkProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NetworkProvider::Zilliqa(_) => write!(f, "ZIL"),
            NetworkProvider::Ethereum => write!(f, "ETH"),
        }
    }
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
        accounts: &[&Address],
    ) -> Result<FToken, NetworkErrors> {
        match self {
            NetworkProvider::Ethereum => {
                unreachable!()
            }
            NetworkProvider::Zilliqa(zil) => {
                let requests = build_token_requests(contract, accounts, false)?;
                let responses = zil
                    .req::<Vec<ResultRes<Value>>>(
                        &requests
                            .iter()
                            .map(|(req, _)| req.clone())
                            .collect::<Vec<_>>(),
                    )
                    .await
                    .map_err(NetworkErrors::Request)?;

                match contract {
                    Address::Secp256k1Sha256Zilliqa(_) => {
                        let (name, symbol, decimals) = process_zil_metadata_response(
                            responses[0]
                                .result
                                .as_ref()
                                .ok_or(NetworkErrors::InvalidContractInit)?,
                        )?;

                        let mut balances: HashMap<Address, U256> = HashMap::new();

                        for (i, (_, req_type)) in requests.iter().enumerate().skip(1) {
                            if let RequestType::Balance(account) = req_type {
                                let balance =
                                    process_zil_balance_response(&responses[i], account, false);
                                balances.insert(account.to_owned().clone(), balance);
                            }
                        }

                        Ok(FToken {
                            balances,
                            name,
                            symbol,
                            decimals,
                            addr: contract.clone(),
                            logo: None,
                            default: false,
                            native: false,
                        })
                    }
                    Address::Secp256k1Keccak256Ethereum(_) => {
                        let mut metadata_iter = responses.iter();
                        let name = process_eth_metadata_response(
                            metadata_iter
                                .next()
                                .ok_or(NetworkErrors::InvalidContractInit)?,
                            &MetadataField::Name,
                        )?;
                        let symbol = process_eth_metadata_response(
                            metadata_iter
                                .next()
                                .ok_or(NetworkErrors::InvalidContractInit)?,
                            &MetadataField::Symbol,
                        )?;
                        let decimals: u8 = process_eth_metadata_response(
                            metadata_iter
                                .next()
                                .ok_or(NetworkErrors::InvalidContractInit)?,
                            &MetadataField::Decimals,
                        )?
                        .parse()
                        .map_err(|_| NetworkErrors::InvalidContractInit)?;

                        let mut balances: HashMap<Address, U256> = HashMap::new();
                        for ((_, req_type), response) in
                            requests.iter().zip(responses.iter()).skip(3)
                        {
                            if let RequestType::Balance(account) = req_type {
                                let balance = process_eth_balance_response(response)?;
                                balances.insert(account.to_owned().clone(), balance);
                            }
                        }

                        Ok(FToken {
                            balances,
                            name,
                            symbol,
                            decimals,
                            addr: contract.clone(),
                            logo: None,
                            default: false,
                            native: false,
                        })
                    }
                }
            }
        }
    }

    pub async fn get_tokens_balances(
        &self,
        tokens: &mut [FToken],
        accounts: &[&Address],
    ) -> Result<(), NetworkErrors> {
        match self {
            NetworkProvider::Ethereum => {
                unreachable!()
            }
            NetworkProvider::Zilliqa(zil) => {
                let mut all_requests = Vec::new();
                let mut request_mapping = Vec::new();

                for (token_idx, token) in tokens.iter().enumerate() {
                    let requests = build_token_requests(&token.addr, accounts, token.native)?;

                    for (req, req_type) in requests {
                        if let RequestType::Balance(account) = req_type {
                            request_mapping.push((token_idx, account));
                            all_requests.push(req);
                        }
                    }
                }

                if !all_requests.is_empty() {
                    let responses = zil
                        .req::<Vec<ResultRes<Value>>>(&all_requests)
                        .await
                        .map_err(NetworkErrors::Request)?;

                    for ((token_idx, account), response) in
                        request_mapping.iter().zip(responses.iter())
                    {
                        match tokens[*token_idx].addr {
                            Address::Secp256k1Sha256Zilliqa(_) => {
                                let balance = process_zil_balance_response(
                                    response,
                                    account,
                                    tokens[*token_idx].native,
                                );
                                tokens[*token_idx]
                                    .balances
                                    .insert(account.to_owned().clone(), balance);
                            }
                            Address::Secp256k1Keccak256Ethereum(_) => {
                                let balance = process_eth_balance_response(response)?;
                                tokens[*token_idx]
                                    .balances
                                    .insert(account.to_owned().clone(), balance);
                            }
                        }
                    }
                }

                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::U256;
    use config::address::ADDR_LEN;
    use tokio;

    #[tokio::test]
    async fn test_get_ftoken_meta() {
        let zil = ZilliqaJsonRPC::from_vec(vec![ZilliqaJsonRPC::PROTO_MAINNET.to_string()], 0);
        let net = NetworkProvider::Zilliqa(zil);
        let token_addr =
            Address::from_zil_bech32("zil1l0g8u6f9g0fsvjuu74ctyla2hltefrdyt7k5f4").unwrap();
        let account = [
            &Address::from_zil_bech32("zil1gmk7xpsyxthczk202a0yavhxk56mqch0ghl02f").unwrap(),
            &Address::from_zil_bech32("zil1wl38cwww2u3g8wzgutxlxtxwwc0rf7jf27zace").unwrap(),
            &Address::from_zil_bech32("zil12nfykegk3gtatvc50yratrahxt662sr3yhy8c2").unwrap(),
            &Address::Secp256k1Sha256Zilliqa([0u8; ADDR_LEN]),
        ];
        let ftoken = net.get_ftoken_meta(&token_addr, &account).await.unwrap();

        assert!(*ftoken.balances.get(account[0]).unwrap() >= U256::from(0));
        assert!(*ftoken.balances.get(account[1]).unwrap() >= U256::from(0));
        assert!(*ftoken.balances.get(account[2]).unwrap() == U256::from(0));
        assert!(*ftoken.balances.get(account[3]).unwrap() == U256::from(0));

        assert_eq!(&ftoken.name, "ZilPay wallet");
        assert_eq!(&ftoken.symbol, "ZLP");
        assert_eq!(ftoken.decimals, 18u8);
    }

    #[tokio::test]
    async fn test_fetch_accounts_tokens_balances() {
        let zil = ZilliqaJsonRPC::from_vec(vec![ZilliqaJsonRPC::PROTO_MAINNET.to_string()], 0);
        let net = NetworkProvider::Zilliqa(zil);
        // Add multiple custom tokens
        let mut tokens = vec![
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
            &Address::from_zil_bech32("zil1gmk7xpsyxthczk202a0yavhxk56mqch0ghl02f").unwrap(),
            &Address::from_zil_bech32("zil1wl38cwww2u3g8wzgutxlxtxwwc0rf7jf27zace").unwrap(),
            &Address::from_zil_bech32("zil12nfykegk3gtatvc50yratrahxt662sr3yhy8c2").unwrap(),
        ];

        net.get_tokens_balances(&mut tokens, &accounts)
            .await
            .unwrap();

        assert!(&tokens[0].balances.contains_key(accounts[0]));
        assert!(&tokens[0].balances.contains_key(accounts[1]));
        assert!(&tokens[0].balances.contains_key(accounts[2]));

        assert!(&tokens[1].balances.contains_key(accounts[0]));
        assert!(&tokens[1].balances.contains_key(accounts[1]));
        assert!(&tokens[1].balances.contains_key(accounts[2]));

        assert!(&tokens[2].balances.contains_key(accounts[0]));
        assert!(&tokens[2].balances.contains_key(accounts[1]));
        assert!(&tokens[2].balances.contains_key(accounts[2]));
    }

    #[tokio::test]
    async fn test_fetch_eth_tokens() {
        let mut zil = ZilliqaJsonRPC::new();

        zil.selected = 1; // testnet

        let net = NetworkProvider::Zilliqa(zil);
        // Add multiple custom tokens
        let mut tokens = vec![
            FToken::eth(),
            FToken {
                name: "MyToken".to_string(),
                symbol: "MTK".to_string(),
                decimals: 18,
                native: false,
                addr: Address::from_eth_address("0xf06686B5Eb5cAe38c09f12412B729045647E74e3")
                    .unwrap(),
                logo: None,
                default: false,
                balances: HashMap::new(),
            },
        ];
        let accounts = [
            &Address::from_eth_address("0x7aa13D6AE95fb8E843d3bCC2eea365F71c3bACbe").unwrap(),
            &Address::from_eth_address("0x4d9DF80AD454fFE924f98321bF7280Fd3705BD85").unwrap(),
        ];

        net.get_tokens_balances(&mut tokens, &accounts)
            .await
            .unwrap();

        assert!(&tokens[0].balances.contains_key(accounts[0]));
        assert!(&tokens[0].balances.contains_key(accounts[1]));

        assert!(&tokens[1].balances.contains_key(accounts[0]));
        assert!(&tokens[1].balances.contains_key(accounts[1]));
    }

    #[tokio::test]
    async fn test_fetch_eth_meta_data() {
        let zil = ZilliqaJsonRPC::new();
        let net = NetworkProvider::Zilliqa(zil);
        let token_addr =
            Address::from_eth_address("0x2274005778063684fbB1BfA96a2b725dC37D75f9").unwrap();
        let account = [
            &Address::from_eth_address("0x7aa13D6AE95fb8E843d3bCC2eea365F71c3bACbe").unwrap(),
            &Address::from_eth_address("0x4d9DF80AD454fFE924f98321bF7280Fd3705BD85").unwrap(),
        ];

        let ftoken = net.get_ftoken_meta(&token_addr, &account).await.unwrap();

        assert_eq!(&ftoken.name, "Zilliqa-bridged USDT token");
        assert_eq!(&ftoken.symbol, "zUSDT");
        assert_eq!(ftoken.decimals, 6u8);

        assert!(*ftoken.balances.get(account[0]).unwrap() == U256::from(0));
        assert!(*ftoken.balances.get(account[1]).unwrap() == U256::from(0));
    }

    #[tokio::test]
    async fn test_fetch_evm_scilla_tokens() {
        let zil = ZilliqaJsonRPC::from_vec(vec![ZilliqaJsonRPC::PROTO_MAINNET.to_string()], 0);
        let net = NetworkProvider::Zilliqa(zil);
        // Add multiple custom tokens
        let mut tokens = vec![
            FToken::zil(),
            FToken::eth(),
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
                name: "Zilliqa-bridged USDT token".to_string(),
                symbol: "zUSDT".to_string(),
                decimals: 18,
                native: false,
                addr: Address::from_eth_address("0x2274005778063684fbB1BfA96a2b725dC37D75f9")
                    .unwrap(),
                logo: None,
                default: false,
                balances: HashMap::new(),
            },
        ];
        let accounts = [
            &Address::from_zil_bech32("zil1gmk7xpsyxthczk202a0yavhxk56mqch0ghl02f").unwrap(),
            &Address::from_zil_bech32("zil1wl38cwww2u3g8wzgutxlxtxwwc0rf7jf27zace").unwrap(),
            &Address::from_zil_bech32("zil12nfykegk3gtatvc50yratrahxt662sr3yhy8c2").unwrap(),
            &Address::from_eth_address("0x7aa13D6AE95fb8E843d3bCC2eea365F71c3bACbe").unwrap(),
            &Address::from_eth_address("0x4d9DF80AD454fFE924f98321bF7280Fd3705BD85").unwrap(),
        ];

        net.get_tokens_balances(&mut tokens, &accounts)
            .await
            .unwrap();

        assert!(&tokens[0].balances.contains_key(accounts[0]));
        assert!(&tokens[0].balances.contains_key(accounts[1]));
        assert!(&tokens[0].balances.contains_key(accounts[2]));
        assert!(&tokens[0].balances.contains_key(accounts[3]));
        assert!(&tokens[0].balances.contains_key(accounts[4]));

        assert!(&tokens[1].balances.contains_key(accounts[0]));
        assert!(&tokens[1].balances.contains_key(accounts[1]));
        assert!(&tokens[1].balances.contains_key(accounts[2]));
        assert!(&tokens[1].balances.contains_key(accounts[3]));
        assert!(&tokens[1].balances.contains_key(accounts[4]));

        assert!(&tokens[2].balances.contains_key(accounts[0]));
        assert!(&tokens[2].balances.contains_key(accounts[1]));
        assert!(&tokens[2].balances.contains_key(accounts[2]));
        assert!(&tokens[2].balances.contains_key(accounts[3]));
        assert!(&tokens[2].balances.contains_key(accounts[4]));
    }
}
