use alloy::primitives::{Address as AlloyAddress, U256};
use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Serialize, Deserialize, PartialEq, Clone)]
pub struct PendingWithdrawal {
    pub amount: U256,
    pub withdrawal_block: u64,
    pub claimable: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct LPToken {
    pub name: String,
    pub symbol: String,
    pub decimals: u8,
    pub address: AlloyAddress,
    pub price: Option<f64>,
}

#[derive(Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct ZilValidator {
    pub future_stake: U256,
    pub pending_withdrawals: U256,
    pub reward_address: String,
    pub status: bool,
}

#[derive(Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct FinalOutput {
    pub name: String,
    pub address: String,
    pub token: Option<LPToken>,
    pub deleg_amt: U256,
    pub rewards: U256,
    pub claimable_amount: U256,
    pub vote_power: Option<f64>,
    pub apr: Option<f64>,
    pub commission: Option<f64>,
    pub total_rewards: Option<U256>,
    pub total_stake: Option<U256>,
    pub total_network_stake: Option<U256>,
    pub version: Option<String>,
    pub unbonding_period: Option<u64>,
    pub tag: String,
    pub current_block: Option<u64>,
    pub pending_withdrawals: Vec<PendingWithdrawal>,
    pub validators: Vec<ZilValidator>,
    pub hide: bool,
    pub uptime: u8,
    pub can_stake: bool,
}

#[cfg(test)]
mod tests {
    use crate::{
        provider::NetworkProvider,
        scilla_stake::ZilliqaScillaStakeing,
        zil_stake_evm::{get_zq2_providers, ZilliqaEVMStakeing},
    };

    use proto::address::Address;
    use rpc::network_config::ChainConfig;

    fn create_zilliqa_config() -> ChainConfig {
        ChainConfig {
            ftokens: vec![],
            logo: String::new(),
            diff_block_time: 0,
            testnet: None,
            chain_ids: [1, 0],
            name: "Zilliqa".to_string(),
            chain: "ZIL".to_string(),
            short_name: String::new(),
            rpc: vec!["https://api.zilliqa.com".to_string()],
            features: vec![],
            slip_44: 313,
            ens: None,
            explorers: vec![],
            fallback_enabled: true,
        }
    }

    #[tokio::test]
    async fn test_request_zil_staking_pools() {
        let pools = get_zq2_providers().await.unwrap();
        assert!(!pools.is_empty());
        assert!(pools.iter().any(|p| p.name == "Moonlet"));
    }

    #[tokio::test]
    async fn test_get_scilla_stake() {
        let addr = Address::from_zil_bech32("zil1wl38cwww2u3g8wzgutxlxtxwwc0rf7jf27zace").unwrap();

        let net_conf = create_zilliqa_config();
        let provider = NetworkProvider::new(net_conf);
        let result = provider.fetch_scilla_stake(&addr).await;
        let final_output = result.unwrap();

        println!("{:#?}", final_output);
    }

    #[tokio::test]
    async fn test_get_evm_stake() {
        let addr = Address::from_eth_address("0x8bd81306F248307c3fa1bb40fbD59baa86FFb2BA").unwrap();

        let net_conf = create_zilliqa_config();
        let provider = NetworkProvider::new(net_conf);
        let result = provider.fetch_evm_stake(&addr).await;
        let final_output = result.unwrap();

        println!("{:#?}", final_output);
    }
}
