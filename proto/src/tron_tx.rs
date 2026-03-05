use crate::address::Address;
use crate::tron_generated::protocol;
use config::address::ADDR_LEN;
use prost::Message;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use protocol::transaction::contract::ContractType;

fn addr_to_tron_bytes(addr: &Address) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(21);
    bytes.push(0x41);
    bytes.extend_from_slice(addr.as_ref());
    bytes
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum TronResource {
    Bandwidth,
    Energy,
}

impl TronResource {
    fn to_proto(&self) -> i32 {
        match self {
            TronResource::Bandwidth => 0,
            TronResource::Energy => 1,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum TronContractCall {
    Transfer {
        to_address: Address,
        amount: i64,
    },
    TriggerSmartContract {
        contract_address: Address,
        call_value: i64,
        data: Vec<u8>,
        call_token_value: i64,
        token_id: i64,
    },
    FreezeBalanceV2 {
        frozen_balance: i64,
        resource: TronResource,
    },
    UnfreezeBalanceV2 {
        unfreeze_balance: i64,
        resource: TronResource,
    },
    WithdrawExpireUnfreeze,
    DelegateResource {
        resource: TronResource,
        balance: i64,
        receiver_address: Address,
        lock: bool,
        lock_period: i64,
    },
    UnDelegateResource {
        resource: TronResource,
        balance: i64,
        receiver_address: Address,
    },
    CancelAllUnfreezeV2,
    TransferAsset {
        asset_name: Vec<u8>,
        to_address: Address,
        amount: i64,
    },
    VoteWitness {
        votes: Vec<(Address, i64)>,
    },
    AccountCreate {
        account_address: Address,
        account_type: i32,
    },
    AccountUpdate {
        account_name: Vec<u8>,
    },
    WitnessCreate {
        url: Vec<u8>,
    },
    WitnessUpdate {
        update_url: Vec<u8>,
    },
    CreateSmartContract {
        new_contract: Vec<u8>,
        call_token_value: i64,
        token_id: i64,
    },
    ProposalCreate {
        parameters: Vec<(i64, i64)>,
    },
    ProposalApprove {
        proposal_id: i64,
        is_add_approval: bool,
    },
    ProposalDelete {
        proposal_id: i64,
    },
    AccountPermissionUpdate {
        raw_data: Vec<u8>,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TronTransactionRequest {
    pub owner_address: Address,
    pub ref_block_bytes: Vec<u8>,
    pub ref_block_hash: Vec<u8>,
    pub expiration: i64,
    pub timestamp: i64,
    pub fee_limit: i64,
    pub contract: TronContractCall,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TronTransactionReceipt {
    pub raw_data_bytes: Vec<u8>,
    pub tx_id: [u8; 32],
    pub signature: Vec<u8>,
    pub owner_address: Address,
    pub contract: TronContractCall,
}

impl TronTransactionRequest {
    fn encode_contract(&self) -> (String, Vec<u8>, ContractType) {
        let owner = addr_to_tron_bytes(&self.owner_address);

        match &self.contract {
            TronContractCall::Transfer { to_address, amount } => {
                let c = protocol::TransferContract {
                    owner_address: owner,
                    to_address: addr_to_tron_bytes(to_address),
                    amount: *amount,
                };
                (
                    "type.googleapis.com/protocol.TransferContract".into(),
                    c.encode_to_vec(),
                    ContractType::TransferContract,
                )
            }
            TronContractCall::TriggerSmartContract {
                contract_address,
                call_value,
                data,
                call_token_value,
                token_id,
            } => {
                let c = protocol::TriggerSmartContract {
                    owner_address: owner,
                    contract_address: addr_to_tron_bytes(contract_address),
                    call_value: *call_value,
                    data: data.clone(),
                    call_token_value: *call_token_value,
                    token_id: *token_id,
                };
                (
                    "type.googleapis.com/protocol.TriggerSmartContract".into(),
                    c.encode_to_vec(),
                    ContractType::TriggerSmartContract,
                )
            }
            TronContractCall::FreezeBalanceV2 {
                frozen_balance,
                resource,
            } => {
                let c = protocol::FreezeBalanceV2Contract {
                    owner_address: owner,
                    frozen_balance: *frozen_balance,
                    resource: resource.to_proto(),
                };
                (
                    "type.googleapis.com/protocol.FreezeBalanceV2Contract".into(),
                    c.encode_to_vec(),
                    ContractType::FreezeBalanceV2Contract,
                )
            }
            TronContractCall::UnfreezeBalanceV2 {
                unfreeze_balance,
                resource,
            } => {
                let c = protocol::UnfreezeBalanceV2Contract {
                    owner_address: owner,
                    unfreeze_balance: *unfreeze_balance,
                    resource: resource.to_proto(),
                };
                (
                    "type.googleapis.com/protocol.UnfreezeBalanceV2Contract".into(),
                    c.encode_to_vec(),
                    ContractType::UnfreezeBalanceV2Contract,
                )
            }
            TronContractCall::WithdrawExpireUnfreeze => {
                let c = protocol::WithdrawExpireUnfreezeContract {
                    owner_address: owner,
                };
                (
                    "type.googleapis.com/protocol.WithdrawExpireUnfreezeContract".into(),
                    c.encode_to_vec(),
                    ContractType::WithdrawExpireUnfreezeContract,
                )
            }
            TronContractCall::DelegateResource {
                resource,
                balance,
                receiver_address,
                lock,
                lock_period,
            } => {
                let c = protocol::DelegateResourceContract {
                    owner_address: owner,
                    resource: resource.to_proto(),
                    balance: *balance,
                    receiver_address: addr_to_tron_bytes(receiver_address),
                    lock: *lock,
                    lock_period: *lock_period,
                };
                (
                    "type.googleapis.com/protocol.DelegateResourceContract".into(),
                    c.encode_to_vec(),
                    ContractType::DelegateResourceContract,
                )
            }
            TronContractCall::UnDelegateResource {
                resource,
                balance,
                receiver_address,
            } => {
                let c = protocol::UnDelegateResourceContract {
                    owner_address: owner,
                    resource: resource.to_proto(),
                    balance: *balance,
                    receiver_address: addr_to_tron_bytes(receiver_address),
                };
                (
                    "type.googleapis.com/protocol.UnDelegateResourceContract".into(),
                    c.encode_to_vec(),
                    ContractType::UnDelegateResourceContract,
                )
            }
            TronContractCall::CancelAllUnfreezeV2 => {
                let c = protocol::CancelAllUnfreezeV2Contract {
                    owner_address: owner,
                };
                (
                    "type.googleapis.com/protocol.CancelAllUnfreezeV2Contract".into(),
                    c.encode_to_vec(),
                    ContractType::CancelAllUnfreezeV2Contract,
                )
            }
            TronContractCall::TransferAsset {
                asset_name,
                to_address,
                amount,
            } => {
                let c = protocol::TransferAssetContract {
                    asset_name: asset_name.clone(),
                    owner_address: owner,
                    to_address: addr_to_tron_bytes(to_address),
                    amount: *amount,
                };
                (
                    "type.googleapis.com/protocol.TransferAssetContract".into(),
                    c.encode_to_vec(),
                    ContractType::TransferAssetContract,
                )
            }
            TronContractCall::VoteWitness { votes } => {
                let vote_list = votes
                    .iter()
                    .map(|(addr, count)| protocol::vote_witness_contract::Vote {
                        vote_address: addr_to_tron_bytes(addr),
                        vote_count: *count,
                    })
                    .collect();
                let c = protocol::VoteWitnessContract {
                    owner_address: owner,
                    votes: vote_list,
                    support: false,
                };
                (
                    "type.googleapis.com/protocol.VoteWitnessContract".into(),
                    c.encode_to_vec(),
                    ContractType::VoteWitnessContract,
                )
            }
            TronContractCall::AccountCreate {
                account_address,
                account_type,
            } => {
                let c = protocol::AccountCreateContract {
                    owner_address: owner,
                    account_address: addr_to_tron_bytes(account_address),
                    r#type: *account_type,
                };
                (
                    "type.googleapis.com/protocol.AccountCreateContract".into(),
                    c.encode_to_vec(),
                    ContractType::AccountCreateContract,
                )
            }
            TronContractCall::AccountUpdate { account_name } => {
                let c = protocol::AccountUpdateContract {
                    account_name: account_name.clone(),
                    owner_address: owner,
                };
                (
                    "type.googleapis.com/protocol.AccountUpdateContract".into(),
                    c.encode_to_vec(),
                    ContractType::AccountUpdateContract,
                )
            }
            TronContractCall::WitnessCreate { url } => {
                let c = protocol::WitnessCreateContract {
                    owner_address: owner,
                    url: url.clone(),
                };
                (
                    "type.googleapis.com/protocol.WitnessCreateContract".into(),
                    c.encode_to_vec(),
                    ContractType::WitnessCreateContract,
                )
            }
            TronContractCall::WitnessUpdate { update_url } => {
                let c = protocol::WitnessUpdateContract {
                    owner_address: owner,
                    update_url: update_url.clone(),
                };
                (
                    "type.googleapis.com/protocol.WitnessUpdateContract".into(),
                    c.encode_to_vec(),
                    ContractType::WitnessUpdateContract,
                )
            }
            TronContractCall::CreateSmartContract {
                new_contract,
                call_token_value,
                token_id,
            } => {
                let c = protocol::CreateSmartContract {
                    owner_address: owner,
                    new_contract: Some(
                        protocol::SmartContract::decode(new_contract.as_slice())
                            .unwrap_or_default(),
                    ),
                    call_token_value: *call_token_value,
                    token_id: *token_id,
                };
                (
                    "type.googleapis.com/protocol.CreateSmartContract".into(),
                    c.encode_to_vec(),
                    ContractType::CreateSmartContract,
                )
            }
            TronContractCall::ProposalCreate { parameters } => {
                let c = protocol::ProposalCreateContract {
                    owner_address: owner,
                    parameters: parameters.iter().cloned().collect(),
                };
                (
                    "type.googleapis.com/protocol.ProposalCreateContract".into(),
                    c.encode_to_vec(),
                    ContractType::ProposalCreateContract,
                )
            }
            TronContractCall::ProposalApprove {
                proposal_id,
                is_add_approval,
            } => {
                let c = protocol::ProposalApproveContract {
                    owner_address: owner,
                    proposal_id: *proposal_id,
                    is_add_approval: *is_add_approval,
                };
                (
                    "type.googleapis.com/protocol.ProposalApproveContract".into(),
                    c.encode_to_vec(),
                    ContractType::ProposalApproveContract,
                )
            }
            TronContractCall::ProposalDelete { proposal_id } => {
                let c = protocol::ProposalDeleteContract {
                    owner_address: owner,
                    proposal_id: *proposal_id,
                };
                (
                    "type.googleapis.com/protocol.ProposalDeleteContract".into(),
                    c.encode_to_vec(),
                    ContractType::ProposalDeleteContract,
                )
            }
            TronContractCall::AccountPermissionUpdate { raw_data } => (
                "type.googleapis.com/protocol.AccountPermissionUpdateContract".into(),
                raw_data.clone(),
                ContractType::AccountPermissionUpdateContract,
            ),
        }
    }

    pub fn to_raw_data_bytes(&self) -> Vec<u8> {
        let (type_url, value, contract_type) = self.encode_contract();

        let contract = protocol::transaction::Contract {
            r#type: contract_type as i32,
            parameter: Some(prost_types::Any { type_url, value }),
            provider: Vec::new(),
            contract_name: Vec::new(),
            permission_id: 0,
        };

        let raw = protocol::transaction::Raw {
            ref_block_bytes: self.ref_block_bytes.clone(),
            ref_block_num: 0,
            ref_block_hash: self.ref_block_hash.clone(),
            expiration: self.expiration,
            auths: Vec::new(),
            data: Vec::new(),
            contract: vec![contract],
            scripts: Vec::new(),
            timestamp: self.timestamp,
            fee_limit: self.fee_limit,
        };

        raw.encode_to_vec()
    }

    pub fn tx_id(&self) -> [u8; 32] {
        let raw_bytes = self.to_raw_data_bytes();
        let hash = Sha256::digest(&raw_bytes);
        hash.into()
    }

    pub fn to_address(&self) -> Address {
        match &self.contract {
            TronContractCall::Transfer { to_address, .. } => to_address.clone(),
            TronContractCall::TriggerSmartContract {
                contract_address, ..
            } => contract_address.clone(),
            TronContractCall::DelegateResource {
                receiver_address, ..
            } => receiver_address.clone(),
            TronContractCall::UnDelegateResource {
                receiver_address, ..
            } => receiver_address.clone(),
            TronContractCall::TransferAsset { to_address, .. } => to_address.clone(),
            TronContractCall::AccountCreate {
                account_address, ..
            } => account_address.clone(),
            _ => self.owner_address.clone(),
        }
    }
}

impl TronTransactionReceipt {
    pub fn verify(&self) -> Result<bool, errors::tx::TransactionErrors> {
        use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};

        let hash = Sha256::digest(&self.raw_data_bytes);
        let computed_id: [u8; 32] = hash.into();
        if computed_id != self.tx_id {
            return Ok(false);
        }

        if self.signature.len() != 65 {
            return Ok(false);
        }

        let sig = Signature::from_slice(&self.signature[..64])
            .map_err(|_| errors::tx::TransactionErrors::InvalidSignature)?;
        let recovery_id = RecoveryId::try_from(self.signature[64])
            .map_err(|_| errors::tx::TransactionErrors::InvalidSignature)?;

        let recovered_key = VerifyingKey::recover_from_prehash(&self.tx_id, &sig, recovery_id)
            .map_err(|_| errors::tx::TransactionErrors::InvalidSignature)?;

        let addr = alloy::primitives::Address::from_public_key(&recovered_key);
        let addr_bytes: [u8; ADDR_LEN] = addr.into();

        Ok(addr_bytes == *self.owner_address.as_ref())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keypair::KeyPair;
    use k256::ecdsa::SigningKey;

    fn sign_tron_tx(request: &TronTransactionRequest, keypair: &KeyPair) -> TronTransactionReceipt {
        let raw_data_bytes = request.to_raw_data_bytes();
        let tx_id = Sha256::digest(&raw_data_bytes);
        let tx_id: [u8; 32] = tx_id.into();

        let sk_bytes = keypair.get_sk_bytes();
        let signing_key = SigningKey::from_slice(&sk_bytes).unwrap();
        let (sig, recovery_id) = signing_key.sign_prehash_recoverable(&tx_id).unwrap();

        let mut signature = sig.to_bytes().to_vec();
        signature.push(recovery_id.to_byte());

        TronTransactionReceipt {
            raw_data_bytes,
            tx_id,
            signature,
            owner_address: request.owner_address.clone(),
            contract: request.contract.clone(),
        }
    }

    #[test]
    fn test_transfer_sign_verify() {
        let keypair = KeyPair::gen_tron().unwrap();
        let owner = keypair.get_addr().unwrap();
        let to = KeyPair::gen_tron().unwrap().get_addr().unwrap();

        let request = TronTransactionRequest {
            owner_address: owner,
            ref_block_bytes: vec![0x00, 0x01],
            ref_block_hash: vec![0xab; 8],
            expiration: 1700000000000,
            timestamp: 1699999990000,
            fee_limit: 0,
            contract: TronContractCall::Transfer {
                to_address: to,
                amount: 1_000_000,
            },
        };

        let receipt = sign_tron_tx(&request, &keypair);
        assert!(receipt.verify().unwrap());
    }

    #[test]
    fn test_trigger_smart_contract_sign_verify() {
        let keypair = KeyPair::gen_tron().unwrap();
        let owner = keypair.get_addr().unwrap();
        let contract_addr = KeyPair::gen_tron().unwrap().get_addr().unwrap();

        let mut data = Vec::new();
        data.extend_from_slice(&hex::decode("a9059cbb").unwrap());
        data.extend_from_slice(&[0u8; 12]);
        data.extend_from_slice(contract_addr.as_ref());
        data.extend_from_slice(&[0u8; 31]);
        data.push(0x01);

        let request = TronTransactionRequest {
            owner_address: owner,
            ref_block_bytes: vec![0x00, 0x02],
            ref_block_hash: vec![0xcd; 8],
            expiration: 1700000000000,
            timestamp: 1699999990000,
            fee_limit: 100_000_000,
            contract: TronContractCall::TriggerSmartContract {
                contract_address: contract_addr,
                call_value: 0,
                data,
                call_token_value: 0,
                token_id: 0,
            },
        };

        let receipt = sign_tron_tx(&request, &keypair);
        assert!(receipt.verify().unwrap());
    }

    #[test]
    fn test_with_external_signature() {
        let keypair = KeyPair::gen_tron().unwrap();
        let owner = keypair.get_addr().unwrap();
        let to = KeyPair::gen_tron().unwrap().get_addr().unwrap();

        let request = TronTransactionRequest {
            owner_address: owner.clone(),
            ref_block_bytes: vec![0x00, 0x03],
            ref_block_hash: vec![0xef; 8],
            expiration: 1700000000000,
            timestamp: 1699999990000,
            fee_limit: 0,
            contract: TronContractCall::Transfer {
                to_address: to,
                amount: 500_000,
            },
        };

        let raw_data_bytes = request.to_raw_data_bytes();
        let tx_id: [u8; 32] = Sha256::digest(&raw_data_bytes).into();

        let sk_bytes = keypair.get_sk_bytes();
        let signing_key = SigningKey::from_slice(&sk_bytes).unwrap();
        let (sig, recovery_id) = signing_key.sign_prehash_recoverable(&tx_id).unwrap();
        let mut signature = sig.to_bytes().to_vec();
        signature.push(recovery_id.to_byte());

        let receipt = TronTransactionReceipt {
            raw_data_bytes,
            tx_id,
            signature,
            owner_address: owner,
            contract: request.contract.clone(),
        };

        assert!(receipt.verify().unwrap());
    }

    #[test]
    fn test_wrong_keypair_fails_verification() {
        let keypair1 = KeyPair::gen_tron().unwrap();
        let keypair2 = KeyPair::gen_tron().unwrap();
        let owner1 = keypair1.get_addr().unwrap();
        let to = keypair2.get_addr().unwrap();

        let request = TronTransactionRequest {
            owner_address: owner1,
            ref_block_bytes: vec![0x00, 0x04],
            ref_block_hash: vec![0x11; 8],
            expiration: 1700000000000,
            timestamp: 1699999990000,
            fee_limit: 0,
            contract: TronContractCall::Transfer {
                to_address: to,
                amount: 100_000,
            },
        };

        let receipt = sign_tron_tx(&request, &keypair2);
        assert!(!receipt.verify().unwrap());
    }

    #[test]
    fn test_to_address() {
        let keypair = KeyPair::gen_tron().unwrap();
        let owner = keypair.get_addr().unwrap();
        let to = KeyPair::gen_tron().unwrap().get_addr().unwrap();

        let request = TronTransactionRequest {
            owner_address: owner.clone(),
            ref_block_bytes: vec![0x00, 0x05],
            ref_block_hash: vec![0x22; 8],
            expiration: 1700000000000,
            timestamp: 1699999990000,
            fee_limit: 0,
            contract: TronContractCall::Transfer {
                to_address: to.clone(),
                amount: 100_000,
            },
        };

        assert_eq!(request.to_address(), to);

        let freeze_request = TronTransactionRequest {
            owner_address: owner.clone(),
            ref_block_bytes: vec![0x00, 0x06],
            ref_block_hash: vec![0x33; 8],
            expiration: 1700000000000,
            timestamp: 1699999990000,
            fee_limit: 0,
            contract: TronContractCall::FreezeBalanceV2 {
                frozen_balance: 10_000_000,
                resource: TronResource::Energy,
            },
        };

        assert_eq!(freeze_request.to_address(), owner);
    }

    #[test]
    fn test_protobuf_roundtrip() {
        let keypair = KeyPair::gen_tron().unwrap();
        let owner = keypair.get_addr().unwrap();
        let to = KeyPair::gen_tron().unwrap().get_addr().unwrap();

        let request = TronTransactionRequest {
            owner_address: owner,
            ref_block_bytes: vec![0x00, 0x07],
            ref_block_hash: vec![0x44; 8],
            expiration: 1700000000000,
            timestamp: 1699999990000,
            fee_limit: 0,
            contract: TronContractCall::Transfer {
                to_address: to,
                amount: 2_000_000,
            },
        };

        let raw_bytes = request.to_raw_data_bytes();

        let decoded = protocol::transaction::Raw::decode(raw_bytes.as_slice()).unwrap();
        assert_eq!(decoded.ref_block_bytes, vec![0x00, 0x07]);
        assert_eq!(decoded.ref_block_hash, vec![0x44; 8]);
        assert_eq!(decoded.expiration, 1700000000000);
        assert_eq!(decoded.timestamp, 1699999990000);
        assert_eq!(decoded.contract.len(), 1);

        let contract = &decoded.contract[0];
        assert_eq!(contract.r#type, ContractType::TransferContract as i32);
        let any = contract.parameter.as_ref().unwrap();
        let transfer = protocol::TransferContract::decode(any.value.as_slice()).unwrap();
        assert_eq!(transfer.amount, 2_000_000);
    }

    #[test]
    fn test_freeze_balance_v2_sign_verify() {
        let keypair = KeyPair::gen_tron().unwrap();
        let owner = keypair.get_addr().unwrap();

        let request = TronTransactionRequest {
            owner_address: owner,
            ref_block_bytes: vec![0x00, 0x08],
            ref_block_hash: vec![0x55; 8],
            expiration: 1700000000000,
            timestamp: 1699999990000,
            fee_limit: 0,
            contract: TronContractCall::FreezeBalanceV2 {
                frozen_balance: 10_000_000,
                resource: TronResource::Energy,
            },
        };

        let receipt = sign_tron_tx(&request, &keypair);
        assert!(receipt.verify().unwrap());
    }

    #[test]
    fn test_delegate_resource_sign_verify() {
        let keypair = KeyPair::gen_tron().unwrap();
        let owner = keypair.get_addr().unwrap();
        let receiver = KeyPair::gen_tron().unwrap().get_addr().unwrap();

        let request = TronTransactionRequest {
            owner_address: owner,
            ref_block_bytes: vec![0x00, 0x09],
            ref_block_hash: vec![0x66; 8],
            expiration: 1700000000000,
            timestamp: 1699999990000,
            fee_limit: 0,
            contract: TronContractCall::DelegateResource {
                resource: TronResource::Bandwidth,
                balance: 5_000_000,
                receiver_address: receiver,
                lock: false,
                lock_period: 0,
            },
        };

        let receipt = sign_tron_tx(&request, &keypair);
        assert!(receipt.verify().unwrap());
    }
}
