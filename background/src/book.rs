use proto::address::Address;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressBookEntry {
    pub name: String,
    pub addr: Address,
    pub net: usize,
    pub slip44: u32,
}

impl AddressBookEntry {
    pub fn add(name: String, addr: Address, net: usize, slip44: u32) -> Self {
        Self {
            name,
            addr,
            net,
            slip44,
        }
    }
}
