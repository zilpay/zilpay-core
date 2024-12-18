use proto::address::Address;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressBookEntry {
    pub name: String,
    pub addr: Address,
    pub net: usize,
}

impl AddressBookEntry {
    pub fn add(name: String, addr: Address, net: usize) -> Self {
        Self { name, addr, net }
    }
}
