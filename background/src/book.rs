use proto::address::Address;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressBookEntry {
    pub name: String,
    pub addr: Address,
}

impl AddressBookEntry {
    pub fn add(name: String, addr: Address) -> Self {
        Self { name, addr }
    }
}
