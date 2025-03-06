use config::storage::ADDRESS_BOOK_DB_KEY_V1;
use errors::background::BackgroundError;

use crate::book::AddressBookEntry;
use crate::{Background, Result};

/// Manages the address book functionality
pub trait AddressBookManagement {
    type Error;

    /// Retrieves all address book entries
    fn get_address_book(&self) -> Vec<AddressBookEntry>;

    /// Adds a new entry to the address book
    fn add_to_address_book(
        &self,
        address: AddressBookEntry,
    ) -> std::result::Result<(), Self::Error>;
}

impl AddressBookManagement for Background {
    type Error = BackgroundError;

    fn get_address_book(&self) -> Vec<AddressBookEntry> {
        let bytes = self.storage.get(ADDRESS_BOOK_DB_KEY_V1).unwrap_or_default();

        if bytes.is_empty() {
            return Vec::with_capacity(1);
        }

        bincode::deserialize(&bytes).unwrap_or(Vec::with_capacity(1))
    }

    fn add_to_address_book(&self, address: AddressBookEntry) -> Result<()> {
        let mut book = self.get_address_book();

        if book.iter().any(|c| c.addr == address.addr) {
            return Err(BackgroundError::AddressAlreadyExists(
                address.addr.auto_format(),
            ));
        }

        book.push(address);

        let bytes =
            bincode::serialize(&book).or(Err(BackgroundError::FailToSerializeAddressBook))?;

        self.storage.set(ADDRESS_BOOK_DB_KEY_V1, &bytes)?;
        self.storage.flush()?;

        Ok(())
    }
}

#[cfg(test)]
mod tests_background {
    use proto::address::Address;
    use rand::Rng;

    use crate::bg_storage::StorageManagement;

    use super::*;

    fn setup_test_background() -> (Background, String) {
        let mut rng = rand::thread_rng();
        let dir = format!("/tmp/{}", rng.gen::<usize>());
        let bg = Background::from_storage_path(&dir).unwrap();
        (bg, dir)
    }

    #[test]
    fn test_address_book() {
        let (bg, dir) = setup_test_background();
        // Test empty address book
        let book = bg.get_address_book();
        assert!(book.is_empty());

        // Create test address
        let name = "Test Contact".to_string();
        let address =
            Address::from_eth_address("0x1234567890123456789012345678901234567890").unwrap();
        let entry = AddressBookEntry {
            name,
            addr: address.clone(),
            net: 0,
        };

        // Add address to book
        bg.add_to_address_book(entry.clone()).unwrap();

        // Verify address was added
        let book = bg.get_address_book();
        assert_eq!(book.len(), 1);
        assert_eq!(&book[0].name, "Test Contact");
        assert_eq!(&book[0].addr, &address);
        // Add another address
        let name2 = "Second Contact".to_string();
        let address2 =
            Address::from_eth_address("0xabcdefabcdefabcdefabcdefabcdefabcdefabcd").unwrap();
        let entry2 = AddressBookEntry {
            name: name2,
            addr: address2.clone(),
            net: 0,
        };

        bg.add_to_address_book(entry2.clone()).unwrap();

        // Verify both addresses exist
        let book = bg.get_address_book();
        assert_eq!(book.len(), 2);
        assert_eq!(book[1].name, "Second Contact");
        assert_eq!(book[1].addr, address2);

        // Test persistence - create new instance
        drop(bg);
        let bg2 = Background::from_storage_path(&dir).unwrap();
        let book = bg2.get_address_book();

        assert_eq!(book.len(), 2);
        assert_eq!(book[0].name, "Test Contact");
        assert_eq!(book[0].addr, address);
        assert_eq!(book[1].name, "Second Contact");
        assert_eq!(book[1].addr, address2);
    }
}
