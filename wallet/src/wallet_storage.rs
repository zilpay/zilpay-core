use crate::wallet_data::WalletData;
use crate::wallet_token::TokenManagement;
use crate::wallet_transaction::WalletTransaction;
use crate::Result;
use crate::Wallet;
use crate::WalletAddrType;
use errors::wallet::WalletErrors;
use history::transaction::HistoricalTransaction;
use proto::tx::TransactionRequest;
use rand::Rng;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::sync::Arc;
use storage::LocalStorage;
use token::ft::FToken;

pub trait StorageOperations {
    type Error;

    fn init_wallet(
        wallet_address: WalletAddrType,
        storage: Arc<LocalStorage>,
    ) -> std::result::Result<Self, Self::Error>
    where
        Self: Sized;
    fn safe_storage_save(
        cipher_entropy: &[u8],
        storage: Arc<LocalStorage>,
    ) -> std::result::Result<usize, Self::Error>;
    fn save_wallet_data(&self, data: WalletData) -> std::result::Result<(), Self::Error>;
    fn save_ftokens(&self, ftokens: &[FToken]) -> std::result::Result<(), Self::Error>;
    fn save_request_txns(
        &self,
        req_txns: &[TransactionRequest],
    ) -> std::result::Result<(), Self::Error>;
    fn save_history(
        &self,
        history: &[HistoricalTransaction],
    ) -> std::result::Result<(), Self::Error>;
    fn get_wallet_data(&self) -> std::result::Result<WalletData, Self::Error>;
    fn get_request_txns(&self) -> std::result::Result<Vec<TransactionRequest>, Self::Error>;
    fn get_history(&self) -> std::result::Result<Vec<HistoricalTransaction>, Self::Error>;
    fn get_ftokens(&self) -> std::result::Result<Vec<FToken>, Self::Error>;
    fn clear_data(&self) -> std::result::Result<(), Self::Error>;
}

impl StorageOperations for Wallet {
    type Error = WalletErrors;

    fn init_wallet(wallet_address: WalletAddrType, storage: Arc<LocalStorage>) -> Result<Self> {
        Ok(Self {
            storage,
            wallet_address,
        })
    }

    fn clear_data(&self) -> Result<()> {
        self.storage.remove(self.wallet_address.as_slice())?;

        Ok(())
    }

    fn get_wallet_data(&self) -> Result<WalletData> {
        let bytes = self.storage.get(self.wallet_address.as_slice())?;
        let data = bincode::deserialize(&bytes)?;

        Ok(data)
    }

    fn get_ftokens(&self) -> Result<Vec<FToken>> {
        let ftokens_key = Wallet::get_token_db_key(&self.wallet_address);
        let bytes = match self.storage.get(&ftokens_key) {
            Ok(b) => b,
            Err(_) => return Ok(Vec::with_capacity(0)),
        };
        let ftokens: Vec<FToken> = bincode::deserialize(&bytes)?;

        Ok(ftokens)
    }

    fn get_request_txns(&self) -> Result<Vec<TransactionRequest>> {
        let req_txns_key = Wallet::get_db_request_transactions_key(&self.wallet_address);
        let bytes = match self.storage.get(&req_txns_key) {
            Ok(b) => b,
            Err(_) => return Ok(Vec::with_capacity(0)),
        };
        let req_txns: Vec<TransactionRequest> = bincode::deserialize(&bytes)?;

        Ok(req_txns)
    }

    fn get_history(&self) -> Result<Vec<HistoricalTransaction>> {
        let history_db_key = Wallet::get_db_history_key(&self.wallet_address);
        let bytes = match self.storage.get(&history_db_key) {
            Ok(b) => b,
            Err(_) => return Ok(Vec::with_capacity(0)),
        };
        let history: Vec<HistoricalTransaction> = bincode::deserialize(&bytes)?;

        Ok(history)
    }

    fn safe_storage_save(cipher_entropy: &[u8], storage: Arc<LocalStorage>) -> Result<usize> {
        let mut rng = ChaCha20Rng::from_entropy();
        let mut cipher_entropy_key: usize;

        loop {
            cipher_entropy_key = rng.gen();
            let key = usize::to_le_bytes(cipher_entropy_key);
            let is_exists_key = storage.exists(&key)?;

            if is_exists_key {
                continue;
            }

            storage.set(&key, cipher_entropy)?;

            break;
        }

        Ok(cipher_entropy_key)
    }

    fn save_wallet_data(&self, data: WalletData) -> Result<()> {
        let bytes = bincode::serialize(&data)?;

        self.storage.set(&self.wallet_address, &bytes)?;
        self.storage.flush()?;

        Ok(())
    }

    fn save_ftokens(&self, ftokens: &[FToken]) -> std::result::Result<(), Self::Error> {
        let ft_bytes = bincode::serialize(ftokens)?;
        let token_key = Wallet::get_token_db_key(&self.wallet_address);

        self.storage.set(&token_key, &ft_bytes)?;
        self.storage.flush()?;

        Ok(())
    }

    fn save_request_txns(&self, req_txns: &[TransactionRequest]) -> Result<()> {
        let req_txns_bytes = bincode::serialize(req_txns)?;
        let req_txns_db_key = Wallet::get_db_request_transactions_key(&self.wallet_address);

        self.storage.set(&req_txns_db_key, &req_txns_bytes)?;
        self.storage.flush()?;

        Ok(())
    }

    fn save_history(
        &self,
        history: &[HistoricalTransaction],
    ) -> std::result::Result<(), Self::Error> {
        let history_bytes = bincode::serialize(history)?;
        let history_db_key = Wallet::get_db_history_key(&self.wallet_address);

        self.storage.set(&history_db_key, &history_bytes)?;
        self.storage.flush()?;

        Ok(())
    }
}

#[cfg(test)]
mod tests_wallet_storage {
    use super::*;
    use crate::{
        wallet_data::{AuthMethod, WalletData},
        wallet_types::WalletTypes,
    };
    use config::sha::SHA256_SIZE;
    use proto::{address::Address, tx::TransactionRequest, zil_tx::ZILTransactionRequest};
    use settings::wallet_settings::WalletSettings;
    use std::sync::Arc;
    use storage::LocalStorage;
    use token::ft::FToken;

    fn setup() -> (WalletAddrType, Arc<LocalStorage>) {
        let mut rng = rand::thread_rng();
        let dir = format!("/tmp/{}", rng.gen::<usize>());
        let wallet_address = [42u8; SHA256_SIZE];
        let storage = Arc::new(LocalStorage::from(&dir).unwrap());

        (wallet_address, storage)
    }

    #[test]
    fn test_init_wallet() {
        let (wallet_address, storage) = setup();
        let wallet = Wallet::init_wallet(wallet_address, storage.clone());
        assert!(wallet.is_ok());

        let wallet = wallet.unwrap();
        assert_eq!(wallet.wallet_address, wallet_address);
    }

    #[test]
    fn test_safe_storage_save() {
        let (_, storage) = setup();
        let cipher_entropy = vec![1, 2, 3, 4, 5];

        let result = Wallet::safe_storage_save(&cipher_entropy, storage.clone());
        assert!(result.is_ok());

        let key = result.unwrap();
        let stored_data = storage.get(&usize::to_le_bytes(key));
        assert!(stored_data.is_ok());
        assert_eq!(stored_data.unwrap(), cipher_entropy);
    }

    #[test]
    fn test_wallet_data_operations() {
        let (wallet_address, storage) = setup();
        let wallet = Wallet::init_wallet(wallet_address, storage).unwrap();

        // Create test wallet data
        let test_data = WalletData {
            proof_key: 0,
            wallet_type: WalletTypes::SecretKey,
            settings: WalletSettings::default(),
            wallet_name: String::new(),
            accounts: Vec::new(),
            selected_account: 0,
            biometric_type: AuthMethod::None,
        };

        // Test saving wallet data
        assert!(wallet.save_wallet_data(test_data.clone()).is_ok());

        // Test retrieving wallet data
        let retrieved_data = wallet.get_wallet_data();
        assert!(retrieved_data.is_ok());
        assert_eq!(retrieved_data.unwrap(), test_data);
    }

    #[test]
    fn test_ftoken_operations() {
        let (wallet_address, storage) = setup();
        let wallet = Wallet::init_wallet(wallet_address, storage).unwrap();

        // Create test tokens
        let test_tokens = vec![FToken::zil(0)];

        // Test saving tokens
        assert!(wallet.save_ftokens(&test_tokens).is_ok());

        // Test retrieving tokens
        let retrieved_tokens = wallet.get_ftokens();
        assert!(retrieved_tokens.is_ok());
        assert_eq!(retrieved_tokens.unwrap(), test_tokens);
    }

    #[test]
    fn test_transaction_request_operations() {
        let (wallet_address, storage) = setup();
        let wallet = Wallet::init_wallet(wallet_address, storage).unwrap();

        let tx_req = ZILTransactionRequest {
            chain_id: 42,
            nonce: 1,
            gas_price: 2000 / 10u128.pow(6),
            gas_limit: 100000,
            to_addr: Address::Secp256k1Sha256Zilliqa(Address::ZERO),
            amount: 1 / 10u128.pow(6),
            code: Vec::new(),
            data: Vec::new(),
        };

        // Create test transaction requests
        let test_txns = vec![TransactionRequest::Zilliqa((tx_req, Default::default()))];

        // Test saving transaction requests
        assert!(wallet.save_request_txns(&test_txns).is_ok());

        // Test retrieving transaction requests
        let retrieved_txns = wallet.get_request_txns();
        assert!(retrieved_txns.is_ok());
        assert_eq!(retrieved_txns.unwrap(), test_txns);
    }

    #[test]
    fn test_empty_storage_retrieval() {
        let (wallet_address, storage) = setup();
        let wallet = Wallet::init_wallet(wallet_address, storage).unwrap();

        // Test retrieving from empty storage
        let empty_tokens = wallet.get_ftokens();
        assert!(empty_tokens.is_ok());
        assert!(empty_tokens.unwrap().is_empty());

        let empty_txns = wallet.get_request_txns();
        assert!(empty_txns.is_ok());
        assert!(empty_txns.unwrap().is_empty());

        let empty_history = wallet.get_history();
        assert!(empty_history.is_ok());
        assert!(empty_history.unwrap().is_empty());
    }
}
