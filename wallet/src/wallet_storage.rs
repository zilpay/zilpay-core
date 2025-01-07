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
}

impl StorageOperations for Wallet {
    type Error = WalletErrors;

    fn init_wallet(wallet_address: WalletAddrType, storage: Arc<LocalStorage>) -> Result<Self> {
        Ok(Self {
            storage,
            wallet_address,
        })
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
        self.storage
            .set(self.wallet_address.as_slice(), &data.to_bytes()?)?;
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
