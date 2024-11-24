pub const ZIL_MAIN_SCILLA_URL: &str = "https://api.zilliqa.com";
pub const PROTO_TESTNET: &str = "https://api.zq2-prototestnet.zilliqa.com/";
pub const SYS_SIZE: usize = std::mem::size_of::<usize>();

pub mod address;
pub mod argon;
pub mod cipher;
pub mod contracts;
pub mod key;
pub mod sha;
pub mod storage;
pub mod wallet;
