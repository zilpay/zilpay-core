use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum TokenType {
    Native(String),
    ERC20(String),
    ERC721(String),
    ERC1155(String),
}
