use async_trait::async_trait;
use serde::de::DeserializeOwned;
use serde_json::Value;
use std::fmt::Debug;
use zil_errors::rpc::RpcError;

pub type Result<T> = std::result::Result<T, RpcError>;

pub trait RpcMethod: ToString {}

pub trait NetworkConfigTrait {
    fn nodes(&self) -> &[String];
    fn default_node(&self) -> &str;

    fn add_node(&mut self, node: String) -> Result<()>;
    fn add_node_group(&mut self, nodes: Vec<String>) -> Result<()>;

    fn remove_node_group(&mut self, indexes: Vec<usize>) -> Result<()>;
    fn remove_node(&mut self, node_index: usize) -> Result<()>;
}

#[async_trait]
pub trait JsonRPC {
    const MAX_ERROR: usize = 5;
    type Method: RpcMethod;

    fn get_nodes(&self) -> &[String];

    async fn req<SR>(&self, payloads: &[Value]) -> Result<SR>
    where
        SR: DeserializeOwned + Debug;
}
