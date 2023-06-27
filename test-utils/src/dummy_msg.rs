use async_graphql::SimpleObject;
use ethers_contract::EthAbiType;
use ethers_core::types::transaction::eip712::Eip712;
use ethers_derive_eip712::*;
use prost::Message;
use serde::{Deserialize, Serialize};

#[derive(Eip712, EthAbiType, Clone, Message, Serialize, Deserialize, SimpleObject)]
#[eip712(
    name = "Graphcast POI Radio Dummy Msg",
    version = "0",
    chain_id = 1,
    verifying_contract = "0xc944e90c64b2c07662a292be6244bdf05cda44a7"
)]
pub struct DummyMsg {
    #[prost(string, tag = "1")]
    pub identifier: String,
    #[prost(int32, tag = "2")]
    pub dummy_value: i32,
}

impl DummyMsg {
    pub fn new(identifier: String, dummy_value: i32) -> Self {
        DummyMsg {
            identifier,
            dummy_value,
        }
    }

    pub fn from_ref(dummy_msg: &DummyMsg) -> Self {
        DummyMsg {
            identifier: dummy_msg.identifier.clone(),
            dummy_value: dummy_msg.dummy_value,
        }
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap()
    }

    pub fn from_json(s: &str) -> Self {
        serde_json::from_str(s).unwrap()
    }
}
