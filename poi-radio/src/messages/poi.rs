use async_graphql::SimpleObject;
use ethers_contract::EthAbiType;
use ethers_core::types::transaction::eip712::Eip712;
use ethers_derive_eip712::*;
use graphcast_sdk::{
    graphcast_agent::message_typing::{BuildMessageError, GraphcastMessage},
    graphql::client_graph_node::query_graph_node_network_block_hash,
    networks::NetworkName,
};
use prost::Message;
use serde::{Deserialize, Serialize};
use tracing::trace;

#[derive(Eip712, EthAbiType, Clone, Message, Serialize, Deserialize, PartialEq, SimpleObject)]
#[eip712(
    name = "PublicPoiMessage",
    version = "0",
    chain_id = 1,
    verifying_contract = "0xc944e90c64b2c07662a292be6244bdf05cda44a7"
)]
pub struct PublicPoiMessage {
    #[prost(string, tag = "1")]
    pub identifier: String,
    #[prost(string, tag = "2")]
    pub content: String,
    //TODO: see if timestamp that comes with waku message can be used
    /// nonce cached to check against the next incoming message
    #[prost(int64, tag = "3")]
    pub nonce: i64,
    /// blockchain relevant to the message
    #[prost(string, tag = "4")]
    pub network: String,
    /// block relevant to the message
    #[prost(uint64, tag = "5")]
    pub block_number: u64,
    /// block hash generated from the block number
    #[prost(string, tag = "6")]
    pub block_hash: String,
    /// Graph account sender
    #[prost(string, tag = "7")]
    pub graph_account: String,
}

impl PublicPoiMessage {
    pub fn new(
        identifier: String,
        content: String,
        nonce: i64,
        network: String,
        block_number: u64,
        block_hash: String,
        graph_account: String,
    ) -> Self {
        PublicPoiMessage {
            identifier,
            content,
            nonce,
            network,
            block_number,
            block_hash,
            graph_account,
        }
    }

    pub fn build(
        identifier: String,
        content: String,
        nonce: i64,
        network: NetworkName,
        block_number: u64,
        block_hash: String,
        graph_account: String,
    ) -> Self {
        PublicPoiMessage::new(
            identifier,
            content,
            nonce,
            network.to_string(),
            block_number,
            block_hash,
            graph_account,
        )
    }

    pub fn payload_content(&self) -> String {
        self.content.clone()
    }

    // Check for the valid hash between local graph node and gossip
    pub async fn valid_hash(&self, graph_node_endpoint: &str) -> Result<&Self, BuildMessageError> {
        let block_hash: String = query_graph_node_network_block_hash(
            graph_node_endpoint,
            &self.network,
            self.block_number,
        )
        .await
        .map_err(BuildMessageError::FieldDerivations)?;

        trace!(
            network = tracing::field::debug(self.network.clone()),
            block_number = self.block_number,
            block_hash = block_hash,
            "Queried block hash from graph node",
        );

        if self.block_hash == block_hash {
            Ok(self)
        } else {
            Err(BuildMessageError::InvalidFields(anyhow::anyhow!(
                "Message hash ({}) differ from trusted provider response ({}), drop message",
                self.block_hash,
                block_hash
            )))
        }
    }

    /// Check duplicated fields: payload message has duplicated fields with GraphcastMessage, the values must be the same
    pub fn valid_outer(&self, outer: &GraphcastMessage<Self>) -> Result<&Self, BuildMessageError> {
        if self.nonce == outer.nonce
            && self.graph_account == outer.graph_account
            && self.identifier == outer.identifier
        {
            Ok(self)
        } else {
            Err(BuildMessageError::InvalidFields(anyhow::anyhow!(
                "Radio message wrapped by inconsistent GraphcastMessage: {:#?} <- {:#?}\nnonce check: {:#?}\naccount check: {:#?}\nidentifier check: {:#?}",
                &self,
                &outer,
                self.nonce == outer.nonce,
                self.graph_account == outer.graph_account,
                self.identifier == outer.identifier,
            )))
        }
    }

    /// Make sure all messages stored are valid
    pub async fn validity_check(
        &self,
        gc_msg: &GraphcastMessage<Self>,
        graph_node_endpoint: &str,
    ) -> Result<&Self, BuildMessageError> {
        let _ = self
            .valid_hash(graph_node_endpoint)
            .await
            .map(|radio_msg| radio_msg.valid_outer(gc_msg))??;
        Ok(self)
    }
}
