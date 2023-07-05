use async_graphql::{Error, ErrorExtensions, SimpleObject};
use autometrics::autometrics;
use chrono::Utc;
use ethers_contract::EthAbiType;
use ethers_core::types::transaction::eip712::Eip712;
use ethers_derive_eip712::*;
use once_cell::sync::OnceCell;
use prost::Message;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};
use tokio::signal;
use tracing::{error, trace};

use graphcast_sdk::{
    graphcast_agent::GraphcastAgentError,
    graphql::{client_graph_node::get_indexing_statuses, QueryError},
};
use graphcast_sdk::{
    graphcast_agent::{
        message_typing::{BuildMessageError, GraphcastMessage},
        GraphcastAgent,
    },
    graphql::{
        client_graph_node::query_graph_node_network_block_hash,
        client_network::query_network_subgraph,
    },
    networks::NetworkName,
    BlockPointer,
};

use crate::operator::attestation::AttestationError;

pub mod config;
pub mod graphql;
pub mod metrics;
pub mod operator;
pub mod server;
pub mod state;

/// A global static (singleton) instance of GraphcastAgent. It is useful to ensure that we have only one GraphcastAgent
/// per Radio instance, so that we can keep track of state and more easily test our Radio application.
pub static GRAPHCAST_AGENT: OnceCell<Arc<GraphcastAgent>> = OnceCell::new();

pub fn radio_name() -> &'static str {
    "poi-radio"
}

#[derive(Eip712, EthAbiType, Clone, Message, Serialize, Deserialize, PartialEq, SimpleObject)]
#[eip712(
    name = "Graphcast POI Radio",
    version = "0",
    chain_id = 1,
    verifying_contract = "0xc944e90c64b2c07662a292be6244bdf05cda44a7"
)]
pub struct RadioPayloadMessage {
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

impl RadioPayloadMessage {
    pub fn new(
        identifier: String,
        content: String,
        nonce: i64,
        network: String,
        block_number: u64,
        block_hash: String,
        graph_account: String,
    ) -> Self {
        RadioPayloadMessage {
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
        network: NetworkName,
        block_number: u64,
        block_hash: String,
        graph_account: String,
    ) -> Self {
        RadioPayloadMessage::new(
            identifier,
            content,
            Utc::now().timestamp(),
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
                "Radio message wrapped by inconsistent GraphcastMessage: {:#?} <- {:#?}",
                &self,
                &outer,
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

/// Generate default topics that is operator address resolved to indexer address
/// and then its active on-chain allocations -> function signature should just return
/// A vec of strings for subtopics
pub async fn active_allocation_hashes(
    network_subgraph: &str,
    indexer_address: &str,
) -> Vec<String> {
    query_network_subgraph(network_subgraph, indexer_address)
        .await
        .map(|result| result.indexer_allocations())
        .unwrap_or_else(|e| {
            error!(err = tracing::field::debug(&e), "Failed to generate topics");
            vec![]
        })
}

/// Generate content topics for all deployments that are syncing on Graph node
/// filtering for deployments on an index node
pub async fn syncing_deployment_hashes(
    graph_node_endpoint: &str,
    // graphQL filter
) -> Vec<String> {
    get_indexing_statuses(graph_node_endpoint)
        .await
        .map_err(|e| -> Vec<String> {
            error!(err = tracing::field::debug(&e), "Topic generation error");
            [].to_vec()
        })
        .unwrap()
        .iter()
        .filter(|&status| status.node.is_some() && status.node != Some(String::from("removed")))
        .map(|s| s.subgraph.clone())
        .collect::<Vec<String>>()
}

/// This function returns the string representation of a set of network mapped to their chainhead blocks
#[autometrics]
pub fn chainhead_block_str(
    network_chainhead_blocks: &HashMap<NetworkName, BlockPointer>,
) -> String {
    let mut blocks_str = String::new();
    blocks_str.push_str("{ ");
    for (i, (network, block_pointer)) in network_chainhead_blocks.iter().enumerate() {
        if i > 0 {
            blocks_str.push_str(", ");
        }
        blocks_str.push_str(&format!("{}: {}", network, block_pointer.number));
    }
    blocks_str.push_str(" }");
    blocks_str
}

/// Graceful shutdown when receive signal
pub async fn shutdown_signal(running_program: Arc<AtomicBool>) {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {println!("Shutting down server...");},
        _ = terminate => {},
    }

    running_program.store(false, Ordering::SeqCst);
    opentelemetry::global::shutdown_tracer_provider();
}

#[derive(Debug, thiserror::Error)]
pub enum OperationError {
    #[error("Send message trigger isn't met: {0}")]
    SendTrigger(String),
    #[error("Message sent already, skip to avoid duplicates: {0}")]
    SkipDuplicate(String),
    #[error("Comparison trigger isn't met: {0}")]
    CompareTrigger(String, u64, String),
    #[error("Agent encountered problems: {0}")]
    Agent(GraphcastAgentError),
    #[error("Failed to query: {0}")]
    Query(QueryError),
    #[error("Attestation failure: {0}")]
    Attestation(AttestationError),
    #[error("Others: {0}")]
    Others(String),
}

impl OperationError {
    pub fn clone_with_inner(&self) -> Self {
        match self {
            OperationError::SendTrigger(msg) => OperationError::SendTrigger(msg.clone()),
            OperationError::SkipDuplicate(msg) => OperationError::SkipDuplicate(msg.clone()),
            OperationError::CompareTrigger(d, b, m) => {
                OperationError::CompareTrigger(d.clone(), *b, m.clone())
            }
            e => OperationError::Others(e.to_string()),
        }
    }
}

impl ErrorExtensions for OperationError {
    fn extend(&self) -> Error {
        Error::new(format!("{}", self))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn simple_message() -> RadioPayloadMessage {
        RadioPayloadMessage::new(
            String::from("QmHash"),
            String::from("0x0"),
            1,
            String::from("goerli"),
            0,
            String::from("0xa"),
            String::from("0xaaa"),
        )
    }

    fn wrong_outer_message(payload: RadioPayloadMessage) -> GraphcastMessage<RadioPayloadMessage> {
        GraphcastMessage {
            identifier: String::from("ping-pong-content-topic"),
            payload,
            nonce: 1687448729,
            graph_account: String::from("0xe9a1cabd57700b17945fd81feefba82340d9568f"),
            signature: String::from("2cd3fa305efd9c362bc71adee6e5a85c357a951af84c80667b8ddae23ac81c3821dac7d9c167e2776a9a56d8726b472312f40d9cc7461d1a6950d00e52d6e8521b")
        }
    }

    fn good_outer_message(payload: RadioPayloadMessage) -> GraphcastMessage<RadioPayloadMessage> {
        GraphcastMessage {
            identifier: payload.identifier.clone(),
            payload: payload.clone(),
            nonce: payload.nonce,
            graph_account: payload.graph_account,
            signature: String::from("2cd3fa305efd9c362bc71adee6e5a85c357a951af84c80667b8ddae23ac81c3821dac7d9c167e2776a9a56d8726b472312f40d9cc7461d1a6950d00e52d6e8521b")
        }
    }

    #[tokio::test]
    async fn test_message_wrap() {
        let wrong_msg = wrong_outer_message(simple_message());
        let right_msg = good_outer_message(simple_message());

        assert!(simple_message().valid_outer(&wrong_msg).is_err());
        assert!(simple_message().valid_outer(&right_msg).is_ok());
    }
}
