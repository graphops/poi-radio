use async_graphql::SimpleObject;
use attestation::AttestationError;
use autometrics::autometrics;
use ethers_contract::EthAbiType;
use ethers_core::types::transaction::eip712::Eip712;
use ethers_derive_eip712::*;
use once_cell::sync::OnceCell;
use prost::Message;
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex as SyncMutex,
    },
};
use tokio::signal;
use tracing::{error, trace};

use graphcast_sdk::{
    config::CoverageLevel, graphcast_agent::GraphcastAgentError,
    graphql::client_graph_node::get_indexing_statuses,
};
use graphcast_sdk::{
    graphcast_agent::{
        message_typing::GraphcastMessage, waku_handling::WakuHandlingError, GraphcastAgent,
    },
    graphql::client_network::query_network_subgraph,
    networks::NetworkName,
    BlockPointer,
};

use crate::metrics::{CACHED_MESSAGES, VALIDATED_MESSAGES};

pub mod attestation;
pub mod graphql;
pub mod metrics;
pub mod server;

pub type MessagesVec = OnceCell<Arc<SyncMutex<Vec<GraphcastMessage<RadioPayloadMessage>>>>>;

/// A global static (singleton) instance of GraphcastAgent. It is useful to ensure that we have only one GraphcastAgent
/// per Radio instance, so that we can keep track of state and more easily test our Radio application.
pub static GRAPHCAST_AGENT: OnceCell<GraphcastAgent> = OnceCell::new();

/// A global static (singleton) instance of A GraphcastMessage vector.
/// It is used to save incoming messages after they've been validated, in order
/// defer their processing for later, because async code is required for the processing but
/// it is not allowed in the handler itself.
pub static MESSAGES: OnceCell<Arc<SyncMutex<Vec<GraphcastMessage<RadioPayloadMessage>>>>> =
    OnceCell::new();

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
}

impl RadioPayloadMessage {
    pub fn new(identifier: String, content: String) -> Self {
        RadioPayloadMessage {
            identifier,
            content,
        }
    }

    pub fn payload_content(&self) -> String {
        self.content.clone()
    }
}

/// Custom callback for handling the validated GraphcastMessage, in this case we only save the messages to a local store
/// to process them at a later time. This is required because for the processing we use async operations which are not allowed
/// in the handler.
#[autometrics]
pub fn radio_msg_handler(
) -> impl Fn(Result<GraphcastMessage<RadioPayloadMessage>, WakuHandlingError>) {
    |msg: Result<GraphcastMessage<RadioPayloadMessage>, WakuHandlingError>| {
        // TODO: Handle the error case by incrementing a Prometheus "error" counter
        if let Ok(msg) = msg {
            trace!("Received message: {:?}", msg);
            let id = msg.identifier.clone();
            VALIDATED_MESSAGES.with_label_values(&[&id]).inc();
            MESSAGES.get().unwrap().lock().unwrap().push(msg);
            CACHED_MESSAGES.with_label_values(&[&id]).set(
                MESSAGES
                    .get()
                    .unwrap()
                    .lock()
                    .unwrap()
                    .len()
                    .try_into()
                    .unwrap(),
            );
        }
    }
}

/// Generate default topics that is operator address resolved to indexer address
/// and then its active on-chain allocations -> function signature should just return
/// A vec of strings for subtopics
pub async fn active_allocation_hashes(
    network_subgraph: &str,
    indexer_address: String,
) -> Vec<String> {
    query_network_subgraph(network_subgraph.to_string(), indexer_address)
        .await
        .map_err(|e| -> Vec<String> {
            error!("Topic generation error: {}", e);
            [].to_vec()
        })
        .unwrap()
        .indexer_allocations()
}

/// Generate content topics for all deployments that are syncing on Graph node
/// filtering for deployments on an index node
pub async fn syncing_deployment_hashes(
    graph_node_endpoint: &str,
    // graphQL filter
) -> Vec<String> {
    get_indexing_statuses(graph_node_endpoint.to_string())
        .await
        .map_err(|e| -> Vec<String> {
            error!("Topic generation error: {}", e);
            [].to_vec()
        })
        .unwrap()
        .iter()
        .filter(|&status| status.node.is_some() && status.node != Some(String::from("removed")))
        .map(|s| s.subgraph.clone())
        .collect::<Vec<String>>()
}

/// Generate a set of unique topics along with given static topics
#[autometrics]
pub async fn generate_topics(
    coverage: CoverageLevel,
    network_subgraph: String,
    indexer_address: String,
    graph_node_endpoint: String,
    static_topics: &Vec<String>,
) -> Vec<String> {
    match coverage {
        CoverageLevel::Minimal => static_topics.to_vec(),
        CoverageLevel::OnChain => {
            let mut topics = active_allocation_hashes(&network_subgraph, indexer_address).await;
            for topic in static_topics {
                if !topics.contains(topic) {
                    topics.push(topic.clone());
                }
            }
            topics
        }
        CoverageLevel::Comprehensive => {
            let active_topics: HashSet<String> =
                active_allocation_hashes(&network_subgraph, indexer_address)
                    .await
                    .into_iter()
                    .collect();
            let additional_topics: HashSet<String> =
                syncing_deployment_hashes(&graph_node_endpoint)
                    .await
                    .into_iter()
                    .collect();

            let mut combined_topics: Vec<String> = static_topics.clone();
            combined_topics.extend(
                active_topics
                    .into_iter()
                    .chain(additional_topics.into_iter()),
            );
            combined_topics
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    const NETWORK: NetworkName = NetworkName::Goerli;

    #[test]
    fn test_add_message() {
        _ = MESSAGES.set(Arc::new(SyncMutex::new(Vec::new())));
        let mut messages = MESSAGES.get().unwrap().lock().unwrap();

        let hash: String = "QmWECgZdP2YMcV9RtKU41GxcdW8EGYqMNoG98ubu5RGN6U".to_string();
        let content: String =
            "0xa6008cea5905b8b7811a68132feea7959b623188e2d6ee3c87ead7ae56dd0eae".to_string();
        let nonce: i64 = 123321;
        let block_number: u64 = 0;
        let block_hash: String = "0xblahh".to_string();

        let radio_msg = RadioPayloadMessage::new(hash.clone(), content);
        let sig: String = "4be6a6b7f27c4086f22e8be364cbdaeddc19c1992a42b08cbe506196b0aafb0a68c8c48a730b0e3155f4388d7cc84a24b193d091c4a6a4e8cd6f1b305870fae61b".to_string();
        let msg = GraphcastMessage::new(
            hash,
            Some(radio_msg),
            nonce,
            NETWORK,
            block_number,
            block_hash,
            sig,
        )
        .expect("Shouldn't get here since the message is purposefully constructed for testing");

        assert!(messages.is_empty());

        messages.push(msg);
        assert_eq!(
            messages.first().unwrap().identifier,
            "QmWECgZdP2YMcV9RtKU41GxcdW8EGYqMNoG98ubu5RGN6U".to_string()
        );
    }

    #[test]
    fn test_delete_messages() {
        _ = MESSAGES.set(Arc::new(SyncMutex::new(Vec::new())));

        let mut messages = MESSAGES.get().unwrap().lock().unwrap();

        let hash: String = "QmWECgZdP2YMcV9RtKU41GxcdW8EGYqMNoG98ubu5RGN6U".to_string();
        let content: String =
            "0xa6008cea5905b8b7811a68132feea7959b623188e2d6ee3c87ead7ae56dd0eae".to_string();
        let nonce: i64 = 123321;
        let block_number: u64 = 0;
        let block_hash: String = "0xblahh".to_string();
        let radio_msg = RadioPayloadMessage::new(hash.clone(), content);
        let sig: String = "4be6a6b7f27c4086f22e8be364cbdaeddc19c1992a42b08cbe506196b0aafb0a68c8c48a730b0e3155f4388d7cc84a24b193d091c4a6a4e8cd6f1b305870fae61b".to_string();
        let msg = GraphcastMessage::new(
            hash,
            Some(radio_msg),
            nonce,
            NETWORK,
            block_number,
            block_hash,
            sig,
        )
        .expect("Shouldn't get here since the message is purposefully constructed for testing");

        messages.push(msg);
        assert!(!messages.is_empty());

        messages.clear();
        assert!(messages.is_empty());
    }
}
