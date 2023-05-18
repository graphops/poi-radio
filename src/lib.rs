use async_graphql::{Error, ErrorExtensions, SimpleObject};

use autometrics::autometrics;
use config::{Config, CoverageLevel};
use ethers_contract::EthAbiType;
use ethers_core::types::transaction::eip712::Eip712;
use ethers_derive_eip712::*;
use once_cell::sync::OnceCell;
use partial_application::partial;
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
    graphcast_agent::GraphcastAgentError,
    graphql::{client_graph_node::get_indexing_statuses, client_registry::query_registry_indexer},
};
use graphcast_sdk::{
    graphcast_agent::{
        message_typing::GraphcastMessage, waku_handling::WakuHandlingError, GraphcastAgent,
    },
    graphql::client_network::query_network_subgraph,
    networks::NetworkName,
    BlockPointer,
};

use crate::{
    attestation::AttestationError,
    metrics::handle_serve_metrics,
    operation::{compare_poi, gossip_poi},
    server::run_server,
};
use crate::{
    attestation::LocalAttestationsMap,
    metrics::{CACHED_MESSAGES, VALIDATED_MESSAGES},
};

use crate::state::PersistedState;
use dotenv::dotenv;
use std::thread::sleep;
use tokio::{
    sync::Mutex as AsyncMutex,
    time::{interval, timeout, Duration},
};
use tracing::{debug, info, warn};

use graphcast_sdk::{
    build_wallet, graphcast_id_address,
    graphql::client_graph_node::{update_chainhead_blocks, update_network_chainheads},
};

pub mod attestation;
pub mod config;
pub mod graphql;
pub mod metrics;
pub mod operation;
pub mod server;
pub mod state;

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

/// Radio's global config
pub static CONFIG: OnceCell<Arc<SyncMutex<Config>>> = OnceCell::new();

pub static RADIO_NAME: OnceCell<String> = OnceCell::new();

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
        .map(|result| result.indexer_allocations())
        .unwrap_or_else(|e| {
            error!("Topic generation error: {}", e);
            vec![]
        })
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

impl ErrorExtensions for OperationError {
    fn extend(&self) -> Error {
        Error::new(format!("{}", self))
    }
}

pub fn clear_all_messages() {
    _ = MESSAGES.set(Arc::new(SyncMutex::new(vec![])));
}

pub async fn run_radio(radio_name: String, radio_config: Config) {
    _ = RADIO_NAME.set(radio_name);
    dotenv().ok();
    // console_subscriber::init();

    if let Some(port) = radio_config.metrics_port {
        tokio::spawn(handle_serve_metrics(
            radio_config
                .metrics_host
                .clone()
                .unwrap_or(String::from("0.0.0.0")),
            port,
        ));
    }

    debug!("Initializing Graphcast Agent");

    let graphcast_agent_config = radio_config
        .to_graphcast_agent_config(RADIO_NAME.get().expect("RADIO_NAME required."))
        .await
        .unwrap_or_else(|e| panic!("Could not create GraphcastAgentConfig: {e}"));

    _ = GRAPHCAST_AGENT.set(
        GraphcastAgent::new(graphcast_agent_config)
            .await
            .expect("Initialize Graphcast agent"),
    );

    debug!("Initialized Graphcast Agent");
    // Using unwrap directly as the query has been ran in the set-up validation
    let wallet = build_wallet(radio_config.wallet_input().unwrap()).unwrap();
    // The query here must be Ok but so it is okay to panic here
    // Alternatively, make validate_set_up return wallet, address, and stake
    let my_address = query_registry_indexer(
        radio_config.registry_subgraph.to_string(),
        graphcast_id_address(&wallet),
    )
    .await
    .unwrap();
    let my_stake = query_network_subgraph(
        radio_config.network_subgraph.to_string(),
        my_address.clone(),
    )
    .await
    .unwrap()
    .indexer_stake();
    info!(
        "Initializing radio to act on behalf of indexer {:#?} with stake {}",
        my_address.clone(),
        my_stake
    );

    let topic_coverage = radio_config.coverage.clone();
    let topic_network = radio_config.network_subgraph.clone();
    let topic_graph_node = radio_config.graph_node_endpoint.clone();
    let topic_static = &radio_config.topics.clone();
    let generate_topics = partial!(generate_topics => topic_coverage.clone(), topic_network.clone(), my_address.clone(), topic_graph_node.clone(), topic_static);
    let topics = generate_topics().await;
    GRAPHCAST_AGENT
        .get()
        .unwrap()
        .update_content_topics(topics.clone())
        .await;

    info!("Found content topics for subscription: {:?}", topics);
    let file_path = &radio_config.persistence_file_path.clone();
    let state = if let Some(path) = file_path {
        //TODO: set up synchronous panic hook as part of PersistedState functions
        // panic_hook(&path);
        let state = PersistedState::load_cache(path);
        debug!("Loaded Persisted state cache: {:#?}", state);
        state
    } else {
        debug!("Created new state without persistence");
        PersistedState::new(None, None)
    };

    _ = MESSAGES.set(state.remote_messages());
    let local_attestations: Arc<AsyncMutex<LocalAttestationsMap>> =
        Arc::new(AsyncMutex::new(state.local_attestations()));

    GRAPHCAST_AGENT
        .get()
        .unwrap()
        .register_handler(Arc::new(AsyncMutex::new(radio_msg_handler())))
        .expect("Could not register handler");

    let running = Arc::new(AtomicBool::new(true));
    let skip_iteration = Arc::new(AtomicBool::new(false));
    let skip_iteration_clone = skip_iteration.clone();

    _ = CONFIG.set(Arc::new(SyncMutex::new(radio_config)));
    if CONFIG.get().unwrap().lock().unwrap().server_port.is_some() {
        tokio::spawn(run_server(running.clone(), Arc::clone(&local_attestations)));
    }

    // Can later expose to radio config for the users
    let mut topic_update_interval = interval(Duration::from_secs(600));
    let mut state_update_interval = interval(Duration::from_secs(15));
    let mut gossip_poi_interval = interval(Duration::from_secs(30));
    let mut comparison_interval = interval(Duration::from_secs(60));

    let iteration_timeout = Duration::from_secs(180);
    let update_timeout = Duration::from_secs(10);
    let gossip_timeout = Duration::from_secs(150);

    // Skip a main loop iteration when hit timeout
    tokio::spawn(async move {
        tokio::time::sleep(iteration_timeout).await;
        skip_iteration_clone.store(true, Ordering::SeqCst);
    });

    // Main loop for sending messages, can factor out
    // and take radio specific query and parsing for radioPayload
    while running.load(Ordering::SeqCst) {
        // Run event intervals sequentially by satisfication of other intervals and corresponding tick
        tokio::select! {
            _ = topic_update_interval.tick() => {
                if skip_iteration.load(Ordering::SeqCst) {
                    skip_iteration.store(false, Ordering::SeqCst);
                    continue;
                }
                // Update topic subscription
                let result = timeout(update_timeout,
                    GRAPHCAST_AGENT
                    .get()
                    .unwrap()
                    .update_content_topics(generate_topics().await)
                ).await;

                if result.is_err() {
                    warn!("update_content_topics timed out");
                } else {
                    debug!("update_content_topics completed");
                }
            },
            _ = state_update_interval.tick() => {
                if skip_iteration.load(Ordering::SeqCst) {
                    skip_iteration.store(false, Ordering::SeqCst);
                    continue;
                }
                // TODO: make operator struct that keeps the global state
                // Update the state to persist
                let result = timeout(update_timeout,
                    state.update(Some(local_attestations.clone()), Some(MESSAGES.get().unwrap().clone()))
                ).await;

                if let Ok(r) = result {
                    debug!("state update completed");

                    // Save cache if path provided
                    if let Some(path) = file_path {
                        r.update_cache(path);
                    }
                } else {
                    warn!("state update timed out");
                }
            },
            _ = gossip_poi_interval.tick() => {
                if skip_iteration.load(Ordering::SeqCst) {
                    skip_iteration.store(false, Ordering::SeqCst);
                    continue;
                }

                let result = timeout(gossip_timeout, {
                    let network_chainhead_blocks: Arc<AsyncMutex<HashMap<NetworkName, BlockPointer>>> =
                        Arc::new(AsyncMutex::new(HashMap::new()));
                    // Update all the chainheads of the network
                    // Also get a hash map returned on the subgraph mapped to network name and latest block
                    let graph_node = CONFIG
                        .get()
                        .unwrap()
                        .lock()
                        .unwrap()
                        .graph_node_endpoint
                        .clone();
                    let subgraph_network_latest_blocks =
                        match update_chainhead_blocks(graph_node, &mut *network_chainhead_blocks.lock().await)
                            .await
                        {
                            Ok(res) => res,
                            Err(e) => {
                                error!("Could not query indexing statuses, pull again later: {e}");
                                continue;
                            }
                        };

                    trace!(
                        "Subgraph network and latest blocks: {:#?}",
                        subgraph_network_latest_blocks,
                    );

                    // Radio specific message content query function
                    // Function takes in an identifier string and make specific queries regarding the identifier
                    // The example here combines a single function provided query endpoint, current block info based on the subgraph's indexing network
                    // Then the function gets sent to agent for making identifier independent queries
                    let identifiers = GRAPHCAST_AGENT.get().unwrap().content_identifiers().await;
                    let num_topics = identifiers.len();
                    let blocks_str = chainhead_block_str(&*network_chainhead_blocks.lock().await);
                    info!(
                        "Network statuses:\n{}: {:#?}\n{}: {:#?}\n{}: {}",
                        "Chainhead blocks",
                        blocks_str.clone(),
                        "Number of gossip peers",
                        GRAPHCAST_AGENT.get().unwrap().number_of_peers(),
                        "Number of tracked deployments (topics)",
                        num_topics,
                    );

                    gossip_poi(
                        identifiers,
                        &network_chainhead_blocks.clone(),
                        &subgraph_network_latest_blocks.clone(),
                        local_attestations.clone(),
                    )
                }).await;

                if result.is_err() {
                    warn!("gossip_poi timed out");
                } else {
                    debug!("gossip_poi completed");
                }
            },
            _ = comparison_interval.tick() => {
                if skip_iteration.load(Ordering::SeqCst) {
                    skip_iteration.store(false, Ordering::SeqCst);
                    continue;
                }

                let result = timeout(gossip_timeout, {
                    let mut network_chainhead_blocks: HashMap<NetworkName, BlockPointer> =
                        HashMap::new();
                    let local_attestations = local_attestations.clone();

                    // Update all the chainheads of the network
                    // Also get a hash map returned on the subgraph mapped to network name and latest block
                    let graph_node_endpoint = CONFIG
                        .get()
                        .unwrap()
                        .lock()
                        .unwrap()
                        .graph_node_endpoint
                        .clone();
                    let indexing_status = match get_indexing_statuses(graph_node_endpoint.clone()).await {
                        Ok(res) => res,
                        Err(e) => {
                            error!("Could not query indexing statuses, pull again later: {e}");
                            continue;
                        }
                    };
                    update_network_chainheads(
                            indexing_status,
                            &mut network_chainhead_blocks,
                        );

                    let identifiers = GRAPHCAST_AGENT.get().unwrap().content_identifiers().await;
                    let num_topics = identifiers.len();
                    let blocks_str = chainhead_block_str(&network_chainhead_blocks);
                    info!(
                        "Network statuses:\n{}: {:#?}\n{}: {:#?}\n{}: {}",
                        "Chainhead blocks",
                        blocks_str.clone(),
                        "Number of gossip peers",
                        GRAPHCAST_AGENT.get().unwrap().number_of_peers(),
                        "Number of tracked deployments (topics)",
                        num_topics,
                    );

                    compare_poi(
                        identifiers,
                        &Arc::new(AsyncMutex::new(network_chainhead_blocks.clone())),
                        local_attestations,
                    )
                }).await;

                if result.is_err() {
                    warn!("compare_poi timed out");
                } else {
                    debug!("compare_poi completed");
                }
            },
            else => break,
        }

        sleep(Duration::from_secs(5));
        continue;
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
