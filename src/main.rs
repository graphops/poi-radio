use autometrics::autometrics;
use chrono::Utc;
use dotenv::dotenv;
use std::cmp::max;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as SyncMutex};
use std::{thread::sleep, time::Duration};
use tokio::sync::Mutex as AsyncMutex;
use tracing::log::warn;
use tracing::{debug, error, info, trace};

use crate::graphql::query_graph_node_poi;
use graphcast_sdk::config::Config;
use graphcast_sdk::graphcast_agent::message_typing::{BuildMessageError, GraphcastMessage};
use graphcast_sdk::graphcast_agent::{GraphcastAgent, GraphcastAgentError};
use graphcast_sdk::graphql::client_graph_node::update_chainhead_blocks;
use graphcast_sdk::graphql::client_network::query_network_subgraph;
use graphcast_sdk::graphql::client_registry::query_registry_indexer;
use graphcast_sdk::networks::NetworkName;
use graphcast_sdk::{
    build_wallet, determine_message_block, graphcast_id_address, BlockPointer, NetworkBlockError,
    NetworkPointer,
};
use poi_radio::attestation::log_summary;
use poi_radio::metrics::{handle_serve_metrics, CACHED_MESSAGES};
use poi_radio::server::run_server;
use poi_radio::OperationError;
use poi_radio::{
    attestation::{
        clear_local_attestation, compare_attestations, local_comparison_point, process_messages,
        save_local_attestation, Attestation, ComparisonResult, LocalAttestationsMap,
    },
    chainhead_block_str, generate_topics, radio_msg_handler, RadioPayloadMessage, GRAPHCAST_AGENT,
    MESSAGES,
};
use poi_radio::{shutdown_signal, CONFIG};

pub mod attestation;
mod graphql;
pub mod metrics;
pub mod server;

#[macro_use]
extern crate partial_application;

#[tokio::main]
async fn main() {
    let radio_name: &str = "poi-radio";
    dotenv().ok();

    // Parse basic configurations
    let config = Config::args();

    if let Some(port) = config.metrics_port {
        tokio::spawn(handle_serve_metrics(
            config
                .metrics_host
                .clone()
                .unwrap_or(String::from("0.0.0.0")),
            port,
        ));
    }

    if let Err(e) = config.validate_set_up().await {
        panic!("Could not validate the supplied configurations: {e}")
    }

    // Using unwrap directly as the query has been ran in the set-up validation
    let wallet = build_wallet(config.wallet_input().unwrap()).unwrap();
    // The query here must be Ok but so it is okay to panic here
    // Alternatively, make validate_set_up return wallet, address, and stake
    let my_address = query_registry_indexer(
        config.registry_subgraph.to_string(),
        graphcast_id_address(&wallet),
    )
    .await
    .unwrap();
    let my_stake = query_network_subgraph(config.network_subgraph.to_string(), my_address.clone())
        .await
        .unwrap()
        .indexer_stake();
    info!(
        "Initializing radio to act on behalf of indexer {:#?} with stake {}",
        my_address.clone(),
        my_stake
    );

    let topic_coverage = config.coverage.clone();
    let topic_network = config.network_subgraph.clone();
    let topic_graph_node = config.graph_node_endpoint.clone();
    let topic_static = &config.topics.clone();
    let generate_topics = partial!(generate_topics => topic_coverage.clone(), topic_network.clone(), my_address.clone(), topic_graph_node.clone(), topic_static);
    let topics = generate_topics().await;
    info!("Found content topics for subscription: {:?}", topics);

    debug!("Initializing Graphcast Agent");
    _ = GRAPHCAST_AGENT.set(
        GraphcastAgent::new(
            config.wallet_input().unwrap().to_string(),
            radio_name,
            &config.registry_subgraph.clone(),
            &config.network_subgraph.clone(),
            &config.graph_node_endpoint,
            config.boot_node_addresses.clone(),
            Some(&config.graphcast_network),
            topics,
            // Maybe move Waku specific configs to a sub-group
            config.waku_node_key.clone(),
            config.waku_host.clone(),
            config.waku_port.clone(),
            None,
        )
        .await
        .expect("Initialize Graphcast agent"),
    );
    debug!("Initialized Graphcast Agent");
    _ = MESSAGES.set(Arc::new(SyncMutex::new(vec![])));

    GRAPHCAST_AGENT
        .get()
        .unwrap()
        .register_handler(Arc::new(AsyncMutex::new(radio_msg_handler())))
        .expect("Could not register handler");
    let local_attestations: Arc<AsyncMutex<LocalAttestationsMap>> =
        Arc::new(AsyncMutex::new(HashMap::new()));

    _ = CONFIG.set(Arc::new(SyncMutex::new(config)));
    let running = Arc::new(AtomicBool::new(true));
    if CONFIG.get().unwrap().lock().unwrap().server_port.is_some() {
        tokio::spawn(run_server(running.clone(), Arc::clone(&local_attestations)));
    }

    // Main loop for sending messages, can factor out
    // and take radio specific query and parsing for radioPayload
    while running.load(Ordering::SeqCst) {
        let network_chainhead_blocks: Arc<AsyncMutex<HashMap<NetworkName, BlockPointer>>> =
            Arc::new(AsyncMutex::new(HashMap::new()));
        let local_attestations = Arc::clone(&local_attestations);
        // Update topic subscription
        if Utc::now().timestamp() % 120 == 0 {
            GRAPHCAST_AGENT
                .get()
                .unwrap()
                .update_content_topics(generate_topics().await)
                .await;
        }
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

        let mut send_handles = vec![];
        let mut compare_handles = vec![];
        for id in identifiers {
            /* Set up */
            let collect_duration = CONFIG
                .get()
                .unwrap()
                .lock()
                .unwrap()
                .collect_message_duration;
            let local_attestations = Arc::clone(&local_attestations);
            let (network_name, latest_block, message_block, compare_block, collect_window_end) =
                if let Ok(params) = message_set_up(
                    id.clone(),
                    &network_chainhead_blocks,
                    &subgraph_network_latest_blocks,
                    Arc::clone(&local_attestations),
                    collect_duration,
                )
                .await
                {
                    params
                } else {
                    let err_msg = "Failed to set up message parameters for ...".to_string();
                    warn!("{}", err_msg);
                    continue;
                };

            let latest_block_number = latest_block.number;
            /* Send message */
            let id_cloned = id.clone();
            let id_cloned2 = id.clone();
            let local = Arc::clone(&local_attestations);
            let send_handle = tokio::spawn(async move {
                message_send(
                    id_cloned,
                    message_block,
                    latest_block,
                    network_name,
                    local,
                    GRAPHCAST_AGENT.get().unwrap(),
                )
                .await
            });

            let registry_subgraph = CONFIG
                .get()
                .unwrap()
                .lock()
                .unwrap()
                .registry_subgraph
                .clone();
            let network_subgraph = CONFIG
                .get()
                .unwrap()
                .lock()
                .unwrap()
                .network_subgraph
                .clone();
            let local = Arc::clone(&local_attestations);
            let msgs = MESSAGES.get().unwrap().lock().unwrap().to_vec();
            let filtered_msg = msgs
                .iter()
                .filter(|&m| m.identifier == id.clone())
                .cloned()
                .collect();
            debug!("filted by id to get {:#?}", filtered_msg);

            let compare_handle = tokio::spawn(async move {
                message_comparison(
                    id_cloned2,
                    collect_window_end,
                    latest_block_number,
                    compare_block,
                    registry_subgraph.clone(),
                    network_subgraph.clone(),
                    filtered_msg,
                    local,
                )
                .await
            });
            send_handles.push(send_handle);
            compare_handles.push(compare_handle);
        }

        let mut send_ops = vec![];
        for handle in send_handles {
            if let Ok(s) = handle.await {
                send_ops.push(s);
            }
        }
        let mut compare_ops = vec![];
        for handle in compare_handles {
            let res = handle.await;
            if let Ok(s) = res {
                // Skip clean up for comparisonResult for Error and buildFailed
                match s {
                    Ok(r) => {
                        compare_ops.push(Ok(r.clone()));

                        /* Clean up cache */
                        // Only clear the ones matching identifier and block number equal or less
                        // Retain the msgs with a different identifier, or if their block number is greater
                        let local = Arc::clone(&local_attestations);
                        clear_local_attestation(local, r.deployment_hash(), r.block()).await;
                        CACHED_MESSAGES
                            .with_label_values(&[&r.deployment_hash()])
                            .set(
                                MESSAGES
                                    .get()
                                    .unwrap()
                                    .lock()
                                    .unwrap()
                                    .len()
                                    .try_into()
                                    .unwrap(),
                            );
                        MESSAGES.get().unwrap().lock().unwrap().retain(|msg| {
                            msg.block_number >= r.block() || msg.identifier != r.deployment_hash()
                        });
                        CACHED_MESSAGES
                            .with_label_values(&[&r.deployment_hash()])
                            .set(
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
                    Err(e) => {
                        warn!("Compare handles: {}", e.to_string());
                        compare_ops.push(Err(e.clone_with_inner()));
                    }
                }
            }
        }
        log_summary(blocks_str, num_topics, send_ops, compare_ops, radio_name).await;
        sleep(Duration::from_secs(5));
        continue;
    }
}

/// Determine the parameters for messages to send and compare
#[autometrics(track_concurrency)]
pub async fn message_set_up(
    id: String,
    network_chainhead_blocks: &Arc<AsyncMutex<HashMap<NetworkName, BlockPointer>>>,
    subgraph_network_latest_blocks: &HashMap<String, NetworkPointer>,
    local_attestations: Arc<AsyncMutex<HashMap<String, HashMap<u64, Attestation>>>>,
    collect_window_duration: i64,
) -> Result<(NetworkName, BlockPointer, u64, Option<u64>, Option<i64>), BuildMessageError> {
    let time = Utc::now().timestamp();
    // Get the indexing network of the deployment
    // and update the NETWORK message block
    let (network_name, latest_block) = match subgraph_network_latest_blocks.get(&id.clone()) {
        Some(network_block) => (
            NetworkName::from_string(&network_block.network.clone()),
            network_block.block.clone(),
        ),
        None => {
            let err_msg = format!("Could not query the subgraph's indexing network, check Graph node's indexing statuses of subgraph deployment {}", id.clone());
            warn!("{}", err_msg);
            return Err(BuildMessageError::Network(NetworkBlockError::FailedStatus(
                err_msg,
            )));
        }
    };

    let message_block =
        match determine_message_block(&*network_chainhead_blocks.lock().await, network_name) {
            Ok(block) => block,
            Err(e) => return Err(BuildMessageError::Network(e)),
        };

    // Get trigger from the local corresponding attestation
    let (compare_block, collect_window_end) = match local_comparison_point(
        Arc::clone(&local_attestations),
        id.clone(),
        collect_window_duration,
    )
    .await
    {
        Some((block, time)) => (Some(block), Some(time)),
        None => (None, None),
    };

    debug!(
        "Deployment status:\n{}: {}\n{}: {}\n{}: {}\n{}: {}\n{}: {}\n{}: {}\n{}: {}\n{}: {:#?}\n{}: {}",
        "IPFS Hash",
        id.clone(),
        "Network",
        network_name,
        "Send message block",
        message_block,
        "Subgraph latest block",
        latest_block.number,
        "Send message block countdown (blocks)",
        max(0, message_block as i64 - latest_block.number as i64),
        "Repeated message, skip sending",
        local_attestations
            .lock()
            .await
            .get(&id.clone())
            .and_then(|blocks| blocks.get(&message_block))
            .is_some(),
        "current time",
        time,
        "Comparison time",
        collect_window_end,
        "Comparison countdown (seconds)",
        max(0, time - collect_window_end.unwrap_or_default()),
    );

    Ok((
        network_name,
        latest_block,
        message_block,
        compare_block,
        collect_window_end,
    ))
}

/// Construct the message and send it to Graphcast network
#[autometrics(track_concurrency)]
pub async fn message_send(
    id: String,
    message_block: u64,
    latest_block: BlockPointer,
    network_name: NetworkName,
    local_attestations: Arc<AsyncMutex<HashMap<String, HashMap<u64, Attestation>>>>,
    graphcast_agent: &GraphcastAgent,
) -> Result<String, OperationError> {
    trace!(
        "Checking latest block number and the message block: {0} >?= {message_block}",
        latest_block.number
    );

    // Deployment did not sync to message_block
    if latest_block.number < message_block {
        //TODO: fill in variant in SDK
        let err_msg = format!(
            "Did not send message for deployment {}: latest_block ({}) syncing status must catch up to the message block ({})",
            id.clone(),
            latest_block.number, message_block,
        );
        trace!("{}", err_msg);
        return Err(OperationError::SendTrigger(err_msg));
    };

    // Already sent message
    if local_attestations
        .lock()
        .await
        .get(&id.clone())
        .and_then(|blocks| blocks.get(&message_block))
        .is_some()
    {
        let err_msg = format!(
            "Repeated message for deployment {}, skip sending message for block: {}",
            id.clone(),
            message_block
        );
        trace!("{}", err_msg);
        return Err(OperationError::SkipDuplicate(err_msg));
    }

    let block_hash = match graphcast_agent
        .get_block_hash(network_name.to_string(), message_block)
        .await
    {
        Ok(hash) => hash,
        Err(e) => {
            let err_msg = format!("Failed to query graph node for the block hash: {e}");
            error!("{}", err_msg);
            return Err(OperationError::Agent(e));
        }
    };

    match query_graph_node_poi(
        graphcast_agent.graph_node_endpoint.clone(),
        id.clone(),
        block_hash.clone(),
        message_block.try_into().unwrap(),
    )
    .await
    {
        Ok(content) => {
            let radio_message = RadioPayloadMessage::new(id.clone(), content.clone());
            match graphcast_agent
                .send_message(id.clone(), network_name, message_block, Some(radio_message))
                .await
            {
                Ok(msg_id) => {
                    save_local_attestation(
                        local_attestations,
                        content.clone(),
                        id.clone(),
                        message_block,
                    )
                    .await;
                    Ok(msg_id)
                }
                Err(e) => {
                    error!("{}: {}", "Failed to send message", e);
                    Err(OperationError::Agent(e))
                }
            }
        }
        Err(e) => {
            error!("{}: {}", "Failed to query message content", e);
            Err(OperationError::Agent(
                GraphcastAgentError::QueryResponseError(e),
            ))
        }
    }
}

/// Compare validated messages
#[allow(clippy::too_many_arguments)]
#[autometrics(track_concurrency)]
pub async fn message_comparison(
    id: String,
    collect_window_end: Option<i64>,
    latest_block: u64,
    compare_block: Option<u64>,
    registry_subgraph: String,
    network_subgraph: String,
    messages: Vec<GraphcastMessage<RadioPayloadMessage>>,
    local_attestations: Arc<AsyncMutex<HashMap<String, HashMap<u64, Attestation>>>>,
) -> Result<ComparisonResult, OperationError> {
    let time = Utc::now().timestamp();

    // Update to only process the identifier&compare_block related messages within the collection window
    let filter_msg: Vec<GraphcastMessage<RadioPayloadMessage>> = messages
        .iter()
        .filter(|&m| Some(m.block_number) == compare_block && Some(m.nonce) <= collect_window_end)
        .cloned()
        .collect();

    let (compare_block, _collect_window_end) = match (compare_block, collect_window_end) {
        (Some(block), Some(window)) if time >= window && latest_block > block => (block, window),
        _ => {
            let err_msg = format!("Deployment {} comparison not triggered: collecting messages until time {}; currently {time}", id.clone(), match collect_window_end { None => String::from("None"), Some(x) => x.to_string()},);
            debug!("{}", err_msg);
            return Err(OperationError::CompareTrigger(
                id.clone(),
                compare_block.unwrap_or_default(),
                err_msg,
            ));
        }
    };

    debug!(
        "Comparing validated and filtered messages:\n{}: {}\n{}: {}\n{}: {}",
        "Deployment",
        id.clone(),
        "Block",
        compare_block,
        "Number of matching messages cached",
        filter_msg.len(),
    );
    let remote_attestations_result =
        process_messages(filter_msg, &registry_subgraph, &network_subgraph).await;
    let remote_attestations = match remote_attestations_result {
        Ok(remote) => {
            debug!(
                "Processed message\n{}: {}",
                "Number of unique remote POIs",
                remote.len(),
            );
            remote
        }
        Err(err) => {
            trace!(
                "{}",
                format!("{}{}", "An error occured while parsing messages: {}", err)
            );
            return Err(OperationError::Attestation(err));
        }
    };
    let comparison_result = compare_attestations(
        compare_block,
        remote_attestations,
        Arc::clone(&local_attestations),
        &id,
    )
    .await;

    Ok(comparison_result)
}
