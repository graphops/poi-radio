use autometrics::autometrics;
use chrono::Utc;

use std::cmp::max;
use std::collections::HashMap;

use std::sync::Arc;

use tokio::sync::Mutex as AsyncMutex;
use tracing::log::warn;
use tracing::{debug, error, trace};

use graphcast_sdk::graphcast_agent::message_typing::{BuildMessageError, GraphcastMessage};
use graphcast_sdk::graphcast_agent::{GraphcastAgent, GraphcastAgentError};

use graphcast_sdk::networks::NetworkName;
use graphcast_sdk::{determine_message_block, BlockPointer, NetworkBlockError, NetworkPointer};

use crate::CONFIG;
use crate::{
    attestation::{
        clear_local_attestation, compare_attestations, local_comparison_point, log_summary,
        process_messages, save_local_attestation, Attestation, ComparisonResult,
    },
    chainhead_block_str,
    graphql::query_graph_node_poi,
    metrics::CACHED_MESSAGES,
    OperationError, RadioPayloadMessage, GRAPHCAST_AGENT, MESSAGES, RADIO_NAME,
};

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
        "Number of messages matching deployment and block number",
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

pub async fn gossip_poi(
    identifiers: Vec<String>,
    network_chainhead_blocks: &Arc<AsyncMutex<HashMap<NetworkName, BlockPointer>>>,
    subgraph_network_latest_blocks: &HashMap<String, NetworkPointer>,
    local_attestations: Arc<AsyncMutex<HashMap<String, HashMap<u64, Attestation>>>>,
) {
    let mut send_handles = vec![];
    let mut compare_handles = vec![];
    for id in identifiers.clone() {
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
                network_chainhead_blocks,
                subgraph_network_latest_blocks,
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
    let blocks_str = chainhead_block_str(&*network_chainhead_blocks.lock().await);
    log_summary(
        blocks_str,
        identifiers.len(),
        send_ops,
        compare_ops,
        RADIO_NAME.get().unwrap(),
    )
    .await;
}
