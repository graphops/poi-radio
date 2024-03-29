use autometrics::autometrics;
use chrono::Utc;
use graphcast_sdk::callbook::CallBook;
use std::cmp::max;
use std::collections::HashMap;
use std::sync::{Arc, Mutex as SyncMutex};
use tracing::{debug, error, trace, warn};

use graphcast_sdk::{
    determine_message_block,
    graphcast_agent::{
        message_typing::{BuildMessageError, GraphcastMessage},
        GraphcastAgent, GraphcastAgentError,
    },
    networks::NetworkName,
    BlockPointer, NetworkBlockError, NetworkPointer,
};

use crate::messages::poi::PublicPoiMessage;
use crate::operator::attestation::process_ppoi_message;
use crate::{
    metrics::CACHED_MESSAGES,
    operator::{
        attestation::{
            compare_attestations, local_comparison_point, save_local_attestation, Attestation,
            ComparisonResult,
        },
        callbook::CallBookRadioExtensions,
        RadioOperator,
    },
    OperationError, GRAPHCAST_AGENT,
};

/// Determine the parameters for messages to send and compare
#[autometrics(track_concurrency)]
pub async fn gossip_set_up(
    id: String,
    network_chainhead_blocks: &HashMap<NetworkName, BlockPointer>,
    subgraph_network_latest_blocks: &HashMap<String, NetworkPointer>,
) -> Result<(NetworkName, BlockPointer, u64), BuildMessageError> {
    // Get the indexing network of the deployment
    // and update the NETWORK message block
    let (network_name, latest_block) = match subgraph_network_latest_blocks.get(&id.clone()) {
        Some(network_block) => (
            NetworkName::from_string(&network_block.network.clone()),
            network_block.block.clone(),
        ),
        None => {
            let err_msg = format!("Could not query the subgraph's indexing network, check Graph node's indexing statuses of subgraph deployment {}", id.clone());
            warn!(
                err = tracing::field::debug(&err_msg),
                "Failed to build message"
            );
            return Err(BuildMessageError::Network(NetworkBlockError::FailedStatus(
                err_msg,
            )));
        }
    };

    let message_block = match determine_message_block(network_chainhead_blocks, network_name) {
        Ok(block) => block,
        Err(e) => return Err(BuildMessageError::Network(e)),
    };

    debug!(
        deployment_hash = tracing::field::debug(&id),
        network = tracing::field::debug(&network_name),
        message_block = message_block,
        latest_block = latest_block.number,
        message_countdown_blocks = max(0, message_block as i64 - latest_block.number as i64),
        "Deployment status",
    );

    Ok((network_name, latest_block, message_block))
}

/// Construct the message and send it to Graphcast network
#[autometrics(track_concurrency)]
pub async fn message_send(
    id: String,
    callbook: CallBook,
    message_block: u64,
    latest_block: BlockPointer,
    network_name: NetworkName,
    local_attestations: Arc<SyncMutex<HashMap<String, HashMap<u64, Attestation>>>>,
    graphcast_agent: &GraphcastAgent,
) -> Result<String, OperationError> {
    trace!(
        message_block = message_block,
        latest_block = latest_block.number,
        "Check message send requirement",
    );

    // Deployment did not sync to message_block
    if latest_block.number < message_block {
        //TODO: fill in variant in SDK
        let err_msg = format!(
            "Did not send message for deployment {}: latest_block ({}) syncing status must catch up to the message block ({})",
            id.clone(),
            latest_block.number, message_block,
        );
        trace!(err = err_msg, "Skip send",);
        return Err(OperationError::SendTrigger(err_msg));
    };

    // Message has already been sent
    if local_attestations
        .lock()
        .unwrap()
        .get(&id.clone())
        .and_then(|blocks| blocks.get(&message_block))
        .is_some()
    {
        let err_msg = format!(
            "Repeated message for deployment {}, skip sending message for block: {}",
            id.clone(),
            message_block
        );
        trace!(err = err_msg, "Skip send");
        return Err(OperationError::SkipDuplicate(err_msg));
    }

    let block_hash = match graphcast_agent
        .callbook
        .block_hash(&network_name.to_string(), message_block)
        .await
    {
        Ok(hash) => hash,
        Err(e) => {
            let err_msg = format!("Failed to query graph node for the block hash: {e}");
            warn!(err = err_msg, "Failed to send message");
            return Err(OperationError::Query(e));
        }
    };

    match callbook
        .query_poi(
            id.clone(),
            block_hash.clone(),
            message_block.try_into().unwrap(),
        )
        .await
    {
        Ok(content) => {
            let nonce = Utc::now().timestamp();
            let block_hash = callbook
                .block_hash(&network_name.to_string(), message_block)
                .await
                .map_err(OperationError::Query)?;
            let radio_message = PublicPoiMessage::build(
                id.clone(),
                content.clone(),
                nonce,
                network_name,
                message_block,
                block_hash,
                graphcast_agent.graphcast_identity.graph_account.clone(),
            );
            match graphcast_agent
                .send_message(&id, radio_message, nonce)
                .await
            {
                Ok(msg_id) => {
                    save_local_attestation(
                        local_attestations.clone(),
                        content.clone(),
                        id.clone(),
                        message_block,
                    );
                    trace!("save local attestations: {:#?}", local_attestations);
                    Ok(msg_id)
                }
                Err(e) => {
                    error!(err = tracing::field::debug(&e), "Failed to send message");
                    Err(OperationError::Agent(e))
                }
            }
        }
        Err(e) => {
            error!(
                err = tracing::field::debug(&e),
                "Failed to query message content"
            );
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
    collect_window_duration: i64,
    callbook: CallBook,
    messages: Vec<GraphcastMessage<PublicPoiMessage>>,
    local_attestations: HashMap<String, HashMap<u64, Attestation>>,
) -> Result<ComparisonResult, OperationError> {
    let time = Utc::now().timestamp();

    let (compare_block, collect_window_end) = match local_comparison_point(
        &local_attestations,
        &messages,
        id.clone(),
        collect_window_duration,
    ) {
        Some((block, window)) if time >= window => (block, window),
        Some((compare_block, window)) => {
            let err_msg = format!("Deployment {} comparison not triggered: collecting messages until time {}; currently {time}", id.clone(), window);
            debug!(err = err_msg, "Collecting messages",);
            return Err(OperationError::CompareTrigger(
                id.clone(),
                compare_block,
                err_msg,
            ));
        }
        _ => {
            let err_msg = format!(
                "Deployment {} comparison not triggered: no matching attestation to compare",
                id.clone()
            );
            debug!(err = err_msg, "No matching attestations",);
            return Err(OperationError::CompareTrigger(id.clone(), 0, err_msg));
        }
    };

    let filter_msg: Vec<GraphcastMessage<PublicPoiMessage>> = messages
        .iter()
        .filter(|&m| m.payload.block_number == compare_block && m.nonce <= collect_window_end)
        .cloned()
        .collect();
    debug!(
        deployment_hash = id,
        time,
        comparison_time = collect_window_end,
        compare_block,
        comparison_countdown_seconds = max(0, time - collect_window_end),
        number_of_messages_matched_to_compare = filter_msg.len(),
        "Comparison state",
    );
    let remote_attestations_result = process_ppoi_message(filter_msg, &callbook).await;
    let remote_attestations = match remote_attestations_result {
        Ok(remote) => {
            debug!(unique_remote_nPOIs = remote.len(), "Processed messages",);
            remote
        }
        Err(err) => {
            trace!(
                err = tracing::field::debug(&err),
                "An error occured while processing the messages",
            );
            return Err(OperationError::Attestation(err));
        }
    };
    let comparison_result =
        compare_attestations(compare_block, remote_attestations, &local_attestations, &id);

    Ok(comparison_result)
}

impl RadioOperator {
    pub async fn gossip_poi(
        &self,
        identifiers: Vec<String>,
        network_chainhead_blocks: &HashMap<NetworkName, BlockPointer>,
        subgraph_network_latest_blocks: &HashMap<String, NetworkPointer>,
    ) -> Vec<Result<String, OperationError>> {
        let mut send_handles = vec![];
        for id in identifiers.clone() {
            /* Set up */
            let (network_name, latest_block, message_block) = if let Ok(params) = gossip_set_up(
                id.clone(),
                network_chainhead_blocks,
                subgraph_network_latest_blocks,
            )
            .await
            {
                params
            } else {
                let err_msg = "Failed to set up message parameters".to_string();
                warn!(id, err_msg, "Gossip POI failed");
                continue;
            };

            /* Send message */
            let id_cloned = id.clone();

            let callbook = self.config.callbook();
            let local_attestations = self.persisted_state.local_attestations.clone();
            let send_handle = tokio::spawn(async move {
                message_send(
                    id_cloned,
                    callbook,
                    message_block,
                    latest_block,
                    network_name,
                    Arc::clone(&local_attestations),
                    GRAPHCAST_AGENT.get().unwrap(),
                )
                .await
            });

            send_handles.push(send_handle);
        }

        let mut send_ops = vec![];
        for handle in send_handles {
            if let Ok(s) = handle.await {
                send_ops.push(s);
            }
        }
        send_ops
    }

    pub async fn compare_poi(
        &self,
        identifiers: Vec<String>,
    ) -> Vec<Result<ComparisonResult, OperationError>> {
        let mut compare_handles = vec![];

        // Additional radio message check happens here since messages are synchronously stored to state cache in msg handler
        let remote_messages = self
            .state()
            .valid_ppoi_messages(&self.config.graph_node_endpoint)
            .await;

        for id in identifiers.clone() {
            /* Set up */
            let collect_duration: i64 = self.config.collect_message_duration().to_owned();
            let id_cloned = id.clone();
            let callbook = self.config.callbook();
            let local_attestations = self.state().local_attestations();
            let filtered_msg = remote_messages
                .iter()
                .filter(|&m| m.identifier == id.clone())
                .cloned()
                .collect();

            let compare_handle = tokio::spawn(async move {
                message_comparison(
                    id_cloned,
                    collect_duration,
                    callbook.clone(),
                    filtered_msg,
                    local_attestations,
                )
                .await
            });
            compare_handles.push(compare_handle);
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
                        // clear_local_attestation(&mut local_attestations, r.deployment_hash(), r.block());
                        self.persisted_state
                            .clean_local_attestations(r.block(), r.deployment_hash());
                        self.persisted_state
                            .clean_remote_messages(r.block(), r.deployment_hash());
                        CACHED_MESSAGES
                            .with_label_values(&[&r.deployment_hash()])
                            .set(self.state().remote_messages().len().try_into().unwrap());
                    }
                    // Err(OperationError::CompareTrigger(d, b, m)) => {
                    //     trace!(m, "Compare handles");
                    //     self.persisted_state
                    //         .clean_local_attestations(b, d.clone());
                    //     self.persisted_state
                    //         .clean_remote_messages(b, d.clone());

                    //     compare_ops.push(Err(OperationError::CompareTrigger(d, b, m).clone_with_inner()));
                    // }
                    Err(e) => {
                        trace!(err = tracing::field::debug(&e), "Compare handles");

                        compare_ops.push(Err(e.clone_with_inner()));
                    }
                }
            }
        }
        compare_ops
    }
}
