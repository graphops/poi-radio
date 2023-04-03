use chrono::Utc;
use dotenv::dotenv;
use num_traits::Zero;
use poi_radio::metrics::handle_serve_metrics;
use std::collections::HashMap;
use std::sync::{Arc, Mutex as SyncMutex};
use std::{thread::sleep, time::Duration};
use tokio::sync::Mutex as AsyncMutex;

use tracing::log::warn;
use tracing::{debug, error, info, trace};

/// Radio specific query function to fetch Proof of Indexing for each allocated subgraph
use graphcast_sdk::bots::{DiscordBot, SlackBot};
use graphcast_sdk::config::Config;
use graphcast_sdk::graphcast_agent::message_typing::{BuildMessageError, GraphcastMessage};
use graphcast_sdk::graphcast_agent::GraphcastAgent;
use graphcast_sdk::graphql::client_graph_node::update_chainhead_blocks;
use graphcast_sdk::graphql::client_network::query_network_subgraph;
use graphcast_sdk::graphql::client_registry::query_registry_indexer;
use graphcast_sdk::networks::NetworkName;
use graphcast_sdk::{
    build_wallet, determine_message_block, graphcast_id_address, BlockPointer, NetworkBlockError,
    NetworkPointer,
};

use poi_radio::{
    attestation::{
        clear_local_attestation, compare_attestations, local_comparison_point, process_messages,
        save_local_attestation, Attestation, ComparisonResult, LocalAttestationsMap,
    },
    chainhead_block_str, generate_topics, radio_msg_handler, RadioPayloadMessage, GRAPHCAST_AGENT,
    MESSAGES,
};

use crate::graphql::query_graph_node_poi;

mod graphql;

#[macro_use]
extern crate partial_application;

#[tokio::main]
async fn main() {
    let radio_name: &str = "poi-radio";
    dotenv().ok();

    // Parse basic configurations
    let config = Config::args();
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

    let generate_topics = partial!(generate_topics => config.coverage.clone(), config.network_subgraph.clone(), my_address.clone(), config.graph_node_endpoint.clone(), &config.topics);
    let topics = generate_topics().await;
    info!("Found content topics for subscription: {:?}", topics);

    debug!("Initializing the Graphcast Agent");
    _ = GRAPHCAST_AGENT.set(
        GraphcastAgent::new(
            config.wallet_input().unwrap().to_string(),
            radio_name,
            &config.registry_subgraph,
            &config.network_subgraph,
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
    _ = MESSAGES.set(Arc::new(SyncMutex::new(vec![])));

    GRAPHCAST_AGENT
        .get()
        .unwrap()
        .register_handler(Arc::new(AsyncMutex::new(radio_msg_handler())))
        .expect("Could not register handler");
    let local_attestations: Arc<AsyncMutex<LocalAttestationsMap>> =
        Arc::new(AsyncMutex::new(HashMap::new()));

    if let Some(port) = config.metrics_port {
        tokio::spawn(handle_serve_metrics(port));
    }

    // Main loop for sending messages, can factor out
    // and take radio specific query and parsing for radioPayload
    loop {
        let network_chainhead_blocks: Arc<AsyncMutex<HashMap<NetworkName, BlockPointer>>> =
            Arc::new(AsyncMutex::new(HashMap::new()));
        let local_attestations = local_attestations.clone();
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
        let subgraph_network_latest_blocks = match update_chainhead_blocks(
            config.graph_node_endpoint.clone(),
            &mut *network_chainhead_blocks.lock().await,
        )
        .await
        {
            Ok(res) => res,
            Err(e) => {
                error!("Could not query indexing statuses, pull again later: {e}");
                continue;
            }
        };

        debug!(
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
            let local_attestations = local_attestations.clone();
            let (network_name, latest_block, message_block, compare_block, collect_window_end) =
                if let Ok(params) = message_set_up(
                    id.clone(),
                    &network_chainhead_blocks,
                    &subgraph_network_latest_blocks,
                    &local_attestations,
                    config.collect_message_duration,
                )
                .await
                {
                    params
                } else {
                    let err_msg = "Failed to set up message parameters for ...".to_string();
                    warn!("{}", err_msg);
                    return;
                };

            /* Send message */
            let id_cloned = id.clone();
            let local_cloned = Arc::clone(&local_attestations);
            let send_handle = tokio::spawn(async move {
                message_send(
                    id_cloned,
                    message_block,
                    latest_block,
                    network_name,
                    local_cloned,
                    GRAPHCAST_AGENT.get().unwrap(),
                )
                .await
            });
            send_handles.push(send_handle);

            let registry_subgraph = config.registry_subgraph.clone();
            let network_subgraph = config.network_subgraph.clone();
            let compare_handle = tokio::spawn(async move {
                message_comparison(
                    id.clone(),
                    collect_window_end,
                    message_block,
                    compare_block,
                    registry_subgraph.clone(),
                    network_subgraph.clone(),
                    network_name,
                    Arc::clone(MESSAGES.get().unwrap()),
                    Arc::clone(&local_attestations),
                )
                .await
            });
            compare_handles.push(compare_handle);
        }

        /* compare result logs */
        // loop through the handles
        // handle has a join method that blocks the current thread, waiting until the spawned thread is closed to continue executing code.
        // Generate attestation summary
        let mut match_strings = vec![];
        let mut not_found_strings = vec![];
        let mut divergent_strings = vec![];

        for handle in compare_handles {
            match handle.await {
                Ok(comparision_result) => match comparision_result {
                    Ok(ComparisonResult::Match(msg)) => {
                        debug!("{}", msg.clone());
                        match_strings.push(msg);
                    }
                    Ok(ComparisonResult::NotFound(msg)) => {
                        warn!("{}", msg);
                        not_found_strings.push(msg);
                    }
                    Ok(ComparisonResult::Divergent(msg)) => {
                        error!("{}", msg);
                        divergent_strings.push(msg.clone());
                        if let (Some(token), Some(channel)) =
                            (&config.slack_token, &config.slack_channel)
                        {
                            if let Err(e) = SlackBot::send_webhook(
                                token.to_string(),
                                channel.as_str(),
                                radio_name,
                                msg.as_str(),
                            )
                            .await
                            {
                                warn!("Failed to send notification to Slack: {}", e);
                            }
                        }

                        if let Some(webhook_url) = &config.discord_webhook.clone() {
                            if let Err(e) =
                                DiscordBot::send_webhook(webhook_url, radio_name, msg.as_str())
                                    .await
                            {
                                warn!("Failed to send notification to Discord: {}", e);
                            }
                        }
                    }
                    _ => {
                        error!("An error occured while comparing attestations");
                    }
                },
                Err(e) => {
                    error!("Join error to the thread: {}", e)
                }
            }
        }

        let mut num_msg_sent = 0;
        for handle in send_handles {
            if (handle.await).is_ok() {
                num_msg_sent += 1;
            }
        }

        info!(
            "Operation summary for blocks {}:\n{}: {}\n{} out of {} deployments cross checked\n{}: {}\n{}: {}\n{}: {}\n{}: {:#?}",
            blocks_str,
            "Number of messages sent",
            num_msg_sent,
            match_strings.len() + divergent_strings.len(),
            num_topics,
            "Successful attestations",
            match_strings.len(),
            "Total Topics without attestations",
            num_topics - match_strings.len() - divergent_strings.len(),
            "Topics reached comparison with no remote attestation",
            not_found_strings.len(),
            "Divergence",
            divergent_strings,
        );
        sleep(Duration::from_secs(5));
        continue;
    }
}

/// Determine the parameters for messages to send and compare
pub async fn message_set_up(
    id: String,
    network_chainhead_blocks: &Arc<AsyncMutex<HashMap<NetworkName, BlockPointer>>>,
    subgraph_network_latest_blocks: &HashMap<String, NetworkPointer>,
    local_attestations: &Arc<AsyncMutex<HashMap<String, HashMap<u64, Attestation>>>>,
    collect_window_duration: i64,
) -> Result<(NetworkName, BlockPointer, u64, u64, i64), BuildMessageError> {
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
    let (compare_block, collect_window_end) = local_comparison_point(
        &*local_attestations.lock().await,
        id.clone(),
        collect_window_duration,
    )
    .await;

    info!(
        "Deployment status:\n{}: {}\n{}: {}\n{}: {}\n{}: {}\n{}: {}\n{} {}: {}",
        "IPFS Hash",
        id.clone(),
        "Network",
        network_name,
        "Send message block",
        message_block,
        "Latest block",
        latest_block.number,
        "Latest block reached send message block",
        latest_block.number >= message_block,
        "Reached comparison time",
        collect_window_end,
        time >= collect_window_end,
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
pub async fn message_send(
    id: String,
    message_block: u64,
    latest_block: BlockPointer,
    network_name: NetworkName,
    local_attestations: Arc<AsyncMutex<HashMap<String, HashMap<u64, Attestation>>>>,
    graphcast_agent: &GraphcastAgent,
) -> Result<String, anyhow::Error> {
    debug!(
        "Checking latest block number and the message block: {0} >?= {message_block}",
        latest_block.number
    );

    if latest_block.number < message_block {
        return Err(anyhow::anyhow!(
            "latest block number has not reached the message block: {0} >?= {message_block}",
            latest_block.number
        ));
    };
    if local_attestations
        .lock()
        .await
        .get(&id.clone())
        .and_then(|blocks| blocks.get(&message_block))
        .is_none()
    {
        let block_hash = match graphcast_agent
            .get_block_hash(network_name.to_string(), message_block)
            .await
        {
            Ok(hash) => hash,
            Err(e) => {
                let err_msg = format!("Failed to query graph node for the block hash: {e}");
                error!("{}", err_msg);
                return Err(anyhow::anyhow!("{}", err_msg));
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
                    Ok(id) => {
                        let attestation = Attestation::new(
                            content.clone(),
                            Zero::zero(),
                            vec![],
                            vec![Utc::now().timestamp()],
                        );

                        save_local_attestation(
                            &mut *local_attestations.lock().await,
                            attestation,
                            id.clone(),
                            message_block,
                        );
                        Ok(id)
                    }
                    Err(e) => {
                        error!("{}: {}", "Failed to send message", e);
                        Err(anyhow::anyhow!("{}: {}", "Failed to send message", e))
                    }
                }
            }
            Err(e) => {
                error!("{}: {}", "Failed to query message content", e);
                Err(anyhow::anyhow!(
                    "{}: {}",
                    "Failed to query message content",
                    e
                ))
            }
        }
    } else {
        trace!(
            "Repeated message block, skip sending message for block: {}",
            message_block
        );
        Err(anyhow::anyhow!(
            "Repeated message block, skip sending message for block: {}",
            message_block
        ))
    }
}

/// Compare validated messages
#[allow(clippy::too_many_arguments)]
pub async fn message_comparison(
    id: String,
    collect_window_end: i64,
    message_block: u64,
    compare_block: u64,
    registry_subgraph: String,
    network_subgraph: String,
    network_name: NetworkName,
    messages: Arc<SyncMutex<Vec<GraphcastMessage<RadioPayloadMessage>>>>,
    local_attestations: Arc<AsyncMutex<HashMap<String, HashMap<u64, Attestation>>>>,
) -> Result<ComparisonResult, anyhow::Error> {
    if Utc::now().timestamp() >= collect_window_end && message_block > compare_block {
        let msgs = messages.lock().unwrap().to_vec();
        // Update to only process the identifier&compare_block related messages within the collection window
        let msgs: Vec<GraphcastMessage<RadioPayloadMessage>> = msgs
            .iter()
            .filter(|&m| {
                m.identifier == id.clone()
                    && m.block_number == compare_block
                    && m.nonce <= collect_window_end
            })
            .cloned()
            .collect();

        debug!(
            "Comparing validated messages:\n{}: {}\n{}: {}\n{}: {}",
            "Deployment",
            id.clone(),
            "Block",
            compare_block,
            "Number of messages",
            msgs.len(),
        );
        let remote_attestations_result = process_messages(
            Arc::new(AsyncMutex::new(msgs)),
            &registry_subgraph,
            &network_subgraph,
        )
        .await;
        let remote_attestations = match remote_attestations_result {
            Ok(remote) => {
                debug!(
                    "Processed messages:\n{}: {}",
                    "Number of unique remote POIs",
                    remote.len(),
                );
                remote
            }
            Err(err) => {
                let err_msg = format!("{}{}", "An error occured while parsing messages: {}", err);
                error!("{}", err_msg);
                return Ok(ComparisonResult::BuildFailed(err_msg));
            }
        };

        let comparison_result = compare_attestations(
            network_name,
            compare_block,
            remote_attestations.clone(),
            Arc::clone(&local_attestations),
            &id,
        )
        .await;

        // Only clear the ones matching identifier and block number equal or less
        // Retain the msgs with a different identifier, or if their block number is greater
        clear_local_attestation(
            &mut *local_attestations.lock().await,
            id.clone(),
            compare_block,
        );
        messages
            .lock()
            .unwrap()
            .retain(|msg| msg.block_number > compare_block || msg.identifier != id.clone());
        debug!("Messages left: {:#?}", messages);

        comparison_result
    } else {
        let err_msg = "Comparison not triggered".to_string();
        debug!("{}", err_msg);
        Ok(ComparisonResult::BuildFailed(err_msg))
    }
}
