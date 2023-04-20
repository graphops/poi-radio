#![allow(clippy::await_holding_lock)]
use crate::utils::{
    generate_deterministic_address, generate_random_address, get_random_port, round_to_nearest,
    setup_mock_env_vars, setup_mock_server, test_process_messages, DummyMsg, RadioTestConfig,
};
use crate::CONFIG;
use chrono::Utc;

use ethers::signers::{LocalWallet, Signer};
use graphcast_sdk::graphcast_agent::message_typing::{BuildMessageError, GraphcastMessage};
use graphcast_sdk::graphcast_agent::{GraphcastAgent, GraphcastAgentError};
use graphcast_sdk::graphql::client_graph_node::update_chainhead_blocks;
use graphcast_sdk::graphql::client_network::query_network_subgraph;
use graphcast_sdk::graphql::client_registry::query_registry_indexer;
use graphcast_sdk::networks::NetworkName;
use graphcast_sdk::{
    determine_message_block, graphcast_id_address, BlockPointer, NetworkBlockError, NetworkPointer,
};
use hex::encode;
use once_cell::sync::OnceCell;
use poi_radio::attestation::{
    clear_local_attestation, compare_attestations, local_comparison_point, log_summary,
    save_local_attestation, ComparisonResult, LocalAttestationsMap, RemoteAttestationsMap,
};
use poi_radio::graphql::query_graph_node_poi;
use poi_radio::metrics::{handle_serve_metrics, CACHED_MESSAGES};
use poi_radio::{
    attestation::Attestation, chainhead_block_str, radio_msg_handler, MessagesVec, OperationError,
    RadioPayloadMessage, GRAPHCAST_AGENT, MESSAGES,
};
use rand::{thread_rng, Rng};
use secp256k1::SecretKey;
use std::cmp::max;
use std::collections::HashMap;
use std::env;
use std::sync::{Arc, Mutex as SyncMutex};
use std::{thread::sleep, time::Duration};
use tokio::sync::Mutex as AsyncMutex;
use tracing::{debug, error, info, trace, warn};

use crate::setup::constants::{MOCK_SUBGRAPH_GOERLI, MOCK_SUBGRAPH_MAINNET};

pub async fn run_test_radio<S, A, P>(
    runtime_config: Arc<RadioTestConfig>,
    success_handler: S,
    test_attestation_handler: A,
    post_comparison_handler: P,
) where
    S: Fn(MessagesVec, &str) + std::marker::Send + 'static + std::marker::Copy + std::marker::Sync,
    A: Fn(u64, &RemoteAttestationsMap, &LocalAttestationsMap)
        + std::marker::Send
        + 'static
        + std::marker::Copy
        + std::marker::Sync,
    P: Fn(MessagesVec, u64, &str)
        + std::marker::Send
        + 'static
        + std::marker::Copy
        + std::marker::Sync,
{
    let collect_message_duration: i64 = env::var("COLLECT_MESSAGE_DURATION")
        .unwrap_or("60".to_string())
        .parse::<i64>()
        .unwrap_or(60);

    let graphcast_id = generate_random_address();
    env::set_var("MOCK_SENDER", graphcast_id.clone());
    let indexer_address = generate_deterministic_address(&graphcast_id);

    let mock_server_uri = setup_mock_server(
        round_to_nearest(Utc::now().timestamp()).try_into().unwrap(),
        &indexer_address,
        &graphcast_id,
        &runtime_config.subgraphs.clone().unwrap_or(vec![
            MOCK_SUBGRAPH_MAINNET.to_string(),
            MOCK_SUBGRAPH_GOERLI.to_string(),
        ]),
        runtime_config.indexer_stake,
        &runtime_config.poi,
    )
    .await;
    setup_mock_env_vars(&mock_server_uri);

    let private_key = env::var("PRIVATE_KEY").expect("No private key provided.");
    let registry_subgraph =
        env::var("REGISTRY_SUBGRAPH_ENDPOINT").expect("No registry subgraph endpoint provided.");
    let network_subgraph =
        env::var("NETWORK_SUBGRAPH_ENDPOINT").expect("No network subgraph endpoint provided.");
    let graph_node_endpoint =
        env::var("GRAPH_NODE_STATUS_ENDPOINT").expect("No Graph node status endpoint provided.");

    if env::var("METRICS_PORT").is_ok() {
        info!(
            "Starting metrics server on port {}",
            env::var("METRICS_PORT").unwrap()
        );
        tokio::spawn(handle_serve_metrics(
            "0.0.0.0".to_string(),
            env::var("METRICS_PORT")
                .unwrap()
                .parse::<u16>()
                .expect("Failed to parse METRICS_PORT environment variable as u16"),
        ));
    }

    let wallet = private_key.parse::<LocalWallet>().unwrap();
    let mut rng = thread_rng();
    let mut private_key = [0u8; 32];
    rng.fill(&mut private_key[..]);

    let private_key = SecretKey::from_slice(&private_key).expect("Error parsing secret key");
    let private_key_hex = encode(private_key.secret_bytes());
    env::set_var("PRIVATE_KEY", &private_key_hex);

    let private_key = env::var("PRIVATE_KEY").unwrap();

    // TODO: Add something random and unique here to avoid noise form other operators
    let radio_name: &str = "test-poi-radio";

    let my_address =
        query_registry_indexer(registry_subgraph.clone(), graphcast_id_address(&wallet))
            .await
            .unwrap();
    let my_stake = query_network_subgraph(network_subgraph.clone(), my_address.clone())
        .await
        .unwrap()
        .indexer_stake();
    info!(
        "Initializing radio to act on behalf of indexer {:#?} with stake {}",
        my_address.clone(),
        my_stake
    );

    let graphcast_agent = GraphcastAgent::new(
        private_key,
        radio_name,
        &registry_subgraph,
        &network_subgraph,
        &graph_node_endpoint,
        vec![],
        Some("testnet"),
        runtime_config.subgraphs.clone().unwrap_or(vec![
            MOCK_SUBGRAPH_MAINNET.to_string(),
            MOCK_SUBGRAPH_GOERLI.to_string(),
        ]),
        None,
        None,
        Some(get_random_port()),
        None,
    )
    .await
    .unwrap();

    _ = GRAPHCAST_AGENT.set(graphcast_agent);
    _ = MESSAGES.set(Arc::new(SyncMutex::new(vec![])));

    GRAPHCAST_AGENT
        .get()
        .unwrap()
        .register_handler(Arc::new(AsyncMutex::new(radio_msg_handler())))
        .expect("Could not register handler");

    let local_attestations: Arc<AsyncMutex<LocalAttestationsMap>> =
        Arc::new(AsyncMutex::new(HashMap::new()));
    // Main loop for sending messages, can factor out
    // and take radio specific query and parsing for radioPayload
    loop {
        let network_chainhead_blocks: Arc<AsyncMutex<HashMap<NetworkName, BlockPointer>>> =
            Arc::new(AsyncMutex::new(HashMap::new()));
        let local_attestations = Arc::clone(&local_attestations);
        // Update all the chainheads of the network
        // Also get a hash map returned on the subgraph mapped to network name and latest block
        let subgraph_network_latest_blocks = match update_chainhead_blocks(
            graph_node_endpoint.clone(),
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
            let local_attestations = Arc::clone(&local_attestations);
            let (network_name, latest_block, message_block, compare_block, collect_window_end) =
                if let Ok(params) = message_set_up(
                    id.clone(),
                    &network_chainhead_blocks,
                    &subgraph_network_latest_blocks,
                    Arc::clone(&local_attestations),
                    collect_message_duration,
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

            let runtime_config_cloned = Arc::clone(&runtime_config);
            let send_handle = tokio::spawn(async move {
                message_send(
                    id_cloned,
                    message_block,
                    latest_block,
                    network_name,
                    local,
                    GRAPHCAST_AGENT.get().unwrap(),
                    Arc::clone(&runtime_config_cloned),
                )
                .await
            });

            let registry_subgraph = registry_subgraph.clone();
            let network_subgraph = network_subgraph.clone();
            let local = Arc::clone(&local_attestations);
            let msgs = MESSAGES.get().unwrap().lock().unwrap().to_vec();
            let filtered_msg = msgs
                .iter()
                .filter(|&m| m.identifier == id.clone())
                .cloned()
                .collect();
            debug!("filted by id to get {:#?}", filtered_msg);

            let runtime_config_indexer_stake = runtime_config.indexer_stake;
            let graphcast_id_clone = graphcast_id.clone();
            let compare_handle = tokio::spawn(async move {
                message_comparison(
                    id_cloned2,
                    collect_window_end,
                    latest_block_number,
                    compare_block,
                    registry_subgraph.clone(),
                    network_subgraph.clone(),
                    network_name,
                    filtered_msg,
                    local,
                    success_handler,
                    test_attestation_handler,
                    runtime_config_indexer_stake,
                    &graphcast_id_clone,
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
                        clear_local_attestation(local, r.deployment(), r.block()).await;
                        CACHED_MESSAGES.with_label_values(&[&r.deployment()]).set(
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
                            msg.block_number >= r.block() || msg.identifier != r.deployment()
                        });

                        post_comparison_handler(
                            OnceCell::with_value(MESSAGES.get().unwrap().clone()),
                            r.block(),
                            &r.deployment(),
                        );

                        CACHED_MESSAGES.with_label_values(&[&r.deployment()]).set(
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

        let config = CONFIG.get().unwrap();
        log_summary(
            blocks_str,
            num_topics,
            send_ops,
            compare_ops,
            radio_name,
            config,
        )
        .await;

        setup_mock_server(
            round_to_nearest(Utc::now().timestamp()).try_into().unwrap(),
            &indexer_address,
            &graphcast_id,
            &runtime_config.subgraphs.clone().unwrap_or(vec![
                MOCK_SUBGRAPH_MAINNET.to_string(),
                MOCK_SUBGRAPH_GOERLI.to_string(),
            ]),
            runtime_config.indexer_stake,
            &runtime_config.poi,
        )
        .await;

        sleep(Duration::from_secs(5));
        continue;
    }
}
/// Determine the parameters for messages to send and compare
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
pub async fn message_send(
    id: String,
    message_block: u64,
    latest_block: BlockPointer,
    network_name: NetworkName,
    local_attestations: Arc<AsyncMutex<HashMap<String, HashMap<u64, Attestation>>>>,
    graphcast_agent: &GraphcastAgent,
    runtime_config: Arc<RadioTestConfig>,
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

    if let Some(payload) = &runtime_config.invalid_payload {
        let payload = DummyMsg::from_ref(payload);

        _ = graphcast_agent
            .send_message(id.clone(), network_name, message_block, Some(payload))
            .await;

        return Ok("Sent message with invalid payload".to_string());
    }

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

            if let Some(invalid_nonce) = runtime_config.invalid_time {
                let content_topic = graphcast_agent
                    .match_content_topic(id.clone())
                    .await
                    .unwrap();

                let payload = Some(radio_message);
                let sig = graphcast_agent
                    .wallet
                    .sign_typed_data(payload.as_ref().unwrap())
                    .await
                    .expect("Failed to sign payload");

                // Create GraphcastMessage using the `new` method
                let graphcast_message = GraphcastMessage::new(
                    id.clone(),
                    payload,
                    invalid_nonce,
                    network_name,
                    message_block,
                    block_hash,
                    sig.to_string(),
                )
                .expect("Failed to create Graphcast message");

                graphcast_message
                    .send_to_waku(
                        &graphcast_agent.node_handle,
                        graphcast_agent.pubsub_topic.clone(),
                        content_topic,
                    )
                    .expect("Failed to send Graphcast message");

                return Ok("Sent message with invalid nonce".to_string());
            }

            if let Some(invalid_hash) = &runtime_config.invalid_hash {
                let content_topic = graphcast_agent
                    .match_content_topic(id.clone())
                    .await
                    .unwrap();

                let payload = Some(radio_message);
                let sig = graphcast_agent
                    .wallet
                    .sign_typed_data(payload.as_ref().unwrap())
                    .await
                    .expect("Failed to sign payload");

                // Create GraphcastMessage using the `new` method
                let graphcast_message = GraphcastMessage::new(
                    id.clone(),
                    payload,
                    Utc::now().timestamp(),
                    network_name,
                    message_block,
                    invalid_hash.to_string(),
                    sig.to_string(),
                )
                .expect("Failed to create Graphcast message");

                graphcast_message
                    .send_to_waku(
                        &graphcast_agent.node_handle,
                        graphcast_agent.pubsub_topic.clone(),
                        content_topic,
                    )
                    .expect("Failed to send Graphcast message");

                return Ok("Sent message with invalid nonce".to_string());
            }

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
pub async fn message_comparison<S, A>(
    id: String,
    collect_window_end: Option<i64>,
    latest_block: u64,
    compare_block: Option<u64>,
    registry_subgraph: String,
    network_subgraph: String,
    network_name: NetworkName,
    messages: Vec<GraphcastMessage<RadioPayloadMessage>>,
    local_attestations: Arc<AsyncMutex<HashMap<String, HashMap<u64, Attestation>>>>,
    success_handler: S,
    test_attestation_handler: A,
    runtime_config_indexer_stake: f32,
    graphcast_id: &str,
) -> Result<ComparisonResult, OperationError>
where
    S: Fn(MessagesVec, &str) + std::marker::Send,
    A: Fn(u64, &RemoteAttestationsMap, &LocalAttestationsMap) + std::marker::Send,
{
    let time = Utc::now().timestamp();

    // Update to only process the identifier&compare_block related messages within the collection window
    let filter_msg: Vec<GraphcastMessage<RadioPayloadMessage>> = messages
        .iter()
        .filter(|&m| Some(m.block_number) == compare_block && Some(m.nonce) <= collect_window_end)
        .cloned()
        .collect();

    if filter_msg.is_empty() {
        let err_msg = format!(
            "Deployment {} comparison not triggered: No valid remote messages cached for the block: {}",
            id.clone(),
            match compare_block {
                None => String::from("None"),
                Some(x) => x.to_string(),
            }
        );
        debug!("{}", err_msg);
        return Ok(ComparisonResult::NotFound(
            id.clone(),
            compare_block.unwrap_or_default(),
            err_msg,
        ));
    }

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
        "Number of messages",
        filter_msg.len(),
    );
    let remote_attestations_result = test_process_messages(
        filter_msg,
        &registry_subgraph,
        &network_subgraph,
        runtime_config_indexer_stake,
    )
    .await;
    let remote_attestations = match remote_attestations_result {
        Ok(remote) => {
            success_handler(
                OnceCell::with_value(MESSAGES.get().unwrap().clone()),
                graphcast_id,
            );

            test_attestation_handler(
                compare_block,
                &remote,
                &local_attestations.lock().await.clone(),
            );
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
        network_name,
        compare_block,
        remote_attestations,
        Arc::clone(&local_attestations),
        &id,
    )
    .await;

    Ok(comparison_result)
}
