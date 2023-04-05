#![allow(clippy::await_holding_lock)]
use crate::utils::{
    empty_attestation_handler, generate_deterministic_address, generate_random_address,
    get_random_port, setup_mock_env_vars, setup_mock_server, RadioTestConfig,
};
use chrono::Utc;

use ethers::signers::LocalWallet;
use ethers_contract::EthAbiType;
use ethers_core::types::transaction::eip712::Eip712;
use ethers_derive_eip712::*;
use graphcast_sdk::bots::{DiscordBot, SlackBot};
use graphcast_sdk::graphcast_agent::message_typing::GraphcastMessage;
use graphcast_sdk::graphcast_agent::GraphcastAgent;
use graphcast_sdk::graphql::client_graph_node::update_chainhead_blocks;
use graphcast_sdk::graphql::client_network::query_network_subgraph;
use graphcast_sdk::graphql::client_registry::query_registry_indexer;
use graphcast_sdk::networks::NetworkName;
use graphcast_sdk::{determine_message_block, graphcast_id_address, BlockPointer};
use hex::encode;
use partial_application::partial;
use poi_radio::attestation::{
    compare_attestations, local_comparison_point, process_messages, save_local_attestation,
    ComparisonResult,
};
use poi_radio::metrics::handle_serve_metrics;
use poi_radio::{
    chainhead_block_str, radio_msg_handler, Attestation, LocalAttestationsMap, MessagesArc,
    RadioPayloadMessage, RemoteAttestationsMap, GRAPHCAST_AGENT, MESSAGES,
};
use prost::Message;
use rand::{thread_rng, Rng};
use secp256k1::SecretKey;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::sync::{Arc, Mutex as SyncMutex};
use std::{thread::sleep, time::Duration};
use tokio::sync::Mutex as AsyncMutex;
use tracing::{debug, error, info, trace, warn};

use crate::setup::constants::{MOCK_SUBGRAPH_GOERLI, MOCK_SUBGRAPH_MAINNET};
use poi_radio::graphql::query_graph_node_poi;

fn round_to_nearest(number: i64) -> i64 {
    (number / 10) * 10 + if number % 10 > 4 { 10 } else { 0 }
}

#[derive(Eip712, EthAbiType, Clone, Message, Serialize, Deserialize)]
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
}

pub async fn run_test_radio<S, A, P>(
    runtime_config: &RadioTestConfig,
    success_handler: S,
    test_attestation_handler: A,
    post_comparison_handler: P,
) where
    S: Fn(MessagesArc),
    A: Fn(u64, &RemoteAttestationsMap, &LocalAttestationsMap),
    P: Fn(MessagesArc, u64, &str, usize),
{
    let collect_message_duration: i64 = env::var("COLLECT_MESSAGE_DURATION")
        .unwrap_or("60".to_string())
        .parse::<i64>()
        .unwrap_or(60);

    let graphcast_id = generate_random_address();
    env::set_var("MOCK_SENDER", graphcast_id.clone());
    let indexer_address = generate_deterministic_address(&graphcast_id);

    debug!("Actual graphcast_id: {}", graphcast_id);

    let mock_server_uri = setup_mock_server(
        round_to_nearest(Utc::now().timestamp()).try_into().unwrap(),
        &indexer_address,
        &graphcast_id,
        &runtime_config.subgraphs.clone().unwrap_or(vec![
            MOCK_SUBGRAPH_MAINNET.to_string(),
            MOCK_SUBGRAPH_GOERLI.to_string(),
        ]),
        &runtime_config.indexer_stake,
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

    if runtime_config.is_setup_instance {
        GRAPHCAST_AGENT
            .get()
            .unwrap()
            .register_handler(Arc::new(AsyncMutex::new(empty_attestation_handler())))
            .expect("Could not register handler");
    } else {
        GRAPHCAST_AGENT
            .get()
            .unwrap()
            .register_handler(Arc::new(AsyncMutex::new(radio_msg_handler())))
            .expect("Could not register handler");
    };

    let mut network_chainhead_blocks: HashMap<NetworkName, BlockPointer> = HashMap::new();
    let local_attestations: Arc<AsyncMutex<LocalAttestationsMap>> =
        Arc::new(AsyncMutex::new(HashMap::new()));

    // Main loop for sending messages, can factor out
    // and take radio specific query and parsing for radioPayload
    loop {
        let subgraph_network_latest_blocks = match update_chainhead_blocks(
            graph_node_endpoint.clone(),
            &mut network_chainhead_blocks,
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
        let identifiers = GRAPHCAST_AGENT.get().unwrap().content_identifiers().await;
        let num_topics = identifiers.len();
        //TODO: move to helper
        let blocks_str = chainhead_block_str(&network_chainhead_blocks);
        info!(
            "Network statuses:\n{}: {:#?}\n{}: {:#?}\n{}: {}",
            "Chainhead blocks",
            blocks_str,
            "Number of gossip peers",
            GRAPHCAST_AGENT.get().unwrap().number_of_peers(),
            "Number of tracked deployments (topics)",
            num_topics,
        );

        for id in identifiers {
            let time = Utc::now().timestamp();

            // Get the indexing network of the deployment
            // and update the NETWORK message block
            let (network_name, latest_block) = match subgraph_network_latest_blocks.get(&id.clone())
            {
                Some(network_block) => (
                    NetworkName::from_string(&network_block.network.clone()),
                    network_block.block.clone(),
                ),
                None => {
                    error!("Could not query the subgraph's indexing network, check Graph node's indexing statuses of subgraph deployment {}", id.clone());
                    continue;
                }
            };

            let message_block =
                match determine_message_block(&network_chainhead_blocks, network_name) {
                    Ok(block) => block,
                    Err(_) => continue,
                };

            // first stored message block
            // Get trigger from the local corresponding attestation
            let (compare_block, collect_window_end) = local_comparison_point(
                Arc::clone(&local_attestations),
                id.clone(),
                collect_message_duration,
            )
            .await;

            info!(
                "Deployment status:\n{}: {}\n{}: {}\n{}: {}\n{}: {}\n{}: {}\n{}: {}",
                "IPFS Hash",
                id.clone(),
                "Network",
                network_name,
                "Send message block",
                message_block,
                "Latest block",
                latest_block.number,
                "Reached send message block",
                latest_block.number >= message_block,
                "Reached comparison time",
                time >= collect_window_end,
            );

            if time >= collect_window_end && message_block > compare_block {
                let msgs = MESSAGES.get().unwrap().lock().unwrap().to_vec();
                // Update to only process the identifier&compare_block related messages within the collection window
                let msgs: Vec<GraphcastMessage<RadioPayloadMessage>> = msgs
                    .iter()
                    .filter(|&m| {
                        // info!("ident {}", m.identifier);
                        // info!("num {}", m.block_number);
                        // info!("nonce {}", m.nonce);
                        // info!("id {}", id.clone());
                        // info!("compare block {}", compare_block);
                        // info!("collect windows end {}", collect_window_end);

                        // info!("ident equal to id.clone {}", m.identifier == id.clone());
                        // info!("block num to com_block {}", m.block_number > compare_block);
                        // info!("nonce to window {}", m.nonce <= collect_window_end);

                        m.identifier == id.clone() && m.block_number > compare_block
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

                info!(
                    "remote_attestations_result: {:?}",
                    remote_attestations_result
                );

                let remote_attestations = match remote_attestations_result {
                    Ok(remote) => {
                        success_handler(Arc::clone(MESSAGES.get().unwrap()));

                        test_attestation_handler(
                            compare_block,
                            &remote,
                            &local_attestations.lock().await.clone(),
                        );

                        debug!(
                            "Processed messages:\n{}: {}",
                            "Number of unique remote POIs",
                            remote.len(),
                        );
                        remote
                    }
                    Err(err) => {
                        error!("{}{}", "An error occured while parsing messages: {}", err);
                        continue;
                    }
                };

                match compare_attestations(
                    network_name,
                    compare_block,
                    remote_attestations.clone(),
                    Arc::clone(&local_attestations),
                    &id.clone(),
                )
                .await
                {
                    Ok(ComparisonResult::Match(msg)) => {
                        debug!("{}", msg);
                        let len = MESSAGES.get().unwrap().lock().unwrap().to_vec().len();
                        MESSAGES.get().unwrap().lock().unwrap().retain(|msg| {
                            msg.block_number > compare_block || msg.identifier != id.clone()
                        });
                        debug!("Messages left: {:#?}", MESSAGES);
                        post_comparison_handler(
                            Arc::clone(MESSAGES.get().unwrap()),
                            compare_block,
                            &id,
                            len,
                        );
                    }
                    Ok(ComparisonResult::NotFound(msg)) => {
                        warn!("{}", msg);
                        MESSAGES.get().unwrap().lock().unwrap().retain(|msg| {
                            msg.block_number > compare_block || msg.identifier != id.clone()
                        });
                        debug!("Messages left: {:#?}", MESSAGES);
                    }
                    Ok(ComparisonResult::Divergent(msg)) => {
                        error!("{}", msg);

                        if let (Ok(token), Ok(channel)) =
                            (env::var("SLACK_TOKEN"), env::var("SLACK_CHANNEL"))
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

                        if let Ok(webhook_url) = env::var("DISCORD_WEBHOOK") {
                            if let Err(e) =
                                DiscordBot::send_webhook(&webhook_url, radio_name, msg.as_str())
                                    .await
                            {
                                warn!("Failed to send notification to Discord: {}", e);
                            }
                        }

                        if runtime_config.panic_if_poi_diverged {
                            panic!("{}", msg);
                        } else {
                            let len = MESSAGES.get().unwrap().lock().unwrap().to_vec().len();
                            MESSAGES.get().unwrap().lock().unwrap().retain(|msg| {
                                msg.block_number > compare_block || msg.identifier != id.clone()
                            });
                            debug!("Messages left: {:#?}", MESSAGES);
                            error!("{}", msg);
                            post_comparison_handler(
                                Arc::clone(MESSAGES.get().unwrap()),
                                compare_block,
                                &id,
                                len,
                            );
                        }
                    }
                    Err(e) => {
                        error!("An error occurred while comparing attestations: {}", e);
                    }
                }
            }

            let poi_query =
                partial!( query_graph_node_poi => graph_node_endpoint.clone(), id.clone(), _, _);

            debug!(
                "Checking latest block number and the message block: {0} >?= {message_block}",
                latest_block.number
            );
            if latest_block.number >= message_block {
                if local_attestations
                    .lock()
                    .await
                    .get(&id)
                    .and_then(|blocks| blocks.get(&message_block))
                    .is_none()
                {
                    let block_hash = match GRAPHCAST_AGENT
                        .get()
                        .unwrap()
                        .get_block_hash(network_name.to_string(), message_block)
                        .await
                    {
                        Ok(hash) => hash,
                        Err(e) => {
                            error!("Failed to query graph node for the block hash: {e}");
                            continue;
                        }
                    };

                    if runtime_config.invalid_payload {
                        // Send dummy msg
                        debug!("Sending dummy message");
                        let radio_message = DummyMsg::new(id.clone(), 5);
                        info!("{}: {:?}", "Attempting to send message", radio_message);

                        match GRAPHCAST_AGENT
                            .get()
                            .unwrap()
                            .send_message(
                                id.clone(),
                                network_name,
                                message_block,
                                Some(radio_message),
                            )
                            .await
                        {
                            Ok(sent) => {
                                info!("{}: {}", "Sent message id", sent);
                            }
                            Err(e) => error!("{}: {}", "Failed to send message", e),
                        };

                        continue;
                    }

                    match poi_query(block_hash.clone(), message_block.try_into().unwrap()).await {
                        Ok(content) => {
                            let radio_message =
                                RadioPayloadMessage::new(id.clone(), content.clone());
                            info!("{}: {:?}", "Attempting to send message", radio_message);

                            match GRAPHCAST_AGENT
                                .get()
                                .unwrap()
                                .send_message(
                                    id.clone(),
                                    network_name,
                                    message_block,
                                    Some(radio_message),
                                )
                                .await
                            {
                                Ok(_) => {
                                    let attestation = Attestation::new(
                                        content.clone(),
                                        my_stake.clone(),
                                        vec![my_address.clone()],
                                        vec![time],
                                    );

                                    save_local_attestation(
                                        &mut *local_attestations.lock().await,
                                        attestation,
                                        id.clone(),
                                        message_block,
                                    );
                                }
                                Err(e) => error!("{}: {}", "Failed to send message", e),
                            };
                        }
                        Err(e) => error!("{}: {}", "Failed to query message", e),
                    }
                } else {
                    trace!("Skipping sending message for block: {}", message_block);
                }
            }
        }

        let graphcast_id = generate_random_address();
        env::set_var("MOCK_SENDER", graphcast_id.clone());
        let indexer_address = generate_deterministic_address(&graphcast_id);

        debug!("Actual graphcast_id: {}", graphcast_id);

        setup_mock_server(
            round_to_nearest(Utc::now().timestamp()).try_into().unwrap(),
            &indexer_address,
            &graphcast_id,
            &runtime_config.subgraphs.clone().unwrap_or(vec![
                MOCK_SUBGRAPH_MAINNET.to_string(),
                MOCK_SUBGRAPH_GOERLI.to_string(),
            ]),
            &runtime_config.indexer_stake,
            &runtime_config.poi,
        )
        .await;
        sleep(Duration::from_secs(5));
        continue;
    }
}
