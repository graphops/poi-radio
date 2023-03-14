use chrono::Utc;
use colored::*;
use dotenv::dotenv;
use ethers::signers::LocalWallet;
/// Radio specific query function to fetch Proof of Indexing for each allocated subgraph
use graphcast_sdk::graphcast_agent::GraphcastAgent;
use graphcast_sdk::graphql::client_network::query_network_subgraph;
use graphcast_sdk::graphql::client_registry::query_registry_indexer;
use graphcast_sdk::{
    graphcast_id_address, init_tracing, read_boot_node_addresses, BlockPointer, NetworkName,
    NETWORKS,
};
use num_bigint::BigUint;
use num_traits::Zero;
use poi_radio::{
    active_allocation_hashes, attestation_handler, compare_attestations, comparison_trigger,
    process_messages, save_local_attestation, Attestation, BlockClock, ComparisonResult,
    LocalAttestationsMap, RadioPayloadMessage, GRAPHCAST_AGENT, MESSAGES,
};
use std::collections::HashMap;
use std::env;
use std::sync::{Arc, Mutex as SyncMutex};
use std::{thread::sleep, time::Duration};
use tokio::sync::Mutex as AsyncMutex;
use tracing::log::warn;
use tracing::{debug, error, info, trace};

use crate::graphql::{query_graph_node_poi, update_network_chainheads};

mod graphql;

#[macro_use]
extern crate partial_application;

#[tokio::main]
async fn main() {
    dotenv().ok();
    init_tracing().expect("Could not set up global default subscriber");

    let graph_node_endpoint =
        env::var("GRAPH_NODE_STATUS_ENDPOINT").expect("No Graph node status endpoint provided.");
    let private_key = env::var("PRIVATE_KEY").expect("No private key provided.");

    // Subgraph endpoints
    let registry_subgraph =
        env::var("REGISTRY_SUBGRAPH").expect("No registry subgraph endpoint provided.");
    let network_subgraph =
        env::var("NETWORK_SUBGRAPH").expect("No network subgraph endpoint provided.");
    let graphcast_network = env::var("GRAPHCAST_NETWORK").ok();

    // Configure the amount of time in seconds spent collecting messages before attesting
    let collect_message_duration: i64 = env::var("COLLECT_MESSAGE_DURATION")
        .unwrap_or("30".to_string())
        .parse::<i64>()
        .unwrap_or(30);

    // Option for where to host the waku node instance
    let waku_host = env::var("WAKU_HOST").ok();
    let waku_port = env::var("WAKU_PORT").ok();
    let waku_node_key = env::var("WAKU_NODE_KEY").ok();

    let wallet = private_key.parse::<LocalWallet>().unwrap();
    let radio_name: &str = "poi-radio";

    let my_address =
        query_registry_indexer(registry_subgraph.to_string(), graphcast_id_address(&wallet))
            .await
            .ok();

    let topics_query = partial!(active_allocation_hashes => &network_subgraph, my_address.clone());
    let topics = topics_query().await;

    let graphcast_agent = GraphcastAgent::new(
        private_key,
        radio_name,
        &registry_subgraph,
        &network_subgraph,
        &graph_node_endpoint,
        read_boot_node_addresses(),
        graphcast_network.as_deref(),
        topics,
        waku_node_key,
        waku_host,
        waku_port,
        None,
    )
    .await
    .unwrap();

    _ = GRAPHCAST_AGENT.set(graphcast_agent);
    _ = MESSAGES.set(Arc::new(SyncMutex::new(vec![])));

    GRAPHCAST_AGENT
        .get()
        .unwrap()
        .register_handler(Arc::new(AsyncMutex::new(attestation_handler())))
        .expect("Could not register handler");

    let mut block_store: HashMap<NetworkName, BlockClock> = HashMap::new();
    let mut network_chainhead_blocks: HashMap<NetworkName, BlockPointer> = HashMap::new();
    let local_attestations: Arc<AsyncMutex<LocalAttestationsMap>> =
        Arc::new(AsyncMutex::new(HashMap::new()));

    let my_stake = if let Some(addr) = my_address.clone() {
        query_network_subgraph(network_subgraph.to_string(), addr)
            .await
            .unwrap()
            .indexer_stake()
    } else {
        BigUint::zero()
    };
    info!(
        "Acting on behalf of indexer {:#?} with stake {}",
        my_address, my_stake
    );

    // Main loop for sending messages, can factor out
    // and take radio specific query and parsing for radioPayload
    loop {
        // Update topic subscription
        if Utc::now().timestamp() % 120 == 0 {
            GRAPHCAST_AGENT
                .get()
                .unwrap()
                .update_content_topics(topics_query().await)
                .await;
        }
        // Update all the chainheads of the network
        // Also get a hash map returned on the subgraph mapped to network name and latest block
        let subgraph_network_latest_blocks = match update_network_chainheads(
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
        trace!(
            "Subgraph network and latest blocks: {:#?}\nNetwork chainhead: {:#?}",
            subgraph_network_latest_blocks,
            network_chainhead_blocks
        );
        //TODO: check that if no networks had an new message update blocks, sleep for a few seconds and 'continue'

        // Radio specific message content query function
        // Function takes in an identifier string and make specific queries regarding the identifier
        // The example here combines a single function provided query endpoint, current block info based on the subgraph's indexing network
        // Then the function gets sent to agent for making identifier independent queries
        let identifiers = GRAPHCAST_AGENT.get().unwrap().content_identifiers().await;
        for id in identifiers {
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

            // Get the examination frequency of the network
            let examination_frequency = match NETWORKS
                .iter()
                .find(|n| n.name.to_string() == network_name.to_string())
            {
                Some(n) => n.interval,
                None => {
                    warn!("Subgraph is indexing an unsupported network, please report an issue on https://github.com/graphops/graphcast-rs");
                    continue;
                }
            };

            // Calculate the block to send message about
            let message_block = match network_chainhead_blocks.get(&network_name) {
                Some(BlockPointer { hash: _, number }) => number - number % examination_frequency,
                None => {
                    error!(
                        "Could not get the chainhead block number on network {} and cannot determine the block to send message about",
                        network_name.to_string(),
                    );
                    continue;
                }
            };

            let block_clock = block_store
                .entry(network_name)
                .or_insert_with(|| BlockClock {
                    current_block: latest_block.number,
                    compare_block: message_block,
                });

            // Wait a bit before querying information on the current block
            if block_clock.current_block == message_block {
                sleep(Duration::from_secs(5));
                continue;
            }

            let msgs = MESSAGES.get().unwrap().lock().unwrap().to_vec();
            // first stored message block
            let (compare_block, comparison_trigger) = comparison_trigger(
                Arc::new(AsyncMutex::new(msgs)),
                id.clone(),
                collect_message_duration,
            )
            .await;

            info!(
                "{} {} {} {} {} {} {} {}",
                "🔗 Message block: ".cyan(),
                message_block,
                "🔗 Current block from block clock: ".cyan(),
                block_clock.current_block,
                "🔗 Latest block: ".cyan(),
                latest_block.number,
                "🔗 Compare block: ".cyan(),
                compare_block
            );

            // Update block clock
            block_clock.current_block = latest_block.number;

            if Utc::now().timestamp() >= comparison_trigger {
                info!("{}", "Comparing attestations");
                trace!("{}{:?}", "Messages: ", MESSAGES);

                let msgs = MESSAGES.get().unwrap().lock().unwrap().to_vec();
                let remote_attestations = process_messages(
                    Arc::new(AsyncMutex::new(msgs)),
                    &registry_subgraph,
                    &network_subgraph,
                )
                .await;
                match remote_attestations {
                    Ok(remote_attestations) => {
                        let comparison_result = compare_attestations(
                            compare_block,
                            remote_attestations.clone(),
                            Arc::clone(&local_attestations),
                        )
                        .await;

                        match comparison_result {
                            Ok(ComparisonResult::Match(msg)) => {
                                info!("{}", msg.green().bold());
                                // Only clear the ones matching identifier and block number
                                MESSAGES.get().unwrap().lock().unwrap().retain(|msg| {
                                    msg.block_number != compare_block
                                        || msg.identifier != id.clone()
                                });
                                debug!("Messages left: {:#?}", MESSAGES);
                            }
                            Ok(ComparisonResult::NotFound(m)) => {
                                warn!("{}", m);
                                MESSAGES.get().unwrap().lock().unwrap().retain(|msg| {
                                    msg.block_number != compare_block
                                        || msg.identifier != id.clone()
                                });
                                debug!("Messages left: {:#?}", MESSAGES);
                            }
                            Ok(ComparisonResult::Divergent(m)) => {
                                error!("{}", m);
                                MESSAGES.get().unwrap().lock().unwrap().retain(|msg| {
                                    msg.block_number != compare_block
                                        || msg.identifier != id.clone()
                                });
                                debug!("Messages left: {:#?}", MESSAGES);
                            }
                            Err(e) => {
                                error!("An error occured while comparing attestations: {}", e);
                            }
                        }
                    }
                    Err(err) => {
                        error!(
                            "{}{}",
                            "An error occured while parsing messages: {}".red().bold(),
                            err
                        );
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

                match poi_query(block_hash.clone(), message_block.try_into().unwrap()).await {
                    Ok(content) => {
                        let attestation = Attestation {
                            npoi: content.clone(),
                            stake_weight: my_stake.clone(),
                            senders: Vec::new(),
                        };

                        save_local_attestation(
                            &mut *local_attestations.lock().await,
                            attestation,
                            id.clone(),
                            message_block,
                        );

                        let radio_message = RadioPayloadMessage::new(id.clone(), content.clone());
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
                            Ok(sent) => info!("{}: {}", "Sent message id".green(), sent),
                            Err(e) => error!("{}: {}", "Failed to send message".red(), e),
                        };
                    }
                    Err(e) => error!("{}: {}", "Failed to query message".red(), e),
                }
            }
        }

        sleep(Duration::from_secs(5));
        continue;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex::encode;
    use rand::{thread_rng, Rng};
    use secp256k1::SecretKey;
    use std::sync::{Arc, Mutex as SyncMutex};
    use tokio::sync::Mutex as AsyncMutex;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    #[ignore]
    async fn regression_test() {
        dotenv().ok();

        let is_display = matches!(std::env::args().nth(1), Some(x) if x == *"display");
        let mut rng = thread_rng();
        let mut private_key = [0u8; 32];
        rng.fill(&mut private_key[..]);

        let private_key = SecretKey::from_slice(&private_key).expect("Error parsing secret key");
        let private_key_hex = encode(private_key.secret_bytes());
        env::set_var("PRIVATE_KEY", &private_key_hex);

        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/graphcast-registry"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"{
                    "data": {
                        "indexer": {
                            "graphcastID": "0x54f4cdc1ac7cd3377f43834fbde09a7ffe6fe337"
                        }
                    },
                    "errors": null
                }"#,
            ))
            .mount(&mock_server)
            .await;

        Mock::given(method("POST"))
            .and(path("/network-subgraph"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"{
                    "data": {
                        "indexer" : {
                            "stakedTokens": "100000000000000000000000",
                            "allocations": [{
                                "subgraphDeployment": {
                                    "ipfsHash": "QmbaLc7fEfLGUioKWehRhq838rRzeR8cBoapNJWNSAZE8u"
                                }
                            }]
                        },
                        "graphNetwork": {
                            "minimumIndexerStake": "100000000000000000000000"
                        }
                    },
                    "errors": null
                }"#,
            ))
            .mount(&mock_server)
            .await;

        Mock::given(method("POST"))
            .and(path("/graph-node-status"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"{
                    "data": {
                        "block_hash_from_number" : "193bb3a5e78b8726f6138cfae7dd18c83fe32843032999966fd2ca6973f88f3b"
                    },
                    "errors": null
                }"#,
            ))
            .mount(&mock_server)
            .await;

        let private_key = env::var("PRIVATE_KEY").expect("No private key provided.");

        // TODO: Add something random and unique here to avoid noise form other operators
        let radio_name: &str = "test-poi-crosschecker-radio";

        let graphcast_agent = GraphcastAgent::new(
            private_key,
            radio_name,
            &(mock_server.uri() + "/graphcast-registry"),
            &(mock_server.uri() + "/network-subgraph"),
            &(mock_server.uri() + "/graph-node-status"),
            [].to_vec(),
            Some("default"),
            vec!["some-hash".to_string()],
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();

        _ = GRAPHCAST_AGENT.set(graphcast_agent);
        _ = MESSAGES.set(Arc::new(SyncMutex::new(vec![])));

        GRAPHCAST_AGENT
            .get()
            .unwrap()
            .register_handler(Arc::new(AsyncMutex::new(attestation_handler())))
            .expect("Could not register handler (Should not get here)");
        let hash = "some-hash".to_string();
        let content = "poi".to_string();

        let radio_msg = RadioPayloadMessage::new(hash.clone(), content.clone());
        let network = NetworkName::from_string("goerli");
        let mut block = 0;
        // Just to introduce sender and skip first time check
        GRAPHCAST_AGENT
            .get()
            .unwrap()
            .send_message(
                "some-hash".to_string(),
                network,
                block,
                Some(radio_msg.clone()),
            )
            .await
            .unwrap();

        sleep(Duration::from_secs(1));

        loop {
            GRAPHCAST_AGENT
                .get()
                .unwrap()
                .send_message(
                    "some-hash".to_string(),
                    network,
                    block,
                    Some(radio_msg.clone()),
                )
                .await
                .unwrap();

            if is_display && MESSAGES.get().unwrap().lock().unwrap().len() > 4 {
                break;
            }

            block += 1;
            sleep(Duration::from_secs(1));
        }
    }
}
