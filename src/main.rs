use colored::*;
use dotenv::dotenv;
use ethers::signers::LocalWallet;
/// Radio specific query function to fetch Proof of Indexing for each allocated subgraph
use graphcast_sdk::graphcast_agent::GraphcastAgent;
use graphcast_sdk::graphql::client_network::query_network_subgraph;
use graphcast_sdk::graphql::client_registry::query_registry_indexer;
use graphcast_sdk::{graphcast_id_address, init_tracing, read_boot_node_addresses};
use hex::encode;
use num_bigint::BigUint;
use num_traits::Zero;
use poi_radio::{
    attestation_handler, compare_attestations, process_messages, save_local_attestation,
    Attestation, BlockClock, BlockPointer, LocalAttestationsMap, NetworkName, RadioPayloadMessage,
    GRAPHCAST_AGENT, MESSAGES, NETWORKS,
};
use rand::{thread_rng, Rng};
use secp256k1::SecretKey;
use std::collections::HashMap;
use std::env;
use std::sync::{Arc, Mutex};
use std::{thread::sleep, time::Duration};
use tracing::log::warn;
use tracing::{debug, error, info};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::graphql::{
    query_graph_node_network_block_hash, query_graph_node_poi, update_network_chainheads,
};

mod graphql;

#[macro_use]
extern crate partial_application;

#[tokio::main]
async fn main() {
    dotenv().ok();
    init_tracing().expect("Could not set up global default subscriber");

    let private_key = env::var("PRIVATE_KEY").expect("No private key provided.");

    // Subgraph endpoints
    let registry_subgraph =
        env::var("REGISTRY_SUBGRAPH").expect("No registry subgraph endpoint provided.");
    let network_subgraph =
        env::var("NETWORK_SUBGRAPH").expect("No network subgraph endpoint provided.");

    // Option for where to host the waku node instance
    let waku_host = env::var("WAKU_HOST").ok();
    let waku_port = env::var("WAKU_PORT").ok();
    let waku_node_key = env::var("WAKU_NODE_KEY").ok();

    // Send message every x blocks for which wait y blocks before attestations
    let wait_block_duration = 2;

    let wallet = private_key.parse::<LocalWallet>().unwrap();
    let mut rng = thread_rng();
    let mut private_key = [0u8; 32];
    rng.fill(&mut private_key[..]);

    let private_key = SecretKey::from_slice(&private_key).expect("Error parsing secret key");
    let private_key_hex = encode(private_key.secret_bytes());
    env::set_var("PRIVATE_KEY", &private_key_hex);

    //&(mock_server.uri() + "/graphcast-registry"&(mock_server.uri() + "/graphcast-registry"

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
        .and(path("/graphql"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"{
                "data": {
                  "proofOfIndexing": "0x25331f98b82ca7f3966256bf508a7ede52e715b631dfa3d73b846bb7617f6b9e",
                  "blockHashFromNumber":"4dbba1ba9fb18b0034965712598be1368edcf91ae2c551d59462aab578dab9c5",
                  "indexingStatuses": [
                    {
                      "subgraph": "QmggQnSgia4iDPWHpeY6aWxesRFdb8o5DKZUx96zZqEWrB",
                      "synced": true,
                      "health": "healthy",
                      "fatalError": null,
                      "chains": [
                        {
                          "network": "mainnet",
                          "latestBlock": {
                            "number": "16642243",
                            "hash": "b30395958a317ccc06da46782f660ce674cbe6792e5573dc630978c506114a0a"
                          },
                          "chainHeadBlock": {
                            "number": "16642243",
                            "hash": "b30395958a317ccc06da46782f660ce674cbe6792e5573dc630978c506114a0a"
                          }
                        }
                      ]
                    }
                  ]
                }
              }
              "#,
        ))
        .mount(&mock_server)
        .await;

    env::set_var(
        "GRAPH_NODE_STATUS_ENDPOINT",
        format!("{}{}", &mock_server.uri(), "/graphql"),
    );

    env::set_var(
        "REGISTRY_SUBGRAPH_ENDPOINT",
        format!("{}{}", &mock_server.uri(), "/graphcast-registry"),
    );

    let graph_node_endpoint =
        env::var("GRAPH_NODE_STATUS_ENDPOINT").expect("No Graph node status endpoint provided.");

    let private_key = env::var("PRIVATE_KEY").unwrap();
    let eth_node = env::var("ETH_NODE").expect("No ETH URL provided.");

    // TODO: Add something random and unique here to avoid noise form other operators
    let radio_name: &str = "test-poi-radio";

    let my_address =
        query_registry_indexer(registry_subgraph.to_string(), graphcast_id_address(&wallet))
            .await
            .ok();

    let graphcast_agent = GraphcastAgent::new(
        private_key,
        eth_node,
        radio_name,
        &(mock_server.uri() + "/graphcast-registry"),
        &(mock_server.uri() + "/network-subgraph"),
        read_boot_node_addresses(),
        Some(vec![
            "QmggQnSgia4iDPWHpeY6aWxesRFdb8o5DKZUx96zZqEWrB".to_string()
        ]),
        waku_node_key,
        waku_host,
        waku_port,
        None,
    )
    .await
    .unwrap();

    _ = GRAPHCAST_AGENT.set(graphcast_agent);
    _ = MESSAGES.set(Arc::new(Mutex::new(vec![])));

    let radio_handler = Arc::new(Mutex::new(attestation_handler()));
    GRAPHCAST_AGENT
        .get()
        .unwrap()
        .register_handler(radio_handler)
        .expect("Could not register handler");

    let mut block_store: HashMap<NetworkName, BlockClock> = HashMap::new();
    let mut network_chainhead_blocks: HashMap<NetworkName, BlockPointer> = HashMap::new();
    let local_attestations: Arc<Mutex<LocalAttestationsMap>> = Arc::new(Mutex::new(HashMap::new()));

    let my_stake = if let Some(addr) = my_address.clone() {
        query_network_subgraph(network_subgraph.to_string(), addr)
            .await
            .unwrap()
            .indexer_stake()
    } else {
        BigUint::zero()
    };
    info!(
        "Acting on behave of indexer {:#?} with stake {}",
        my_address, my_stake
    );

    // Main loop for sending messages, can factor out
    // and take radio specific query and parsing for radioPayload
    loop {
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
        debug!(
            "Subgraph network and latest blocks: {:#?}\nNetwork chainhead: {:#?}",
            subgraph_network_latest_blocks, network_chainhead_blocks
        );
        //TODO: check that if no networks had an new message update blocks, sleep for a few seconds and 'continue'

        // Radio specific message content query function
        // Function takes in an identifier string and make specific queries regarding the identifier
        // The example here combines a single function provided query endpoint, current block info based on the subgraph's indexing network
        // Then the function gets sent to agent for making identifier independent queries
        let identifiers = GRAPHCAST_AGENT.get().unwrap().content_identifiers();

        info!("debugging with style {:?}", subgraph_network_latest_blocks);

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
                    current_block: 0,
                    compare_block: 0,
                });

            // Wait a bit before querying information on the current block
            if block_clock.current_block == message_block {
                sleep(Duration::from_secs(5));
                continue;
            }

            debug!("{} {}", "🔗 Block number:".cyan(), message_block);
            block_clock.current_block = latest_block.number;

            if latest_block.number == block_clock.compare_block {
                debug!("{}", "Comparing attestations".magenta());

                let remote_attestations = process_messages(
                    Arc::clone(MESSAGES.get().unwrap()),
                    &registry_subgraph,
                    &network_subgraph,
                )
                .await;
                match remote_attestations {
                    Ok(remote_attestations) => {
                        let mut messages = MESSAGES.get().unwrap().lock().unwrap();
                        match compare_attestations(
                            block_clock.compare_block - wait_block_duration,
                            remote_attestations,
                            Arc::clone(&local_attestations),
                        ) {
                            Ok(msg) => {
                                debug!("{}", msg.green().bold());
                                messages.clear();
                            }
                            Err(err) => {
                                error!("{}", err);
                                messages.clear();
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
                block_clock.compare_block = message_block + wait_block_duration;
                // block number and hash can actually be queried from graph node, but need a deterministic consensus on block number
                let block_hash = match query_graph_node_network_block_hash(
                    graph_node_endpoint.clone(),
                    network_name.to_string().to_lowercase(),
                    message_block.try_into().unwrap(),
                )
                .await
                {
                    Ok(hash) => hash,
                    Err(e) => {
                        error!("Failed to query graph node for the block hash: {e}");
                        continue;
                    }
                };

                match poi_query(block_hash, message_block.try_into().unwrap()).await {
                    Ok(content) => {
                        let attestation = Attestation {
                            npoi: content.clone(),
                            stake_weight: my_stake.clone(),
                            senders: Vec::new(),
                        };

                        save_local_attestation(
                            &mut local_attestations.lock().unwrap(),
                            attestation,
                            id.clone(),
                            message_block,
                        );

                        let radio_message = RadioPayloadMessage::new(id.clone(), content.clone());
                        match GRAPHCAST_AGENT
                            .get()
                            .unwrap()
                            .send_message(id.clone(), message_block, Some(radio_message))
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

        let private_key = env::var("PRIVATE_KEY").expect("No private key provided.");
        let eth_node = env::var("ETH_NODE").expect("No ETH URL provided.");

        // TODO: Add something random and unique here to avoid noise form other operators
        let radio_name: &str = "test-poi-crosschecker-radio";

        let graphcast_agent = GraphcastAgent::new(
            private_key,
            eth_node,
            radio_name,
            &(mock_server.uri() + "/graphcast-registry"),
            &(mock_server.uri() + "/network-subgraph"),
            [].to_vec(),
            Some(vec![
                "QmggQnSgia4iDPWHpeY6aWxesRFdb8o5DKZUx96zZqEWrB".to_string()
            ]),
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();

        _ = GRAPHCAST_AGENT.set(graphcast_agent);
        _ = MESSAGES.set(Arc::new(Mutex::new(vec![])));

        let radio_handler = Arc::new(Mutex::new(attestation_handler()));
        GRAPHCAST_AGENT
            .get()
            .unwrap()
            .register_handler(radio_handler)
            .expect("Could not register handler (Should not get here)");
        let hash = "QmggQnSgia4iDPWHpeY6aWxesRFdb8o5DKZUx96zZqEWrB".to_string();
        let content = "poi".to_string();

        let radio_msg = RadioPayloadMessage::new(hash.clone(), content.clone());
        // Just to introduce sender and skip first time check
        GRAPHCAST_AGENT
            .get()
            .unwrap()
            .send_message(
                "QmggQnSgia4iDPWHpeY6aWxesRFdb8o5DKZUx96zZqEWrB".to_string(),
                0,
                Some(radio_msg.clone()),
            )
            .await
            .unwrap();

        sleep(Duration::from_secs(1));

        let mut block = 1;

        loop {
            GRAPHCAST_AGENT
                .get()
                .unwrap()
                .send_message(
                    "QmggQnSgia4iDPWHpeY6aWxesRFdb8o5DKZUx96zZqEWrB".to_string(),
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
