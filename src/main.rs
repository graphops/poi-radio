use colored::*;
use dotenv::dotenv;
use ethers::signers::LocalWallet;
use ethers::types::Block;
use ethers::{
    providers::{Http, Middleware, Provider},
    types::U64,
};
/// Radio specific query function to fetch Proof of Indexing for each allocated subgraph
use graphcast_sdk::gossip_agent::GossipAgent;
use graphcast_sdk::graphql::client_network::query_network_subgraph;
use graphcast_sdk::graphql::client_registry::query_registry_indexer;
use graphcast_sdk::{init_tracing, operator_address, read_boot_node_addresses};
use num_bigint::BigUint;
use num_traits::Zero;
use poi_radio::{
    active_allocation_hashes, attestation_handler, compare_attestations, process_messages,
    save_local_attestation, Attestation, BlockClock, LocalAttestationsMap, NetworkName,
    RadioPayloadMessage, GOSSIP_AGENT, MESSAGES, NETWORKS,
};
use std::collections::HashMap;
use std::env;
use std::sync::{Arc, Mutex};
use std::{thread::sleep, time::Duration};
use tracing::log::warn;
use tracing::{debug, error, info};

use graphql::query_graph_node_poi;

use crate::graphql::{query_graph_node_deployment_network, query_graph_node_network_block_hash};

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
    let eth_node = env::var("ETH_NODE").expect("No ETH URL provided.");

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

    // Initialize providers for indexing networks in the format of PROVIDER_[NETWORK_NAME]
    let provider_endpoints: HashMap<NetworkName, Option<Provider<Http>>> = NETWORKS
        .iter()
        .map(|n| {
            let network_name = n.name;
            (
                network_name.clone(),
                env::var("PROVIDER_".to_string() + &network_name.to_string().to_uppercase())
                    .ok()
                    .and_then(|endpoint| Provider::<Http>::try_from(endpoint).ok()),
            )
        })
        .collect();

    let wallet = private_key.parse::<LocalWallet>().unwrap();
    let radio_name: &str = "poi-radio";

    let my_address =
        query_registry_indexer(registry_subgraph.to_string(), operator_address(&wallet))
            .await
            .ok();

    let topics = if let Some(addr) = my_address.clone() {
        active_allocation_hashes(&network_subgraph, addr).await.ok()
    } else {
        None
    };

    let gossip_agent = GossipAgent::new(
        private_key,
        eth_node,
        radio_name,
        &registry_subgraph,
        &network_subgraph,
        read_boot_node_addresses(),
        topics,
        waku_node_key,
        waku_host,
        waku_port,
        None,
    )
    .await
    .unwrap();

    _ = GOSSIP_AGENT.set(gossip_agent);
    _ = MESSAGES.set(Arc::new(Mutex::new(vec![])));

    let radio_handler = Arc::new(Mutex::new(attestation_handler()));
    GOSSIP_AGENT
        .get()
        .unwrap()
        .register_handler(radio_handler)
        .expect("Could not register handler");

    let mut block_store: HashMap<NetworkName, BlockClock> = HashMap::new();

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
        // Radio specific message content query function
        // Function takes in an identifier string and make specific queries regarding the identifier
        // The example here combines a single function provided query endpoint, current block info based on the subgraph's indexing network
        // Then the function gets sent to agent for making identifier independent queries
        let identifiers = GOSSIP_AGENT.get().unwrap().content_identifiers();
        for id in identifiers {
            // Get the indexing network of the deployment
            let network_name = match query_graph_node_deployment_network(
                graph_node_endpoint.clone(),
                id.clone(),
            )
            .await
            {
                Ok(network) => NetworkName::from_string(&network),
                Err(e) => {
                    warn!("Could not query for the subgraph's indexing network, check Graph node's indexing statuses of the deployment {}: {}", id.clone(), e);
                    continue;
                }
            };

            let provider_name = format!("PROVIDER_{}", network_name.to_string().to_uppercase());
            let indexing_network_provider = if let Some(provider) = provider_endpoints.get(&network_name) {
                provider.as_ref().unwrap()
            } else {
                error!(
                    "Missing a block provider for the indexing network {}, please provide one named `{}`",
                    network_name,
                    provider_name
                );
                continue;
            };

            let block_number =
                U64::as_u64(&indexing_network_provider.get_block_number().await.unwrap()) - 5;

            let block_clock = block_store
                .entry(network_name)
                .or_insert_with(|| BlockClock {
                    current_block: 0,
                    compare_block: 0,
                });

            if block_clock.current_block == block_number {
                sleep(Duration::from_secs(5));
                continue;
            }

            debug!("{} {}", "🔗 Block number:".cyan(), block_number);
            block_clock.current_block = block_number;

            if block_number == block_clock.compare_block {
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

            // Send POI message at a fixed frequency
            let examination_frequency = NETWORKS
                .iter()
                .find(|n| n.name.to_string() == network_name.to_string())
                .map(|n| n.interval)
                .unwrap_or_else(|| {
                    panic!(
                        "Subgraph is indexing an unsupported network, please report an issue on https://github.com/graphops/graphcast-rs"
                    );
            });

            if block_number % examination_frequency == 0 {
                //TODO: compare_block and attestation need to be network based
                block_clock.compare_block = block_number + wait_block_duration;
                // block number and hash can actually be queried from graph node, but need a deterministic consensus on block number
                let block_hash = match query_graph_node_network_block_hash(
                    graph_node_endpoint.clone(),
                    network_name.to_string().to_lowercase(),
                    block_number.try_into().unwrap(),
                )
                .await
                {
                    Ok(hash) => hash,
                    Err(e) => {
                        warn!("Failed to query graph node for the block hash: {e}");
                        let block: Block<_> = indexing_network_provider
                            .get_block(block_number)
                            .await
                            .unwrap()
                            .unwrap();
                        format!("{:#x}", block.hash.unwrap())
                    }
                };

                match poi_query(block_hash, block_number.try_into().unwrap()).await {
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
                            block_number,
                        );

                        let radio_message = RadioPayloadMessage::new(id.clone(), content.clone());
                        match GOSSIP_AGENT
                            .get()
                            .unwrap()
                            .send_message(id.clone(), block_number, Some(radio_message))
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
            .and(path("/gossip-registry-test"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"{
                    "data": {
                        "graphAccount": {
                            "gossipOperatorOf": {
                                "id": "0x54f4cdc1ac7cd3377f43834fbde09a7ffe6fe337"
                            }
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

        let gossip_agent = GossipAgent::new(
            private_key,
            eth_node,
            radio_name,
            &(mock_server.uri() + "/gossip-registry-test"),
            &(mock_server.uri() + "/network-subgraph"),
            [].to_vec(),
            Some(vec!["some-hash".to_string()]),
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();

        _ = GOSSIP_AGENT.set(gossip_agent);
        _ = MESSAGES.set(Arc::new(Mutex::new(vec![])));

        let radio_handler = Arc::new(Mutex::new(attestation_handler()));
        GOSSIP_AGENT
            .get()
            .unwrap()
            .register_handler(radio_handler)
            .expect("Could not register handler (Should not get here)");
        let hash = "some-hash".to_string();
        let content = "poi".to_string();

        let radio_msg = RadioPayloadMessage::new(hash.clone(), content.clone());
        // Just to introduce sender and skip first time check
        GOSSIP_AGENT
            .get()
            .unwrap()
            .send_message("some-hash".to_string(), 0, Some(radio_msg.clone()))
            .await
            .unwrap();

        sleep(Duration::from_secs(1));

        let mut block = 1;

        loop {
            GOSSIP_AGENT
                .get()
                .unwrap()
                .send_message("some-hash".to_string(), block, Some(radio_msg.clone()))
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
