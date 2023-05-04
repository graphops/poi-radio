use chrono::Utc;
use dotenv::dotenv;
use graphcast_sdk::graphql::client_graph_node::update_chainhead_blocks;
use graphcast_sdk::networks::NetworkName;

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as SyncMutex};
use std::{thread::sleep, time::Duration};
use tokio::sync::Mutex as AsyncMutex;
use tracing::{debug, error, info, trace};

use graphcast_sdk::graphcast_agent::GraphcastAgent;
use graphcast_sdk::graphql::{
    client_network::query_network_subgraph, client_registry::query_registry_indexer,
};
use graphcast_sdk::{build_wallet, graphcast_id_address, BlockPointer};

use poi_radio::config::Config;
use poi_radio::metrics::handle_serve_metrics;
use poi_radio::operation::gossip_poi;
use poi_radio::server::run_server;
use poi_radio::CONFIG;
use poi_radio::{
    attestation::LocalAttestationsMap, chainhead_block_str, generate_topics, radio_msg_handler,
    GRAPHCAST_AGENT, MESSAGES,
};

#[macro_use]
extern crate partial_application;

#[tokio::main]
async fn main() {
    let radio_name: &str = "poi-radio";
    dotenv().ok();

    // Parse basic configurations
    let radio_config = Config::args();

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
        .to_graphcast_agent_config(radio_name)
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

    info!("Found content topics for subscription: {:?}", topics);
    _ = MESSAGES.set(Arc::new(SyncMutex::new(vec![])));

    GRAPHCAST_AGENT
        .get()
        .unwrap()
        .register_handler(Arc::new(AsyncMutex::new(radio_msg_handler())))
        .expect("Could not register handler");
    let local_attestations: Arc<AsyncMutex<LocalAttestationsMap>> =
        Arc::new(AsyncMutex::new(HashMap::new()));

    _ = CONFIG.set(Arc::new(SyncMutex::new(radio_config)));
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

        gossip_poi(
            identifiers,
            &network_chainhead_blocks,
            &subgraph_network_latest_blocks,
            local_attestations,
        )
        .await;

        sleep(Duration::from_secs(5));
        continue;
    }
}
