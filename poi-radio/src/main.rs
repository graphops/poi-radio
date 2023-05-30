use dotenv::dotenv;
use poi_radio::attestation::process_comparison_results;
use poi_radio::notifier::Notifier;
use poi_radio::radio_name;
use std::collections::{HashMap, HashSet};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex as SyncMutex,
};
use std::thread::sleep;
use tokio::{
    sync::Mutex as AsyncMutex,
    time::{interval, timeout, Duration},
};
use tracing::{debug, error, info, trace, warn};

use graphcast_sdk::{
    graphql::client_graph_node::{
        get_indexing_statuses, update_chainhead_blocks, update_network_chainheads,
    },
    networks::NetworkName,
    BlockPointer,
};
use poi_radio::{
    attestation::{log_gossip_summary, LocalAttestationsMap},
    chainhead_block_str,
    config::Config,
    generate_topics,
    metrics::handle_serve_metrics,
    operation::{compare_poi, gossip_poi},
    radio_msg_handler,
    server::run_server,
    CONFIG, GRAPHCAST_AGENT, MESSAGES,
};

#[macro_use]
extern crate partial_application;

#[tokio::main]
async fn main() {
    dotenv().ok();

    // Parse basic configurations
    let radio_config = Config::args();

    // Set up Prometheus metrics url if configured
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
    _ = GRAPHCAST_AGENT.set(
        radio_config
            .create_graphcast_agent()
            .await
            .expect("Initialize Graphcast agent"),
    );
    debug!("Initialized Graphcast Agent");

    // Initialize program state
    _ = CONFIG.set(Arc::new(SyncMutex::new(radio_config.clone())));
    let state = radio_config.init_radio_state().await;
    _ = MESSAGES.set(state.remote_messages());
    let local_attestations: Arc<AsyncMutex<LocalAttestationsMap>> =
        Arc::new(AsyncMutex::new(state.local_attestations()));

    let (my_address, _) = radio_config.basic_info().await.unwrap();
    let topic_coverage = radio_config.coverage.clone();
    let topic_network = radio_config.network_subgraph.clone();
    let topic_graph_node = radio_config.graph_node_endpoint.clone();
    let topic_static = &radio_config.topics.clone();
    let generate_topics = partial!(generate_topics => topic_coverage.clone(), topic_network.clone(), my_address.clone(), topic_graph_node.clone(), topic_static);
    let topics = generate_topics().await;
    debug!(
        topics = tracing::field::debug(&topics),
        "Found content topics for subscription",
    );
    GRAPHCAST_AGENT
        .get()
        .unwrap()
        .update_content_topics(topics.clone())
        .await;

    GRAPHCAST_AGENT
        .get()
        .unwrap()
        .register_handler(Arc::new(AsyncMutex::new(radio_msg_handler())))
        .expect("Could not register handler");

    // Control flow
    // TODO: expose to radio config for the users
    let running = Arc::new(AtomicBool::new(true));
    let skip_iteration = Arc::new(AtomicBool::new(false));
    let skip_iteration_clone = skip_iteration.clone();

    let mut topic_update_interval = interval(Duration::from_secs(600));
    let mut state_update_interval = interval(Duration::from_secs(15));
    let mut gossip_poi_interval = interval(Duration::from_secs(30));
    let mut comparison_interval = interval(Duration::from_secs(60));

    let iteration_timeout = Duration::from_secs(180);
    let update_timeout = Duration::from_secs(10);
    let gossip_timeout = Duration::from_secs(150);

    let notifier = Notifier::from_config(radio_name(), &CONFIG.get().unwrap().lock().unwrap());

    // Separate control flow thread to skip a main loop iteration when hit timeout
    tokio::spawn(async move {
        tokio::time::sleep(iteration_timeout).await;
        skip_iteration_clone.store(true, Ordering::SeqCst);
    });

    // Initialize Http server if configured
    if CONFIG.get().unwrap().lock().unwrap().server_port.is_some() {
        tokio::spawn(run_server(running.clone(), Arc::clone(&local_attestations)));
    }

    let mut divergent_subgraphs: HashSet<String> = HashSet::new();

    // Main loop for sending messages, can factor out
    // and take radio specific query and parsing for radioPayload
    while running.load(Ordering::SeqCst) {
        // Run event intervals sequentially by satisfication of other intervals and corresponding tick
        tokio::select! {
            _ = topic_update_interval.tick() => {
                if skip_iteration.load(Ordering::SeqCst) {
                    skip_iteration.store(false, Ordering::SeqCst);
                    continue;
                }
                // Update topic subscription
                let result = timeout(update_timeout,
                    GRAPHCAST_AGENT
                    .get()
                    .unwrap()
                    .update_content_topics(generate_topics().await)
                ).await;

                if result.is_err() {
                    warn!("update_content_topics timed out");
                } else {
                    debug!("update_content_topics completed");
                }
            },
            _ = state_update_interval.tick() => {
                if skip_iteration.load(Ordering::SeqCst) {
                    skip_iteration.store(false, Ordering::SeqCst);
                    continue;
                }
                // TODO: make operator struct that keeps the global state
                // Update the state to persist
                let result = timeout(update_timeout,
                    state.update(Some(local_attestations.clone()), Some(MESSAGES.get().unwrap().clone()))
                ).await;

                if let Ok(r) = result {
                    debug!("state update completed");

                    // Save cache if path provided
                    if let Some(path) = &radio_config.persistence_file_path.clone() {
                        r.update_cache(path);
                    }
                } else {
                    warn!("state update timed out");
                }
            },
            _ = gossip_poi_interval.tick() => {
                if skip_iteration.load(Ordering::SeqCst) {
                    skip_iteration.store(false, Ordering::SeqCst);
                    continue;
                }

                let result = timeout(gossip_timeout, {
                    let network_chainhead_blocks: Arc<AsyncMutex<HashMap<NetworkName, BlockPointer>>> =
                        Arc::new(AsyncMutex::new(HashMap::new()));
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
                                error!(err = tracing::field::debug(&e), "Could not query indexing statuses, pull again later");
                                continue;
                            }
                        };

                    trace!(
                        network_pointers = tracing::field::debug(&subgraph_network_latest_blocks),
                        "Subgraph network and latest blocks",
                    );

                    // Radio specific message content query function
                    // Function takes in an identifier string and make specific queries regarding the identifier
                    // The example here combines a single function provided query endpoint, current block info based on the subgraph's indexing network
                    // Then the function gets sent to agent for making identifier independent queries
                    let identifiers = GRAPHCAST_AGENT.get().unwrap().content_identifiers().await;
                    let num_topics = identifiers.len();
                    let blocks_str = chainhead_block_str(&*network_chainhead_blocks.lock().await);
                    info!(
                        chainhead = blocks_str.clone(),
                        num_gossip_peers = GRAPHCAST_AGENT.get().unwrap().number_of_peers(),
                        num_topics,
                        "Network statuses",
                    );

                    let send_ops = gossip_poi(
                        identifiers.clone(),
                        &network_chainhead_blocks.clone(),
                        &subgraph_network_latest_blocks.clone(),
                        local_attestations.clone(),
                    ).await;

                    log_gossip_summary(
                        blocks_str,
                        identifiers.len(),
                        send_ops,
                    )
                }).await;

                if result.is_err() {
                    warn!("gossip_poi timed out");
                } else {
                    debug!("gossip_poi completed");
                }
            },
            _ = comparison_interval.tick() => {
                if skip_iteration.load(Ordering::SeqCst) {
                    skip_iteration.store(false, Ordering::SeqCst);
                    continue;
                }

                let result = timeout(gossip_timeout, {
                    let mut network_chainhead_blocks: HashMap<NetworkName, BlockPointer> =
                        HashMap::new();
                    let local_attestations = Arc::clone(&local_attestations);

                    // Update all the chainheads of the network
                    // Also get a hash map returned on the subgraph mapped to network name and latest block
                    let graph_node_endpoint = CONFIG
                        .get()
                        .unwrap()
                        .lock()
                        .unwrap()
                        .graph_node_endpoint
                        .clone();
                    let indexing_status = match get_indexing_statuses(graph_node_endpoint.clone()).await {
                        Ok(res) => res,
                        Err(e) => {
                            error!(err = tracing::field::debug(&e), "Could not query indexing statuses, pull again later");
                            continue;
                        }
                    };
                    update_network_chainheads(
                            indexing_status,
                            &mut network_chainhead_blocks,
                        );

                    let identifiers = GRAPHCAST_AGENT.get().unwrap().content_identifiers().await;
                    let blocks_str = chainhead_block_str(&network_chainhead_blocks);

                    let comparison_res = compare_poi(
                        identifiers.clone(),
                        local_attestations,
                    )
                    .await;

                    process_comparison_results(
                        blocks_str,
                        identifiers.len(),
                        comparison_res,
                        &mut divergent_subgraphs,
                        notifier.clone()
                    )
                }).await;

                if result.is_err() {
                    warn!("compare_poi timed out");
                } else {
                    debug!("compare_poi completed");
                }
            },
            else => break,
        }

        sleep(Duration::from_secs(5));
        continue;
    }
}
