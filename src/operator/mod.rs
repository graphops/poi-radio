use derive_getters::Getters;
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex as SyncMutex};
use std::thread;
use std::time::Duration;
use tokio::sync::Mutex as AsyncMutex;
use tokio::time::{interval, sleep, timeout};
use tracing::{debug, error, info, trace, warn};

use graphcast_sdk::{
    build_wallet,
    graphcast_agent::{message_typing::GraphcastMessage, GraphcastAgent},
    graphcast_id_address,
    graphql::{
        client_graph_node::{subgraph_network_blocks, update_network_chainheads},
        client_registry::query_registry_indexer,
    },
};

use crate::chainhead_block_str;
use crate::metrics::handle_serve_metrics;
use crate::operator::attestation::log_gossip_summary;
use crate::operator::attestation::process_comparison_results;
use crate::server::run_server;
use crate::state::PersistedState;
use crate::{config::Config, metrics::CACHED_MESSAGES};
use crate::{RadioPayloadMessage, GRAPHCAST_AGENT};

use self::notifier::Notifier;

pub mod attestation;
pub mod callbook;
pub mod notifier;
pub mod operation;

/// Aggregated control flow configurations
/// Not used currently
#[derive(Getters)]
#[allow(unused)]
struct ControlFlow {
    running: Arc<AtomicBool>,
    skip_iteration: Arc<AtomicBool>,
    iteration_timeout: Duration,
    update_timeout: Duration,
    gossip_timeout: Duration,
    topic_update_duration: Duration,
    state_update_duration: Duration,
    gossip_poi_duration: Duration,
    comparison_duration: Duration,
}

impl ControlFlow {
    fn new() -> Self {
        let running = Arc::new(AtomicBool::new(true));
        let skip_iteration = Arc::new(AtomicBool::new(false));

        let topic_update_duration = Duration::from_secs(600);
        let state_update_duration = Duration::from_secs(15);
        let gossip_poi_duration = Duration::from_secs(30);
        let comparison_duration = Duration::from_secs(60);

        let iteration_timeout = Duration::from_secs(180);
        let update_timeout = Duration::from_secs(10);
        let gossip_timeout = Duration::from_secs(150);

        ControlFlow {
            running,
            skip_iteration,
            iteration_timeout,
            update_timeout,
            gossip_timeout,
            topic_update_duration,
            state_update_duration,
            gossip_poi_duration,
            comparison_duration,
        }
    }
}

/// Radio operator contains all states needed for radio operations
#[allow(unused)]
pub struct RadioOperator {
    config: Config,
    persisted_state: Arc<SyncMutex<PersistedState>>,
    graphcast_agent: Arc<GraphcastAgent>,
    notifier: Notifier,
    control_flow: ControlFlow,
    indexer_address: String,
}

impl RadioOperator {
    /// Create a radio operator with radio configurations, persisted data,
    /// graphcast agent, and control flow
    pub async fn new(config: Config) -> RadioOperator {
        debug!("Initializing Radio operator");
        let wallet = build_wallet(
            config
                .wallet_input()
                .expect("Operator wallet input invalid"),
        )
        .expect("Radio operator cannot build wallet");
        // The query here must be Ok but so it is okay to panic here
        // Alternatively, make validate_set_up return wallet, address, and stake
        let indexer_address = query_registry_indexer(
            config.registry_subgraph.to_string(),
            graphcast_id_address(&wallet),
        )
        .await
        .expect("Radio operator registered to indexer");

        debug!("Initializing program state");
        // Initialize program state
        let persisted_state: Arc<SyncMutex<PersistedState>> =
            Arc::new(SyncMutex::new(config.init_radio_state().await));

        debug!("Initializing Graphcast Agent");
        let graphcast_agent = Arc::new(
            config
                .create_graphcast_agent()
                .await
                .expect("Initialize Graphcast agent"),
        );
        debug!("Set global static instance of graphcast_agent");
        _ = GRAPHCAST_AGENT.set(graphcast_agent.clone());

        let notifier = Notifier::from_config(&config);

        RadioOperator {
            config,
            persisted_state,
            graphcast_agent,
            notifier,
            control_flow: ControlFlow::new(),
            indexer_address,
        }
    }

    /// Preparation for running the radio applications
    /// Expose metrics and subscribe to graphcast topics
    pub async fn prepare(&self) {
        // Set up Prometheus metrics url if configured
        if let Some(port) = self.config.metrics_port {
            debug!("Initializing metrics port");
            tokio::spawn(handle_serve_metrics(self.config.metrics_host.clone(), port));
        }

        // Provide generated topics to Graphcast agent
        let topics = self
            .config
            .generate_topics(self.indexer_address.clone())
            .await;
        debug!(
            topics = tracing::field::debug(&topics),
            "Found content topics for subscription",
        );
        self.graphcast_agent
            .update_content_topics(topics.clone())
            .await;

        let (sender, receiver) = mpsc::channel::<GraphcastMessage<RadioPayloadMessage>>();
        let handler = RadioOperator::radio_msg_handler(SyncMutex::new(sender));
        GRAPHCAST_AGENT
            .get()
            .unwrap()
            .register_handler(Arc::new(AsyncMutex::new(handler)))
            .expect("Could not register handler");
        let state_ref = self.persisted_state.clone();
        thread::spawn(move || {
            for msg in receiver {
                trace!(
                    "Radio operator received a validated message from Graphcast agent: {:#?}",
                    msg
                );
                let identifier = msg.identifier.clone();
                state_ref
                    .lock()
                    .unwrap()
                    .remote_messages()
                    .lock()
                    .unwrap()
                    .push(msg.clone());
                CACHED_MESSAGES.with_label_values(&[&identifier]).set(
                    state_ref
                        .lock()
                        .unwrap()
                        .remote_messages()
                        .lock()
                        .unwrap()
                        .iter()
                        .filter(|m| m.identifier == identifier)
                        .collect::<Vec<&GraphcastMessage<RadioPayloadMessage>>>()
                        .len()
                        .try_into()
                        .unwrap(),
                );
            }
        });
    }

    pub fn graphcast_agent(&self) -> &GraphcastAgent {
        &self.graphcast_agent
    }

    /// Read persisted state at the time of access
    pub async fn state(&self) -> PersistedState {
        self.persisted_state.lock().unwrap().clone()
    }

    /// Radio operations
    pub async fn run(&self) {
        // Control flow
        // TODO: expose to radio config for the users
        let running = Arc::new(AtomicBool::new(true));
        let skip_iteration = Arc::new(AtomicBool::new(false));
        let skip_iteration_clone = skip_iteration.clone();

        let mut topic_update_interval = interval(Duration::from_secs(600));
        let mut state_update_interval = interval(Duration::from_secs(60));
        let mut gossip_poi_interval = interval(Duration::from_secs(30));
        let mut comparison_interval = interval(Duration::from_secs(30));

        let iteration_timeout = Duration::from_secs(180);
        let update_timeout = Duration::from_secs(5);
        let gossip_timeout = Duration::from_secs(120);

        // Separate thread to skip a main loop iteration when hit timeout
        tokio::spawn(async move {
            tokio::time::sleep(iteration_timeout).await;
            skip_iteration_clone.store(true, Ordering::SeqCst);
        });

        let mut divergent_subgraphs: HashSet<String> = HashSet::new();

        // Initialize Http server with graceful shutdown if configured
        if self.config.server_port().is_some() {
            tokio::spawn(run_server(
                self.config.clone(),
                self.persisted_state.clone(),
                running.clone(),
            ));
        }

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
                        self.graphcast_agent()
                        .update_content_topics(self.config.generate_topics(self.indexer_address.clone()).await)
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

                    // Save cache if path provided
                    let _ = &self.config.persistence_file_path.as_ref().map(|path| {
                        self.persisted_state.lock().unwrap().update_cache(path);
                    });
                },
                _ = gossip_poi_interval.tick() => {
                    if skip_iteration.load(Ordering::SeqCst) {
                        skip_iteration.store(false, Ordering::SeqCst);
                        continue;
                    }

                    let result = timeout(gossip_timeout, {
                        // Update all the chainheads of the network
                        // Also get a hash map returned on the subgraph mapped to network name and latest block
                        let network_chainhead_blocks = match self.config.callbook().indexing_statuses().await {
                            Ok(res) => update_network_chainheads(
                                res,
                            ),
                            Err(e) => {
                                error!(err = tracing::field::debug(&e), "Could not query indexing statuses, pull again later");
                                continue;
                            }
                        };
                        // Separate calls to indexing_statuses as it is not cloneable
                        let subgraph_network_latest_blocks = match self.config.callbook().indexing_statuses().await {
                            Ok(res) => subgraph_network_blocks(res),
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
                        let identifiers = self.graphcast_agent.content_identifiers().await;
                        let num_topics = identifiers.len();
                        let blocks_str = chainhead_block_str(&network_chainhead_blocks);
                        info!(
                            chainhead = blocks_str.clone(),
                            num_gossip_peers = self.graphcast_agent.number_of_peers(),
                            num_topics,
                            "Network statuses",
                        );

                        let send_ops = self.gossip_poi(
                            identifiers.clone(),
                            &network_chainhead_blocks.clone(),
                            &subgraph_network_latest_blocks,
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

                    let result = timeout(update_timeout, {
                        // Update all the chainheads of the network
                        // Also get a hash map returned on the subgraph mapped to network name and latest block
                        let indexing_status = match self.config.callbook().indexing_statuses().await {
                            Ok(res) => res,
                            Err(e) => {
                                error!(err = tracing::field::debug(&e), "Could not query indexing statuses, pull again later");
                                continue;
                            }
                        };
                        let network_chainhead_blocks = update_network_chainheads(
                                indexing_status,
                            );
                        let identifiers = self.graphcast_agent().content_identifiers().await;
                        let blocks_str = chainhead_block_str(&network_chainhead_blocks);

                        let comparison_res = self.compare_poi(
                            identifiers.clone(),
                        )
                        .await;

                        process_comparison_results(
                            blocks_str,
                            identifiers.len(),
                            comparison_res,
                            &mut divergent_subgraphs,
                            self.notifier.clone()
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

            sleep(Duration::from_secs(5)).await;
            continue;
        }
    }
}
