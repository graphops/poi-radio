use clap::Parser;
use ethers::signers::WalletError;
use graphcast_sdk::build_wallet;
use graphcast_sdk::graphcast_agent::GraphcastAgent;
use graphcast_sdk::graphcast_agent::GraphcastAgentConfig;
use graphcast_sdk::graphcast_agent::GraphcastAgentError;
use graphcast_sdk::graphcast_id_address;
use graphcast_sdk::graphql::client_network::query_network_subgraph;
use graphcast_sdk::graphql::client_registry::query_registry_indexer;
use graphcast_sdk::graphql::QueryError;
use graphcast_sdk::init_tracing;
use serde::{Deserialize, Serialize};
use tracing::info;

#[derive(clap::ValueEnum, Clone, Debug, Serialize, Deserialize)]
pub enum CoverageLevel {
    Minimal,
    OnChain,
    Comprehensive,
}

#[derive(Clone, Debug, Parser, Serialize, Deserialize)]
#[clap(
    name = "poi-radio",
    about = "Cross-check POIs with other Indexer in real time",
    author = "GraphOps"
)]
pub struct Config {
    #[clap(
        long,
        value_name = "ENDPOINT",
        env = "GRAPH_NODE_STATUS_ENDPOINT",
        help = "API endpoint to the Graph Node Status Endpoint"
    )]
    pub graph_node_endpoint: String,
    #[clap(
        long,
        value_name = "KEY",
        value_parser = Config::parse_key,
        env = "PRIVATE_KEY",
        hide_env_values = true,
        help = "Private key to the Graphcast ID wallet (Precendence over mnemonics)",
    )]
    pub private_key: Option<String>,
    #[clap(
        long,
        value_name = "KEY",
        value_parser = Config::parse_key,
        env = "MNEMONIC",
        hide_env_values = true,
        help = "Mnemonic to the Graphcast ID wallet (first address of the wallet is used; Only one of private key or mnemonic is needed)",
    )]
    pub mnemonic: Option<String>,
    #[clap(
        long,
        value_name = "SUBGRAPH",
        env = "REGISTRY_SUBGRAPH",
        help = "Subgraph endpoint to the Graphcast Registry",
        default_value = "https://api.thegraph.com/subgraphs/name/hopeyen/graphcast-registry-goerli"
    )]
    pub registry_subgraph: String,
    #[clap(
        long,
        value_name = "SUBGRAPH",
        env = "NETWORK_SUBGRAPH",
        help = "Subgraph endpoint to The Graph network subgraph",
        default_value = "https://gateway.testnet.thegraph.com/network"
    )]
    pub network_subgraph: String,
    #[clap(
        long,
        default_value = "testnet",
        value_name = "NAME",
        env = "GRAPHCAST_NETWORK",
        help = "Supported Graphcast networks: mainnet, testnet",
        possible_values = ["testnet", "mainnet"]
    )]
    pub graphcast_network: String,
    #[clap(
        long,
        value_name = "[TOPIC]",
        value_delimiter = ',',
        env = "TOPICS",
        help = "Comma separated static list of content topics to subscribe to (Static list to include)"
    )]
    pub topics: Vec<String>,
    #[clap(
        long,
        value_name = "COVERAGE",
        value_enum,
        default_value = "on-chain",
        env = "COVERAGE",
        help = "Toggle for topic coverage level",
        long_help = "Topic coverage level\ncomprehensive: Subscribe to on-chain topics, user defined static topics, and additional topics\n
            on-chain: Subscribe to on-chain topics and user defined static topics\nminimal: Only subscribe to user defined static topics.\n
            Default is set to on-chain coverage"
    )]
    pub coverage: CoverageLevel,
    #[clap(
        long,
        min_values = 0,
        default_value = "120",
        value_name = "COLLECT_MESSAGE_DURATION",
        env = "COLLECT_MESSAGE_DURATION",
        help = "Set the minimum duration to wait for a topic message collection"
    )]
    pub collect_message_duration: i64,
    #[clap(
        long,
        value_name = "WAKU_HOST",
        help = "Host for the GraphQL HTTP server",
        env = "WAKU_HOST"
    )]
    pub waku_host: Option<String>,
    #[clap(
        long,
        value_name = "WAKU_PORT",
        help = "Port for the GraphQL HTTP server",
        env = "WAKU_PORT"
    )]
    pub waku_port: Option<String>,
    #[clap(
        long,
        value_name = "KEY",
        env = "WAKU_NODE_KEY",
        hide_env_values = true,
        help = "Private key to the Waku node id"
    )]
    pub waku_node_key: Option<String>,
    #[clap(
        long,
        value_name = "KEY",
        env = "WAKU_ADDRESS",
        hide_env_values = true,
        help = "Advertised address to be connected among the Waku peers"
    )]
    pub waku_addr: Option<String>,
    #[clap(
        long,
        value_name = "NODE_ADDRESSES",
        help = "Comma separated static list of waku boot nodes to connect to",
        env = "BOOT_NODE_ADDRESSES"
    )]
    pub boot_node_addresses: Vec<String>,
    #[clap(
        long,
        value_name = "WAKU_LOG_LEVEL",
        help = "Waku node logging configuration",
        env = "WAKU_LOG_LEVEL"
    )]
    pub waku_log_level: Option<String>,
    #[clap(
        long,
        value_name = "LOG_LEVEL",
        default_value = "info",
        help = "logging configurationt to set as RUST_LOG",
        env = "RUST_LOG"
    )]
    pub log_level: String,
    #[clap(
        long,
        value_name = "SLACK_TOKEN",
        help = "Slack bot API token",
        env = "SLACK_TOKEN"
    )]
    pub slack_token: Option<String>,
    #[clap(
        long,
        value_name = "SLACK_CHANNEL",
        help = "Name of Slack channel to send messages to (has to be a public channel)",
        env = "SLACK_CHANNEL"
    )]
    pub slack_channel: Option<String>,
    #[clap(
        long,
        value_name = "INSTANCE",
        // Basic instance runs with default configs, invalid_payload sends a malformed message, divergent sends an unexpected nPOI value
        possible_values = &["basic", "invalid_payload", "divergent", "invalid_hash", "invalid_nonce"],
        help = "Instance to run (integration tests)"
    )]
    pub instance: Option<String>,
    #[clap(
        long,
        value_name = "CHECK",
        possible_values = &[
            "simple_tests",
            "invalid_sender",
            "poi_divergence_remote",
            "poi_divergence_local",
            "invalid_messages"
        ],
        help = "Check to run (integration tests)"
    )]
    pub check: Option<String>,
    #[clap(
        long,
        value_name = "DISCORD_WEBHOOK",
        help = "Discord webhook URL to send messages to",
        env = "DISCORD_WEBHOOK"
    )]
    pub discord_webhook: Option<String>,
    #[clap(
        long,
        value_name = "METRICS_HOST",
        help = "If set, the Radio will expose Prometheus metrics on the given host (off by default). This requires having a local Prometheus server running and scraping metrics on the given port.",
        env = "METRICS_HOST"
    )]
    pub metrics_host: Option<String>,
    #[clap(
        long,
        value_name = "METRICS_PORT",
        help = "If set, the Radio will expose Prometheus metrics on the given port (off by default). This requires having a local Prometheus server running and scraping metrics on the given port.",
        env = "METRICS_PORT"
    )]
    pub metrics_port: Option<u16>,
    #[clap(
        long,
        value_name = "SERVER_HOST",
        help = "If set, the Radio will expose API service on the given host (off by default).",
        env = "SERVER_HOST"
    )]
    pub server_host: Option<String>,
    #[clap(
        long,
        value_name = "SERVER_PORT",
        help = "If set, the Radio will expose API service on the given port (off by default).",
        env = "SERVER_PORT"
    )]
    pub server_port: Option<u16>,
}

impl Config {
    /// Parse config arguments
    pub fn args() -> Self {
        // TODO: load config file before parse (maybe add new level of subcommands)
        let config = Config::parse();
        std::env::set_var("RUST_LOG", config.log_level.clone());
        // Enables tracing under RUST_LOG variable
        init_tracing().expect("Could not set up global default subscriber for logger, check environmental variable `RUST_LOG` or the CLI input `log-level`");
        config
    }

    /// Validate that private key as an Eth wallet
    fn parse_key(value: &str) -> Result<String, WalletError> {
        // The wallet can be stored instead of the original private key
        let wallet = build_wallet(value)?;
        let addr = graphcast_id_address(&wallet);
        info!("Resolved Graphcast id: {}", addr);
        Ok(String::from(value))
    }

    /// Private key takes precedence over mnemonic
    pub fn wallet_input(&self) -> Result<&String, ConfigError> {
        match (&self.private_key, &self.mnemonic) {
            (Some(p), _) => Ok(p),
            (_, Some(m)) => Ok(m),
            _ => Err(ConfigError::ValidateInput(
                "Must provide either private key or mnemonic".to_string(),
            )),
        }
    }

    pub async fn to_graphcast_agent_config(
        &self,
        radio_name: &'static str,
    ) -> Result<GraphcastAgentConfig, GraphcastAgentError> {
        let wallet_key = self.wallet_input().unwrap().to_string();
        let topics = self.topics.clone();

        GraphcastAgentConfig::new(
            wallet_key,
            radio_name,
            self.registry_subgraph.clone(),
            self.network_subgraph.clone(),
            self.graph_node_endpoint.clone(),
            Some(self.boot_node_addresses.clone()),
            Some(self.graphcast_network.to_owned()),
            Some(topics),
            self.waku_node_key.clone(),
            self.waku_host.clone(),
            self.waku_port.clone(),
            self.waku_addr.clone(),
        )
        .await
    }

    pub async fn basic_info(&self) -> Result<(String, f32), QueryError> {
        // Using unwrap directly as the query has been ran in the set-up validation
        let wallet = build_wallet(self.wallet_input().unwrap()).unwrap();
        // The query here must be Ok but so it is okay to panic here
        // Alternatively, make validate_set_up return wallet, address, and stake
        let my_address = query_registry_indexer(
            self.registry_subgraph.to_string(),
            graphcast_id_address(&wallet),
        )
        .await
        .unwrap();
        let my_stake =
            query_network_subgraph(self.network_subgraph.to_string(), my_address.clone())
                .await
                .unwrap()
                .indexer_stake();
        info!(
            "Initializing radio to act on behalf of indexer {:#?} with stake {}",
            my_address.clone(),
            my_stake
        );
        Ok((my_address, my_stake))
    }

    pub async fn create_graphcast_agent(
        &self,
        radio_name: &'static str,
    ) -> Result<GraphcastAgent, GraphcastAgentError> {
        let config = self.to_graphcast_agent_config(radio_name).await.unwrap();
        GraphcastAgent::new(config).await
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("Validate the input: {0}")]
    ValidateInput(String),
    #[error("Generate JSON representation of the config file: {0}")]
    GenerateJson(serde_json::Error),
    #[error("QueryError: {0}")]
    QueryError(QueryError),
    #[error("Toml file error: {0}")]
    ReadStr(std::io::Error),
    #[error("Unknown error: {0}")]
    Other(anyhow::Error),
}
