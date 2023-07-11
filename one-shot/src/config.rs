use clap::Parser;
use derive_getters::Getters;
use ethers::signers::WalletError;
use serde::{Deserialize, Serialize};
use tracing::info;

use graphcast_sdk::{
    build_wallet,
    callbook::CallBook,
    graphcast_agent::{
        message_typing::IdentityValidation, GraphcastAgentConfig, GraphcastAgentError,
    },
    graphql::{
        client_network::query_network_subgraph, client_registry::query_registry, QueryError,
    },
    init_tracing, wallet_address,
};

#[derive(Clone, Debug, Parser, Serialize, Deserialize, Getters, Default)]
#[clap(
    name = "one-shot-messenger",
    about = "Send a message to Graphcast network",
    author = "GraphOps"
)]
pub struct Config {
    #[clap(
        long,
        value_name = "KEY",
        value_parser = Config::parse_key,
        env = "PRIVATE_KEY",
        hide_env_values = true,
        help = "Private key to the Graphcast ID wallet (Precendence over mnemonics)",
    )]
    // should keep this value private, this is current public due to the constructing a Config in test-utils
    // We can get around this by making an explicit function to make config instead of direct build in {}
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
        value_name = "GRAPH_ACCOUNT",
        env = "GRAPH_ACCOUNT",
        help = "Graph account corresponding to Graphcast operator"
    )]
    pub graph_account: String,
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
        default_value = "https://api.thegraph.com/subgraphs/name/graphprotocol/graph-network-goerli"
    )]
    pub network_subgraph: String,
    #[clap(
        long,
        default_value = "testnet",
        value_name = "NAME",
        env = "GRAPHCAST_NETWORK",
        help = "Supported Graphcast networks: mainnet, testnet",
        possible_values = ["testnet", "mainnet"],
    )]
    pub graphcast_network: String,
    #[clap(
        long,
        value_name = "[TOPIC]",
        value_delimiter = ',',
        env = "TOPICS",
        help = "Comma separated static list of content topics to subscribe to (Static list to include) (right now just send message to the first element of the vec?"
    )]
    pub topics: Vec<String>,
    #[clap(
        long,
        value_name = "IDENTIFIER",
        env = "IDENTIFIER",
        help = "Subgraph hash is used to be the message content identifier"
    )]
    pub identifier: String,
    #[clap(
        long,
        value_name = "NEW_HASH",
        env = "NEW_HASH",
        help = "Subgraph hash for the upgrade version of the subgraph"
    )]
    pub new_hash: String,
    #[clap(
        long,
        value_name = "SUBGRAPH_ID",
        env = "SUBGRAPH_ID",
        help = "Subgraph id shared by the old and new deployment"
    )]
    pub subgraph_id: String,
    #[clap(
        long,
        value_name = "INDEX_NETWORK",
        env = "INDEX_NETWORK",
        help = "Subgraph id shared by the old and new deployment"
    )]
    pub index_network: String,
    #[clap(
        long,
        value_name = "MIGRATION_TIME",
        env = "MIGRATION_TIME",
        help = "UNIX timestamp that the developer plan on migrating the usage"
    )]
    pub migration_time: i64,
    #[clap(
        long,
        value_name = "WAKU_HOST",
        help = "Host for the Waku gossip client",
        env = "WAKU_HOST"
    )]
    pub waku_host: Option<String>,
    #[clap(
        long,
        value_name = "WAKU_PORT",
        help = "Port for the Waku gossip client",
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
        value_name = "DISCV5_ENRS",
        help = "Comma separated ENRs for Waku discv5 bootstrapping",
        env = "DISCV5_ENRS"
    )]
    pub discv5_enrs: Option<Vec<String>>,
    #[clap(
        long,
        value_name = "DISCV5_PORT",
        help = "Waku node to expose discoverable udp port",
        env = "DISCV5_PORT"
    )]
    pub discv5_port: Option<u16>,
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
        value_name = "DISCORD_WEBHOOK",
        help = "Discord webhook URL to send messages to",
        env = "DISCORD_WEBHOOK"
    )]
    pub discord_webhook: Option<String>,
    #[clap(
        long,
        value_name = "TELEGRAM_TOKEN",
        help = "Telegram Bot API Token",
        env = "TELEGRAM_TOKEN"
    )]
    pub telegram_token: Option<String>,
    #[clap(
        long,
        value_name = "TELEGRAM_CHAT_ID",
        help = "Id of Telegram chat (DM or group) to send messages to",
        env = "TELEGRAM_CHAT_ID"
    )]
    pub telegram_chat_id: Option<i64>,
    #[clap(
        long,
        value_name = "METRICS_HOST",
        default_value = "0.0.0.0",
        help = "If port is set, the Radio will expose Prometheus metrics on the given host. This requires having a local Prometheus server running and scraping metrics on the given port.",
        env = "METRICS_HOST"
    )]
    pub metrics_host: String,
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
        default_value = "0.0.0.0",
        help = "If port is set, the Radio will expose API service on the given host.",
        env = "SERVER_HOST"
    )]
    pub server_host: String,
    #[clap(
        long,
        value_name = "SERVER_PORT",
        help = "If set, the Radio will expose API service on the given port (off by default).",
        env = "SERVER_PORT"
    )]
    pub server_port: Option<u16>,
    #[clap(
        long,
        value_name = "PERSISTENCE_FILE_PATH",
        help = "If set, the Radio will periodically store states of the program to the file in json format",
        env = "PERSISTENCE_FILE_PATH"
    )]
    pub persistence_file_path: Option<String>,
    #[clap(
        long,
        value_name = "LOG_FORMAT",
        env = "LOG_FORMAT",
        help = "Support logging formats: pretty, json, full, compact",
        long_help = "pretty: verbose and human readable; json: not verbose and parsable; compact:  not verbose and not parsable; full: verbose and not parsible",
        possible_values = ["pretty", "json", "full", "compact"],
        default_value = "pretty"
    )]
    pub log_format: String,
    #[clap(
        long,
        value_name = "RADIO_NAME",
        env = "RADIO_NAME",
        default_value = "poi-radio"
    )]
    pub radio_name: String,
    #[clap(long, value_name = "FILTER_PROTOCOL", env = "ENABLE_FILTER_PROTOCOL")]
    pub filter_protocol: Option<bool>,
    #[clap(
        long,
        value_name = "ID_VALIDATION",
        value_enum,
        env = "ID_VALIDATION",
        help = "Identity validaiton mechanism for message signers",
        long_help = "Identity validaiton mechanism for message signers\n
        no-check: all messages signer is valid, \n
        valid-address: signer needs to be an valid Eth address, \n
        graphcast-registered: must be registered at Graphcast Registry, \n
        graph-network-account: must be a Graph account, \n
        registered-indexer: must be registered at Graphcast Registry, correspond to and Indexer statisfying indexer minimum stake requirement, \n
        indexer: must be registered at Graphcast Registry or is a Graph Account, correspond to and Indexer statisfying indexer minimum stake requirement"
    )]
    pub id_validation: IdentityValidation,
    #[clap(
        long,
        value_name = "TOPIC_UPDATE_INTERVAL",
        env = "TOPIC_UPDATE_INTERVAL",
        default_value = "600"
    )]
    pub topic_update_interval: u64,
}

impl Config {
    /// Parse config arguments
    pub fn args() -> Self {
        // TODO: load config file before parse (maybe add new level of subcommands)
        let config = Config::parse();
        std::env::set_var("RUST_LOG", config.log_level.clone());
        // Enables tracing under RUST_LOG variable
        init_tracing(config.log_format.clone()).expect("Could not set up global default subscriber for logger, check environmental variable `RUST_LOG` or the CLI input `log-level`");
        config
    }

    /// Validate that private key as an Eth wallet
    fn parse_key(value: &str) -> Result<String, WalletError> {
        // The wallet can be stored instead of the original private key
        let wallet = build_wallet(value)?;
        let address = wallet_address(&wallet);
        info!(address, "Resolved Graphcast id");
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
    ) -> Result<GraphcastAgentConfig, GraphcastAgentError> {
        let wallet_key = self.wallet_input().unwrap().to_string();
        let topics = self.topics.clone();

        info!(
            wallet_key = tracing::field::debug(&wallet_key),
            graph_account = tracing::field::debug(&self.graph_account.clone()),
            radio_name = tracing::field::debug(&self.radio_name.clone()),
            registry_subgraph = tracing::field::debug(&self.registry_subgraph.clone()),
            network_subgraph = tracing::field::debug(&self.network_subgraph.clone()),
            id_validation = tracing::field::debug(&self.id_validation.clone()),
            boot_node_addresses = tracing::field::debug(&Some(self.boot_node_addresses.clone())),
            graphcast_network = tracing::field::debug(&Some(self.graphcast_network.to_owned())),
            topics = tracing::field::debug(&Some(topics.clone())),
            waku_node_key = tracing::field::debug(&self.waku_node_key.clone()),
            waku_host = tracing::field::debug(&self.waku_host.clone()),
            waku_port = tracing::field::debug(&self.waku_port.clone()),
            waku_addr = tracing::field::debug(&self.waku_addr.clone()),
            filter_protocol = tracing::field::debug(&self.filter_protocol),
            discv5_enrs = tracing::field::debug(&self.discv5_enrs.clone()),
            discv5_port = tracing::field::debug(&self.discv5_port),
            "Config stuff",
        );

        GraphcastAgentConfig::new(
            wallet_key,
            self.graph_account.clone(),
            self.radio_name.clone(),
            self.registry_subgraph.clone(),
            self.network_subgraph.clone(),
            self.id_validation.clone(),
            None,
            Some(self.boot_node_addresses.clone()),
            Some(self.graphcast_network.to_owned()),
            Some(topics),
            self.waku_node_key.clone(),
            self.waku_host.clone(),
            self.waku_port.clone(),
            self.waku_addr.clone(),
            self.filter_protocol,
            self.discv5_enrs.clone(),
            self.discv5_port,
        )
        .await
    }

    pub async fn basic_info(&self) -> Result<(String, f32), QueryError> {
        // Using unwrap directly as the query has been ran in the set-up validation
        let wallet = build_wallet(
            self.wallet_input()
                .map_err(|e| QueryError::Other(e.into()))?,
        )
        .map_err(|e| QueryError::Other(e.into()))?;
        // The query here must be Ok but so it is okay to panic here
        // Alternatively, make validate_set_up return wallet, address, and stake
        let my_address = query_registry(self.registry_subgraph(), &wallet_address(&wallet)).await?;
        let my_stake = query_network_subgraph(self.network_subgraph(), &my_address)
            .await
            .unwrap()
            .indexer_stake();
        info!(
            my_address,
            my_stake, "Initializing radio operator for indexer identity",
        );
        Ok((my_address, my_stake))
    }

    pub fn callbook(&self) -> CallBook {
        CallBook::new(
            self.registry_subgraph.clone(),
            self.network_subgraph.clone(),
            None,
        )
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
