use clap::{ArgSettings, Parser};
use graphcast_sdk::graphcast_agent::message_typing::IdentityValidation;
use poi_radio::config::{Config, CoverageLevel};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Parser, Serialize, Deserialize)]
#[clap(name = "test-sender", about = "Mock message sender")]
pub struct TestSenderConfig {
    #[clap(long, value_name = "TOPICS", help = "Topics for test messages", setting = ArgSettings::UseValueDelimiter)]
    pub topics: Vec<String>,
    #[clap(long, value_name = "RADIO_NAME", help = "Instance-specific radio name")]
    pub radio_name: String,
    #[clap(long, value_name = "BLOCK_HASH")]
    pub block_hash: Option<String>,
    #[clap(long, value_name = "SENDER_TOKENS")]
    pub staked_tokens: Option<String>,
    #[clap(long, value_name = "NONCE")]
    pub nonce: Option<String>,
    #[clap(long, value_name = "RADIO_PAYLOAD")]
    pub radio_payload: Option<String>,
    #[clap(long, value_name = "POI")]
    pub poi: Option<String>,
}

pub fn test_config() -> Config {
    Config {
        indexer_address: String::from("0x7e6528e4ce3055e829a32b5dc4450072bac28bc6"),
        graph_node_endpoint: String::new(),
        private_key: Some(
            "ccaea3e3aca412cb3920dbecd77bc725dfe9a5e16f940f19912d9c9dbee01e8f".to_string(),
        ),
        mnemonic: None,
        registry_subgraph: String::new(),
        network_subgraph: String::new(),
        graphcast_network: "testnet".to_string(),
        topics: vec![],
        coverage: CoverageLevel::OnChain,
        collect_message_duration: 60,
        waku_host: None,
        waku_port: None,
        waku_node_key: None,
        waku_addr: None,
        boot_node_addresses: vec![],
        waku_log_level: None,
        log_level: "off,hyper=off,graphcast_sdk=trace,poi_radio=trace,test_runner=trace"
            .to_string(),
        slack_token: None,
        slack_channel: None,
        discord_webhook: None,
        metrics_host: String::new(),
        metrics_port: None,
        server_host: String::new(),
        server_port: None,
        persistence_file_path: None,
        log_format: "pretty".to_string(),
        radio_name: String::new(),
        telegram_chat_id: None,
        telegram_token: None,
        discv5_enrs: None,
        discv5_port: None,
        filter_protocol: None,
        id_validation: IdentityValidation::ValidAddress,
        topic_update_interval: 600,
    }
}
