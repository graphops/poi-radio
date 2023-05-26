use poi_radio::config::{Config, CoverageLevel};

pub fn test_config(
    graph_node_endpoint: String,
    registry_subgraph: String,
    network_subgraph: String,
) -> Config {
    Config {
        radio_name: "poi-radio-test".to_string(),
        graph_node_endpoint,
        private_key: Some(
            "caf5c93f0c8aee3b945f33b9192014e83d50cec25f727a13460f6ef1eb6a5844".to_string(),
        ),
        mnemonic: None,
        registry_subgraph,
        network_subgraph,
        graphcast_network: "testnet".to_string(),
        topics: vec![
            "QmpRkaVUwUQAwPwWgdQHYvw53A5gh3CP3giWnWQZdA2BTE".to_string(),
            "QmtYT8NhPd6msi1btMc3bXgrfhjkJoC4ChcM5tG6fyLjHE".to_string(),
        ],
        coverage: CoverageLevel::OnChain,
        collect_message_duration: 30,
        waku_host: None,
        waku_port: None,
        waku_node_key: None,
        waku_addr: None,
        boot_node_addresses: vec![],
        waku_log_level: None,
        log_level: "off,hyper=off,graphcast_sdk=trace,poi_radio=trace,poi-radio-e2e-tests=trace"
            .to_string(),
        slack_token: None,
        slack_channel: None,
        discord_webhook: None,
        metrics_host: None,
        metrics_port: None,
        server_host: None,
        server_port: None,
        persistence_file_path: Some("./test-runner/state.json".to_string()),
        log_format: "pretty".to_string(),
        telegram_chat_id: None,
        telegram_token: None,
    }
}
