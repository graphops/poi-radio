pub static MOCK_SUBGRAPH_MAINNET: &str = "QmggQnSgia4iDPWHpeY6aWxesRFdb8o5DKZUx96zZqEWrB";
pub static MOCK_SUBGRAPH_GOERLI: &str = "Qm11QnSgia4iDPWHpeY6aWxesRFdb8o5DKZUx96zZqEWrB";
pub static MOCK_SUBGRAPH_GOERLI_2: &str = "Qm22QnSgia4iDPWHpeY6aWxesRFdb8o5DKZUx96zZqEWrB";

#[cfg(test)]
pub mod tests {
    use crate::config::{Config, CoverageLevel};

    pub fn test_config() -> Config {
        Config {
            graph_node_endpoint: "http://localhost:8035/graphql".to_string(),
            private_key: Some(
                "caf5c93f0c8aee3b945f33b9192014e83d50cec25f727a13460f6ef1eb6a5844".to_string(),
            ),
            mnemonic: None,
            registry_subgraph:
                "https://api.thegraph.com/subgraphs/name/hopeyen/graphcast-registry-goerli"
                    .to_string(),
            network_subgraph: "https://gateway.testnet.thegraph.com/network".to_string(),
            graphcast_network: "testnet".to_string(),
            topics: vec![],
            coverage: CoverageLevel::OnChain,
            collect_message_duration: 120,
            waku_host: None,
            waku_port: None,
            waku_node_key: None,
            waku_addr: None,
            boot_node_addresses: vec!["/ip4/164.90.179.254/tcp/31900".to_string()],
            waku_log_level: None,
            log_level: "off,hyper=off,graphcast_sdk=debug,poi_radio=debug,integration_tests=debug"
                .to_string(),
            slack_token: None,
            slack_channel: None,
            instance: None,
            check: None,
            discord_webhook: None,
            metrics_host: None,
            metrics_port: None,
            server_host: None,
            server_port: None,
        }
    }
}
