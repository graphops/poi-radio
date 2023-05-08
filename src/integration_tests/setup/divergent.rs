#[cfg(test)]
pub mod tests {
    use crate::integration_tests::setup::test_radio::tests::run_test_radio;
    use crate::integration_tests::utils::RadioTestConfig;
    use crate::{
        attestation::{LocalAttestationsMap, RemoteAttestationsMap},
        MessagesVec,
    };
    use std::sync::Arc;

    fn post_comparison_handler(_messages: MessagesVec, _block: u64, _subgraph: &str) {}

    fn success_handler(_messages: MessagesVec, _graphcast_id: &str) {}

    fn test_attestation_handler(
        _block: u64,
        _remote: &RemoteAttestationsMap,
        _local: &LocalAttestationsMap,
    ) {
    }

    #[tokio::test]
    pub async fn run_divergent_instance() {
        let mut config = RadioTestConfig::default_config();
        config.poi =
            "0x33331f98b82ca7f3966256bf508a7ede52e715b631dfa3d73b846bb7617f6b9e".to_string();
        config.indexer_stake = 600000.0;
        run_test_radio(
            Arc::new(config),
            success_handler,
            test_attestation_handler,
            post_comparison_handler,
        )
        .await;
    }
}
