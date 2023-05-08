#[cfg(test)]
pub mod tests {
    use std::sync::Arc;

    use crate::integration_tests::utils::RadioTestConfig;
    use crate::integration_tests::{setup::test_radio::tests::run_test_radio, utils::DummyMsg};
    use crate::{
        attestation::{LocalAttestationsMap, RemoteAttestationsMap},
        MessagesVec,
    };

    fn post_comparison_handler(_messages: MessagesVec, _block: u64, _subgraph: &str) {}

    fn success_handler(_messages: MessagesVec, _graphcast_id: &str) {}

    fn test_attestation_handler(
        _block: u64,
        _remote: &RemoteAttestationsMap,
        _local: &LocalAttestationsMap,
    ) {
    }

    #[tokio::test]
    pub async fn run_invalid_payload_instance() {
        let mut config = RadioTestConfig::default_config();
        let dummy_message = DummyMsg::new("hello".to_string(), 42);
        config.invalid_payload = Some(dummy_message);

        let config = Arc::new(config);

        run_test_radio(
            Arc::clone(&config),
            success_handler,
            test_attestation_handler,
            post_comparison_handler,
        )
        .await;
    }
}
