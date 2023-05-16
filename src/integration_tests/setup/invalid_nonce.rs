#[cfg(test)]
pub mod tests {
    use std::sync::Arc;

    use crate::integration_tests::utils::RadioTestConfig;
    use crate::run_test_radio;
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
    pub async fn run_invalid_nonce_instance() {
        let mut config: RadioTestConfig = RadioTestConfig::default_config();
        config.invalid_time = Some(1650153600);

        run_test_radio(
            Arc::new(config),
            success_handler,
            test_attestation_handler,
            post_comparison_handler,
        )
        .await;
    }
}
