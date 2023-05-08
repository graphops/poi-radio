#[cfg(test)]
pub mod tests {
    use std::sync::Arc;

    use crate::integration_tests::setup::test_radio::tests::run_test_radio;
    use crate::integration_tests::utils::RadioTestConfig;
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
    pub async fn run_invalid_block_hash_instance() {
        let invalid_block_hash =
            "4rfba1ba9fb18b0034965712598be1368edcf91ae2c551d59462aab578dab9c5".to_string();

        let mut config = RadioTestConfig::new();
        config.invalid_hash = Some(invalid_block_hash);

        run_test_radio(
            Arc::new(config),
            success_handler,
            test_attestation_handler,
            post_comparison_handler,
        )
        .await;
    }
}
