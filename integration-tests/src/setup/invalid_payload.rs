use crate::setup::test_radio::run_test_radio;
use crate::utils::RadioTestConfig;
use poi_radio::{LocalAttestationsMap, MessagesArc, RemoteAttestationsMap};

fn post_comparison_handler(_messages: MessagesArc, _block: u64, _subgraph: &str, _prev_len: usize) {
}

fn success_handler(_messages: MessagesArc) {}

fn test_attestation_handler(
    _block: u64,
    _remote: &RemoteAttestationsMap,
    _local: &LocalAttestationsMap,
) {
}

#[tokio::main]
pub async fn run_invalid_payload_instance() {
    let mut config = RadioTestConfig::default_config();
    config.invalid_payload = true;
    run_test_radio(
        &config,
        success_handler,
        test_attestation_handler,
        post_comparison_handler,
    )
    .await;
}
