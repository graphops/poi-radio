use crate::setup::test_radio::run_test_radio;
use crate::utils::RadioRuntimeConfig;
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
pub async fn run_divergent_instance() {
    let mut config = RadioRuntimeConfig::default_config();
    config.poi = "0x33331f98b82ca7f3966256bf508a7ede52e715b631dfa3d73b846bb7617f6b9e".to_string();
    config.indexer_stake = "600000000000000000000000".to_string();
    run_test_radio(
        &config,
        success_handler,
        test_attestation_handler,
        post_comparison_handler,
    )
    .await;
}
