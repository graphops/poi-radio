use crate::utils::RadioRuntimeConfig;
use colored::Colorize;
use poi_radio::{LocalAttestationsMap, MessagesArc, RemoteAttestationsMap};
use tracing::{error, info};

use crate::setup::test_radio::run_test_radio;

fn post_comparison_handler(_messages: MessagesArc, _block: u64, _subgraph: &str, _prev_len: usize) {
}

fn test_attestation_handler(
    _block: u64,
    _remote: &RemoteAttestationsMap,
    _local: &LocalAttestationsMap,
) {
}

fn success_handler(messages: MessagesArc) {
    let messages = messages.lock().unwrap();
    info!("MESSAGES: {:?}", messages);

    if messages.len() > 0 {
        error!("{}", "invalid_sender test failed".red());
        std::process::exit(1);
    }
}

#[tokio::main]
pub async fn run_invalid_sender() {
    let mut config = RadioRuntimeConfig::new(false, true);
    config.indexer_address = Some("0x002aee240e7a4b356620b0a6053c14a073499413".to_string());
    config.operator_address = Some("0x92239c8f2baba65dc4de65bd9fa16defc08699c7".to_string());
    config.indexer_stake = "1".to_string();
    run_test_radio(
        &config,
        success_handler,
        test_attestation_handler,
        post_comparison_handler,
    )
    .await;
}
