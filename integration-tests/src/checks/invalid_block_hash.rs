use std::env;

use crate::utils::RadioRuntimeConfig;
use colored::Colorize;
use poi_radio::{LocalAttestationsMap, MessagesArc, RemoteAttestationsMap};
use tracing::{debug, error};

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
    debug!("{:?}", messages);

    if messages.len() > 0 {
        error!("{}", "invalid_block_hash test failed".red());
        std::process::exit(1);
    }
}

#[tokio::main]
pub async fn run_invalid_block_hash() {
    env::set_var(
        "MOCK_BLOCK_HASH",
        "4rfba1ba9fb18b0034965712598be1368edcf91ae2c551d59462aab578dab9c5",
    );

    let mut config = RadioRuntimeConfig::new(false, true);
    // These values are for the Indexer we're RECEIVING from, now our own
    config.indexer_address = Some("0x002aee240e7a4b356620b0a6053c14a073499413".to_string());
    config.operator_address = Some("0x92239c8f2baba65dc4de65bd9fa16defc08699c7".to_string());
    run_test_radio(
        &config,
        success_handler,
        test_attestation_handler,
        post_comparison_handler,
    )
    .await;
}
