use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;

use crate::utils::RadioTestConfig;

use poi_radio::{
    attestation::{LocalAttestationsMap, RemoteAttestationsMap},
    MessagesVec, MESSAGES,
};
use tracing::{error, info};

use crate::setup::test_radio::run_test_radio;

fn post_comparison_handler(_messages: MessagesVec, _block: u64, _subgraph: &str) {}

fn test_attestation_handler(
    _block: u64,
    _remote: &RemoteAttestationsMap,
    _local: &LocalAttestationsMap,
) {
}

fn success_handler(_messages: MessagesVec, _graphcast_id: &str) {}

#[tokio::main]
pub async fn run_invalid_sender_check() {
    let mut config = RadioTestConfig::new();
    config.indexer_stake = 1.00;

    let run_test_radio_future = run_test_radio(
        Arc::new(config),
        success_handler,
        test_attestation_handler,
        post_comparison_handler,
    );

    // Spawn the sleep_future and get a handle for it
    let delay = tokio::spawn(async move {
        sleep(Duration::from_secs(60)).await;
        let messages = MESSAGES.get().unwrap().lock().unwrap();
        if messages.is_empty() {
            info!("invalid_sender test is successful ✅");
            std::process::exit(0);
        } else {
            error!("invalid_sender test failed");
            std::process::exit(1);
        }
    });

    // Run run_test_radio_future
    run_test_radio_future.await;

    let _ = delay.await;
}
