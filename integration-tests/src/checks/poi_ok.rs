use crate::utils::RadioTestConfig;

use poi_radio::{LocalAttestationsMap, MessagesArc, RemoteAttestationsMap};
use tracing::{debug, info};

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
    debug!("MESSAGES: {:?}", messages);

    if messages.len() >= 5 {
        info!("5 valid messages received!");
        info!("{}", "poi_ok test is successful ✅");
        // std::process::exit(0);
    }
}

#[tokio::main]
pub async fn run_poi_ok() {
    let config = RadioTestConfig::new(false, true);
    run_test_radio(
        &config,
        success_handler,
        test_attestation_handler,
        post_comparison_handler,
    )
    .await;
}
