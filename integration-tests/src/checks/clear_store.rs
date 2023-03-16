use poi_radio::{LocalAttestationsMap, MessagesArc, RemoteAttestationsMap};
use tracing::{info, trace};

use crate::{setup::test_radio::run_test_radio, utils::RadioTestConfig};

fn post_comparison_handler(messages: MessagesArc, block: u64, subgraph: &str, prev_len: usize) {
    trace!("Starting post_comparison_handler");
    trace!("messages to assert on: {:?}", messages);

    if messages.lock().unwrap().len() > 0 {
        assert!(
            !messages
                .lock()
                .unwrap()
                .iter()
                .any(|msg| msg.block_number == block && msg.identifier == *subgraph),
            "There were messages found with block {block} and subgraph id {subgraph}"
        );

        assert!(messages.lock().unwrap().to_vec().len() < prev_len);

        info!("{}", "clear_store test is successful ✅");
        std::process::exit(0);
    }
}

fn test_attestation_handler(
    _block: u64,
    _remote: &RemoteAttestationsMap,
    _local: &LocalAttestationsMap,
) {
}

fn success_handler(_messages: MessagesArc) {}

#[tokio::main]
pub async fn run_clear_store() {
    let config = RadioTestConfig::new(false, false);
    run_test_radio(
        &config,
        success_handler,
        test_attestation_handler,
        post_comparison_handler,
    )
    .await;
}
