use crate::setup::test_radio::run_test_radio;
use crate::utils::RadioTestConfig;

use poi_radio::{LocalAttestationsMap, MessagesArc, RemoteAttestationsMap};
use std::sync::atomic::{AtomicUsize, Ordering};
use tracing::{info, trace};

fn post_comparison_handler(_messages: MessagesArc, _block: u64, _subgraph: &str, _prev_len: usize) {
}

fn test_attestation_handler(
    _block: u64,
    _remote: &RemoteAttestationsMap,
    _local: &LocalAttestationsMap,
) {
}

fn success_handler(messages: MessagesArc) {
    static COUNTER: AtomicUsize = AtomicUsize::new(0);
    let messages = messages.lock().unwrap();

    if messages.len() > 0 {
        info!("1 valid message received!");
        assert!(
            messages
                .iter()
                .all(|m| m.payload.as_ref().unwrap().content != *"0xMyOwnPoi"),
            "Message found with POI sent from same instance",
        );

        info!("{}", "skip_messages_from_self test is successful ✅");
        std::process::exit(0);
    } else {
        let count = COUNTER.fetch_add(1, Ordering::SeqCst);
        if count >= 3 {
            trace!("Exiting as there were no messages received within 3 attempts");
            info!("{}", "skip_messages_from_self test is successful ✅");
            std::process::exit(0);
        }
    }
}

#[tokio::main]
pub async fn run_skip_messages_from_self() {
    let mut config = RadioTestConfig::new(false, true);
    config.poi = "0xMyOwnPoi".to_string();
    run_test_radio(
        &config,
        success_handler,
        test_attestation_handler,
        post_comparison_handler,
    )
    .await;
}
