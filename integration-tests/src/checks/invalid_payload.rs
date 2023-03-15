use crate::utils::RadioRuntimeConfig;
use colored::Colorize;
use poi_radio::{LocalAttestationsMap, MessagesArc, RemoteAttestationsMap};
use tracing::{debug, info};

use crate::setup::test_radio::run_test_radio;

use std::any::type_name;

fn type_of<T>(_: T) -> &'static str {
    type_name::<T>()
}

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

    // Maybe pass in dynamic count here too
    if messages.len() >= 5 {
        debug!("messages {:?}", messages);

        info!("5 or more valid messages received! Checking payloads");
        assert!(
            messages
                .iter()
                .all(|m| !type_of(&m.payload).contains("DummyMsg")),
            "Message found with invalid payload",
        );
        info!("{}", "invalid_payload test is sucessful ✅".green());
        std::process::exit(0);
    }
}

#[tokio::main]
pub async fn run_invalid_payload() {
    let config = RadioRuntimeConfig::new(false, true);
    run_test_radio(
        &config,
        success_handler,
        test_attestation_handler,
        post_comparison_handler,
    )
    .await;
}
