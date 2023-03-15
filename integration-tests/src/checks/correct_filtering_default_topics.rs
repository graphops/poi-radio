use crate::setup::constants::{MOCK_SUBGRAPH_GOERLI, MOCK_SUBGRAPH_MAINNET};
use crate::utils::RadioRuntimeConfig;
use colored::Colorize;
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

    // Maybe pass in dynamic count here too
    if messages.len() >= 5 {
        debug!("messages {:?}", messages);

        info!("5 or more valid messages received! Checking content topics");
        let test_topics = &[MOCK_SUBGRAPH_MAINNET, MOCK_SUBGRAPH_GOERLI];
        let found_all = test_topics.iter().all(|test_topic| {
            messages
                .iter()
                .any(|message| message.identifier == *test_topic)
        });

        if !found_all {
            panic!(
                "Did not find both {} and {} in the messages",
                MOCK_SUBGRAPH_MAINNET, MOCK_SUBGRAPH_GOERLI
            );
        } else {
            info!(
                "{}",
                "correct_filtering_default_topics test is sucessful ✅".green()
            );
            std::process::exit(0);
        }
    }
}

#[tokio::main]
pub async fn run_correct_filtering_default_topics() {
    let config = RadioRuntimeConfig::new(false, true);
    run_test_radio(
        &config,
        success_handler,
        test_attestation_handler,
        post_comparison_handler,
    )
    .await;
}
