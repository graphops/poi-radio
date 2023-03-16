use crate::setup::test_radio::run_test_radio;
use crate::utils::RadioTestConfig;

use partial_application::partial;
use poi_radio::{LocalAttestationsMap, MessagesArc, RemoteAttestationsMap};
use tracing::info;

fn post_comparison_handler(_messages: MessagesArc, _block: u64, _subgraph: &str, _prev_len: usize) {
}

fn test_attestation_handler(
    _block: u64,
    _remote: &RemoteAttestationsMap,
    _local: &LocalAttestationsMap,
) {
}

fn handler(count: u32, messages: MessagesArc) {
    let messages = messages.lock().unwrap();

    if (messages.len() as u32) < count {
        return;
    }

    let messages = messages.iter().cloned().collect::<Vec<_>>();
    let block = messages
        .last()
        .expect("Message vec to not be empty")
        .block_number;
    let messages = messages
        .into_iter()
        .filter(|msg| msg.block_number == block)
        .collect::<Vec<_>>();

    let messages_prev_len = messages.len() as u32;
    assert!(
        messages_prev_len >= (count as f32 * 0.7) as u32,
        "Expected message arr length to be at least 70% of mock senders count."
    );

    info!("{}", "num_messages test is successful ✅");
    std::process::exit(0);
}

#[tokio::main]
pub async fn run_num_messages(count: u32) {
    let config = RadioTestConfig::new(false, true);
    run_test_radio(
        &config,
        partial!(handler => count, _),
        test_attestation_handler,
        post_comparison_handler,
    )
    .await;
}
