use crate::{
    setup::constants::{MOCK_SUBGRAPH_GOERLI, MOCK_SUBGRAPH_GOERLI_2, MOCK_SUBGRAPH_MAINNET},
    utils::{generate_deterministic_address, RadioTestConfig},
};

use graphcast_sdk::graphcast_agent::message_typing::GraphcastMessage;
use poi_radio::{
    attestation::{LocalAttestationsMap, RemoteAttestationsMap},
    MessagesVec, RadioPayloadMessage,
};
use std::{
    env,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use tracing::{error, info, trace};

use crate::setup::test_radio::run_test_radio;

static SUCCESS_HANDLER_CALLED: AtomicBool = AtomicBool::new(false);
static POST_COMPARISON_HANDLER_CALLED: AtomicBool = AtomicBool::new(false);
static TEST_ATTESTATION_HANDLER_CALLED: AtomicBool = AtomicBool::new(false);

fn post_comparison_handler(messages: MessagesVec, block: u64, subgraph: &str) {
    if POST_COMPARISON_HANDLER_CALLED.load(Ordering::SeqCst) {
        info!("Post comparison handler already called, returning early.");
        return;
    }

    if !SUCCESS_HANDLER_CALLED.load(Ordering::SeqCst) {
        info!("Success handler not called yet, returning early.");
        return;
    }

    let messages = messages.get().unwrap().lock().unwrap();

    let all_conditions_met = messages
        .iter()
        .all(|msg| msg.block_number >= block || msg.identifier != subgraph);

    info!("All conditions met: {:?}", all_conditions_met);

    if !all_conditions_met {
        error!("{}", "clear_store test failed");
        std::process::exit(1);
    } else {
        info!("{}", "clear_store test is successful ✅");
        POST_COMPARISON_HANDLER_CALLED.store(true, Ordering::SeqCst);
        std::process::exit(0);
    }
}

fn test_attestation_handler(
    block: u64,
    remote: &RemoteAttestationsMap,
    local: &LocalAttestationsMap,
) {
    if TEST_ATTESTATION_HANDLER_CALLED.load(Ordering::SeqCst) {
        return;
    }

    if let Some((ipfs_hash, blocks)) = local.iter().next() {
        if let Some(local_attestation) = blocks.get(&block) {
            if let Some(remote_blocks) = remote.get(ipfs_hash) {
                if let Some(remote_attestations) = remote_blocks.get(&block) {
                    let mut remote_attestations = remote_attestations.clone();
                    remote_attestations.sort_by(|a, b| a.stake_weight.cmp(&b.stake_weight));

                    if remote_attestations.len() > 1 {
                        info!("Sorted attestations: {:#?}", remote_attestations);
                    }

                    let most_attested_npoi = &remote_attestations.last().unwrap().npoi;
                    info!("Most attested npoi: {:#?}", most_attested_npoi);
                    info!("Local npoi: {:#?}", &local_attestation.npoi);

                    for attestation in remote_attestations.iter() {
                        let unique_senders = attestation
                            .senders
                            .iter()
                            .collect::<std::collections::HashSet<_>>();

                        if unique_senders.len() >= 2 && attestation.stake_weight >= 200000 {
                            info!("{}", "store_attestations test is successful ✅");
                            TEST_ATTESTATION_HANDLER_CALLED.store(true, Ordering::SeqCst);
                        }
                    }
                }
            }
        }
    }
}

static DURATION_COUNTER: AtomicUsize = AtomicUsize::new(0);
static RAN_FIRST: AtomicBool = AtomicBool::new(false);

fn success_handler(start_time: Instant, messages: MessagesVec, graphcast_id: &str) {
    if SUCCESS_HANDLER_CALLED.load(Ordering::SeqCst) {
        return;
    }

    let elapsed = start_time.elapsed();

    if elapsed >= Duration::from_secs(10) && !RAN_FIRST.load(Ordering::SeqCst) {
        let count = DURATION_COUNTER.fetch_add(1, Ordering::SeqCst);

        if count == 0 {
            info!("Comparison function not yet called.");
            RAN_FIRST.store(true, Ordering::SeqCst);
        } else {
            error!("Comparison function called before expected.");
            std::process::exit(1);
        }
    }

    if elapsed > Duration::from_secs(60) {
        let count = COUNTER.fetch_add(1, Ordering::SeqCst);
        trace!("Count: {}", count);
        if count == 2 {
            info!("Comparison function called 2 times.");
            info!("{}", "comparison_interval test is successful ✅");
        }
    }

    static COUNTER: AtomicUsize = AtomicUsize::new(0);
    let messages = messages.get().unwrap().lock().unwrap();

    if messages.len() > 0 {
        info!("1 valid message received!");

        let is_not_from_self = |m: &GraphcastMessage<RadioPayloadMessage>| {
            let sender_address_result = m.recover_sender_address();

            if let Ok(sender_address) = sender_address_result {
                sender_address != generate_deterministic_address(graphcast_id)
            } else {
                true
            }
        };

        if messages.iter().all(is_not_from_self) {
            info!("skip_messages_from_self test is successful ✅");
        } else {
            error!("skip_messages_from_self test failed, there was a message found with payload = '0xMyOwnPoi'");
            std::process::exit(1);
        }
    } else {
        let count = COUNTER.fetch_add(1, Ordering::SeqCst);
        if count >= 3 {
            trace!("Exiting as there were no messages received within 3 attempts");
            error!("{}", "skip_messages_from_self test failed");
        }
    }

    if messages.len() >= 5 {
        info!("5 valid messages received!");
        info!("{}", "simple receiver check is successful ✅");

        info!("Checking content topics");
        let test_topics = &[MOCK_SUBGRAPH_MAINNET, MOCK_SUBGRAPH_GOERLI];

        let found_all = test_topics.iter().all(|test_topic| {
            messages
                .iter()
                .any(|message| message.identifier == *test_topic)
        });

        let found_non_subscribed = messages.iter().any(|message| {
            message.identifier != MOCK_SUBGRAPH_MAINNET
                && message.identifier != MOCK_SUBGRAPH_GOERLI
        });

        if !found_all {
            error!(
                "Did not find both {} and {} in the messages",
                MOCK_SUBGRAPH_MAINNET, MOCK_SUBGRAPH_GOERLI
            );
            std::process::exit(1);
        }

        if found_non_subscribed {
            error!(
                "Found topic which Radio is not subscribed to {}",
                MOCK_SUBGRAPH_GOERLI_2
            );
            std::process::exit(1);
        }

        if found_non_subscribed {
            error!(
                "Did not find both {} and {} in the messages",
                MOCK_SUBGRAPH_MAINNET, MOCK_SUBGRAPH_GOERLI
            );
        } else {
            info!("correct_filtering_default_topics test is successful ✅");
        }

        info!(
            "{}",
            "correct_filtering_different_topics test is successful ✅"
        );

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
        let count = 3;

        if messages_prev_len >= (count as f32 * 0.7) as u32 {
            info!("{}", "num_messages test is successful ✅");
            SUCCESS_HANDLER_CALLED.store(true, Ordering::SeqCst);
        } else {
            error!("Expected message arr length to be at least 70% of mock senders count.");
            std::process::exit(1);
        }
    }
}

#[tokio::main]
pub async fn run_simple_tests() {
    // Collect duration to 1 minute
    env::set_var("COLLECT_MESSAGE_DURATION", "60");

    let start_time = Instant::now();

    let config = RadioTestConfig::new();
    run_test_radio(
        Arc::new(config),
        move |messages, graphcast_id: &str| success_handler(start_time, messages, graphcast_id),
        test_attestation_handler,
        post_comparison_handler,
    )
    .await;

    info!("Comparison function called less than 5 times.");
    std::process::exit(1);
}
