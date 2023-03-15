use crate::utils::RadioRuntimeConfig;
use colored::Colorize;
use poi_radio::{LocalAttestationsMap, MessagesArc, RemoteAttestationsMap};
use std::env;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tracing::{info, trace};

use crate::setup::test_radio::run_test_radio;

fn post_comparison_handler(_messages: MessagesArc, _block: u64, _subgraph: &str, _prev_len: usize) {
}

fn test_attestation_handler(
    _block: u64,
    _remote: &RemoteAttestationsMap,
    _local: &LocalAttestationsMap,
) {
}

static COUNTER: AtomicUsize = AtomicUsize::new(0);

fn success_handler(start_time: Instant, _messages: MessagesArc) {
    let elapsed = start_time.elapsed();
    let one_minute = Duration::from_secs(60);

    if elapsed >= one_minute {
        let count = COUNTER.fetch_add(1, Ordering::SeqCst);
        trace!("Count: {}", count);
        if count == 5 {
            info!("Comparison function called 5 times.");

            info!("{}", "comparison_interval test is successful ✅".green());
            std::process::exit(0);
        }
    }
}

#[tokio::main]
pub async fn run_comparison_interval() {
    // Collect duration to 1 second
    env::set_var("COLLECT_MESSAGE_DURATION", "1");

    let config = RadioRuntimeConfig::new(false, false);
    let start_time = Instant::now();

    run_test_radio(
        &config,
        move |messages| success_handler(start_time, messages),
        test_attestation_handler,
        post_comparison_handler,
    )
    .await;

    info!("Comparison function called less than 5 times.");
    std::process::exit(1);
}
