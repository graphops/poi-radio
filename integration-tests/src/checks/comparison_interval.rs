use crate::utils::RadioTestConfig;

use poi_radio::{LocalAttestationsMap, MessagesArc, RemoteAttestationsMap};
use std::env;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tracing::{error, info, trace};

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
static RAN_FIRST: AtomicBool = AtomicBool::new(false);

fn success_handler(start_time: Instant, _messages: MessagesArc) {
    let elapsed = start_time.elapsed();

    if elapsed >= Duration::from_secs(30) && !RAN_FIRST.load(Ordering::SeqCst) {
        let count = COUNTER.fetch_add(1, Ordering::SeqCst);
        info!("Count: {}", count);
        info!("Count is zero : {}", count == 0);

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
            std::process::exit(0);
        }
    }
}

#[tokio::main]
pub async fn run_comparison_interval() {
    // Collect duration to 1 second
    env::set_var("COLLECT_MESSAGE_DURATION", "30");

    let config = RadioTestConfig::new(false, false);
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
