use std::collections::HashMap;
use std::time::Instant;

use graphcast_sdk::init_tracing;
use test_runner::{
    invalid_block_hash::invalid_block_hash_test, invalid_nonce::invalid_nonce_test,
    invalid_payload::invalid_payload_test, invalid_sender::invalid_sender_test,
    message_handling::send_and_receive_test, poi_divergent::poi_divergent_test,
    poi_match::poi_match_test, topics::topics_test,
};
use test_utils::config::test_config;
use tracing::{error, info};

async fn run_tests(
    tests: Vec<(&str, tokio::task::JoinHandle<()>)>,
) -> (bool, HashMap<String, bool>) {
    let mut tests_passed = true;
    let mut test_results: HashMap<String, bool> = HashMap::new();

    for (test_name, test_task) in tests {
        match test_task.await {
            Ok(()) => {
                info!("{} passed ✅", test_name);
                test_results.insert(test_name.to_string(), true);
            }
            Err(_e) => {
                error!("{} failed ❌", test_name);
                tests_passed = false;
                test_results.insert(test_name.to_string(), false);
            }
        }
    }

    (tests_passed, test_results)
}
#[tokio::main]
pub async fn main() {
    let config = test_config();

    std::env::set_var(
        "RUST_LOG",
        "off,hyper=off,graphcast_sdk=trace,poi_radio=trace,test_runner=trace,test_sender=trace,test_utils=trace",
    );
    init_tracing(config.log_format).expect("Could not set up global default subscriber for logger, check environmental variable `RUST_LOG` or the CLI input `log-level");

    let start_time = Instant::now();

    let mut retry_count = 3;
    let mut initial_test_results: HashMap<String, bool> = HashMap::new();
    let mut initial_tests_passed = false;

    while retry_count > 0 && !initial_tests_passed {
        let initial_tests = vec![
            (
                "send_and_receive_test",
                tokio::spawn(send_and_receive_test()),
            ),
            ("topics_test", tokio::spawn(topics_test())),
        ];

        let (tests_passed, test_results) = run_tests(initial_tests).await;
        initial_test_results = test_results;

        if tests_passed {
            initial_tests_passed = true;
        } else {
            retry_count -= 1;
        }
    }

    if initial_tests_passed {
        let poi_tests = vec![
            ("poi_divergent_test", tokio::spawn(poi_divergent_test())),
            ("poi_match_test", tokio::spawn(poi_match_test())),
        ];

        let (poi_tests_passed, poi_test_results) = run_tests(poi_tests).await;
        if poi_tests_passed {
            let remaining_tests = vec![
                (
                    "invalid_block_hash_test",
                    tokio::spawn(invalid_block_hash_test()),
                ),
                ("invalid_sender_test", tokio::spawn(invalid_sender_test())),
                ("invalid_nonce_test", tokio::spawn(invalid_nonce_test())),
                ("invalid_payload_test", tokio::spawn(invalid_payload_test())),
            ];

            let (remaining_tests_passed, remaining_test_results) = run_tests(remaining_tests).await;

            print_test_summary(
                initial_test_results,
                poi_test_results,
                remaining_test_results,
                remaining_tests_passed,
                start_time,
            );
        } else {
            print_test_summary(
                initial_test_results,
                poi_test_results,
                HashMap::new(),
                false,
                start_time,
            );
        }
    } else {
        print_test_summary(
            initial_test_results,
            HashMap::new(),
            HashMap::new(),
            false,
            start_time,
        );
    }
}

fn print_test_summary(
    initial_test_results: HashMap<String, bool>,
    poi_test_results: HashMap<String, bool>,
    remaining_test_results: HashMap<String, bool>,
    remaining_tests_passed: bool,
    start_time: Instant,
) {
    let elapsed_time = start_time.elapsed();
    // Print summary of tests
    println!("\nTest Summary:\n");
    for (test_name, passed) in initial_test_results
        .iter()
        .chain(&poi_test_results)
        .chain(&remaining_test_results)
    {
        if *passed {
            info!("{}: PASSED", test_name);
        } else {
            error!("{}: FAILED", test_name);
        }
    }

    if remaining_tests_passed {
        info!(
            "All tests passed ✅. Time elapsed: {}s",
            elapsed_time.as_secs()
        );
    } else {
        error!(
            "Some tests failed ❌. Time elapsed: {}s",
            elapsed_time.as_secs()
        );
    }
}
