use std::time::Instant;

use graphcast_sdk::init_tracing;
use test_runner::{message_handling::send_and_receive_test, topics::topics_test};
use test_utils::config::test_config;
use tracing::info;

#[tokio::main]
pub async fn main() {
    let config = test_config();

    std::env::set_var(
        "RUST_LOG",
        "off,hyper=off,graphcast_sdk=debug,poi_radio=debug,test_runner=debug,test_sender=debug,test_utils=debug",
    );
    init_tracing(config.log_format).expect("Could not set up global default subscriber for logger, check environmental variable `RUST_LOG` or the CLI input `log-level");

    let start_time = Instant::now();

    let send_and_receive_task = tokio::spawn(send_and_receive_test());
    let topics_test_task = tokio::spawn(topics_test());

    let (_send_and_receive_result, _topics_test_result) =
        tokio::join!(send_and_receive_task, topics_test_task);

    let elapsed_time = start_time.elapsed();

    info!(
        "All checks passed ✅. Time elapsed: {}s",
        elapsed_time.as_secs()
    );
}
