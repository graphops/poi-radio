use std::process::{Child, Command};
use std::sync::{Arc, Mutex};

use graphcast_sdk::init_tracing;
use poi_radio::config::CoverageLevel;
use poi_radio::state::PersistedState;
use test_runner::message_handling::send_and_receive_test;
use test_utils::config::test_config;
use test_utils::mock_server::start_mock_server;
use tokio::time::{sleep, Duration};
use tracing::{debug, info};

struct Cleanup {
    sender: Arc<Mutex<Child>>,
    radio: Arc<Mutex<Child>>,
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = self.sender.lock().unwrap().kill();
        let _ = self.radio.lock().unwrap().kill();
    }
}

#[tokio::main]
pub async fn main() {
    let id = uuid::Uuid::new_v4().to_string();
    std::env::set_var("TEST_RUN_ID", &id);

    let sender = Arc::new(Mutex::new(
        Command::new("cargo")
            .arg("run")
            .arg("-p")
            .arg("test-sender")
            .spawn()
            .expect("Failed to start command"),
    ));

    let host = "127.0.0.1:8085";
    tokio::spawn(start_mock_server(host));

    let config = test_config(
        format!("http://{}/graphql", host),
        format!("http://{}/registry-subgraph", host),
        format!("http://{}/network-subgraph", host),
    );

    std::env::set_var(
        "RUST_LOG",
        "off,hyper=off,graphcast_sdk=debug,poi_radio=debug,test_runner=debug,test_sender=debug,radio=debug",
    );
    init_tracing(config.log_format.clone()).expect("Could not set up global default subscriber for logger, check environmental variable `RUST_LOG` or the CLI input `log-level");

    info!("Starting");

    let radio = Arc::new(Mutex::new(
        Command::new("cargo")
            .arg("run")
            .arg("-p")
            .arg("poi-radio")
            .arg("--")
            .arg("--graph-node-endpoint")
            .arg(&config.graph_node_endpoint)
            .arg("--private-key")
            .arg(config.private_key.as_deref().unwrap_or("None"))
            .arg("--registry-subgraph")
            .arg(&config.registry_subgraph)
            .arg("--network-subgraph")
            .arg(&config.network_subgraph)
            .arg("--graphcast-network")
            .arg(&config.graphcast_network)
            .arg("--topics")
            .arg(config.topics.join(","))
            .arg("--coverage")
            .arg(match config.coverage {
                CoverageLevel::Minimal => "minimal",
                CoverageLevel::OnChain => "on-chain",
                CoverageLevel::Comprehensive => "comprehensive",
            })
            .arg("--collect-message-duration")
            .arg(config.collect_message_duration.to_string())
            .arg("--waku-log-level")
            .arg(config.waku_log_level.as_deref().unwrap_or("None"))
            .arg("--log-level")
            .arg(&config.log_level)
            .arg("--slack-token")
            .arg(config.slack_token.as_deref().unwrap_or("None"))
            .arg("--slack-channel")
            .arg(config.slack_channel.as_deref().unwrap_or("None"))
            .arg("--discord-webhook")
            .arg(config.discord_webhook.as_deref().unwrap_or("None"))
            .arg("--persistence-file-path")
            .arg(config.persistence_file_path.as_deref().unwrap_or("None"))
            .arg("--log-format")
            .arg(&config.log_format)
            .arg("--radio-name")
            .arg(&config.radio_name)
            .spawn()
            .expect("Failed to start command"),
    ));

    let cleanup = Cleanup {
        sender: Arc::clone(&sender),
        radio: Arc::clone(&radio),
    };

    // Wait for 3 minutes asynchronously
    sleep(Duration::from_secs(180)).await;

    // Kill the processes
    let _ = cleanup.sender.lock().unwrap().kill();
    let _ = cleanup.radio.lock().unwrap().kill();

    let state_file_path = "./test-runner/state.json";
    let persisted_state = PersistedState::load_cache(state_file_path);
    debug!("persisted state {:?}", persisted_state);

    let local_attestations = persisted_state.local_attestations();
    let remote_messages = persisted_state.remote_messages();
    let remote_messages = remote_messages.lock().unwrap();

    send_and_receive_test(&local_attestations.lock().unwrap(), &remote_messages);

    info!("All checks passed ✅");
}
