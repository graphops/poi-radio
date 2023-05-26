use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use graphcast_sdk::init_tracing;
use poi_radio::config::CoverageLevel;

use tracing::info;
use utils::config::test_config;
use utils::mock_server::start_mock_server;

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
    std::env::set_var(
        "RUST_LOG",
        "off,hyper=off,graphcast_sdk=debug,poi_radio=debug,poi-radio-e2e-tests=debug,test_runner=debug,sender=debug,radio=debug",
    );
    init_tracing("pretty".to_string()).expect("Could not set up global default subscriber for logger, check environmental variable `RUST_LOG` or the CLI input `log-level");

    info!("Starting");

    let host = "127.0.0.1:8087";
    info!("before starting mock server");

    // Using std::thread::spawn instead of tokio::spawn
    let server_handle = thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(start_mock_server(host))
    });

    // Your logic to start sender and radio
    let sender = Arc::new(Mutex::new(
        Command::new("cargo")
            .arg("run")
            .arg("--bin")
            .arg("sender")
            .stdout(Stdio::piped())
            .spawn()
            .expect("Failed to start command"),
    ));

    let radio = Arc::new(Mutex::new(
        Command::new("echo").arg("Radio started").spawn().unwrap(),
    ));

    let _cleanup = Cleanup { sender, radio };

    info!("server created and time awaited?");

    // Now use tokio's async sleep function.
    tokio::time::sleep(Duration::from_secs(5)).await;

    info!("server created and time awaited?");

    let config = test_config(
        format!("http://{}/graphql", host),
        format!("http://{}/registry-subgraph", host),
        format!("http://{}/network-subgraph", host),
    );

    // Run the 'cargo run --bin radio' command
    Command::new("cargo")
        .args(["run", "-p", "poi-radio", "--"])
        .args(["--graph-node-endpoint", &config.graph_node_endpoint])
        .args(["--radio-name", &config.radio_name])
        .args(["--private-key", &config.private_key.unwrap()])
        .args(["--registry-subgraph", &config.registry_subgraph])
        .args(["--network-subgraph", &config.network_subgraph])
        .args(["--graphcast-network", &config.graphcast_network])
        .args(["--topics", &config.topics.join(",")])
        .args([
            "--coverage",
            match config.coverage {
                CoverageLevel::OnChain => "on-chain",
                CoverageLevel::Minimal => "minimal",
                CoverageLevel::Comprehensive => "comprehensive",
            },
        ])
        .args([
            "--collect-message-duration",
            &config.collect_message_duration.to_string(),
        ])
        .args(["--log-level", &config.log_level])
        .args(["--log-format", &config.log_format])
        .args([
            "--persistence-file-path",
            &config.persistence_file_path.unwrap(),
        ])
        .stdout(Stdio::inherit()) // so it outputs to the terminal
        .spawn()
        .expect("Failed to start command");

    // Wait for the server thread to finish
    server_handle.join().unwrap();
}
