use std::fs::{DirBuilder, File};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;

use graphcast_sdk::init_tracing;
use poi_radio::config::CoverageLevel;
use poi_radio::state::PersistedState;
use tokio::task;
use tokio::time::{sleep, Duration};
use tracing::{info, trace};
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

    // Create directories if they don't exist and open the log files
    let sender_log_file_path = Path::new("logs/sender.log");
    let radio_log_file_path = Path::new("logs/radio.log");

    let log_files = [&sender_log_file_path, &radio_log_file_path];

    for log_file_path in log_files.iter() {
        if let Some(directory) = log_file_path.parent() {
            if !directory.exists() {
                DirBuilder::new()
                    .recursive(true)
                    .create(directory)
                    .expect("Failed to create directory");
            }
        }
    }

    let sender_log_file =
        File::create(sender_log_file_path).expect("Failed to open sender log file");
    let radio_log_file = File::create(radio_log_file_path).expect("Failed to open radio log file");

    // Run the 'cargo run --bin sender' command
    let sender = Arc::new(Mutex::new(
        Command::new("cargo")
            .arg("run")
            .arg("--bin")
            .arg("sender")
            .stdout(Stdio::piped())
            .spawn()
            .expect("Failed to start command"),
    ));

    let host = "127.0.0.1:8087";

    // Using std::thread::spawn instead of tokio::spawn
    let server_handle = thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(start_mock_server(host))
    });

    // Now use tokio's async sleep function.
    tokio::time::sleep(Duration::from_secs(5)).await;

    info!("server created and time awaited?");

    let config = test_config(
        format!("http://{}/graphql", host),
        format!("http://{}/registry-subgraph", host),
        format!("http://{}/network-subgraph", host),
    );

    // Run the 'cargo run --bin radio' command
    let radio = Arc::new(Mutex::new(
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
            .expect("Failed to start command"),
    ));

    // Create cleanup struct
    let _cleanup = Cleanup {
        sender: Arc::clone(&sender),
        radio: Arc::clone(&radio),
    };

    let processes = vec![
        (Arc::clone(&sender), sender_log_file),
        (Arc::clone(&radio), radio_log_file),
    ];

    let mut handlers = Vec::new();

    // Handle the output of each process in a new thread
    for (process, mut log_file) in processes {
        let process = Arc::clone(&process);

        let handler = task::spawn(async move {
            let reader = BufReader::new(
                process
                    .lock()
                    .unwrap()
                    .stdout
                    .take()
                    .expect("Failed to capture stdout"),
            );

            // Read the stdout line by line and write to the corresponding log file
            for line in reader.lines() {
                match line {
                    Ok(line) => {
                        writeln!(log_file, "{}", line).expect("Failed to write to log file");
                    }
                    Err(err) => eprintln!("Error: {}", err),
                }
            }
        });

        handlers.push(handler);
    }

    // Wait for 2 minutes asynchronously
    sleep(Duration::from_secs(120)).await;

    // Read the content of the state.json file
    let state_file_path = "./test-runner/state.json";
    let persisted_state = PersistedState::load_cache(state_file_path);
    trace!("persisted state {:?}", persisted_state);

    let local_attestations = persisted_state.local_attestations();

    assert!(
        !local_attestations.is_empty(),
        "There should be at least one element in local_attestations"
    );

    let test_hashes_local = vec![
        "QmpRkaVUwUQAwPwWgdQHYvw53A5gh3CP3giWnWQZdA2BTE",
        "QmtYT8NhPd6msi1btMc3bXgrfhjkJoC4ChcM5tG6fyLjHE",
    ];

    for test_hash in test_hashes_local {
        assert!(
            local_attestations.contains_key(test_hash),
            "No attestation found with ipfs hash {}",
            test_hash
        );
    }

    let remote_messages = persisted_state.remote_messages();
    let remote_messages = remote_messages.lock().unwrap();

    let test_hashes_remote = vec!["QmtYT8NhPd6msi1btMc3bXgrfhjkJoC4ChcM5tG6fyLjHE"];

    for target_id in test_hashes_remote {
        let has_target_id = remote_messages
            .iter()
            .any(|msg| msg.identifier == *target_id);
        assert!(
            has_target_id,
            "No remote message found with identifier {}",
            target_id
        );
    }

    info!("All checks passed ✅");

    for handler in handlers {
        let _ = handler.abort_handle();
    }

    server_handle.join().unwrap();
}
