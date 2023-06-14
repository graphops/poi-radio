use std::{
    fs,
    net::{TcpListener, UdpSocket},
    path::Path,
    process::{Child, Command},
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};

use mock_server::start_mock_server;
use poi_radio::config::{Config, CoverageLevel};
use rand::Rng;
use tracing::info;

pub mod config;
pub mod mock_server;

pub struct ProcessManager {
    pub senders: Vec<Arc<Mutex<Child>>>,
    pub radio: Arc<Mutex<Child>>,
}

impl Drop for ProcessManager {
    fn drop(&mut self) {
        let _ = self.senders.get(0).unwrap().lock().unwrap().kill();
        let _ = self.radio.lock().unwrap().kill();
    }
}

fn find_random_tcp_port() -> u16 {
    let mut rng = rand::thread_rng();
    let mut port = 0;

    for _ in 0..10 {
        // Generate a random port number within the range 49152 to 65535
        let test_port = rng.gen_range(49152..=65535);
        match TcpListener::bind(("0.0.0.0", test_port)) {
            Ok(_) => {
                port = test_port;
                break;
            }
            Err(_) => {
                println!("Port {} is not available, retrying...", test_port);
                thread::sleep(Duration::from_secs(1));
                continue;
            }
        }
    }

    if port == 0 {
        panic!("Could not find a free port");
    }

    port
}

pub fn setup(config: &Config, test_file_name: &str) -> ProcessManager {
    assert!(
        !Path::new(&config.persistence_file_path.clone().unwrap()).exists(),
        "State file already exists, previous test may have not cleaned up successfully"
    );

    let id = uuid::Uuid::new_v4().to_string();
    let radio_name = format!("{}-{}", test_file_name, id);

    // TODO: Make sender accept custom config
    let basic_sender = Arc::new(Mutex::new(
        Command::new("cargo")
            .arg("run")
            .arg("-p")
            .arg("test-sender")
            .arg("--")
            .arg("--topics")
            .arg("QmtYT8NhPd6msi1btMc3bXgrfhjkJoC4ChcM5tG6fyLjHE")
            .arg("--radio-name")
            .arg(&radio_name)
            .spawn()
            .expect("Failed to start command"),
    ));

    let port = find_random_tcp_port();

    let host = format!("127.0.0.1:{}", port);
    tokio::spawn(start_mock_server(host.clone()));

    let waku_port = find_random_udp_port();
    let discv5_port = find_random_udp_port();

    let mut config = config.clone();
    config.graph_node_endpoint = format!("http://{}/graphql", host);
    config.registry_subgraph = format!("http://{}/registry-subgraph", host);
    config.network_subgraph = format!("http://{}/network-subgraph", host);
    config.radio_name = radio_name;
    config.waku_port = Some(waku_port.to_string());
    config.discv5_port = Some(discv5_port);

    info!(
        "Starting POI Radio instance on port {}",
        waku_port.to_string()
    );

    let radio = Arc::new(Mutex::new(start_radio(&config)));

    ProcessManager {
        senders: vec![Arc::clone(&basic_sender)],
        radio: Arc::clone(&radio),
    }
}

pub fn teardown(process_manager: ProcessManager, store_path: &str) {
    // Kill the processes
    for sender in &process_manager.senders {
        let _ = sender.lock().unwrap().kill();
    }
    let _ = process_manager.radio.lock().unwrap().kill();

    if Path::new(&store_path).exists() {
        fs::remove_file(store_path).unwrap();
    }
}

pub fn start_radio(config: &Config) -> Child {
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
        .arg("--waku-port")
        .arg(config.waku_port.as_deref().unwrap_or("None"))
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
        .arg("--discv5-port")
        .arg(
            config
                .discv5_port
                .map(|p| p.to_string())
                .unwrap_or_else(|| "None".to_string()),
        )
        .spawn()
        .expect("Failed to start command")
}

pub fn find_random_udp_port() -> u16 {
    let mut rng = rand::thread_rng();
    let mut port = 0;

    for _ in 0..10 {
        // Generate a random port number within the range 49152 to 65535
        let test_port = rng.gen_range(49152..=65535);
        match UdpSocket::bind(("0.0.0.0", test_port)) {
            Ok(_) => {
                port = test_port;
                break;
            }
            Err(_) => continue,
        }
    }

    if port == 0 {
        panic!("Could not find a free port");
    }

    port
}
