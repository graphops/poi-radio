mod config;

use std::{net::IpAddr, str::FromStr, thread::sleep, time::Duration};

use chrono::Utc;
use clap::Parser;
use config::SenderConfig;
use graphcast_sdk::{
    build_wallet,
    graphcast_agent::{
        message_typing::GraphcastMessage,
        waku_handling::{connect_multiaddresses, gather_nodes},
    },
    init_tracing,
    networks::NetworkName,
};
use poi_radio::RadioPayloadMessage;
use rand::RngCore;
use ring::digest;
use test_utils::find_random_udp_port;
use tracing::info;
use waku::{
    waku_new, GossipSubParams, ProtocolId, WakuContentTopic, WakuNodeConfig, WakuPubSubTopic,
};

fn generate_random_poi() -> String {
    let mut rng = rand::thread_rng();
    let mut input = [0u8; 32]; // 32 bytes for SHA-256

    rng.fill_bytes(&mut input);

    let hash = digest::digest(&digest::SHA256, &input);

    let mut hash_string = String::from("0x");
    for byte in hash.as_ref() {
        hash_string.push_str(&format!("{:02x}", byte));
    }

    hash_string
}

async fn start_sender(config: SenderConfig) {
    std::env::set_var(
        "RUST_LOG",
        "off,hyper=off,graphcast_sdk=info,poi_radio=info,poi-radio-e2e-tests=info",
    );
    init_tracing("pretty".to_string()).expect("Could not set up global default subscriber for logger, check environmental variable `RUST_LOG` or the CLI input `log-level");

    let gossipsub_params = GossipSubParams {
        seen_messages_ttl_seconds: Some(1800),
        history_length: Some(100_000),
        ..Default::default()
    };

    let port = find_random_udp_port();
    info!("Starting test sender instance on port {}", port);

    let node_config = WakuNodeConfig {
        host: IpAddr::from_str("127.0.0.1").ok(),
        port: Some(port.into()),
        advertise_addr: None, // Fill this for boot nodes
        node_key: None,
        keep_alive_interval: None,
        relay: Some(false), // Default true - will receive all msg on relay
        min_peers_to_publish: Some(0), // Default 0
        filter: Some(true), // Default false
        log_level: None,
        relay_topics: [].to_vec(),
        discv5: Some(false),
        discv5_bootstrap_nodes: [].to_vec(),
        discv5_udp_port: None,
        store: None,
        database_url: None,
        store_retention_max_messages: None,
        store_retention_max_seconds: None,
        gossipsub_params: Some(gossipsub_params),
    };

    let node_handle = waku_new(Some(node_config)).unwrap().start().unwrap();

    let wallet =
        build_wallet("baf5c93f0c8aee3b945f33b9192014e83d50cec25f727a13460f6ef1eb6a5844").unwrap();

    let pubsub_topic_str = "/waku/2/graphcast-v0-testnet/proto";
    let pubsub_topic = WakuPubSubTopic::from_str(pubsub_topic_str).unwrap();

    loop {
        for topic in config.topics.clone() {
            let timestamp = Utc::now().timestamp();
            let timestamp = (timestamp + 9) / 10 * 10;

            let radio_payload = RadioPayloadMessage::new(topic.clone(), generate_random_poi());

            let graphcast_message = GraphcastMessage::build(
                &wallet,
                topic.clone(),
                Some(radio_payload),
                NetworkName::Goerli,
                timestamp.try_into().unwrap(),
                "4dbba1ba9fb18b0034965712598be1368edcf91ae2c551d59462aab578dab9c5".to_string(),
            )
            .await
            .unwrap();

            let nodes = gather_nodes(vec![], &pubsub_topic);
            // Connect to peers on the filter protocol
            connect_multiaddresses(nodes, &node_handle, ProtocolId::Filter);

            let content_topic = format!("/{}/0/{}/proto", config.radio_name, topic);
            let content_topic = WakuContentTopic::from_str(&content_topic).unwrap();

            let sent =
                graphcast_message.send_to_waku(&node_handle, pubsub_topic.clone(), content_topic);

            info!("Message is sent {:?}", sent);

            sleep(Duration::from_secs(1));
        }

        sleep(Duration::from_secs(10));
    }
}

#[tokio::main]
pub async fn main() {
    let config = SenderConfig::parse();
    start_sender(config).await;
}
