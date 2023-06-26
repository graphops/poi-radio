use std::{env, net::IpAddr, str::FromStr, thread::sleep, time::Duration};

use chrono::Utc;
use graphcast_sdk::{
    build_wallet,
    graphcast_agent::{
        message_typing::GraphcastMessage,
        waku_handling::{connect_multiaddresses, gather_nodes, get_dns_nodes},
    },
    init_tracing,
    networks::NetworkName,
};
use poi_radio::RadioPayloadMessage;
use rand::RngCore;
use ring::digest;
use tracing::{error, info};
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

#[tokio::main]
pub async fn main() {
    std::env::set_var(
        "RUST_LOG",
        "off,hyper=off,graphcast_sdk=trace,poi_radio=trace,test_sender=trace",
    );
    init_tracing("pretty".to_string()).expect("Could not set up global default subscriber for logger, check environmental variable `RUST_LOG` or the CLI input `log-level");

    let gossipsub_params = GossipSubParams {
        seen_messages_ttl_seconds: Some(1800),
        history_length: Some(100_000),
        ..Default::default()
    };

    let pubsub_topic = WakuPubSubTopic::from_str("/waku/2/graphcast-v0-testnet/proto").unwrap();

    let discv5_nodes: Vec<String> = get_dns_nodes(&pubsub_topic)
        .into_iter()
        .filter(|d| d.enr.is_some())
        .map(|d| d.enr.unwrap().to_string())
        .collect::<Vec<String>>();

    let node_config = WakuNodeConfig {
        host: IpAddr::from_str("127.0.0.1").ok(),
        port: Some(60002),
        advertise_addr: None, // Fill this for boot nodes
        node_key: None,
        keep_alive_interval: None,
        relay: Some(false), // Default true - will receive all msg on relay
        min_peers_to_publish: Some(0), // Default 0
        filter: Some(true), // Default false¡
        log_level: None,
        relay_topics: [].to_vec(),
        discv5: Some(false),
        discv5_bootstrap_nodes: discv5_nodes,
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

    loop {
        let timestamp = Utc::now().timestamp();
        let timestamp = (timestamp + 9) / 10 * 10;

        let radio_payload = RadioPayloadMessage::new(
            "QmtYT8NhPd6msi1btMc3bXgrfhjkJoC4ChcM5tG6fyLjHE".to_string(),
            generate_random_poi(),
        );

        let graphcast_message = GraphcastMessage::build(
            &wallet,
            "QmtYT8NhPd6msi1btMc3bXgrfhjkJoC4ChcM5tG6fyLjHE".to_string(),
            Some(radio_payload),
            NetworkName::Goerli,
            timestamp.try_into().unwrap(),
            "4dbba1ba9fb18b0034965712598be1368edcf91ae2c551d59462aab578dab9c5".to_string(),
            "0x7e6528e4ce3055e829a32b5dc4450072bac28bc6".to_string(),
        )
        .await
        .unwrap();

        let nodes = gather_nodes(vec![], &pubsub_topic);
        // Connect to peers on the filter protocol
        connect_multiaddresses(nodes, &node_handle, ProtocolId::Filter);

        let id = env::var("TEST_RUN_ID").unwrap_or_else(|_| panic!("TEST_RUN_ID not set"));

        let content_topic = format!(
            "/poi-radio-test-{}/0/QmtYT8NhPd6msi1btMc3bXgrfhjkJoC4ChcM5tG6fyLjHE/proto",
            id
        );
        let content_topic = WakuContentTopic::from_str(&content_topic).unwrap();

        if let Err(e) = graphcast_message.send_to_waku(
            &node_handle,
            WakuPubSubTopic::from_str("/waku/2/graphcast-v0-testnet/proto").unwrap(),
            content_topic,
        ) {
            error!("Failed to send message: {:?}", e);
        } else {
            info!("Message sent successfully");
        }

        sleep(Duration::from_secs(5));
    }
}
