use std::{net::IpAddr, str::FromStr, thread::sleep, time::Duration};

use chrono::Utc;
use clap::Parser;
use graphcast_sdk::{
    build_wallet,
    graphcast_agent::{
        message_typing::GraphcastMessage,
        waku_handling::{connect_multiaddresses, gather_nodes, get_dns_nodes},
    },
    init_tracing,
    networks::NetworkName,
};
use poi_radio::messages::poi::PublicPoiMessage;
use test_utils::{config::TestSenderConfig, dummy_msg::DummyMsg, find_random_udp_port};
use tracing::{error, info};
use waku::{
    waku_new, GossipSubParams, ProtocolId, WakuContentTopic, WakuNodeConfig, WakuPubSubTopic,
};

async fn start_sender(config: TestSenderConfig) {
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

    let pubsub_topic_str = "/waku/2/graphcast-v0-testnet/proto";
    let pubsub_topic = WakuPubSubTopic::from_str(pubsub_topic_str).unwrap();
    loop {
        for topic in config.topics.clone() {
            let timestamp = Utc::now().timestamp();
            let timestamp = (timestamp + 9) / 10 * 10;

            let nodes = gather_nodes(vec![], &pubsub_topic);
            // Connect to peers on the filter protocol
            connect_multiaddresses(nodes, &node_handle, ProtocolId::Filter);

            let content_topic = format!("/{}/0/{}/proto", config.radio_name, topic);
            let content_topic = WakuContentTopic::from_str(&content_topic).unwrap();

            let nonce = config.nonce.clone().unwrap().parse::<i64>().unwrap();

            let radio_payload_clone = config.radio_payload.clone();
            match radio_payload_clone.as_deref() {
                Some("radio_payload_message") => {
                    let radio_payload = PublicPoiMessage::build(
                        topic.clone(),
                        config.poi.clone().unwrap(),
                        nonce,
                        NetworkName::Goerli,
                        timestamp.try_into().unwrap(),
                        config.block_hash.clone().unwrap(),
                        "0x7e6528e4ce3055e829a32b5dc4450072bac28bc6".to_string(),
                    );

                    let graphcast_message = GraphcastMessage::build(
                        &wallet,
                        topic.clone(),
                        "0x7e6528e4ce3055e829a32b5dc4450072bac28bc6".to_string(),
                        nonce,
                        radio_payload,
                    )
                    .await
                    .unwrap();

                    match graphcast_message.send_to_waku(
                        &node_handle,
                        WakuPubSubTopic::from_str("/waku/2/graphcast-v0-testnet/proto").unwrap(),
                        content_topic,
                    ) {
                        Ok(id) => {
                            info!("Message sent successfully. Mеssage id: {:?}", id);
                        }
                        Err(e) => {
                            error!("Failed to send message: {:?}", e);
                        }
                    }
                }
                _ => {
                    let payload = DummyMsg::from_json(&config.radio_payload.clone().unwrap());
                    let graphcast_message = GraphcastMessage::build(
                        &wallet,
                        topic.clone(),
                        "0x7e6528e4ce3055e829a32b5dc4450072bac28bc6".to_string(),
                        timestamp,
                        payload,
                    )
                    .await
                    .unwrap();

                    match graphcast_message.send_to_waku(
                        &node_handle,
                        WakuPubSubTopic::from_str("/waku/2/graphcast-v0-testnet/proto").unwrap(),
                        content_topic,
                    ) {
                        Ok(id) => {
                            info!("Message sent successfully. Mеssage id: {:?}", id);
                        }
                        Err(e) => {
                            error!("Failed to send message: {:?}", e);
                        }
                    }
                }
            }

            sleep(Duration::from_secs(1));
        }
        sleep(Duration::from_secs(1));
    }
}

#[tokio::main]
pub async fn main() {
    let config = TestSenderConfig::parse();
    start_sender(config).await;
}
