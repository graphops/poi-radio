use criterion::async_executor::FuturesExecutor;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rand::{thread_rng, Rng};
use secp256k1::SecretKey;
use std::collections::HashMap;
use std::sync::{Arc, Mutex as SyncMutex};
use tokio::sync::Mutex as AsyncMutex;

use graphcast_sdk::networks::NetworkName;
use graphcast_sdk::{BlockPointer, NetworkPointer};
use poi_radio::attestation::LocalAttestationsMap;
use poi_radio::operation::gossip_poi;
use poi_radio::{config::Config, CONFIG, RADIO_NAME};

fn gossip_poi_bench(c: &mut Criterion) {
    let identifiers = black_box(vec!["identifier1".to_string(), "identifier2".to_string()]);
    let network_chainhead_blocks: Arc<AsyncMutex<HashMap<NetworkName, BlockPointer>>> =
        black_box(Arc::new(AsyncMutex::new(Default::default())));
    let subgraph_network_latest_blocks: HashMap<String, NetworkPointer> =
        black_box(Default::default());
    let local_attestations: Arc<AsyncMutex<LocalAttestationsMap>> =
        black_box(Arc::new(AsyncMutex::new(Default::default())));
    let pk = black_box(generate_random_private_key());

    let config = black_box(Config {
        graph_node_endpoint: String::from("http://localhost:8030/graphql"),
        private_key: Some(pk.display_secret().to_string()),
        mnemonic: None,
        registry_subgraph: String::from(
            "https://api.thegraph.com/subgraphs/name/hopeyen/graphcast-registry-goerli",
        ),
        network_subgraph: String::from("https://gateway.testnet.thegraph.com/network"),
        graphcast_network: String::from("testnet"),
        topics: vec![String::from(
            "QmbaLc7fEfLGUioKWehRhq838rRzeR8cBoapNJWNSAZE8u",
        )],
        coverage: poi_radio::config::CoverageLevel::Comprehensive,
        collect_message_duration: 10,
        waku_host: None,
        waku_port: None,
        waku_node_key: None,
        boot_node_addresses: vec![],
        waku_log_level: None,
        waku_addr: None,
        log_level: String::from("info"),
        slack_token: None,
        slack_channel: None,
        instance: None,
        check: None,
        discord_webhook: None,
        metrics_host: None,
        metrics_port: None,
        server_host: None,
        server_port: None,
    });
    _ = black_box(CONFIG.set(Arc::new(SyncMutex::new(config))));
    _ = black_box(RADIO_NAME.set("bench-radio"));

    c.bench_function("gossip_poi", move |b| {
        b.to_async(FuturesExecutor).iter(|| async {
            gossip_poi(
                identifiers.clone(),
                &network_chainhead_blocks,
                &subgraph_network_latest_blocks,
                local_attestations.clone(),
            )
            .await
        })
    });
}

criterion_group!(benches, gossip_poi_bench);
criterion_main!(benches);

pub fn generate_random_private_key() -> SecretKey {
    let mut rng = thread_rng();
    let mut private_key = [0u8; 32];
    rng.fill(&mut private_key[..]);

    SecretKey::from_slice(&private_key).expect("Error parsing secret key")
}
