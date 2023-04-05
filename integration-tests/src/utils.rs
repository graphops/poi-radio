use graphcast_sdk::graphcast_agent::message_typing::GraphcastMessage;
use graphcast_sdk::graphcast_agent::waku_handling::WakuHandlingError;
use poi_radio::RadioPayloadMessage;
use rand::{thread_rng, Rng};
use secp256k1::SecretKey;
use sha3::{Digest, Keccak256};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::{env, net::TcpListener};
use tracing::{debug, error, info};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

pub fn generate_random_address() -> String {
    let mut rng = thread_rng();
    let mut private_key = [0u8; 32];
    rng.fill(&mut private_key[..]);

    let private_key = SecretKey::from_slice(&private_key).expect("Error parsing secret key");

    let public_key =
        secp256k1::PublicKey::from_secret_key(&secp256k1::Secp256k1::new(), &private_key)
            .serialize_uncompressed();

    let address_bytes = &Keccak256::digest(&public_key[1..])[12..];

    info!("random address: {}", hex::encode(address_bytes));
    format!("0x{}", hex::encode(address_bytes))
}

pub fn generate_deterministic_address(graphcast_id: &str) -> String {
    let mut hasher = DefaultHasher::new();
    graphcast_id.hash(&mut hasher);
    let hashed_result = hasher.finish();

    let mut indexer_address = "0x".to_string();
    indexer_address.push_str(&format!("{:040x}", hashed_result));

    indexer_address
}

pub fn empty_attestation_handler(
) -> impl Fn(Result<GraphcastMessage<RadioPayloadMessage>, WakuHandlingError>) {
    |msg: Result<GraphcastMessage<RadioPayloadMessage>, WakuHandlingError>| match msg {
        Ok(msg) => {
            debug!("Message received: {:?}", msg);
            debug!("This is a setup instance. Continuing...");
        }
        Err(err) => {
            error!("{}", err);
        }
    }
}

pub fn get_random_port() -> String {
    let listener = TcpListener::bind("localhost:0").unwrap();
    let port = listener.local_addr().unwrap().port().to_string();
    debug!("Random port: {}", port);

    port
}

pub async fn setup_mock_server(
    block_number: u64,
    indexer_address: &String,
    graphcast_id: &String,
    ipfs_hashes: &[String],
    staked_tokens: &String,
    poi: &String,
) -> String {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/graphcast-registry"))
        .respond_with(ResponseTemplate::new(200).set_body_string(format!(
            r#"{{
                "data": {{
                  "indexers": [
                    {{
                      "graphcastID": "{graphcast_id}",
                      "id": "{indexer_address}"
                    }}
                  ]
                }},
                "errors": null,
                "extensions": null
              }}
              "#,
            graphcast_id = graphcast_id,
            indexer_address = indexer_address,
        )))
        .mount(&mock_server)
        .await;

    let mut allocations_str = String::new();
    for ipfs_hash in ipfs_hashes {
        allocations_str.push_str(&format!(
            r#"{{"subgraphDeployment": {{"ipfsHash": "{}"}}}},"#,
            ipfs_hash
        ));
    }

    Mock::given(method("POST"))
        .and(path("/network-subgraph"))
        .respond_with(ResponseTemplate::new(200).set_body_string(format!(
            r#"{{
                "data": {{
                    "indexer" : {{
                        "stakedTokens": "{staked_tokens}",
                        "allocations": [{}
                        ]
                    }},
                    "graphNetwork": {{
                        "minimumIndexerStake": "100000000000000000000000"
                    }}
                }},
                "errors": null
            }}"#,
            allocations_str.trim_end_matches(','),
        )))
        .mount(&mock_server)
        .await;

    Mock::given(method("POST"))
        .and(path("/graphql"))
        .respond_with(ResponseTemplate::new(200).set_body_string(format!(
            r#"{{
                "data": {{
                  "proofOfIndexing": "{poi}",
                  "blockHashFromNumber":"4dbba1ba9fb18b0034965712598be1368edcf91ae2c551d59462aab578dab9c5",
                  "indexingStatuses": [
                    {{
                      "subgraph": "{}",
                      "synced": true,
                      "health": "healthy",
                      "node": "default",
                      "fatalError": null,
                      "chains": [
                        {{
                          "network": "mainnet",
                          "latestBlock": {{
                            "number": "{block_number}",
                            "hash": "b30395958a317ccc06da46782f660ce674cbe6792e5573dc630978c506114a0a"
                          }},
                          "chainHeadBlock": {{
                            "number": "{block_number}",
                            "hash": "b30395958a317ccc06da46782f660ce674cbe6792e5573dc630978c506114a0a"
                          }}
                        }}
                      ]
                    }},
                    {{
                        "subgraph": "{}",
                        "synced": true,
                        "health": "healthy",
                        "node": "default",
                        "fatalError": null,
                        "chains": [
                          {{
                            "network": "goerli",
                            "latestBlock": {{
                                "number": "{}",
                                "hash": "b30395958a317ccc06da46782f660ce674cbe6792e5573dc630978c506114a0a"
                              }},
                              "chainHeadBlock": {{
                                "number": "{}",
                                "hash": "b30395958a317ccc06da46782f660ce674cbe6792e5573dc630978c506114a0a"
                              }}
                          }}
                        ]
                      }}
                  ]
                }}
              }}
              "#,
              ipfs_hashes[0], ipfs_hashes[1], block_number + 5, block_number + 5, // use the provided ipfs hashes
            )))
        .mount(&mock_server)
        .await;

    mock_server.uri()
}

pub fn setup_mock_env_vars(mock_server_uri: &String) {
    env::set_var(
        "GRAPH_NODE_STATUS_ENDPOINT",
        format!("{}{}", mock_server_uri, "/graphql"),
    );

    env::set_var(
        "REGISTRY_SUBGRAPH_ENDPOINT",
        format!("{}{}", mock_server_uri, "/graphcast-registry"),
    );

    env::set_var(
        "NETWORK_SUBGRAPH_ENDPOINT",
        format!("{}{}", mock_server_uri, "/network-subgraph"),
    );
}

pub struct RadioTestConfig {
    pub is_setup_instance: bool,
    pub panic_if_poi_diverged: bool,
    pub subgraphs: Option<Vec<String>>,
    pub indexer_stake: String,
    pub poi: String,
    pub indexer_address: Option<String>,
    pub operator_address: Option<String>,
    pub invalid_payload: bool,
}

impl RadioTestConfig {
    pub fn default_config() -> Self {
        RadioTestConfig {
            is_setup_instance: true,
            panic_if_poi_diverged: false,
            subgraphs: None,
            indexer_stake: "100000000000000000000000".to_string(),
            poi: "0x25331f98b82ca7f3966256bf508a7ede52e715b631dfa3d73b846bb7617f6b9e".to_string(),
            indexer_address: None,
            operator_address: None,
            invalid_payload: false,
        }
    }
    pub fn new(is_setup_instance: bool, panic_if_poi_diverged: bool) -> Self {
        RadioTestConfig {
            is_setup_instance,
            panic_if_poi_diverged,
            subgraphs: None,
            indexer_stake: "100000000000000000000000".to_string(),
            poi: "0x25331f98b82ca7f3966256bf508a7ede52e715b631dfa3d73b846bb7617f6b9e".to_string(),
            indexer_address: None,
            operator_address: None,
            invalid_payload: false,
        }
    }
}
