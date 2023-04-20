use async_graphql::SimpleObject;
use chrono::Utc;
use ethers_contract::EthAbiType;
use ethers_core::types::transaction::eip712::Eip712;
use ethers_derive_eip712::*;
use graphcast_sdk::graphcast_agent::message_typing::{
    get_indexer_stake, BuildMessageError, GraphcastMessage,
};
use graphcast_sdk::graphql::client_registry::query_registry_indexer;
use poi_radio::attestation::{combine_senders, AttestationError, RemoteAttestationsMap};
use poi_radio::metrics::{ACTIVE_INDEXERS, INDEXER_COUNT_BY_NPOI};
use poi_radio::{attestation::Attestation, RadioPayloadMessage};
use prost::Message;
use rand::{thread_rng, Rng};
use secp256k1::SecretKey;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::thread::sleep;
use std::time::Duration;
use std::{env, net::TcpListener};
use tracing::{debug, info};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::setup::constants::{
    MOCK_SUBGRAPH_GOERLI, MOCK_SUBGRAPH_GOERLI_2, MOCK_SUBGRAPH_MAINNET,
};

#[derive(Eip712, EthAbiType, Clone, Message, Serialize, Deserialize, SimpleObject)]
#[eip712(
    name = "Graphcast POI Radio Dummy Msg",
    version = "0",
    chain_id = 1,
    verifying_contract = "0xc944e90c64b2c07662a292be6244bdf05cda44a7"
)]
pub struct DummyMsg {
    #[prost(string, tag = "1")]
    pub identifier: String,
    #[prost(int32, tag = "2")]
    pub dummy_value: i32,
}

impl DummyMsg {
    pub fn new(identifier: String, dummy_value: i32) -> Self {
        DummyMsg {
            identifier,
            dummy_value,
        }
    }

    pub fn from_ref(dummy_msg: &DummyMsg) -> Self {
        DummyMsg {
            identifier: dummy_msg.identifier.clone(),
            dummy_value: dummy_msg.dummy_value,
        }
    }
}

pub fn round_to_nearest(number: i64) -> i64 {
    (number / 10) * 10 + if number % 10 > 4 { 10 } else { 0 }
}

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

pub fn generate_deterministic_address(base: &str) -> String {
    let mut hasher = DefaultHasher::new();
    base.hash(&mut hasher);
    let hashed_result = hasher.finish();

    let mut res = "0x".to_string();
    res.push_str(&format!("{:040x}", hashed_result));

    res
}

pub fn get_random_port() -> String {
    let listener = TcpListener::bind("localhost:0").unwrap();
    let port = listener.local_addr().unwrap().port().to_string();
    debug!("Random port: {}", port);

    port
}

pub fn f32_to_grt_gwei_string(input: f32) -> String {
    let formatted = format!("{:0.18}", input);
    let parts: Vec<&str> = formatted.split('.').collect();
    let mut result = format!("{}{}", parts[0], parts[1]);

    while result.starts_with('0') && result.len() > 1 {
        result.remove(0);
    }

    result
}

pub async fn setup_mock_server(
    block_number: u64,
    indexer_address: &String,
    graphcast_id: &String,
    ipfs_hashes: &[String],
    staked_tokens: f32,
    poi: &String,
) -> String {
    let mock_server = MockServer::start().await;
    let staked_tokens = f32_to_grt_gwei_string(staked_tokens);

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
                        "minimumIndexerStake": "10000000000000000000000"
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
    pub subgraphs: Option<Vec<String>>,
    pub indexer_stake: f32,
    pub poi: String,
    pub indexer_address: Option<String>,
    pub operator_address: Option<String>,
    pub invalid_payload: Option<DummyMsg>,
    pub invalid_time: Option<i64>,
    pub invalid_hash: Option<String>,
    pub invalid_sender: bool,
}

impl Default for RadioTestConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl RadioTestConfig {
    pub fn default_config() -> Self {
        RadioTestConfig {
            subgraphs: None,
            indexer_stake: 100000.0,
            poi: "0x25331f98b82ca7f3966256bf508a7ede52e715b631dfa3d73b846bb7617f6b9e".to_string(),
            indexer_address: None,
            operator_address: None,
            invalid_payload: None,
            invalid_hash: None,
            invalid_time: None,
            invalid_sender: false,
        }
    }
    pub fn new() -> Self {
        RadioTestConfig {
            subgraphs: None,
            indexer_stake: 100000.0,
            poi: "0x25331f98b82ca7f3966256bf508a7ede52e715b631dfa3d73b846bb7617f6b9e".to_string(),
            indexer_address: None,
            operator_address: None,
            invalid_payload: None,
            invalid_hash: None,
            invalid_time: None,
            invalid_sender: false,
        }
    }
}

pub async fn test_process_messages(
    messages: Vec<GraphcastMessage<RadioPayloadMessage>>,
    registry_subgraph: &str,
    network_subgraph: &str,
    runtime_config_indexer_stake: f32,
) -> Result<RemoteAttestationsMap, AttestationError> {
    let mut remote_attestations: RemoteAttestationsMap = HashMap::new();

    // Check if there are existing attestations for the block
    let first_message = messages.first();
    let first_msg = if first_message.is_none() {
        return Ok(remote_attestations);
    } else {
        first_message.unwrap()
    };

    for msg in messages.iter() {
        let radio_msg = &msg.payload.clone().unwrap();
        let npoi = radio_msg.payload_content().to_string();
        let sender = msg
            .recover_sender_address()
            .map_err(AttestationError::BuildError)?;
        let indexer_address = query_registry_indexer(registry_subgraph.to_string(), sender.clone())
            .await
            .map_err(|e| AttestationError::BuildError(BuildMessageError::FieldDerivations(e)))?;
        let sender_stake = get_indexer_stake(indexer_address.clone(), network_subgraph)
            .await
            .map_err(|e| AttestationError::BuildError(BuildMessageError::FieldDerivations(e)))?;

        //TODO: update this to utilize update_blocks?
        let blocks = remote_attestations
            .entry(msg.identifier.to_string())
            .or_default();
        let attestations = blocks.entry(msg.block_number).or_default();

        let existing_attestation = attestations.iter_mut().find(|a| a.npoi == npoi);

        if let Some(existing_attestation) = existing_attestation {
            if let Ok(updated_attestation) = Attestation::update(
                existing_attestation,
                indexer_address,
                sender_stake,
                msg.nonce,
            ) {
                // Replace the existing_attestation with the updated_attestation
                *existing_attestation = updated_attestation;
            }
        } else {
            // Unwrap is okay because bytes (Vec<u8>) is a valid utf-8 sequence
            attestations.push(Attestation::new(
                radio_msg.payload_content().to_string(),
                sender_stake,
                vec![indexer_address],
                vec![msg.nonce],
            ));
        }

        let graphcast_id = generate_deterministic_address(&sender);
        env::set_var("MOCK_SENDER", graphcast_id.clone());
        let indexer_address = generate_deterministic_address(&graphcast_id);

        setup_mock_server(
            round_to_nearest(Utc::now().timestamp()).try_into().unwrap(),
            &indexer_address,
            &graphcast_id,
            &[
                MOCK_SUBGRAPH_MAINNET.to_string(),
                MOCK_SUBGRAPH_GOERLI.to_string(),
                MOCK_SUBGRAPH_GOERLI_2.to_string(),
            ],
            runtime_config_indexer_stake,
            &"0x25331f98b82ca7f3966256bf508a7ede52e715b631dfa3d73b846bb7617f6b9e".to_string(),
        )
        .await;

        sleep(Duration::from_secs(1));
    }

    // update once at the end
    // active peers for each deployment
    debug!(
        "process message into attestations: {:#?} -> {:#?}",
        messages.len(),
        remote_attestations.len()
    );
    // npoi_hist by attestation - don't care for attestation but should be grouped together
    // so the summed up metrics should be ACTIVE_INDEXERS
    let npoi_hist = INDEXER_COUNT_BY_NPOI.with_label_values(&[&first_msg.identifier.to_string()]);
    let blocks = remote_attestations
        .entry(first_msg.identifier.to_string())
        .or_default();
    for a in blocks.entry(first_msg.block_number).or_default() {
        // this can probably sum up to active peers)
        // Update INDEXER_COUNT_BY_NPOI metric
        npoi_hist.observe(a.senders.len() as f64);
    }

    let active_indexers = ACTIVE_INDEXERS.with_label_values(&[&first_msg.identifier.to_string()]);
    let senders = combine_senders(blocks.entry(first_msg.block_number).or_default());
    active_indexers.set(senders.len().try_into().unwrap());

    Ok(remote_attestations)
}
