use chrono::Utc;
use num_bigint::BigUint;
use num_traits::ToPrimitive;
use rand::{thread_rng, Rng};
use secp256k1::SecretKey;
use sha3::{Digest, Keccak256, Sha3_256};
use std::{
    collections::{hash_map::DefaultHasher, HashMap},
    env,
    fmt::{self, Display},
    hash::{Hash, Hasher},
    sync::Arc,
};
use tokio::sync::Mutex as AsyncMutex;
use tracing::{debug, error, info, warn};

use crate::RadioPayloadMessage;
use graphcast_sdk::{
    graphcast_agent::message_typing::{get_indexer_stake, BuildMessageError, GraphcastMessage},
    graphql::client_registry::query_registry_indexer,
    networks::NetworkName,
};
use once_cell::sync::Lazy;
use prometheus::{GaugeVec, IntCounterVec, IntGaugeVec, Opts};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// A wrapper around an attested NPOI, tracks Indexers that have sent it plus their accumulated stake
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Attestation {
    pub npoi: String,
    pub stake_weight: BigUint,
    pub senders: Vec<String>,
    pub sender_group_hash: String,
    pub timestamp: Vec<i64>,
}

impl Attestation {
    pub fn new(
        npoi: String,
        stake_weight: BigUint,
        senders: Vec<String>,
        timestamp: Vec<i64>,
    ) -> Self {
        let addresses = &mut senders.clone();
        sort_addresses(addresses);
        let sender_group_hash = hash_addresses(addresses);
        Attestation {
            npoi,
            stake_weight,
            senders,
            sender_group_hash,
            timestamp,
        }
    }

    /// Used whenever we receive a new attestation for an NPOI that already exists in the store
    pub fn update(
        base: &Self,
        address: String,
        stake: BigUint,
        timestamp: i64,
    ) -> Result<Self, AttestationError> {
        if base.senders.contains(&address) {
            Err(AttestationError::UpdateError(
                "There is already an attestation from this address. Skipping...".to_string(),
            ))
        } else {
            Ok(Self::new(
                base.npoi.clone(),
                base.stake_weight.clone() + stake,
                [base.senders.clone(), vec![address]].concat(),
                [base.timestamp.clone(), vec![timestamp]].concat(),
            ))
        }
    }
}

impl fmt::Display for Attestation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "NPOI: {}\nsender addresses: {:#?}\nstake weight: {}",
            self.npoi, self.senders, self.stake_weight
        )
    }
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

pub type RemoteAttestationsMap = HashMap<String, HashMap<u64, Vec<Attestation>>>;
pub type LocalAttestationsMap = HashMap<String, HashMap<u64, Attestation>>;

// Received (and validated) messages counter
pub static VALIDATED_MESSAGES: Lazy<IntCounterVec> = Lazy::new(|| {
    let counter_vec = IntCounterVec::new(
        Opts::new("validated_messages", "Number of validated messages"),
        &["deployment", "block_number"],
    )
    .expect("Failed to create validated_messages counter");
    prometheus::register(Box::new(counter_vec.clone()))
        .expect("Failed to register validated_messages counter");
    counter_vec
});

// These are the subgraphs that are being actively cross-checked (the ones we are receiving remote attestations for)
pub static ACTIVE_SUBGRAPHS: Lazy<IntGaugeVec> = Lazy::new(|| {
    let opts = Opts::new(
        "active_subgraphs",
        "Number of subgraphs being actively crosschecked with other indexers",
    );
    let gauge_vec =
        IntGaugeVec::new(opts, &["subgraph"]).expect("Failed to create active_subgraphs gauge");
    prometheus::register(Box::new(gauge_vec.clone()))
        .expect("Failed to register active_subgraphs gauge");
    gauge_vec
});

pub static DIVERGING_SUBGRAPHS: Lazy<IntGaugeVec> = Lazy::new(|| {
    let opts = Opts::new(
        "diverging_subgraphs",
        "Number of diverging subgraphs with non-consensus POIs for each subgraph, block, and network",
    );
    let gauge_vec = IntGaugeVec::new(opts, &["subgraph", "block_number", "network"])
        .expect("Failed to create diverging_subgraphs gauge");
    prometheus::register(Box::new(gauge_vec.clone()))
        .expect("Failed to register diverging_subgraphs gauge");
    gauge_vec
});

pub static AGGREGATE_ATTESTING_STAKE_NPOI: Lazy<GaugeVec> = Lazy::new(|| {
    let opts = Opts::new(
        "aggregate_attesting_stake_npoi",
        "Aggregate attesting stake in GRT for each nPOI",
    );
    let gauge_vec = GaugeVec::new(
        opts,
        &["deployment_hash", "npoi", "network", "block_number"],
    )
    .expect("Failed to create aggregate_attesting_stake_npoi gauge");
    prometheus::register(Box::new(gauge_vec.clone()))
        .expect("Failed to register aggregate_attesting_stake_npoi gauge");
    gauge_vec
});

pub static AGGREGATE_ATTESTING_STAKE_INDEXER_GROUP: Lazy<GaugeVec> = Lazy::new(|| {
    let opts = Opts::new(
        "aggregate_attesting_stake_indexer_group",
        "Aggregate attesting stake in GRT for each indexer group",
    );
    let gauge_vec = GaugeVec::new(
        opts,
        &[
            "deployment_hash",
            "indexer_group_hash",
            "network",
            "block_number",
        ],
    )
    .expect("Failed to create aggregate_attesting_stake_indexer_group gauge");
    prometheus::register(Box::new(gauge_vec.clone()))
        .expect("Failed to register aggregate_attesting_stake_indexer_group gauge");
    gauge_vec
});

// Remove these helpers from here
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

pub fn generate_deterministic_address(input: &str) -> String {
    let mut hasher = DefaultHasher::new();
    input.hash(&mut hasher);
    let hashed_result = hasher.finish();

    let mut indexer_address = "0x".to_string();
    indexer_address.push_str(&format!("{:040x}", hashed_result));

    indexer_address
}

fn round_to_nearest(number: i64) -> i64 {
    (number / 10) * 10 + if number % 10 > 4 { 10 } else { 0 }
}

pub static MOCK_SUBGRAPH_MAINNET: &str = "QmggQnSgia4iDPWHpeY6aWxesRFdb8o5DKZUx96zZqEWrB";
pub static MOCK_SUBGRAPH_GOERLI: &str = "Qm11QnSgia4iDPWHpeY6aWxesRFdb8o5DKZUx96zZqEWrB";
pub static MOCK_SUBGRAPH_GOERLI_2: &str = "Qm22QnSgia4iDPWHpeY6aWxesRFdb8o5DKZUx96zZqEWrB";

/// This function processes the global messages map that we populate when
/// messages are being received. It constructs the remote attestations
/// map and returns it if the processing succeeds.
pub async fn process_messages(
    messages: Arc<AsyncMutex<Vec<GraphcastMessage<RadioPayloadMessage>>>>,
    registry_subgraph: &str,
    network_subgraph: &str,
) -> Result<RemoteAttestationsMap, AttestationError> {
    info!("Messages {:?}", messages.lock().await);

    let mut remote_attestations: RemoteAttestationsMap = HashMap::new();

    for msg in messages.lock().await.iter() {
        info!("Message being processed: {:?}", msg);
        //
        // This is highly experimental but will try to mock here
        let graphcast_id = generate_deterministic_address(&msg.signature);
        env::set_var("MOCK_SENDER", graphcast_id.clone());
        let indexer_address = generate_deterministic_address(&graphcast_id);

        debug!("Actual graphcast_id: {}", graphcast_id);

        setup_mock_server(
            round_to_nearest(Utc::now().timestamp()).try_into().unwrap(),
            &indexer_address,
            &graphcast_id,
            &[
                MOCK_SUBGRAPH_MAINNET.to_string(),
                MOCK_SUBGRAPH_GOERLI.to_string(),
            ],
            &"100000000000000000000000".to_string(),
            &"0x25331f98b82ca7f3966256bf508a7ede52e715b631dfa3d73b846bb7617f6b9e".to_string(),
        )
        .await;
        // End of mocks
        //
        let radio_msg = &msg.payload.clone().unwrap();
        let sender = msg
            .recover_sender_address()
            .map_err(AttestationError::BuildError)?;

        info!("SENDER {}", sender);

        let indexer_address = query_registry_indexer(registry_subgraph.to_string(), sender.clone())
            .await
            .map_err(|e| AttestationError::BuildError(BuildMessageError::FieldDerivations(e)))?;
        let sender_stake = get_indexer_stake(indexer_address.clone(), network_subgraph)
            .await
            .map_err(|e| AttestationError::BuildError(BuildMessageError::FieldDerivations(e)))?;

        //TODO: update this to utilize update_blocks?
        // Check if there are existing attestations for the block
        let blocks = remote_attestations
            .entry(msg.identifier.to_string())
            .or_default();

        info!("Blocks: {:?}", blocks);

        let attestations = blocks.entry(msg.block_number).or_default();

        info!("Attestations {:?}", attestations);
        info!("Block: {}", msg.block_number);

        let existing_attestation = attestations
            .iter_mut()
            .find(|a| a.npoi == radio_msg.payload_content());

        if let Some(existing_attestation) = existing_attestation {
            if let Ok(updated_attestation) = Attestation::update(
                existing_attestation,
                indexer_address.clone(),
                sender_stake.clone(),
                msg.nonce,
            ) {
                info!("old!!");
                // Replace the existing_attestation with the updated_attestation
                *existing_attestation = updated_attestation;

                // Update AGGREGATE_ATTESTING_STAKE_NPOI metric
                let npoi_gauge = AGGREGATE_ATTESTING_STAKE_NPOI.with_label_values(&[
                    &msg.identifier.to_string(),
                    &existing_attestation.npoi,
                    &msg.network,
                    &msg.block_number.to_string(),
                ]);
                npoi_gauge.set(existing_attestation.stake_weight.to_f64().unwrap());

                // Update AGGREGATE_ATTESTING_STAKE_INDEXER_GROUP metric
                let indexer_group_gauge = AGGREGATE_ATTESTING_STAKE_INDEXER_GROUP
                    .with_label_values(&[
                        &msg.identifier.to_string(),
                        &indexer_address,
                        &msg.network,
                        &msg.block_number.to_string(),
                    ]);
                indexer_group_gauge.set(existing_attestation.stake_weight.to_f64().unwrap());
            }
        } else {
            info!("new!!");
            // Unwrap is okay because bytes (Vec<u8>) is a valid utf-8 sequence
            let new_attestation = Attestation::new(
                radio_msg.payload_content().to_string(),
                sender_stake.clone(),
                vec![indexer_address.clone()],
                vec![msg.nonce],
            );
            attestations.push(new_attestation.clone());

            // Update AGGREGATE_ATTESTING_STAKE_NPOI metric
            let npoi_gauge = AGGREGATE_ATTESTING_STAKE_NPOI.with_label_values(&[
                &msg.identifier.to_string(),
                &new_attestation.npoi,
                &msg.network,
                &msg.block_number.to_string(),
            ]);
            npoi_gauge.set(new_attestation.stake_weight.to_f64().unwrap());

            // Update AGGREGATE_ATTESTING_STAKE_INDEXER_GROUP metric
            let indexer_group_gauge = AGGREGATE_ATTESTING_STAKE_INDEXER_GROUP.with_label_values(&[
                &msg.identifier.to_string(),
                &indexer_address,
                &msg.network,
                &msg.block_number.to_string(),
            ]);
            indexer_group_gauge.set(new_attestation.stake_weight.to_f64().unwrap());
        }
    }
    Ok(remote_attestations)
}

/// Determine the comparison pointer on both block and time based on the local attestations
/// If they don't exist, then return default value that shall never be validated to trigger
pub async fn local_comparison_point(
    local_attestations: Arc<AsyncMutex<LocalAttestationsMap>>,
    id: String,
    collect_window_duration: i64,
) -> (u64, i64) {
    let local_attestation = local_attestations.lock().await;
    if let Some(blocks_map) = local_attestation.get(&id) {
        // Find the attestaion by the smallest block
        blocks_map
            .iter()
            .min_by_key(|(&min_block, attestation)| {
                // unwrap is okay because we add timestamp at local creation of attestation
                (min_block, *attestation.timestamp.first().unwrap())
            })
            .map(|(&block, a)| {
                (
                    block,
                    *a.timestamp.first().unwrap() + collect_window_duration,
                )
            })
            .unwrap_or((0_u64, i64::MAX))
    } else {
        (0_u64, i64::MAX)
    }
}

/// Updates the `blocks` HashMap to include the new attestation.
pub fn update_blocks(
    block_number: u64,
    blocks: &HashMap<u64, Vec<Attestation>>,
    npoi: String,
    stake: BigUint,
    address: String,
    timestamp: i64,
) -> HashMap<u64, Vec<Attestation>> {
    let mut blocks_clone: HashMap<u64, Vec<Attestation>> = HashMap::new();
    blocks_clone.extend(blocks.clone());
    blocks_clone.insert(
        block_number,
        vec![Attestation::new(
            npoi,
            stake,
            vec![address],
            vec![timestamp],
        )],
    );
    blocks_clone
}

/// Saves NPOIs that we've generated locally, in order to compare them with remote ones later
pub fn save_local_attestation(
    local_attestations: &mut LocalAttestationsMap,
    attestation: Attestation,
    ipfs_hash: String,
    block_number: u64,
) {
    let blocks = local_attestations.get(&ipfs_hash);

    match blocks {
        Some(blocks) => {
            let mut blocks_clone: HashMap<u64, Attestation> = HashMap::new();
            blocks_clone.extend(blocks.clone());
            blocks_clone.insert(block_number, attestation);
            local_attestations.insert(ipfs_hash, blocks_clone);
        }
        None => {
            let mut blocks_clone: HashMap<u64, Attestation> = HashMap::new();
            blocks_clone.insert(block_number, attestation);
            local_attestations.insert(ipfs_hash, blocks_clone);
        }
    }
}

/// Clear the expired local attesatoins
pub fn clear_local_attestation(
    local_attestations: &mut LocalAttestationsMap,
    ipfs_hash: String,
    block_number: u64,
) {
    let blocks = local_attestations.get(&ipfs_hash);

    if let Some(blocks) = blocks {
        let mut blocks_clone: HashMap<u64, Attestation> = HashMap::new();
        blocks_clone.extend(blocks.clone());
        blocks_clone.remove(&block_number);
        local_attestations.insert(ipfs_hash, blocks_clone);
    }
}

#[derive(Debug, PartialEq, Eq, Hash)]
pub enum ComparisonResult {
    NotFound(String),
    Divergent(String),
    Match(String),
}

impl Display for ComparisonResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ComparisonResult::NotFound(s) => write!(f, "NotFound: {s}"),
            ComparisonResult::Divergent(s) => write!(f, "Divergent: {s}"),
            ComparisonResult::Match(s) => write!(f, "Matched: {s}"),
        }
    }
}

/// Compares local attestations against remote ones using the attestation stores we populated while processing saved GraphcastMessage messages.
/// It takes our attestation (NPOI) for a given subgraph on a given block and compares it to the top-attested one from the remote attestations.
/// The top remote attestation is found by grouping attestations together and increasing their total stake-weight every time we see a new message
/// with the same NPOI from an Indexer (NOTE: one Indexer can only send 1 attestation per subgraph per block). The attestations are then sorted
/// and we take the one with the highest total stake-weight.
pub async fn compare_attestations(
    network_name: NetworkName,
    attestation_block: u64,
    remote: RemoteAttestationsMap,
    local: Arc<AsyncMutex<LocalAttestationsMap>>,
    ipfs_hash: &str,
) -> Result<ComparisonResult, anyhow::Error> {
    debug!(
        "Comparing attestations:\nlocal: {:#?}\n remote: {:#?}",
        local, remote
    );

    let local = local.lock().await;

    let blocks = match local.get(ipfs_hash) {
        Some(blocks) => blocks,
        None => {
            return Ok(ComparisonResult::NotFound(String::from(
                "No local attestation found",
            )))
        }
    };
    let local_attestation = match blocks.get(&attestation_block) {
        Some(attestations) => attestations,
        None => {
            return Ok(ComparisonResult::NotFound(format!(
                "No local attestation found for block {attestation_block}"
            )))
        }
    };

    let remote_blocks = match remote.get(ipfs_hash) {
        Some(blocks) => blocks,
        None => {
            return Ok(ComparisonResult::NotFound(format!(
                "No remote attestation found for subgraph {ipfs_hash}"
            )))
        }
    };
    let remote_attestations = match remote_blocks.get(&attestation_block) {
        Some(attestations) => attestations,
        None => {
            return Ok(ComparisonResult::NotFound(format!(
                "No remote attestation found for subgraph {ipfs_hash} on block {attestation_block}"
            )))
        }
    };

    let mut remote_attestations = remote_attestations.clone();
    remote_attestations.sort_by(|a, b| a.stake_weight.partial_cmp(&b.stake_weight).unwrap());

    let subgraph_gauge = ACTIVE_SUBGRAPHS.with_label_values(&[ipfs_hash]);

    let senders: Vec<String> = remote_attestations
        .clone()
        .into_iter()
        .flat_map(|attestation| attestation.senders)
        .collect();

    // The value is the total number of senders that are attesting for that subgraph
    subgraph_gauge.set(senders.len().try_into().unwrap());

    if remote_attestations.len() > 1 {
        warn!(
            "More than 1 nPOI found for subgraph {} on block {}. Attestations (sorted): {:#?}",
            ipfs_hash, attestation_block, remote_attestations
        );
    }

    let diverging_subgraph_gauge = DIVERGING_SUBGRAPHS.with_label_values(&[
        ipfs_hash,
        &attestation_block.to_string(),
        &network_name.to_string(),
    ]);

    let most_attested_npoi = &remote_attestations.last().unwrap().npoi;
    if most_attested_npoi == &local_attestation.npoi {
        info!(
            "nPOI matched for subgraph {} on block {} with {} of remote attestations",
            ipfs_hash,
            attestation_block,
            remote_attestations.len(),
        );
        Ok(ComparisonResult::Match(format!(
            "POIs match for subgraph {ipfs_hash} on block {attestation_block}!: {most_attested_npoi}"
        )))
    } else {
        diverging_subgraph_gauge.set(1);
        info!(
            "Number of nPOI submitted for block {}: {:#?}\n{}: {:#?}",
            attestation_block, remote_attestations, "Local attestation", local_attestation
        );
        Ok(ComparisonResult::Divergent(format!(
            "❗ POIs don't match for subgraph {ipfs_hash} on network {network_name} at block {attestation_block}!\n\nLocal attestation:\n{local_attestation:#?}\n\nRemote attestations:\n{remote_attestations:#?}"
        )))
    }
}

/// Deterministically sort addresses
fn sort_addresses(addresses: &mut [String]) {
    addresses.sort_by(|a, b| {
        let bytes_a = hex::decode(&a[2..]).unwrap();
        let bytes_b = hex::decode(&b[2..]).unwrap();
        bytes_a.cmp(&bytes_b)
    });
}

/// Deterministically ordering the indexer addresses attesting to a nPOI, and then hashing that list
fn hash_addresses(addresses: &[String]) -> String {
    // create a SHA3-256 object
    let mut hasher = Sha3_256::new();
    // iteratively decode addresses to bytes
    let mut bytes = Vec::new();
    for address in addresses {
        let addr = address[2..].to_string();
        bytes.extend(hex::decode(addr).unwrap());
    }

    // write input message
    hasher.update(&bytes);
    // read hash digest
    let result = hasher.finalize();
    hex::encode(result)
}

#[derive(Debug, thiserror::Error)]
pub enum AttestationError {
    #[error("Failed to build attestation: {0}")]
    BuildError(BuildMessageError),
    #[error("Failed to update attestation: {0}")]
    UpdateError(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_traits::One;

    #[test]
    fn test_update_blocks() {
        let mut blocks: HashMap<u64, Vec<Attestation>> = HashMap::new();
        blocks.insert(
            42,
            vec![Attestation::new(
                "default".to_string(),
                BigUint::default(),
                Vec::new(),
                Vec::new(),
            )],
        );
        let block_clone = update_blocks(
            42,
            &blocks,
            "awesome-npoi".to_string(),
            BigUint::default(),
            "0xadd3".to_string(),
            1,
        );

        assert_eq!(
            block_clone.get(&42).unwrap().first().unwrap().npoi,
            "awesome-npoi".to_string()
        );
    }

    #[test]
    fn test_sort_sender_addresses_unique() {
        let attestation = Attestation::new(
            "awesome-npoi".to_string(),
            BigUint::one(),
            vec!["0xaac5349585cbbf924026d25a520ffa9e8b51a39b".to_string()],
            vec![1],
        );
        let attestation2 = Attestation::new(
            "awesome-npoi".to_string(),
            BigUint::one(),
            vec!["0xbbc5349585cbbf924026d25a520ffa9e8b51a39b".to_string()],
            vec![1],
        );
        assert_ne!(
            attestation2.sender_group_hash,
            attestation.sender_group_hash
        );
    }

    #[test]
    fn test_sort_sender_addresses() {
        let attestation = Attestation::new(
            "awesome-npoi".to_string(),
            BigUint::one(),
            vec![
                "0xaac5349585cbbf924026d25a520ffa9e8b51a39b".to_string(),
                "0xbbc5349585cbbf924026d25a520ffa9e8b51a39b".to_string(),
            ],
            vec![1, 2],
        );
        let attestation2 = Attestation::new(
            "awesome-npoi".to_string(),
            BigUint::one(),
            vec![
                "0xbbc5349585cbbf924026d25a520ffa9e8b51a39b".to_string(),
                "0xaac5349585cbbf924026d25a520ffa9e8b51a39b".to_string(),
            ],
            vec![1, 2],
        );
        assert_eq!(
            attestation2.sender_group_hash,
            attestation.sender_group_hash
        );
    }

    #[test]
    fn test_attestation_sorting() {
        let attestation1 = Attestation::new(
            "awesome-npoi".to_string(),
            BigUint::default(),
            vec!["0xa1".to_string()],
            vec![0],
        );

        let attestation2 = Attestation::new(
            "awesome-npoi".to_string(),
            BigUint::default(),
            vec!["0xa2".to_string()],
            vec![1],
        );

        let attestation3 = Attestation::new(
            "awesome-npoi".to_string(),
            BigUint::one(),
            vec!["0xa3".to_string()],
            vec![2],
        );

        let mut attestations = vec![attestation1, attestation2, attestation3];

        attestations.sort_by(|a, b| a.stake_weight.partial_cmp(&b.stake_weight).unwrap());

        assert_eq!(attestations.last().unwrap().stake_weight, BigUint::one());
        assert_eq!(
            attestations.last().unwrap().senders.first().unwrap(),
            &"0xa3".to_string()
        );
        assert_eq!(attestations.last().unwrap().timestamp, vec![2]);
    }

    #[test]
    fn test_attestation_update_success() {
        let attestation = Attestation::new(
            "awesome-npoi".to_string(),
            BigUint::default(),
            vec!["0xa1".to_string()],
            vec![2],
        );

        let updated_attestation =
            Attestation::update(&attestation, "0xa2".to_string(), BigUint::one(), 1);

        assert!(updated_attestation.is_ok());
        assert_eq!(
            updated_attestation.as_ref().unwrap().stake_weight,
            BigUint::one()
        );
        assert_eq!(updated_attestation.unwrap().timestamp, [2, 1]);
    }

    #[test]
    fn test_attestation_update_fail() {
        let attestation = Attestation::new(
            "awesome-npoi".to_string(),
            BigUint::default(),
            vec!["0xa1".to_string()],
            vec![0],
        );

        let updated_attestation =
            Attestation::update(&attestation, "0xa1".to_string(), BigUint::default(), 0);

        assert!(updated_attestation.is_err());
    }

    #[tokio::test]
    async fn test_compare_attestations_generic_fail() {
        let res = compare_attestations(
            NetworkName::Goerli,
            42,
            HashMap::new(),
            Arc::new(AsyncMutex::new(HashMap::new())),
            "non-existent-ipfs-hash",
        )
        .await;

        assert!(res.is_ok());
        assert_eq!(
            res.unwrap().to_string(),
            "NotFound: No local attestation found".to_string()
        );
    }

    #[tokio::test]
    async fn test_compare_attestations_remote_not_found_fail() {
        let mut remote_blocks: HashMap<u64, Vec<Attestation>> = HashMap::new();
        let mut local_blocks: HashMap<u64, Attestation> = HashMap::new();

        remote_blocks.insert(
            42,
            vec![Attestation::new(
                "awesome-npoi".to_string(),
                BigUint::default(),
                vec!["0xa1".to_string()],
                vec![1],
            )],
        );

        local_blocks.insert(
            42,
            Attestation::new(
                "awesome-npoi".to_string(),
                BigUint::default(),
                Vec::new(),
                vec![0],
            ),
        );

        let mut remote_attestations: HashMap<String, HashMap<u64, Vec<Attestation>>> =
            HashMap::new();
        let mut local_attestations: HashMap<String, HashMap<u64, Attestation>> = HashMap::new();

        remote_attestations.insert("my-awesome-hash".to_string(), remote_blocks);
        local_attestations.insert("different-awesome-hash".to_string(), local_blocks);

        let res = compare_attestations(
            NetworkName::Goerli,
            42,
            remote_attestations,
            Arc::new(AsyncMutex::new(local_attestations)),
            "different-awesome-hash",
        )
        .await;

        assert!(res.is_ok());
        assert_eq!(
            res.unwrap().to_string(),
            "NotFound: No remote attestation found for subgraph different-awesome-hash".to_string()
        );
    }

    #[tokio::test]
    async fn test_compare_attestations_local_not_found_fail() {
        let remote_blocks: HashMap<u64, Vec<Attestation>> = HashMap::new();
        let local_blocks: HashMap<u64, Attestation> = HashMap::new();

        let mut remote_attestations: HashMap<String, HashMap<u64, Vec<Attestation>>> =
            HashMap::new();
        let mut local_attestations: HashMap<String, HashMap<u64, Attestation>> = HashMap::new();

        remote_attestations.insert("my-awesome-hash".to_string(), remote_blocks);
        local_attestations.insert("my-awesome-hash".to_string(), local_blocks);

        let res = compare_attestations(
            NetworkName::Goerli,
            42,
            remote_attestations,
            Arc::new(AsyncMutex::new(local_attestations)),
            "my-awesome-hash",
        )
        .await;

        assert!(res.is_ok());
        assert_eq!(
            res.unwrap().to_string(),
            "NotFound: No local attestation found for block 42".to_string()
        );
    }

    #[tokio::test]
    async fn test_compare_attestations_success() {
        let mut remote_blocks: HashMap<u64, Vec<Attestation>> = HashMap::new();
        let mut local_blocks: HashMap<u64, Attestation> = HashMap::new();

        remote_blocks.insert(
            42,
            vec![Attestation::new(
                "awesome-npoi".to_string(),
                BigUint::default(),
                vec!["0xa1".to_string()],
                vec![0],
            )],
        );

        local_blocks.insert(
            42,
            Attestation::new(
                "awesome-npoi".to_string(),
                BigUint::default(),
                Vec::new(),
                vec![0],
            ),
        );

        let mut remote_attestations: HashMap<String, HashMap<u64, Vec<Attestation>>> =
            HashMap::new();
        let mut local_attestations: HashMap<String, HashMap<u64, Attestation>> = HashMap::new();

        remote_attestations.insert("my-awesome-hash".to_string(), remote_blocks);
        local_attestations.insert("my-awesome-hash".to_string(), local_blocks);

        let res = compare_attestations(
            NetworkName::Goerli,
            42,
            remote_attestations,
            Arc::new(AsyncMutex::new(local_attestations)),
            "my-awesome-hash",
        )
        .await;

        assert!(res.is_ok());
        assert_eq!(
            res.unwrap(),
            ComparisonResult::Match(
                "POIs match for subgraph my-awesome-hash on block 42!: awesome-npoi".to_string()
            )
        );
    }

    #[test]
    fn clear_local_attestation_success() {
        let mut local_blocks: HashMap<u64, Attestation> = HashMap::new();
        let attestation1 = Attestation::new(
            "awesome-npoi".to_string(),
            BigUint::default(),
            vec!["0xa1".to_string()],
            vec![0],
        );

        let attestation2 = Attestation::new(
            "awesome-npoi".to_string(),
            BigUint::default(),
            vec!["0xa2".to_string()],
            vec![1],
        );

        let attestation3 = Attestation::new(
            "awesome-npoi".to_string(),
            BigUint::one(),
            vec!["0xa3".to_string()],
            vec![2],
        );

        local_blocks.insert(42, attestation1);
        local_blocks.insert(43, attestation2);
        local_blocks.insert(44, attestation3);

        let mut local_attestations: HashMap<String, HashMap<u64, Attestation>> = HashMap::new();
        local_attestations.insert("hash".to_string(), local_blocks.clone());
        local_attestations.insert("hash2".to_string(), local_blocks);

        clear_local_attestation(&mut local_attestations, "hash".to_string(), 43);

        assert_eq!(local_attestations.get("hash").unwrap().len(), 2);
        assert!(local_attestations.get("hash").unwrap().get(&43).is_none());
        assert_eq!(local_attestations.get("hash2").unwrap().len(), 3);
    }

    #[tokio::test]
    async fn local_attestation_pointer_success() {
        let mut local_blocks: HashMap<u64, Attestation> = HashMap::new();
        let attestation1 = Attestation::new(
            "awesome-npoi".to_string(),
            BigUint::default(),
            vec!["0xa1".to_string()],
            vec![2],
        );

        let attestation2 = Attestation::new(
            "awesome-npoi".to_string(),
            BigUint::default(),
            vec!["0xa2".to_string()],
            vec![4],
        );

        let attestation3 = Attestation::new(
            "awesome-npoi".to_string(),
            BigUint::one(),
            vec!["0xa3".to_string()],
            vec![6],
        );

        local_blocks.insert(42, attestation1);
        local_blocks.insert(43, attestation2);
        local_blocks.insert(44, attestation3);

        let mut local_attestations: HashMap<String, HashMap<u64, Attestation>> = HashMap::new();
        local_attestations.insert("hash".to_string(), local_blocks.clone());
        local_attestations.insert("hash2".to_string(), local_blocks);
        let local = Arc::new(AsyncMutex::new(local_attestations));
        let (block_num, collect_window_end) =
            local_comparison_point(Arc::clone(&local), "hash".to_string(), 120).await;

        assert_eq!(block_num, 42);
        assert_eq!(collect_window_end, 122);
    }
}
