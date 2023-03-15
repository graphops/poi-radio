use anyhow::anyhow;
use ethers_contract::EthAbiType;
use ethers_core::types::transaction::eip712::Eip712;
use ethers_derive_eip712::*;
use num_bigint::BigUint;
use once_cell::sync::OnceCell;
use prost::Message;

use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fmt::{self, Display},
    sync::{Arc, Mutex as SyncMutex},
};
use tokio::sync::Mutex as AsyncMutex;
use tracing::{debug, error, info, warn};

use graphcast_sdk::{
    config::NetworkName,
    graphcast_agent::{
        message_typing::{get_indexer_stake, GraphcastMessage},
        waku_handling::WakuHandlingError,
        GraphcastAgent,
    },
    graphql::{client_network::query_network_subgraph, client_registry::query_registry_indexer},
    BlockPointer,
};

#[derive(Eip712, EthAbiType, Clone, Message, Serialize, Deserialize)]
#[eip712(
    name = "Graphcast POI Radio",
    version = "0",
    chain_id = 1,
    verifying_contract = "0xc944e90c64b2c07662a292be6244bdf05cda44a7"
)]
pub struct RadioPayloadMessage {
    #[prost(string, tag = "1")]
    pub identifier: String,
    #[prost(string, tag = "2")]
    pub content: String,
}

impl RadioPayloadMessage {
    pub fn new(identifier: String, content: String) -> Self {
        RadioPayloadMessage {
            identifier,
            content,
        }
    }

    pub fn payload_content(&self) -> String {
        self.content.clone()
    }
}

pub type RemoteAttestationsMap = HashMap<String, HashMap<u64, Vec<Attestation>>>;
pub type LocalAttestationsMap = HashMap<String, HashMap<u64, Attestation>>;

/// A global static (singleton) instance of GraphcastAgent. It is useful to ensure that we have only one GraphcastAgent
/// per Radio instance, so that we can keep track of state and more easily test our Radio application.
pub static GRAPHCAST_AGENT: OnceCell<GraphcastAgent> = OnceCell::new();

/// A global static (singleton) instance of A GraphcastMessage vector.
/// It is used to save incoming messages after they've been validated, in order
/// defer their processing for later, because async code is required for the processing but
/// it is not allowed in the handler itself.
pub static MESSAGES: OnceCell<Arc<SyncMutex<Vec<GraphcastMessage<RadioPayloadMessage>>>>> =
    OnceCell::new();

/// Updates the `blocks` HashMap to include the new attestation.
pub fn update_blocks(
    block_number: u64,
    blocks: &HashMap<u64, Vec<Attestation>>,
    npoi: String,
    stake: BigUint,
    address: String,
) -> HashMap<u64, Vec<Attestation>> {
    let mut blocks_clone: HashMap<u64, Vec<Attestation>> = HashMap::new();
    blocks_clone.extend(blocks.clone());
    blocks_clone.insert(
        block_number,
        vec![Attestation::new(npoi, stake, vec![address])],
    );
    blocks_clone
}

/// Generate default topics that is operator address resolved to indexer address
/// and then its active on-chain allocations -> function signature should just return
/// A vec of strings for subtopics
pub async fn active_allocation_hashes(
    network_subgraph: &str,
    indexer_address: String,
) -> Vec<String> {
    query_network_subgraph(network_subgraph.to_string(), indexer_address)
        .await
        .map_err(|e| -> Vec<String> {
            error!("Topic generation error: {}", e);
            [].to_vec()
        })
        .unwrap()
        .indexer_allocations()
}

/// Generate default topics along with given static topics
pub async fn generate_topics(
    network_subgraph: String,
    indexer_address: String,
    static_topics: &Vec<String>,
) -> Vec<String> {
    let mut topics = active_allocation_hashes(&network_subgraph, indexer_address).await;
    for topic in static_topics {
        if !topics.contains(topic) {
            topics.push(topic.clone());
        }
    }
    topics
}

/// This function processes the global messages map that we populate when
/// messages are being received. It constructs the remote attestations
/// map and returns it if the processing succeeds.
pub async fn process_messages(
    messages: Arc<AsyncMutex<Vec<GraphcastMessage<RadioPayloadMessage>>>>,
    registry_subgraph: &str,
    network_subgraph: &str,
) -> Result<RemoteAttestationsMap, anyhow::Error> {
    let mut remote_attestations: RemoteAttestationsMap = HashMap::new();
    let messages = AsyncMutex::new(messages.lock().await);

    for msg in messages.lock().await.iter() {
        let radio_msg = &msg.payload.clone().unwrap();
        let sender = msg.recover_sender_address()?;
        let indexer_address =
            query_registry_indexer(registry_subgraph.to_string(), sender.clone()).await?;
        let sender_stake = get_indexer_stake(indexer_address.clone(), network_subgraph).await?;

        // Check if there are existing attestations for the block
        let blocks = remote_attestations
            .entry(msg.identifier.to_string())
            .or_default();
        let attestations = blocks.entry(msg.block_number).or_default();

        let existing_attestation = attestations
            .iter_mut()
            .find(|a| a.npoi == radio_msg.payload_content());

        match existing_attestation {
            Some(existing_attestation) => {
                existing_attestation.stake_weight += sender_stake;
                if !existing_attestation
                    .senders
                    .contains(&indexer_address.clone())
                {
                    existing_attestation.senders.push(indexer_address.clone());
                }
            }
            None => {
                attestations.push(Attestation::new(
                    radio_msg.payload_content().to_string(),
                    sender_stake,
                    vec![indexer_address],
                ));
            }
        }
    }
    Ok(remote_attestations)
}

/// A wrapper around an attested NPOI, tracks Indexers that have sent it plus their accumulated stake
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Attestation {
    pub npoi: String,
    pub stake_weight: BigUint,
    pub senders: Vec<String>,
}

impl Attestation {
    pub fn new(npoi: String, stake_weight: BigUint, senders: Vec<String>) -> Self {
        Attestation {
            npoi,
            stake_weight,
            senders,
        }
    }

    /// Used whenever we receive a new attestation for an NPOI that already exists in the store
    pub fn update(base: &Self, address: String, stake: BigUint) -> Result<Self, anyhow::Error> {
        if base.senders.contains(&address) {
            Err(anyhow!(
                "{}",
                "There is already an attestation from this address. Skipping...".to_string()
            ))
        } else {
            let senders = [base.senders.clone(), vec![address]].concat();
            Ok(Self::new(
                base.npoi.clone(),
                base.stake_weight.clone() + stake,
                senders,
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

/// Custom callback for handling the validated GraphcastMessage, in this case we only save the messages to a local store
/// to process them at a later time. This is required because for the processing we use async operations which are not allowed
/// in the handler.
pub fn attestation_handler(
) -> impl Fn(Result<GraphcastMessage<RadioPayloadMessage>, WakuHandlingError>) {
    |msg: Result<GraphcastMessage<RadioPayloadMessage>, WakuHandlingError>| {
        // TODO: Handle the error case by incrementing a Prometheus "error" counter
        if let Ok(msg) = msg {
            debug!("Received message: {:?}", msg);
            MESSAGES.get().unwrap().lock().unwrap().push(msg);
        }
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
    attestation_block: u64,
    remote: RemoteAttestationsMap,
    local: Arc<AsyncMutex<LocalAttestationsMap>>,
) -> Result<ComparisonResult, anyhow::Error> {
    debug!(
        "Comparing attestations:\nlocal: {:#?}\n remote: {:#?}",
        local, remote
    );

    let local = local.lock().await;
    let (ipfs_hash, blocks) = match local.iter().next() {
        Some(pair) => pair,
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

    if remote_attestations.len() > 1 {
        warn!(
            "More than 1 nPOI found for subgraph {} on block {}. Attestations (sorted): {:#?}",
            ipfs_hash, attestation_block, remote_attestations
        );
    }

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
        info!(
            "Number of nPOI submitted for block {}: {:#?}\n{}: {:#?}",
            attestation_block, remote_attestations, "Local attestation", local_attestation
        );
        Ok(ComparisonResult::Divergent(format!(
            "POIs don't match for subgraph {ipfs_hash} on block {attestation_block}!\nlocal attestation: {local:#?}\nremote attestations: {remote:#?}"
        )))
    }
}

pub fn chainhead_block_str(
    network_chainhead_blocks: &HashMap<NetworkName, BlockPointer>,
) -> String {
    let mut blocks_str = String::new();
    blocks_str.push_str("{ ");
    for (i, (network, block_pointer)) in network_chainhead_blocks.iter().enumerate() {
        if i > 0 {
            blocks_str.push_str(", ");
        }
        blocks_str.push_str(&format!("{}: {}", network, block_pointer.number));
    }
    blocks_str.push_str(" }");
    blocks_str
}

#[cfg(test)]
mod tests {
    use graphcast_sdk::config::NetworkName;
    use num_traits::One;

    use super::*;

    const NETWORK: NetworkName = NetworkName::Goerli;

    #[test]
    fn test_basic_global_map() {
        _ = MESSAGES.set(Arc::new(SyncMutex::new(Vec::new())));
        let mut messages = MESSAGES.get().unwrap().lock().unwrap();

        let hash: String = "QmWECgZdP2YMcV9RtKU41GxcdW8EGYqMNoG98ubu5RGN6U".to_string();
        let content: String =
            "0xa6008cea5905b8b7811a68132feea7959b623188e2d6ee3c87ead7ae56dd0eae".to_string();
        let nonce: i64 = 123321;
        let block_number: u64 = 0;
        let block_hash: String = "0xblahh".to_string();

        let radio_msg = RadioPayloadMessage::new(hash.clone(), content);
        let sig: String = "4be6a6b7f27c4086f22e8be364cbdaeddc19c1992a42b08cbe506196b0aafb0a68c8c48a730b0e3155f4388d7cc84a24b193d091c4a6a4e8cd6f1b305870fae61b".to_string();
        let msg = GraphcastMessage::new(
            hash,
            Some(radio_msg),
            nonce,
            NETWORK,
            block_number,
            block_hash,
            sig,
        )
        .expect("Shouldn't get here since the message is purposefully constructed for testing");

        assert!(messages.is_empty());

        messages.push(msg);
        assert_eq!(
            messages.first().unwrap().identifier,
            "QmWECgZdP2YMcV9RtKU41GxcdW8EGYqMNoG98ubu5RGN6U".to_string()
        );
    }

    #[test]
    fn test_update_blocks() {
        let mut blocks: HashMap<u64, Vec<Attestation>> = HashMap::new();
        blocks.insert(
            42,
            vec![Attestation::new(
                "default".to_string(),
                BigUint::default(),
                Vec::new(),
            )],
        );
        let block_clone = update_blocks(
            42,
            &blocks,
            "awesome-npoi".to_string(),
            BigUint::default(),
            "address".to_string(),
        );

        assert_eq!(
            block_clone.get(&42).unwrap().first().unwrap().npoi,
            "awesome-npoi".to_string()
        );
    }

    #[test]
    fn test_delete_messages() {
        _ = MESSAGES.set(Arc::new(SyncMutex::new(Vec::new())));

        let mut messages = MESSAGES.get().unwrap().lock().unwrap();

        let hash: String = "QmWECgZdP2YMcV9RtKU41GxcdW8EGYqMNoG98ubu5RGN6U".to_string();
        let content: String =
            "0xa6008cea5905b8b7811a68132feea7959b623188e2d6ee3c87ead7ae56dd0eae".to_string();
        let nonce: i64 = 123321;
        let block_number: u64 = 0;
        let block_hash: String = "0xblahh".to_string();
        let radio_msg = RadioPayloadMessage::new(hash.clone(), content);
        let sig: String = "4be6a6b7f27c4086f22e8be364cbdaeddc19c1992a42b08cbe506196b0aafb0a68c8c48a730b0e3155f4388d7cc84a24b193d091c4a6a4e8cd6f1b305870fae61b".to_string();
        let msg = GraphcastMessage::new(
            hash,
            Some(radio_msg),
            nonce,
            NETWORK,
            block_number,
            block_hash,
            sig,
        )
        .expect("Shouldn't get here since the message is purposefully constructed for testing");

        messages.push(msg);
        assert!(!messages.is_empty());

        messages.clear();
        assert!(messages.is_empty());
    }

    #[test]
    fn test_attestation_sorting() {
        let attestation1 = Attestation::new(
            "awesome-npoi".to_string(),
            BigUint::default(),
            vec!["i-am-groot1".to_string()],
        );

        let attestation2 = Attestation::new(
            "awesome-npoi".to_string(),
            BigUint::default(),
            vec!["i-am-groot2".to_string()],
        );

        let attestation3 = Attestation::new(
            "awesome-npoi".to_string(),
            BigUint::one(),
            vec!["i-am-groot3".to_string()],
        );

        let mut attestations = vec![attestation1, attestation2, attestation3];

        attestations.sort_by(|a, b| a.stake_weight.partial_cmp(&b.stake_weight).unwrap());

        assert_eq!(attestations.last().unwrap().stake_weight, BigUint::one());
        assert_eq!(
            attestations.last().unwrap().senders.first().unwrap(),
            &"i-am-groot3".to_string()
        );
    }

    #[test]
    fn test_attestation_update_success() {
        let attestation = Attestation::new(
            "awesome-npoi".to_string(),
            BigUint::default(),
            vec!["i-am-groot".to_string()],
        );

        let updated_attestation =
            Attestation::update(&attestation, "soggip".to_string(), BigUint::one());

        assert!(updated_attestation.is_ok());
        assert_eq!(updated_attestation.unwrap().stake_weight, BigUint::one());
    }

    #[test]
    fn test_attestation_update_fail() {
        let attestation = Attestation::new(
            "awesome-npoi".to_string(),
            BigUint::default(),
            vec!["i-am-groot".to_string()],
        );

        let updated_attestation =
            Attestation::update(&attestation, "i-am-groot".to_string(), BigUint::default());

        assert!(updated_attestation.is_err());
        assert_eq!(
            updated_attestation.unwrap_err().to_string(),
            "There is already an attestation from this address. Skipping...".to_string()
        );
    }

    #[tokio::test]
    async fn test_compare_attestations_generic_fail() {
        let res = compare_attestations(
            42,
            HashMap::new(),
            Arc::new(AsyncMutex::new(HashMap::new())),
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
                vec!["i-am-groot".to_string()],
            )],
        );

        local_blocks.insert(
            42,
            Attestation::new("awesome-npoi".to_string(), BigUint::default(), Vec::new()),
        );

        let mut remote_attestations: HashMap<String, HashMap<u64, Vec<Attestation>>> =
            HashMap::new();
        let mut local_attestations: HashMap<String, HashMap<u64, Attestation>> = HashMap::new();

        remote_attestations.insert("my-awesome-hash".to_string(), remote_blocks);
        local_attestations.insert("different-awesome-hash".to_string(), local_blocks);

        let res = compare_attestations(
            42,
            remote_attestations,
            Arc::new(AsyncMutex::new(local_attestations)),
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
            42,
            remote_attestations,
            Arc::new(AsyncMutex::new(local_attestations)),
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
                vec!["i-am-groot".to_string()],
            )],
        );

        local_blocks.insert(
            42,
            Attestation::new("awesome-npoi".to_string(), BigUint::default(), Vec::new()),
        );

        let mut remote_attestations: HashMap<String, HashMap<u64, Vec<Attestation>>> =
            HashMap::new();
        let mut local_attestations: HashMap<String, HashMap<u64, Attestation>> = HashMap::new();

        remote_attestations.insert("my-awesome-hash".to_string(), remote_blocks);
        local_attestations.insert("my-awesome-hash".to_string(), local_blocks);

        let res = compare_attestations(
            42,
            remote_attestations,
            Arc::new(AsyncMutex::new(local_attestations)),
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
}
