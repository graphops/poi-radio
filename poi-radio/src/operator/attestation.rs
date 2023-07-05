use async_graphql::{Enum, Error, ErrorExtensions, SimpleObject};
use autometrics::autometrics;
use chrono::Utc;
use num_traits::Zero;
use serde_derive::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::{
    collections::HashMap,
    fmt::{self, Display},
    sync::{Arc, Mutex as SyncMutex},
};

use tracing::{debug, error, info, trace, warn};

use graphcast_sdk::graphcast_agent::message_typing::{
    get_indexer_stake, BuildMessageError, GraphcastMessage,
};

use crate::{
    metrics::{
        ACTIVE_INDEXERS, DIVERGING_SUBGRAPHS, INDEXER_COUNT_BY_NPOI, LOCAL_NPOIS_TO_COMPARE,
    },
    state::PersistedState,
    OperationError, RadioPayloadMessage,
};

use super::Notifier;

/// A wrapper around an attested NPOI, tracks Indexers that have sent it plus their accumulated stake
#[derive(Clone, Debug, PartialEq, Eq, Hash, SimpleObject, Serialize, Deserialize)]
pub struct Attestation {
    pub npoi: String,
    pub stake_weight: i64,
    pub senders: Vec<String>,
    pub sender_group_hash: String,
    pub timestamp: Vec<i64>,
}

#[autometrics]
impl Attestation {
    pub fn new(npoi: String, stake_weight: f32, senders: Vec<String>, timestamp: Vec<i64>) -> Self {
        let addresses = &mut senders.clone();
        sort_addresses(addresses);
        let sender_group_hash = hash_addresses(addresses);
        Attestation {
            npoi,
            stake_weight: stake_weight as i64,
            senders,
            sender_group_hash,
            timestamp,
        }
    }

    /// Used whenever we receive a new attestation for an NPOI that already exists in the store
    pub fn update(
        base: &Self,
        address: String,
        stake: f32,
        timestamp: i64,
    ) -> Result<Self, AttestationError> {
        if base.senders.contains(&address) {
            Err(AttestationError::UpdateError(
                "There is already an attestation from this address. Skipping...".to_string(),
            ))
        } else {
            Ok(Self::new(
                base.npoi.clone(),
                (base.stake_weight as f32) + stake,
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

pub type RemoteAttestationsMap = HashMap<String, HashMap<u64, Vec<Attestation>>>;
pub type LocalAttestationsMap = HashMap<String, HashMap<u64, Attestation>>;

#[derive(SimpleObject, Debug)]
pub struct AttestationEntry {
    pub deployment: String,
    pub block_number: u64,
    pub attestation: Attestation,
}

pub fn attestations_to_vec(attestations: &LocalAttestationsMap) -> Vec<AttestationEntry> {
    attestations
        .iter()
        .flat_map(|(npoi, inner_map)| {
            inner_map.iter().map(move |(blk, att)| AttestationEntry {
                deployment: npoi.clone(),
                block_number: *blk,
                attestation: att.clone(),
            })
        })
        .collect()
}

#[autometrics]
pub async fn process_messages(
    messages: Vec<GraphcastMessage<RadioPayloadMessage>>,
    network_subgraph: &str,
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
        let sender_stake = get_indexer_stake(&msg.graph_account, network_subgraph)
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
                msg.graph_account.clone(),
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
                vec![msg.graph_account.clone()],
                vec![msg.nonce],
            ));
        }
    }

    // update once at the end
    // active peers for each deployment
    debug!(
        num_msgs = messages.len(),
        num_attestation = remote_attestations.len(),
        "Process message into attestations",
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

pub fn combine_senders(attestations: &[Attestation]) -> Vec<String> {
    <&[Attestation]>::clone(&attestations)
        .iter()
        .flat_map(|attestation| attestation.senders.clone())
        .collect()
}

/// Determine the comparison pointer on both block and time based on the local attestations
/// If they don't exist, then return default value that shall never be validated to trigger
pub fn local_comparison_point(
    local_attestations: &LocalAttestationsMap,
    id: String,
    collect_window_duration: i64,
) -> Option<(u64, i64)> {
    if let Some(blocks_map) = local_attestations.get(&id) {
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
    } else {
        None
    }
}

/// Updates the `blocks` HashMap to include the new attestation.
pub fn update_blocks(
    block_number: u64,
    blocks: &HashMap<u64, Vec<Attestation>>,
    npoi: String,
    stake: f32,
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
    local_attestations: Arc<SyncMutex<LocalAttestationsMap>>,
    content: String,
    ipfs_hash: String,
    block_number: u64,
) {
    let attestation = Attestation::new(content, Zero::zero(), vec![], vec![Utc::now().timestamp()]);

    let mut local_attestations = local_attestations.lock().unwrap();

    local_attestations
        .entry(ipfs_hash.clone())
        .or_default()
        .entry(block_number)
        .and_modify(|existing_attestation| *existing_attestation = attestation.clone())
        .or_insert(attestation);

    let npoi_gauge = LOCAL_NPOIS_TO_COMPARE.with_label_values(&[&ipfs_hash]);

    // The value is the total number of senders that are attesting for that subgraph
    npoi_gauge.set(local_attestations.len().try_into().unwrap());
}

/// Clear the expired local attestations after comparing with remote results
pub fn clear_local_attestation(
    local_attestations: Arc<SyncMutex<HashMap<String, HashMap<u64, Attestation>>>>,
    ipfs_hash: String,
    block_number: u64,
) {
    let mut local_attestations = local_attestations.lock().unwrap();
    let blocks = local_attestations.get(&ipfs_hash);

    if let Some(blocks) = blocks {
        let mut blocks_clone: HashMap<u64, Attestation> = HashMap::new();
        blocks_clone.extend(blocks.clone());
        blocks_clone.remove(&block_number);
        let npoi_gauge = LOCAL_NPOIS_TO_COMPARE.with_label_values(&[&ipfs_hash]);
        // The value is the total number of senders that are attesting for that subgraph
        npoi_gauge.set(blocks_clone.len().try_into().unwrap());
        local_attestations.insert(ipfs_hash, blocks_clone);
    };
}

/// Tracks results indexed by deployment hash and block number
#[derive(Enum, Debug, PartialEq, Eq, Hash, Clone, Copy, Serialize, Deserialize)]
pub enum ComparisonResultType {
    NotFound,
    Divergent,
    Match,
    BuildFailed,
}

/// Keep track of the attestation result for a deployment and block
/// Can add block_hash and network fields for tracking if needed
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, SimpleObject)]
pub struct ComparisonResult {
    pub deployment: String,
    pub block_number: u64,
    pub result_type: ComparisonResultType,
    pub local_attestation: Option<Attestation>,
    pub attestations: Vec<Attestation>,
}

impl ComparisonResult {
    pub fn deployment_hash(&self) -> String {
        self.deployment.clone()
    }

    pub fn block(&self) -> u64 {
        self.block_number
    }
}

impl Display for ComparisonResultType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ComparisonResultType::NotFound => {
                write!(f, "NotFound")
            }
            ComparisonResultType::Divergent => {
                write!(f, "Divergent")
            }
            ComparisonResultType::Match => {
                write!(f, "Matched")
            }
            ComparisonResultType::BuildFailed => write!(f, "Failed to build message"),
        }
    }
}

impl Display for ComparisonResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.result_type {
            ComparisonResultType::NotFound => {
                if self.local_attestation.is_none() {
                    write!(
                        f,
                        "{} for local attestation: deployment {} at block {}",
                        self.result_type,
                        self.deployment_hash(),
                        self.block()
                    )
                } else {
                    write!(
                        f,
                        "{} for remote attestations: deployment {} at block {}",
                        self.result_type,
                        self.deployment_hash(),
                        self.block()
                    )
                }
            }
            ComparisonResultType::Divergent => {
                write!(
                    f,
                    "{}: deployment {} at block {}",
                    self.result_type,
                    self.deployment_hash(),
                    self.block()
                )
            }
            ComparisonResultType::Match => {
                write!(
                    f,
                    "{}: deployment {} at block {}",
                    self.result_type,
                    self.deployment_hash(),
                    self.block()
                )
            }
            ComparisonResultType::BuildFailed => write!(
                f,
                "{}: deployment {} at block {}",
                self.result_type,
                self.deployment_hash(),
                self.block()
            ),
        }
    }
}

impl Clone for ComparisonResult {
    fn clone(&self) -> Self {
        ComparisonResult {
            deployment: self.deployment_hash(),
            block_number: self.block(),
            result_type: self.result_type,
            local_attestation: self.local_attestation.clone(),
            attestations: self.attestations.clone(),
        }
    }
}

/// Compares local attestations against remote ones using the attestation stores we populated while processing saved GraphcastMessage messages.
/// It takes our attestation (NPOI) for a given subgraph on a given block and compares it to the top-attested one from the remote attestations.
/// The top remote attestation is found by grouping attestations together and increasing their total stake-weight every time we see a new message
/// with the same NPOI from an Indexer (NOTE: one Indexer can only send 1 attestation per subgraph per block). The attestations are then sorted
/// and we take the one with the highest total stake-weight.
pub fn compare_attestations(
    attestation_block: u64,
    remote: RemoteAttestationsMap,
    local: &LocalAttestationsMap,
    ipfs_hash: &str,
) -> ComparisonResult {
    trace!(
        local = tracing::field::debug(&local),
        remote = tracing::field::debug(&remote),
        "Comparing attestations",
    );

    // Filtering local and remote attestations
    let blocks = match local.get(ipfs_hash) {
        Some(blocks) => blocks,
        None => {
            debug!(ipfs_hash, "No local attestation stored for any blocks",);
            return ComparisonResult {
                deployment: ipfs_hash.to_string(),
                block_number: attestation_block,
                result_type: ComparisonResultType::NotFound,
                local_attestation: None,
                attestations: vec![],
            };
        }
    };
    let local_attestation = match blocks.get(&attestation_block) {
        Some(attestations) => attestations,
        None => {
            debug!(ipfs_hash, attestation_block, "No local attestation stored",);
            return ComparisonResult {
                deployment: ipfs_hash.to_string(),
                block_number: attestation_block,
                result_type: ComparisonResultType::NotFound,
                local_attestation: None,
                attestations: vec![],
            };
        }
    };

    let remote_blocks = match remote.get(ipfs_hash) {
        Some(blocks) => blocks,
        None => {
            debug!(ipfs_hash, "No remote attestation stored for any block");
            return ComparisonResult {
                deployment: ipfs_hash.to_string(),
                block_number: attestation_block,
                result_type: ComparisonResultType::NotFound,
                local_attestation: Some(local_attestation.clone()),
                attestations: vec![],
            };
        }
    };
    let remote_attestations = match remote_blocks.get(&attestation_block) {
        Some(attestations) if !attestations.is_empty() => attestations,
        _ => {
            debug!(ipfs_hash, attestation_block, "No remote attestation stored",);
            return ComparisonResult {
                deployment: ipfs_hash.to_string(),
                block_number: attestation_block,
                result_type: ComparisonResultType::NotFound,
                local_attestation: Some(local_attestation.clone()),
                attestations: vec![],
            };
        }
    };

    let mut remote_attestations = remote_attestations.clone();
    remote_attestations.sort_by(|a, b| a.stake_weight.partial_cmp(&b.stake_weight).unwrap());

    let sender_gauge = ACTIVE_INDEXERS.with_label_values(&[ipfs_hash]);
    // The value is the total number of senders that are attesting for that subgraph
    let senders: Vec<String> = combine_senders(&remote_attestations);
    sender_gauge.set(senders.len().try_into().unwrap());

    if remote_attestations.len() > 1 {
        warn!(
            ipfs_hash,
            attestation_block,
            sorted_attestations = tracing::field::debug(&remote_attestations),
            "More than 1 nPOI found",
        );
    }

    let most_attested_npoi = &remote_attestations.last().unwrap().npoi;
    if most_attested_npoi == &local_attestation.npoi {
        trace!(
            ipfs_hash,
            attestation_block,
            num_unique_npois = remote_attestations.len(),
            "nPOI matched",
        );
        ComparisonResult {
            deployment: ipfs_hash.to_string(),
            block_number: attestation_block,
            result_type: ComparisonResultType::Match,
            local_attestation: Some(local_attestation.clone()),
            attestations: remote_attestations,
        }
    } else {
        debug!(
            attestation_block,
            remote_attestations = tracing::field::debug(&remote_attestations),
            local_attestation = tracing::field::debug(&local_attestation),
            "Number of nPOI submitted",
        );
        ComparisonResult {
            deployment: ipfs_hash.to_string(),
            block_number: attestation_block,
            result_type: ComparisonResultType::Divergent,
            local_attestation: Some(local_attestation.clone()),
            attestations: remote_attestations,
        }
    }
}

/// Assume that local and remote has already been matched with the desired deployment and block
pub fn compare_attestation(
    local: AttestationEntry,
    remote_attestations: Vec<Attestation>,
) -> ComparisonResult {
    let local_attestation = local.attestation;
    let mut remote_attestations = remote_attestations;
    remote_attestations.sort_by(|a, b| a.stake_weight.partial_cmp(&b.stake_weight).unwrap());

    let most_attested_npoi = &remote_attestations.last().unwrap().npoi;
    if most_attested_npoi == &local_attestation.npoi {
        trace!(
            local.block_number,
            remote_attestations = tracing::field::debug(&remote_attestations),
            local_attestation = tracing::field::debug(&local_attestation),
            "nPOI matched",
        );
        ComparisonResult {
            deployment: local.deployment.to_string(),
            block_number: local.block_number,
            result_type: ComparisonResultType::Match,
            local_attestation: Some(local_attestation),
            attestations: remote_attestations,
        }
    } else {
        warn!(
            block = local.block_number,
            remote_attestations = tracing::field::debug(&remote_attestations),
            local_attestation = tracing::field::debug(&local_attestation),
            "Detected divergence",
        );
        ComparisonResult {
            deployment: local.deployment.to_string(),
            block_number: local.block_number,
            result_type: ComparisonResultType::Divergent,
            local_attestation: Some(local_attestation),
            attestations: remote_attestations,
        }
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

/// This function logs the operational summary of the main event loop
#[allow(clippy::too_many_arguments)]
pub async fn log_gossip_summary(
    blocks_str: String,
    num_topics: usize,
    messages_sent: Vec<Result<String, OperationError>>,
) {
    // Generate gossip summary
    let mut send_success = vec![];
    let mut trigger_failed = vec![];
    let mut skip_repeated = vec![];
    let mut build_errors = vec![];
    for result in messages_sent {
        match result {
            Ok(s) => send_success.push(s),
            Err(OperationError::SendTrigger(e)) => trigger_failed.push(e),
            Err(OperationError::SkipDuplicate(e)) => skip_repeated.push(e),
            Err(e) => build_errors.push(e),
        }
    }

    info!(
        chainhead = blocks_str,
        num_topics,
        num_sent_success = send_success.len(),
        num_sent_previously = skip_repeated.len(),
        num_syncing_to_chainhead = trigger_failed.len(),
        build_errors = tracing::field::debug(&build_errors),
        "Gossip summary",
    );
}

/// This function logs the operational summary of the main event loop
pub async fn process_comparison_results(
    blocks_str: String,
    num_topics: usize,
    result_strings: Vec<Result<ComparisonResult, OperationError>>,
    notifier: Notifier,
    persisted_state: PersistedState,
) {
    // Generate attestation summary
    let mut match_strings = vec![];
    let mut not_found_strings = vec![];
    let mut divergent_strings = vec![];
    let mut cmp_trigger_failed = vec![];
    let mut attestation_failed = vec![];
    let mut cmp_errors = vec![];

    for result in result_strings {
        match result {
            Ok(comparison_result) => {
                let result_type = persisted_state
                    .handle_comparison_result(comparison_result.clone(), notifier.clone())
                    .await;

                match result_type {
                    ComparisonResultType::Match => {
                        match_strings.push(comparison_result.to_string());
                    }
                    ComparisonResultType::NotFound => {
                        not_found_strings.push(comparison_result.to_string());
                    }
                    ComparisonResultType::Divergent => {
                        divergent_strings.push(comparison_result.to_string());
                    }
                    _ => attestation_failed.push(comparison_result.to_string()),
                }
            }
            Err(OperationError::CompareTrigger(_, _, e)) => cmp_trigger_failed.push(e.to_string()),
            Err(OperationError::Attestation(e)) => attestation_failed.push(e.to_string()),
            Err(e) => cmp_errors.push(e.to_string()),
        }
    }
    DIVERGING_SUBGRAPHS.set(divergent_strings.len().try_into().unwrap());

    info!(
        chainhead_blocks = blocks_str,
        num_topics,
        num_active_crosschecks = match_strings.len() + divergent_strings.len(),
        num_attestations_matched = match_strings.len(),
        num_topics_inactive = not_found_strings.len(),
        num_waiting_to_compare = cmp_trigger_failed.len(),
        diverged = tracing::field::debug(divergent_strings),
        attestation_failed = tracing::field::debug(attestation_failed),
        comparison_errors = tracing::field::debug(cmp_errors),
        "Comparison state",
    );
}

#[derive(Debug, thiserror::Error)]
pub enum AttestationError {
    #[error("Failed to build attestation: {0}")]
    BuildError(BuildMessageError),
    #[error("Failed to update attestation: {0}")]
    UpdateError(String),
}

impl ErrorExtensions for AttestationError {
    fn extend(&self) -> Error {
        Error::new(format!("{}", self))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // TODO: add setup and teardown functions

    #[test]
    fn test_update_blocks() {
        let mut blocks: HashMap<u64, Vec<Attestation>> = HashMap::new();
        blocks.insert(
            42,
            vec![Attestation::new(
                "default".to_string(),
                0.0,
                Vec::new(),
                Vec::new(),
            )],
        );
        let block_clone = update_blocks(
            42,
            &blocks,
            "awesome-npoi".to_string(),
            0.0,
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
            1.0,
            vec!["0xaac5349585cbbf924026d25a520ffa9e8b51a39b".to_string()],
            vec![1],
        );
        let attestation2 = Attestation::new(
            "awesome-npoi".to_string(),
            1.0,
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
            1.0,
            vec![
                "0xaac5349585cbbf924026d25a520ffa9e8b51a39b".to_string(),
                "0xbbc5349585cbbf924026d25a520ffa9e8b51a39b".to_string(),
            ],
            vec![1, 2],
        );
        let attestation2 = Attestation::new(
            "awesome-npoi".to_string(),
            1.0,
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
            0.0,
            vec!["0xa1".to_string()],
            vec![0],
        );

        let attestation2 = Attestation::new(
            "awesome-npoi".to_string(),
            0.0,
            vec!["0xa2".to_string()],
            vec![1],
        );

        let attestation3 = Attestation::new(
            "awesome-npoi".to_string(),
            1.0,
            vec!["0xa3".to_string()],
            vec![2],
        );

        let mut attestations = vec![attestation1, attestation2, attestation3];

        attestations.sort_by(|a, b| a.stake_weight.partial_cmp(&b.stake_weight).unwrap());

        assert_eq!(attestations.last().unwrap().stake_weight, 1);
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
            0.0,
            vec!["0xa1".to_string()],
            vec![2],
        );

        let updated_attestation = Attestation::update(&attestation, "0xa2".to_string(), 1.0, 1);

        assert!(updated_attestation.is_ok());
        assert_eq!(updated_attestation.as_ref().unwrap().stake_weight, 1);
        assert_eq!(updated_attestation.unwrap().timestamp, [2, 1]);
    }

    #[test]
    fn test_attestation_update_fail() {
        let attestation = Attestation::new(
            "awesome-npoi".to_string(),
            0.0,
            vec!["0xa1".to_string()],
            vec![0],
        );

        let updated_attestation = Attestation::update(&attestation, "0xa1".to_string(), 0.0, 0);

        assert!(updated_attestation.is_err());
        assert_eq!(
            updated_attestation.unwrap_err().to_string(),
            "Failed to update attestation: There is already an attestation from this address. Skipping...".to_string()
        );
    }

    #[tokio::test]
    async fn test_compare_attestations_generic_fail() {
        let res = compare_attestations(
            42,
            HashMap::new(),
            &HashMap::new(),
            "non-existent-ipfs-hash",
        );

        assert_eq!(
            res.to_string(),
            "NotFound for local attestation: deployment non-existent-ipfs-hash at block 42"
                .to_string()
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
                0.0,
                vec!["0xa1".to_string()],
                vec![1],
            )],
        );

        local_blocks.insert(
            42,
            Attestation::new("awesome-npoi".to_string(), 0.0, Vec::new(), vec![0]),
        );

        let mut remote_attestations: HashMap<String, HashMap<u64, Vec<Attestation>>> =
            HashMap::new();
        let mut local_attestations: HashMap<String, HashMap<u64, Attestation>> = HashMap::new();

        remote_attestations.insert("my-awesome-hash".to_string(), remote_blocks);
        local_attestations.insert("different-awesome-hash".to_string(), local_blocks);

        let res = compare_attestations(
            42,
            remote_attestations,
            &local_attestations,
            "different-awesome-hash",
        );

        assert_eq!(
            res.to_string(),
            "NotFound for remote attestations: deployment different-awesome-hash at block 42"
                .to_string()
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
            &local_attestations,
            "my-awesome-hash",
        );

        assert_eq!(
            res.to_string(),
            "NotFound for local attestation: deployment my-awesome-hash at block 42".to_string()
        );
    }

    #[tokio::test]
    async fn test_compare_attestations_success() {
        let mut remote_blocks: HashMap<u64, Vec<Attestation>> = HashMap::new();
        let mut local_blocks: HashMap<u64, Attestation> = HashMap::new();

        let remote = Attestation::new(
            "awesome-npoi".to_string(),
            0.0,
            vec!["0xa1".to_string()],
            vec![0],
        );
        remote_blocks.insert(42, vec![remote.clone()]);

        let local = Attestation::new("awesome-npoi".to_string(), 0.0, Vec::new(), vec![0]);
        local_blocks.insert(42, local.clone());

        let mut remote_attestations: HashMap<String, HashMap<u64, Vec<Attestation>>> =
            HashMap::new();
        let mut local_attestations: HashMap<String, HashMap<u64, Attestation>> = HashMap::new();

        remote_attestations.insert("my-awesome-hash".to_string(), remote_blocks);
        local_attestations.insert("my-awesome-hash".to_string(), local_blocks);

        let res = compare_attestations(
            42,
            remote_attestations,
            &local_attestations,
            "my-awesome-hash",
        );

        assert_eq!(
            res,
            ComparisonResult {
                deployment: "my-awesome-hash".to_string(),
                block_number: 42,
                result_type: ComparisonResultType::Match,
                local_attestation: Some(local),
                attestations: vec![remote],
            }
        );
    }

    #[tokio::test]
    async fn clear_local_attestation_success() {
        let mut local_blocks: HashMap<u64, Attestation> = HashMap::new();
        let attestation1 = Attestation::new(
            "awesome-npoi".to_string(),
            0.0,
            vec!["0xa1".to_string()],
            vec![0],
        );

        let attestation2 = Attestation::new(
            "awesome-npoi".to_string(),
            0.0,
            vec!["0xa2".to_string()],
            vec![1],
        );

        let attestation3 = Attestation::new(
            "awesome-npoi".to_string(),
            1.0,
            vec!["0xa3".to_string()],
            vec![2],
        );

        local_blocks.insert(42, attestation1);
        local_blocks.insert(43, attestation2);
        local_blocks.insert(44, attestation3);

        let mut local_attestations: HashMap<String, HashMap<u64, Attestation>> = HashMap::new();
        local_attestations.insert("hash".to_string(), local_blocks.clone());
        local_attestations.insert("hash2".to_string(), local_blocks);
        let local = Arc::new(SyncMutex::new(local_attestations));

        clear_local_attestation(Arc::clone(&local), "hash".to_string(), 43);

        assert_eq!(local.lock().unwrap().get("hash").unwrap().len(), 2);
        assert!(local
            .lock()
            .unwrap()
            .get("hash")
            .unwrap()
            .get(&43)
            .is_none());
        assert_eq!(local.lock().unwrap().get("hash2").unwrap().len(), 3);
    }

    #[tokio::test]
    async fn local_attestation_pointer_success() {
        let mut local_blocks: HashMap<u64, Attestation> = HashMap::new();
        let attestation1 = Attestation::new(
            "awesome-npoi".to_string(),
            0.0,
            vec!["0xa1".to_string()],
            vec![2],
        );

        let attestation2 = Attestation::new(
            "awesome-npoi".to_string(),
            0.0,
            vec!["0xa2".to_string()],
            vec![4],
        );

        let attestation3 = Attestation::new(
            "awesome-npoi".to_string(),
            1.0,
            vec!["0xa3".to_string()],
            vec![6],
        );

        local_blocks.insert(42, attestation1);
        local_blocks.insert(43, attestation2);
        local_blocks.insert(44, attestation3);

        let mut local_attestations: HashMap<String, HashMap<u64, Attestation>> = HashMap::new();
        local_attestations.insert("hash".to_string(), local_blocks.clone());
        local_attestations.insert("hash2".to_string(), local_blocks);
        let (block_num, collect_window_end) =
            local_comparison_point(&local_attestations, "hash".to_string(), 120).unwrap();

        assert_eq!(block_num, 42);
        assert_eq!(collect_window_end, 122);
    }

    #[tokio::test]
    async fn test_save_local_attestation() {
        let local_attestations = Arc::new(SyncMutex::new(HashMap::new()));
        save_local_attestation(
            local_attestations.clone(),
            "npoi-x".to_string(),
            "0xa1".to_string(),
            0,
        );

        save_local_attestation(
            local_attestations.clone(),
            "npoi-y".to_string(),
            "0xa1".to_string(),
            1,
        );

        save_local_attestation(
            local_attestations.clone(),
            "npoi-z".to_string(),
            "0xa2".to_string(),
            2,
        );

        assert!(!local_attestations.lock().unwrap().is_empty());
        assert!(local_attestations.lock().unwrap().len() == 2);
        assert!(
            local_attestations
                .lock()
                .unwrap()
                .get("0xa1")
                .unwrap()
                .len()
                == 2
        );
        assert!(
            local_attestations
                .lock()
                .unwrap()
                .get("0xa2")
                .unwrap()
                .len()
                == 1
        );
        assert!(
            local_attestations
                .lock()
                .unwrap()
                .get("0xa1")
                .unwrap()
                .get(&0)
                .unwrap()
                .npoi
                == *"npoi-x"
        );
    }
}
