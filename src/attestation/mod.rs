use async_graphql::SimpleObject;
use autometrics::autometrics;
use chrono::Utc;

use num_traits::Zero;
use sha3::{Digest, Sha3_256};
use std::{
    collections::HashMap,
    fmt::{self, Display},
    sync::Arc,
};
use tokio::sync::Mutex as AsyncMutex;
use tracing::{debug, error, info, trace, warn};

use graphcast_sdk::{
    bots::{DiscordBot, SlackBot},
    config::Config,
    graphcast_agent::message_typing::{get_indexer_stake, BuildMessageError, GraphcastMessage},
    graphql::client_registry::query_registry_indexer,
    networks::NetworkName,
};

use crate::{
    metrics::{
        ACTIVE_INDEXERS, DIVERGING_SUBGRAPHS, INDEXER_COUNT_BY_NPOI, LOCAL_NPOIS_TO_COMPARE,
    },
    OperationError, RadioPayloadMessage,
};

/// A wrapper around an attested NPOI, tracks Indexers that have sent it plus their accumulated stake
#[derive(Clone, Debug, PartialEq, Eq, Hash, SimpleObject)]
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

#[derive(SimpleObject)]
pub struct AttestationEntry {
    pub deployment: String,
    pub block_number: u64,
    pub attestation: Attestation,
}

pub async fn attestations_to_vec(
    attestations: &Arc<AsyncMutex<LocalAttestationsMap>>,
) -> Vec<AttestationEntry> {
    attestations
        .lock()
        .await
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

/// This function processes the global messages map that we populate when
/// messages are being received. It constructs the remote attestations
/// map and returns it if the processing succeeds.
#[autometrics]
pub async fn process_messages(
    messages: Vec<GraphcastMessage<RadioPayloadMessage>>,
    registry_subgraph: &str,
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

pub fn combine_senders(attestations: &[Attestation]) -> Vec<String> {
    <&[Attestation]>::clone(&attestations)
        .iter()
        .flat_map(|attestation| attestation.senders.clone())
        .collect()
}

/// Determine the comparison pointer on both block and time based on the local attestations
/// If they don't exist, then return default value that shall never be validated to trigger
pub async fn local_comparison_point(
    local_attestations: Arc<AsyncMutex<LocalAttestationsMap>>,
    id: String,
    collect_window_duration: i64,
) -> Option<(u64, i64)> {
    let local_attestations = local_attestations.lock().await;
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
pub async fn save_local_attestation(
    local_attestations: Arc<AsyncMutex<LocalAttestationsMap>>,
    content: String,
    ipfs_hash: String,
    block_number: u64,
) {
    let attestation = Attestation::new(
        content.clone(),
        Zero::zero(),
        vec![],
        vec![Utc::now().timestamp()],
    );

    let mut local_attestations = local_attestations.lock().await;
    let blocks = local_attestations.get(&ipfs_hash);

    match blocks {
        Some(blocks) => {
            let mut blocks_clone: HashMap<u64, Attestation> = HashMap::new();
            blocks_clone.extend(blocks.clone());
            // Save the first attestation for a comparison period
            blocks_clone.entry(block_number).or_insert(attestation);
            local_attestations.insert(ipfs_hash.clone(), blocks_clone);
        }
        None => {
            let mut blocks_clone: HashMap<u64, Attestation> = HashMap::new();
            blocks_clone.insert(block_number, attestation);
            local_attestations.insert(ipfs_hash.clone(), blocks_clone);
        }
    };

    let npoi_gauge = LOCAL_NPOIS_TO_COMPARE.with_label_values(&[&ipfs_hash.clone()]);

    // The value is the total number of senders that are attesting for that subgraph
    npoi_gauge.set(local_attestations.len().try_into().unwrap());
}

/// Clear the expired local attestations after comparing with remote results
pub async fn clear_local_attestation(
    local_attestations: Arc<AsyncMutex<LocalAttestationsMap>>,
    ipfs_hash: String,
    block_number: u64,
) {
    let mut local_attestations = local_attestations.lock().await;
    let blocks = local_attestations.get(&ipfs_hash.clone());

    if let Some(blocks) = blocks {
        let mut blocks_clone: HashMap<u64, Attestation> = HashMap::new();
        blocks_clone.extend(blocks.clone());
        blocks_clone.remove(&block_number);
        let npoi_gauge = LOCAL_NPOIS_TO_COMPARE.with_label_values(&[&ipfs_hash.clone()]);
        // The value is the total number of senders that are attesting for that subgraph
        npoi_gauge.set(blocks_clone.len().try_into().unwrap());
        local_attestations.insert(ipfs_hash.clone(), blocks_clone);
    };
}

/// Tracks results indexed by deployment hash and block number
#[derive(Debug, PartialEq, Eq, Hash)]
pub enum ComparisonResult {
    NotFound(String, u64, String),
    Divergent(String, u64, String),
    Match(String, u64, String),
    BuildFailed(String, u64, String),
}

impl ComparisonResult {
    pub fn deployment(&self) -> String {
        match self {
            ComparisonResult::NotFound(d, _, _) => d.clone(),
            ComparisonResult::Divergent(d, _, _) => d.clone(),
            ComparisonResult::Match(d, _, _) => d.clone(),
            ComparisonResult::BuildFailed(d, _, _) => d.clone(),
        }
    }

    pub fn block(&self) -> u64 {
        match self {
            ComparisonResult::NotFound(_, b, _) => *b,
            ComparisonResult::Divergent(_, b, _) => *b,
            ComparisonResult::Match(_, b, _) => *b,
            ComparisonResult::BuildFailed(_, b, _) => *b,
        }
    }
    pub fn help_string(&self) -> String {
        match self {
            ComparisonResult::NotFound(_, _, h) => h.clone(),
            ComparisonResult::Divergent(_, _, h) => h.clone(),
            ComparisonResult::Match(_, _, h) => h.clone(),
            ComparisonResult::BuildFailed(_, _, h) => h.clone(),
        }
    }
}

impl Display for ComparisonResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        debug!("Display for comparison reulst");
        match self {
            ComparisonResult::NotFound(d, b, s) => {
                write!(f, "NotFound: deployment {d} at block {b}: {s}")
            }
            ComparisonResult::Divergent(d, b, s) => {
                write!(f, "Divergent: deployment {d} at block {b}: {s}")
            }
            ComparisonResult::Match(d, b, s) => {
                write!(f, "Matched: deployment {d} at block {b}: {s}")
            }
            ComparisonResult::BuildFailed(d, b, s) => write!(
                f,
                "Failed to build message: deployment {d} at block {b}: {s}"
            ),
        }
    }
}

impl Clone for ComparisonResult {
    fn clone(&self) -> Self {
        debug!("Clone for comparison reulst");
        match self {
            ComparisonResult::NotFound(a, b, c) => {
                ComparisonResult::NotFound(a.clone(), *b, c.clone())
            }
            ComparisonResult::Divergent(a, b, c) => {
                ComparisonResult::Divergent(a.clone(), *b, c.clone())
            }
            ComparisonResult::Match(a, b, c) => ComparisonResult::Match(a.clone(), *b, c.clone()),
            ComparisonResult::BuildFailed(a, b, c) => {
                ComparisonResult::BuildFailed(a.clone(), *b, c.clone())
            }
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
) -> ComparisonResult {
    trace!(
        "Comparing attestations:\nlocal: {:#?}\n remote: {:#?}",
        local,
        remote
    );

    let local = local.lock().await;

    let blocks = match local.get(ipfs_hash) {
        Some(blocks) => blocks,
        None => {
            return ComparisonResult::NotFound(
                ipfs_hash.to_string(),
                attestation_block,
                String::from("No local attestation found"),
            )
        }
    };
    let local_attestation = match blocks.get(&attestation_block) {
        Some(attestations) => attestations,
        None => {
            return ComparisonResult::NotFound(
                ipfs_hash.to_string(),
                attestation_block,
                "No local attestation found for the deployment".to_string(),
            )
        }
    };

    let remote_blocks = match remote.get(ipfs_hash) {
        Some(blocks) => blocks,
        None => {
            return ComparisonResult::NotFound(
                ipfs_hash.to_string(),
                attestation_block,
                "No remote attestation found for the block".to_string(),
            )
        }
    };
    let remote_attestations = match remote_blocks.get(&attestation_block) {
        Some(attestations) if !attestations.is_empty() => attestations,
        _ => {
            return ComparisonResult::NotFound(
                ipfs_hash.to_string(),
                attestation_block,
                "No remote attestation found".to_string(),
            )
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
        ComparisonResult::Match(
            ipfs_hash.to_string(),
            attestation_block,
            format!("nPOIs matched!: {most_attested_npoi}"),
        )
    } else {
        info!(
            "Number of nPOI submitted for block {}: {:#?}\n{}: {:#?}",
            attestation_block, remote_attestations, "Local attestation", local_attestation
        );
        ComparisonResult::Divergent(ipfs_hash.to_string(), attestation_block, format!(
            "❗ POIs didn't match! Network: {network_name}\nLocal attestation:\n{local_attestation:#?}\n\nRemote attestations:\n{remote_attestations:#?}"
        ))
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
pub async fn log_summary(
    blocks_str: String,
    num_topics: usize,
    messages_sent: Vec<Result<String, OperationError>>,
    result_strings: Vec<Result<ComparisonResult, OperationError>>,
    radio_name: &str,
    config: &Config,
) {
    // Generate send summary
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

    // Generate attestation summary
    let mut match_strings = vec![];
    let mut not_found_strings = vec![];
    let mut divergent_strings = vec![];
    let mut cmp_trigger_failed = vec![];
    let mut attestation_failed = vec![];
    let mut cmp_errors = vec![];

    for result in result_strings {
        match result {
            Ok(ComparisonResult::Match(d, b, s)) => {
                match_strings.push(format!("deployment {} at block {}: {}", d, b, s));
            }
            Ok(ComparisonResult::NotFound(d, b, s)) => {
                not_found_strings.push(format!("deployment {} at block {}: {}", d, b, s));
            }
            Ok(ComparisonResult::Divergent(d, b, s)) => {
                error!("{}", s);
                if let (Some(token), Some(channel)) = (&config.slack_token, &config.slack_channel) {
                    if let Err(e) =
                        SlackBot::send_webhook(token.to_string(), channel, radio_name, s.as_str())
                            .await
                    {
                        warn!("Failed to send notification to Slack: {}", e);
                    }
                }

                if let Some(webhook_url) = config.discord_webhook.clone() {
                    if let Err(e) =
                        DiscordBot::send_webhook(&webhook_url, radio_name, s.as_str()).await
                    {
                        warn!("Failed to send notification to Discord: {}", e);
                    }
                }
                divergent_strings.push(format!("deployment {} at block {}: {}", d, b, s));
            }
            Ok(ComparisonResult::BuildFailed(d, b, s)) => {
                attestation_failed.push(format!("deployment {} at block {}: {}", d, b, s))
            }
            Err(OperationError::CompareTrigger(_, _, e)) => cmp_trigger_failed.push(e.to_string()),
            // Share with the compareResult::BuildFailed
            Err(OperationError::Attestation(e)) => attestation_failed.push(e.to_string()),
            Err(e) => cmp_errors.push(e.to_string()),
        }
    }
    DIVERGING_SUBGRAPHS.set(divergent_strings.len().try_into().unwrap());

    info!(
        "Operation summary for\n{}: {}:\n{}: {}\n{}: {}\n{}: {:#?}\n{}: {:#?}\n{}: {:#?}\n{}: {}\n{}: {}\n{}: {:#?}\n{}: {:#?}\n{}: {:#?}\n{}: {:#?}\n{}: {:#?}",
        "Chainhead blocks",
        blocks_str.clone(),
        "# of deployments tracked",
        num_topics,
        "# of deployment updates sent",
        send_success.len(),
        "# of deployments waiting for next message interval",
        skip_repeated.len(),
        "Deployments catching up to chainhead",
        trigger_failed,
        "Deployments failed to build message",
        build_errors,
        "# of deployments actively cross-checked",
        match_strings.len() + divergent_strings.len(),
        "# of successful attestations",
        match_strings.len(),
        "# of deployments without remote attestation",
        not_found_strings.len(),
        "Divergence",
        divergent_strings,
        "Compare trigger out of bound",
        cmp_trigger_failed,
        "Attestation failed",
        attestation_failed,
        "Comparison failed",
        cmp_errors,
    );
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
            NetworkName::Goerli,
            42,
            HashMap::new(),
            Arc::new(AsyncMutex::new(HashMap::new())),
            "non-existent-ipfs-hash",
        )
        .await;

        assert_eq!(
            res.to_string(),
            "NotFound: deployment non-existent-ipfs-hash at block 42: No local attestation found"
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
            NetworkName::Goerli,
            42,
            remote_attestations,
            Arc::new(AsyncMutex::new(local_attestations)),
            "different-awesome-hash",
        )
        .await;

        assert_eq!(
            res.to_string(),
            "NotFound: deployment different-awesome-hash at block 42: No remote attestation found for the block"
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
            NetworkName::Goerli,
            42,
            remote_attestations,
            Arc::new(AsyncMutex::new(local_attestations)),
            "my-awesome-hash",
        )
        .await;

        assert_eq!(
            res.to_string(),
            "NotFound: deployment my-awesome-hash at block 42: No local attestation found for the deployment"
                .to_string()
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
                0.0,
                vec!["0xa1".to_string()],
                vec![0],
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
        local_attestations.insert("my-awesome-hash".to_string(), local_blocks);

        let res = compare_attestations(
            NetworkName::Goerli,
            42,
            remote_attestations,
            Arc::new(AsyncMutex::new(local_attestations)),
            "my-awesome-hash",
        )
        .await;

        assert_eq!(
            res,
            ComparisonResult::Match(
                "my-awesome-hash".to_string(),
                42,
                "nPOIs matched!: awesome-npoi".to_string()
            )
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
        let local = Arc::new(AsyncMutex::new(local_attestations));

        clear_local_attestation(Arc::clone(&local), "hash".to_string(), 43).await;

        assert_eq!(local.lock().await.get("hash").unwrap().len(), 2);
        assert!(local.lock().await.get("hash").unwrap().get(&43).is_none());
        assert_eq!(local.lock().await.get("hash2").unwrap().len(), 3);
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
        let local = Arc::new(AsyncMutex::new(local_attestations));
        let (block_num, collect_window_end) =
            local_comparison_point(local, "hash".to_string(), 120)
                .await
                .unwrap();

        assert_eq!(block_num, 42);
        assert_eq!(collect_window_end, 122);
    }
}
