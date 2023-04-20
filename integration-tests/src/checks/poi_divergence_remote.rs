use std::{env, sync::Arc};

use crate::utils::RadioTestConfig;

use poi_radio::{
    attestation::{LocalAttestationsMap, RemoteAttestationsMap},
    MessagesVec,
};
use tracing::{debug, info};

use crate::setup::test_radio::run_test_radio;

fn post_comparison_handler(_messages: MessagesVec, _block: u64, _subgraph: &str) {}

fn test_attestation_handler(
    block: u64,
    remote: &RemoteAttestationsMap,
    local: &LocalAttestationsMap,
) {
    let (ipfs_hash, blocks) = match local.iter().next() {
        Some(pair) => pair,
        None => {
            debug!("No local attestations found");
            return;
        }
    };

    let local_attestation = match blocks.get(&block) {
        Some(attestation) => attestation,
        None => {
            debug!("No local attestation found for block {}", block);
            return;
        }
    };

    let remote_blocks = match remote.get(ipfs_hash) {
        Some(blocks) => blocks,
        None => {
            debug!("No remote blocks found for IPFS hash {:?}", ipfs_hash);
            return;
        }
    };

    let mut remote_attestations = match remote_blocks.get(&block) {
        Some(attestations) => attestations.clone(),
        None => {
            debug!("No remote attestations found for block {}", block);
            return;
        }
    };

    remote_attestations.sort_by(|a, b| a.stake_weight.cmp(&b.stake_weight));

    debug!(
        "Remote attestations on block {}: {:#?}",
        block, remote_attestations
    );
    info!(
        "Number of nPOIs submitted for block {}: {:#?}",
        block,
        remote_attestations.len()
    );
    if remote_attestations.len() > 1 {
        info!("Sorted attestations: {:#?}", remote_attestations);
    }

    let most_attested_npoi = &remote_attestations.last().unwrap().npoi;
    info!("Most attested npoi: {:#?}", most_attested_npoi);
    info!("Local npoi: {:#?}", &local_attestation.npoi);

    if remote_attestations.len() >= 2 {
        if most_attested_npoi == &local_attestation.npoi {
            info!("{}", "poi_divergence_remote test is successful ✅");
            std::process::exit(0);
        } else {
            info!("{}", "poi_divergence_remote test failed");
            std::process::exit(1);
        }
    } else {
        debug!("Not enough remote attestations to compare (minimum 2 required)");
    }
}

fn success_handler(_messages: MessagesVec, _graphcast_id: &str) {}

#[tokio::main]
pub async fn run_poi_divergence_remote() {
    let config = RadioTestConfig::new();
    env::set_var("COLLECT_MESSAGE_DURATION", "90");

    run_test_radio(
        Arc::new(config),
        success_handler,
        test_attestation_handler,
        post_comparison_handler,
    )
    .await;
}
