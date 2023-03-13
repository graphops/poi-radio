use crate::utils::RadioRuntimeConfig;
use colored::Colorize;
use num_bigint::BigUint;
use poi_radio::{LocalAttestationsMap, MessagesArc, RemoteAttestationsMap};
use tracing::{debug, info};

use crate::setup::test_radio::run_test_radio;

fn post_comparison_handler(_messages: MessagesArc, _block: u64, _subgraph: &str, _prev_len: usize) {
}

fn test_attestation_handler(
    block: u64,
    remote: &RemoteAttestationsMap,
    local: &LocalAttestationsMap,
) {
    debug!("Something from test_attestation_handler");
    debug!("Inputs {:?}{:?}{:?}", block, remote, local);

    if let Some((ipfs_hash, blocks)) = local.iter().next() {
        if let Some(local_attestation) = blocks.get(&block) {
            if let Some(remote_blocks) = remote.get(ipfs_hash) {
                if let Some(remote_attestations) = remote_blocks.get(&block) {
                    let mut remote_attestations = remote_attestations.clone();
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

                    // This check assumes there are 5 basic instances running. This is what remote attestations looks like currently with no divergence (example):
                    //[
                    //     Attestation {
                    //         npoi: "0x25331f98b82ca7f3966256bf508a7ede52e715b631dfa3d73b846bb7617f6b9e",
                    //         stake_weight: 600000000000000000000000,
                    //         senders: [
                    //             "0xfc79d32003aefc2b6a58682e38fee99576a8c0f3",
                    //             "0x5ddbc82d5c2f2f3d45e8431a4ab993c6da947ebc",
                    //             "0xb456d167c337f9784184c147f2133b7855a9c4aa",
                    //             "0xf9aed4dec0c5d209310e0d283be31ecc83a24556",
                    //             "0x787f18952c1ee355482389d16084949ce13b9211",
                    //             "0x7876b79df6e6b58a95b5d30ecd99dacc0e7005d3",
                    //         ],
                    //     },
                    // ]

                    for attestation in remote_attestations.iter() {
                        let unique_senders = attestation
                            .senders
                            .iter()
                            .collect::<std::collections::HashSet<_>>();
                        if unique_senders.len() >= 5
                            && attestation.stake_weight
                                >= BigUint::from(500000000000000000000000u128)
                        {
                            info!("{}", "store_attestations test is successful ✅".green());
                            std::process::exit(0);
                        }
                    }
                }
            }
        }
    }
}

fn success_handler(_messages: MessagesArc) {}

#[tokio::main]
pub async fn run_store_attestations() {
    let config = RadioRuntimeConfig::new(false, true);
    run_test_radio(
        &config,
        success_handler,
        test_attestation_handler,
        post_comparison_handler,
    )
    .await;
}
