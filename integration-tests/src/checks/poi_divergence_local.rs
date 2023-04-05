use crate::utils::RadioTestConfig;

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

                    // This check assumes there are less basic than divergent instances running. This is what remote attestations looks like currently with no divergence (example):
                    // [
                    //     Attestation {
                    //         npoi: "0x33331f98b82ca7f3966256bf508a7ede52e715b631dfa3d73b846bb7617f6b9e",
                    //         stake_weight: 100000000000000000000000,
                    //         senders: [
                    //             "0x8927cd2853d3c1349e0d2a42010c48c2ca5d8bf1",
                    //         ],
                    //     },
                    //     Attestation {
                    //         npoi: "0x25331f98b82ca7f3966256bf508a7ede52e715b631dfa3d73b846bb7617f6b9e",
                    //         stake_weight: 600000000000000000000000,
                    //         senders: [
                    //             "0xc70b60b9e232275a6aab9794d2e99d064c369887",
                    //             "0x31e809f32563290987ee3771bb920b05eb000237",
                    //             "0x14924fd3842cc70aaffb689e5c5da07df164b641",
                    //             "0x0c73cccbb4e4b87ce808fd518e0b750ebf3d6c14",
                    //             "0xc25bed133dd8252065c38df769d0946772d11eb7",
                    //             "0x2e6b0c5e5fa6e72b4eb2540591f135dde12205e9",
                    //         ],
                    //     },
                    // ]

                    if remote_attestations.len() >= 2 {
                        assert!(most_attested_npoi != &local_attestation.npoi);
                        info!("{}", "poi_divergence_local test is successful ✅");
                        std::process::exit(0);
                    }
                }
            }
        }
    }
}

fn success_handler(_messages: MessagesArc) {}

#[tokio::main]
pub async fn run_poi_divergence_local() {
    let config = RadioTestConfig::new(false, false);
    run_test_radio(
        &config,
        success_handler,
        test_attestation_handler,
        post_comparison_handler,
    )
    .await;
}
