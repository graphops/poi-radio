use crate::utils::RadioTestConfig;

use poi_radio::{
    attestation::{LocalAttestationsMap, RemoteAttestationsMap},
    MessagesVec,
};
use tracing::{error, info};

use crate::setup::test_radio::run_test_radio;

use std::{any::type_name, sync::Arc};

fn type_of<T>(_: T) -> &'static str {
    type_name::<T>()
}

fn post_comparison_handler(_messages: MessagesVec, _block: u64, _subgraph: &str) {}

fn test_attestation_handler(
    _block: u64,
    _remote: &RemoteAttestationsMap,
    _local: &LocalAttestationsMap,
) {
}

fn success_handler(messages: MessagesVec, _graphcast_id: &str) {
    let messages = messages.get().unwrap().lock().unwrap();

    if messages.len() >= 5 {
        info!("At least 5 messages received");

        let mut failed_conditions = vec![];

        if !messages
            .iter()
            .all(|m| !type_of(&m.payload).contains("hello"))
        {
            failed_conditions.push("Some messages contain 'hello' in their payload");
        }

        if !messages.iter().all(|m| m.nonce != 1678665600) {
            failed_conditions.push("Some messages have nonce equal to 1678665600");
        }

        if !messages.iter().all(|m| {
            m.block_hash != "4rfba1ba9fb18b0034965712598be1368edcf91ae2c551d59462aab578dab9c5"
        }) {
            failed_conditions.push("Some messages have a block_hash equal to '4rfba1ba9fb18b0034965712598be1368edcf91ae2c551d59462aab578dab9c5'");
        }

        if failed_conditions.is_empty() {
            info!("invalid_messages test is successful ✅");
            std::process::exit(0);
        } else {
            error!("invalid_messages test failed due to the following reasons:");
            for reason in failed_conditions {
                error!("  - {}", reason);
            }
            std::process::exit(1);
        }
    }
}

#[tokio::main]
pub async fn run_invalid_messages() {
    let config = RadioTestConfig::new();
    run_test_radio(
        Arc::new(config),
        success_handler,
        test_attestation_handler,
        post_comparison_handler,
    )
    .await;
}
