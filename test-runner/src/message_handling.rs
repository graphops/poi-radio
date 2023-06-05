use std::collections::HashMap;

use graphcast_sdk::graphcast_agent::message_typing::GraphcastMessage;
use poi_radio::{operator::attestation::Attestation, RadioPayloadMessage};
use tracing::{debug, info};

pub fn send_and_receive_test(
    local_attestations: &HashMap<String, HashMap<u64, Attestation>>,
    remote_messages: &[GraphcastMessage<RadioPayloadMessage>],
) {
    debug!("Starting send_and_receive_test");

    assert!(
        !local_attestations.is_empty(),
        "There should be at least one element in local_attestations"
    );

    let test_hashes_local = vec![
        "QmpRkaVUwUQAwPwWgdQHYvw53A5gh3CP3giWnWQZdA2BTE",
        "QmtYT8NhPd6msi1btMc3bXgrfhjkJoC4ChcM5tG6fyLjHE",
    ];

    for test_hash in test_hashes_local {
        assert!(
            local_attestations.contains_key(test_hash),
            "No attestation found with ipfs hash {}",
            test_hash
        );
    }

    let test_hashes_remote = vec!["QmtYT8NhPd6msi1btMc3bXgrfhjkJoC4ChcM5tG6fyLjHE"];

    for target_id in test_hashes_remote {
        let has_target_id = remote_messages
            .iter()
            .any(|msg| msg.identifier == *target_id);
        assert!(
            has_target_id,
            "No remote message found with identifier {}",
            target_id
        );
    }

    info!("send_and_receive_test passed ✅");
}
