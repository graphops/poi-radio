use poi_radio::state::PersistedState;
use test_utils::{config::test_config, setup, teardown};
use tokio::time::{sleep, Duration};
use tracing::{debug, info};

pub async fn topics_test() {
    let test_file_name = "topics";
    let store_path = format!("./test-runner/state/{}.json", test_file_name);

    let mut config = test_config();
    config.persistence_file_path = Some(store_path.clone());
    let process_manager = setup(&config, test_file_name);

    // Wait for 3 minutes asynchronously
    sleep(Duration::from_secs(180)).await;

    let persisted_state = PersistedState::load_cache(&store_path);
    debug!("persisted state {:?}", persisted_state);

    // Calling teardown ealy since we don't need the processes to run after getting a snapshot of the state
    teardown(process_manager, &store_path);

    let local_attestations = persisted_state.local_attestations();
    let remote_messages = persisted_state.remote_messages();

    debug!("Starting topics_test");

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

    info!("topics_test passed ✅");
}
