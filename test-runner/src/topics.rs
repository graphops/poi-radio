use poi_radio::state::PersistedState;
use test_utils::{
    config::{test_config, TestSenderConfig},
    setup, teardown,
};
use tokio::time::{sleep, Duration};
use tracing::debug;

pub async fn topics_test() {
    let test_file_name = "topics";
    let store_path = format!("./test-runner/state/{}.json", test_file_name);

    let radio_topics = vec![
        "Qmdefault1AbcDEFghijKLmnoPQRstUVwxYzABCDEFghijklmnopq".to_string(),
        "Qmdefault2XyZABCdefGHIjklMNOpqrstuvWXYZabcdefGHIJKLMN".to_string(),
        "QmonlyinradioXyZABCdeFgHIjklMNOpqrstuvWXYZabcdefGHIJKL".to_string(),
    ];

    let test_sender_topics = vec![
        "Qmdefault1AbcDEFghijKLmnoPQRstUVwxYzABCDEFghijklmnopq".to_string(),
        "Qmdefault2XyZABCdefGHIjklMNOpqrstuvWXYZabcdefGHIJKLMN".to_string(),
        "QmonlyintestsenderXyZABCdeFgHIjklMNOpqrstuvWXYZabcdEFG".to_string(),
    ];

    let mut config = test_config();
    config.persistence_file_path = Some(store_path.clone());
    config.topics = radio_topics.clone();
    config.topic_update_interval = 90;

    let mut test_sender_config = TestSenderConfig {
        topics: test_sender_topics,
        radio_name: String::new(),
        block_hash: None,
        staked_tokens: None,
        nonce: None,
        radio_payload: None,
        poi: None,
    };

    let process_manager = setup(&config, test_file_name, &mut test_sender_config).await;

    sleep(Duration::from_secs(89)).await;

    let persisted_state = PersistedState::load_cache(&store_path);
    debug!("persisted state {:?}", persisted_state);

    let local_attestations = persisted_state.local_attestations();
    let remote_messages = persisted_state.remote_messages();

    debug!("Starting topics_test");

    assert!(
        !local_attestations.is_empty(),
        "There should be at least one element in local_attestations"
    );

    for test_hash in radio_topics {
        assert!(
            local_attestations.contains_key(&test_hash),
            "No attestation found with ipfs hash {}",
            test_hash
        );
    }

    let test_hashes_remote = vec![
        "Qmdefault1AbcDEFghijKLmnoPQRstUVwxYzABCDEFghijklmnopq",
        "Qmdefault2XyZABCdefGHIjklMNOpqrstuvWXYZabcdefGHIJKLMN",
    ];

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

    let non_existent_test_hash = "QmonlyintestsenderXyZABCdeFgHIjklMNOpqrstuvWXYZabcdEFG";

    let has_non_existent_test_hash = remote_messages
        .iter()
        .any(|msg| msg.identifier == non_existent_test_hash);

    assert!(
        !has_non_existent_test_hash,
        "Unexpected remote message found with identifier {}",
        non_existent_test_hash
    );

    let new_subgraphs = vec!["QmonlyintestsenderXyZABCdeFgHIjklMNOpqrstuvWXYZabcdEFG".to_string()]; // change this to your new subgraphs
    process_manager
        .server_state
        .update_subgraphs(new_subgraphs)
        .await;

    tokio::time::sleep(Duration::from_secs(50)).await;

    let persisted_state = PersistedState::load_cache(&store_path);
    debug!("persisted state {:?}", persisted_state);

    let remote_messages = persisted_state.remote_messages();

    let test_hash = "QmonlyintestsenderXyZABCdeFgHIjklMNOpqrstuvWXYZabcdEFG";
    let has_test_hash = remote_messages
        .iter()
        .any(|msg| msg.identifier == test_hash);

    assert!(
        has_test_hash,
        "Expected remote message not found with identifier {}",
        test_hash
    );

    teardown(process_manager, &store_path);
}
