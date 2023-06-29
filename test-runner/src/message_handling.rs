use poi_radio::state::PersistedState;
use test_utils::{
    config::{test_config, TestSenderConfig},
    messages_are_equal, payloads_are_equal, setup, teardown,
};
use tokio::time::{sleep, Duration};
use tracing::{debug, trace};

pub async fn send_and_receive_test() {
    let test_file_name = "message_handling";
    let store_path = format!("./test-runner/state/{}.json", test_file_name);

    let radio_topics = vec![
        "Qmdefault1AbcDEFghijKLmnoPQRstUVwxYzABCDEFghijklmnopq".to_string(),
        "Qmdefault2XyZABCdefGHIjklMNOpqrstuvWXYZabcdefGHIJKLMN".to_string(),
    ];

    let test_sender_topics =
        vec!["Qmdefault1AbcDEFghijKLmnoPQRstUVwxYzABCDEFghijklmnopq".to_string()];

    let mut config = test_config();
    config.persistence_file_path = Some(store_path.clone());
    config.topics = radio_topics.clone();

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

    teardown(process_manager, &store_path);

    let local_attestations = persisted_state.local_attestations();
    let remote_messages = persisted_state.remote_messages();

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

    let test_hashes_remote = vec!["Qmdefault1AbcDEFghijKLmnoPQRstUVwxYzABCDEFghijklmnopq"];

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

    trace!("Num of remote messages {}", remote_messages.len());

    assert!(
        remote_messages.len() >= 5,
        "The number of remote messages should at least 5. Actual: {}",
        remote_messages.len()
    );

    for (index, message1) in remote_messages.iter().enumerate() {
        for message2 in remote_messages.iter().skip(index + 1) {
            if messages_are_equal(message1, message2)
                && payloads_are_equal(
                    message1.payload.as_ref().unwrap(),
                    message2.payload.as_ref().unwrap(),
                )
            {
                panic!(
                    "Duplicate remote message found with identifier {}",
                    message1.identifier
                );
            }
        }
    }
}
