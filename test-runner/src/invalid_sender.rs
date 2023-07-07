use graphcast_sdk::graphcast_agent::message_typing::IdentityValidation;
use poi_radio::state::PersistedState;
use test_utils::{
    config::{test_config, TestSenderConfig},
    setup, teardown,
};
use tokio::time::{sleep, Duration};
use tracing::debug;

pub async fn invalid_sender_test() {
    let test_file_name = "invalid_sender";
    let store_path = format!("./test-runner/state/{}.json", test_file_name);

    let radio_topics = vec!["Qmdefault1AbcDEFghijKLmnoPQRstUVwxYzABCDEFghijklmnopq".to_string()];

    let test_sender_topics =
        vec!["Qmdefault1AbcDEFghijKLmnoPQRstUVwxYzABCDEFghijklmnopq".to_string()];

    let mut config = test_config();
    config.persistence_file_path = Some(store_path.clone());
    config.topics = radio_topics.clone();
    config.id_validation = IdentityValidation::RegisteredIndexer;

    let mut test_sender_config = TestSenderConfig {
        topics: test_sender_topics,
        radio_name: String::new(),
        block_hash: None,
        staked_tokens: Some("1".to_string()),
        nonce: None,
        radio_payload: None,
        poi: None,
    };

    let process_manager = setup(&config, test_file_name, &mut test_sender_config).await;

    sleep(Duration::from_secs(89)).await;

    let persisted_state = PersistedState::load_cache(&store_path);
    debug!("persisted state {:?}", persisted_state);

    teardown(process_manager, &store_path);

    let remote_messages = persisted_state.remote_messages();
    assert!(
        remote_messages.is_empty(),
        "Remote messages should be empty"
    );
}
