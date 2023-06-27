use poi_radio::state::PersistedState;
use test_utils::{
    config::{test_config, TestSenderConfig},
    dummy_msg::DummyMsg,
    setup, teardown,
};
use tokio::time::{sleep, Duration};
use tracing::debug;

pub async fn invalid_payload_test() {
    let test_file_name = "invalid_payload";
    let store_path = format!("./test-runner/state/{}.json", test_file_name);

    let radio_topics = vec!["Qmdefault1AbcDEFghijKLmnoPQRstUVwxYzABCDEFghijklmnopq".to_string()];

    let test_sender_topics =
        vec!["Qmdefault1AbcDEFghijKLmnoPQRstUVwxYzABCDEFghijklmnopq".to_string()];

    let mut config = test_config();
    config.persistence_file_path = Some(store_path.clone());
    config.topics = radio_topics.clone();

    let dummy_radio_payload = DummyMsg::new("hello".to_string(), 42);

    let mut test_sender_config = TestSenderConfig {
        topics: test_sender_topics,
        radio_name: String::new(),
        block_hash: Some(
            "3071f4b00c2fc57c7f97d18e77b0e9c377cebae15959e6254b1a1d48a83b92e8".to_string(),
        ),
        staked_tokens: None,
        nonce: None,
        radio_payload: Some(DummyMsg::to_json(&dummy_radio_payload)),
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
