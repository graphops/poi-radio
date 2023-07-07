use poi_radio::{operator::attestation::ComparisonResultType, state::PersistedState};
use test_utils::{
    config::{test_config, TestSenderConfig},
    setup, teardown,
};
use tokio::time::{sleep, Duration};
use tracing::debug;

pub async fn poi_match_test() {
    let test_file_name = "poi_match";
    let store_path = format!("./test-runner/state/{}.json", test_file_name);

    let radio_topics = vec!["Qmdefault1AbcDEFghijKLmnoPQRstUVwxYzABCDEFghijklmnopq".to_string()];

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

    sleep(Duration::from_secs(550)).await;

    let persisted_state = PersistedState::load_cache(&store_path);
    debug!("persisted state {:?}", persisted_state);

    let comparison_results = persisted_state.comparison_results();

    assert!(
        !comparison_results.is_empty(),
        "The comparison results should not be empty"
    );

    let has_match_result = comparison_results.iter().any(|result| {
        result.1.deployment == "Qmdefault1AbcDEFghijKLmnoPQRstUVwxYzABCDEFghijklmnopq"
            && result.1.result_type == ComparisonResultType::Match
    });

    assert!(
        has_match_result,
        "No comparison result found with deployment 'Qmdefault1AbcDEFghijKLmnoPQRstUVwxYzABCDEFghijklmnopq' and result type 'Match'"
    );

    teardown(process_manager, &store_path);
}
