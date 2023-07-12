use serde::{Deserialize, Serialize};

use std::panic::PanicInfo;
use std::path::Path;

use std::str::FromStr;
use std::sync::{Arc, Mutex as SyncMutex};
use std::{
    collections::HashMap,
    fs::{remove_file, File},
    io::{BufReader, Write},
};
use std::{fs, panic};
use tracing::{info, trace, warn};

use graphcast_sdk::graphcast_agent::message_typing::GraphcastMessage;

use crate::operator::attestation::{
    clear_local_attestation, ComparisonResult, ComparisonResultType,
};
use crate::operator::notifier::Notifier;
use crate::RADIO_OPERATOR;

use crate::{messages::poi::PublicPoiMessage, operator::attestation::Attestation};

type Local = Arc<SyncMutex<HashMap<String, HashMap<u64, Attestation>>>>;
type Remote = Arc<SyncMutex<Vec<GraphcastMessage<PublicPoiMessage>>>>;
type ComparisonResults = Arc<SyncMutex<HashMap<String, ComparisonResult>>>;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PersistedState {
    pub local_attestations: Local,
    pub remote_messages: Remote,
    pub comparison_results: ComparisonResults,
}

impl PersistedState {
    pub fn new(
        local: Option<Local>,
        remote: Option<Remote>,
        comparison_results: Option<ComparisonResults>,
    ) -> PersistedState {
        let local_attestations = local.unwrap_or(Arc::new(SyncMutex::new(HashMap::new())));
        let remote_messages = remote.unwrap_or(Arc::new(SyncMutex::new(vec![])));
        let comparison_results =
            comparison_results.unwrap_or(Arc::new(SyncMutex::new(HashMap::new())));

        PersistedState {
            local_attestations,
            remote_messages,
            comparison_results,
        }
    }

    /// Optional updates for either local_attestations, remote_messages or comparison_results without requiring either to be in-scope
    pub async fn update(
        &mut self,
        local_attestations: Option<Local>,
        remote_messages: Option<Remote>,
        comparison_results: Option<ComparisonResults>,
    ) -> PersistedState {
        let local_attestations = match local_attestations {
            None => self.local_attestations.clone(),
            Some(l) => l,
        };
        let remote_messages = match remote_messages {
            None => self.remote_messages.clone(),
            Some(r) => r,
        };
        let comparison_results = match comparison_results {
            None => self.comparison_results.clone(),
            Some(r) => r,
        };
        PersistedState {
            local_attestations,
            remote_messages,
            comparison_results,
        }
    }

    /// Getter for local_attestations
    pub fn local_attestations(&self) -> HashMap<String, HashMap<u64, Attestation>> {
        self.local_attestations.lock().unwrap().clone()
    }

    /// Getter for one local_attestation
    pub fn local_attestation(&self, deployment: String, block_number: u64) -> Option<Attestation> {
        match self.local_attestations.lock().unwrap().get(&deployment) {
            None => None,
            Some(blocks_map) => blocks_map.get(&block_number).cloned(),
        }
    }

    /// Getter for remote_messages
    pub fn remote_messages(&self) -> Vec<GraphcastMessage<PublicPoiMessage>> {
        self.remote_messages.lock().unwrap().clone()
    }

    /// Getter for comparison_results
    pub fn comparison_results(&self) -> HashMap<String, ComparisonResult> {
        self.comparison_results.lock().unwrap().clone()
    }

    /// Getter for comparison result
    pub fn comparison_result(&self, deployment: String) -> Option<ComparisonResult> {
        self.comparison_results
            .lock()
            .unwrap()
            .get(&deployment)
            .cloned()
    }

    /// Update local_attestations
    pub async fn update_local(&mut self, local_attestations: Local) {
        self.local_attestations = local_attestations;
    }

    /// Update remote_messages
    pub async fn update_remote(
        &mut self,
        remote_messages: Vec<GraphcastMessage<PublicPoiMessage>>,
    ) -> Vec<GraphcastMessage<PublicPoiMessage>> {
        self.remote_messages = Arc::new(SyncMutex::new(remote_messages));
        self.remote_messages()
    }

    /// Add message to remote_messages
    /// Generalize PublicPoiMessage
    pub fn add_remote_message(&self, msg: GraphcastMessage<PublicPoiMessage>) {
        trace!(msg = tracing::field::debug(&msg), "adding remote message");
        self.remote_messages.lock().unwrap().push(msg)
    }

    /// Add entry to comparison_results
    pub fn add_comparison_result(&self, comparison_result: ComparisonResult) {
        let deployment = comparison_result.clone().deployment;

        self.comparison_results
            .lock()
            .unwrap()
            .insert(deployment, comparison_result);
    }

    pub async fn valid_ppoi_messages(
        &mut self,
        graph_node_endpoint: &str,
    ) -> Vec<GraphcastMessage<PublicPoiMessage>> {
        let remote_messages = self.remote_messages();
        let mut valid_messages = vec![];

        for message in remote_messages {
            let is_valid = message
                .payload
                .validity_check(&message, graph_node_endpoint)
                .await;

            if is_valid.is_ok() {
                valid_messages.push(message);
            }
        }

        self.update_remote(valid_messages).await
    }

    pub async fn handle_comparison_result(
        &self,
        new_comparison_result: ComparisonResult,
        notifier: Notifier,
    ) -> ComparisonResultType {
        let (should_notify, updated_comparison_result, result_type) = {
            let mut results = self.comparison_results.lock().unwrap();
            let deployment = &new_comparison_result.deployment;

            let current_result = results.get(deployment).cloned();

            let result_type = if !results.contains_key(deployment) {
                results.insert(deployment.clone(), new_comparison_result.clone());
                new_comparison_result.result_type
            } else {
                match &current_result {
                    Some(current_result)
                        if current_result.result_type != new_comparison_result.result_type
                            && new_comparison_result.result_type
                                != ComparisonResultType::NotFound =>
                    {
                        results.insert(deployment.clone(), new_comparison_result.clone());
                        new_comparison_result.result_type
                    }
                    Some(current_result) => {
                        if let ComparisonResultType::Match | ComparisonResultType::NotFound =
                            new_comparison_result.result_type
                        {
                            results.insert(deployment.clone(), new_comparison_result.clone());
                        }
                        current_result.result_type
                    }
                    None => {
                        results.insert(deployment.clone(), new_comparison_result.clone());
                        new_comparison_result.result_type
                    }
                }
            };

            let should_notify = result_type != ComparisonResultType::NotFound;

            (should_notify, new_comparison_result.clone(), result_type)
        };

        if should_notify {
            notifier.notify(updated_comparison_result.to_string()).await;
        }

        result_type
    }

    /// Clean remote_messages
    pub fn clean_remote_messages(&self, block_number: u64, deployment: String) {
        trace!(
            msgs = tracing::field::debug(&self.remote_messages.lock().unwrap()),
            "cleaning these messages"
        );
        self.remote_messages
            .lock()
            .unwrap()
            .retain(|msg| msg.payload.block_number >= block_number || msg.identifier != deployment)
    }

    /// Clean local_attestations
    // TODO: Refactor with attestations operations
    pub fn clean_local_attestations(&self, block_number: u64, ipfs_hash: String) {
        clear_local_attestation(self.local_attestations.clone(), ipfs_hash, block_number)
    }

    /// Update file cache
    pub fn update_cache(&self, path: &str) {
        // Attempt to serialize state to JSON
        let state_json = serde_json::to_string(&self.clone())
            .unwrap_or_else(|_| "Could not serialize state to JSON".to_owned());

        let path = Path::new(path);

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        // Write state to file
        let mut file = File::create(path).unwrap();
        file.write_all(state_json.as_bytes()).unwrap();
    }

    /// Load cache into persisted state
    pub fn load_cache(path: &str) -> PersistedState {
        info!(path, "load cache from path");
        let file = match File::open(path) {
            Ok(f) => f,
            Err(e) => {
                warn!(
                    err = tracing::field::debug(&e),
                    "No persisted state file provided, create an empty state"
                );
                // No state persisted, create new
                let state = PersistedState::new(None, None, None);
                state.update_cache(path);
                return state;
            }
        };

        let reader: BufReader<File> = BufReader::new(file);
        let state: PersistedState = match serde_json::from_reader(reader) {
            Ok(s) => s,
            Err(e) => {
                // Persisted state can't be parsed, create a new one
                warn!(
                    err = e.to_string(),
                    "Could not parse persisted state file, created an empty state",
                );
                PersistedState::new(None, None, None)
            }
        };
        state
    }

    /// Clean up
    pub fn delete_cache(path: &str) {
        _ = remove_file(path);
    }
}

// TODO: panic hook for updating the cache file before exiting the program
/// Set up panic hook to store persisted state
pub fn panic_hook(file_path: &str) {
    let path = String::from_str(file_path).expect("Invalid file path provided");
    panic::set_hook(Box::new(move |panic_info| panic_cache(panic_info, &path)));
}

pub fn panic_cache(panic_info: &PanicInfo<'_>, file_path: &str) {
    RADIO_OPERATOR
        .get()
        .unwrap()
        .state()
        .update_cache(file_path);
    // Log panic information and program state
    eprintln!("Panic occurred! Panic info: {:?}", panic_info);
}

#[cfg(test)]
mod tests {
    use super::*;
    use graphcast_sdk::networks::NetworkName;

    use crate::operator::attestation::{save_local_attestation, ComparisonResultType};

    /// Tests for load, update, and store cache
    #[tokio::test]
    async fn test_state_cache() {
        let path = "test-state.json";
        PersistedState::delete_cache(path);

        let mut state = PersistedState::load_cache(path);
        assert!(state.local_attestations().is_empty());
        assert!(state.remote_messages().is_empty());
        assert!(state.comparison_results().is_empty());

        let local_attestations = Arc::new(SyncMutex::new(HashMap::new()));
        let messages = Arc::new(SyncMutex::new(Vec::new()));
        let comparison_results = Arc::new(SyncMutex::new(HashMap::new()));

        save_local_attestation(
            local_attestations.clone(),
            "npoi-x".to_string(),
            "0xa1".to_string(),
            0,
        );

        save_local_attestation(
            local_attestations.clone(),
            "npoi-y".to_string(),
            "0xa1".to_string(),
            1,
        );

        save_local_attestation(
            local_attestations.clone(),
            "npoi-z".to_string(),
            "0xa2".to_string(),
            2,
        );

        let test_comparison_result = ComparisonResult {
            deployment: "test_deployment".to_string(),
            block_number: 42,
            result_type: ComparisonResultType::Match,
            local_attestation: None,
            attestations: vec![],
        };
        comparison_results
            .lock()
            .unwrap()
            .insert("test_deployment".to_string(), test_comparison_result);

        let hash: String = "QmWECgZdP2YMcV9RtKU41GxcdW8EGYqMNoG98ubu5RGN6U".to_string();
        let content: String =
            "0xa6008cea5905b8b7811a68132feea7959b623188e2d6ee3c87ead7ae56dd0eae".to_string();
        let nonce: i64 = 123321;
        let block_number: u64 = 0;
        let block_hash: String = "0xblahh".to_string();
        let radio_msg = PublicPoiMessage::build(
            hash.clone(),
            content,
            nonce,
            NetworkName::Goerli,
            block_number,
            block_hash,
            String::from("0xe9a1cabd57700b17945fd81feefba82340d9568f"),
        );
        let sig: String = "4be6a6b7f27c4086f22e8be364cbdaeddc19c1992a42b08cbe506196b0aafb0a68c8c48a730b0e3155f4388d7cc84a24b193d091c4a6a4e8cd6f1b305870fae61b".to_string();
        let msg = GraphcastMessage::new(
            hash,
            nonce,
            String::from("0xe9a1cabd57700b17945fd81feefba82340d9568f"),
            radio_msg,
            sig,
        )
        .expect("Shouldn't get here since the message is purposefully constructed for testing");
        messages.lock().unwrap().push(msg);

        state = state
            .update(
                Some(local_attestations.clone()),
                Some(messages.clone()),
                Some(comparison_results.clone()),
            )
            .await;
        state.update_cache(path);

        let state = PersistedState::load_cache(path);
        assert_eq!(state.remote_messages.lock().unwrap().len(), 1);
        assert!(!state.local_attestations.lock().unwrap().is_empty());
        assert!(state.local_attestations.lock().unwrap().len() == 2);
        assert!(
            state
                .local_attestations
                .lock()
                .unwrap()
                .get("0xa1")
                .unwrap()
                .len()
                == 2
        );
        assert!(
            state
                .local_attestations
                .lock()
                .unwrap()
                .get("0xa2")
                .unwrap()
                .len()
                == 1
        );
        assert!(
            state
                .local_attestations
                .lock()
                .unwrap()
                .get("0xa1")
                .unwrap()
                .get(&0)
                .unwrap()
                .npoi
                == *"npoi-x"
        );

        assert_eq!(state.comparison_results.lock().unwrap().len(), 1);
        assert_eq!(
            state
                .comparison_results
                .lock()
                .unwrap()
                .get("test_deployment")
                .unwrap()
                .block_number,
            42
        );
        assert_eq!(
            state
                .comparison_results
                .lock()
                .unwrap()
                .get("test_deployment")
                .unwrap()
                .result_type,
            ComparisonResultType::Match
        );

        PersistedState::delete_cache(path);
    }

    #[tokio::test]
    async fn handle_comparison_result_new_deployment() {
        let notifier = Notifier::new("not-a-real-radio".to_string(), None, None, None, None, None);
        let local_attestations = Arc::new(SyncMutex::new(HashMap::new()));
        let remote_messages = Arc::new(SyncMutex::new(Vec::new()));
        let comparison_results = Arc::new(SyncMutex::new(HashMap::new()));
        let state = PersistedState {
            local_attestations,
            remote_messages,
            comparison_results,
        };

        let new_result = ComparisonResult {
            deployment: String::from("new_deployment"),
            block_number: 1,
            result_type: ComparisonResultType::Match,
            local_attestation: None,
            attestations: Vec::new(),
        };

        state.handle_comparison_result(new_result, notifier).await;

        let comparison_results = state.comparison_results.lock().unwrap();
        assert!(comparison_results.contains_key(&String::from("new_deployment")));
    }

    #[tokio::test]
    async fn handle_comparison_result_change_result_type() {
        let notifier = Notifier::new("not-a-real-radio".to_string(), None, None, None, None, None);
        let local_attestations = Arc::new(SyncMutex::new(HashMap::new()));
        let remote_messages = Arc::new(SyncMutex::new(Vec::new()));
        let comparison_results = Arc::new(SyncMutex::new(HashMap::new()));
        let state = PersistedState {
            local_attestations,
            remote_messages,
            comparison_results,
        };

        let old_result = ComparisonResult {
            deployment: String::from("existing_deployment"),
            block_number: 1,
            result_type: ComparisonResultType::Match,
            local_attestation: None,
            attestations: Vec::new(),
        };

        let new_result = ComparisonResult {
            deployment: String::from("existing_deployment"),
            block_number: 1,
            result_type: ComparisonResultType::Divergent,
            local_attestation: None,
            attestations: Vec::new(),
        };

        state
            .comparison_results
            .lock()
            .unwrap()
            .insert(String::from("existing_deployment"), old_result.clone());
        state.handle_comparison_result(new_result, notifier).await;

        let comparison_results = state.comparison_results.lock().unwrap();
        let result = comparison_results
            .get(&String::from("existing_deployment"))
            .unwrap();
        assert_eq!(result.result_type, ComparisonResultType::Divergent);
    }
}
