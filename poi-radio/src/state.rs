use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use std::sync::{Arc, Mutex as SyncMutex};
use std::{
    collections::HashMap,
    fs::{remove_file, File},
    io::{BufReader, Write},
};
use tracing::warn;

use graphcast_sdk::graphcast_agent::message_typing::GraphcastMessage;

use crate::operator::attestation::clear_local_attestation;
use crate::{operator::attestation::Attestation, RadioPayloadMessage};

type Local = Arc<SyncMutex<HashMap<String, HashMap<u64, Attestation>>>>;
type Remote = Arc<SyncMutex<Vec<GraphcastMessage<RadioPayloadMessage>>>>;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PersistedState {
    pub local_attestations: Local,
    pub remote_messages: Remote,
}

impl PersistedState {
    pub fn new(local: Option<Local>, remote: Option<Remote>) -> PersistedState {
        let local_attestations = local.unwrap_or(Arc::new(SyncMutex::new(HashMap::new())));
        let remote_messages = remote.unwrap_or(Arc::new(SyncMutex::new(vec![])));

        PersistedState {
            local_attestations,
            remote_messages,
        }
    }

    /// Optional updates for either local_attestations or remote_messages without requiring either to be in-scope
    pub async fn update(
        &mut self,
        local_attestations: Option<Local>,
        remote_messages: Option<Remote>,
    ) -> PersistedState {
        let local_attestations = match local_attestations {
            None => self.local_attestations.clone(),
            Some(l) => l,
        };
        let remote_messages = match remote_messages {
            None => self.remote_messages.clone(),
            Some(r) => r,
        };
        PersistedState {
            local_attestations,
            remote_messages,
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
    pub fn remote_messages(&self) -> Vec<GraphcastMessage<RadioPayloadMessage>> {
        self.remote_messages.lock().unwrap().clone()
    }

    /// Update local_attestations
    pub async fn update_local(&mut self, local_attestations: Local) {
        self.local_attestations = local_attestations;
    }

    /// Update remote_messages
    pub async fn update_remote(&mut self, remote_messages: Remote) {
        self.remote_messages = remote_messages;
    }

    /// Add message to remote_messages
    pub fn add_remote_message(&self, msg: GraphcastMessage<RadioPayloadMessage>) {
        self.remote_messages.lock().unwrap().push(msg)
    }

    /// Clean remote_messages
    pub fn clean_remote_messages(&self, block_number: u64, deployment: String) {
        self.remote_messages
            .lock()
            .unwrap()
            .retain(|msg| msg.block_number >= block_number || msg.identifier != deployment)
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
        let file = match File::open(path) {
            Ok(f) => f,
            Err(_) => {
                warn!("No persisted state file provided, create an empty state");
                // No state persisted, create new
                return PersistedState::new(None, None);
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
                PersistedState::new(None, None)
            }
        };
        state
    }

    /// Clean up
    pub fn delete_cache(path: &str) {
        _ = remove_file(path);
    }
}

//TODO: panic hook for updating the cache file before exiting the program
// /// Set up panic hook to store persisted state
// pub fn panic_hook<'a>(file_path: &str){
//     let path = String::from_str(file_path).expect("Invalid file path provided");
//     panic::set_hook(Box::new(move |panic_info| panic_cache(panic_info, &path)));
// }

// pub fn panic_cache(panic_info: &PanicInfo<'_>, file_path: &str) {
//     update_cache(file_path);
//     // Log panic information and program state
//     eprintln!("Panic occurred! Panic info: {:?}", panic_info);
// }

#[cfg(test)]
mod tests {
    use graphcast_sdk::networks::NetworkName;

    use crate::operator::attestation::save_local_attestation;

    use super::*;

    /// Tests for load, update, and store cache
    #[tokio::test]
    async fn test_state_cache() {
        let path = "test-state.json";
        PersistedState::delete_cache(path);

        let mut state = PersistedState::load_cache(path);
        assert!(state.local_attestations.lock().unwrap().is_empty());
        assert!(state.remote_messages.lock().unwrap().is_empty());

        let local_attestations = Arc::new(SyncMutex::new(HashMap::new()));
        let messages = Arc::new(SyncMutex::new(Vec::new()));
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

        let hash: String = "QmWECgZdP2YMcV9RtKU41GxcdW8EGYqMNoG98ubu5RGN6U".to_string();
        let content: String =
            "0xa6008cea5905b8b7811a68132feea7959b623188e2d6ee3c87ead7ae56dd0eae".to_string();
        let nonce: i64 = 123321;
        let block_number: u64 = 0;
        let block_hash: String = "0xblahh".to_string();
        let radio_msg = RadioPayloadMessage::new(hash.clone(), content);
        let sig: String = "4be6a6b7f27c4086f22e8be364cbdaeddc19c1992a42b08cbe506196b0aafb0a68c8c48a730b0e3155f4388d7cc84a24b193d091c4a6a4e8cd6f1b305870fae61b".to_string();
        let msg = GraphcastMessage::new(
            hash,
            Some(radio_msg),
            nonce,
            NetworkName::Goerli,
            block_number,
            block_hash,
            sig,
        )
        .expect("Shouldn't get here since the message is purposefully constructed for testing");
        messages.lock().unwrap().push(msg);

        state = state
            .update(Some(local_attestations.clone()), Some(messages.clone()))
            .await;
        state.update_cache(path);

        let state = PersistedState::load_cache(path);
        assert!(state.remote_messages.lock().unwrap().len() == 1);
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

        PersistedState::delete_cache(path);
    }
}
