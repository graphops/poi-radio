use async_graphql::{Context, EmptyMutation, EmptySubscription, Object, Schema};
use graphcast_sdk::graphcast_agent::message_typing::GraphcastMessage;
use std::sync::Arc;
use tokio::sync::Mutex as AsyncMutex;
use tracing::debug;

use crate::attestation::{
    attestations_to_vec, compare_attestations, process_messages, AttestationEntry,
    AttestationError, ComparisonResult, LocalAttestationsMap,
};
use crate::{RadioPayloadMessage, CONFIG, MESSAGES};

pub(crate) type POIRadioSchema = Schema<QueryRoot, EmptyMutation, EmptySubscription>;

// Unified query object for resolvers
#[derive(Default)]
pub struct QueryRoot;

#[Object]
impl QueryRoot {
    async fn radio_payload_messages(
        &self,
        _ctx: &Context<'_>,
    ) -> Result<Vec<GraphcastMessage<RadioPayloadMessage>>, anyhow::Error> {
        Ok(MESSAGES.get().unwrap().lock().unwrap().to_vec())
    }

    async fn radio_payload_messages_by_deployment(
        &self,
        _ctx: &Context<'_>,
        identifier: String,
    ) -> Result<Vec<GraphcastMessage<RadioPayloadMessage>>, anyhow::Error> {
        Ok(MESSAGES
            .get()
            .unwrap()
            .lock()
            .unwrap()
            .iter()
            .cloned()
            .filter(|message| message.identifier == identifier.clone())
            .collect::<Vec<_>>())
    }

    async fn local_attestations(
        &self,
        ctx: &Context<'_>,
        identifier: Option<String>,
        block: Option<u64>,
    ) -> Result<Vec<AttestationEntry>, anyhow::Error> {
        let attestations = &ctx.data_unchecked::<Arc<AsyncMutex<LocalAttestationsMap>>>();
        let filtered = attestations_to_vec(attestations)
            .await
            .into_iter()
            .filter(|entry| filter_fn(entry, &identifier, &block))
            .collect::<Vec<_>>();

        Ok(filtered)
    }

    // TODO: Reproduce tabular summary view. use process_message and compare_attestations
    async fn comparison_results(
        &self,
        ctx: &Context<'_>,
        deployment: Option<String>,
        block: Option<u64>,
    ) -> Result<Vec<ComparisonResult>, anyhow::Error> {
        // Utilize the provided filters on local_attestations
        let locals = match self.local_attestations(ctx, deployment, block).await {
            Ok(r) => r,
            Err(e) => return Err(e),
        };

        let mut res = vec![];
        for entry in locals {
            let r = self
                .comparison_result(ctx, entry.deployment, entry.block_number)
                .await;
            // Return err if just one has err? (ignored for now)
            if r.is_ok() {
                res.push(r.unwrap());
            }
        }

        Ok(res)
    }

    async fn comparison_result(
        &self,
        ctx: &Context<'_>,
        deployment: String,
        block: u64,
    ) -> Result<ComparisonResult, AttestationError> {
        let local_attestations = &ctx.data_unchecked::<Arc<AsyncMutex<LocalAttestationsMap>>>();
        let filter_msg: Vec<GraphcastMessage<RadioPayloadMessage>> = MESSAGES
            .get()
            .unwrap()
            .lock()
            .unwrap()
            .iter()
            .filter(|&m| m.block_number == block)
            .cloned()
            .collect();

        let registry_subgraph = CONFIG
            .get()
            .unwrap()
            .lock()
            .unwrap()
            .registry_subgraph
            .clone();
        let network_subgraph = CONFIG
            .get()
            .unwrap()
            .lock()
            .unwrap()
            .network_subgraph
            .clone();
        let remote_attestations_result =
            process_messages(filter_msg, &registry_subgraph, &network_subgraph).await;
        let remote_attestations = match remote_attestations_result {
            Ok(remote) => {
                debug!(
                    "Processed message\n{}: {}",
                    "Number of unique remote POIs",
                    remote.len(),
                );
                remote
            }
            Err(err) => {
                debug!(
                    "{}",
                    format!("{}{}", "An error occured while parsing messages: {}", err)
                );
                return Err(err);
            }
        };
        let comparison_result = compare_attestations(
            block,
            remote_attestations,
            Arc::clone(local_attestations),
            &deployment.clone(),
        )
        .await;

        Ok(comparison_result)
    }
}

pub async fn build_schema(ctx: Arc<POIRadioContext>) -> POIRadioSchema {
    Schema::build(QueryRoot, EmptyMutation, EmptySubscription)
        .data(Arc::clone(&ctx.local_attestations))
        .finish()
}

pub struct POIRadioContext {
    pub local_attestations: Arc<AsyncMutex<LocalAttestationsMap>>,
}

impl POIRadioContext {
    pub async fn init(local_attestations: Arc<AsyncMutex<LocalAttestationsMap>>) -> Self {
        Self { local_attestations }
    }

    pub async fn local_attestations(&self) -> LocalAttestationsMap {
        self.local_attestations.lock().await.clone()
    }
}

/// Filter funciton for Attestations on deployment and block
fn filter_fn(entry: &AttestationEntry, identifier: &Option<String>, block: &Option<u64>) -> bool {
    let is_matching_deployment = match identifier {
        Some(dep) => entry.deployment == dep.clone(),
        None => true, // Skip check
    };
    let is_matching_block = match block {
        Some(b) => entry.block_number == *b,
        None => true, // Skip check
    };
    is_matching_deployment && is_matching_block
}
