use async_graphql::{Context, EmptyMutation, EmptySubscription, Object, Schema};
use graphcast_sdk::graphcast_agent::message_typing::GraphcastMessage;
use std::sync::Arc;
use tokio::sync::Mutex as AsyncMutex;

use crate::attestation::{attestations_to_vec, AttestationEntry, LocalAttestationsMap};
use crate::{RadioPayloadMessage, MESSAGES};

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
    ) -> Result<Vec<AttestationEntry>, anyhow::Error> {
        let attestations = &ctx.data_unchecked::<Arc<AsyncMutex<LocalAttestationsMap>>>();
        let local = attestations_to_vec(attestations).await;

        Ok(local)
    }

    async fn local_attestations_by_deployment(
        &self,
        ctx: &Context<'_>,
        identifier: String,
    ) -> Result<Vec<AttestationEntry>, anyhow::Error> {
        let attestations = &ctx.data_unchecked::<Arc<AsyncMutex<LocalAttestationsMap>>>();
        let filtered = attestations_to_vec(attestations)
            .await
            .into_iter()
            .filter(|entry| entry.deployment == identifier.clone())
            .collect::<Vec<_>>();

        Ok(filtered)
    }

    async fn local_attestations_by_deployment_block(
        &self,
        ctx: &Context<'_>,
        identifier: String,
        block: u64,
    ) -> Result<Vec<AttestationEntry>, anyhow::Error> {
        let attestations = &ctx.data_unchecked::<Arc<AsyncMutex<LocalAttestationsMap>>>();
        let filtered = attestations_to_vec(attestations)
            .await
            .into_iter()
            .filter(|entry| entry.deployment == identifier.clone() && entry.block_number == block)
            .collect::<Vec<_>>();

        Ok(filtered)
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
