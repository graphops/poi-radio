use async_graphql::{Context, EmptyMutation, EmptySubscription, Object, Schema, SimpleObject};
use chrono::Utc;

use std::{collections::HashMap, sync::Arc};
use thiserror::Error;

use crate::{
    config::Config,
    operator::attestation::{
        self, attestations_to_vec, compare_attestation, process_messages, Attestation,
        AttestationEntry, AttestationError, ComparisonResult, ComparisonResultType,
        LocalAttestationsMap,
    },
    state::PersistedState,
    RadioPayloadMessage,
};
use graphcast_sdk::{graphcast_agent::message_typing::GraphcastMessage, graphql::QueryError};

pub(crate) type POIRadioSchema = Schema<QueryRoot, EmptyMutation, EmptySubscription>;

// Unified query object for resolvers
#[derive(Default)]
pub struct QueryRoot;

#[Object]
impl QueryRoot {
    async fn radio_payload_messages(
        &self,
        ctx: &Context<'_>,
        identifier: Option<String>,
        block: Option<u64>,
    ) -> Result<Vec<GraphcastMessage<RadioPayloadMessage>>, HttpServiceError> {
        let msgs = ctx
            .data_unchecked::<Arc<POIRadioContext>>()
            .remote_messages_filtered(&identifier, &block);
        Ok(msgs)
    }

    async fn local_attestations(
        &self,
        ctx: &Context<'_>,
        identifier: Option<String>,
        block: Option<u64>,
    ) -> Result<Vec<AttestationEntry>, HttpServiceError> {
        let attestations = ctx
            .data_unchecked::<Arc<POIRadioContext>>()
            .local_attestations(identifier, block);
        let filtered = attestations_to_vec(&attestations);

        Ok(filtered)
    }

    /// Function that optionally takes in identifier and block filters.
    async fn comparison_results(
        &self,
        ctx: &Context<'_>,
        identifier: Option<String>,
        block: Option<u64>,
        result_type: Option<ComparisonResultType>,
    ) -> Result<Vec<ComparisonResult>, HttpServiceError> {
        let res = &ctx
            .data_unchecked::<Arc<POIRadioContext>>()
            .comparison_results(identifier, block, result_type)
            .await;

        Ok(res.to_vec())
    }

    /// Function to grab the latest relevant comparison result of a deployment
    async fn comparison_result(
        &self,
        ctx: &Context<'_>,
        identifier: String,
    ) -> Result<Option<ComparisonResult>, HttpServiceError> {
        let res = &ctx
            .data_unchecked::<Arc<POIRadioContext>>()
            .comparison_result(identifier);
        Ok(res.clone())
    }

    /// Return the sender ratio for remote attestations, with a "!" for the attestation matching local
    async fn comparison_ratio(
        &self,
        ctx: &Context<'_>,
        deployment: Option<String>,
        block: Option<u64>,
        result_type: Option<ComparisonResultType>,
    ) -> Result<Vec<CompareRatio>, HttpServiceError> {
        let res = self
            .comparison_results(ctx, deployment, block, result_type)
            .await?;
        let local_info = self.indexer_info(ctx).await?;

        let mut ratios = vec![];
        for r in res {
            // Double check for local attestations to ensure there will be no divide by 0 during the ratio
            let local_attestation = if let Some(local_attestation) = r.local_attestation {
                local_attestation
            } else {
                continue;
            };
            let local_npoi = local_attestation.npoi.clone();

            // Aggregate remote attestations with the local attestations
            let mut aggregated_attestations: Vec<Attestation> = vec![];
            for a in r.attestations {
                if a.npoi == local_attestation.npoi {
                    let updateed_attestation = attestation::Attestation::update(
                        &a,
                        local_info.address.clone(),
                        local_info.stake,
                        Utc::now().timestamp(),
                    );
                    if let Ok(updated_a) = updateed_attestation {
                        aggregated_attestations.push(updated_a);
                    } else {
                        continue;
                    }
                } else {
                    aggregated_attestations.push(a)
                }
            }
            let sender_ratio = sender_count_str(&aggregated_attestations, local_npoi.clone());
            let stake_ratio = stake_weight_str(&aggregated_attestations, local_npoi);
            ratios.push(CompareRatio::new(
                r.deployment,
                r.block_number,
                sender_ratio,
                stake_ratio,
            ));
        }
        Ok(ratios)
    }

    /// Return indexer info
    async fn indexer_info(&self, ctx: &Context<'_>) -> Result<IndexerInfo, HttpServiceError> {
        let config = ctx.data_unchecked::<Arc<POIRadioContext>>().radio_config();
        let basic_info = config
            .basic_info()
            .await
            .map_err(HttpServiceError::QueryError)?;
        Ok(IndexerInfo {
            address: basic_info.0,
            stake: basic_info.1,
        })
    }
}

/// Helper function to order attestations by stake weight and then find the number of unique senders
pub fn sender_count_str(attestations: &[Attestation], local_npoi: String) -> String {
    // Create a HashMap to store the attestation and senders
    let mut temp_attestations = attestations.to_owned();
    let mut output = String::new();

    // Sort the attestations by descending stake weight
    temp_attestations.sort_by(|a, b| b.stake_weight.cmp(&a.stake_weight));
    // Iterate through the attestations and populate the maps
    // No set is needed since uniqueness is garuanteeded by validation
    for att in attestations.iter() {
        let separator = if att.npoi == local_npoi { "*:" } else { ":" };

        output.push_str(&format!("{}{}", att.senders.len(), separator));
    }

    output.pop(); // Remove the trailing ':'

    output
}

/// Helper function to order attestations by stake weight and then find the number of unique senders
pub fn stake_weight_str(attestations: &[Attestation], local_npoi: String) -> String {
    // Create a HashMap to store the attestation and senders
    let mut temp_attestations = attestations.to_owned();
    let mut output = String::new();

    // Sort the attestations by descending stake weight
    temp_attestations.sort_by(|a, b| b.stake_weight.cmp(&a.stake_weight));
    // Iterate through the attestations and populate the maps
    // No set is needed since uniqueness is garuanteeded by validation
    for att in attestations.iter() {
        let separator = if att.npoi == local_npoi { "*:" } else { ":" };
        output.push_str(&format!("{}{}", att.stake_weight, separator));
    }

    output.pop(); // Remove the trailing ':'
    output
}

pub async fn build_schema(ctx: Arc<POIRadioContext>) -> POIRadioSchema {
    Schema::build(QueryRoot, EmptyMutation, EmptySubscription)
        .data(ctx.persisted_state)
        .finish()
}

pub struct POIRadioContext {
    pub radio_config: Config,
    pub persisted_state: &'static PersistedState,
}

impl POIRadioContext {
    pub fn init(radio_config: Config, persisted_state: &'static PersistedState) -> Self {
        Self {
            radio_config,
            persisted_state,
        }
    }

    pub fn local_attestations(
        &self,
        identifier: Option<String>,
        block: Option<u64>,
    ) -> LocalAttestationsMap {
        let attestations = self.persisted_state.local_attestations();
        let mut empty_attestations: LocalAttestationsMap = HashMap::new();

        if let Some(deployment) = identifier {
            if let Some(deployment_attestations) = attestations.get(&deployment) {
                if let Some(block) = block {
                    if let Some(attestation) = deployment_attestations.get(&block) {
                        let single_entry = (block, attestation.clone());
                        let inner_map = vec![single_entry].into_iter().collect();

                        vec![(deployment, inner_map)].into_iter().collect()
                    } else {
                        // Return empty hashmap if no entry satisfy the supplied identifier and block
                        empty_attestations
                    }
                } else {
                    // Return all blocks since no block was specified
                    empty_attestations.insert(deployment, deployment_attestations.clone());
                    empty_attestations
                }
            } else {
                empty_attestations
            }
        } else {
            attestations
        }
    }

    pub fn remote_messages(&self) -> Vec<GraphcastMessage<RadioPayloadMessage>> {
        self.persisted_state.remote_messages()
    }

    pub fn remote_messages_filtered(
        &self,
        identifier: &Option<String>,
        block: &Option<u64>,
    ) -> Vec<GraphcastMessage<RadioPayloadMessage>> {
        let msgs = self.remote_messages();
        let filtered = msgs
            .iter()
            .cloned()
            .filter(|message| filter_remote_messages(message, identifier, block))
            .collect::<Vec<_>>();
        filtered
    }

    pub fn comparison_result(&self, identifier: String) -> Option<ComparisonResult> {
        let cmp_results = self.persisted_state.comparison_results();
        cmp_results.get(&identifier).cloned()
    }

    pub async fn comparison_results(
        &self,
        identifier: Option<String>,
        block: Option<u64>,
        result_type: Option<ComparisonResultType>,
    ) -> Vec<ComparisonResult> {
        // Simply take from persisted state if block is not specified
        if block.is_none() {
            let cmp_results = self.persisted_state.comparison_results();

            cmp_results
                .iter()
                .filter(|&(deployment, cmp_res)| {
                    (identifier.is_none() | (Some(deployment.clone()) == identifier))
                        && (result_type.is_none() | (Some(cmp_res.result_type) == result_type))
                })
                .map(|(_, cmp_res)| cmp_res.clone())
                .collect::<Vec<ComparisonResult>>()
        } else {
            // Calculate for the block if specified
            let locals = attestations_to_vec(&self.local_attestations(identifier.clone(), block));

            let config = self.radio_config();
            let network_subgraph = config.network_subgraph.clone();

            let mut res = vec![];
            for entry in locals {
                let deployment_identifier = entry.deployment.clone();
                let msgs = self.remote_messages_filtered(&identifier, &block);
                let remote_attestations = process_messages(msgs, &network_subgraph)
                    .await
                    .ok()
                    .and_then(|r| {
                        r.get(&deployment_identifier)
                            .and_then(|deployment_attestations| {
                                deployment_attestations.get(&entry.block_number).cloned()
                            })
                    })
                    .unwrap_or_default();

                let r = compare_attestation(entry, remote_attestations);
                if result_type.is_none() | (result_type.unwrap() == r.result_type) {
                    res.push(r);
                }
            }

            res
        }
    }

    pub fn radio_config(&self) -> Config {
        self.radio_config.clone()
    }
}

/// Filter funciton for Attestations on deployment and block
fn filter_remote_messages(
    entry: &GraphcastMessage<RadioPayloadMessage>,
    identifier: &Option<String>,
    block: &Option<u64>,
) -> bool {
    let is_matching_identifier = match identifier {
        Some(id) => entry.identifier == id.clone(),
        None => true, // Skip check
    };
    let is_matching_block = match block {
        Some(b) => entry.block_number == *b,
        None => true, // Skip check
    };
    is_matching_identifier && is_matching_block
}

#[derive(Debug, PartialEq, Eq, Hash, SimpleObject)]
struct CompareRatio {
    deployment: String,
    block_number: u64,
    sender_ratio: String,
    stake_ratio: String,
}

impl CompareRatio {
    fn new(
        deployment: String,
        block_number: u64,
        sender_ratio: String,
        stake_ratio: String,
    ) -> Self {
        CompareRatio {
            deployment,
            block_number,
            sender_ratio,
            stake_ratio,
        }
    }
}

#[derive(Debug, PartialEq, SimpleObject)]
struct IndexerInfo {
    address: String,
    stake: f32,
}

#[derive(Error, Debug)]
pub enum HttpServiceError {
    #[error("Service processing failed: {0}")]
    AttestationError(AttestationError),
    #[error("Missing requested data: {0}")]
    MissingData(String),
    #[error("Query failed: {0}")]
    QueryError(QueryError),
    // Below ones are not used yet
    #[error("HTTP request failed: {0}")]
    RequestFailed(String),
    #[error("HTTP response error: {0}")]
    ResponseError(String),
    #[error("Timeout error")]
    TimeoutError,
    #[error("Invalid URL: {0}")]
    InvalidUrl(String),
    #[error("HTTP client error: {0}")]
    HttpClientError(#[from] reqwest::Error),
}
