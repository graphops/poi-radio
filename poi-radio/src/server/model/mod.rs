use async_graphql::{
    Context, EmptyMutation, EmptySubscription, InputObject, Object, Schema, SimpleObject,
};

use std::{collections::HashMap, sync::Arc};
use thiserror::Error;

use crate::{
    config::Config,
    operator::attestation::{
        attestations_to_vec, compare_attestation, process_messages, Attestation, AttestationEntry,
        AttestationError, ComparisonResult, ComparisonResultType, LocalAttestationsMap,
    },
    state::PersistedState,
    RadioPayloadMessage,
};
use graphcast_sdk::graphcast_agent::message_typing::GraphcastMessage;

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
            .remote_messages();
        let filtered = msgs
            .iter()
            .cloned()
            .filter(|message| filter_remote_messages(message, &identifier, &block))
            .collect::<Vec<_>>();
        Ok(filtered)
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

    // TODO: Reproduce tabular summary view. use process_message and compare_attestations
    async fn comparison_results(
        &self,
        ctx: &Context<'_>,
        deployment: Option<String>,
        block: Option<u64>,
        _filter: Option<ResultFilter>,
    ) -> Result<Vec<ComparisonResult>, HttpServiceError> {
        // Utilize the provided filters on local_attestations
        let locals = attestations_to_vec(
            &ctx.data_unchecked::<Arc<POIRadioContext>>()
                .local_attestations(deployment.clone(), block),
        );

        let config = ctx.data_unchecked::<Arc<POIRadioContext>>().radio_config();
        let registry_subgraph = config.registry_subgraph.clone();
        let network_subgraph = config.network_subgraph.clone();

        let mut res = vec![];
        for entry in locals {
            let deployment_identifier = entry.deployment.clone();
            let msgs = self
                .radio_payload_messages(
                    ctx,
                    Some(deployment_identifier.clone()),
                    Some(entry.block_number),
                )
                .await?;
            let remote_attestations =
                match process_messages(msgs, &registry_subgraph, &network_subgraph).await {
                    Ok(r) => {
                        if let Some(deployment_attestations) = r.get(&deployment_identifier.clone())
                        {
                            if let Some(deployment_block_attestations) =
                                deployment_attestations.get(&entry.block_number)
                            {
                                deployment_block_attestations.clone()
                            } else {
                                continue;
                            }
                        } else {
                            continue;
                        }
                    }
                    Err(_e) => continue,
                };

            let r = compare_attestation(entry, remote_attestations);
            res.push(r);
        }

        // let remote_attestations =
        //     process_messages(msgs, &registry_subgraph, &network_subgraph).await?;
        // let comparison_result =
        //     compare_attestations(deployment, remote_attestations, &locals, block).await;

        Ok(res)
    }

    // async fn comparison_result(
    //     &self,
    //     ctx: &Context<'_>,
    //     deployment: String,
    //     block: u64,
    // ) -> Result<ComparisonResult, HttpServiceError> {
    //     let config = ctx.data_unchecked::<Arc<POIRadioContext>>().radio_config();
    //     let msgs = self
    //         .radio_payload_messages(ctx, Some(deployment.clone()), Some(block))
    //         .await?;
    //     let local_attestations = self
    //         .local_attestations(ctx, Some(deployment.clone()), Some(block))
    //         .await?;

    //     let registry_subgraph = config.registry_subgraph.clone();
    //     let network_subgraph = config.network_subgraph.clone();

    //     let remote_attestations =
    //         match process_messages(msgs, &registry_subgraph, &network_subgraph).await {
    //             Ok(remote) => remote,
    //             Err(err) => {
    //                 debug!(
    //                     err = tracing::field::debug(&err),
    //                     "An error occured while parsing messages"
    //                 );
    //                 return Err(err);
    //             }
    //         };
    //     let comparison_result =
    //         compare_attestation(remote_attestations, local_attestations, deployment, block).await;
    //     Ok(comparison_result)
    // }

    /// Return the sender ratio for remote attestations, with a "!" for the attestation matching local
    async fn comparison_ratio(
        &self,
        ctx: &Context<'_>,
        deployment: Option<String>,
        block: Option<u64>,
        filter: Option<ResultFilter>,
    ) -> Result<Vec<CompareRatio>, anyhow::Error> {
        let res = self
            .comparison_results(ctx, deployment, block, filter)
            .await?;
        let mut ratios = vec![];
        for r in res {
            let npoi = r
                .local_attestation
                .map(|a| a.npoi)
                .unwrap_or_else(|| "None".to_string());
            let sender_ratio = sender_count_str(&r.attestations, npoi.clone());
            let stake_ratio = stake_weight_str(&r.attestations, npoi);
            ratios.push(CompareRatio::new(
                r.deployment,
                r.block_number,
                sender_ratio,
                stake_ratio,
            ));
        }
        Ok(ratios)
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
        let separator = if att.npoi == local_npoi { "!/" } else { "/" };

        output.push_str(&format!("{}{}", att.senders.len(), separator));
    }

    output.pop(); // Remove the trailing '/'

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

    output.pop(); // Remove the trailing '/'

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

#[derive(InputObject)]
struct ResultFilter {
    deployment: Option<String>,
    block_number: Option<u64>,
    result_type: Option<ComparisonResultType>,
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

#[derive(Error, Debug)]
pub enum HttpServiceError {
    #[error("Service processing failed: {0}")]
    AttestationError(AttestationError),
    #[error("Missing requested data: {0}")]
    MissingData(String),
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
