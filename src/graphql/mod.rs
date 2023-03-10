use graphql_client::{GraphQLQuery, Response};
use serde_derive::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::trace;

use poi_radio::SubgraphStatus;
// Maybe later on move graphql to SDK as the queries are pretty standarded
use graphcast_sdk::graphql::QueryError;
use graphcast_sdk::{BlockPointer, NetworkName};

/// Derived GraphQL Query to Proof of Indexing
#[derive(GraphQLQuery, Serialize, Deserialize, Debug)]
#[graphql(
    schema_path = "src/graphql/schema_graph_node.graphql",
    query_path = "src/graphql/query_proof_of_indexing.graphql",
    response_derives = "Debug, Serialize, Deserialize"
)]
pub struct ProofOfIndexing;

#[derive(GraphQLQuery, Serialize, Deserialize, Debug)]
#[graphql(
    schema_path = "src/graphql/schema_graph_node.graphql",
    query_path = "src/graphql/query_indexing_statuses.graphql",
    response_derives = "Debug, Serialize, Deserialize",
    normalization = "rust"
)]
pub struct IndexingStatuses;

#[derive(GraphQLQuery, Serialize, Deserialize, Debug)]
#[graphql(
    schema_path = "src/graphql/schema_graph_node.graphql",
    query_path = "src/graphql/query_block_hash_from_number.graphql",
    response_derives = "Debug, Serialize, Deserialize"
)]
pub struct BlockHashFromNumber;

/// Query graph node for Proof of Indexing
pub async fn perform_proof_of_indexing(
    graph_node_endpoint: String,
    variables: proof_of_indexing::Variables,
) -> Result<reqwest::Response, reqwest::Error> {
    let request_body = ProofOfIndexing::build_query(variables);
    let client = reqwest::Client::new();
    client
        .post(graph_node_endpoint)
        .json(&request_body)
        .send()
        .await?
        .error_for_status()
}

/// Construct GraphQL variables and parse result for Proof of Indexing.
/// For other radio use cases, provide a function that returns a string
pub async fn query_graph_node_poi(
    graph_node_endpoint: String,
    ipfs_hash: String,
    block_hash: String,
    block_number: i64,
) -> Result<String, QueryError> {
    let variables: proof_of_indexing::Variables = proof_of_indexing::Variables {
        subgraph: ipfs_hash.clone(),
        block_hash: block_hash.clone(),
        block_number,
        indexer: None,
    };
    let queried_result = perform_proof_of_indexing(graph_node_endpoint.clone(), variables).await?;
    let response_body: Response<proof_of_indexing::ResponseData> = queried_result.json().await?;

    if let Some(data) = response_body.data {
        match data.proof_of_indexing {
            Some(poi) => Ok(poi),
            _ => Err(QueryError::EmptyResponseError(
                "No POI returned".to_string(),
            )),
        }
    } else {
        Err(QueryError::EmptyResponseError(
            "No POI response from Graph Node".to_string(),
        ))
    }
}

/// Query graph node for Indexing Statuses
pub async fn perform_indexing_statuses(
    graph_node_endpoint: String,
    variables: indexing_statuses::Variables,
) -> Result<reqwest::Response, reqwest::Error> {
    let request_body = IndexingStatuses::build_query(variables);
    let client = reqwest::Client::new();
    client
        .post(graph_node_endpoint)
        .json(&request_body)
        .send()
        .await?
        .error_for_status()
}

/// Construct GraphQL variables and parse result for Proof of Indexing.
/// For other radio use cases, provide a function that returns a string
pub async fn update_network_chainheads(
    graph_node_endpoint: String,
    network_map: &mut HashMap<NetworkName, BlockPointer>,
) -> Result<HashMap<String, SubgraphStatus>, QueryError> {
    let variables: indexing_statuses::Variables = indexing_statuses::Variables {};
    let queried_result = perform_indexing_statuses(graph_node_endpoint.clone(), variables).await?;
    let response_body: Response<indexing_statuses::ResponseData> = queried_result.json().await?;

    // subgraph (network, latest blocks)
    let mut subgraph_network_blocks: HashMap<String, SubgraphStatus> = HashMap::new();

    let updated_networks = response_body
        .data
        .map(|data| {
            data.indexing_statuses
                .into_iter()
                .map(|status| {
                    status
                        .chains
                        .into_iter()
                        .map(|chain| {
                            let network_name = chain.network.clone();
                            let _chainhead_block = chain
                                .chain_head_block
                                .map(|blk| BlockPointer {
                                    hash: blk.hash,
                                    number: blk.number.as_str().parse::<u64>().unwrap_or_default(),
                                })
                                .map(|blk| {
                                    if let Some(block) = network_map
                                        .get_mut(&NetworkName::from_string(&network_name.clone()))
                                    {
                                        *block = blk.clone();
                                    } else {
                                        network_map
                                            .entry(NetworkName::from_string(&network_name.clone()))
                                            .or_insert(blk.clone());
                                    };
                                    blk
                                });

                            chain
                                .latest_block
                                .map(|blk| BlockPointer {
                                    hash: blk.hash,
                                    number: blk.number.as_str().parse::<u64>().unwrap_or_default(),
                                })
                                .map(|blk| {
                                    subgraph_network_blocks
                                        .entry(status.subgraph.clone())
                                        .or_insert(SubgraphStatus {
                                            network: chain.network.clone(),
                                            block: blk.clone(),
                                        });
                                    blk
                                });
                            network_name
                        })
                        .collect::<String>()
                })
                .collect::<Vec<String>>()
        })
        .ok_or(QueryError::IndexingError);
    trace!("Updated networks: {:#?}", updated_networks);
    Ok(subgraph_network_blocks)
}
