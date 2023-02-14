// Maybe later on move graphql to SDK as the queries are pretty standarded
use graphcast_sdk::graphql::QueryError;
use graphql_client::{GraphQLQuery, Response};
use serde_derive::{Deserialize, Serialize};

/// Derived GraphQL Query to Proof of Indexing
#[derive(GraphQLQuery, Serialize, Deserialize, Debug)]
#[graphql(
    schema_path = "src/graphql/schema_graph_node.graphql",
    query_path = "src/graphql/query_proof_of_indexing.graphql",
    response_derives = "Debug, Serialize, Deserialize"
)]
pub struct ProofOfIndexing;

#[derive(GraphQLQuery, Serialize, Deserialize, Debug, Clone)]
#[graphql(
    schema_path = "src/graphql/schema_graph_node.graphql",
    query_path = "src/graphql/query_indexing_statuses.graphql",
    response_derives = "Debug, Serialize, Deserialize, Clone"
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
            _ => Err(QueryError::EmptyResponseError),
        }
    } else {
        Err(QueryError::EmptyResponseError)
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
pub async fn query_graph_node_deployment_network(
    graph_node_endpoint: String,
    ipfs_hash: String,
) -> Result<String, QueryError> {
    let variables: indexing_statuses::Variables = indexing_statuses::Variables {
        deployments: vec![ipfs_hash.clone()],
    };
    let queried_result = perform_indexing_statuses(graph_node_endpoint.clone(), variables).await?;
    let response_body: Response<indexing_statuses::ResponseData> = queried_result.json().await?;

    response_body
        .data
        .and_then(|data| {
            data.indexing_statuses
                .first()
                .and_then(|status| status.chains.first())
                .map(|chain| chain.network.clone())
        })
        .ok_or(QueryError::IndexingError)
}

/// Query graph node for Block hash
pub async fn perform_block_hash_from_number(
    graph_node_endpoint: String,
    variables: block_hash_from_number::Variables,
) -> Result<reqwest::Response, reqwest::Error> {
    let request_body = BlockHashFromNumber::build_query(variables);
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
pub async fn query_graph_node_network_block_hash(
    graph_node_endpoint: String,
    network: String,
    block_number: i64,
) -> Result<String, QueryError> {
    let variables: block_hash_from_number::Variables = block_hash_from_number::Variables {
        network,
        block_number,
    };
    let queried_result =
        perform_block_hash_from_number(graph_node_endpoint.clone(), variables).await?;
    let response_body: Response<block_hash_from_number::ResponseData> =
        queried_result.json().await?;

    if let Some(data) = response_body.data {
        match data.block_hash_from_number {
            Some(hash) => Ok(hash),
            _ => Err(QueryError::EmptyResponseError),
        }
    } else {
        Err(QueryError::EmptyResponseError)
    }
}
