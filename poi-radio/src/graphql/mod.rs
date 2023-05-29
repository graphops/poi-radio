use graphql_client::{GraphQLQuery, Response};
use serde_derive::{Deserialize, Serialize};

// Maybe later on move graphql to SDK as the queries are pretty standarded
use graphcast_sdk::graphql::QueryError;

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
            _ => Err(QueryError::ParseResponseError(
                "No POI returned".to_string(),
            )),
        }
    } else {
        Err(QueryError::ParseResponseError(
            "No POI response from Graph Node".to_string(),
        ))
    }
}
