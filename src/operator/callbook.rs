use axum::async_trait;

use crate::graphql::query_graph_node_poi;
use graphcast_sdk::callbook::CallBook;
use graphcast_sdk::graphql::QueryError;

#[async_trait]
pub trait CallBookRadioExtensions {
    // Define the additional function(s) you want to add to CallBook
    async fn query_poi(
        &self,
        ipfs_hash: String,
        block_hash: String,
        block_number: i64,
    ) -> Result<String, QueryError>;
}

#[async_trait]
impl CallBookRadioExtensions for CallBook {
    async fn query_poi(
        &self,
        ipfs_hash: String,
        block_hash: String,
        block_number: i64,
    ) -> Result<String, QueryError> {
        query_graph_node_poi(
            self.graph_node_status().to_string(),
            ipfs_hash,
            block_hash,
            block_number,
        )
        .await
    }
}
