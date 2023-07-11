use chrono::Utc;
use tracing::{error, info};

use graphcast_sdk::networks::NetworkName;

use crate::operator::RadioOperator;
use poi_radio::{messages::upgrade::VersionUpgradeMessage, OperationError};

impl RadioOperator {
    pub async fn gossip_one_shot(&self) -> Result<String, OperationError> {
        // configure radio config to parse in a subcommand for the radio payload message?
        let identifier = self.config.identifier.clone();
        let new_hash = self.config.new_hash.clone();
        let subgraph_id = self.config.subgraph_id.clone();
        let time = Utc::now().timestamp();
        let network = self.config.index_network();
        let migrate_time = self.config.migration_time;
        let graph_account = self.config.graph_account.clone();
        let radio_message = VersionUpgradeMessage::build(
            identifier.clone(),
            new_hash.clone(),
            time,
            subgraph_id,
            NetworkName::from_string(network),
            migrate_time,
            graph_account,
        );
        match self
            .graphcast_agent
            .send_message(&identifier, radio_message, time)
            .await
        {
            Ok(msg_id) => {
                info!(msg_id, "Sent message");
                Ok(msg_id)
            }
            Err(e) => {
                error!(err = tracing::field::debug(&e), "Failed to send message");
                Err(OperationError::Agent(e))
            }
        }
    }
}
