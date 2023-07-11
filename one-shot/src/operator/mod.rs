use std::sync::Arc;
use tracing::{debug, warn};

use graphcast_sdk::{build_wallet, graphcast_agent::GraphcastAgent};

use crate::config::Config;
use crate::GRAPHCAST_AGENT;
pub mod operation;

/// Radio operator contains all states needed for radio operations
#[allow(unused)]
pub struct RadioOperator {
    config: Config,
    graphcast_agent: Arc<GraphcastAgent>,
}

impl RadioOperator {
    /// Create a radio operator with radio configurations, persisted data,
    /// graphcast agent, and control flow
    pub async fn new(config: &Config) -> RadioOperator {
        debug!("Initializing Radio operator");
        let _wallet = build_wallet(
            config
                .wallet_input()
                .expect("Operator wallet input invalid"),
        )
        .expect("Radio operator cannot build wallet");

        debug!("Initializing Graphcast Agent");
        let (agent, _receiver) =
            GraphcastAgent::new(config.to_graphcast_agent_config().await.unwrap())
                .await
                .expect("Initialize Graphcast agent");
        let graphcast_agent = Arc::new(agent);
        // Provide topics to Graphcast agent
        let topics = vec![config.identifier.clone()];
        debug!(
            topics = tracing::field::debug(&topics),
            "Found content topics for subscription",
        );
        graphcast_agent.update_content_topics(topics.clone()).await;
        debug!("Set global static instance of graphcast_agent");
        _ = GRAPHCAST_AGENT.set(graphcast_agent.clone());

        RadioOperator {
            config: config.clone(),
            graphcast_agent,
        }
    }

    pub fn graphcast_agent(&self) -> &GraphcastAgent {
        &self.graphcast_agent
    }

    /// radio continuously attempt to send message until success
    pub async fn run(&'static self) {
        let mut res = self.gossip_one_shot().await;
        while let Err(e) = res {
            warn!(err = tracing::field::debug(&e), "Failed to gossip, repeat");
            res = self.gossip_one_shot().await;
        }
    }
}
