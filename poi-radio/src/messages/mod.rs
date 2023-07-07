use graphcast_sdk::graphcast_agent::{
    message_typing::GraphcastMessage, waku_handling::WakuHandlingError,
};
use poi::PublicPoiMessage;
use std::{
    any::Any,
    sync::{mpsc, Mutex as SyncMutex},
};
use tracing::{error, trace};
use upgrade::VersionUpgradeMessage;

pub mod poi;
pub mod upgrade;

#[derive(Debug, Clone, serde_derive::Deserialize, serde_derive::Serialize)]
pub enum MessageType {
    PublicPoi(GraphcastMessage<poi::PublicPoiMessage>),
    VersionUpgrade(GraphcastMessage<upgrade::VersionUpgradeMessage>),
}

pub fn typed_handler(sender: SyncMutex<mpsc::Sender<MessageType>>, msg: &dyn Any) {
    if let Some(Ok(ppoi_message)) =
        msg.downcast_ref::<Result<GraphcastMessage<PublicPoiMessage>, WakuHandlingError>>()
    {
        trace!(
            ppoi_message = tracing::field::debug(&ppoi_message),
            "Received Graphcast validated message"
        );

        // let id = ppoi_message.identifier.clone();
        // VALIDATED_MESSAGES.with_label_values(&[&id]).inc();

        match sender
            .lock()
            .unwrap()
            .send(MessageType::PublicPoi(ppoi_message.clone()))
        {
            Ok(_) => trace!("Sent received message to radio operator"),
            Err(e) => error!("Could not send message to channel: {:#?}", e),
        }
    } else if let Some(Ok(upgrade_message)) =
        msg.downcast_ref::<Result<GraphcastMessage<VersionUpgradeMessage>, WakuHandlingError>>()
    {
        trace!(
            upgrade_message = tracing::field::debug(&upgrade_message),
            "Received Graphcast validated message"
        );

        // let id = upgrade_message.identifier.clone();
        // VALIDATED_MESSAGES.with_label_values(&[&id]).inc();

        match sender
            .lock()
            .unwrap()
            .send(MessageType::VersionUpgrade(upgrade_message.clone()))
        {
            Ok(_) => trace!("Sent upgrade message to radio operator"),
            Err(e) => error!("Could not send message to channel: {:#?}", e),
        }
    }
}
