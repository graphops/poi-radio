use dotenv::dotenv;
use once_cell::sync::OnceCell;
use poi_radio::{config::Config, operator::RadioOperator};

extern crate partial_application;

/// A global static (singleton) instance of GraphcastAgent. It is useful to ensure that we have only one GraphcastAgent
/// per Radio instance, so that we can keep track of state and more easily test our Radio application.
pub static RADIO_OPERATOR: OnceCell<RadioOperator> = OnceCell::new();

#[tokio::main]
async fn main() {
    dotenv().ok();

    // Parse basic configurations
    let radio_config = Config::args();

    // Initialization and pass in for static lifetime throughout the program
    let radio_operator = RadioOperator::new(radio_config).await;

    // Start separate processes
    radio_operator.prepare().await;

    _ = RADIO_OPERATOR.set(radio_operator);

    // Start radio operations
    RADIO_OPERATOR.get().unwrap().run().await;
}
