use dotenv::dotenv;
use poi_radio::{config::Config, operator::RadioOperator};

extern crate partial_application;

#[tokio::main]
async fn main() {
    dotenv().ok();

    // Parse basic configurations
    let radio_config = Config::args();

    // Initialization
    let radio_operator = RadioOperator::new(radio_config).await;

    // Start separate processes
    radio_operator.prepare().await;

    // Start radio operations
    radio_operator.run().await;
}
