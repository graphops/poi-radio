use dotenv::dotenv;
use one_shot::{config::Config, operator::RadioOperator, RADIO_OPERATOR};

extern crate partial_application;

#[tokio::main]
async fn main() {
    dotenv().ok();
    // Parse basic configurations
    let radio_config = Config::args();

    // Initialization and pass in for static lifetime throughout the program
    let radio_operator = RadioOperator::new(&radio_config).await;

    _ = RADIO_OPERATOR.set(radio_operator);

    // Start radio operations
    RADIO_OPERATOR.get().unwrap().run().await;
}
