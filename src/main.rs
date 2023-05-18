use poi_radio::{config::Config, run_radio};

#[tokio::main]
async fn main() {
    // Parse basic configurations
    let radio_config = Config::args();

    run_radio("poi-radio".to_string(), radio_config).await;
}
