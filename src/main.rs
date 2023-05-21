use poi_radio::{config::Config, run_radio};

pub fn radio_name() -> &'static str {
    "poi-radio"
}

#[tokio::main]
async fn main() {
    // Parse basic configurations
    let radio_config = Config::args();

    run_radio(radio_name(), radio_config).await;
}
