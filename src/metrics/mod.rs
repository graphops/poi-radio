use autometrics::{encode_global_metrics, global_metrics_exporter};
use axum::http::StatusCode;
use axum::routing::get;
use axum::Router;
use once_cell::sync::Lazy;
use prometheus::{Counter, IntGaugeVec, Opts};
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::process::{Command, Stdio};
use tracing::info;

/// This handler serializes the metrics into a string for Prometheus to scrape
async fn get_metrics() -> (StatusCode, String) {
    match encode_global_metrics() {
        Ok(metrics) => (StatusCode::OK, metrics),
        Err(err) => (StatusCode::INTERNAL_SERVER_ERROR, format!("{err:?}")),
    }
}

/// Run the API server as well as Prometheus and a traffic generator
async fn handle_serve_metrics() {
    // Set up the exporter to collect metrics
    let _exporter = global_metrics_exporter();

    let app = Router::new().route("/metrics", get(get_metrics));

    let addr = SocketAddr::from(([127, 0, 0, 1], 3001));
    let server = axum::Server::bind(&addr);

    server
        .serve(app.into_make_service())
        .await
        .expect("Error starting example API server");
}

// Received (and validated) messages counter
pub static VALIDATED_MESSAGES: Lazy<Counter> = Lazy::new(|| {
    let counter = Counter::new(
        "validated_messages_total",
        "Total number of validated messages",
    )
    .expect("Failed to create validated_messages_total counter");
    prometheus::register(Box::new(counter.clone()))
        .expect("Failed to register validated_messages_total counter");
    counter
});

// These are the subgraphs that are being actively cross-checked (the ones we are receiving remote attestations for)
// Maybe CHECKED_SUBGRAPHS is a better name?
pub static ACTIVE_SUBGRAPHS: Lazy<IntGaugeVec> = Lazy::new(|| {
    let opts = Opts::new(
        "active_subgraphs",
        "Number of subgraphs being actively crosschecked with other indexers",
    );
    let gauge_vec =
        IntGaugeVec::new(opts, &["subgraph"]).expect("Failed to create active_subgraphs gauge");
    prometheus::register(Box::new(gauge_vec.clone()))
        .expect("Failed to register active_subgraphs gauge");
    gauge_vec
});

pub fn start_prometheus_server() {
    const PROMETHEUS_CONFIG_PATH: &str = "./prometheus.yml";

    match Command::new("prometheus")
        .args(["--config.file", PROMETHEUS_CONFIG_PATH])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        Err(err) if err.kind() == ErrorKind::NotFound => {
            panic!("Failed to start prometheus (do you have the prometheus binary installed and in your path?)");
        }
        Err(err) => {
            panic!("Failed to start prometheus: {err}");
        }
        Ok(_) => {
            info!(
                "Running Prometheus on port 9090 (using config file: {PROMETHEUS_CONFIG_PATH})\n"
            );
        }
    }

    tokio::spawn(handle_serve_metrics());
}
