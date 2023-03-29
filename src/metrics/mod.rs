use autometrics::{encode_global_metrics, global_metrics_exporter};
use axum::http::StatusCode;
use axum::routing::get;
use axum::Router;
use std::net::SocketAddr;

/// This handler serializes the metrics into a string for Prometheus to scrape
async fn get_metrics() -> (StatusCode, String) {
    match encode_global_metrics() {
        Ok(metrics) => (StatusCode::OK, metrics),
        Err(err) => (StatusCode::INTERNAL_SERVER_ERROR, format!("{err:?}")),
    }
}

/// Run the API server as well as Prometheus and a traffic generator
pub async fn handle_serve_metrics(port: u16) {
    // Set up the exporter to collect metrics
    let _exporter = global_metrics_exporter();

    let app = Router::new().route("/metrics", get(get_metrics));

    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let server = axum::Server::bind(&addr);

    server
        .serve(app.into_make_service())
        .await
        .expect("Error starting example API server");
}
