use axum::{extract::Extension, routing::get, Router, Server};

use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use tokio::sync::Mutex as AsyncMutex;
use tracing::info;

use crate::attestation::LocalAttestationsMap;
use crate::server::model::{build_schema, POIRadioContext};
use crate::server::routes::{graphql_handler, graphql_playground, health};
use crate::{shutdown_signal, CONFIG};

pub mod model;
pub mod routes;

/// Run HTTP server to provide API services
/// Set up the routes for a radio health endpoint at `/health`
/// and a versioned GraphQL endpoint at `api/v1/graphql`
/// This function starts a API server at the configured server_host and server_port
pub async fn run_server(
    running_program: Arc<AtomicBool>,
    local_attestations: Arc<AsyncMutex<LocalAttestationsMap>>,
) {
    info!("Initializing HTTP server");
    let host = CONFIG
        .get()
        .unwrap()
        .lock()
        .unwrap()
        .server_host
        .clone()
        .unwrap_or(String::from("0.0.0.0"));
    let port = CONFIG.get().unwrap().lock().unwrap().server_port.unwrap();

    let context = Arc::new(POIRadioContext::init(Arc::clone(&local_attestations)).await);

    let schema = build_schema(Arc::clone(&context)).await;

    info!("API Service starting at {host}:{port}");

    let app = Router::new()
        .route("/health", get(health))
        .route(
            "/api/v1/graphql",
            get(graphql_playground).post(graphql_handler),
        )
        .layer(Extension(schema))
        .layer(Extension(context));
    let addr = SocketAddr::from_str(&format!("{}:{}", host, port)).expect("Start HTTP Service");

    Server::bind(&addr)
        .serve(app.into_make_service())
        .with_graceful_shutdown(shutdown_signal(running_program))
        .await
        .unwrap();
}
