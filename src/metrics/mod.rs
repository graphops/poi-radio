use autometrics::{encode_global_metrics, global_metrics_exporter};
use axum::http::StatusCode;
use axum::routing::get;
use axum::Router;
use once_cell::sync::Lazy;
use prometheus::{core::Collector, Registry};
use prometheus::{
    linear_buckets, HistogramOpts, HistogramVec, IntCounterVec, IntGauge, IntGaugeVec, Opts,
};
use std::{net::SocketAddr, str::FromStr};
use tracing::{debug, info};

// Received (and validated) messages counter
#[allow(dead_code)]
pub static VALIDATED_MESSAGES: Lazy<IntCounterVec> = Lazy::new(|| {
    let m = IntCounterVec::new(
        Opts::new("validated_messages", "Number of validated messages")
            .namespace("graphcast")
            .subsystem("poi_radio"),
        &["deployment"],
    )
    .expect("Failed to create validated_messages counters");
    prometheus::register(Box::new(m.clone()))
        .expect("Failed to register validated_messages counter");
    m
});

// Received (and validated) messages counter
#[allow(dead_code)]
pub static CACHED_MESSAGES: Lazy<IntGaugeVec> = Lazy::new(|| {
    let m = IntGaugeVec::new(
        Opts::new("cached_messages", "Number of messages in cache")
            .namespace("graphcast")
            .subsystem("poi_radio"),
        &["deployment"],
    )
    .expect("Failed to create cached_messages gauges");
    prometheus::register(Box::new(m.clone())).expect("Failed to register cached_messages guage");
    m
});

// These are the subgraphs that are being actively cross-checked (the ones we are receiving remote attestations for)
#[allow(dead_code)]
pub static ACTIVE_INDEXERS: Lazy<IntGaugeVec> = Lazy::new(|| {
    let m = IntGaugeVec::new(
        Opts::new(
            "ACTIVE_INDEXERS",
            "Number of indexers actively crosschecking on the deployment (self excluded)",
        )
        .namespace("graphcast")
        .subsystem("poi_radio"),
        &["deployment"],
    )
    .expect("Failed to create ACTIVE_INDEXERS gauges");
    prometheus::register(Box::new(m.clone())).expect("Failed to register ACTIVE_INDEXERS counter");
    m
});

#[allow(dead_code)]
pub static DIVERGING_SUBGRAPHS: Lazy<IntGauge> = Lazy::new(|| {
    let m = IntGauge::with_opts(
        Opts::new(
            "diverging_subgraphs",
            "Number of diverging subgraphs with non-consensus POIs from cross-checking",
        )
        .namespace("graphcast")
        .subsystem("poi_radio"),
    )
    .expect("Failed to create diverging_subgraphs gauge");
    prometheus::register(Box::new(m.clone()))
        .expect("Failed to register diverging_subgraphs counter");
    m
});

#[allow(dead_code)]
pub static LOCAL_NPOIS_TO_COMPARE: Lazy<IntGaugeVec> = Lazy::new(|| {
    let m = IntGaugeVec::new(
        Opts::new(
            "local_npois_to_compare",
            "Number of nPOIs stored locally for each subgraph",
        )
        .namespace("graphcast")
        .subsystem("poi_radio"),
        &["deployment"],
    )
    .expect("Failed to create LOCAL_NPOIS_TO_COMPARE gauges");
    prometheus::register(Box::new(m.clone()))
        .expect("Failed to register local_npois_to_compare gauge");
    m
});

#[allow(dead_code)]
pub static INDEXER_COUNT_BY_NPOI: Lazy<HistogramVec> = Lazy::new(|| {
    let m = HistogramVec::new(
        HistogramOpts::new(
            "indexer_count_by_npoi",
            "Count of indexers attesting for a nPOI",
        )
        .namespace("graphcast")
        .subsystem("poi_radio")
        .buckets(linear_buckets(0.0, 1.0, 20).unwrap()),
        // Q: if we add indexer group hash here
        // then new metric is created for changes in indexers. I imagine this not so important
        // when it is the same group, but it is a chance to record indexer info.
        // description of metrics cannot be updated after initialization
        &["deployment"],
    )
    .expect("Failed to create indexer_count_by_npoi histograms");
    prometheus::register(Box::new(m.clone()))
        .expect("Failed to register indexer_count_by_npoi counter");
    m
});

#[allow(dead_code)]
pub static REGISTRY: Lazy<prometheus::Registry> = Lazy::new(prometheus::Registry::new);

#[allow(dead_code)]
pub fn register_metrics(registry: &Registry, metrics: Vec<Box<dyn Collector>>) {
    for metric in metrics {
        registry.register(metric).expect("Cannot register metrics");
        debug!("registered metric");
    }
}

#[allow(dead_code)]
pub fn start_metrics() {
    register_metrics(
        &REGISTRY,
        vec![
            Box::new(VALIDATED_MESSAGES.clone()),
            Box::new(CACHED_MESSAGES.clone()),
            Box::new(ACTIVE_INDEXERS.clone()),
            Box::new(DIVERGING_SUBGRAPHS.clone()),
            Box::new(LOCAL_NPOIS_TO_COMPARE.clone()),
            Box::new(INDEXER_COUNT_BY_NPOI.clone()),
        ],
    );
}

/// This handler serializes the metrics into a string for Prometheus to scrape
#[allow(dead_code)]
pub async fn get_metrics() -> (StatusCode, String) {
    match encode_global_metrics() {
        Ok(metrics) => (StatusCode::OK, metrics),
        Err(err) => (StatusCode::INTERNAL_SERVER_ERROR, format!("{err:?}")),
    }
}

/// Run the API server as well as Prometheus and a traffic generator
#[allow(dead_code)]
pub async fn handle_serve_metrics(host: String, port: u16) {
    // Set up the exporter to collect metrics
    let _exporter = global_metrics_exporter();

    let app = Router::new().route("/metrics", get(get_metrics));
    let addr =
        SocketAddr::from_str(&format!("{}:{}", host, port)).expect("Start Prometheus metrics");
    let server = axum::Server::bind(&addr);
    info!(
        address = addr.to_string(),
        "Prometheus Metrics port exposed"
    );

    server
        .serve(app.into_make_service())
        .await
        .expect("Error starting example API server");
}
