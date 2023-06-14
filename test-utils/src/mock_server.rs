use axum::{routing::post, Router};
use chrono::Utc;
use rand::Rng;
use std::fmt::Write;
use std::{convert::Infallible, net::SocketAddr, str::FromStr};
use tower::ServiceBuilder;
use tower_http::trace::TraceLayer;

pub async fn start_mock_server(address: String) {
    // Define the HTTP handlers
    let app = Router::new()
        .route("/graphql", post(handler_graphql))
        .route("/registry-subgraph", post(handler_graphcast_registry))
        .route("/network-subgraph", post(handler_network_subgraph)) // Added this line
        .layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .into_inner(),
        );

    // Create the server and start listening for requests
    let addr = SocketAddr::from_str(&address).unwrap();
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

async fn handler_graphql() -> Result<String, Infallible> {
    let timestamp = Utc::now().timestamp();
    let timestamp = (timestamp + 9) / 10 * 10;

    let response_body = format!(
        r#"{{"data": {{"proofOfIndexing": "0x25331f98b82ca7f3966256bf508a7ede52e715b631dfa3d73b846bb7617f6b9e", "blockHashFromNumber": "4dbba1ba9fb18b0034965712598be1368edcf91ae2c551d59462aab578dab9c5", "indexingStatuses": [{{"subgraph": "QmpRkaVUwUQAwPwWgdQHYvw53A5gh3CP3giWnWQZdA2BTE", "synced": true, "health": "healthy", "node": "default", "fatalError": null, "chains": [{{"network": "mainnet", "latestBlock": {{"number": "{}", "hash": "b30395958a317ccc06da46782f660ce674cbe6792e5573dc630978c506114a0a"}}, "chainHeadBlock": {{"number": "{}", "hash": "b30395958a317ccc06da46782f660ce674cbe6792e5573dc630978c506114a0a"}}}}]}}, {{"subgraph": "QmtYT8NhPd6msi1btMc3bXgrfhjkJoC4ChcM5tG6fyLjHE", "synced": true, "health": "healthy", "node": "default", "fatalError": null, "chains": [{{"network": "goerli", "latestBlock": {{"number": "{}", "hash": "b30395958a317ccc06da46782f660ce674cbe6792e5573dc630978c506114a0a"}}, "chainHeadBlock": {{"number": "{}", "hash": "b30395958a317ccc06da46782f660ce674cbe6792e5573dc630978c506114a0a"}}}}]}}]}}}}"#,
        timestamp, timestamp, timestamp, timestamp
    );

    Ok(response_body)
}

async fn handler_graphcast_registry() -> Result<String, Infallible> {
    // Generate a random Ethereum address
    let mut rng = rand::thread_rng();
    let graphcast_id: String = (0..20)
        .map(|_| rng.gen::<u8>())
        .collect::<Vec<u8>>()
        .iter()
        .fold(String::new(), |mut acc, &n| {
            write!(&mut acc, "{:02x}", n).unwrap();
            acc
        });

    let indexer: String = (0..20)
        .map(|_| rng.gen::<u8>())
        .collect::<Vec<u8>>()
        .iter()
        .fold(String::new(), |mut acc, &n| {
            write!(&mut acc, "{:02x}", n).unwrap();
            acc
        });

    let response_body = format!(
        r#"{{
        "data": {{
            "graphcast_ids": [
                {{
                    "indexer": "0x{}",
                    "graphcastID": "0x{}"
                }}
            ]
        }},
        "errors": null,
        "extensions": null
    }}"#,
        indexer, graphcast_id
    );

    Ok(response_body)
}

async fn handler_network_subgraph() -> Result<String, Infallible> {
    let response_body = r#"
    {
        "data": {
            "indexer": {
                "stakedTokens": "10000000000000000000000",
                "allocations": [
                    {
                        "subgraphDeployment": {
                            "ipfsHash": "QmpRkaVUwUQAwPwWgdQHYvw53A5gh3CP3giWnWQZdA2BTE"
                        }
                    },
                    {
                        "subgraphDeployment": {
                            "ipfsHash": "QmtYT8NhPd6msi1btMc3bXgrfhjkJoC4ChcM5tG6fyLjHE"
                        }
                    }
                ]
            },
            "graphNetwork": {
                "minimumIndexerStake": "10000000000000000000000"
            }
        },
        "errors": null
    }"#;

    Ok(response_body.to_string())
}
