use poi_radio::attestation::LocalAttestationsMap;
use poi_radio::attestation::RemoteAttestationsMap;
use poi_radio::run_radio_impl;

pub async fn run_poi_radio() {
    run_radio_impl(
        None,
        Some(|_, _: &str| {}),
        Some(|_, _: &RemoteAttestationsMap, _: &LocalAttestationsMap| {}),
        Some(|_, _, _: &str| {}),
    )
    .await;
}

#[tokio::main]
async fn main() {
    run_poi_radio().await;
}
