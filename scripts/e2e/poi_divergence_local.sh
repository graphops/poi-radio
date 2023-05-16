#!/bin/bash

RUST_BACKTRACE=1 RUST_LOG="off,hyper=off,graphcast_sdk=debug,poi_radio=trace,integration_tests=trace" cargo test --lib -- "integration_tests::setup::basic::tests::run_basic_instance" &
sleep 5

RUST_BACKTRACE=1 RUST_LOG="off,hyper=off,graphcast_sdk=debug,poi_radio=trace,integration_tests=trace" cargo test --lib -- "integration_tests::setup::divergent::tests::run_divergent_instance" &
sleep 5

RUST_BACKTRACE=1 RUST_LOG="off,hyper=off,graphcast_sdk=debug,poi_radio=trace,integration_tests=trace" cargo test --lib -- "integration_tests::setup::divergent::tests::run_divergent_instance" &
sleep 5

RUST_BACKTRACE=1 RUST_LOG="off,hyper=off,graphcast_sdk=debug,poi_radio=trace,integration_tests=trace" cargo test --lib -- "integration_tests::checks::poi_divergence_local::tests::test_poi_divergence_local"
if [ $? -eq 0 ]; then
    echo "POI divergence local test executed successfully."
else
    echo "POI divergence local test executed with errors."
    exit 1
fi
