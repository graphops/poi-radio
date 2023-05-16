#!/bin/bash

RUST_BACKTRACE=1 RUST_LOG="off,hyper=off,graphcast_sdk=debug,poi_radio=trace,integration_tests=trace" cargo test --lib -- "integration_tests::setup::basic::tests::run_basic_instance" &
RUST_BACKTRACE=1 RUST_LOG="off,hyper=off,graphcast_sdk=debug,poi_radio=trace,integration_tests=trace" cargo test --lib -- "integration_tests::setup::invalid_nonce::tests::run_invalid_nonce_instance" &
RUST_BACKTRACE=1 RUST_LOG="off,hyper=off,graphcast_sdk=debug,poi_radio=trace,integration_tests=trace" cargo test --lib -- "integration_tests::setup::invalid_payload::tests::run_invalid_payload_instance" &
RUST_BACKTRACE=1 RUST_LOG="off,hyper=off,graphcast_sdk=debug,poi_radio=trace,integration_tests=trace" cargo test --lib -- "integration_tests::setup::invalid_block_hash::tests::run_invalid_block_hash_instance" &

RUST_BACKTRACE=1 RUST_LOG="off,hyper=off,graphcast_sdk=debug,poi_radio=trace,integration_tests=trace" cargo test --lib -- "integration_tests::checks::invalid_messages::tests::test_invalid_messages"
if [ $? -eq 0 ]; then
    echo "Invalid messages test executed successfully."
else
    echo "Invalid messages test executed with errors."
    exit 1
fi
