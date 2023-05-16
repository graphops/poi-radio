#!/bin/bash

RUST_BACKTRACE=1 RUST_LOG="off,hyper=off,graphcast_sdk=debug,poi_radio=trace,integration_tests=trace" cargo test --lib -- "integration_tests::setup::basic::tests::run_basic_instance" &
RUST_BACKTRACE=1 RUST_LOG="off,hyper=off,graphcast_sdk=debug,poi_radio=trace,integration_tests=trace" cargo test --lib -- "integration_tests::setup::basic::tests::run_basic_instance" &
RUST_BACKTRACE=1 RUST_LOG="off,hyper=off,graphcast_sdk=debug,poi_radio=trace,integration_tests=trace" cargo test --lib -- "integration_tests::setup::basic::tests::run_basic_instance" &

RUST_BACKTRACE=1 RUST_LOG="off,hyper=off,graphcast_sdk=debug,poi_radio=trace,integration_tests=trace" cargo test --lib -- "integration_tests::checks::simple_tests::tests::run_simple_tests"
# Check if the previous command was successful
if [ $? -eq 0 ]; then
    echo "Simple tests executed successfully."
else
    echo "Simple tests executed with errors."
    exit 1
fi
