#!/bin/bash

# Function to start a docker container and check if it started successfully
start_container() {
    docker run -d --name $1 my_test_image bash -c "RUST_BACKTRACE=1 RUST_LOG=\"off,hyper=off,graphcast_sdk=debug,poi_radio=trace,integration_tests=trace\" cargo test --lib -- \"integration_tests::setup::$2::tests::run_$2_instance\""
    if [ $? -ne 0 ]; then
        echo "Failed to start $1"
        exit 1
    fi
}

# Function to stop and remove all docker containers
cleanup() {
    echo "Cleaning up..."
    docker rm -f $(docker ps -a -q)
}

# Get the start time
start_time=$(date +%s)

# Clean up all existing containers
cleanup

# Start setup instances for simple_tests
echo "Starting basic instances for simple_tests..."
start_container setup_instance_basic_1 basic
start_container setup_instance_basic_2 basic

# Run simple_tests.sh...
echo "Running simple_tests.sh..."
docker run --rm --network host my_test_image bash -c "RUST_BACKTRACE=1 RUST_LOG=\"off,hyper=off,graphcast_sdk=debug,poi_radio=trace,integration_tests=trace\" cargo test --lib -- \"integration_tests::checks::simple_tests::tests::run_simple_tests\""

# Clean up all existing containers
cleanup

# Start setup instances for invalid_messages and invalid_sender tests
echo "Starting instances for invalid_messages and invalid_sender tests..."
start_container setup_instance_invalid_nonce invalid_nonce
start_container setup_instance_invalid_payload invalid_payload
start_container setup_instance_invalid_block_hash invalid_block_hash

# Run invalid_messages.sh...
echo "Running invalid_messages.sh..."
docker run --rm --network host my_test_image bash -c "RUST_BACKTRACE=1 RUST_LOG=\"off,hyper=off,graphcast_sdk=debug,poi_radio=trace,integration_tests=trace\" cargo test --lib -- \"integration_tests::checks::invalid_messages::tests::test_invalid_messages\""

# Run invalid_sender.sh...
echo "Running invalid_sender.sh..."
docker run --rm --network host my_test_image bash -c "RUST_BACKTRACE=1 RUST_LOG=\"off,hyper=off,graphcast_sdk=debug,poi_radio=trace,integration_tests=trace\" cargo test --lib -- \"integration_tests::checks::invalid_sender::tests::test_invalid_sender_check\""

# Clean up all existing containers
cleanup

# Start setup instances for poi_divergence_remote test
echo "Starting instances for poi_divergence_remote test..."
start_container setup_instance_basic_1 basic
start_container setup_instance_basic_2 basic
start_container setup_instance_divergent_1 divergent

# Run poi_divergence_remote.sh...
echo "Running poi_divergence_remote.sh..."
docker run --rm --network host my_test_image bash -c "RUST_BACKTRACE=1 RUST_LOG=\"off,hyper=off,graphcast_sdk=debug,poi_radio=trace,integration_tests=trace\" cargo test --lib -- \"integration_tests::checks::poi_divergence_remote::tests::test_poi_divergence_remote\""

# Clean up all existing containers
cleanup

# # Start setup instances for poi_divergence_local test
# echo "Starting instances for poi_divergence_local test..."
# start_container setup_instance_basic_1 basic
# start_container setup_instance_divergent_1 divergent
# start_container setup_instance_divergent_2 divergent

# # Stop two of the divergent instances
# docker stop setup_instance_divergent_1
# docker stop setup_instance_divergent_2

# # Run poi_divergence_local.sh...
# echo "Running poi_divergence_local.sh..."
# docker run --rm --network host my_test_image bash -c "RUST_BACKTRACE=1 RUST_LOG=\"off,hyper=off,graphcast_sdk=debug,poi_radio=trace,integration_tests=trace\" cargo test --lib -- \"integration_tests::checks::poi_divergence_local::tests::test_poi_divergence_local\""

# # Clean up all existing containers
# cleanup

# Check if the tests were successful
if [ $? -eq 0 ]; then
    echo "All tests executed successfully."
else
    echo "Some tests executed with errors."
    exit 1
fi

# Clean up all existing containers one last time
cleanup

# Calculate and display the execution time
end_time=$(date +%s)
execution_time=$((end_time - start_time))
echo "Total execution time of the script: $execution_time seconds."
