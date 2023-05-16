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

# Function to check if a docker container is running
is_container_running() {
    if [ "$(docker ps -q -f name=$1)" ]; then
        return 0
    else
        return 1
    fi
}

# Clean up all existing containers
cleanup

# Start setup instances for poi_divergence_local test
echo "Starting instances for poi_divergence_local test..."
start_container setup_instance_basic_1 basic
start_container setup_instance_divergent_1 divergent
start_container setup_instance_divergent_2 divergent

# Check if the containers are running
if is_container_running setup_instance_basic_1 && is_container_running setup_instance_divergent_1 && is_container_running setup_instance_divergent_2; then
    echo "All setup instances are running."
else
    echo "One or more setup instances are not running."
    exit 1
fi

# Run poi_divergence_local.sh...
echo "Running poi_divergence_local.sh..."
docker run --rm --network host my_test_image bash -c "RUST_BACKTRACE=1 RUST_LOG=\"off,hyper=off,graphcast_sdk=debug,poi_radio=trace,integration_tests=trace\" cargo test --lib -- \"integration_tests::checks::poi_divergence_local::tests::test_poi_divergence_local\""

# Clean up all existing containers
cleanup
