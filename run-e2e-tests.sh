#!/bin/bash

if [ -f .env ]; then
    # Read environment variables from .env file
    source .env
else
    # Export environment variables
    export GRAPH_NODE_STATUS_ENDPOINT=$GRAPH_NODE_STATUS_ENDPOINT
    export REGISTRY_SUBGRAPH=$REGISTRY_SUBGRAPH
    export NETWORK_SUBGRAPH=$NETWORK_SUBGRAPH
    export GRAPHCAST_NETWORK=$GRAPHCAST_NETWORK
    export RUST_LOG=$RUST_LOG
    export PRIVATE_KEY=$PRIVATE_KEY
fi

# Create logs directory if it doesn't exist
mkdir -p logs

# Define variables
compose_file="e2e-tests.docker-compose.yml"
num_basic_containers=5

# Variables for summary report
num_total_tests=0
num_success_tests=0
num_fail_tests=0
num_timeout_tests=0
names_of_failed_tests=()

# Function to stop containers and print summary report
stop_containers() {
    echo "Stopping containers..."
    docker-compose -f $compose_file down
    end_time=$SECONDS
    duration=$((end_time - start_time))
    duration_minutes=$((duration / 60))
    duration_seconds=$((duration % 60))

    echo "Summary Report:"
    echo "
-------------------------------------
Total Tests Run: $num_total_tests
Successful Tests: $num_success_tests
Failed Tests: $num_fail_tests
Timed Out Tests: $num_timeout_tests
Test Suite Duration: ${duration_minutes}m ${duration_seconds}s
-------------------------------------
"

    if [ "$num_fail_tests" -gt 0 ]; then
        echo "The following tests failed:"
        printf '%s\n' "${names_of_failed_tests[@]}"
        dump_failed_tests_logs
        exit 1
    fi

    exit 0
}

# Function to run tests with timeout
run_test_with_timeout() {
    local test_name=$1
    local timeout_value=$2
    echo "Running test: $test_name"
    num_total_tests=$((num_total_tests + 1))
    timeout $timeout_value cargo run --bin integration-tests -- --check=$test_name 2>&1 | tee "logs/${test_name}_logs.log"
    timeout_exit_code=${PIPESTATUS[0]}
    cargo_exit_code=${PIPESTATUS[1]}
    if [ $cargo_exit_code -eq 0 ]; then
        echo "$test_name - ✓"
        num_success_tests=$((num_success_tests + 1))
        rm "logs/${test_name}_logs.log"
    elif [[ " ${validation_tests[@]} " =~ " ${test_name} " ]]; then
        echo "$test_name - timeout (but considered successful)"
        num_success_tests=$((num_success_tests + 1))
    elif [ $timeout_exit_code -eq 124 ]; then
        echo "$test_name - timeout"
        num_timeout_tests=$((num_timeout_tests + 1))
        names_of_failed_tests+=("$test_name")
    else
        echo "$test_name - ✗"
        num_fail_tests=$((num_fail_tests + 1))
        names_of_failed_tests+=("$test_name")
    fi
}

# Function to dump failed test logs to a file
dump_failed_tests_logs() {
    echo "Dumping failed tests logs to logs/failed_tests_logs.log"
    rm -f "logs/failed_tests_logs.log"
    for test_name in "${names_of_failed_tests[@]}"; do
        echo "===== $test_name =====" >>logs/failed_tests_logs.log
        cat "logs/${test_name}_logs.log" >>logs/failed_tests_logs.log
        echo -e "\n\n" >>logs/failed_tests_logs.log
        rm "logs/${test_name}_logs.log"
    done
}

# Start containers
start_time=$SECONDS
echo "Starting containers..."
docker-compose -f $compose_file up -d --scale basic-instance=$num_basic_containers
docker-compose -f $compose_file up -d invalid-block-hash-instance invalid-payload-instance invalid-nonce-instance

# Wait for containers to start
echo "Waiting for containers to start..."
until [ $(docker-compose -f $compose_file ps -q basic-instance | wc -l) -eq $num_basic_containers ]; do
    sleep 1
done

# Wait 10 seconds for containers to settle
echo "Waiting for containers to settle..."
sleep 15

echo "Running all simple tests"
timeout 15m cargo run --bin integration-tests -- --check=simple_tests 2>&1 | tee logs/simple_tests_logs.log
timeout_exit_code=${PIPESTATUS[0]}
num_total_tests=$((num_total_tests + 1))
if [ $timeout_exit_code -eq 0 ]; then
    echo "simple_tests - ✓"
    num_success_tests=$((num_success_tests + 1))
    rm logs/simple_tests_logs.log
elif [ $timeout_exit_code -eq 124 ]; then
    echo "simple_tests - timeout"
    num_timeout_tests=$((num_timeout_tests + 1))
    names_of_failed_tests+=("simple_tests")
else
    echo "simple_tests - ✗"
    num_fail_tests=$((num_fail_tests + 1))
    names_of_failed_tests+=("simple_tests")
fi

# Run one-off test
echo "Running test: invalid_sender"
num_total_tests=$((num_total_tests + 1))
timeout 5m cargo run --bin integration-tests -- --check=invalid_sender 2>&1 | tee logs/invalid_sender_logs.log
timeout_exit_code=${PIPESTATUS[0]}
if [ $timeout_exit_code -eq 0 ]; then
    echo "invalid_sender - ✓"
    num_success_tests=$((num_success_tests + 1))
    rm logs/invalid_sender_logs.log
elif [ $timeout_exit_code -eq 124 ]; then
    echo "invalid_sender - timeout"
    num_timeout_tests=$((num_timeout_tests + 1))
    names_of_failed_tests+=("invalid_sender")
else
    echo "invalid_sender - ✗"
    num_fail_tests=$((num_fail_tests + 1))
    names_of_failed_tests+=("invalid_sender")
fi

# Run one-off test
echo "Running test: invalid_messages"
num_total_tests=$((num_total_tests + 1))
timeout 5m cargo run --bin integration-tests -- --check=invalid_messages 2>&1 | tee logs/invalid_messages_logs.log
timeout_exit_code=${PIPESTATUS[0]}
if [ $timeout_exit_code -eq 0 ]; then
    echo "invalid_messages - ✓"
    num_success_tests=$((num_success_tests + 1))
    rm logs/invalid_messages_logs.log
elif [ $timeout_exit_code -eq 124 ]; then
    echo "invalid_messages - timeout"
    num_timeout_tests=$((num_timeout_tests + 1))
    names_of_failed_tests+=("invalid_messages")
else
    echo "invalid_messages - ✗"
    num_fail_tests=$((num_fail_tests + 1))
    names_of_failed_tests+=("invalid_messages")
fi

# Scale up divergent instances
echo "Scaling containers..."
docker-compose -f $compose_file up -d --scale divergent-instance=1 basic-instance=8

# Wait 1 minute for containers to settle
echo "Waiting for containers to settle..."
sleep 60

# Run one-off test
echo "Running test: poi_divergence_remote"
num_total_tests=$((num_total_tests + 1))
timeout 5m cargo run --bin integration-tests -- --check=poi_divergence_remote 2>&1 | tee logs/poi_divergence_remote_logs.log
timeout_exit_code=${PIPESTATUS[0]}
if [ $timeout_exit_code -eq 0 ]; then
    echo "poi_divergence_remote - ✓"
    num_success_tests=$((num_success_tests + 1))
    rm logs/poi_divergence_remote_logs.log
elif [ $timeout_exit_code -eq 124 ]; then
    echo "poi_divergence_remote - timeout"
    num_timeout_tests=$((num_timeout_tests + 1))
    names_of_failed_tests+=("poi_divergence_remote")
else
    echo "poi_divergence_remote - ✗"
    num_fail_tests=$((num_fail_tests + 1))
    names_of_failed_tests+=("poi_divergence_remote")
fi

# Scale down basic instances to 1 and scale up divergent instances to 5
echo "Scaling containers..."
docker-compose -f $compose_file up -d --scale basic-instance=1 --scale divergent-instance=5

# Wait 10 seconds for containers to settle
echo "Waiting for containers to settle..."
sleep 10

# Run one-off test
echo "Running test: poi_divergence_local"
num_total_tests=$((num_total_tests + 1))
timeout 5m cargo run --bin integration-tests -- --check=poi_divergence_local 2>&1 | tee logs/poi_divergence_local_logs.log
timeout_exit_code=${PIPESTATUS[0]}
if [ $timeout_exit_code -eq 0 ]; then
    echo "poi_divergence_local - ✓"
    num_success_tests=$((num_success_tests + 1))
    rm logs/poi_divergence_local_logs.log
elif [ $timeout_exit_code -eq 124 ]; then
    echo "poi_divergence_local - timeout"
    num_timeout_tests=$((num_timeout_tests + 1))
    names_of_failed_tests+=("poi_divergence_local")
else
    echo "poi_divergence_local - ✗"
    num_fail_tests=$((num_fail_tests + 1))
    names_of_failed_tests+=("poi_divergence_local")
fi

# Stop containers and print summary report
stop_containers
