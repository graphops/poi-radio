#!/bin/bash

# Function to kill child processes when SIGINT is received
function clean_up {
    echo "Cleaning up child processes..."
    kill $(jobs -p) 2>/dev/null
    [ -n "$basic_instance_pid_1" ] && kill "$basic_instance_pid_1" 2>/dev/null
    [ -n "$basic_instance_pid_2" ] && kill "$basic_instance_pid_2" 2>/dev/null
    [ -n "$invalid_payload_pid" ] && kill "$invalid_payload_pid" 2>/dev/null
    [ -n "$invalid_nonce_pid" ] && kill "$invalid_nonce_pid" 2>/dev/null
    [ -n "$invalid_block_hash_pid" ] && kill "$invalid_block_hash_pid" 2>/dev/null
    [ -n "$divergent_instance_pid_1" ] && kill "$divergent_instance_pid_1" 2>/dev/null
    [ -n "$divergent_instance_pid_2" ] && kill "$divergent_instance_pid_2" 2>/dev/null
    echo "Exiting..."
    exit
}

# Trap SIGINT signal (Ctrl+C) and call clean_up function
trap clean_up SIGINT

# Create logs directory if it doesn't exist
mkdir -p logs

# Variables for summary report
num_total_tests=0
num_success_tests=0
num_fail_tests=0
names_of_failed_tests=()

# Function to print summary report
print_summary_report() {
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

run_test() {
    local test_name=$1
    local test_path=$2
    local test_env=$3
    echo "Running test: $test_name"
    num_total_tests=$((num_total_tests + 1))

    if [ "$test_name" == "run_basic_instance" ]; then
        for i in {1..2}; do
            if [ "$(uname)" == "Darwin" ]; then
                sudo ifconfig lo0 alias 127.0.0.2 up
                (RUST_BACKTRACE=1 RUST_LOG="off,hyper=off,graphcast_sdk=debug,poi_radio=trace,integration_tests=trace" cargo test --lib -- $test_path "$test_env" >"logs/${test_name}_${i}_logs.log" 2>&1) &
                if [ "$i" -eq 1 ]; then
                    basic_instance_pid_1=$!
                else
                    basic_instance_pid_2=$!
                fi
            else
                sudo ip netns add basic_instance_${i}
                sudo ip netns exec basic_instance_${i} bash -c "(RUST_BACKTRACE=1 RUST_LOG=\"off,hyper=off,graphcast_sdk=debug,poi_radio=trace,integration_tests=trace\" cargo test --lib -- $test_path \"$test_env\" > \"logs/${test_name}_${i}_logs.log\" 2>&1) &"
                if [ "$i" -eq 1 ]; then
                    basic_instance_pid_1=$!
                else
                    basic_instance_pid_2=$!
                fi
            fi
        done
    elif [ "$test_name" == "setup_invalid_payload_instance" ]; then
        (RUST_BACKTRACE=1 RUST_LOG="off,hyper=off,graphcast_sdk=debug,poi_radio=trace,integration_tests=trace" cargo test --lib -- $test_path "$test_env" >"logs/${test_name}_logs.log" 2>&1) &
        invalid_payload_pid=$!
    elif [ "$test_name" == "setup_invalid_nonce_instance" ]; then
        (RUST_BACKTRACE=1 RUST_LOG="off,hyper=off,graphcast_sdk=debug,poi_radio=trace,integration_tests=trace" cargo test --lib -- $test_path "$test_env" >"logs/${test_name}_logs.log" 2>&1) &
        invalid_nonce_pid=$!
    elif [ "$test_name" == "setup_invalid_block_hash_instance" ]; then
        (RUST_BACKTRACE=1 RUST_LOG="off,hyper=off,graphcast_sdk=debug,poi_radio=trace,integration_tests=trace" cargo test --lib -- $test_path "$test_env" >"logs/${test_name}_logs.log" 2>&1) &
        invalid_block_hash_pid=$!
    else
        RUST_BACKTRACE=1 RUST_LOG="off,hyper=off,graphcast_sdk=debug,poi_radio=trace,integration_tests=trace" cargo test --lib -- $test_path "$test_env" >"logs/${test_name}_logs.log" 2>&1
        if [ $? -eq 0 ]; then
            echo "$test_name - ✓"
            num_success_tests=$((num_success_tests + 1))
        else
            echo "$test_name - ✗"
            num_fail_tests=$((num_fail_tests + 1))
            names_of_failed_tests+=("$test_name")
        fi
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
    done
}

# Start time
start_time=$SECONDS

run_test "run_basic_instance" "integration_tests::setup::basic::tests::run_basic_instance" "RUST_LOG=trace"
run_test "simple_tests" "integration_tests::checks::simple_tests::tests::run_simple_tests" "RUST_LOG=trace"
run_test "invalid_messages" "integration_tests::checks::invalid_messages::tests::test_invalid_messages" "RUST_LOG=trace"
run_test "invalid_sender" "integration_tests::checks::invalid_sender::tests::test_invalid_sender_check" "RUST_LOG=trace"

# Print summary report and exit
print_summary_report
