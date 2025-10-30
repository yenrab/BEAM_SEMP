#!/bin/bash

# Unit test runner with process isolation to avoid mocking conflicts

set -e

echo "=== Unit Tests with Process Isolation ==="
echo ""

# Test modules to run
TEST_MODULES=(
    "trust_conn_sup_unit_tests"
    "trust_listener_unit_tests" 
    "trust_rpc_worker_unit_tests"
    "trust_conn_fsm_unit_tests"
)

# Run each test module in isolation
for module in "${TEST_MODULES[@]}"; do
    echo "Running $module in isolation..."
    rebar3 as test eunit --dir=test/unit --module="$module" || {
        echo "❌ $module failed"
        continue
    }
    echo "✅ $module passed"
    echo ""
done

echo "=== Unit Tests Complete ==="
