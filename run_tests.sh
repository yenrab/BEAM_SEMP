#!/bin/bash

# Multiplexing and Backpressure Test Suite
# Based on the comprehensive testing plan

set -e

echo "=== Multiplexing and Backpressure Test Suite ==="
echo ""

# Check if rebar3 is available
if ! command -v rebar3 &> /dev/null; then
    echo "Error: rebar3 not found. Please install rebar3 first."
    exit 1
fi

# Create test directories
mkdir -p test/results
mkdir -p logs
mkdir -p _build/test/cover
mkdir -p coverdata

# Function to run tests with error handling
run_test_phase() {
    local phase_name="$1"
    local command="$2"
    local description="$3"
    
    echo "=== $phase_name ==="
    echo "$description"
    echo "Running: $command"
    echo ""
    
    if eval "$command"; then
        echo "✅ $phase_name completed successfully"
        echo ""
    else
        echo "❌ $phase_name failed"
        echo ""
        return 1
    fi
}

# Function to check test results
check_test_results() {
    local test_type="$1"
    local result_dir="$2"
    
    if [ -d "$result_dir" ] && [ "$(ls -A $result_dir 2>/dev/null)" ]; then
        echo "📊 $test_type results available in $result_dir"
    else
        echo "⚠️  No $test_type results found in $result_dir"
    fi
}

# Clean and compile first
echo "=== Setup Phase ==="
echo "Cleaning and compiling project..."
echo ""

rebar3 clean
rebar3 as test compile

if [ $? -ne 0 ]; then
    echo "❌ Compilation failed. Please fix compilation errors first."
    exit 1
fi

echo "✅ Compilation successful"
echo ""

# Phase 1: Unit Tests (EUnit) - Working minimal tests
echo "=== Phase 1: Unit Tests (EUnit) - Minimal Tests ==="
echo "Running minimal unit tests in isolated environment..."
run_test_phase "Phase 1: Unit Tests (EUnit)" \
    "rebar3 as test eunit --dir=test/unit/isolated" \
    "Running minimal unit tests with isolated mocking..."

# Phase 2: Integration Tests (Common Test)
run_test_phase "Phase 2: Integration Tests (Common Test)" \
    "rebar3 as test ct --suite=test/integration/fsm_integration_SUITE" \
    "Running integration tests with real components..."

# Check integration test results
check_test_results "Integration test" "logs"

# Phase 3: System Tests - Multiplexing
run_test_phase "Phase 3a: System Tests - Multiplexing" \
    "rebar3 as test ct --suite=test/system/multiplexing_SUITE" \
    "Running system tests for multiplexing functionality..."

# Phase 3: System Tests - Backpressure
run_test_phase "Phase 3b: System Tests - Backpressure" \
    "rebar3 as test ct --suite=test/system/backpressure_SUITE" \
    "Running system tests for backpressure functionality..."

# After all tests in phases, collect any scattered .coverdata files
find . -maxdepth 1 -name "*.coverdata" -print -exec mv -f {} coverdata/ \; || true

# Phase 4: Performance Tests
run_test_phase "Phase 4: Performance Tests" \
    "rebar3 as test ct --suite=test/system/performance_SUITE" \
    "Running performance benchmarks..."

# Phase 5: Coverage Report
echo "=== Phase 5: Test Coverage Report ==="
echo "Generating coverage report..."
echo ""

if rebar3 as test cover --verbose; then
    echo "✅ Coverage report generated successfully"
    echo ""
    
    # Check if coverage report exists
    if [ -f "_build/test/cover/index.html" ]; then
        echo "📊 Coverage report available at: _build/test/cover/index.html"
        echo "   Open in browser: file://$(pwd)/_build/test/cover/index.html"
    else
        echo "⚠️  Coverage report not found"
    fi
else
    echo "❌ Coverage report generation failed"
    echo ""
fi

# Final sweep: ensure any late-written coverdata files are collected
find . -maxdepth 1 -name "*.coverdata" -print -exec mv -f {} coverdata/ \; || true

# Summary
echo "=== Test Suite Summary ==="
echo ""

# Check all test results
echo "📁 Test Results Locations:"
echo "   - Unit tests: test/results/"
echo "   - Integration/System tests: logs/"
echo "   - Coverage report: _build/test/cover/"
echo ""

# Count test files
unit_tests=$(find test/unit -name "*.erl" 2>/dev/null | wc -l)
integration_tests=$(find test/integration -name "*_SUITE.erl" 2>/dev/null | wc -l)
system_tests=$(find test/system -name "*_SUITE.erl" 2>/dev/null | wc -l)

echo "📊 Test Suite Statistics:"
echo "   - Unit test modules: $unit_tests"
echo "   - Integration test suites: $integration_tests"
echo "   - System test suites: $system_tests"
echo ""

# Performance targets reminder
echo "🎯 Performance Targets:"
echo "   - Throughput: > 10,000 requests/sec per connection"
echo "   - Latency p99: < 50ms"
echo "   - Max connections: > 1,000 concurrent"
echo "   - Memory per connection: < 100KB"
echo "   - Backpressure latency: < 10ms"
echo ""

# Coverage targets reminder
echo "📈 Coverage Targets:"
echo "   - Unit Tests: 90% code coverage"
echo "   - Integration Tests: 85% path coverage"
echo "   - System Tests: 100% critical path coverage"
echo "   - Overall: 85% combined coverage"
echo ""

echo "=== All Tests Completed ==="
echo ""

# Optional: Open coverage report in browser (macOS)
if command -v open &> /dev/null && [ -f "_build/test/cover/index.html" ]; then
    echo "🌐 Opening coverage report in browser..."
    open "_build/test/cover/index.html"
fi

echo "✅ Test suite execution completed successfully!"
echo ""
echo "For detailed test execution, run individual phases:"
echo "  rebar3 as test eunit                                    # Unit tests only"
echo "  rebar3 as test ct --suite=test/integration/*_SUITE     # Integration tests only"
echo "  rebar3 as test ct --suite=test/system/*_SUITE         # System tests only"
echo "  rebar3 as test cover --verbose                         # Coverage only"
echo ""