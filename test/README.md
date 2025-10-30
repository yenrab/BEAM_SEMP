# Multiplexing and Backpressure Test Suite

This directory contains comprehensive tests for the TRUST Windowed Multiplexing and Backpressure implementation.

## Test Structure

```
test/
├── unit/                          # EUnit tests (mocked dependencies)
│   ├── trust_conn_fsm_unit_tests.erl
│   ├── trust_rpc_worker_unit_tests.erl
│   ├── trust_conn_sup_unit_tests.erl
│   └── trust_listener_unit_tests.erl
├── integration/                   # Common Test (real components)
│   ├── fsm_integration_SUITE.erl
│   ├── worker_integration_SUITE.erl
│   └── security_integration_SUITE.erl
├── system/                        # Common Test (full system)
│   ├── multiplexing_SUITE.erl
│   ├── backpressure_SUITE.erl
│   └── performance_SUITE.erl
├── test_helpers.erl               # Test helper functions
├── mock_modules.erl               # Mock module implementations
└── README.md                      # This file
```

## Test Execution

### Quick Start

```bash
# Run all tests
./run_tests.sh

# Run specific test phases
rebar3 eunit                                    # Unit tests only
rebar3 ct --suite=test/integration/*_SUITE     # Integration tests only
rebar3 ct --suite=test/system/*_SUITE          # System tests only
```

### Individual Test Suites

```bash
# Unit tests
rebar3 eunit --module=trust_conn_fsm_unit_tests
rebar3 eunit --module=trust_rpc_worker_unit_tests
rebar3 eunit --module=trust_conn_sup_unit_tests
rebar3 eunit --module=trust_listener_unit_tests

# Integration tests
rebar3 ct --suite=test/integration/fsm_integration_SUITE
rebar3 ct --suite=test/integration/worker_integration_SUITE
rebar3 ct --suite=test/integration/security_integration_SUITE

# System tests
rebar3 ct --suite=test/system/multiplexing_SUITE
rebar3 ct --suite=test/system/backpressure_SUITE
rebar3 ct --suite=test/system/performance_SUITE
```

## Test Coverage

### Unit Tests (EUnit)
- **Target**: 90% code coverage
- **Framework**: EUnit with mocking
- **Dependencies**: meck, proper
- **Execution**: Fast (< 1 minute)
- **Scope**: Individual modules with mocked dependencies

### Integration Tests (Common Test)
- **Target**: 85% path coverage
- **Framework**: Common Test with real components
- **Dependencies**: Real OTP application, TLS sockets
- **Execution**: Medium (< 10 minutes)
- **Scope**: Component interactions with real dependencies

### System Tests (Common Test)
- **Target**: 100% critical path coverage
- **Framework**: Common Test with full system
- **Dependencies**: Complete application stack
- **Execution**: Longer (< 30 minutes)
- **Scope**: End-to-end functionality

## Test Categories

### 1. Unit Tests

#### FSM State Machine Tests
- FSM initialization with config override
- State transitions (handshake → active → draining → closing)
- Session window enforcement (max_calls, max_age_ms, idle_ms)
- Duplicate request ID detection
- Frame size validation
- Worker spawn logic
- Backpressure triggers (max_inflight reached)
- GOAWAY generation (all reasons)
- Telemetry event emission

#### Worker Tests
- Worker initialization with FSM pid
- MFA execution (call vs cast)
- Permission checking (whitelist, forbidden MFAs)
- Response/error sending to FSM
- Telemetry event emission
- Security integration (suspicion tracking)

#### Supervisor Tests
- Dynamic supervisor initialization
- Child spec validation
- Restart strategy (one_for_one)
- Child termination handling

#### Listener Tests
- Listener initialization
- Accept loop logic
- FSM spawning with correct parameters
- Socket handoff to FSM
- Connection tracking

### 2. Integration Tests

#### FSM Integration
- Complete FSM lifecycle with real components
- Token validation integration
- Worker spawning and monitoring
- Request/response flow
- Session window behavior
- GOAWAY handling

#### Worker Integration
- Worker-FSM communication flow
- Real MFA execution
- Permission checking with real ETS tables
- Error propagation

#### Security Integration
- Token validation flow
- Whitelist enforcement
- Suspicion tracking
- Forbidden MFA blocking

### 3. System Tests

#### Multiplexing System
- End-to-end multiplexed session
- Multiple requests over single connection
- Request correlation (req_id matching)
- Concurrent request handling
- Out-of-order response handling

#### Backpressure System
- Socket pause/resume behavior
- TCP backpressure integration
- Request queuing when max_inflight reached
- Resume after worker completion
- Flow control under load

#### Performance Benchmarks
- Throughput benchmarks
- Latency measurements
- Connection capacity
- Memory usage under load
- CPU usage profiling

## Performance Targets

- **Throughput**: > 10,000 requests/sec per connection
- **Latency p99**: < 50ms
- **Max connections**: > 1,000 concurrent
- **Memory per connection**: < 100KB
- **Backpressure latency**: < 10ms

## Test Configuration

### rebar.config
```erlang
{profiles, [
    {test, [
        {erl_opts, [debug_info, nowarn_export_all]},
        {deps, [
            meck,  %% For mocking in unit tests
            proper  %% For property-based testing
        ]},
        {ct_opts, [
            {dir, "test/integration"},
            {dir, "test/system"},
            {logdir, "logs"},
            {cover_enabled, true},
            {cover_opts, [verbose]}
        ]},
        {eunit_opts, [
            verbose,
            {report, {eunit_surefire, [{dir, "test/results"}]}}
        ]}
    ]}
]}.
```

## Test Helpers

### test_helpers.erl
- `setup_test_env/0` - Sets up test environment with mocked dependencies
- `cleanup_test_env/1` - Cleans up test environment
- `create_test_socket/0` - Creates mock SSL socket
- `create_test_certificate/0` - Creates test certificate
- `mock_telemetry/0` - Sets up telemetry mocking
- `capture_telemetry_events/0` - Captures telemetry events for verification
- `create_test_client_id/0` - Creates test client ID
- `setup_whitelist/1` - Sets up whitelist for testing

### mock_modules.erl
- `mock_ssl/0` - Mocks SSL module for testing
- `mock_trust_token/0` - Mocks trust_token module
- `mock_trust_suspicion/0` - Mocks trust_suspicion module
- `mock_semp_whitelist/0` - Mocks semp_whitelist module
- `mock_semp_policy/0` - Mocks semp_policy module
- `unmock_all/0` - Unmocks all modules

## CI/CD Integration

### GitHub Actions Workflow
```yaml
name: Test Suite

on: [push, pull_request]

jobs:
  unit:
    runs-on: ubuntu-latest
    steps:
         - uses: actions/checkout@v2
         - uses: erlef/setup-beam@v1
        with:
          otp-version: '26.0'
          rebar3-version: '3.22'
         - run: rebar3 eunit
         - run: rebar3 cover --verbose

  integration:
    runs-on: ubuntu-latest
    needs: unit
    steps:
         - uses: actions/checkout@v2
         - uses: erlef/setup-beam@v1
         - run: rebar3 ct --suite=test/integration/*_SUITE

  system:
    runs-on: ubuntu-latest
    needs: integration
    steps:
         - uses: actions/checkout@v2
         - uses: erlef/setup-beam@v1
         - run: rebar3 ct --suite=test/system/*_SUITE

  performance:
    runs-on: ubuntu-latest
    needs: system
    if: github.ref == 'refs/heads/main'
    steps:
         - uses: actions/checkout@v2
         - uses: erlef/setup-beam@v1
         - run: rebar3 ct --suite=test/system/performance_SUITE
         - run: python scripts/analyze_performance.py
```

## Test Reports

### Coverage Reports
- Location: `_build/test/cover/`
- Format: HTML and XML
- Target: 85% overall coverage

### Test Results
- Location: `test/results/`
- Format: JUnit XML
- Includes: Test execution time, pass/fail status

### Test Logs
- Location: `logs/`
- Format: Text logs
- Includes: Detailed test execution logs

## Success Criteria

- All unit tests pass
- All integration tests pass
- All system tests pass
- Performance benchmarks meet targets
- Code coverage meets targets
- No memory leaks detected
- All edge cases covered
- Documentation complete

## Troubleshooting

### Common Issues

1. **Mock failures**: Ensure all dependencies are properly mocked
2. **Timeout issues**: Increase timeout values for slow tests
3. **Memory leaks**: Check for proper cleanup in test cases
4. **Coverage gaps**: Add more test cases for uncovered code paths

### Debug Mode

```bash
# Run tests with debug output
rebar3 eunit --verbose
rebar3 ct --verbose

# Run specific test with debug
rebar3 eunit --module=trust_conn_fsm_unit_tests --verbose
```

### Performance Analysis

```bash
# Run performance tests with profiling
rebar3 ct --suite=test/system/performance_SUITE --verbose

# Analyze memory usage
rebar3 ct --suite=test/system/performance_SUITE --cover
```
