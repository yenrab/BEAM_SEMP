# Spiral Test Coverage Plan

## Overview
This plan outlines a spiral approach to test coverage, starting with isolated modules and progressing to modules with increasing dependencies. Target: 85% overall coverage (Unit: 90%, Integration: 85%, System: 100% critical paths).

## Architectural Refactoring Principle

**Critical Requirement:** Facade functions are to be created **only for dependencies external to semp and trust modules** (e.g., `ssl`, `inet`, `io`, `persistent_term`, `telemetry`). Existing semp and trust modules (`semp_whitelist`, `semp_policy`, `trust_token`, `trust_suspicion`, etc.) are easily mocked directly and should NOT be wrapped in facades.

**Important:** Mocking of facade functions is intended **only for unit tests**. Integration tests and system tests should use the real facade implementations (which delegate to the actual libraries) to verify end-to-end behavior.

**Refactoring Rules:**

**External dependencies (require facades):**
- Direct `ssl:*` calls → replace with `semp_facades:*` equivalents
- Direct `inet:*` calls → create facade functions in `semp_facades` and replace
- Direct `io:*` calls → create facade functions in `semp_facades` and replace
- Direct `persistent_term:*` calls → create facade functions in `semp_facades` and replace
- Direct `telemetry:*` calls (if not already wrapped) → create facade functions in `semp_facades` and replace

**Internal semp/trust modules (mock directly, no facades needed):**
- `semp_whitelist:*` calls → mock directly in unit tests (do not create facades)
- `semp_policy:*` calls → mock directly in unit tests (do not create facades)
- `trust_token:*` calls → mock directly in unit tests (do not create facades)
- `trust_suspicion:*` calls → mock directly in unit tests (do not create facades)
- Other semp/trust modules → mock directly in unit tests (do not create facades)

**Note:** The codebase currently contains facade functions for `trust_token` and `trust_suspicion` in `semp_facades.erl`. These should be **removed** and direct calls to these modules should be used instead. Any code using `semp_facades:trust_token_*` or `semp_facades:trust_suspicion_*` should be refactored to call the modules directly.

**Before writing tests, verify:**
1. All external dependencies (outside semp/trust) go through facades
2. Internal semp/trust modules are called directly (no facades)
3. Facade modules only contain functions for external dependencies
4. Source code uses facade calls for external libraries, direct calls for internal modules

**Testing Strategy:**
- **Unit Tests:** Mock internal semp/trust modules directly; mock facade functions (for external dependencies) to isolate the module under test
- **Integration Tests:** Use real implementations (no mocks) to test module interactions
- **System Tests:** Use real implementations (no mocks) to test end-to-end behavior

## Dependency Analysis Summary

### Tier 0: No Project Dependencies (0%)
Modules that only depend on stdlib/kernel/external libraries:
- `semp_dns` (0% coverage) - DNS resolution, uses `inet` only. **Refactor:** Add facade functions for `inet` operations.
- `semp_events` (0% coverage) - Telemetry wrapper (facade), should not be tested.
- `semp_io` (44% coverage) - ANSI color printing, uses `io` only. **Refactor:** Add facade functions for `io` operations.
- `semp_policy` (36% coverage) - Policy checking, uses `persistent_term` only. **Refactor:** Add facade for `persistent_term` operations.
- `semp_kill_it_all` (85% coverage) - Distribution control
- `trust_ssl_facade` (0% coverage) - SSL facade wrapper, should not be tested.
- `trpc_loader` (40% coverage) - API loader
- `trpc` (0% coverage) - TRPC protocol

### Tier 1: Minimal Dependencies (1-2 modules)
- `semp_util` (18% coverage) - depends on `semp_facades` (for SSL operations only)
- `semp_facades` (0% coverage) - facade wrapper for external dependencies only, should not be tested.
- `semp_whitelist` (6% coverage) - depends on `semp_util`. **Mock directly in tests.**
- `trust_token` (0% coverage) - standalone ETS operations. **Mock directly in tests.**
- `trust_suspicion` (0% coverage) - standalone ETS, optionally `semp_whitelist`. **Mock directly in tests.**

### Tier 2: Moderate Dependencies (3-4 modules)
- `trust_rpc_worker` (44% coverage) - depends on `semp_policy`, `semp_whitelist`. **Mock directly in tests.**
- `trust_conn` (0% coverage) - depends on `semp_facades`, `semp_util`, `semp_whitelist`, `trust_suspicion`, `semp_policy`. **Refactor:** Replace any `semp_facades:trust_token_*` or `semp_facades:trust_suspicion_*` calls with direct module calls. **Mock internal modules directly in tests.**

### Tier 3: High Dependencies (5+ modules)
- `trust_conn_fsm` (31% coverage) - depends on `semp_facades`, `semp_util`, `trust_suspicion`, `trust_conn_worker_sup`, `telemetry`. **Refactor:** Replace any `semp_facades:trust_token_*` or `semp_facades:trust_suspicion_*` calls with direct module calls. **Mock internal modules directly in tests.**
- `trust_listener` (8% coverage) - depends on `semp_facades`, `semp_whitelist`, `trust_suspicion`, `trust_token`, `trust_conn_fsm`. **Refactor:** Replace any `semp_facades:trust_token_*` or `semp_facades:trust_suspicion_*` calls with direct module calls. **Mock internal modules directly in tests.**

## Spiral Test Implementation Plan

### Phase 1: Foundation (Tier 0) - Target: 90% coverage

**Priority:**

1. `semp_dns` - `test/unit/semp_dns_unit_tests.erl`
   - **Refactor First:** Add `semp_facades:inet_parse_address/1`, `semp_facades:inet_getaddrs/2` and replace direct `inet` calls in `semp_dns.erl`
   - Test `resolve/1` with IP literals (IPv4, IPv6)
   - Test `resolve/1` with hostnames (success, failure)
   - Test binary and string inputs

2. `semp_io` - `test/unit/semp_io_unit_tests.erl`
   - **Refactor First:** Add `semp_facades:io_put_chars/2` and replace direct `io` calls in `semp_io.erl`
   - Test `print_color/3` with various color specs
   - Test fallback paths (stderr, user, group_leader)

3. `semp_policy` - Expand existing tests (`semp_policy` currently 36%)
   - **Refactor First:** Add `semp_facades:persistent_term_get/1` and replace direct `persistent_term` calls in `semp_policy.erl`
   - Test `is_forbidden/3` with prefix matching
   - Test module-level bans
   - Test function-level bans
   - Test `default_map/0`

4. `trpc` - `test/unit/trpc_unit_tests.erl`
   - Test protocol encoding/decoding
   - Test error cases

### Phase 2: Core Utilities (Tier 1) - Target: 90% coverage

**Priority:**

1. `semp_util` (currently 18%) - Expand `test/unit/semp_util_unit_tests.erl`
   - **Refactor:** Verify all SSL calls use `semp_facades` (already uses `semp_facades:send`)
   - Test `send_frame/2` success and failure paths
   - Test `recv_frame/2` with valid/invalid frames
   - Test `cert_fingerprint_sha512/1`
   - Test `fp_hex/1` and `constant_time_eq/2`

2. `semp_whitelist` (6%) - `test/unit/semp_whitelist_unit_tests.erl`
   - **Refactor:** Verify uses `semp_facades` only for external dependencies (SSL/certificate operations)
   - **Mock:** Mock `semp_util` directly (not through facade)
   - Test `table/1`, `ensure/1`, `reload/1`
   - Test `is_allowed/2` with various specs
   - Test `spec/2` lookup
   - Test `whitelist_path/1` resolution
   - Test file loading and certificate processing

3. `trust_token` (0%) - `test/unit/trust_token_unit_tests.erl`
   - **Refactor:** Remove any facade wrappers; ensure code calls `trust_token:*` directly
   - **Mock:** Not needed (standalone module, mock in dependent modules' tests)
   - Test `ensure/0`, `table/0`
   - Test `issue/1` and `issue/2`
   - Test `token_for/1`, `validate/2`
   - Test `revoke_fp/1`, `gc_expired/0`
   - Test expiration and TTL logic

4. `trust_suspicion` (0%) - `test/unit/trust_suspicion_unit_tests.erl`
   - **Refactor:** Remove any facade wrappers; ensure code calls `trust_suspicion:*` directly
   - **Mock:** Mock `semp_whitelist` directly in tests that require it
   - Test `ensure/0`
   - Test `seed_from_whitelist/1`
   - Test `writePeer/1`, `bump/2`, `is_trusted/1`
   - Test quarantine thresholds

### Phase 3: Worker Components (Tier 2) - Target: 90% coverage

**Priority:**

1. `trust_rpc_worker` (44%) - Expand `test/unit/trust_rpc_worker_unit_tests.erl`
   - **Mock:** Mock `semp_whitelist` and `semp_policy` directly (no facades)
   - Test permission checking with `semp_whitelist`
   - Test policy enforcement with `semp_policy`
   - Test call vs cast execution
   - Test error handling and telemetry

2. `trust_conn` (0%) - `test/unit/trust_conn_unit_tests.erl`
   - **Refactor:** Replace `semp_facades:trust_token_*` calls with direct `trust_token:*` calls
   - **Refactor:** Replace `semp_facades:trust_suspicion_*` calls with direct `trust_suspicion:*` calls
   - **Refactor:** Ensure all SSL operations use `semp_facades`
   - **Mock:** Mock `semp_whitelist`, `semp_policy`, `trust_suspicion`, `trust_token` directly
   - Test TLS handshake success/failure
   - Test ALPN validation
   - Test whitelist and suspicion gates
   - Test token validation/issuance paths
   - Test MFA execution with permissions
   - Test error paths and connection cleanup

### Phase 4: Orchestration Components (Tier 3) - Target: 90% coverage

**Priority:**

1. `trust_conn_fsm` (31%) - Expand `test/unit/trust_conn_fsm_unit_tests.erl`
   - **Refactor:** Replace `semp_facades:trust_token_*` calls with direct `trust_token:*` calls
   - **Refactor:** Replace `semp_facades:trust_suspicion_*` calls with direct `trust_suspicion:*` calls
   - **Refactor:** Ensure all SSL operations use `semp_facades`
   - **Mock:** Mock `trust_suspicion`, `trust_token`, `trust_conn_worker_sup` directly
   - Test state transitions (handshake_token → active → draining → closing)
   - Test max_inflight backpressure
   - Test max_calls and draining
   - Test idle timeout
   - Test worker lifecycle and monitoring
   - Test frame decoding (call, cast, token)
   - Test GOAWAY generation

2. `trust_listener` (8%) - Expand `test/unit/trust_listener_unit_tests.erl`
   - **Refactor:** Replace `semp_facades:trust_token_*` calls with direct `trust_token:*` calls
   - **Refactor:** Replace any direct SSL calls with `semp_facades` if needed
   - **Mock:** Mock `semp_whitelist`, `trust_suspicion`, `trust_token`, `trust_conn_fsm` directly
   - Test listener initialization
   - Test accept loop and connection spawning
   - Test FSM child supervision
   - Test connection monitoring
   - Test error handling

### Phase 5: Integration Tests - Target: 85% path coverage

Expand existing integration tests:
- `test/integration/fsm_integration_SUITE.erl` - FSM lifecycle
- `test/integration/worker_integration_SUITE.erl` - Worker execution
- Add integration tests for:
  - End-to-end connection flow
  - Token lifecycle
  - Suspicion system behavior
  - Whitelist policy enforcement

**Note:** Integration tests use real implementations (no mocks) to verify module interactions.

### Phase 6: System Tests - Target: 100% critical path coverage

- `test/system/multiplexing_SUITE.erl` - Concurrent sessions
- `test/system/backpressure_SUITE.erl` - Backpressure scenarios
- `test/system/performance_SUITE.erl` - Performance validation

**Note:** System tests use real implementations (no mocks) to verify end-to-end behavior.

## Refactoring Checklist

### Remove Existing Incorrect Facades:
- [ ] Remove `semp_facades:trust_token_*` functions from `semp_facades.erl`
- [ ] Remove `semp_facades:trust_suspicion_*` functions from `semp_facades.erl`
- [ ] Refactor `trust_conn.erl` to call `trust_token:*` and `trust_suspicion:*` directly
- [ ] Refactor `trust_conn_fsm.erl` to call `trust_token:*` and `trust_suspicion:*` directly
- [ ] Refactor `trust_listener.erl` to call `trust_token:*` directly

### Tier 0 Modules (Add Facades for External Dependencies):
- [ ] `semp_dns`: Create `semp_facades:inet_parse_address/1`, `semp_facades:inet_getaddrs/2` and refactor
- [ ] `semp_io`: Create `semp_facades:io_put_chars/2` and refactor
- [ ] `semp_policy`: Create `semp_facades:persistent_term_get/1` and refactor

### Verify Facade Usage:
- [ ] Verify all SSL operations use `semp_facades` (not direct `ssl:` calls)
- [ ] Verify all `inet` operations use facades (where needed)
- [ ] Verify all `io` operations use facades (where needed)
- [ ] Verify all `persistent_term` operations use facades (where needed)
- [ ] Verify NO facade functions exist for internal semp/trust modules
- [ ] Verify internal semp/trust modules are called directly in source code
- [ ] Update `semp_facades.erl` to export only external dependency facades
- [ ] Verify facade functions delegate correctly to underlying external libraries

## File Locations
- Unit tests: `test/unit/`
- Integration tests: `test/integration/`
- System tests: `test/system/`
- Test helpers: `test/test_helpers.erl`
- Mock modules: `test/mock_modules.erl`

## Success Criteria
- Tier 0 modules: 90%+ coverage
- Tier 1 modules: 90%+ coverage  
- Tier 2 modules: 90%+ coverage
- Tier 3 modules: 90%+ coverage
- Overall: 85%+ combined coverage
- All critical paths tested in system tests
- All external dependencies routed through facades for testability
- All internal semp/trust modules mocked directly (no facades)
- No facade functions for internal modules

