%%%-------------------------------------------------------------------
%% @doc Unit tests for trust_rpc_worker using EUnit with mocking.
%% @end
%%%-------------------------------------------------------------------

-module(trust_rpc_worker_unit_tests).
-include_lib("eunit/include/eunit.hrl").

%%--------------------------------------------------------------------
%% @doc Test suite setup and teardown.
%% @end
%%--------------------------------------------------------------------
worker_unit_test_() ->
    {foreach,
     fun setup_worker_test/0,
     fun cleanup_worker_test/1,
     [
        fun worker_executes_allowed_mfa_test/1,
        fun worker_rejects_forbidden_mfa_test/1,
        fun worker_rejects_non_whitelisted_client_test/1,
        fun worker_sends_response_to_fsm_test/1,
        fun worker_sends_error_to_fsm_on_crash_test/1,
        fun worker_emits_telemetry_on_completion_test/1,
        fun worker_emits_telemetry_on_crash_test/1
     ]}.

%%--------------------------------------------------------------------
%% @doc Sets up worker test environment.
%% @end
%%--------------------------------------------------------------------
setup_worker_test() ->
    %% Clean up any existing mocks first
    meck:unload(),
    
    %% Setup test environment
    {WhitelistTab, PolicyTab} = test_helpers:setup_test_env(),
    
    %% Mock all dependencies
    mock_modules:mock_semp_whitelist(),
    mock_modules:mock_semp_policy(),
    
    %% Mock FSM communication
    meck:new(gen_statem, [unstick, passthrough]),
    meck:expect(gen_statem, cast, fun(_Pid, _Msg) -> ok end),
    
    %% Mock telemetry
    meck:new(telemetry, [unstick, passthrough]),
    meck:expect(telemetry, execute, fun(_Event, _Measurements, _Metadata) -> ok end),
    
    %% Create test FSM pid
    FsmPid = spawn(fun() -> receive _ -> ok end end),
    
    {FsmPid, WhitelistTab, PolicyTab}.

%%--------------------------------------------------------------------
%% @doc Cleans up worker test environment.
%% @end
%%--------------------------------------------------------------------
cleanup_worker_test({_FsmPid, WhitelistTab, PolicyTab}) ->
    mock_modules:unmock_all(),
    test_helpers:cleanup_test_env({WhitelistTab, PolicyTab}),
    ok.

%%--------------------------------------------------------------------
%% @doc Tests worker executes allowed MFA.
%% @end
%%--------------------------------------------------------------------
worker_executes_allowed_mfa_test({FsmPid, _WhitelistTab, _PolicyTab}) ->
    %% Mock whitelist to allow client
    meck:expect(semp_whitelist, is_allowed, fun(_Type, _ClientId) -> true end),
    
    %% Mock policy to allow MFA
    meck:expect(semp_policy, is_forbidden, fun(_M, _F, _A) -> false end),
    
    %% Start worker
    ReqId = 1,
    MFA = {lists, reverse, [1,2,3,4,5]},
    Args = [[1,2,3,4,5]],
    {ok, Pid} = trust_rpc_worker:start_link(FsmPid, ReqId, call, MFA, Args),
    
    %% Wait for worker to complete
    timer:sleep(100),
    
    %% Verify worker completed successfully
    ?assertNot(is_process_alive(Pid)),
    
    %% Verify FSM was notified
    ?assert(meck:called(gen_statem, cast, [FsmPid, '_'])),
    
    %% Cleanup
    ok.

%%--------------------------------------------------------------------
%% @doc Tests worker rejects forbidden MFA.
%% @end
%%--------------------------------------------------------------------
worker_rejects_forbidden_mfa_test({FsmPid, _WhitelistTab, _PolicyTab}) ->
    %% Mock whitelist to allow client
    meck:expect(semp_whitelist, is_allowed, fun(_Type, _ClientId) -> true end),
    
    %% Mock policy to forbid MFA
    meck:expect(semp_policy, is_forbidden, fun(_M, _F, _A) -> true end),
    
    %% Start worker
    ReqId = 1,
    MFA = {os, cmd, ["rm -rf /"]},
    Args = [["rm -rf /"]],
    {ok, Pid} = trust_rpc_worker:start_link(FsmPid, ReqId, call, MFA, Args),
    
    %% Wait for worker to complete
    timer:sleep(100),
    
    %% Verify worker completed (should have rejected)
    ?assertNot(is_process_alive(Pid)),
    
    %% Cleanup
    ok.

%%--------------------------------------------------------------------
%% @doc Tests worker rejects non-whitelisted client.
%% @end
%%--------------------------------------------------------------------
worker_rejects_non_whitelisted_client_test({FsmPid, _WhitelistTab, _PolicyTab}) ->
    %% Mock whitelist to reject client
    meck:expect(semp_whitelist, is_allowed, fun(_Type, _ClientId) -> false end),
    
    %% Start worker
    ReqId = 1,
    MFA = {lists, reverse, [1,2,3,4,5]},
    Args = [[1,2,3,4,5]],
    {ok, Pid} = trust_rpc_worker:start_link(FsmPid, ReqId, call, MFA, Args),
    
    %% Wait for worker to complete
    timer:sleep(100),
    
    %% Verify worker completed (should have rejected)
    ?assertNot(is_process_alive(Pid)),
    
    %% Cleanup
    ok.

%%--------------------------------------------------------------------
%% @doc Tests worker sends response to FSM.
%% @end
%%--------------------------------------------------------------------
worker_sends_response_to_fsm_test({FsmPid, _WhitelistTab, _PolicyTab}) ->
    %% Mock whitelist to allow client
    meck:expect(semp_whitelist, is_allowed, fun(_Type, _ClientId) -> true end),
    
    %% Mock policy to allow MFA
    meck:expect(semp_policy, is_forbidden, fun(_M, _F, _A) -> false end),
    
    %% Start worker
    ReqId = 1,
    MFA = {lists, reverse, [1,2,3,4,5]},
    Args = [[1,2,3,4,5]],
    {ok, Pid} = trust_rpc_worker:start_link(FsmPid, ReqId, call, MFA, Args),
    
    %% Wait for worker to complete
    timer:sleep(100),
    
    %% Verify FSM was called with response frame
    Calls = meck:history(gen_statem, cast),
    ResponseCalls = [Call || Call <- Calls, 
        element(2, Call) =:= [FsmPid, {send_frame, '_'}]],
    ?assert(length(ResponseCalls) > 0),
    
    %% Cleanup
    ok.

%%--------------------------------------------------------------------
%% @doc Tests worker sends error to FSM on crash.
%% @end
%%--------------------------------------------------------------------
worker_sends_error_to_fsm_on_crash_test({FsmPid, _WhitelistTab, _PolicyTab}) ->
    %% Mock whitelist to allow client
    meck:expect(semp_whitelist, is_allowed, fun(_Type, _ClientId) -> true end),
    
    %% Mock policy to allow MFA
    meck:expect(semp_policy, is_forbidden, fun(_M, _F, _A) -> false end),
    
    %% Start worker with MFA that will crash
    ReqId = 1,
    MFA = {erlang, error, [test_error]},
    Args = [[test_error]],
    {ok, Pid} = trust_rpc_worker:start_link(FsmPid, ReqId, call, MFA, Args),
    
    %% Wait for worker to crash and handle it
    timer:sleep(100),
    
    %% Verify FSM was called with error frame
    Calls = meck:history(gen_statem, cast),
    ErrorCalls = [Call || Call <- Calls, 
        element(2, Call) =:= [FsmPid, {send_frame, '_'}]],
    ?assert(length(ErrorCalls) > 0),
    
    %% Cleanup
    ok.

%%--------------------------------------------------------------------
%% @doc Tests worker emits telemetry on completion.
%% @end
%%--------------------------------------------------------------------
worker_emits_telemetry_on_completion_test({FsmPid, _WhitelistTab, _PolicyTab}) ->
    %% Mock whitelist to allow client
    meck:expect(semp_whitelist, is_allowed, fun(_Type, _ClientId) -> true end),
    
    %% Mock policy to allow MFA
    meck:expect(semp_policy, is_forbidden, fun(_M, _F, _A) -> false end),
    
    %% Start worker
    ReqId = 1,
    MFA = {lists, reverse, [1,2,3,4,5]},
    Args = [[1,2,3,4,5]],
    {ok, Pid} = trust_rpc_worker:start_link(FsmPid, ReqId, call, MFA, Args),
    
    %% Wait for worker to complete
    timer:sleep(100),
    
    %% Verify telemetry was called
    ?assert(meck:called(telemetry, execute, ['_', '_', '_'])),
    
    %% Cleanup
    ok.

%%--------------------------------------------------------------------
%% @doc Tests worker emits telemetry on crash.
%% @end
%%--------------------------------------------------------------------
worker_emits_telemetry_on_crash_test({FsmPid, _WhitelistTab, _PolicyTab}) ->
    %% Mock whitelist to allow client
    meck:expect(semp_whitelist, is_allowed, fun(_Type, _ClientId) -> true end),
    
    %% Mock policy to allow MFA
    meck:expect(semp_policy, is_forbidden, fun(_M, _F, _A) -> false end),
    
    %% Start worker with MFA that will crash
    ReqId = 1,
    MFA = {erlang, error, [test_error]},
    Args = [[test_error]],
    {ok, Pid} = trust_rpc_worker:start_link(FsmPid, ReqId, call, MFA, Args),
    
    %% Wait for worker to crash and handle it
    timer:sleep(100),
    
    %% Verify telemetry was called for crash
    Calls = meck:history(telemetry, execute),
    CrashCalls = [Call || Call <- Calls, 
        element(2, Call) =:= [trust, worker, crash]],
    ?assert(length(CrashCalls) > 0),
    
    %% Cleanup
    ok.
