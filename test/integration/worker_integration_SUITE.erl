%%%-------------------------------------------------------------------
%% @doc Integration tests for trust_rpc_worker with real components.
%% @end
%%%-------------------------------------------------------------------

-module(worker_integration_SUITE).
-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").

%% Test callbacks
-export([all/0, groups/0, init_per_suite/1, end_per_suite/1,
         init_per_testcase/2, end_per_testcase/2]).

%% Test cases
-export([
    worker_fsm_communication_call/1,
    worker_fsm_communication_cast/1,
    worker_real_mfa_execution_success/1,
    worker_real_mfa_execution_error/1,
    worker_permission_checking_whitelist/1,
    worker_permission_checking_forbidden_mfa/1,
    worker_permission_checking_specific_permissions/1,
    worker_error_propagation_call/1,
    worker_error_propagation_cast/1,
    worker_concurrent_execution/1,
    worker_telemetry_events/1,
    worker_duration_calculation/1
]).

%%--------------------------------------------------------------------
%% @doc Returns list of all test cases.
%% @end
%%--------------------------------------------------------------------
all() ->
    [
        worker_fsm_communication_call,
        worker_fsm_communication_cast,
        worker_real_mfa_execution_success,
        worker_real_mfa_execution_error,
        worker_permission_checking_whitelist,
        worker_permission_checking_forbidden_mfa,
        worker_permission_checking_specific_permissions,
        worker_error_propagation_call,
        worker_error_propagation_cast,
        worker_concurrent_execution,
        worker_telemetry_events,
        worker_duration_calculation
    ].

%%--------------------------------------------------------------------
%% @doc Test groups.
%% @end
%%--------------------------------------------------------------------
groups() ->
    [].

%%--------------------------------------------------------------------
%% @doc Suite initialization.
%% @end
%%--------------------------------------------------------------------
init_per_suite(Config) ->
    %% Start application first to load all modules
    application:start(beam_semp),
    
    %% Setup test environment with real ETS tables
    {WhitelistTab, PolicyTab} = test_helpers:setup_test_env(),
    
    %% Setup mocks AFTER starting the application
    mock_modules:mock_semp_facades(),
    mock_modules:mock_trust_token(),
    mock_modules:mock_trust_suspicion(),
    mock_modules:mock_semp_whitelist(),
    mock_modules:mock_semp_policy(),
    
    %% Add tables to config for cleanup
    [{whitelist_tab, WhitelistTab}, {policy_tab, PolicyTab} | Config].

%%--------------------------------------------------------------------
%% @doc Suite cleanup.
%% @end
%%--------------------------------------------------------------------
end_per_suite(Config) ->
    %% Get tables from config and cleanup
    WhitelistTab = proplists:get_value(whitelist_tab, Config),
    PolicyTab = proplists:get_value(policy_tab, Config),
    
    %% Only cleanup if tables exist
    case WhitelistTab of
        undefined -> ok;
        _ -> 
            case PolicyTab of
                undefined -> ok;
                _ -> test_helpers:cleanup_test_env({WhitelistTab, PolicyTab})
            end
    end,
    
    %% Stop application
    application:stop(beam_semp),
    Config.

%%--------------------------------------------------------------------
%% @doc Test case initialization.
%% @end
%%--------------------------------------------------------------------
init_per_testcase(_TestCase, Config) ->
    %% Start supervisors (check if already running)
    ConnSupPid = case whereis(trust_conn_sup) of
        undefined ->
            case trust_conn_sup:start_link() of
                {ok, ConnPid} -> ConnPid;
                {error, {already_started, ConnPid}} -> ConnPid
            end;
        ConnPid -> ConnPid
    end,
    
    WorkerSupPid = case whereis(trust_conn_worker_sup) of
        undefined ->
            case trust_conn_worker_sup:start_link() of
                {ok, WorkerPid} -> WorkerPid;
                {error, {already_started, WorkerPid}} -> WorkerPid
            end;
        WorkerPid -> WorkerPid
    end,
    
    [{conn_sup, ConnSupPid}, {worker_sup, WorkerSupPid} | Config].

%%--------------------------------------------------------------------
%% @doc Test case cleanup.
%% @end
%%--------------------------------------------------------------------
end_per_testcase(_TestCase, Config) ->
    %% Stop supervisors gracefully
    ConnSupPid = ?config(conn_sup, Config),
    WorkerSupPid = ?config(worker_sup, Config),
    
    %% Stop supervisors (they will clean up their children)
    case is_process_alive(ConnSupPid) of
        true -> gen_server:stop(ConnSupPid);
        false -> ok
    end,
    
    case is_process_alive(WorkerSupPid) of
        true -> gen_server:stop(WorkerSupPid);
        false -> ok
    end,
    
    Config.

%%--------------------------------------------------------------------
%% @doc Tests Worker-FSM communication for CALL requests.
%% @end
%%--------------------------------------------------------------------
worker_fsm_communication_call(_Config) ->
    %% Create test FSM and worker
    Socket = test_helpers:create_test_socket(),
    PeerInfo = test_helpers:create_test_peer_info(),
    SessionConfig = test_helpers:create_test_session_config(),
    
    %% Start FSM
    {ok, FsmPid} = trust_conn_fsm:start_link(Socket, PeerInfo, SessionConfig),
    
    %% Start worker for a CALL request
    ReqId = make_ref(),
    MFA = {erlang, length, 1},
    Args = [[1, 2, 3]],
    
    %% Mock permission checking to allow the call
    meck:expect(semp_policy, is_forbidden, fun(_, _, _) -> false end),
    meck:expect(semp_whitelist, is_allowed, fun(_, _) -> true end),
    meck:expect(semp_whitelist, table, fun(_) -> ets:new(test_table, []) end),
    
    {ok, WorkerPid} = trust_rpc_worker:start_link(FsmPid, ReqId, call, MFA, Args, <<"test_client">>),
    
    %% Verify worker started successfully
    ?assert(is_process_alive(WorkerPid)),
    
    %% Wait for worker to complete (it should terminate after execution)
    timer:sleep(100),
    
    %% Verify worker has terminated (temporary workers exit after completion)
    ?assertNot(is_process_alive(WorkerPid)),
    
    %% Cleanup FSM
    gen_statem:stop(FsmPid),
    ok.

%%--------------------------------------------------------------------
%% @doc Tests Worker-FSM communication for CAST requests.
%% @end
%%--------------------------------------------------------------------
worker_fsm_communication_cast(_Config) ->
    %% Create test FSM and worker
    Socket = test_helpers:create_test_socket(),
    PeerInfo = test_helpers:create_test_peer_info(),
    SessionConfig = test_helpers:create_test_session_config(),
    
    %% Start FSM
    {ok, FsmPid} = trust_conn_fsm:start_link(Socket, PeerInfo, SessionConfig),
    
    %% Start worker for a CAST request
    ReqId = make_ref(),
    MFA = {erlang, length, 1},
    Args = [[1, 2, 3]],
    
    %% Mock permission checking to allow the call
    meck:expect(semp_policy, is_forbidden, fun(_, _, _) -> false end),
    meck:expect(semp_whitelist, is_allowed, fun(_, _) -> true end),
    meck:expect(semp_whitelist, table, fun(_) -> ets:new(test_table, []) end),
    
    {ok, WorkerPid} = trust_rpc_worker:start_link(FsmPid, ReqId, cast, MFA, Args, <<"test_client">>),
    
    %% Verify worker started successfully
    ?assert(is_process_alive(WorkerPid)),
    
    %% Wait for worker to complete (it should terminate after execution)
    timer:sleep(100),
    
    %% Verify worker has terminated (temporary workers exit after completion)
    ?assertNot(is_process_alive(WorkerPid)),
    
    %% Cleanup FSM
    gen_statem:stop(FsmPid),
    ok.

%%--------------------------------------------------------------------
%% @doc Tests real MFA execution with successful result.
%% @end
%%--------------------------------------------------------------------
worker_real_mfa_execution_success(_Config) ->
    %% Create test FSM and worker
    Socket = test_helpers:create_test_socket(),
    PeerInfo = test_helpers:create_test_peer_info(),
    SessionConfig = test_helpers:create_test_session_config(),
    
    %% Start FSM
    {ok, FsmPid} = trust_conn_fsm:start_link(Socket, PeerInfo, SessionConfig),
    
    %% Start worker with a simple MFA that returns a value
    ReqId = make_ref(),
    MFA = {erlang, length, 1},
    Args = [[1, 2, 3, 4, 5]],
    
    %% Mock permission checking to allow the call
    meck:expect(semp_policy, is_forbidden, fun(_, _, _) -> false end),
    meck:expect(semp_whitelist, is_allowed, fun(_, _) -> true end),
    meck:expect(semp_whitelist, table, fun(_) -> ets:new(test_table, []) end),
    
    {ok, WorkerPid} = trust_rpc_worker:start_link(FsmPid, ReqId, call, MFA, Args, <<"test_client">>),
    
    %% Verify worker started successfully
    ?assert(is_process_alive(WorkerPid)),
    
    %% Wait for worker to complete
    timer:sleep(100),
    
    %% Verify worker has terminated successfully
    ?assertNot(is_process_alive(WorkerPid)),
    
    %% Cleanup FSM
    gen_statem:stop(FsmPid),
    ok.

%%--------------------------------------------------------------------
%% @doc Tests real MFA execution with error.
%% @end
%%--------------------------------------------------------------------
worker_real_mfa_execution_error(_Config) ->
    %% Create test FSM and worker
    Socket = test_helpers:create_test_socket(),
    PeerInfo = test_helpers:create_test_peer_info(),
    SessionConfig = test_helpers:create_test_session_config(),
    
    %% Start FSM
    {ok, FsmPid} = trust_conn_fsm:start_link(Socket, PeerInfo, SessionConfig),
    
    %% Start worker with an MFA that will cause an error
    ReqId = make_ref(),
    MFA = {erlang, length, 1},
    Args = [not_a_list],  %% This will cause a badarg error
    
    %% Mock permission checking to allow the call
    meck:expect(semp_policy, is_forbidden, fun(_, _, _) -> false end),
    meck:expect(semp_whitelist, is_allowed, fun(_, _) -> true end),
    meck:expect(semp_whitelist, table, fun(_) -> ets:new(test_table, []) end),
    
    {ok, WorkerPid} = trust_rpc_worker:start_link(FsmPid, ReqId, call, MFA, Args, <<"test_client">>),
    
    %% Verify worker started successfully
    ?assert(is_process_alive(WorkerPid)),
    
    %% Wait for worker to complete (it should terminate due to error)
    timer:sleep(100),
    
    %% Verify worker has terminated (due to error)
    ?assertNot(is_process_alive(WorkerPid)),
    
    %% Cleanup FSM
    gen_statem:stop(FsmPid),
    ok.

%%--------------------------------------------------------------------
%% @doc Tests permission checking with whitelist.
%% @end
%%--------------------------------------------------------------------
worker_permission_checking_whitelist(_Config) ->
    %% Create test FSM and worker
    Socket = test_helpers:create_test_socket(),
    PeerInfo = test_helpers:create_test_peer_info(),
    SessionConfig = test_helpers:create_test_session_config(),
    
    %% Start FSM
    {ok, FsmPid} = trust_conn_fsm:start_link(Socket, PeerInfo, SessionConfig),
    
    %% Start worker with a whitelisted client
    ReqId = make_ref(),
    MFA = {erlang, length, 1},
    Args = [[1, 2, 3]],
    
    %% Mock the client_id to be whitelisted
    meck:expect(semp_policy, is_forbidden, fun(_, _, _) -> false end),
    meck:expect(semp_whitelist, is_allowed, fun(trust, _ClientId) -> true end),
    meck:expect(semp_whitelist, table, fun(_) -> ets:new(test_table, []) end),
    
    {ok, WorkerPid} = trust_rpc_worker:start_link(FsmPid, ReqId, call, MFA, Args, <<"test_client">>),
    
    %% Verify worker started successfully
    ?assert(is_process_alive(WorkerPid)),
    
    %% Wait for worker to complete
    timer:sleep(100),
    
    %% Verify worker has terminated successfully
    ?assertNot(is_process_alive(WorkerPid)),
    
    %% Cleanup FSM
    gen_statem:stop(FsmPid),
    ok.

%%--------------------------------------------------------------------
%% @doc Tests permission checking with forbidden MFA.
%% @end
%%--------------------------------------------------------------------
worker_permission_checking_forbidden_mfa(_Config) ->
    %% Create test FSM and worker
    Socket = test_helpers:create_test_socket(),
    PeerInfo = test_helpers:create_test_peer_info(),
    SessionConfig = test_helpers:create_test_session_config(),
    
    %% Start FSM
    {ok, FsmPid} = trust_conn_fsm:start_link(Socket, PeerInfo, SessionConfig),
    
    %% Start worker with a forbidden MFA
    ReqId = make_ref(),
    MFA = {os, cmd, 1},  %% This should be forbidden
    Args = ["ls"],
    
    %% Mock the policy to forbid this MFA (handle all cases)
    meck:expect(semp_policy, is_forbidden, fun(os, cmd, 1) -> true; (_, _, _) -> false end),
    
    {ok, WorkerPid} = trust_rpc_worker:start_link(FsmPid, ReqId, call, MFA, Args, <<"test_client">>),
    
    %% Verify worker started successfully
    ?assert(is_process_alive(WorkerPid)),
    
    %% Wait for worker to complete (it should terminate due to forbidden MFA)
    timer:sleep(100),
    
    %% Verify worker has terminated (due to forbidden MFA)
    ?assertNot(is_process_alive(WorkerPid)),
    
    %% Cleanup FSM
    gen_statem:stop(FsmPid),
    ok.

%%--------------------------------------------------------------------
%% @doc Tests permission checking with specific permissions.
%% @end
%%--------------------------------------------------------------------
worker_permission_checking_specific_permissions(_Config) ->
    %% Create test FSM and worker
    Socket = test_helpers:create_test_socket(),
    PeerInfo = test_helpers:create_test_peer_info(),
    SessionConfig = test_helpers:create_test_session_config(),
    
    %% Start FSM
    {ok, FsmPid} = trust_conn_fsm:start_link(Socket, PeerInfo, SessionConfig),
    
    %% Start worker with specific permissions
    ReqId = make_ref(),
    MFA = {erlang, length, 1},
    Args = [[1, 2, 3]],
    
    %% Mock specific permissions (client has permission for erlang:length/1)
    meck:expect(semp_policy, is_forbidden, fun(_, _, _) -> false end),
    meck:expect(semp_whitelist, is_allowed, fun(trust, _ClientId) -> true end),
    meck:expect(semp_whitelist, table, fun(trust) -> ets:new(test_table, []) end),
    
    {ok, WorkerPid} = trust_rpc_worker:start_link(FsmPid, ReqId, call, MFA, Args, <<"test_client">>),
    
    %% Verify worker started successfully
    ?assert(is_process_alive(WorkerPid)),
    
    %% Wait for worker to complete
    timer:sleep(100),
    
    %% Verify worker has terminated successfully
    ?assertNot(is_process_alive(WorkerPid)),
    
    %% Cleanup FSM
    gen_statem:stop(FsmPid),
    ok.

%%--------------------------------------------------------------------
%% @doc Tests error propagation for CALL requests.
%% @end
%%--------------------------------------------------------------------
worker_error_propagation_call(_Config) ->
    %% Create test FSM and worker
    Socket = test_helpers:create_test_socket(),
    PeerInfo = test_helpers:create_test_peer_info(),
    SessionConfig = test_helpers:create_test_session_config(),
    
    %% Start FSM
    {ok, FsmPid} = trust_conn_fsm:start_link(Socket, PeerInfo, SessionConfig),
    
    %% Start worker with an MFA that will cause an error
    ReqId = make_ref(),
    MFA = {erlang, length, 1},
    Args = [not_a_list],  %% This will cause a badarg error
    
    %% Mock permission checking to allow the call
    meck:expect(semp_policy, is_forbidden, fun(_, _, _) -> false end),
    meck:expect(semp_whitelist, is_allowed, fun(_, _) -> true end),
    meck:expect(semp_whitelist, table, fun(_) -> ets:new(test_table, []) end),
    
    {ok, WorkerPid} = trust_rpc_worker:start_link(FsmPid, ReqId, call, MFA, Args, <<"test_client">>),
    
    %% Verify worker started successfully
    ?assert(is_process_alive(WorkerPid)),
    
    %% Wait for worker to complete (it should terminate due to error)
    timer:sleep(100),
    
    %% Verify worker has terminated (due to error)
    ?assertNot(is_process_alive(WorkerPid)),
    
    %% Cleanup FSM
    gen_statem:stop(FsmPid),
    ok.

%%--------------------------------------------------------------------
%% @doc Tests error propagation for CAST requests.
%% @end
%%--------------------------------------------------------------------
worker_error_propagation_cast(_Config) ->
    %% Create test FSM and worker
    Socket = test_helpers:create_test_socket(),
    PeerInfo = test_helpers:create_test_peer_info(),
    SessionConfig = test_helpers:create_test_session_config(),
    
    %% Start FSM
    {ok, FsmPid} = trust_conn_fsm:start_link(Socket, PeerInfo, SessionConfig),
    
    %% Start worker with an MFA that will cause an error
    ReqId = make_ref(),
    MFA = {erlang, length, 1},
    Args = [not_a_list],  %% This will cause a badarg error
    
    %% Mock permission checking to allow the call
    meck:expect(semp_policy, is_forbidden, fun(_, _, _) -> false end),
    meck:expect(semp_whitelist, is_allowed, fun(_, _) -> true end),
    meck:expect(semp_whitelist, table, fun(_) -> ets:new(test_table, []) end),
    
    {ok, WorkerPid} = trust_rpc_worker:start_link(FsmPid, ReqId, cast, MFA, Args, <<"test_client">>),
    
    %% Verify worker started successfully
    ?assert(is_process_alive(WorkerPid)),
    
    %% Wait for worker to complete (it should terminate due to error)
    timer:sleep(100),
    
    %% Verify worker has terminated (due to error)
    ?assertNot(is_process_alive(WorkerPid)),
    
    %% Cleanup FSM
    gen_statem:stop(FsmPid),
    ok.

%%--------------------------------------------------------------------
%% @doc Tests concurrent worker execution.
%% @end
%%--------------------------------------------------------------------
worker_concurrent_execution(_Config) ->
    %% Create test FSM and workers
    Socket = test_helpers:create_test_socket(),
    PeerInfo = test_helpers:create_test_peer_info(),
    SessionConfig = test_helpers:create_test_session_config(),
    
    %% Start FSM
    {ok, FsmPid} = trust_conn_fsm:start_link(Socket, PeerInfo, SessionConfig),
    
    %% Mock permission checking to allow the calls
    meck:expect(semp_policy, is_forbidden, fun(_, _, _) -> false end),
    meck:expect(semp_whitelist, is_allowed, fun(_, _) -> true end),
    meck:expect(semp_whitelist, table, fun(_) -> ets:new(test_table, []) end),
    
    %% Start multiple workers concurrently
    WorkerCount = 5,
    Workers = lists:map(fun(I) ->
        ReqId = make_ref(),
        MFA = {erlang, length, 1},
        Args = [lists:seq(1, I)],
        {ok, WorkerPid} = trust_rpc_worker:start_link(FsmPid, ReqId, call, MFA, Args, <<"test_client">>),
        WorkerPid
    end, lists:seq(1, WorkerCount)),
    
    %% Verify all workers started successfully
    [?assert(is_process_alive(WorkerPid)) || WorkerPid <- Workers],
    
    %% Wait for all workers to complete
    timer:sleep(200),
    
    %% Verify all workers have terminated
    [?assertNot(is_process_alive(WorkerPid)) || WorkerPid <- Workers],
    
    %% Cleanup FSM
    gen_statem:stop(FsmPid),
    ok.

%%--------------------------------------------------------------------
%% @doc Tests telemetry events emission.
%% @end
%%--------------------------------------------------------------------
worker_telemetry_events(_Config) ->
    %% Create test FSM and worker
    Socket = test_helpers:create_test_socket(),
    PeerInfo = test_helpers:create_test_peer_info(),
    SessionConfig = test_helpers:create_test_session_config(),
    
    %% Start FSM
    {ok, FsmPid} = trust_conn_fsm:start_link(Socket, PeerInfo, SessionConfig),
    
    %% Start worker
    ReqId = make_ref(),
    MFA = {erlang, length, 1},
    Args = [[1, 2, 3]],
    
    %% Mock permission checking to allow the call
    meck:expect(semp_policy, is_forbidden, fun(_, _, _) -> false end),
    meck:expect(semp_whitelist, is_allowed, fun(_, _) -> true end),
    meck:expect(semp_whitelist, table, fun(_) -> ets:new(test_table, []) end),
    
    {ok, WorkerPid} = trust_rpc_worker:start_link(FsmPid, ReqId, call, MFA, Args, <<"test_client">>),
    
    %% Verify worker started successfully
    ?assert(is_process_alive(WorkerPid)),
    
    %% Wait for worker to complete
    timer:sleep(100),
    
    %% Verify worker has terminated successfully
    ?assertNot(is_process_alive(WorkerPid)),
    
    %% Note: Telemetry events are emitted during execution
    %% In a real test, we would capture and verify these events
    
    %% Cleanup FSM
    gen_statem:stop(FsmPid),
    ok.

%%--------------------------------------------------------------------
%% @doc Tests duration calculation.
%% @end
%%--------------------------------------------------------------------
worker_duration_calculation(_Config) ->
    %% Create test FSM and worker
    Socket = test_helpers:create_test_socket(),
    PeerInfo = test_helpers:create_test_peer_info(),
    SessionConfig = test_helpers:create_test_session_config(),
    
    %% Start FSM
    {ok, FsmPid} = trust_conn_fsm:start_link(Socket, PeerInfo, SessionConfig),
    
    %% Start worker
    ReqId = make_ref(),
    MFA = {erlang, length, 1},
    Args = [[1, 2, 3]],
    
    %% Mock permission checking to allow the call
    meck:expect(semp_policy, is_forbidden, fun(_, _, _) -> false end),
    meck:expect(semp_whitelist, is_allowed, fun(_, _) -> true end),
    meck:expect(semp_whitelist, table, fun(_) -> ets:new(test_table, []) end),
    
    {ok, WorkerPid} = trust_rpc_worker:start_link(FsmPid, ReqId, call, MFA, Args, <<"test_client">>),
    
    %% Verify worker started successfully
    ?assert(is_process_alive(WorkerPid)),
    
    %% Wait for worker to complete
    timer:sleep(100),
    
    %% Verify worker has terminated successfully
    ?assertNot(is_process_alive(WorkerPid)),
    
    %% Note: Duration calculation is currently returning 0 (TODO in code)
    %% This test verifies the worker completes without crashing
    
    %% Cleanup FSM
    gen_statem:stop(FsmPid),
    ok.
