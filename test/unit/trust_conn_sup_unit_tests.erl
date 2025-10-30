%%%-------------------------------------------------------------------
%% @doc Unit tests for supervisor modules using EUnit.
%% @end
%%%-------------------------------------------------------------------

-module(trust_conn_sup_unit_tests).
-include_lib("eunit/include/eunit.hrl").

%%--------------------------------------------------------------------
%% @doc Test suite setup and teardown.
%% @end
%%--------------------------------------------------------------------
sup_unit_test_() ->
    {foreach,
     fun setup_sup_test/0,
     fun cleanup_sup_test/1,
     [
        fun conn_sup_init_test/1,
        fun conn_sup_starts_fsm_child_test/1,
        fun conn_sup_restarts_failed_fsm_test/1,
        fun worker_sup_init_test/1,
        fun worker_sup_starts_temporary_worker_test/1
     ]}.

%%--------------------------------------------------------------------
%% @doc Sets up supervisor test environment.
%% @end
%%--------------------------------------------------------------------
setup_sup_test() ->
    %% No special setup needed for supervisor tests
    ok.

%%--------------------------------------------------------------------
%% @doc Cleans up supervisor test environment.
%% @end
%%--------------------------------------------------------------------
cleanup_sup_test(_) ->
    %% Cleanup any running supervisors
    case whereis(trust_conn_sup) of
        undefined -> ok;
        ConnSupPid -> supervisor:terminate_child(trust_conn_sup, ConnSupPid)
    end,
    case whereis(trust_conn_worker_sup) of
        undefined -> ok;
        WorkerSupPid -> supervisor:terminate_child(trust_conn_worker_sup, WorkerSupPid)
    end,
    ok.

%%--------------------------------------------------------------------
%% @doc Tests connection supervisor initialization.
%% @end
%%--------------------------------------------------------------------
conn_sup_init_test(_) ->
    %% Start connection supervisor
    {ok, Pid} = trust_conn_sup:start_link(),
    
    %% Verify supervisor is running
    ?assert(is_pid(Pid)),
    ?assert(is_process_alive(Pid)),
    
    %% Verify supervisor is registered
    ?assertEqual(Pid, whereis(trust_conn_sup)),
    
    %% Cleanup
    supervisor:terminate_child(trust_conn_sup, Pid),
    ok.

%%--------------------------------------------------------------------
%% @doc Tests connection supervisor starts FSM child.
%% @end
%%--------------------------------------------------------------------
conn_sup_starts_fsm_child_test(_) ->
    %% Start connection supervisor
    {ok, SupPid} = trust_conn_sup:start_link(),
    
    %% Create mock socket and config
    Socket = {test_socket, make_ref()},
    PeerInfo = #{ip => {127,0,0,1}, port => 12345},
    SessionConfig = #{max_inflight => 4},
    
    %% Mock FSM start_link
    meck:new(trust_conn_fsm, [unstick, passthrough]),
    meck:expect(trust_conn_fsm, start_link, fun(_Socket, _PeerInfo, _Config) ->
        {ok, spawn(fun() -> receive _ -> ok end end)}
    end),
    
    %% Start FSM child
    ChildSpec = #{
        id => {trust_conn_fsm, make_ref()},
        start => {trust_conn_fsm, start_link, [Socket, PeerInfo, SessionConfig]},
        restart => temporary,
        shutdown => 5000,
        type => worker,
        modules => [trust_conn_fsm]
    },
    {ok, FsmPid} = supervisor:start_child(trust_conn_sup, ChildSpec),
    
    %% Verify FSM child is running
    ?assert(is_pid(FsmPid)),
    ?assert(is_process_alive(FsmPid)),
    
    %% Cleanup
    supervisor:terminate_child(trust_conn_sup, FsmPid),
    supervisor:terminate_child(trust_conn_sup, SupPid),
    meck:unload(trust_conn_fsm),
    ok.

%%--------------------------------------------------------------------
%% @doc Tests connection supervisor restarts failed FSM.
%% @end
%%--------------------------------------------------------------------
conn_sup_restarts_failed_fsm_test(_) ->
    %% Start connection supervisor
    {ok, SupPid} = trust_conn_sup:start_link(),
    
    %% Create mock socket and config
    Socket = {test_socket, make_ref()},
    PeerInfo = #{ip => {127,0,0,1}, port => 12345},
    SessionConfig = #{max_inflight => 4},
    
    %% Mock FSM start_link to fail first time, succeed second time
    meck:new(trust_conn_fsm, [unstick, passthrough]),
    CallCount = 0,
    meck:expect(trust_conn_fsm, start_link, fun(_Socket, _PeerInfo, _Config) ->
        case CallCount of
            0 -> {error, test_error};
            _ -> {ok, spawn(fun() -> receive _ -> ok end end)}
        end
    end),
    
    %% Try to start FSM child (should fail)
    ChildSpec = #{
        id => {trust_conn_fsm, make_ref()},
        start => {trust_conn_fsm, start_link, [Socket, PeerInfo, SessionConfig]},
        restart => temporary,
        shutdown => 5000,
        type => worker,
        modules => [trust_conn_fsm]
    },
    {error, _Reason} = supervisor:start_child(trust_conn_sup, ChildSpec),
    
    %% Cleanup
    supervisor:terminate_child(trust_conn_sup, SupPid),
    meck:unload(trust_conn_fsm),
    ok.

%%--------------------------------------------------------------------
%% @doc Tests worker supervisor initialization.
%% @end
%%--------------------------------------------------------------------
worker_sup_init_test(_) ->
    %% Start worker supervisor
    {ok, Pid} = trust_conn_worker_sup:start_link(),
    
    %% Verify supervisor is running
    ?assert(is_pid(Pid)),
    ?assert(is_process_alive(Pid)),
    
    %% Verify supervisor is registered
    ?assertEqual(Pid, whereis(trust_conn_worker_sup)),
    
    %% Cleanup
    supervisor:terminate_child(trust_conn_worker_sup, Pid),
    ok.

%%--------------------------------------------------------------------
%% @doc Tests worker supervisor starts temporary worker.
%% @end
%%--------------------------------------------------------------------
worker_sup_starts_temporary_worker_test(_) ->
    %% Start worker supervisor
    {ok, SupPid} = trust_conn_worker_sup:start_link(),
    
    %% Create mock FSM pid and worker parameters
    FsmPid = spawn(fun() -> receive _ -> ok end end),
    ReqId = 1,
    MFA = {lists, reverse, [1,2,3,4,5]},
    Args = [[1,2,3,4,5]],
    
    %% Mock worker start_link
    meck:new(trust_rpc_worker, [unstick, passthrough]),
    meck:expect(trust_rpc_worker, start_link, fun(_FsmPid, _ReqId, _Type, _MFA, _Args, _ClientId) ->
        {ok, spawn(fun() -> receive _ -> ok end end)}
    end),
    
    %% Start worker child
    ClientId = test_helpers:create_test_client_id(),
    ChildSpec = #{
        id => {trust_rpc_worker, ReqId},
        start => {trust_rpc_worker, start_link, [FsmPid, ReqId, call, MFA, Args, ClientId]},
        restart => temporary,
        shutdown => 4000,
        type => worker,
        modules => [trust_rpc_worker]
    },
    {ok, WorkerPid} = supervisor:start_child(trust_conn_worker_sup, ChildSpec),
    
    %% Verify worker child is running
    ?assert(is_pid(WorkerPid)),
    ?assert(is_process_alive(WorkerPid)),
    
    %% Cleanup
    supervisor:terminate_child(trust_conn_worker_sup, WorkerPid),
    supervisor:terminate_child(trust_conn_worker_sup, SupPid),
    meck:unload(trust_rpc_worker),
    ok.
