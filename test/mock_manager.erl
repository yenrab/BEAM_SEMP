%%%-------------------------------------------------------------------
%% @doc Centralized mock management to avoid conflicts.
%% @end
%%%-------------------------------------------------------------------

-module(mock_manager).
-export([
    setup_all_mocks/0,
    cleanup_all_mocks/0,
    setup_fsm_mocks/0,
    setup_worker_mocks/0,
    setup_listener_mocks/0,
    setup_sup_mocks/0
]).

%%--------------------------------------------------------------------
%% @doc Sets up all mocks for comprehensive testing.
%% @end
%%--------------------------------------------------------------------
setup_all_mocks() ->
    cleanup_all_mocks(),
    setup_semp_facades_mocks(),
    setup_telemetry_mocks(),
    setup_security_mocks(),
    setup_supervisor_mocks(),
    ok.

%%--------------------------------------------------------------------
%% @doc Cleans up all mocks.
%% @end
%%--------------------------------------------------------------------
cleanup_all_mocks() ->
    meck:unload(),
    ok.

%%--------------------------------------------------------------------
%% @doc Sets up mocks for FSM tests.
%% @end
%%--------------------------------------------------------------------
setup_fsm_mocks() ->
    cleanup_all_mocks(),
    setup_semp_facades_mocks(),
    setup_telemetry_mocks(),
    setup_security_mocks(),
    setup_worker_supervisor_mocks(),
    ok.

%%--------------------------------------------------------------------
%% @doc Sets up mocks for worker tests.
%% @end
%%--------------------------------------------------------------------
setup_worker_mocks() ->
    cleanup_all_mocks(),
    setup_telemetry_mocks(),
    setup_security_mocks(),
    setup_fsm_communication_mocks(),
    ok.

%%--------------------------------------------------------------------
%% @doc Sets up mocks for listener tests.
%% @end
%%--------------------------------------------------------------------
setup_listener_mocks() ->
    cleanup_all_mocks(),
    setup_semp_facades_mocks(),
    setup_supervisor_mocks(),
    setup_fsm_mocks(),
    ok.

%%--------------------------------------------------------------------
%% @doc Sets up mocks for supervisor tests.
%% @end
%%--------------------------------------------------------------------
setup_sup_mocks() ->
    cleanup_all_mocks(),
    setup_supervisor_mocks(),
    ok.

%%--------------------------------------------------------------------
%% @doc Sets up SSL mocks.
%% @end
%%--------------------------------------------------------------------
setup_semp_facades_mocks() ->
    meck:new(semp_facades, [unstick, passthrough]),
    meck:expect(semp_facades, setopts, fun(_Socket, _Opts) -> ok end),
    meck:expect(semp_facades, peername, fun(_Socket) -> {ok, {{127,0,0,1}, 12345}} end),
    meck:expect(semp_facades, controlling_process, fun(_Socket, _Pid) -> ok end),
    meck:expect(semp_facades, close, fun(_Socket) -> ok end),
    meck:expect(semp_facades, transport_accept, fun(_Socket, _Timeout) -> 
        {ok, {test_socket, make_ref()}} 
    end),
    ok.

%%--------------------------------------------------------------------
%% @doc Sets up telemetry mocks.
%% @end
%%--------------------------------------------------------------------
setup_telemetry_mocks() ->
    meck:new(telemetry, [unstick, passthrough]),
    meck:expect(telemetry, execute, fun(_Event, _Measurements, _Metadata) -> ok end),
    ok.

%%--------------------------------------------------------------------
%% @doc Sets up security mocks.
%% @end
%%--------------------------------------------------------------------
setup_security_mocks() ->
    meck:new(trust_token, [unstick, passthrough]),
    meck:expect(trust_token, validate, fun(_Token, _State) -> 
        {ok, #{client_id => <<"test_client">>, permissions => any}} 
    end),
    
    meck:new(trust_suspicion, [unstick, passthrough]),
    meck:expect(trust_suspicion, bump, fun(_ClientId, _Direction) -> ok end),
    meck:expect(trust_suspicion, is_suspicious, fun(_ClientId) -> false end),
    
    meck:new(semp_whitelist, [unstick, passthrough]),
    meck:expect(semp_whitelist, is_allowed, fun(_Type, _ClientId) -> true end),
    meck:expect(semp_whitelist, table, fun(_Type) -> test_whitelist end),
    
    meck:new(semp_policy, [unstick, passthrough]),
    meck:expect(semp_policy, is_forbidden, fun(M, F, A) -> 
        case {M, F, A} of
            {os, cmd, _} -> true;
            {file, delete, _} -> true;
            {code, load_binary, _} -> true;
            _ -> false
        end
    end),
    ok.

%%--------------------------------------------------------------------
%% @doc Sets up supervisor mocks.
%% @end
%%--------------------------------------------------------------------
setup_supervisor_mocks() ->
    meck:new(supervisor, [unstick, passthrough]),
    meck:expect(supervisor, start_child, fun(_Sup, _Spec) -> 
        {ok, spawn(fun() -> receive _ -> ok end end)} 
    end),
    meck:expect(supervisor, terminate_child, fun(_Sup, _Pid) -> ok end),
    ok.

%%--------------------------------------------------------------------
%% @doc Sets up worker supervisor mocks.
%% @end
%%--------------------------------------------------------------------
setup_worker_supervisor_mocks() ->
    meck:new(trust_conn_worker_sup, [unstick, passthrough]),
    meck:expect(trust_conn_worker_sup, start_link, fun() -> 
        {ok, spawn(fun() -> receive _ -> ok end end)} 
    end),
    ok.

%%--------------------------------------------------------------------
%% @doc Sets up FSM communication mocks.
%% @end
%%--------------------------------------------------------------------
setup_fsm_communication_mocks() ->
    meck:new(gen_statem, [unstick, passthrough]),
    meck:expect(gen_statem, cast, fun(_Pid, _Msg) -> ok end),
    ok.

