%%%-------------------------------------------------------------------
%% @doc Mock state manager to handle mocking conflicts.
%% @end
%%%-------------------------------------------------------------------

-module(mock_state_manager).
-export([
    start/0,
    stop/0,
    setup_mocks/1,
    cleanup_mocks/1,
    get_mock_state/0,
    set_mock_state/1
]).

%% Mock state record
-record(mock_state, {
    ssl_mocked = false,
    telemetry_mocked = false,
    security_mocked = false,
    supervisor_mocked = false,
    fsm_mocked = false
}).

%%--------------------------------------------------------------------
%% @doc Starts mock state manager.
%% @end
%%--------------------------------------------------------------------
start() ->
    case whereis(mock_state_manager) of
        undefined ->
            Pid = spawn(fun mock_state_loop/0),
            register(mock_state_manager, Pid),
            {ok, Pid};
        Pid ->
            {ok, Pid}
    end.

%%--------------------------------------------------------------------
%% @doc Stops mock state manager.
%% @end
%%--------------------------------------------------------------------
stop() ->
    case whereis(mock_state_manager) of
        undefined -> ok;
        Pid -> 
            Pid ! stop,
            ok
    end.

%%--------------------------------------------------------------------
%% @doc Sets up mocks based on test type.
%% @end
%%--------------------------------------------------------------------
setup_mocks(fsm) ->
    start(),
    mock_state_manager ! {setup, fsm},
    ok;
setup_mocks(worker) ->
    start(),
    mock_state_manager ! {setup, worker},
    ok;
setup_mocks(listener) ->
    start(),
    mock_state_manager ! {setup, listener},
    ok;
setup_mocks(sup) ->
    start(),
    mock_state_manager ! {setup, sup},
    ok.

%%--------------------------------------------------------------------
%% @doc Cleans up mocks.
%% @end
%%--------------------------------------------------------------------
cleanup_mocks(_TestType) ->
    mock_state_manager ! cleanup,
    ok.

%%--------------------------------------------------------------------
%% @doc Gets current mock state.
%% @end
%%--------------------------------------------------------------------
get_mock_state() ->
    mock_state_manager ! {get_state, self()},
    receive
        {mock_state, State} -> State
    after 1000 -> 
        #mock_state{}
    end.

%%--------------------------------------------------------------------
%% @doc Sets mock state.
%% @end
%%--------------------------------------------------------------------
set_mock_state(State) ->
    mock_state_manager ! {set_state, State},
    ok.

%%--------------------------------------------------------------------
%% @doc Mock state loop.
%% @end
%%--------------------------------------------------------------------
mock_state_loop() ->
    mock_state_loop(#mock_state{}).

mock_state_loop(State) ->
    receive
        {setup, fsm} ->
            NewState = setup_fsm_mocks(State),
            mock_state_loop(NewState);
        {setup, worker} ->
            NewState = setup_worker_mocks(State),
            mock_state_loop(NewState);
        {setup, listener} ->
            NewState = setup_listener_mocks(State),
            mock_state_loop(NewState);
        {setup, sup} ->
            NewState = setup_sup_mocks(State),
            mock_state_loop(NewState);
        cleanup ->
            cleanup_all_mocks(State),
            mock_state_loop(#mock_state{});
        {get_state, Pid} ->
            Pid ! {mock_state, State},
            mock_state_loop(State);
        {set_state, NewState} ->
            mock_state_loop(NewState);
        stop ->
            cleanup_all_mocks(State),
            ok
    end.

%%--------------------------------------------------------------------
%% @doc Sets up FSM mocks.
%% @end
%%--------------------------------------------------------------------
setup_fsm_mocks(State) ->
    NewState = State#mock_state{
        ssl_mocked = true,
        telemetry_mocked = true,
        security_mocked = true,
        supervisor_mocked = true
    },
    setup_ssl_mocks(),
    setup_telemetry_mocks(),
    setup_security_mocks(),
    setup_supervisor_mocks(),
    NewState.

%%--------------------------------------------------------------------
%% @doc Sets up worker mocks.
%% @end
%%--------------------------------------------------------------------
setup_worker_mocks(State) ->
    NewState = State#mock_state{
        telemetry_mocked = true,
        security_mocked = true,
        fsm_mocked = true
    },
    setup_telemetry_mocks(),
    setup_security_mocks(),
    setup_fsm_communication_mocks(),
    NewState.

%%--------------------------------------------------------------------
%% @doc Sets up listener mocks.
%% @end
%%--------------------------------------------------------------------
setup_listener_mocks(State) ->
    NewState = State#mock_state{
        ssl_mocked = true,
        supervisor_mocked = true,
        fsm_mocked = true
    },
    setup_ssl_mocks(),
    setup_supervisor_mocks(),
    setup_fsm_mocks(),
    NewState.

%%--------------------------------------------------------------------
%% @doc Sets up supervisor mocks.
%% @end
%%--------------------------------------------------------------------
setup_sup_mocks(State) ->
    NewState = State#mock_state{
        supervisor_mocked = true
    },
    setup_supervisor_mocks(),
    NewState.

%%--------------------------------------------------------------------
%% @doc Cleans up all mocks.
%% @end
%%--------------------------------------------------------------------
cleanup_all_mocks(State) ->
    if
        State#mock_state.ssl_mocked -> meck:unload(ssl);
        true -> ok
    end,
    if
        State#mock_state.telemetry_mocked -> meck:unload(telemetry);
        true -> ok
    end,
    if
        State#mock_state.security_mocked -> 
            meck:unload(trust_token),
            meck:unload(trust_suspicion),
            meck:unload(semp_whitelist),
            meck:unload(semp_policy);
        true -> ok
    end,
    if
        State#mock_state.supervisor_mocked -> meck:unload(supervisor);
        true -> ok
    end,
    if
        State#mock_state.fsm_mocked -> 
            meck:unload(trust_conn_fsm),
            meck:unload(gen_statem);
        true -> ok
    end,
    ok.

%% Mock setup functions (same as in mock_manager.erl)
setup_ssl_mocks() -> ok.
setup_telemetry_mocks() -> ok.
setup_security_mocks() -> ok.
setup_supervisor_mocks() -> ok.
setup_fsm_mocks() -> ok.
setup_fsm_communication_mocks() -> ok.
