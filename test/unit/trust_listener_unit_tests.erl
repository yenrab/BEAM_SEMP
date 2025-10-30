%%%-------------------------------------------------------------------
%% @doc Unit tests for trust_listener using EUnit with mocking.
%% @end
%%%-------------------------------------------------------------------

-module(trust_listener_unit_tests).
-include_lib("eunit/include/eunit.hrl").

%%--------------------------------------------------------------------
%% @doc Test suite setup and teardown.
%% @end
%%--------------------------------------------------------------------
listener_unit_test_() ->
    {foreach,
     fun setup_listener_test/0,
     fun cleanup_listener_test/1,
     [
        fun listener_accepts_connection_test/1,
        fun listener_spawns_fsm_with_session_config_test/1,
        fun listener_transfers_socket_ownership_test/1,
        fun listener_tracks_connections_test/1
     ]}.

%%--------------------------------------------------------------------
%% @doc Sets up listener test environment.
%% @end
%%--------------------------------------------------------------------
setup_listener_test() ->
    %% Clean up any existing mocks first
    meck:unload(),
    
    %% Mock SSL functions
    meck:new(semp_facades, [unstick, passthrough]),
    meck:expect(semp_facades, transport_accept, fun(_Socket, _Timeout) ->
        {ok, {test_socket, make_ref()}}
    end),
    meck:expect(semp_facades, peername, fun(_Socket) ->
        {ok, {{127,0,0,1}, 12345}}
    end),
    meck:expect(semp_facades, controlling_process, fun(_Socket, _Pid) ->
        ok
    end),
    
    %% Mock supervisor functions
    meck:new(supervisor, [unstick, passthrough]),
    meck:expect(supervisor, start_child, fun(_Sup, _Spec) ->
        {ok, spawn(fun() -> receive _ -> ok end end)}
    end),
    
    %% Mock FSM start_link
    meck:new(trust_conn_fsm, [unstick, passthrough]),
    meck:expect(trust_conn_fsm, start_link, fun(_Socket, _PeerInfo, _Config) ->
        {ok, spawn(fun() -> receive _ -> ok end end)}
    end),
    
    %% Create test listener socket
    ListenerSocket = {test_listener_socket, make_ref()},
    
    {ListenerSocket}.

%%--------------------------------------------------------------------
%% @doc Cleans up listener test environment.
%% @end
%%--------------------------------------------------------------------
cleanup_listener_test({_ListenerSocket}) ->
    meck:unload(),
    ok.

%%--------------------------------------------------------------------
%% @doc Tests listener accepts connection.
%% @end
%%--------------------------------------------------------------------
listener_accepts_connection_test({ListenerSocket}) ->
    %% Start listener
    {ok, Pid} = trust_listener:start_link(ListenerSocket),
    
    %% Verify listener is running
    ?assert(is_pid(Pid)),
    ?assert(is_process_alive(Pid)),
    
    %% Trigger accept by sending accept message
    gen_server:cast(Pid, accept),
    timer:sleep(100),
    
    %% Verify SSL transport_accept was called
    ?assert(meck:called(ssl, transport_accept, [ListenerSocket, infinity])),
    
    %% Cleanup
    gen_server:stop(Pid),
    ok.

%%--------------------------------------------------------------------
%% @doc Tests listener spawns FSM with session config.
%% @end
%%--------------------------------------------------------------------
listener_spawns_fsm_with_session_config_test({ListenerSocket}) ->
    %% Start listener
    {ok, Pid} = trust_listener:start_link(ListenerSocket),
    
    %% Trigger accept
    gen_server:cast(Pid, accept),
    timer:sleep(100),
    
    %% Verify FSM was started with correct parameters
    Calls = meck:history(trust_conn_fsm, start_link),
    ?assert(length(Calls) > 0),
    
    %% Verify session config was passed
    [Call] = Calls,
    {_MFA, [Socket, PeerInfo, SessionConfig]} = Call,
    ?assert(is_map(SessionConfig)),
    
    %% Cleanup
    gen_server:stop(Pid),
    ok.

%%--------------------------------------------------------------------
%% @doc Tests listener transfers socket ownership.
%% @end
%%--------------------------------------------------------------------
listener_transfers_socket_ownership_test({ListenerSocket}) ->
    %% Start listener
    {ok, Pid} = trust_listener:start_link(ListenerSocket),
    
    %% Trigger accept
    gen_server:cast(Pid, accept),
    timer:sleep(100),
    
    %% Verify socket ownership was transferred
    ?assert(meck:called(ssl, controlling_process, ['_', '_'])),
    
    %% Cleanup
    gen_server:stop(Pid),
    ok.

%%--------------------------------------------------------------------
%% @doc Tests listener tracks connections.
%% @end
%%--------------------------------------------------------------------
listener_tracks_connections_test({ListenerSocket}) ->
    %% Start listener
    {ok, Pid} = trust_listener:start_link(ListenerSocket),
    
    %% Trigger multiple accepts
    gen_server:cast(Pid, accept),
    gen_server:cast(Pid, accept),
    timer:sleep(100),
    
    %% Verify multiple FSM children were started
    Calls = meck:history(trust_conn_fsm, start_link),
    ?assert(length(Calls) >= 2),
    
    %% Cleanup
    gen_server:stop(Pid),
    ok.
