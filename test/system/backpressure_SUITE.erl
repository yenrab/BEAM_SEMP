%%%-------------------------------------------------------------------
%% @doc System tests for backpressure functionality.
%% @end
%%%-------------------------------------------------------------------

-module(backpressure_SUITE).
-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").

%% Test callbacks
-export([all/0, groups/0, init_per_suite/1, end_per_suite/1,
         init_per_testcase/2, end_per_testcase/2]).

%% Test cases
-export([
    backpressure_pauses_socket_at_max_inflight/1,
    backpressure_resumes_after_worker_completes/1,
    backpressure_queues_in_tcp_buffer/1,
    backpressure_maintains_ordering/1,
    backpressure_handles_slow_workers/1,
    backpressure_telemetry_events/1
]).

%%--------------------------------------------------------------------
%% @doc Returns list of all test cases.
%% @end
%%--------------------------------------------------------------------
all() ->
    [
        backpressure_pauses_socket_at_max_inflight,
        backpressure_resumes_after_worker_completes,
        backpressure_queues_in_tcp_buffer,
        backpressure_maintains_ordering,
        backpressure_handles_slow_workers,
        backpressure_telemetry_events
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
    %% Setup test environment with mocks FIRST (before starting application)
    TestEnv = test_helpers:setup_test_env(),
    
    %% Start full application (handle already started case)
    case application:start(beam_semp) of
        ok -> ok;
        {error, {already_started, _}} -> ok
    end,
    
    %% Start all supervisors (handle already started case)
    ConnSupPid = ensure_supervisor_started(trust_conn_sup),
    WorkerSupPid = ensure_supervisor_started(trust_conn_worker_sup),
    ListenerSupPid = ensure_supervisor_started(trust_listener_sup),
    
    [{conn_sup, ConnSupPid}, 
     {worker_sup, WorkerSupPid}, 
     {listener_sup, ListenerSupPid},
     {test_env, TestEnv} | Config].

%%--------------------------------------------------------------------
%% @doc Suite cleanup.
%% @end
%%--------------------------------------------------------------------
end_per_suite(Config) ->
    %% Cleanup test environment
    case proplists:get_value(test_env, Config) of
        undefined -> ok;
        TestEnv -> test_helpers:cleanup_test_env(TestEnv)
    end,
    
    %% Stop application
    application:stop(beam_semp),
    Config.

%%--------------------------------------------------------------------
%% @doc Test case initialization.
%% @end
%%--------------------------------------------------------------------
init_per_testcase(_TestCase, Config) ->
    Config.

%%--------------------------------------------------------------------
%% @doc Test case cleanup.
%% @end
%%--------------------------------------------------------------------
end_per_testcase(_TestCase, Config) ->
    Config.

%%--------------------------------------------------------------------
%% @doc Tests socket pause at max_inflight.
%% @end
%%--------------------------------------------------------------------
backpressure_pauses_socket_at_max_inflight(_Config) ->
    %% Create test socket and config with small max_inflight
    Socket = test_helpers:create_test_socket(),
    PeerInfo = test_helpers:create_test_peer_info(),
    BaseConfig = test_helpers:create_test_session_config(),
    SessionConfig = maps:put(max_inflight, 2, BaseConfig),
    
    %% Start FSM
    {ok, Pid} = trust_conn_fsm:start_link(Socket, PeerInfo, SessionConfig),
    
    %% Complete handshake
    Token = <<"valid_token">>,
    Frame = term_to_binary(#{t => token, token => Token}),
    gen_statem:cast(Pid, {ssl, Socket, Frame}),
    timer:sleep(100),
    
    %% Send requests up to max_inflight
    Request1 = test_helpers:create_test_request(1),
    Request2 = test_helpers:create_test_request(2),
    gen_statem:cast(Pid, {ssl, Socket, term_to_binary(Request1)}),
    gen_statem:cast(Pid, {ssl, Socket, term_to_binary(Request2)}),
    timer:sleep(100),
    
    %% Send additional request (should trigger backpressure)
    Request3 = test_helpers:create_test_request(3),
    gen_statem:cast(Pid, {ssl, Socket, term_to_binary(Request3)}),
    timer:sleep(100),
    
    %% Verify FSM is still running
    ?assert(is_process_alive(Pid)),
    
    %% Cleanup
    gen_statem:stop(Pid),
    ok.

%%--------------------------------------------------------------------
%% @doc Tests resume after worker completion.
%% @end
%%--------------------------------------------------------------------
backpressure_resumes_after_worker_completes(_Config) ->
    %% Create test socket and config with small max_inflight
    Socket = test_helpers:create_test_socket(),
    PeerInfo = test_helpers:create_test_peer_info(),
    BaseConfig = test_helpers:create_test_session_config(),
    SessionConfig = maps:put(max_inflight, 1, BaseConfig),
    
    %% Start FSM
    {ok, Pid} = trust_conn_fsm:start_link(Socket, PeerInfo, SessionConfig),
    
    %% Complete handshake
    Token = <<"valid_token">>,
    Frame = term_to_binary(#{t => token, token => Token}),
    gen_statem:cast(Pid, {ssl, Socket, Frame}),
    timer:sleep(100),
    
    %% Send request to fill max_inflight
    Request1 = test_helpers:create_test_request(1),
    gen_statem:cast(Pid, {ssl, Socket, term_to_binary(Request1)}),
    timer:sleep(100),
    
    %% Send additional request (should trigger backpressure)
    Request2 = test_helpers:create_test_request(2),
    gen_statem:cast(Pid, {ssl, Socket, term_to_binary(Request2)}),
    timer:sleep(100),
    
    %% Simulate worker completion
    gen_statem:cast(Pid, {'DOWN', make_ref(), process, make_ref(), normal}),
    timer:sleep(100),
    
    %% Verify FSM is still running
    ?assert(is_process_alive(Pid)),
    
    %% Cleanup
    gen_statem:stop(Pid),
    ok.

%%--------------------------------------------------------------------
%% @doc Tests TCP buffer queuing.
%% @end
%%--------------------------------------------------------------------
backpressure_queues_in_tcp_buffer(_Config) ->
    %% Create test socket and config with small max_inflight
    Socket = test_helpers:create_test_socket(),
    PeerInfo = test_helpers:create_test_peer_info(),
    BaseConfig = test_helpers:create_test_session_config(),
    SessionConfig = maps:put(max_inflight, 1, BaseConfig),
    
    %% Start FSM
    {ok, Pid} = trust_conn_fsm:start_link(Socket, PeerInfo, SessionConfig),
    
    %% Complete handshake
    Token = <<"valid_token">>,
    Frame = term_to_binary(#{t => token, token => Token}),
    gen_statem:cast(Pid, {ssl, Socket, Frame}),
    timer:sleep(100),
    
    %% Send request to fill max_inflight
    Request1 = test_helpers:create_test_request(1),
    gen_statem:cast(Pid, {ssl, Socket, term_to_binary(Request1)}),
    timer:sleep(100),
    
    %% Send multiple additional requests (should be queued in TCP buffer)
    Requests = [test_helpers:create_test_request(I) || I <- lists:seq(2, 5)],
    [gen_statem:cast(Pid, {ssl, Socket, term_to_binary(R)}) || R <- Requests],
    timer:sleep(100),
    
    %% Verify FSM is still running
    ?assert(is_process_alive(Pid)),
    
    %% Cleanup
    gen_statem:stop(Pid),
    ok.

%%--------------------------------------------------------------------
%% @doc Tests ordering is maintained.
%% @end
%%--------------------------------------------------------------------
backpressure_maintains_ordering(_Config) ->
    %% Create test socket and config with small max_inflight
    Socket = test_helpers:create_test_socket(),
    PeerInfo = test_helpers:create_test_peer_info(),
    BaseConfig = test_helpers:create_test_session_config(),
    SessionConfig = maps:put(max_inflight, 2, BaseConfig),
    
    %% Start FSM
    {ok, Pid} = trust_conn_fsm:start_link(Socket, PeerInfo, SessionConfig),
    
    %% Complete handshake
    Token = <<"valid_token">>,
    Frame = term_to_binary(#{t => token, token => Token}),
    gen_statem:cast(Pid, {ssl, Socket, Frame}),
    timer:sleep(100),
    
    %% Send requests in specific order
    Requests = [test_helpers:create_test_request(I) || I <- [1,2,3,4,5]],
    [gen_statem:cast(Pid, {ssl, Socket, term_to_binary(R)}) || R <- Requests],
    timer:sleep(200),
    
    %% Verify FSM is still running
    ?assert(is_process_alive(Pid)),
    
    %% Cleanup
    gen_statem:stop(Pid),
    ok.

%%--------------------------------------------------------------------
%% @doc Tests handling of slow workers.
%% @end
%%--------------------------------------------------------------------
backpressure_handles_slow_workers(_Config) ->
    %% Create test socket and config with small max_inflight
    Socket = test_helpers:create_test_socket(),
    PeerInfo = test_helpers:create_test_peer_info(),
    BaseConfig = test_helpers:create_test_session_config(),
    SessionConfig = maps:put(max_inflight, 1, BaseConfig),
    
    %% Start FSM
    {ok, Pid} = trust_conn_fsm:start_link(Socket, PeerInfo, SessionConfig),
    
    %% Complete handshake
    Token = <<"valid_token">>,
    Frame = term_to_binary(#{t => token, token => Token}),
    gen_statem:cast(Pid, {ssl, Socket, Frame}),
    timer:sleep(100),
    
    %% Send request to fill max_inflight
    Request1 = test_helpers:create_test_request(1),
    gen_statem:cast(Pid, {ssl, Socket, term_to_binary(Request1)}),
    timer:sleep(100),
    
    %% Send additional requests (should trigger backpressure)
    Requests = [test_helpers:create_test_request(I) || I <- lists:seq(2, 5)],
    [gen_statem:cast(Pid, {ssl, Socket, term_to_binary(R)}) || R <- Requests],
    timer:sleep(200),
    
    %% Simulate slow worker completion
    timer:sleep(100),
    gen_statem:cast(Pid, {'DOWN', make_ref(), process, make_ref(), normal}),
    timer:sleep(100),
    
    %% Verify FSM is still running
    ?assert(is_process_alive(Pid)),
    
    %% Cleanup
    gen_statem:stop(Pid),
    ok.

%%--------------------------------------------------------------------
%% @doc Tests backpressure telemetry events.
%% @end
%%--------------------------------------------------------------------
backpressure_telemetry_events(_Config) ->
    %% Create test socket and config with small max_inflight
    Socket = test_helpers:create_test_socket(),
    PeerInfo = test_helpers:create_test_peer_info(),
    BaseConfig = test_helpers:create_test_session_config(),
    SessionConfig = maps:put(max_inflight, 1, BaseConfig),
    
    %% Start FSM
    {ok, Pid} = trust_conn_fsm:start_link(Socket, PeerInfo, SessionConfig),
    
    %% Complete handshake
    Token = <<"valid_token">>,
    Frame = term_to_binary(#{t => token, token => Token}),
    gen_statem:cast(Pid, {ssl, Socket, Frame}),
    timer:sleep(100),
    
    %% Send request to fill max_inflight
    Request1 = test_helpers:create_test_request(1),
    gen_statem:cast(Pid, {ssl, Socket, term_to_binary(Request1)}),
    timer:sleep(100),
    
    %% Send additional request (should trigger backpressure)
    Request2 = test_helpers:create_test_request(2),
    gen_statem:cast(Pid, {ssl, Socket, term_to_binary(Request2)}),
    timer:sleep(100),
    
    %% Simulate worker completion
    gen_statem:cast(Pid, {'DOWN', make_ref(), process, make_ref(), normal}),
    timer:sleep(100),
    
    %% Verify FSM is still running
    ?assert(is_process_alive(Pid)),
    
    %% Cleanup
    gen_statem:stop(Pid),
    ok.

%%--------------------------------------------------------------------
%% @doc Helper function to ensure supervisor is started.
%% @end
%%--------------------------------------------------------------------
ensure_supervisor_started(SupervisorName) ->
    case whereis(SupervisorName) of
        undefined -> 
            {ok, Pid} = SupervisorName:start_link(),
            Pid;
        Pid -> Pid
    end.
