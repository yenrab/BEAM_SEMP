%%%-------------------------------------------------------------------
%% @doc Performance tests for multiplexing and backpressure.
%% @end
%%%-------------------------------------------------------------------

-module(performance_SUITE).
-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").

%% Test callbacks
-export([all/0, groups/0, init_per_suite/1, end_per_suite/1,
         init_per_testcase/2, end_per_testcase/2]).

%% Test cases
-export([
    perf_throughput_single_connection/1,
    perf_throughput_concurrent_connections/1,
    perf_latency_percentiles/1,
    perf_memory_usage_under_load/1,
    perf_max_inflight_saturation/1,
    perf_session_lifecycle_overhead/1,
    perf_goaway_drain_performance/1
]).

%%--------------------------------------------------------------------
%% @doc Returns list of all test cases.
%% @end
%%--------------------------------------------------------------------
all() ->
    [
        perf_throughput_single_connection,
        perf_throughput_concurrent_connections,
        perf_latency_percentiles,
        perf_memory_usage_under_load,
        perf_max_inflight_saturation,
        perf_session_lifecycle_overhead,
        perf_goaway_drain_performance
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
%% @doc Tests throughput with single connection.
%% @end
%%--------------------------------------------------------------------
perf_throughput_single_connection(_Config) ->
    %% Create test socket and config
    Socket = test_helpers:create_test_socket(),
    PeerInfo = test_helpers:create_test_peer_info(),
    SessionConfig = test_helpers:create_test_session_config(),
    
    %% Start FSM
    {ok, Pid} = trust_conn_fsm:start_link(Socket, PeerInfo, SessionConfig),
    
    %% Complete handshake
    Token = <<"valid_token">>,
    Frame = term_to_binary(#{t => token, token => Token}),
    gen_statem:cast(Pid, {ssl, Socket, Frame}),
    timer:sleep(100),
    
    %% Measure throughput
    StartTime = erlang:system_time(microsecond),
    RequestCount = 100,
    
    %% Send requests
    Requests = [test_helpers:create_test_request(I) || I <- lists:seq(1, RequestCount)],
    [gen_statem:cast(Pid, {ssl, Socket, term_to_binary(R)}) || R <- Requests],
    
    %% Wait for completion
    timer:sleep(1000),
    
    EndTime = erlang:system_time(microsecond),
    Duration = EndTime - StartTime,
    Throughput = (RequestCount * 1000000) div Duration,
    
    %% Log results
    ct:log("Throughput: ~p requests/sec", [Throughput]),
    ct:log("Duration: ~p microseconds", [Duration]),
    
    %% Verify FSM is still running
    ?assert(is_process_alive(Pid)),
    
    %% Cleanup
    gen_statem:stop(Pid),
    ok.

%%--------------------------------------------------------------------
%% @doc Tests throughput with concurrent connections.
%% @end
%%--------------------------------------------------------------------
perf_throughput_concurrent_connections(_Config) ->
    %% Create multiple test sockets and configs
    ConnectionCount = 10,
    Sockets = [test_helpers:create_test_socket() || _ <- lists:seq(1, ConnectionCount)],
    PeerInfos = [test_helpers:create_test_peer_info() || _ <- lists:seq(1, ConnectionCount)],
    SessionConfig = test_helpers:create_test_session_config(),
    
    %% Start multiple FSMs
    FSMs = lists:map(fun({Socket, PeerInfo}) ->
        {ok, Pid} = trust_conn_fsm:start_link(Socket, PeerInfo, SessionConfig),
        Pid
    end, lists:zip(Sockets, PeerInfos)),
    
    %% Complete handshakes
    Token = <<"valid_token">>,
    Frame = term_to_binary(#{t => token, token => Token}),
    [gen_statem:cast(Pid, {ssl, Socket, Frame}) || {Pid, Socket} <- lists:zip(FSMs, Sockets)],
    timer:sleep(100),
    
    %% Measure throughput
    StartTime = erlang:system_time(microsecond),
    RequestCount = 50,
    
    %% Send requests to all connections
    [begin
        Requests = [test_helpers:create_test_request(I) || I <- lists:seq(1, RequestCount)],
        [gen_statem:cast(Pid, {ssl, Socket, term_to_binary(R)}) || R <- Requests]
    end || {Pid, Socket} <- lists:zip(FSMs, Sockets)],
    
    %% Wait for completion
    timer:sleep(2000),
    
    EndTime = erlang:system_time(microsecond),
    Duration = EndTime - StartTime,
    TotalRequests = RequestCount * ConnectionCount,
    Throughput = (TotalRequests * 1000000) div Duration,
    
    %% Log results
    ct:log("Total throughput: ~p requests/sec", [Throughput]),
    ct:log("Per connection: ~p requests/sec", [Throughput div ConnectionCount]),
    ct:log("Duration: ~p microseconds", [Duration]),
    
    %% Verify all FSMs are still running
    [?assert(is_process_alive(Pid)) || Pid <- FSMs],
    
    %% Cleanup
    [gen_statem:stop(Pid) || Pid <- FSMs],
    ok.

%%--------------------------------------------------------------------
%% @doc Tests latency percentiles.
%% @end
%%--------------------------------------------------------------------
perf_latency_percentiles(_Config) ->
    %% Create test socket and config
    Socket = test_helpers:create_test_socket(),
    PeerInfo = test_helpers:create_test_peer_info(),
    SessionConfig = test_helpers:create_test_session_config(),
    
    %% Start FSM
    {ok, Pid} = trust_conn_fsm:start_link(Socket, PeerInfo, SessionConfig),
    
    %% Complete handshake
    Token = <<"valid_token">>,
    Frame = term_to_binary(#{t => token, token => Token}),
    gen_statem:cast(Pid, {ssl, Socket, Frame}),
    timer:sleep(100),
    
    %% Measure latencies
    RequestCount = 100,
    Latencies = lists:map(fun(I) ->
        StartTime = erlang:system_time(microsecond),
        Request = test_helpers:create_test_request(I),
        gen_statem:cast(Pid, {ssl, Socket, term_to_binary(Request)}),
        timer:sleep(10),  %% Simulate processing time
        EndTime = erlang:system_time(microsecond),
        EndTime - StartTime
    end, lists:seq(1, RequestCount)),
    
    %% Calculate percentiles
    SortedLatencies = lists:sort(Latencies),
    P50 = lists:nth(RequestCount div 2, SortedLatencies),
    P95 = lists:nth(trunc(RequestCount * 0.95), SortedLatencies),
    P99 = lists:nth(trunc(RequestCount * 0.99), SortedLatencies),
    
    %% Log results
    ct:log("P50 latency: ~p microseconds", [P50]),
    ct:log("P95 latency: ~p microseconds", [P95]),
    ct:log("P99 latency: ~p microseconds", [P99]),
    
    %% Verify FSM is still running
    ?assert(is_process_alive(Pid)),
    
    %% Cleanup
    gen_statem:stop(Pid),
    ok.

%%--------------------------------------------------------------------
%% @doc Tests memory usage under load.
%% @end
%%--------------------------------------------------------------------
perf_memory_usage_under_load(_Config) ->
    %% Create test socket and config
    Socket = test_helpers:create_test_socket(),
    PeerInfo = test_helpers:create_test_peer_info(),
    SessionConfig = test_helpers:create_test_session_config(),
    
    %% Start FSM
    {ok, Pid} = trust_conn_fsm:start_link(Socket, PeerInfo, SessionConfig),
    
    %% Complete handshake
    Token = <<"valid_token">>,
    Frame = term_to_binary(#{t => token, token => Token}),
    gen_statem:cast(Pid, {ssl, Socket, Frame}),
    timer:sleep(100),
    
    %% Measure memory usage
    InitialMemory = erlang:memory(total),
    
    %% Send requests under load
    RequestCount = 1000,
    Requests = [test_helpers:create_test_request(I) || I <- lists:seq(1, RequestCount)],
    [gen_statem:cast(Pid, {ssl, Socket, term_to_binary(R)}) || R <- Requests],
    
    %% Wait for processing
    timer:sleep(2000),
    
    %% Measure memory usage after load
    FinalMemory = erlang:memory(total),
    MemoryIncrease = FinalMemory - InitialMemory,
    
    %% Log results
    ct:log("Initial memory: ~p bytes", [InitialMemory]),
    ct:log("Final memory: ~p bytes", [FinalMemory]),
    ct:log("Memory increase: ~p bytes", [MemoryIncrease]),
    ct:log("Memory per request: ~p bytes", [MemoryIncrease div RequestCount]),
    
    %% Verify FSM is still running
    ?assert(is_process_alive(Pid)),
    
    %% Cleanup
    gen_statem:stop(Pid),
    ok.

%%--------------------------------------------------------------------
%% @doc Tests max_inflight saturation.
%% @end
%%--------------------------------------------------------------------
perf_max_inflight_saturation(_Config) ->
    %% Create test socket and config with small max_inflight
    Socket = test_helpers:create_test_socket(),
    PeerInfo = test_helpers:create_test_peer_info(),
    BaseConfig = test_helpers:create_test_session_config(),
    SessionConfig = maps:put(max_inflight, 4, BaseConfig),
    
    %% Start FSM
    {ok, Pid} = trust_conn_fsm:start_link(Socket, PeerInfo, SessionConfig),
    
    %% Complete handshake
    Token = <<"valid_token">>,
    Frame = term_to_binary(#{t => token, token => Token}),
    gen_statem:cast(Pid, {ssl, Socket, Frame}),
    timer:sleep(100),
    
    %% Measure backpressure activation time
    StartTime = erlang:system_time(microsecond),
    
    %% Send requests to saturate max_inflight
    Requests = [test_helpers:create_test_request(I) || I <- lists:seq(1, 10)],
    [gen_statem:cast(Pid, {ssl, Socket, term_to_binary(R)}) || R <- Requests],
    
    %% Wait for backpressure to activate
    timer:sleep(100),
    
    EndTime = erlang:system_time(microsecond),
    ActivationTime = EndTime - StartTime,
    
    %% Log results
    ct:log("Backpressure activation time: ~p microseconds", [ActivationTime]),
    
    %% Verify FSM is still running
    ?assert(is_process_alive(Pid)),
    
    %% Cleanup
    gen_statem:stop(Pid),
    ok.

%%--------------------------------------------------------------------
%% @doc Tests session lifecycle overhead.
%% @end
%%--------------------------------------------------------------------
perf_session_lifecycle_overhead(_Config) ->
    %% Measure session creation time
    StartTime = erlang:system_time(microsecond),
    
    %% Create and start FSM
    Socket = test_helpers:create_test_socket(),
    PeerInfo = test_helpers:create_test_peer_info(),
    SessionConfig = test_helpers:create_test_session_config(),
    {ok, Pid} = trust_conn_fsm:start_link(Socket, PeerInfo, SessionConfig),
    
    %% Complete handshake
    Token = <<"valid_token">>,
    Frame = term_to_binary(#{t => token, token => Token}),
    gen_statem:cast(Pid, {ssl, Socket, Frame}),
    timer:sleep(100),
    
    CreationTime = erlang:system_time(microsecond) - StartTime,
    
    %% Measure session teardown time
    TeardownStartTime = erlang:system_time(microsecond),
    gen_statem:stop(Pid),
    TeardownTime = erlang:system_time(microsecond) - TeardownStartTime,
    
    %% Log results
    ct:log("Session creation time: ~p microseconds", [CreationTime]),
    ct:log("Session teardown time: ~p microseconds", [TeardownTime]),
    
    ok.

%%--------------------------------------------------------------------
%% @doc Tests GOAWAY drain performance.
%% @end
%%--------------------------------------------------------------------
perf_goaway_drain_performance(_Config) ->
    %% Create test socket and config with small max_calls
    Socket = test_helpers:create_test_socket(),
    PeerInfo = test_helpers:create_test_peer_info(),
    BaseConfig = test_helpers:create_test_session_config(),
    SessionConfig = maps:put(max_calls, 5, BaseConfig),
    
    %% Start FSM
    {ok, Pid} = trust_conn_fsm:start_link(Socket, PeerInfo, SessionConfig),
    
    %% Complete handshake
    Token = <<"valid_token">>,
    Frame = term_to_binary(#{t => token, token => Token}),
    gen_statem:cast(Pid, {ssl, Socket, Frame}),
    timer:sleep(100),
    
    %% Measure GOAWAY drain time
    StartTime = erlang:system_time(microsecond),
    
    %% Send requests to trigger max_calls
    Requests = [test_helpers:create_test_request(I) || I <- lists:seq(1, 5)],
    [gen_statem:cast(Pid, {ssl, Socket, term_to_binary(R)}) || R <- Requests],
    
    %% Wait for GOAWAY and drain
    timer:sleep(1000),
    
    EndTime = erlang:system_time(microsecond),
    DrainTime = EndTime - StartTime,
    
    %% Log results
    ct:log("GOAWAY drain time: ~p microseconds", [DrainTime]),
    
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
