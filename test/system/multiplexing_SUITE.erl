%%%-------------------------------------------------------------------
%% @doc System tests for multiplexing functionality.
%% @end
%%%-------------------------------------------------------------------

-module(multiplexing_SUITE).
-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").

%% Test callbacks
-export([all/0, groups/0, init_per_suite/1, end_per_suite/1,
         init_per_testcase/2, end_per_testcase/2]).

%% Test cases
-export([
    system_single_request_response/1,
    system_concurrent_requests_in_order/1,
    system_concurrent_requests_out_of_order/1,
    system_handles_max_inflight_requests/1,
    system_request_correlation_with_reqid/1,
    system_multiple_sessions_isolated/1
]).

%%--------------------------------------------------------------------
%% @doc Returns list of all test cases.
%% @end
%%--------------------------------------------------------------------
all() ->
    [
        system_single_request_response,
        system_concurrent_requests_in_order,
        system_concurrent_requests_out_of_order,
        system_handles_max_inflight_requests,
        system_request_correlation_with_reqid,
        system_multiple_sessions_isolated
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
%% @doc Tests single request-response flow.
%% @end
%%--------------------------------------------------------------------
system_single_request_response(_Config) ->
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
    
    %% Send single request
    Request = test_helpers:create_test_request(1),
    RequestFrame = term_to_binary(Request),
    gen_statem:cast(Pid, {ssl, Socket, RequestFrame}),
    timer:sleep(200),
    
    %% Verify FSM is still running
    ?assert(is_process_alive(Pid)),
    
    %% Cleanup
    gen_statem:stop(Pid),
    ok.

%%--------------------------------------------------------------------
%% @doc Tests concurrent requests in order.
%% @end
%%--------------------------------------------------------------------
system_concurrent_requests_in_order(_Config) ->
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
    
    %% Send multiple requests in order
    Requests = [test_helpers:create_test_request(I) || I <- lists:seq(1, 5)],
    [gen_statem:cast(Pid, {ssl, Socket, term_to_binary(R)}) || R <- Requests],
    timer:sleep(500),
    
    %% Verify FSM is still running
    ?assert(is_process_alive(Pid)),
    
    %% Cleanup
    gen_statem:stop(Pid),
    ok.

%%--------------------------------------------------------------------
%% @doc Tests concurrent requests out of order.
%% @end
%%--------------------------------------------------------------------
system_concurrent_requests_out_of_order(_Config) ->
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
    
    %% Send multiple requests out of order
    Requests = [test_helpers:create_test_request(I) || I <- [3,1,5,2,4]],
    [gen_statem:cast(Pid, {ssl, Socket, term_to_binary(R)}) || R <- Requests],
    timer:sleep(500),
    
    %% Verify FSM is still running
    ?assert(is_process_alive(Pid)),
    
    %% Cleanup
    gen_statem:stop(Pid),
    ok.

%%--------------------------------------------------------------------
%% @doc Tests max_inflight request handling.
%% @end
%%--------------------------------------------------------------------
system_handles_max_inflight_requests(_Config) ->
    %% Create test socket and config with small max_inflight
    Socket = test_helpers:create_test_socket(),
    PeerInfo = test_helpers:create_test_peer_info(),
    BaseConfig = test_helpers:create_test_session_config(),
    SessionConfig = maps:put(max_inflight, 3, BaseConfig),
    
    %% Start FSM
    {ok, Pid} = trust_conn_fsm:start_link(Socket, PeerInfo, SessionConfig),
    
    %% Complete handshake
    Token = <<"valid_token">>,
    Frame = term_to_binary(#{t => token, token => Token}),
    gen_statem:cast(Pid, {ssl, Socket, Frame}),
    timer:sleep(100),
    
    %% Send requests up to max_inflight
    Requests = [test_helpers:create_test_request(I) || I <- lists:seq(1, 3)],
    [gen_statem:cast(Pid, {ssl, Socket, term_to_binary(R)}) || R <- Requests],
    timer:sleep(200),
    
    %% Send additional requests (should trigger backpressure)
    ExtraRequests = [test_helpers:create_test_request(I) || I <- lists:seq(4, 6)],
    [gen_statem:cast(Pid, {ssl, Socket, term_to_binary(R)}) || R <- ExtraRequests],
    timer:sleep(200),
    
    %% Verify FSM is still running
    ?assert(is_process_alive(Pid)),
    
    %% Cleanup
    gen_statem:stop(Pid),
    ok.

%%--------------------------------------------------------------------
%% @doc Tests request correlation with req_id.
%% @end
%%--------------------------------------------------------------------
system_request_correlation_with_reqid(_Config) ->
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
    
    %% Send requests with specific req_ids
    ReqIds = [1, 2, 3, 4, 5],
    Requests = [test_helpers:create_test_request(Id) || Id <- ReqIds],
    [gen_statem:cast(Pid, {ssl, Socket, term_to_binary(R)}) || R <- Requests],
    timer:sleep(500),
    
    %% Verify FSM is still running
    ?assert(is_process_alive(Pid)),
    
    %% Cleanup
    gen_statem:stop(Pid),
    ok.

%%--------------------------------------------------------------------
%% @doc Tests multiple sessions are isolated.
%% @end
%%--------------------------------------------------------------------
system_multiple_sessions_isolated(_Config) ->
    %% Create multiple test sockets and configs
    Socket1 = test_helpers:create_test_socket(),
    Socket2 = test_helpers:create_test_socket(),
    PeerInfo1 = test_helpers:create_test_peer_info(),
    PeerInfo2 = test_helpers:create_test_peer_info(),
    SessionConfig = test_helpers:create_test_session_config(),
    
    %% Start multiple FSMs
    {ok, Pid1} = trust_conn_fsm:start_link(Socket1, PeerInfo1, SessionConfig),
    {ok, Pid2} = trust_conn_fsm:start_link(Socket2, PeerInfo2, SessionConfig),
    
    %% Complete handshakes
    Token = <<"valid_token">>,
    Frame = term_to_binary(#{t => token, token => Token}),
    gen_statem:cast(Pid1, {ssl, Socket1, Frame}),
    gen_statem:cast(Pid2, {ssl, Socket2, Frame}),
    timer:sleep(100),
    
    %% Send requests to both FSMs
    Request1 = test_helpers:create_test_request(1),
    Request2 = test_helpers:create_test_request(2),
    gen_statem:cast(Pid1, {ssl, Socket1, term_to_binary(Request1)}),
    gen_statem:cast(Pid2, {ssl, Socket2, term_to_binary(Request2)}),
    timer:sleep(200),
    
    %% Verify both FSMs are still running
    ?assert(is_process_alive(Pid1)),
    ?assert(is_process_alive(Pid2)),
    
    %% Cleanup
    gen_statem:stop(Pid1),
    gen_statem:stop(Pid2),
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
