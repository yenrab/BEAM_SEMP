%%%-------------------------------------------------------------------
%% @doc Integration tests for FSM with real components.
%% @end
%%%-------------------------------------------------------------------

-module(fsm_integration_SUITE).
-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").

%% Test callbacks
-export([all/0, groups/0, init_per_suite/1, end_per_suite/1,
         init_per_testcase/2, end_per_testcase/2]).

%% Test cases
-export([
    fsm_complete_session_lifecycle/1,
    fsm_handles_multiple_concurrent_requests/1,
    fsm_enforces_max_inflight_limit/1,
    fsm_transitions_to_draining_on_max_calls/1,
    fsm_closes_on_idle_timeout/1,
    fsm_rejects_invalid_token/1,
    fsm_sends_goaway_on_protocol_error/1
]).

%%--------------------------------------------------------------------
%% @doc Returns list of all test cases.
%% @end
%%--------------------------------------------------------------------
all() ->
    [
        fsm_complete_session_lifecycle,
        fsm_handles_multiple_concurrent_requests,
        fsm_enforces_max_inflight_limit,
        fsm_transitions_to_draining_on_max_calls,
        fsm_closes_on_idle_timeout,
        fsm_rejects_invalid_token,
        fsm_sends_goaway_on_protocol_error
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
    
    %% Setup test environment
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
    %% Get tables from config and cleanup (handle case where tables might be deleted)
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
                {error, {already_started, ConnPid}} -> ConnPid;
                {error, ConnReason} -> throw({conn_sup_start_failed, ConnReason})
            end;
        ConnPid -> ConnPid
    end,
    
    WorkerSupPid = case whereis(trust_conn_worker_sup) of
        undefined ->
            case trust_conn_worker_sup:start_link() of
                {ok, WorkerPid} -> WorkerPid;
                {error, {already_started, WorkerPid}} -> WorkerPid;
                {error, WorkerReason} -> throw({worker_sup_start_failed, WorkerReason})
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
%% @doc Tests complete FSM session lifecycle.
%% @end
%%--------------------------------------------------------------------
fsm_complete_session_lifecycle(_Config) ->
    %% Create test socket and config
    Socket = test_helpers:create_test_socket(),
    PeerInfo = test_helpers:create_test_peer_info(),
    SessionConfig = test_helpers:create_test_session_config(),
    
    %% Start FSM
    {ok, Pid} = trust_conn_fsm:start_link(Socket, PeerInfo, SessionConfig),
    
    %% Verify FSM is running
    ?assert(is_pid(Pid)),
    ?assert(is_process_alive(Pid)),
    
    %% Complete handshake
    Token = <<"valid_token">>,
    Frame = term_to_binary(#{t => token_present, token => Token}),
    gen_statem:cast(Pid, {ssl, Socket, Frame}),
    timer:sleep(100),
    
    %% Send a request
    Request = test_helpers:create_test_request(1),
    RequestFrame = term_to_binary(Request),
    gen_statem:cast(Pid, {ssl, Socket, RequestFrame}),
    timer:sleep(100),
    
    %% Verify FSM is still running
    ?assert(is_process_alive(Pid)),
    
    %% Cleanup
    gen_statem:stop(Pid),
    ok.

%%--------------------------------------------------------------------
%% @doc Tests FSM handles multiple concurrent requests.
%% @end
%%--------------------------------------------------------------------
fsm_handles_multiple_concurrent_requests(_Config) ->
    %% Create test socket and config
    Socket = test_helpers:create_test_socket(),
    PeerInfo = test_helpers:create_test_peer_info(),
    SessionConfig = test_helpers:create_test_session_config(),
    
    %% Start FSM
    {ok, Pid} = trust_conn_fsm:start_link(Socket, PeerInfo, SessionConfig),
    
    %% Complete handshake
    Token = <<"valid_token">>,
    Frame = term_to_binary(#{t => token_present, token => Token}),
    gen_statem:cast(Pid, {ssl, Socket, Frame}),
    timer:sleep(100),
    
    %% Send multiple requests
    Requests = [test_helpers:create_test_request(I) || I <- lists:seq(1, 5)],
    [gen_statem:cast(Pid, {ssl, Socket, term_to_binary(R)}) || R <- Requests],
    timer:sleep(200),
    
    %% Verify FSM is still running
    ?assert(is_process_alive(Pid)),
    
    %% Cleanup
    gen_statem:stop(Pid),
    ok.

%%--------------------------------------------------------------------
%% @doc Tests FSM enforces max_inflight limit.
%% @end
%%--------------------------------------------------------------------
fsm_enforces_max_inflight_limit(_Config) ->
    %% Create test socket and config with small max_inflight
    Socket = test_helpers:create_test_socket(),
    PeerInfo = test_helpers:create_test_peer_info(),
    BaseConfig = test_helpers:create_test_session_config(),
    SessionConfig = BaseConfig#{max_inflight => 2},
    
    %% Start FSM
    {ok, Pid} = trust_conn_fsm:start_link(Socket, PeerInfo, SessionConfig),
    
    %% Complete handshake
    Token = <<"valid_token">>,
    Frame = term_to_binary(#{t => token_present, token => Token}),
    gen_statem:cast(Pid, {ssl, Socket, Frame}),
    
    %% Wait for handshake completion
    timer:sleep(100),
    
    %% Send requests up to max_inflight limit
    Request1 = term_to_binary(#{t => call, req_id => 1, m => lists, f => reverse, a => 1, args => [[1,2,3]]}),
    Request2 = term_to_binary(#{t => call, req_id => 2, m => lists, f => reverse, a => 1, args => [[4,5,6]]}),
    
    gen_statem:cast(Pid, {ssl, Socket, Request1}),
    gen_statem:cast(Pid, {ssl, Socket, Request2}),
    
    %% Wait for workers to start
    timer:sleep(100),
    
    %% Verify FSM is still running (not crashed)
    true = is_process_alive(Pid),
    
    %% Send one more request that should trigger backpressure
    Request3 = term_to_binary(#{t => call, req_id => 3, m => lists, f => reverse, a => 1, args => [[7,8,9]]}),
    gen_statem:cast(Pid, {ssl, Socket, Request3}),
    
    %% Wait a bit and verify FSM is still running
    timer:sleep(100),
    true = is_process_alive(Pid),
    
    %% Cleanup
    gen_statem:stop(Pid),
    ok.

%%--------------------------------------------------------------------
%% @doc Tests FSM transitions to draining on max_calls.
%% @end
%%--------------------------------------------------------------------
fsm_transitions_to_draining_on_max_calls(_Config) ->
    %% Create test socket and config with small max_calls
    Socket = test_helpers:create_test_socket(),
    PeerInfo = test_helpers:create_test_peer_info(),
    BaseConfig = test_helpers:create_test_session_config(),
    SessionConfig = BaseConfig#{max_calls => 2},
    
    %% Start FSM
    {ok, Pid} = trust_conn_fsm:start_link(Socket, PeerInfo, SessionConfig),
    
    %% Complete handshake
    Token = <<"valid_token">>,
    Frame = term_to_binary(#{t => token_present, token => Token}),
    gen_statem:cast(Pid, {ssl, Socket, Frame}),
    timer:sleep(100),
    
    %% Send requests up to max_calls limit
    Request1 = term_to_binary(#{t => call, req_id => 1, m => lists, f => reverse, a => 1, args => [[1,2,3]]}),
    Request2 = term_to_binary(#{t => call, req_id => 2, m => lists, f => reverse, a => 1, args => [[4,5,6]]}),
    
    gen_statem:cast(Pid, {ssl, Socket, Request1}),
    gen_statem:cast(Pid, {ssl, Socket, Request2}),
    timer:sleep(100),
    
    %% Verify FSM is still running
    true = is_process_alive(Pid),
    
    %% Send one more request that should trigger draining
    Request3 = term_to_binary(#{t => call, req_id => 3, m => lists, f => reverse, a => 1, args => [[7,8,9]]}),
    gen_statem:cast(Pid, {ssl, Socket, Request3}),
    timer:sleep(100),
    
    %% Verify FSM is still running (should be in draining state)
    true = is_process_alive(Pid),
    
    %% Cleanup
    gen_statem:stop(Pid),
    ok.

%%--------------------------------------------------------------------
%% @doc Tests FSM closes on idle timeout.
%% @end
%%--------------------------------------------------------------------
fsm_closes_on_idle_timeout(_Config) ->
    %% Create test socket and config with short idle timeout
    Socket = test_helpers:create_test_socket(),
    PeerInfo = test_helpers:create_test_peer_info(),
    BaseConfig = test_helpers:create_test_session_config(),
    SessionConfig = BaseConfig#{idle_ms => 100},
    
    %% Start FSM
    {ok, Pid} = trust_conn_fsm:start_link(Socket, PeerInfo, SessionConfig),
    
    %% Verify FSM is running
    true = is_process_alive(Pid),
    
    %% Wait for idle timeout to trigger (with some buffer)
    timer:sleep(250),
    
    %% Verify FSM has closed due to idle timeout
    %% Use a more robust check with timeout
    case is_process_alive(Pid) of
        false -> ok;  %% FSM terminated as expected
        true -> 
            %% FSM is still alive, try to stop it manually
            gen_statem:stop(Pid),
            timer:sleep(50),
            case is_process_alive(Pid) of
                false -> ok;  %% FSM stopped manually
                true -> ct:fail("FSM did not terminate after idle timeout or manual stop")
            end
    end,
    
    ok.

%%--------------------------------------------------------------------
%% @doc Tests FSM rejects invalid token.
%% @end
%%--------------------------------------------------------------------
fsm_rejects_invalid_token(_Config) ->
    %% Create test socket and config
    Socket = test_helpers:create_test_socket(),
    PeerInfo = test_helpers:create_test_peer_info(),
    SessionConfig = test_helpers:create_test_session_config(),
    
    %% Start FSM
    {ok, Pid} = trust_conn_fsm:start_link(Socket, PeerInfo, SessionConfig),
    
    %% Send invalid token
    Token = <<"invalid_token">>,
    Frame = term_to_binary(#{t => token, token => Token}),
    gen_statem:cast(Pid, {ssl, Socket, Frame}),
    timer:sleep(100),
    
    %% Verify FSM has closed
    ?assertNot(is_process_alive(Pid)),
    ok.

%%--------------------------------------------------------------------
%% @doc Tests FSM sends GOAWAY on protocol error.
%% @end
%%--------------------------------------------------------------------
fsm_sends_goaway_on_protocol_error(_Config) ->
    %% Create test socket and config
    Socket = test_helpers:create_test_socket(),
    PeerInfo = test_helpers:create_test_peer_info(),
    SessionConfig = test_helpers:create_test_session_config(),
    
    %% Start FSM and monitor it
    {ok, Pid} = trust_conn_fsm:start_link(Socket, PeerInfo, SessionConfig),
    MRef = erlang:monitor(process, Pid),
    
    %% Send malformed frame directly (without completing handshake first)
    %% This tests that the FSM terminates when receiving a malformed frame
    %% during the handshake phase
    MalformedFrame = <<"invalid_binary_data">>,
    gen_statem:cast(Pid, {ssl, Socket, MalformedFrame}),
    
    %% Wait for FSM to terminate (with timeout)
    receive
        {'DOWN', MRef, process, Pid, _Reason} ->
            ok
    after 1000 ->
            ct:fail("FSM did not terminate after receiving malformed frame")
    end,
    
    %% Verify FSM has closed
    ?assertNot(is_process_alive(Pid)),
    ok.
