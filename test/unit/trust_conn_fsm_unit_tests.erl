%%%-------------------------------------------------------------------
%% @doc Unit tests for trust_conn_fsm using EUnit with mocking.
%% @end
%%%-------------------------------------------------------------------

-module(trust_conn_fsm_unit_tests).
-include_lib("eunit/include/eunit.hrl").

%%--------------------------------------------------------------------
%% @doc Test suite setup and teardown.
%% @end
%%--------------------------------------------------------------------
fsm_unit_test_() ->
    {foreach,
     fun setup_fsm_test/0,
     fun cleanup_fsm_test/1,
     [
        fun fsm_init_with_default_config_test/1,
        fun fsm_init_with_sys_config_override_test/1,
        fun fsm_handshake_token_success_test/1,
        fun fsm_handshake_token_invalid_test/1,
        fun fsm_max_inflight_triggers_backpressure_test/1,
        fun fsm_duplicate_reqid_rejected_test/1,
        fun fsm_frame_size_exceeded_closes_connection_test/1,
        fun fsm_max_calls_triggers_drain_test/1,
        fun fsm_max_age_triggers_drain_test/1,
        fun fsm_idle_timeout_triggers_drain_test/1,
        fun fsm_worker_down_resumes_reads_test/1,
        fun fsm_goaway_sent_on_limit_reached_test/1
     ]}.

%%--------------------------------------------------------------------
%% @doc Sets up FSM test environment.
%% @end
%%--------------------------------------------------------------------
setup_fsm_test() ->
    %% Clean up any existing mocks first
    meck:unload(),
    
    %% Setup test environment
    {WhitelistTab, PolicyTab} = test_helpers:setup_test_env(),
    
    %% Mock all dependencies
    mock_modules:mock_semp_facades(),
    mock_modules:mock_trust_token(),
    mock_modules:mock_trust_suspicion(),
    mock_modules:mock_semp_whitelist(),
    mock_modules:mock_semp_policy(),
    
    %% Create test socket and config
    Socket = test_helpers:create_test_socket(),
    SessionConfig = test_helpers:create_test_session_config(),
    PeerInfo = test_helpers:create_test_peer_info(),
    
    %% Mock worker supervisor
    meck:new(trust_conn_worker_sup, [unstick, passthrough]),
    meck:expect(trust_conn_worker_sup, start_link, fun() -> 
        {ok, spawn(fun() -> receive _ -> ok end end)} 
    end),
    
    %% Mock supervisor for worker spawning
    meck:new(supervisor, [unstick, passthrough]),
    meck:expect(supervisor, start_child, fun(_Sup, _Spec) -> 
        {ok, spawn(fun() -> receive _ -> ok end end)} 
    end),
    
    %% Mock semp_util for frame sending
    meck:new(semp_util, [unstick, passthrough]),
    meck:expect(semp_util, send_frame, fun(_Socket, _Frame) -> ok end),
    
    {Socket, SessionConfig, PeerInfo, WhitelistTab, PolicyTab}.

%%--------------------------------------------------------------------
%% @doc Cleans up FSM test environment.
%% @end
%%--------------------------------------------------------------------
cleanup_fsm_test({_Socket, _SessionConfig, _PeerInfo, WhitelistTab, PolicyTab}) ->
    mock_modules:unmock_all(),
    test_helpers:cleanup_test_env({WhitelistTab, PolicyTab}),
    ok.

%%--------------------------------------------------------------------
%% @doc Tests FSM initialization with default config.
%% @end
%%--------------------------------------------------------------------
fsm_init_with_default_config_test({Socket, SessionConfig, PeerInfo, _WhitelistTab, _PolicyTab}) ->
    %% Mock application:get_env to return default config
    meck:new(application, [unstick, passthrough]),
    meck:expect(application, get_env, fun(beam_semp, session, _Default) -> 
        SessionConfig 
    end),
    
    %% Start FSM
    {ok, Pid} = trust_conn_fsm:start_link(Socket, PeerInfo, #{}),
    
    %% Verify FSM is running
    ?assert(is_pid(Pid)),
    ?assert(is_process_alive(Pid)),
    
    %% Cleanup
    gen_statem:stop(Pid),
    meck:unload(application),
    ok.

%%--------------------------------------------------------------------
%% @doc Tests FSM initialization with sys.config override.
%% @end
%%--------------------------------------------------------------------
fsm_init_with_sys_config_override_test({Socket, _SessionConfig, PeerInfo, _WhitelistTab, _PolicyTab}) ->
    %% Mock application:get_env to return overridden config
    OverrideConfig = #{max_inflight => 16, max_age_ms => 120000},
    meck:new(application, [unstick, passthrough]),
    meck:expect(application, get_env, fun(beam_semp, session, _Default) -> 
        OverrideConfig 
    end),
    
    %% Start FSM
    {ok, Pid} = trust_conn_fsm:start_link(Socket, PeerInfo, #{}),
    
    %% Verify FSM is running
    ?assert(is_pid(Pid)),
    ?assert(is_process_alive(Pid)),
    
    %% Cleanup
    gen_statem:stop(Pid),
    meck:unload(application),
    ok.

%%--------------------------------------------------------------------
%% @doc Tests successful token handshake.
%% @end
%%--------------------------------------------------------------------
fsm_handshake_token_success_test({Socket, SessionConfig, PeerInfo, _WhitelistTab, _PolicyTab}) ->
    %% Mock successful token validation
    meck:expect(trust_token, validate, fun(_Token, _State) -> 
        {ok, #{client_id => <<"test_client">>, permissions => any}} 
    end),
    
    %% Start FSM
    {ok, Pid} = trust_conn_fsm:start_link(Socket, PeerInfo, SessionConfig),
    
    %% Send valid token
    Token = <<"valid_token">>,
    Frame = term_to_binary(#{t => token, token => Token}),
    gen_statem:cast(Pid, {ssl, Socket, Frame}),
    
    %% Wait for transition to active state
    timer:sleep(100),
    
    %% Verify FSM is still running (should be in active state)
    ?assert(is_process_alive(Pid)),
    
    %% Cleanup
    gen_statem:stop(Pid),
    ok.

%%--------------------------------------------------------------------
%% @doc Tests invalid token handshake.
%% @end
%%--------------------------------------------------------------------
fsm_handshake_token_invalid_test({Socket, SessionConfig, PeerInfo, _WhitelistTab, _PolicyTab}) ->
    %% Mock failed token validation
    meck:expect(trust_token, validate, fun(_Token, _State) -> 
        {error, invalid_token} 
    end),
    
    %% Start FSM
    {ok, Pid} = trust_conn_fsm:start_link(Socket, PeerInfo, SessionConfig),
    
    %% Send invalid token
    Token = <<"invalid_token">>,
    Frame = term_to_binary(#{t => token, token => Token}),
    gen_statem:cast(Pid, {ssl, Socket, Frame}),
    
    %% Wait for FSM to close
    timer:sleep(100),
    
    %% Verify FSM has closed
    ?assertNot(is_process_alive(Pid)),
    ok.

%%--------------------------------------------------------------------
%% @doc Tests backpressure when max_inflight is reached.
%% @end
%%--------------------------------------------------------------------
fsm_max_inflight_triggers_backpressure_test({Socket, SessionConfig, PeerInfo, _WhitelistTab, _PolicyTab}) ->
    %% Use small max_inflight for testing
    TestConfig = SessionConfig#{max_inflight => 2},
    
    %% Start FSM
    {ok, Pid} = trust_conn_fsm:start_link(Socket, PeerInfo, TestConfig),
    
    %% Mock successful token validation
    meck:expect(trust_token, validate, fun(_Token, _State) -> 
        {ok, #{client_id => <<"test_client">>, permissions => any}} 
    end),
    
    %% Complete handshake
    Token = <<"valid_token">>,
    Frame = term_to_binary(#{t => token, token => Token}),
    gen_statem:cast(Pid, {ssl, Socket, Frame}),
    timer:sleep(100),
    
    %% Send requests up to max_inflight
    Request1 = test_helpers:create_test_request(1),
    Request2 = test_helpers:create_test_request(2),
    Frame1 = term_to_binary(Request1),
    Frame2 = term_to_binary(Request2),
    
    gen_statem:cast(Pid, {ssl, Socket, Frame1}),
    gen_statem:cast(Pid, {ssl, Socket, Frame2}),
    timer:sleep(100),
    
    %% Send one more request (should trigger backpressure)
    Request3 = test_helpers:create_test_request(3),
    Frame3 = term_to_binary(Request3),
    gen_statem:cast(Pid, {ssl, Socket, Frame3}),
    
    %% Verify telemetry events for backpressure
    Events = test_helpers:capture_telemetry_events(),
    BackpressureEvents = [E || E <- Events, 
        element(1, E) =:= [trust, request, refuse] orelse
        element(1, E) =:= [trust, pause]],
    ?assert(length(BackpressureEvents) > 0),
    
    %% Cleanup
    gen_statem:stop(Pid),
    ok.

%%--------------------------------------------------------------------
%% @doc Tests duplicate request ID rejection.
%% @end
%%--------------------------------------------------------------------
fsm_duplicate_reqid_rejected_test({Socket, SessionConfig, PeerInfo, _WhitelistTab, _PolicyTab}) ->
    %% Start FSM
    {ok, Pid} = trust_conn_fsm:start_link(Socket, PeerInfo, SessionConfig),
    
    %% Mock successful token validation
    meck:expect(trust_token, validate, fun(_Token, _State) -> 
        {ok, #{client_id => <<"test_client">>, permissions => any}} 
    end),
    
    %% Complete handshake
    Token = <<"valid_token">>,
    Frame = term_to_binary(#{t => token, token => Token}),
    gen_statem:cast(Pid, {ssl, Socket, Frame}),
    timer:sleep(100),
    
    %% Send same request twice
    Request = test_helpers:create_test_request(1),
    Frame = term_to_binary(Request),
    
    gen_statem:cast(Pid, {ssl, Socket, Frame}),
    gen_statem:cast(Pid, {ssl, Socket, Frame}),
    timer:sleep(100),
    
    %% Verify telemetry events for duplicate rejection
    Events = test_helpers:capture_telemetry_events(),
    DuplicateEvents = [E || E <- Events, 
        element(1, E) =:= [trust, request, refuse]],
    ?assert(length(DuplicateEvents) > 0),
    
    %% Cleanup
    gen_statem:stop(Pid),
    ok.

%%--------------------------------------------------------------------
%% @doc Tests frame size validation.
%% @end
%%--------------------------------------------------------------------
fsm_frame_size_exceeded_closes_connection_test({Socket, SessionConfig, PeerInfo, _WhitelistTab, _PolicyTab}) ->
    %% Start FSM
    {ok, Pid} = trust_conn_fsm:start_link(Socket, PeerInfo, SessionConfig),
    
    %% Mock successful token validation
    meck:expect(trust_token, validate, fun(_Token, _State) -> 
        {ok, #{client_id => <<"test_client">>, permissions => any}} 
    end),
    
    %% Complete handshake
    Token = <<"valid_token">>,
    Frame = term_to_binary(#{t => token, token => Token}),
    gen_statem:cast(Pid, {ssl, Socket, Frame}),
    timer:sleep(100),
    
    %% Send oversized frame (> 1 MiB)
    LargeData = binary:copy(<<0>>, 1048577),  %% 1 MiB + 1 byte
    LargeFrame = term_to_binary(#{t => request, data => LargeData}),
    gen_statem:cast(Pid, {ssl, Socket, LargeFrame}),
    timer:sleep(100),
    
    %% Verify FSM has closed due to frame size violation
    ?assertNot(is_process_alive(Pid)),
    ok.

%%--------------------------------------------------------------------
%% @doc Tests max_calls triggers drain.
%% @end
%%--------------------------------------------------------------------
fsm_max_calls_triggers_drain_test({Socket, SessionConfig, PeerInfo, _WhitelistTab, _PolicyTab}) ->
    %% Use small max_calls for testing
    TestConfig = SessionConfig#{max_calls => 2},
    
    %% Start FSM
    {ok, Pid} = trust_conn_fsm:start_link(Socket, PeerInfo, TestConfig),
    
    %% Mock successful token validation
    meck:expect(trust_token, validate, fun(_Token, _State) -> 
        {ok, #{client_id => <<"test_client">>, permissions => any}} 
    end),
    
    %% Complete handshake
    Token = <<"valid_token">>,
    Frame = term_to_binary(#{t => token, token => Token}),
    gen_statem:cast(Pid, {ssl, Socket, Frame}),
    timer:sleep(100),
    
    %% Send requests up to max_calls
    Request1 = test_helpers:create_test_request(1),
    Request2 = test_helpers:create_test_request(2),
    Frame1 = term_to_binary(Request1),
    Frame2 = term_to_binary(Request2),
    
    gen_statem:cast(Pid, {ssl, Socket, Frame1}),
    gen_statem:cast(Pid, {ssl, Socket, Frame2}),
    timer:sleep(100),
    
    %% Verify GOAWAY was sent
    Events = test_helpers:capture_telemetry_events(),
    GoawayEvents = [E || E <- Events, 
        element(1, E) =:= [trust, goaway]],
    ?assert(length(GoawayEvents) > 0),
    
    %% Cleanup
    gen_statem:stop(Pid),
    ok.

%%--------------------------------------------------------------------
%% @doc Tests max_age triggers drain.
%% @end
%%--------------------------------------------------------------------
fsm_max_age_triggers_drain_test({Socket, SessionConfig, PeerInfo, _WhitelistTab, _PolicyTab}) ->
    %% Use very short max_age for testing
    TestConfig = SessionConfig#{max_age_ms => 100},
    
    %% Start FSM
    {ok, Pid} = trust_conn_fsm:start_link(Socket, PeerInfo, TestConfig),
    
    %% Mock successful token validation
    meck:expect(trust_token, validate, fun(_Token, _State) -> 
        {ok, #{client_id => <<"test_client">>, permissions => any}} 
    end),
    
    %% Complete handshake
    Token = <<"valid_token">>,
    Frame = term_to_binary(#{t => token, token => Token}),
    gen_statem:cast(Pid, {ssl, Socket, Frame}),
    
    %% Wait for max_age timeout
    timer:sleep(200),
    
    %% Verify GOAWAY was sent due to max_age
    Events = test_helpers:capture_telemetry_events(),
    GoawayEvents = [E || E <- Events, 
        element(1, E) =:= [trust, goaway]],
    ?assert(length(GoawayEvents) > 0),
    
    %% Cleanup
    gen_statem:stop(Pid),
    ok.

%%--------------------------------------------------------------------
%% @doc Tests idle timeout triggers drain.
%% @end
%%--------------------------------------------------------------------
fsm_idle_timeout_triggers_drain_test({Socket, SessionConfig, PeerInfo, _WhitelistTab, _PolicyTab}) ->
    %% Use very short idle timeout for testing
    TestConfig = SessionConfig#{idle_ms => 100},
    
    %% Start FSM
    {ok, Pid} = trust_conn_fsm:start_link(Socket, PeerInfo, TestConfig),
    
    %% Mock successful token validation
    meck:expect(trust_token, validate, fun(_Token, _State) -> 
        {ok, #{client_id => <<"test_client">>, permissions => any}} 
    end),
    
    %% Complete handshake
    Token = <<"valid_token">>,
    Frame = term_to_binary(#{t => token, token => Token}),
    gen_statem:cast(Pid, {ssl, Socket, Frame}),
    timer:sleep(100),
    
    %% Wait for idle timeout
    timer:sleep(200),
    
    %% Verify GOAWAY was sent due to idle timeout
    Events = test_helpers:capture_telemetry_events(),
    GoawayEvents = [E || E <- Events, 
        element(1, E) =:= [trust, goaway]],
    ?assert(length(GoawayEvents) > 0),
    
    %% Cleanup
    gen_statem:stop(Pid),
    ok.

%%--------------------------------------------------------------------
%% @doc Tests worker completion resumes reads.
%% @end
%%--------------------------------------------------------------------
fsm_worker_down_resumes_reads_test({Socket, SessionConfig, PeerInfo, _WhitelistTab, _PolicyTab}) ->
    %% Use small max_inflight for testing
    TestConfig = SessionConfig#{max_inflight => 1},
    
    %% Start FSM
    {ok, Pid} = trust_conn_fsm:start_link(Socket, PeerInfo, TestConfig),
    
    %% Mock successful token validation
    meck:expect(trust_token, validate, fun(_Token, _State) -> 
        {ok, #{client_id => <<"test_client">>, permissions => any}} 
    end),
    
    %% Complete handshake
    Token = <<"valid_token">>,
    Frame = term_to_binary(#{t => token, token => Token}),
    gen_statem:cast(Pid, {ssl, Socket, Frame}),
    timer:sleep(100),
    
    %% Send request to fill max_inflight
    Request = test_helpers:create_test_request(1),
    Frame = term_to_binary(Request),
    gen_statem:cast(Pid, {ssl, Socket, Frame}),
    timer:sleep(100),
    
    %% Simulate worker completion
    gen_statem:cast(Pid, {'DOWN', make_ref(), process, make_ref(), normal}),
    timer:sleep(100),
    
    %% Verify resume telemetry event
    Events = test_helpers:capture_telemetry_events(),
    ResumeEvents = [E || E <- Events, 
        element(1, E) =:= [trust, resume]],
    ?assert(length(ResumeEvents) > 0),
    
    %% Cleanup
    gen_statem:stop(Pid),
    ok.

%%--------------------------------------------------------------------
%% @doc Tests GOAWAY sent on limit reached.
%% @end
%%--------------------------------------------------------------------
fsm_goaway_sent_on_limit_reached_test({Socket, SessionConfig, PeerInfo, _WhitelistTab, _PolicyTab}) ->
    %% Use very small limits for testing
    TestConfig = SessionConfig#{max_calls => 1, max_age_ms => 1000},
    
    %% Start FSM
    {ok, Pid} = trust_conn_fsm:start_link(Socket, PeerInfo, TestConfig),
    
    %% Mock successful token validation
    meck:expect(trust_token, validate, fun(_Token, _State) -> 
        {ok, #{client_id => <<"test_client">>, permissions => any}} 
    end),
    
    %% Complete handshake
    Token = <<"valid_token">>,
    Frame = term_to_binary(#{t => token, token => Token}),
    gen_statem:cast(Pid, {ssl, Socket, Frame}),
    timer:sleep(100),
    
    %% Send request to trigger max_calls
    Request = test_helpers:create_test_request(1),
    Frame = term_to_binary(Request),
    gen_statem:cast(Pid, {ssl, Socket, Frame}),
    timer:sleep(100),
    
    %% Verify GOAWAY was sent
    Events = test_helpers:capture_telemetry_events(),
    GoawayEvents = [E || E <- Events, 
        element(1, E) =:= [trust, goaway]],
    ?assert(length(GoawayEvents) > 0),
    
    %% Cleanup
    gen_statem:stop(Pid),
    ok.
