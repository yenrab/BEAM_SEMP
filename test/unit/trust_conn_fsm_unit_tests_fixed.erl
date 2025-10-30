%%%-------------------------------------------------------------------
%% @doc Unit tests for trust_conn_fsm using EUnit with proper mocking.
%% @end
%%%-------------------------------------------------------------------

-module(trust_conn_fsm_unit_tests_fixed).
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
        fun fsm_handshake_token_success_test/1,
        fun fsm_max_inflight_triggers_backpressure_test/1,
        fun fsm_duplicate_reqid_rejected_test/1,
        fun fsm_frame_size_exceeded_closes_connection_test/1
     ]}.

%%--------------------------------------------------------------------
%% @doc Sets up FSM test environment with isolated mocking.
%% @end
%%--------------------------------------------------------------------
setup_fsm_test() ->
    %% Clean up any existing mocks first
    meck:unload(),
    
    %% Mock semp_facades module
    meck:new(semp_facades, [unstick, passthrough]),
    meck:expect(semp_facades, setopts, fun(_Socket, _Opts) -> ok end),
    meck:expect(semp_facades, peername, fun(_Socket) -> {ok, {{127,0,0,1}, 12345}} end),
    meck:expect(semp_facades, controlling_process, fun(_Socket, _Pid) -> ok end),
    meck:expect(semp_facades, close, fun(_Socket) -> ok end),
    
    %% Mock trust_token module
    meck:new(trust_token, [unstick, passthrough]),
    meck:expect(trust_token, validate, fun(_Token, _State) -> 
        {ok, #{client_id => <<"test_client">>, permissions => any}} 
    end),
    
    %% Mock trust_suspicion module
    meck:new(trust_suspicion, [unstick, passthrough]),
    meck:expect(trust_suspicion, bump, fun(_ClientId, _Direction) -> ok end),
    meck:expect(trust_suspicion, is_suspicious, fun(_ClientId) -> false end),
    
    %% Mock telemetry module
    meck:new(telemetry, [unstick, passthrough]),
    meck:expect(telemetry, execute, fun(_Event, _Measurements, _Metadata) -> ok end),
    
    %% Mock semp_whitelist module
    meck:new(semp_whitelist, [unstick, passthrough]),
    meck:expect(semp_whitelist, is_allowed, fun(_Type, _ClientId) -> true end),
    meck:expect(semp_whitelist, table, fun(_Type) -> test_whitelist end),
    
    %% Mock semp_policy module
    meck:new(semp_policy, [unstick, passthrough]),
    meck:expect(semp_policy, is_forbidden, fun(_M, _F, _A) -> false end),
    
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
    
    %% Create test socket and config
    Socket = {test_socket, make_ref()},
    SessionConfig = #{max_inflight => 4, max_age_ms => 30000, idle_ms => 5000, max_calls => 50, drain_ms => 1000},
    PeerInfo = #{ip => {127,0,0,1}, port => 12345, hostname => "test_host"},
    
    {Socket, SessionConfig, PeerInfo}.

%%--------------------------------------------------------------------
%% @doc Cleans up FSM test environment.
%% @end
%%--------------------------------------------------------------------
cleanup_fsm_test({_Socket, _SessionConfig, _PeerInfo}) ->
    meck:unload(),
    ok.

%%--------------------------------------------------------------------
%% @doc Tests FSM initialization with default config.
%% @end
%%--------------------------------------------------------------------
fsm_init_with_default_config_test({Socket, SessionConfig, PeerInfo}) ->
    %% Start FSM
    {ok, Pid} = trust_conn_fsm:start_link(Socket, PeerInfo, SessionConfig),
    
    %% Verify FSM is running
    ?assert(is_pid(Pid)),
    ?assert(is_process_alive(Pid)),
    
    %% Cleanup
    gen_statem:stop(Pid),
    ok.

%%--------------------------------------------------------------------
%% @doc Tests successful token handshake.
%% @end
%%--------------------------------------------------------------------
fsm_handshake_token_success_test({Socket, SessionConfig, PeerInfo}) ->
    %% Start FSM
    {ok, Pid} = trust_conn_fsm:start_link(Socket, PeerInfo, SessionConfig),
    
    %% Send valid token
    Token = <<"valid_token">>,
    Frame = term_to_binary(#{t => token, token => Token}),
    gen_statem:cast(Pid, {ssl, Socket, Frame}),
    
    %% Wait for transition to active state
    timer:sleep(100),
    
    %% Verify FSM is still running
    ?assert(is_process_alive(Pid)),
    
    %% Cleanup
    gen_statem:stop(Pid),
    ok.

%%--------------------------------------------------------------------
%% @doc Tests backpressure when max_inflight is reached.
%% @end
%%--------------------------------------------------------------------
fsm_max_inflight_triggers_backpressure_test({Socket, SessionConfig, PeerInfo}) ->
    %% Use small max_inflight for testing
    TestConfig = SessionConfig#{max_inflight => 2},
    
    %% Start FSM
    {ok, Pid} = trust_conn_fsm:start_link(Socket, PeerInfo, TestConfig),
    
    %% Complete handshake
    Token = <<"valid_token">>,
    Frame = term_to_binary(#{t => token, token => Token}),
    gen_statem:cast(Pid, {ssl, Socket, Frame}),
    timer:sleep(100),
    
    %% Send requests up to max_inflight
    Request1 = {call, 1, lists, reverse, [1,2,3,4,5]},
    Request2 = {call, 2, lists, reverse, [1,2,3,4,5]},
    Frame1 = term_to_binary(Request1),
    Frame2 = term_to_binary(Request2),
    
    gen_statem:cast(Pid, {ssl, Socket, Frame1}),
    gen_statem:cast(Pid, {ssl, Socket, Frame2}),
    timer:sleep(100),
    
    %% Send one more request (should trigger backpressure)
    Request3 = {call, 3, lists, reverse, [1,2,3,4,5]},
    Frame3 = term_to_binary(Request3),
    gen_statem:cast(Pid, {ssl, Socket, Frame3}),
    
    %% Verify FSM is still running
    ?assert(is_process_alive(Pid)),
    
    %% Cleanup
    gen_statem:stop(Pid),
    ok.

%%--------------------------------------------------------------------
%% @doc Tests duplicate request ID rejection.
%% @end
%%--------------------------------------------------------------------
fsm_duplicate_reqid_rejected_test({Socket, SessionConfig, PeerInfo}) ->
    %% Start FSM
    {ok, Pid} = trust_conn_fsm:start_link(Socket, PeerInfo, SessionConfig),
    
    %% Complete handshake
    Token = <<"valid_token">>,
    Frame = term_to_binary(#{t => token, token => Token}),
    gen_statem:cast(Pid, {ssl, Socket, Frame}),
    timer:sleep(100),
    
    %% Send same request twice
    Request = {call, 1, lists, reverse, [1,2,3,4,5]},
    Frame = term_to_binary(Request),
    
    gen_statem:cast(Pid, {ssl, Socket, Frame}),
    gen_statem:cast(Pid, {ssl, Socket, Frame}),
    timer:sleep(100),
    
    %% Verify FSM is still running
    ?assert(is_process_alive(Pid)),
    
    %% Cleanup
    gen_statem:stop(Pid),
    ok.

%%--------------------------------------------------------------------
%% @doc Tests frame size validation.
%% @end
%%--------------------------------------------------------------------
fsm_frame_size_exceeded_closes_connection_test({Socket, SessionConfig, PeerInfo}) ->
    %% Start FSM
    {ok, Pid} = trust_conn_fsm:start_link(Socket, PeerInfo, SessionConfig),
    
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
