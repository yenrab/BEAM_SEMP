%%%-------------------------------------------------------------------
%% @doc Test helpers for multiplexing and backpressure tests.
%% @end
%%%-------------------------------------------------------------------

-module(test_helpers).
-export([
    setup_test_env/0,
    cleanup_test_env/1,
    create_test_socket/0,
    create_test_certificate/0,
    mock_telemetry/0,
    capture_telemetry_events/0,
    create_test_client_id/0,
    setup_whitelist/1,
    create_test_session_config/0,
    create_test_peer_info/0,
    create_test_request/1,
    create_test_response/1,
    wait_for_condition/2,
    wait_for_condition/3
]).

%%--------------------------------------------------------------------
%% @doc Sets up test environment with mocked dependencies.
%% @end
%%--------------------------------------------------------------------
setup_test_env() ->
    %% Clean up any existing mocks first
    meck:unload(),
    
    %% IMPORTANT: Mock semp_facades:send (the facade function) FIRST before other modules are loaded
    %% This is the facade that wraps ssl:send - we should NEVER mock ssl:send directly
    %% IMPORTANT: trust_token operations are now accessed through semp_facades, so we no longer
    %% need to mock trust_token directly - mock_semp_facades() handles it
    %% Use the proven mock_modules helper functions that work in other tests
    mock_modules:mock_semp_facades(),
    mock_modules:mock_trust_suspicion(),
    mock_modules:mock_semp_whitelist(),
    mock_modules:mock_semp_policy(),
    
    %% Mock telemetry (mock_modules doesn't have this, so use our helper)
    try
        case meck:validate(telemetry) of
            false -> meck:new(telemetry, [unstick, passthrough]);
            _ -> ok
        end
    catch _:_ -> meck:new(telemetry, [unstick, passthrough])
    end,
    mock_telemetry(),
    
    %% Create test ETS tables
    WhitelistTab = ets:new(test_whitelist, [public, named_table]),
    PolicyTab = ets:new(test_policy, [public, named_table]),
    
    {WhitelistTab, PolicyTab}.

%%--------------------------------------------------------------------
%% @doc Cleans up test environment.
%% @end
%%--------------------------------------------------------------------
cleanup_test_env({WhitelistTab, PolicyTab}) ->
    meck:unload(),
    %% Safely delete ETS tables (ignore if already deleted)
    try ets:delete(WhitelistTab) catch _:_ -> ok end,
    try ets:delete(PolicyTab) catch _:_ -> ok end,
    ok.

%%--------------------------------------------------------------------
%% @doc Creates a mock SSL socket for testing.
%% @end
%%--------------------------------------------------------------------
create_test_socket() ->
    %% Create a mock socket that behaves like an SSL socket
    {test_socket, make_ref()}.

%%--------------------------------------------------------------------
%% @doc Creates a test certificate for client authentication.
%% @end
%%--------------------------------------------------------------------
create_test_certificate() ->
    %% Mock certificate data
    #{cert => <<"test_cert_data">>,
      key => <<"test_key_data">>,
      subject => "CN=test_client",
      issuer => "CN=test_ca"}.

%%--------------------------------------------------------------------
%% @doc Sets up telemetry mocking to capture events.
%% @end
%%--------------------------------------------------------------------
mock_telemetry() ->
    %% Create a process to capture telemetry events
    Pid = spawn(fun telemetry_capture_loop/0),
    meck:expect(telemetry, execute, fun(Event, Measurements, Metadata) ->
        Pid ! {telemetry_event, Event, Measurements, Metadata}
    end),
    Pid.

%%--------------------------------------------------------------------
%% @doc Captures telemetry events for verification.
%% @end
%%--------------------------------------------------------------------
capture_telemetry_events() ->
    receive
        {telemetry_event, Event, Measurements, Metadata} ->
            [{Event, Measurements, Metadata} | capture_telemetry_events()]
    after 100 ->
        []
    end.

%%--------------------------------------------------------------------
%% @doc Creates a test client ID.
%% @end
%%--------------------------------------------------------------------
create_test_client_id() ->
    <<"test_client_", (integer_to_binary(erlang:system_time(microsecond)))/binary>>.

%%--------------------------------------------------------------------
%% @doc Sets up whitelist for testing.
%% @end
%%--------------------------------------------------------------------
setup_whitelist(ClientId) ->
    %% Add client to whitelist
    ets:insert(test_whitelist, {ClientId, any}),
    ok.

%%--------------------------------------------------------------------
%% @doc Creates test session configuration.
%% @end
%%--------------------------------------------------------------------
create_test_session_config() ->
    #{max_inflight => 4,
      max_age_ms => 30000,
      idle_ms => 5000,
      max_calls => 50,
      drain_ms => 1000}.

%%--------------------------------------------------------------------
%% @doc Creates test peer information.
%% @end
%%--------------------------------------------------------------------
create_test_peer_info() ->
    #{ip => {127,0,0,1},
      port => 12345,
      hostname => "test_host"}.

%%--------------------------------------------------------------------
%% @doc Creates a test request.
%% @end
%%--------------------------------------------------------------------
create_test_request(ReqId) ->
    {call, ReqId, lists, reverse, [1,2,3,4,5]}.

%%--------------------------------------------------------------------
%% @doc Creates a test response.
%% @end
%%--------------------------------------------------------------------
create_test_response(ReqId) ->
    #{t => result, req_id => ReqId, value => [5,4,3,2,1]}.

%%--------------------------------------------------------------------
%% @doc Waits for a condition to be true.
%% @end
%%--------------------------------------------------------------------
wait_for_condition(Fun, Timeout) ->
    wait_for_condition(Fun, Timeout, 100).

wait_for_condition(Fun, Timeout, Interval) ->
    case Fun() of
        true -> ok;
        false when Timeout > 0 ->
            timer:sleep(Interval),
            wait_for_condition(Fun, Timeout - Interval, Interval);
        false ->
            {error, timeout}
    end.

%%--------------------------------------------------------------------
%% @doc Telemetry capture loop.
%% @end
%%--------------------------------------------------------------------
telemetry_capture_loop() ->
    receive
        {telemetry_event, Event, Measurements, Metadata} ->
            %% Store event for later retrieval
            put({telemetry_event, erlang:system_time(microsecond)}, 
                {Event, Measurements, Metadata}),
            telemetry_capture_loop();
        {get_events, Pid} ->
            Events = get_telemetry_events(),
            Pid ! {telemetry_events, Events},
            telemetry_capture_loop();
        stop ->
            ok
    end.

get_telemetry_events() ->
    [V || {K, V} <- get(), is_tuple(K), element(1, K) =:= telemetry_event].
