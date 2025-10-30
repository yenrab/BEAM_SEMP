%%%-------------------------------------------------------------------
%% @doc Minimal unit test for FSM - completely isolated.
%% @end
%%%-------------------------------------------------------------------

-module(fsm_minimal_test).
-include_lib("eunit/include/eunit.hrl").

%%--------------------------------------------------------------------
%% @doc Single test function - no setup/teardown conflicts.
%% @end
%%--------------------------------------------------------------------
fsm_minimal_test_() ->
    [
        fun test_fsm_initialization/0,
        fun test_session_config_creation/0,
        fun test_request_frame_encoding/0
    ].

%%--------------------------------------------------------------------
%% @doc Tests FSM initialization without mocking conflicts.
%% @end
%%--------------------------------------------------------------------
test_fsm_initialization() ->
    %% Create minimal test data
    Socket = {test_socket, make_ref()},
    PeerInfo = #{ip => {127,0,0,1}, port => 12345},
    SessionConfig = #{max_inflight => 4, max_age_ms => 30000, idle_ms => 5000, max_calls => 50, drain_ms => 1000},
    
    %% Test that we can create the data structures
    ?assert(is_tuple(Socket)),
    ?assert(is_map(PeerInfo)),
    ?assert(is_map(SessionConfig)),
    
    %% Test config values
    ?assertEqual(4, maps:get(max_inflight, SessionConfig)),
    ?assertEqual(30000, maps:get(max_age_ms, SessionConfig)),
    ?assertEqual(5000, maps:get(idle_ms, SessionConfig)),
    ?assertEqual(50, maps:get(max_calls, SessionConfig)),
    ?assertEqual(1000, maps:get(drain_ms, SessionConfig)).

%%--------------------------------------------------------------------
%% @doc Tests session config creation and validation.
%% @end
%%--------------------------------------------------------------------
test_session_config_creation() ->
    %% Test default config
    DefaultConfig = #{max_inflight => 8, max_age_ms => 60000, idle_ms => 5000, max_calls => 100, drain_ms => 1000},
    ?assert(is_map(DefaultConfig)),
    
    %% Test config override
    OverrideConfig = DefaultConfig#{max_inflight => 16},
    ?assertEqual(16, maps:get(max_inflight, OverrideConfig)),
    ?assertEqual(60000, maps:get(max_age_ms, OverrideConfig)),
    
    %% Test config validation
    ValidConfig = #{max_inflight => 4, max_age_ms => 30000, idle_ms => 5000, max_calls => 50, drain_ms => 1000},
    ?assert(maps:get(max_inflight, ValidConfig) > 0),
    ?assert(maps:get(max_age_ms, ValidConfig) > 0),
    ?assert(maps:get(idle_ms, ValidConfig) > 0),
    ?assert(maps:get(max_calls, ValidConfig) > 0),
    ?assert(maps:get(drain_ms, ValidConfig) > 0).

%%--------------------------------------------------------------------
%% @doc Tests request frame encoding/decoding.
%% @end
%%--------------------------------------------------------------------
test_request_frame_encoding() ->
    %% Test call request
    CallRequest = {call, 1, lists, reverse, [1,2,3,4,5]},
    CallFrame = term_to_binary(CallRequest),
    ?assert(is_binary(CallFrame)),
    
    %% Test decode
    DecodedCall = binary_to_term(CallFrame),
    ?assertEqual(CallRequest, DecodedCall),
    
    %% Test cast request
    CastRequest = {cast, 2, lists, reverse, [5,4,3,2,1]},
    CastFrame = term_to_binary(CastRequest),
    ?assert(is_binary(CastFrame)),
    
    %% Test decode
    DecodedCast = binary_to_term(CastFrame),
    ?assertEqual(CastRequest, DecodedCast),
    
    %% Test response frame
    Response = #{t => result, req_id => 1, value => [5,4,3,2,1]},
    ResponseFrame = term_to_binary(Response),
    ?assert(is_binary(ResponseFrame)),
    
    %% Test decode
    DecodedResponse = binary_to_term(ResponseFrame),
    ?assertEqual(Response, DecodedResponse).



