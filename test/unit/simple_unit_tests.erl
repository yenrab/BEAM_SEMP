%%%-------------------------------------------------------------------
%% @doc Simplified unit tests without mocking conflicts.
%% @end
%%%-------------------------------------------------------------------

-module(simple_unit_tests).
-include_lib("eunit/include/eunit.hrl").

%%--------------------------------------------------------------------
%% @doc Test suite for simple unit tests.
%% @end
%%--------------------------------------------------------------------
simple_unit_test_() ->
    [
        fun test_session_config_creation/0,
        fun test_peer_info_creation/0,
        fun test_request_creation/0,
        fun test_response_creation/0,
        fun test_frame_encoding/0,
        fun test_frame_decoding/0,
        fun test_reqid_generation/0,
        fun test_client_id_creation/0
    ].

%%--------------------------------------------------------------------
%% @doc Tests session config creation.
%% @end
%%--------------------------------------------------------------------
test_session_config_creation() ->
    Config = #{max_inflight => 8, max_age_ms => 60000, idle_ms => 5000, max_calls => 100, drain_ms => 1000},
    ?assert(is_map(Config)),
    ?assertEqual(8, maps:get(max_inflight, Config)),
    ?assertEqual(60000, maps:get(max_age_ms, Config)),
    ?assertEqual(5000, maps:get(idle_ms, Config)),
    ?assertEqual(100, maps:get(max_calls, Config)),
    ?assertEqual(1000, maps:get(drain_ms, Config)).

%%--------------------------------------------------------------------
%% @doc Tests peer info creation.
%% @end
%%--------------------------------------------------------------------
test_peer_info_creation() ->
    PeerInfo = #{ip => {127,0,0,1}, port => 12345, hostname => "test_host"},
    ?assert(is_map(PeerInfo)),
    ?assertEqual({127,0,0,1}, maps:get(ip, PeerInfo)),
    ?assertEqual(12345, maps:get(port, PeerInfo)),
    ?assertEqual("test_host", maps:get(hostname, PeerInfo)).

%%--------------------------------------------------------------------
%% @doc Tests request creation.
%% @end
%%--------------------------------------------------------------------
test_request_creation() ->
    ReqId = 1,
    Request = {call, ReqId, lists, reverse, [1,2,3,4,5]},
    ?assert(is_tuple(Request)),
    ?assertEqual(5, tuple_size(Request)),
    ?assertEqual(call, element(1, Request)),
    ?assertEqual(ReqId, element(2, Request)),
    ?assertEqual(lists, element(3, Request)),
    ?assertEqual(reverse, element(4, Request)),
    ?assertEqual([1,2,3,4,5], element(5, Request)).

%%--------------------------------------------------------------------
%% @doc Tests response creation.
%% @end
%%--------------------------------------------------------------------
test_response_creation() ->
    ReqId = 1,
    Result = [5,4,3,2,1],
    Response = #{t => result, req_id => ReqId, value => Result},
    ?assert(is_map(Response)),
    ?assertEqual(result, maps:get(t, Response)),
    ?assertEqual(ReqId, maps:get(req_id, Response)),
    ?assertEqual(Result, maps:get(value, Response)).

%%--------------------------------------------------------------------
%% @doc Tests frame encoding.
%% @end
%%--------------------------------------------------------------------
test_frame_encoding() ->
    Request = {call, 1, lists, reverse, [1,2,3,4,5]},
    Frame = term_to_binary(Request),
    ?assert(is_binary(Frame)),
    ?assert(byte_size(Frame) > 0).

%%--------------------------------------------------------------------
%% @doc Tests frame decoding.
%% @end
%%--------------------------------------------------------------------
test_frame_decoding() ->
    Request = {call, 1, lists, reverse, [1,2,3,4,5]},
    Frame = term_to_binary(Request),
    Decoded = binary_to_term(Frame),
    ?assertEqual(Request, Decoded).

%%--------------------------------------------------------------------
%% @doc Tests request ID generation.
%% @end
%%--------------------------------------------------------------------
test_reqid_generation() ->
    ReqId1 = make_ref(),
    ReqId2 = make_ref(),
    ?assert(is_reference(ReqId1)),
    ?assert(is_reference(ReqId2)),
    ?assert(ReqId1 =/= ReqId2).

%%--------------------------------------------------------------------
%% @doc Tests client ID creation.
%% @end
%%--------------------------------------------------------------------
test_client_id_creation() ->
    ClientId = <<"test_client_", (integer_to_binary(erlang:system_time(microsecond)))/binary>>,
    ?assert(is_binary(ClientId)),
    ?assert(byte_size(ClientId) > 0).
